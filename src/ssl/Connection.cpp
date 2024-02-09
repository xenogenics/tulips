#include <tulips/ssl/Connection.h>
#include <tulips/ssl/Protocol.h>
#include <limits>
#include <fcntl.h>
#include <openssl/err.h>

namespace tulips::ssl {

/*
 * Utilities
 */

const SSL_METHOD*
getMethod(const Protocol type, const bool server, long& flags)
{
  const SSL_METHOD* method = nullptr;
  /*
   * Check requested type.
   */
  switch (type) {
    case Protocol::Auto: {
      method = server ? TLS_server_method() : TLS_client_method();
      flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1;
      break;
    }
    case Protocol::SSLv3: {
      method = server ? SSLv23_server_method() : SSLv23_client_method();
      flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 |
              SSL_OP_NO_TLSv1_2;
      break;
    }
    case Protocol::TLS: {
      method = server ? TLS_server_method() : TLS_client_method();
      flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 |
              SSL_OP_NO_TLSv1_1;
      break;
    }
  }
  /*
   * Return the SSL method.
   */
  return method;
}

std::string
errorToString(const int err)
{
  switch (err) {
    case SSL_ERROR_NONE:
      return "SSL_ERROR_NONE";
    case SSL_ERROR_ZERO_RETURN:
      return "SSL_ERROR_ZERO_RETURN";
    case SSL_ERROR_WANT_READ:
      return "SSL_ERROR_WANT_READ";
    case SSL_ERROR_WANT_WRITE:
      return "SSL_ERROR_WANT_WRITE";
    case SSL_ERROR_WANT_CONNECT:
      return "SSL_ERROR_WANT_CONNECT";
    case SSL_ERROR_WANT_ACCEPT:
      return "SSL_ERROR_WANT_ACCEPT";
    case SSL_ERROR_WANT_X509_LOOKUP:
      return "SSL_ERROR_WANT_X509_LOOKUP";
    case SSL_ERROR_SYSCALL:
      return "SSL_ERROR_SYSCALL";
    default: {
      char buffer[1024];
      ERR_error_string_n(ERR_peek_error(), buffer, 1024);
      return { buffer };
    }
  }
  return "no error";
}

/*
 * SSL connection.
 */

void
Connection::open(SSL_CTX* ctx, const ID id, void* const cookie,
                 const system::Clock::Epoch ts, const int keyfd)
{
  initialize(ctx, id, cookie, ts, keyfd);
  m_state = State::Open;
}

void
Connection::accept(SSL_CTX* ctx, const ID id, void* const cookie,
                   const system::Clock::Epoch ts, const int keyfd)
{
  initialize(ctx, id, cookie, ts, keyfd);
  m_state = State::Accepting;
}

void
Connection::close()
{
  /*
   * Close the key file.
   */
  if (m_keyfd != -1) {
    ::close(m_keyfd);
    m_keyfd = -1;
  }
  /*
   * Delete the read buffer.
   */
  delete[] m_rdbf;
  m_rdbf = nullptr;
  /*
   * No need to free the BIOs, SSL_free does that for us.
   */
  SSL_free(m_ssl);
  m_ssl = nullptr;
  m_bin = nullptr;
  m_bout = nullptr;
  /*
   * Reset the state.
   */
  m_id = std::numeric_limits<ID>::max();
  m_cookie = nullptr;
  m_ts = 0;
  m_state = State::Closed;
  m_blocked = false;
}

Status
Connection::connect(system::Logger& log, ID const& id,
                    std::optional<std::string> const& hostname, const ALP alp)
{
  /*
   * Set the host name for SNI-enabled servers.
   */
  if (hostname.has_value()) {
    SSL_set_tlsext_host_name(m_ssl, hostname.value().c_str());
  }
  /*
   * Apply the application layer protocol.
   */
  switch (alp) {
    case ALP::None: {
      break;
    }
    case ALP::HTTP_1_1: {
      static uint8_t name[] = "\x08http/1.1";
      if (SSL_set_alpn_protos(m_ssl, name, 9)) {
        log.error("SSL", "<", id, "> failed to set ALPN for H1");
        return Status::SslError;
      };
      break;
    }
    case ALP::HTTP_2: {
      static uint8_t name[] = "\x02h2";
      if (SSL_set_alpn_protos(m_ssl, name, 3)) {
        log.error("SSL", "<", id, "> failed to set ALPN for H2");
        return Status::SslError;
      };
      break;
    }
  }
  /*
   * Try to connect.
   *
   * NOTE(xrg): on non-blocking sockets, this operation returns -1.
   */
  auto ret = SSL_connect(m_ssl);
  auto err = SSL_get_error(m_ssl, ret);
  /*
   * Check the result.
   */
  if (ret != -1) {
    auto msg = ssl::errorToString(err);
    log.error("SSL", "<", id, "> initial connect error: ", msg);
    return Status::SslError;
  }
  /*
   * Check the error.
   */
  if (err != SSL_ERROR_WANT_READ) {
    auto msg = ssl::errorToString(err);
    log.error("SSL", "<", id, "> initial connect error: ", msg);
    return Status::SslError;
  }
  /*
   * Update the state and return.
   */
  m_state = Connection::State::Connecting;
  return Status::OperationInProgress;
}

Status
Connection::shutdown(system::Logger& log, ID const& id)
{
  /*
   * Check if the connection is in the right state.
   */
  if (m_state != State::Ready && m_state != State::Shutdown) {
    return Status::NotConnected;
  }
  if (m_state == State::Shutdown) {
    return Status::OperationInProgress;
  }
  /*
   * Mark the state as shut down.
   */
  m_state = Connection::State::Shutdown;
  /*
   * Call SSL_shutdown, repeat if necessary.
   */
  int ret = SSL_shutdown(m_ssl);
  /*
   * Go through the shutdown state machine.
   */
  switch (ret) {
    case 0: {
      log.debug("SSL", "<", id, "> shutdown sent");
      return Status::OperationInProgress;
    }
    case 1: {
      log.debug("SSL", "<", id, "> shutdown completed");
      m_state = Connection::State::Closed;
      return Status::OperationCompleted;
    }
    default: {
      auto err = SSL_get_error(m_ssl, ret);
      auto error = ssl::errorToString(err);
      log.error("SSL", "<", id, "> SSL_shutdown error: ", error);
      return Status::SslError;
    }
  }
}

Action
Connection::onAcked(system::Logger& log, ID const& id, Delegate& delegate,
                    const system::Clock::Epoch ts, const uint32_t alen,
                    uint8_t* const sdata, uint32_t& slen)
{
  /*
   * Reset the blocked state.
   */
  m_blocked = false;
  /*
   * If the BIO has data pending, flush it.
   */
  if (pendingRead() > 0) {
    return flush(log, alen, sdata, slen);
  }
  /*
   * Call the delegate and encrypt the output.
   */
  uint8_t out[alen];
  uint32_t rlen = 0;
  Action act = delegate.onAcked(id, m_cookie, ts, alen, out, rlen);
  /*
   * Bail out if the connection is not longer ready.
   */
  if (m_state != State::Ready) {
    return Action::Continue;
  }
  /*
   * Process the action.
   */
  if (act != Action::Continue) {
    return abortOrClose(log, act, alen, sdata, slen);
  }
  /*
   * Cap the written amount.
   */
  if (rlen > alen) {
    rlen = alen;
  }
  /*
   * Skip if the length is 0.
   */
  if (rlen == 0) {
    return Action::Continue;
  }
  /*
   * Write the data and abort in case of failure.
   */
  if (write(log, id, rlen, out) != Status::Ok) {
    return Action::Abort;
  }
  /*
   * Flush the data.
   */
  return flush(log, alen, sdata, slen);
}

Action
Connection::onNewData(system::Logger& log, ID const& id,
                      api::interface::Delegate<ID>& delegate,
                      const uint8_t* const rdat, const uint32_t rlen,
                      const bool pushed, const system::Clock::Epoch ts,
                      const uint32_t savl, uint8_t* const sdat, uint32_t& slen)
{
  /*
   * Write the data in the input BIO.
   */
  int ret = BIO_write(m_bin, rdat, (int)rlen);
  if (ret != (int)rlen) {
    log.error("SSL", "<", id, "> failed to write ", rlen, "B in BIO");
    return Action::Abort;
  }
  /*
   * Show the buffer level.
   */
  auto avl = pendingWrite();
  log.trace("SSL", "<", id, "> ", rlen, "B, (", avl, "/", BUFLEN, ")");
  /*
   * Check the connection's state.
   */
  switch (m_state) {
    /*
     * Closed is not a valid state.
     */
    case State::Closed: {
      log.error("SSL", "<", id, "> received data on CLOSED");
      return Action::Abort;
    }
    /*
     * Opening is not a valid state.
     */
    case State::Opening: {
      log.error("SSL", "<", id, "> received data on OPENING");
      return Action::Abort;
    }
    /*
     * Open is not a valid state.
     */
    case State::Open: {
      log.error("SSL", "<", id, "> received data on OPEN");
      return Action::Abort;
    }
    /*
     * Handle the SSL handshake.
     */
    case State::Connecting: {
      ret = SSL_connect(m_ssl);
      switch (ret) {
        case 0: {
          auto err = SSL_get_error(m_ssl, ret);
          auto msg = ssl::errorToString(err);
          log.error("SSL", "<", id, "> connect error: ", msg);
          return Action::Abort;
        }
        case 1: {
          log.debug("SSL", "<", id, "> connect successful");
          m_state = State::Connected;
          return flush(log, savl, sdat, slen);
        }
        default: {
          auto err = SSL_get_error(m_ssl, ret);
          if (err == SSL_ERROR_WANT_READ) {
            return flush(log, savl, sdat, slen);
          }
          auto msg = ssl::errorToString(err);
          log.error("SSL", "<", id, "> connect error: ", msg);
          return Action::Abort;
        }
      }
#if defined(__GNUC__) && defined(__GNUC_PREREQ)
      break;
#endif
    }
    /*
     * Process SSL_accept.
     */
    case State::Accepting: {
      ret = SSL_accept(m_ssl);
      switch (ret) {
        case 0: {
          auto err = SSL_get_error(m_ssl, ret);
          log.error("SSL", "<", id, "> accept error: ", errorToString(err));
          return Action::Abort;
        }
        case 1: {
          log.debug("SSL", "<", id, "> accept successful");
          auto ret = flush(log, savl, sdat, slen);
          m_state = State::Ready;
          m_cookie = delegate.onConnected(id, m_cookie, ts);
          return ret;
        }
        default: {
          auto err = SSL_get_error(m_ssl, ret);
          if (err == SSL_ERROR_WANT_READ) {
            return flush(log, savl, sdat, slen);
          }
          log.error("SSL", "<", id, "> accept error: ", errorToString(err));
          return Action::Abort;
        }
      }
    }
    /*
     * Decrypt and pass the data to the delegate.
     */
    case State::Connected:
    case State::Ready:
    case State::Shutdown: {
      uint32_t acc = 0;
      uint8_t out[savl];
      /*
       * Process the internal buffer as long as there is data available.
       */
      do {
        auto bl0 = pendingWrite();
        ret = SSL_read(m_ssl, m_rdbf, BUFLEN);
        auto bl1 = pendingWrite();
        log.trace("SSL", "<", id, "> read: ", ret, ", ", bl0, " -> ", bl1);
        /*
         * Handle error conditions.
         */
        if (ret <= 0) {
          auto err = SSL_get_error(m_ssl, ret);
          auto sht = SSL_get_shutdown(m_ssl);
          /*
           * Check the shutdown condition.
           */
          if (sht & SSL_RECEIVED_SHUTDOWN) {
            auto ret = SSL_shutdown(m_ssl);
            /*
             * Break if the shutdown completed.
             */
            if (ret == 1) {
              log.debug("SSL", "<", id, "> shutdown completed");
              m_state = State::Closed;
              return Action::Close;
            }
            /*
             * Break if the shutdown needs more data.
             */
            int err = SSL_get_error(m_ssl, ret);
            if (err == SSL_ERROR_WANT_READ) {
              break;
            }
            /*
             * Abort otherwise.
             */
            log.error("SSL", "<", id, "> shutdown failed: ", ret, ", ", err);
            return Action::Abort;
          }
          /*
           * Check if the connection needs more data.
           */
          if (err == SSL_ERROR_WANT_READ) {
            break;
          }
          /*
           * Treat it as a read error otherwise.
           */
          else {
            auto m = errorToString(err);
            auto b = pendingWrite();
            log.error("SSL", "<", id, "> read error: ", m, " (", ret, ", ", err,
                      ", ", sht, ") ", b, "B");
            return Action::Abort;
          }
        }
        /*
         * Notify the delegate.
         */
        uint32_t r = 0;
        uint32_t w = savl - acc;
        auto act =
          delegate.onNewData(id, m_cookie, m_rdbf, ret, pushed, ts, w, out, r);
        /*
         * Bail out if the connection is not longer ready.
         */
        if (m_state != State::Ready) {
          return Action::Continue;
        }
        /*
         * Handle close or abort action.
         */
        if (act != Action::Continue) {
          return abortOrClose(log, act, savl, sdat, slen);
        }
        /*
         * Cap the written amount.
         */
        if (r + acc > savl) {
          r = savl - acc;
        }
        /*
         * Skip writting if there is no payload.
         */
        if (r == 0) {
          continue;
        }
        /*
         * Write the data and abort in case of failure.
         */
        if (write(log, id, r, out) != Status::Ok) {
          return Action::Abort;
        }
      } while (ret > 0 && m_state != State::Closed);
      /*
       * Flush the output.
       */
      return flush(log, savl, sdat, slen);
    }
  }
#if defined(__GNUC__) && defined(__GNUC_PREREQ)
  return Action::Continue;
#endif
}

Status
Connection::write(system::Logger& log, ID const& id, const uint32_t len,
                  const uint8_t* const data)
{

  /*
   * Skip if the length is 0.
   */
  if (len == 0) {
    return Status::InvalidArgument;
  }
  /*
   * Check if the connection is in the right state.
   */
  if (m_state != Connection::State::Ready) {
    return Status::NotConnected;
  }
  /*
   * Check if we can write anything.
   */
  if (m_blocked) {
    return Status::OperationInProgress;
  }
  /*
   * Write the data.
   */
  auto ret = SSL_write(m_ssl, data, (int)len);
  /*
   * Handle the errors.
   */
  if (ret <= 0) {
    auto err = SSL_get_error(m_ssl, ret);
    auto m = errorToString(err);
    log.error("SSL", "<", id, "> SSL_write error: ", m);
    return Status::ProtocolError;
  }
  /*
   * Handle partial data.
   */
  if (ret != (int)len) {
    log.error("SSL", "<", id, "> partial SSL_write: ", ret, "/", len);
    return Status::IncompleteData;
  }
  /*
   * Done.
   */
  return Status::Ok;
}

Action
Connection::abortOrClose(system::Logger& log, const Action r,
                         const uint32_t savl, uint8_t* const sdat,
                         uint32_t& slen)
{
  /*
   * Process Continue.
   */
  if (r == Action::Continue) {
    return r;
  }
  /*
   * Process Abort.
   */
  if (r == Action::Abort) {
    log.debug("SSL", "aborting connection");
    return r;
  }
  /*
   * Process Close.
   */
  log.debug("SSL", "closing connection");
  /*
   * Call SSL_shutdown, repeat if necessary.
   */
  int ret = SSL_shutdown(m_ssl);
  if (ret == 0) {
    ret = SSL_shutdown(m_ssl);
  }
  /*
   * Check that the SSL connection expect an answer from the other peer.
   */
  if (ret < 0) {
    auto err = SSL_get_error(m_ssl, ret);
    if (err != SSL_ERROR_WANT_READ) {
      log.error("SSL", "SSL_shutdown error: ", ssl::errorToString(err));
      return Action::Abort;
    }
    /*
     * Flush the shutdown signal.
     */
    m_state = State::Shutdown;
    return flush(log, savl, sdat, slen);
  }
  /*
   * Abort if the shutdown failed.
   */
  log.error("SSL", "SSL_shutdown error, aborting connection");
  return Action::Abort;
}

Action
Connection::flush(system::Logger& log, const uint32_t savl, uint8_t* const sdat,
                  uint32_t& slen)
{
  /*
   * Check and send any data in the BIO buffer.
   */
  size_t len = pendingRead();
  if (len == 0) {
    return Action::Continue;
  }
  /*
   * Skipping if there is no available room in the send buffer.
   */
  if (savl == 0) {
    return Action::Continue;
  }
  /*
   * Get how much data to send back.
   */
  size_t rlen = len > savl ? savl : len;
  log.trace("SSL", "flushing ", rlen, "B (", len, "/", savl, ")");
  /*
   * Read the BIO buffer.
   */
  BIO_read(m_bout, sdat, (int)rlen);
  slen = rlen;
  /*
   * Done.
   */
  return Action::Continue;
}

void
Connection::initialize(SSL_CTX* ctx, const ID id, void* const cookie,
                       const system::Clock::Epoch ts, const int keyfd)
{
  /*
   * Update the state.
   */
  m_id = id;
  m_cookie = cookie;
  m_ts = ts;
  m_keyfd = keyfd;
  m_bin = bio::allocate(BUFLEN);
  m_bout = bio::allocate(BUFLEN);
  m_ssl = SSL_new(ctx);
  m_blocked = false;
  m_rdbf = new uint8_t[BUFLEN];
  /*
   * Update the SSL state.
   */
  SSL_set_bio(m_ssl, m_bin, m_bout);
  SSL_set_app_data(m_ssl, this);
}

}
