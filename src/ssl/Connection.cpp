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
    case SSL_ERROR_SSL: {
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
                 const system::Clock::Value ts, const int keyfd)
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
  m_state = State::Open;
  m_blocked = false;
  m_rdbf = new uint8_t[BUFLEN];
  /*
   * Update the SSL state.
   */
  SSL_set_bio(m_ssl, m_bin, m_bout);
  SSL_set_app_data(m_ssl, this);
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

Action
Connection::onAcked(system::Logger& log, ID const& id, Delegate& delegate,
                    const system::Clock::Value ts, const uint32_t alen,
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
   * Write the data.
   *
   * NOTE(xrg): with BIO_mem, the write always succeeds if len > 0.
   */
  SSL_write(m_ssl, out, (int)rlen);
  /*
   * Flush the data.
   */
  return flush(log, alen, sdata, slen);
}

Action
Connection::onNewData(system::Logger& log, ID const& id,
                      api::interface::Delegate<ID>& delegate,
                      const uint8_t* const data, const uint32_t len,
                      const system::Clock::Value ts)
{
  /*
   * Write the data in the input BIO.
   */
  int ret = BIO_write(m_bin, data, (int)len);
  if (ret != (int)len) {
    log.error("SSL", "<", id, "> failed to write ", len, "B in BIO");
    return Action::Abort;
  }
  /*
   * Show the buffer level.
   */
  auto acc = pendingWrite();
  log.trace("SSL", "<", id, "> ", len, "B, (", acc, "/", BUFLEN, ")");
  /*
   * Only accept Ready state.
   */
  if (m_state != State::Ready && m_state != State::Shutdown) {
    log.error("SSL", "<", id, "> received data in unexpected state");
    return Action::Abort;
  }
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
    auto act = delegate.onNewData(id, m_cookie, m_rdbf, ret, ts);
    if (act != Action::Continue) {
      return act;
    }
  } while (ret > 0 && m_state != State::Closed);
  /*
   * Continue processing.
   */
  return Action::Continue;
}

Action
Connection::onNewData(system::Logger& log, ID const& id,
                      api::interface::Delegate<ID>& delegate,
                      const uint8_t* const data, const uint32_t len,
                      const system::Clock::Value ts, const uint32_t alen,
                      uint8_t* const sdata, uint32_t& slen)
{
  /*
   * Write the data in the input BIO.
   */
  int ret = BIO_write(m_bin, data, (int)len);
  if (ret != (int)len) {
    log.error("SSL", "<", id, "> failed to write ", len, "B in BIO");
    return Action::Abort;
  }
  /*
   * Show the buffer level.
   */
  auto avl = pendingWrite();
  log.trace("SSL", "<", id, "> ", len, "B, (", avl, "/", BUFLEN, ")");
  /*
   * Check the connection's state.
   */
  switch (m_state) {
    /*
     * Closed is not a valid state.
     */
    case State::Open: {
      log.error("SSL", "<", id, "> received data on OPEN");
      return Action::Abort;
    }
    /*
     * Closed is not a valid state.
     */
    case State::Closed: {
      log.error("SSL", "<", id, "> received data on CLOSED");
      return Action::Abort;
    }
    /*
     * Handle the SSL handshake.
     */
    case State::Connecting: {
      ret = SSL_connect(m_ssl);
      switch (ret) {
        case 0: {
          log.error("SSL", "<", id, "> connect error, controlled shutdown");
          return Action::Abort;
        }
        case 1: {
          log.debug("SSL", "<", id, "> connect successful");
          m_state = State::Connected;
          return flush(log, alen, sdata, slen);
        }
        default: {
          auto err = SSL_get_error(m_ssl, ret);
          if (err == SSL_ERROR_WANT_READ) {
            return flush(log, alen, sdata, slen);
          }
          log.error("SSL", "<", id, "> connect error: ", errorToString(err));
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
          m_state = State::Ready;
          return flush(log, alen, sdata, slen);
        }
        default: {
          auto err = SSL_get_error(m_ssl, ret);
          if (err == SSL_ERROR_WANT_READ) {
            return flush(log, alen, sdata, slen);
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
      uint8_t out[alen];
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
        uint32_t rlen = 0;
        uint32_t wlen = alen - acc;
        auto act =
          delegate.onNewData(id, m_cookie, m_rdbf, ret, ts, wlen, out, rlen);
        if (act != Action::Continue) {
          return abortOrClose(log, act, alen, sdata, slen);
        }
        /*
         * Cap the written amount.
         */
        if (rlen + acc > alen) {
          rlen = alen - acc;
        }
        /*
         * Skip writting if there is no payload.
         */
        if (rlen == 0) {
          continue;
        }
        /*
         * Write the data.
         */
        auto wrs = SSL_write(m_ssl, out, (int)rlen);
        /*
         * Handle the errors.
         */
        if (wrs <= 0) {
          auto err = SSL_get_error(m_ssl, wrs);
          auto m = errorToString(err);
          log.error("SSL", "<", id, "> write error: ", m);
          return Action::Abort;
        }
        /*
         * Handle partial data.
         */
        if (wrs != (int)rlen) {
          log.error("SSL", "<", id, "> partial write: ", wrs, "/", len);
          return Action::Abort;
        }
        /*
         * Update the accumulator.
         */
        acc += rlen;
      } while (ret > 0 && m_state != State::Closed);
      /*
       * Flush the output.
       */
      return flush(log, alen, sdata, slen);
    }
  }
#if defined(__GNUC__) && defined(__GNUC_PREREQ)
  return Action::Continue;
#endif
}

Action
Connection::abortOrClose(system::Logger& log, const Action r,
                         const uint32_t alen, uint8_t* const sdata,
                         uint32_t& slen)
{
  /*
   * Process an abort request.
   */
  if (r == Action::Abort) {
    log.debug("SSL", "aborting connection");
    return Action::Abort;
  }
  /*
   * Process a close request.
   */
  if (r == Action::Close) {
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
      return flush(log, alen, sdata, slen);
    }
    /*
     * Abort if the shutdown failed.
     */
    log.error("SSL", "SSL_shutdown error, aborting connection");
    return Action::Abort;
  }
  /*
   * Default return.
   */
  return Action::Continue;
}

Action
Connection::flush(system::Logger& log, const uint32_t alen,
                  uint8_t* const sdata, uint32_t& slen)
{
  /*
   * Check and send any data in the BIO buffer.
   */
  size_t len = pendingRead();
  if (len == 0) {
    return Action::Continue;
  }
  /*
   * Get how much data to send back.
   */
  size_t rlen = len > alen ? alen : len;
  log.trace("SSL", "flushing ", rlen, "B (", len, "/", alen, ")");
  /*
   * Send the response.
   */
  BIO_read(m_bout, sdata, (int)rlen);
  slen = rlen;
  return Action::Continue;
}

}
