#pragma once

#include "BIO.h"
#include <tulips/api/Action.h>
#include <tulips/api/Interface.h>
#include <tulips/ssl/Protocol.h>
#include <tulips/system/Logger.h>
#include <string>
#include <openssl/ssl.h>

#define AS_SSL(__c) (reinterpret_cast<SSL_CTX*>(__c))

namespace tulips::ssl {

/*
 * Utilities.
 */

const SSL_METHOD* getMethod(const Protocol type, const bool server,
                            long& flags);
std::string errorToString(SSL* ssl, const int err);

/*
 * SSL context.
 */

struct Context
{
  enum class State
  {
    Closed,
    Connect,
    Accept,
    Ready,
    Shutdown
  };

  Context(SSL_CTX* ctx, system::Logger& log, const size_t buflen,
          void* cookie = nullptr);
  ~Context();

  /**
   * Process pending data on ACK.
   */
  template<typename ID>
  Action onAcked(ID const& id, api::interface::Delegate<ID>& delegate,
                 const uint32_t alen, uint8_t* const sdata, uint32_t& slen)
  {
    /*
     * Reset the blocked state.
     */
    blocked = false;
    /*
     * If the BIO has data pending, flush it.
     */
    if (pending() > 0) {
      return flush(alen, sdata, slen);
    }
    /*
     * Call the delegate and encrypt the output.
     */
    uint8_t out[alen];
    uint32_t rlen = 0;
    Action act = delegate.onAcked(id, cookie, alen, out, rlen);
    if (act != Action::Continue) {
      return abortOrClose(act, alen, sdata, slen);
    }
    if (rlen > alen) {
      rlen = alen;
    }
    SSL_write(ssl, out, (int)rlen);
    return flush(alen, sdata, slen);
  }

  /**
   * Processing incoming data and encrypt the response.
   */
  template<typename ID>
  Action onNewData(ID const& id, api::interface::Delegate<ID>& delegate,
                   const uint8_t* const data, const uint32_t len)
  {
    int ret = 0;
    /*
     * Write the data in the input BIO.
     */
    BIO_write(bin, data, (int)len);
    /*
     * Only accept Ready state.
     */
    if (state != State::Ready) {
      return Action::Abort;
    }
    /*
     * Process the internal buffer as long as there is data available.
     */
    do {
      ret = SSL_read(ssl, rdbuf, 8192);
      /*
       * Handle partial data.
       */
      if (ret < 0) {
        if (SSL_get_error(ssl, ret) == SSL_ERROR_WANT_READ) {
          break;
        }
        log.error("SSLCTX", "SSL_read error: ", errorToString(ssl, ret));
        return Action::Abort;
      }
      /*
       * Handle shutdown.
       */
      if (ret == 0) {
        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SSL) {
          if (SSL_shutdown(ssl) != 1) {
            return Action::Abort;
          }
          log.debug("SSLCTX", "SSL_shutdown received");
          break;
        }
        log.error("SSLCTX", "SSL_read error: ", errorToString(ssl, ret));
        return Action::Abort;
      }
      /*
       * Notify the delegate.
       */
      if (delegate.onNewData(id, cookie, rdbuf, ret) != Action::Continue) {
        return Action::Abort;
      }
    } while (ret > 0);
    /*
     * Continue processing.
     */
    return Action::Continue;
  }

  /**
   * Processing incoming data and encrypt the response.
   */
  template<typename ID>
  Action onNewData(ID const& id, api::interface::Delegate<ID>& delegate,
                   const uint8_t* const data, const uint32_t len,
                   const uint32_t alen, uint8_t* const sdata, uint32_t& slen)
  {
    /*
     * Write the data in the input BIO.
     */
    BIO_write(bin, data, (int)len);
    /*
     * Check the connection's state.
     */
    switch (state) {
      /*
       * Closed is not a valid state.
       */
      case State::Closed: {
        return Action::Abort;
      }
      /*
       * Handle the SSL handshake.
       */
      case State::Connect: {
        int e = SSL_connect(ssl);
        switch (e) {
          case 0: {
            log.debug("SSLCTX", "SSL_connect error, controlled shutdown");
            return Action::Abort;
          }
          case 1: {
            log.debug("SSLCTX", "SSL_connect successful");
            state = State::Ready;
            return flush(alen, sdata, slen);
          }
          default: {
            if (SSL_get_error(ssl, e) == SSL_ERROR_WANT_READ) {
              return flush(alen, sdata, slen);
            }
            log.error("SSLCTX", "SSL_connect error: ", errorToString(ssl, e));
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
      case State::Accept: {
        int e = SSL_accept(ssl);
        switch (e) {
          case 0: {
            log.error("SSLCTX", "SSL_accept error: ", errorToString(ssl, e));
            return Action::Abort;
          }
          case 1: {
            log.debug("SSLCTX", "SSL_accept successful");
            state = State::Ready;
            return flush(alen, sdata, slen);
          }
          default: {
            if (SSL_get_error(ssl, e) == SSL_ERROR_WANT_READ) {
              return flush(alen, sdata, slen);
            }
            log.error("SSLCTX", "SSL_accept error: ", errorToString(ssl, e));
            return Action::Abort;
          }
        }
      }
      /*
       * Decrypt and pass the data to the delegate.
       */
      case State::Ready: {
        int ret = 0;
        uint32_t acc = 0;
        uint8_t out[alen];
        /*
         * Process the internal buffer as long as there is data available.
         */
        do {
          ret = SSL_read(ssl, rdbuf, 8192);
          /*
           * Handle partial data.
           */
          if (ret < 0) {
            if (SSL_get_error(ssl, ret) == SSL_ERROR_WANT_READ) {
              break;
            }
            log.error("SSLCTX", "SSL_read error: ", errorToString(ssl, ret));
            return Action::Abort;
          }
          /*
           * Handle shutdown.
           */
          if (ret == 0) {
            int err = SSL_get_error(ssl, ret);
            if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SSL) {
              if (SSL_shutdown(ssl) != 1) {
                return Action::Abort;
              }
              log.debug("SSLCTX", "SSL_shutdown received");
              break;
            }
            log.error("SSLCTX", "SSL_read error: ", errorToString(ssl, ret));
            return Action::Abort;
          }
          /*
           * Notify the delegate.
           */
          uint32_t rlen = 0;
          Action res =
            delegate.onNewData(id, cookie, rdbuf, ret, alen - acc, out, rlen);
          if (res != Action::Continue) {
            return abortOrClose(res, alen, sdata, slen);
          }
          /*
           * Update the accumulator and encrypt the data.
           */
          if (rlen + acc > alen) {
            rlen = alen - acc;
          }
          acc += rlen;
          SSL_write(ssl, out, (int)rlen);
        } while (ret > 0);
        /*
         * Flush the output.
         */
        return flush(alen, sdata, slen);
      }
      /*
       * Handle the last piece of shutdown.
       */
      case State::Shutdown: {
        if (SSL_shutdown(ssl) == 1) {
          return Action::Close;
        }
        return Action::Abort;
      }
    }
#if defined(__GNUC__) && defined(__GNUC_PREREQ)
    return Action::Continue;
#endif
  }

  /**
   * Return how much data is pending on the write channel.
   */
  inline size_t pending() { return BIO_ctrl_pending(bout); }

  /**
   * Handle delegate response.
   */
  Action abortOrClose(const Action r, const uint32_t alen, uint8_t* const sdata,
                      uint32_t& slen);

  /**
   * Flush any data pending in the write channel.
   */
  Action flush(const uint32_t alen, uint8_t* const sdata, uint32_t& slen);

  system::Logger& log;
  BIO* bin;
  BIO* bout;
  SSL* ssl;
  State state;
  void* cookie;
  bool blocked;
  uint8_t* rdbuf;
};

}
