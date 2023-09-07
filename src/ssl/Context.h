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
          const api::interface::Client::ID id, void* const cookie);
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
    if (state != State::Ready && state != State::Shutdown) {
      log.error("SSL", "Received data in unexpected state");
      return Action::Abort;
    }
    /*
     * Check the connection's state.
     */
    switch (state) {
      /*
       * Decrypt and pass the data to the delegate.
       */
      case State::Ready: {
        /*
         * Process the internal buffer as long as there is data available.
         */
        do {
          ret = SSL_read(ssl, rdbf, buflen);
          /*
           * Handle partial data.
           */
          if (ret < 0) {
            if (SSL_get_error(ssl, ret) == SSL_ERROR_WANT_READ) {
              break;
            }
            log.error("SSL", "SSL_read error: ", errorToString(ssl, ret));
            return Action::Abort;
          }
          /*
           * Check the error if we received no data.
           */
          if (ret == 0) {
            int err = SSL_get_error(ssl, ret);
            /*
             * Check the shutdown condition.
             */
            if (err == SSL_ERROR_ZERO_RETURN) {
              auto ret = SSL_shutdown(ssl);
              /*
               * Break if the shutdown completed.
               */
              if (ret == 1) {
                log.debug("SSL", "- SSL_shutdown received");
                break;
              }
              /*
               * Break if the shutdown needs more data.
               */
              int err = SSL_get_error(ssl, ret);
              if (err == SSL_ERROR_WANT_READ) {
                break;
              }
              /*
               * Abort otherwise.
               */
              log.error("SSL", "- SSL_shutdown failed (", ret, ", ", err, ")");
              return Action::Abort;
            }
            /*
             * Treat it as a read error otherwise.
             */
            else {
              log.error("SSL", "SSL_read error: ", errorToString(ssl, ret));
              return Action::Abort;
            }
          }
          /*
           * Notify the delegate.
           */
          if (delegate.onNewData(id, cookie, rdbf, ret) != Action::Continue) {
            return Action::Abort;
          }
        } while (ret > 0 && state == State::Ready);
        /*
         * Continue processing.
         */
        return Action::Continue;
      }
      /*
       * Handle the last piece of shutdown.
       */
      case State::Shutdown: {
        auto ret = SSL_shutdown(ssl);
        if (ret == 1) {
          log.error("SSL", "SSL_shutdown completed");
          return Action::Close;
        } else {
          int err = SSL_get_error(ssl, ret);
          if (err == SSL_ERROR_WANT_READ) {
            return Action::Continue;
          }
          log.error("SSL", "SSL_shutdown failed (", ret, ", ", err, ")");
          return Action::Abort;
        }
      }
      default: {
        return Action::Abort;
      }
    }
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
        log.error("SSL", "Received data on a closed context");
        return Action::Abort;
      }
      /*
       * Handle the SSL handshake.
       */
      case State::Connect: {
        int e = SSL_connect(ssl);
        switch (e) {
          case 0: {
            log.error("SSL", "SSL_connect error, controlled shutdown");
            return Action::Abort;
          }
          case 1: {
            log.debug("SSL", "SSL_connect successful");
            state = State::Ready;
            return flush(alen, sdata, slen);
          }
          default: {
            if (SSL_get_error(ssl, e) == SSL_ERROR_WANT_READ) {
              return flush(alen, sdata, slen);
            }
            log.error("SSL", "SSL_connect error: ", errorToString(ssl, e));
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
            log.error("SSL", "SSL_accept error: ", errorToString(ssl, e));
            return Action::Abort;
          }
          case 1: {
            log.debug("SSL", "SSL_accept successful");
            state = State::Ready;
            return flush(alen, sdata, slen);
          }
          default: {
            if (SSL_get_error(ssl, e) == SSL_ERROR_WANT_READ) {
              return flush(alen, sdata, slen);
            }
            log.error("SSL", "SSL_accept error: ", errorToString(ssl, e));
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
          ret = SSL_read(ssl, rdbf, buflen);
          /*
           * Handle partial data.
           */
          if (ret < 0) {
            if (SSL_get_error(ssl, ret) == SSL_ERROR_WANT_READ) {
              break;
            }
            log.error("SSL", "SSL_read error: ", errorToString(ssl, ret));
            return Action::Abort;
          }
          /*
           * Check the error if we received no data.
           */
          if (ret == 0) {
            int err = SSL_get_error(ssl, ret);
            /*
             * Check the shutdown condition.
             */
            if (err == SSL_ERROR_ZERO_RETURN) {
              auto ret = SSL_shutdown(ssl);
              /*
               * Break if the shutdown completed.
               */
              if (ret == 1) {
                log.debug("SSL", "+ SSL_shutdown completed");
                break;
              }
              /*
               * Break if the shutdown needs more data.
               */
              int err = SSL_get_error(ssl, ret);
              if (err == SSL_ERROR_WANT_READ) {
                break;
              }
              /*
               * Abort otherwise.
               */
              log.error("SSL", "+ SSL_shutdown failed (", ret, ", ", err, ")");
              return Action::Abort;
            }
            /*
             * Treat it as a read error otherwise.
             */
            else {
              log.error("SSL", "SSL_read error: ", errorToString(ssl, ret));
              return Action::Abort;
            }
          }
          /*
           * Notify the delegate.
           */
          uint32_t rlen = 0;
          uint32_t wlen = alen - acc;
          auto res = delegate.onNewData(id, cookie, rdbf, ret, wlen, out, rlen);
          if (res != Action::Continue) {
            return abortOrClose(res, alen, sdata, slen);
          }
          /*
           * Cap the written amount.
           */
          if (rlen + acc > alen) {
            rlen = alen - acc;
          }
          /*
           * Update the accumulator and encrypt the data.
           */
          acc += rlen;
          SSL_write(ssl, out, (int)rlen);
        } while (ret > 0 && state == State::Ready);
        /*
         * Flush the output.
         */
        return flush(alen, sdata, slen);
      }
      /*
       * Handle the last piece of shutdown.
       */
      case State::Shutdown: {
        auto ret = SSL_shutdown(ssl);
        if (ret == 1) {
          log.error("SSL", "SSL_shutdown completed");
          return Action::Close;
        } else {
          int err = SSL_get_error(ssl, ret);
          if (err == SSL_ERROR_WANT_READ) {
            return flush(alen, sdata, slen);
          }
          log.error("SSL", "+ SSL_shutdown failed (", ret, ", ", err, ")");
          return Action::Abort;
        }
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
  size_t buflen;
  api::interface::Client::ID id;
  void* cookie;
  BIO* bin;
  BIO* bout;
  SSL* ssl;
  State state;
  bool blocked;
  uint8_t* rdbf;
};

}
