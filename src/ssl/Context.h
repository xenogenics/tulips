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

const SSL_METHOD* getMethod(const Protocol type, const bool srv, long& flags);
std::string errorToString(const int err);

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
          const api::interface::Client::ID id, void* const cookie,
          const int keyfd);
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
    SSL_write(ssl, out, (int)rlen);
    /*
     * Flush the data.
     */
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
    ret = BIO_write(bin, data, (int)len);
    if (ret != (int)len) {
      log.error("SSL", "Failed to write ", len, "B in BIO");
      return Action::Abort;
    }
    /*
     * Only accept Ready state.
     */
    if (state != State::Ready && state != State::Shutdown) {
      log.error("SSL", "Received data in unexpected state");
      return Action::Abort;
    }
    /*
     * Process the internal buffer as long as there is data available.
     */
    do {
      ret = SSL_read(ssl, rdbf, buflen);
      /*
       * Handle error conditions.
       */
      if (ret <= 0) {
        auto err = SSL_get_error(ssl, ret);
        auto sht = SSL_get_shutdown(ssl);
        /*
         * Check the shutdown condition.
         */
        if (sht & SSL_RECEIVED_SHUTDOWN) {
          auto ret = SSL_shutdown(ssl);
          /*
           * Break if the shutdown completed.
           */
          if (ret == 1) {
            log.debug("SSL", "SSL_shutdown completed");
            return Action::Close;
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
          log.error("SSL", "SSL_shutdown failed (", ret, ", ", err, ")");
          return Action::Abort;
        }
        /*
         * Check if the context needs more data.
         */
        if (err == SSL_ERROR_WANT_READ) {
          break;
        }
        /*
         * Treat it as a read error otherwise.
         */
        else {
          auto m = errorToString(err);
          log.error("SSL", "SSL_read error: ", m, " (", err, ")");
          return Action::Abort;
        }
      }
      /*
       * Notify the delegate.
       */
      auto act = delegate.onNewData(id, cookie, rdbf, ret);
      if (act != Action::Continue) {
        return act;
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
    int ret = 0;
    /*
     * Write the data in the input BIO.
     */
    ret = BIO_write(bin, data, (int)len);
    if (ret != (int)len) {
      log.error("SSL", "Failed to write ", len, "B in BIO");
      return Action::Abort;
    }
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
        ret = SSL_connect(ssl);
        switch (ret) {
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
            auto err = SSL_get_error(ssl, ret);
            if (err == SSL_ERROR_WANT_READ) {
              return flush(alen, sdata, slen);
            }
            log.error("SSL", "SSL_connect error: ", errorToString(err));
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
        ret = SSL_accept(ssl);
        switch (ret) {
          case 0: {
            auto err = SSL_get_error(ssl, ret);
            log.error("SSL", "SSL_accept error: ", errorToString(err));
            return Action::Abort;
          }
          case 1: {
            log.debug("SSL", "SSL_accept successful");
            state = State::Ready;
            return flush(alen, sdata, slen);
          }
          default: {
            auto err = SSL_get_error(ssl, ret);
            if (err == SSL_ERROR_WANT_READ) {
              return flush(alen, sdata, slen);
            }
            log.error("SSL", "SSL_accept error: ", errorToString(err));
            return Action::Abort;
          }
        }
      }
      /*
       * Decrypt and pass the data to the delegate.
       */
      case State::Ready:
      case State::Shutdown: {
        uint32_t acc = 0;
        uint8_t out[alen];
        /*
         * Process the internal buffer as long as there is data available.
         */
        do {
          ret = SSL_read(ssl, rdbf, buflen);
          /*
           * Handle error conditions.
           */
          if (ret <= 0) {
            auto err = SSL_get_error(ssl, ret);
            auto sht = SSL_get_shutdown(ssl);
            /*
             * Check the shutdown condition.
             */
            if (sht & SSL_RECEIVED_SHUTDOWN) {
              auto ret = SSL_shutdown(ssl);
              /*
               * Break if the shutdown completed.
               */
              if (ret == 1) {
                log.debug("SSL", "SSL_shutdown completed");
                return Action::Close;
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
              log.error("SSL", "SSL_shutdown failed (", ret, ", ", err, ")");
              return Action::Abort;
            }
            /*
             * Check if the context needs more data.
             */
            if (err == SSL_ERROR_WANT_READ) {
              break;
            }
            /*
             * Treat it as a read error otherwise.
             */
            else {
              auto m = errorToString(err);
              log.error("SSL", "SSL_read error: ", m, " (", err, ")");
              return Action::Abort;
            }
          }
          /*
           * Notify the delegate.
           */
          uint32_t rlen = 0;
          uint32_t wlen = alen - acc;
          auto act = delegate.onNewData(id, cookie, rdbf, ret, wlen, out, rlen);
          if (act != Action::Continue) {
            return abortOrClose(act, alen, sdata, slen);
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
           *
           * NOTE(xrg): with BIO_mem, the write always succeeds if len > 0.
           */
          acc += rlen;
          SSL_write(ssl, out, (int)rlen);
        } while (ret > 0);
        /*
         * Flush the output.
         */
        return flush(alen, sdata, slen);
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

  /**
   * Save the keys into a file.
   */
  void saveKeys(std::string_view prefix);

  system::Logger& log;
  size_t buflen;
  api::interface::Client::ID id;
  void* cookie;
  int keyfd;
  BIO* bin;
  BIO* bout;
  SSL* ssl;
  State state;
  bool blocked;
  uint8_t* rdbf;
};

}
