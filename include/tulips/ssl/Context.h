#pragma once

#include "BIO.h"
#include <tulips/api/Action.h>
#include <tulips/api/Interface.h>
#include <tulips/ssl/Protocol.h>
#include <tulips/system/Clock.h>
#include <tulips/system/Logger.h>
#include <string>
#include <openssl/bio.h>
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
  static constexpr const size_t BUFLEN = 32768;

  using Delegate = api::interface::Client::Delegate;
  using ID = api::interface::Client::ID;

  enum class State
  {
    Closed,
    Open,
    Connecting,
    Connected,
    Accepting,
    Ready,
    Shutdown
  };

  /**
   * Open the context.
   */
  void open(SSL_CTX* const ctx, const ID id, void* const cookie,
            const system::Clock::Value ts, const int keyfd);

  /**
   * Close the context.
   */
  void close();

  /**
   * Process pending data on ACK.
   */
  Action onAcked(system::Logger& log, ID const& id, Delegate& delegate,
                 const system::Clock::Value ts, const uint32_t alen,
                 uint8_t* const sdata, uint32_t& slen);

  /**
   * Processing incoming data and encrypt the response.
   */
  Action onNewData(system::Logger& log, ID const& id, Delegate& delegate,
                   const uint8_t* const data, const uint32_t len,
                   const system::Clock::Value ts);

  /**
   * Processing incoming data and encrypt the response.
   */
  Action onNewData(system::Logger& log, ID const& id, Delegate& delegate,
                   const uint8_t* const data, const uint32_t len,
                   const system::Clock::Value ts, const uint32_t alen,
                   uint8_t* const sdata, uint32_t& slen);

  /**
   * Return how much data is pending on the read channel.
   */
  inline size_t pendingRead() { return BIO_pending(m_bout); }

  /**
   * Return how much data is pending on the write channel.
   */
  inline size_t pendingWrite() { return BIO_pending(m_bin); }

  /**
   * Handle delegate response.
   */
  Action abortOrClose(system::Logger& log, const Action r, const uint32_t alen,
                      uint8_t* const sdata, uint32_t& slen);

  /**
   * Flush any data pending in the write channel.
   */
  Action flush(system::Logger& log, const uint32_t alen, uint8_t* const sdata,
               uint32_t& slen);

  ID m_id;
  void* m_cookie;
  system::Clock::Value m_ts;
  int m_keyfd;
  BIO* m_bin;
  BIO* m_bout;
  SSL* m_ssl;
  State m_state;
  bool m_blocked;
  uint8_t* m_rdbf;
};

}
