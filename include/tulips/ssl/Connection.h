#pragma once

#include <tulips/api/Action.h>
#include <tulips/api/Interface.h>
#include <tulips/ssl/BIO.h>
#include <tulips/ssl/Protocol.h>
#include <tulips/system/Clock.h>
#include <tulips/system/Logger.h>
#include <optional>
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
 * SSL connection.
 */

class Connection
{
public:
  using ALP = api::interface::Client::ApplicationLayerProtocol;
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
   * Open the connection.
   */
  void open(SSL_CTX* const ctx, const ID id, void* const cookie,
            const system::Clock::Value ts, const int keyfd);

  /**
   * Open the connection.
   */
  void accept(SSL_CTX* const ctx, const ID id, void* const cookie,
              const system::Clock::Value ts, const int keyfd);

  /**
   * Close the connection.
   */
  void close();

  /**
   * Handshake.
   */
  Status connect(system::Logger& log, ID const& id,
                 std::optional<std::string> const& hostname, const ALP alp);

  /**
   * Shutdown.
   */
  Status shutdown(system::Logger& log, ID const& id);

  /**
   * Process pending data on ACK.
   */
  Action onAcked(system::Logger& log, ID const& id, Delegate& delegate,
                 const system::Clock::Value ts, const uint32_t savl,
                 uint8_t* const sdat, uint32_t& slen);

  /**
   * Processing incoming data and encrypt the response.
   */
  Action onNewData(system::Logger& log, ID const& id, Delegate& delegate,
                   const uint8_t* const rdat, const uint32_t rlen,
                   const system::Clock::Value ts, const uint32_t savl,
                   uint8_t* const sdat, uint32_t& slen);

  /**
   * Return the connection's state.
   */
  constexpr State state() const { return m_state; }

  /**
   * Move the connection to ready.
   */
  void setReady() { m_state = State::Ready; }

  /**
   * Return the connection's cookie.
   */
  constexpr void* cookie() const { return m_cookie; }

  /**
   * Set the connection's cookie.
   */
  void setCookie(void* const cookie) { m_cookie = cookie; }

  /**
   * Return the connection's timestamp.
   */
  constexpr system::Clock::Value timestamp() const { return m_ts; }

  /**
   * Return the key file's descriptor.
   */
  constexpr int keyFileDescriptor() const { return m_keyfd; }

  /**
   * Return how much data is pending on the read channel.
   */
  inline size_t pendingRead() { return BIO_pending(m_bout); }

  /**
   * Return the start pointer on the read channel.
   */
  const uint8_t* readAt() const { return ssl::bio::readAt(m_bout); }

  /**
   * Return how much data is pending on the write channel.
   */
  inline size_t pendingWrite() { return BIO_pending(m_bin); }

  /**
   * Consume some amount of data on the read channel.
   */
  void consume(const size_t len) { ssl::bio::skip(m_bout, len); }

  /**
   * Write data.
   */
  Status write(system::Logger& log, ID const& id, const uint32_t len,
               const uint8_t* const data);

  /**
   * Return the blocked flag.
   */
  constexpr bool blocked() const { return m_blocked; }

  /**
   * Set the blocked flag.
   */
  void setBlocked(const bool v) { m_blocked = v; }

private:
  static constexpr const size_t BUFLEN = 32768;

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

  /**
   * Initialize the connection's state.
   */
  void initialize(SSL_CTX* const ctx, const ID id, void* const cookie,
                  const system::Clock::Value ts, const int keyfd);

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
