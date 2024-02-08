#pragma once

#include "tulips/system/Clock.h"
#include <tulips/api/Interface.h>
#include <tulips/stack/tcpv4/Connection.h>
#include <functional>
#include <list>
#include <optional>

namespace tulips::api {

class Connection
{
public:
  /**
   * Application layer protocol.
   */
  using ApplicationLayerProtocol = interface::Client::ApplicationLayerProtocol;

  /**
   * Connection state type.
   */
  enum class State
  {
    Closed,
    Opened,
#ifdef TULIPS_ENABLE_ARP
    Resolving,
#endif
    Connecting,
    Connected
  };

  /**
   * Constructor.
   */
  Connection()
    : m_state(State::Closed)
    , m_opts(0)
    , m_host()
#ifdef TULIPS_ENABLE_LATENCY_MONITOR
    , m_count(0)
    , m_lat(0)
    , m_history()
#endif
  {}

  /**
   * @return the state of the connection.
   */
  constexpr State state() const { return m_state; }

  /**
   * Get the connection's ALP.
   */
  constexpr auto applicationLayerProtocol() const { return m_alpn; }

  /**
   * Get the connection's options.
   */
  constexpr auto options() const { return m_opts; }

  /**
   * Set the hostname associated with the connection.
   */
  void setHostName(std::string_view hostname) { m_host.emplace(hostname); }

  /**
   * Get the hostname associated with the connection.
   */
  constexpr auto const& hostName() const { return m_host; }

  /*
   * State management.
   */

  void open(const ApplicationLayerProtocol alpn, const uint8_t options)
  {
    m_state = Connection::State::Opened;
    m_alpn = alpn;
    m_opts = options;
  }

#ifdef TULIPS_ENABLE_ARP
  void resolving() { m_state = State::Resolving; }
#endif

  void connecting() { m_state = State::Connecting; }

  void connected() { m_state = Connection::State::Connected; }

  void close()
  {
    m_state = Connection::State::Closed;
    m_host.reset();
    m_alpn = ApplicationLayerProtocol::None;
    m_opts = 0;
  }

  /*
   * Latency monitoring.
   */

#ifdef TULIPS_ENABLE_LATENCY_MONITOR
  void markOnSent(const system::Clock::Value ts) { m_history.push_back(ts); }

  void markOnAcked()
  {
    m_count += 1;
    m_lat += system::Clock::read() - m_history.front();
    m_history.pop_front();
  }

  uint64_t latency()
  {
    uint64_t res = 0;
    if (m_count > 0) {
      res = m_lat / m_count;
    }
    m_lat = 0;
    m_count = 0;
    return res;
  }
#endif

private:
#ifdef TULIPS_ENABLE_LATENCY_MONITOR
  using History = std::list<system::Clock::Value>;
#endif

  State m_state;
  interface::Client::ApplicationLayerProtocol m_alpn;
  uint8_t m_opts;
  std::optional<std::string> m_host;
#ifdef TULIPS_ENABLE_LATENCY_MONITOR
  size_t m_count;
  system::Clock::Value m_lat;
  History m_history;
#endif
};

}
