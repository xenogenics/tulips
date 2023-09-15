#pragma once

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
    , m_pre(0)
    , m_lat(0)
    , m_history()
#endif
  {}

  /**
   * @return the state of the connection.
   */
  constexpr State state() const { return m_state; }

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

  void open(const uint8_t options)
  {
    m_state = Connection::State::Opened;
    m_opts = options;
  }

  void resolving() { m_state = State::Resolving; }

  void connecting() { m_state = State::Connecting; }

  void connected() { m_state = Connection::State::Connected; }

  void close()
  {
    m_state = Connection::State::Closed;
    m_host.reset();
  }

private:
#ifdef TULIPS_ENABLE_LATENCY_MONITOR
  using History = std::list<system::Clock::Value>;
#endif

  State m_state;
  uint8_t m_opts;
  std::optional<std::string> m_host;
#ifdef TULIPS_ENABLE_LATENCY_MONITOR
  size_t m_count;
  system::Clock::Value m_pre;
  system::Clock::Value m_lat;
  History m_history;
#endif
};

}
