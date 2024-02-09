#pragma once

#include <tulips/api/Action.h>
#include <tulips/stack/tcpv4/Connection.h>
#include <tulips/system/Clock.h>
#include <cstdint>

namespace tulips::stack::tcpv4 {

class EventHandler
{
public:
  /**
   * Timestamp type alias.
   */
  using Timestamp = system::Clock::Epoch;

  /**
   * Default destructor.
   */
  virtual ~EventHandler() = default;

  /**
   * Called when the connection c is connected.
   *
   * @param c the current connection
   * @param ts the timestamp of the event
   */
  virtual void onConnected(Connection& c, const Timestamp ts) = 0;

  /**
   * Called when the connection c is aborted.
   *
   * @param c the current connection
   * @param ts the timestamp of the event
   */
  virtual void onAborted(Connection& c, const Timestamp ts) = 0;

  /**
   * Called when the connection c has timed out.
   *
   * @param c the current connection
   * @param ts the timestamp of the event
   */
  virtual void onTimedOut(Connection& c, const Timestamp ts) = 0;

  /**
   * Called when a full frame has been sent. Only if built with
   * TULIPS_ENABLE_LATENCY_MONITOR.
   *
   * @param c the current connection
   * @param ts the timestamp of the event
   */
  virtual void onSent(Connection& c, const Timestamp ts) = 0;

  /**
   * Called when data for c has been acked.
   *
   * @param c the current connection
   * @param ts the timestamp of the event
   * @param savl the amount of bytes available in the send buffer
   * @param sdat the send buffer
   * @param slen the amount of data written in the send buffer
   *
   * @return the action to take once the callback completed
   */
  virtual Action onAcked(Connection& c, const Timestamp ts, const uint32_t savl,
                         uint8_t* const sdat, uint32_t& slen) = 0;

  /**
   * Called when new data on c has been received.
   *
   * @param c the current connection
   * @param rdat the buffer with the received data
   * @param rlen the length of the data in the receive buffer
   * @param rdts the timestamp of the event
   * @param savl the amount of bytes available in the send buffer
   * @param sdat the send buffer
   * @param slen the amount of data written in the send buffer
   *
   * @return the action to take once the callback completed
   */
  virtual Action onNewData(Connection& connection, const uint8_t* const rdat,
                           const uint32_t rlen, const Timestamp rdts,
                           const uint32_t savl, uint8_t* const sdat,
                           uint32_t& slen) = 0;

  /**
   * Called when the connection c has been closed.
   *
   * @param c the current connection
   * @param rdts the timestamp of the event
   */
  virtual void onClosed(Connection& c, const Timestamp ts) = 0;
};

}
