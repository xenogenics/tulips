#pragma once

#include <tulips/api/Action.h>
#include <tulips/stack/tcpv4/Connection.h>
#include <cstdint>

namespace tulips::stack::tcpv4 {

class EventHandler
{
public:
  virtual ~EventHandler() = default;

  /*
   * Called when the connection c is connected.
   */
  virtual void onConnected(Connection& c) = 0;

  /*
   * Called when the connection c is aborted.
   */
  virtual void onAborted(Connection& c) = 0;

  /*
   * Called when the connection c has timed out.
   */
  virtual void onTimedOut(Connection& c) = 0;

  /*
   * Called when a full frame has been sent. Only if built with
   * TULIPS_ENABLE_LATENCY_MONITOR.
   */
  virtual void onSent(Connection& c) = 0;

  /*
   * Called when data for c has been acked.
   */
  virtual Action onAcked(Connection& c) = 0;

  /*
   * Called when data for c has been acked and a reponse can be sent.
   */
  virtual Action onAcked(Connection& c, const uint32_t alen,
                         uint8_t* const sdata, uint32_t& slen) = 0;

  /*
   * Called when new data on c has been received.
   */
  virtual Action onNewData(Connection& c, const uint8_t* const data,
                           const uint32_t len) = 0;

  /*
   * Called when new data on c has been received and a response can be sent.
   */
  virtual Action onNewData(Connection& c, const uint8_t* const data,
                           const uint32_t len, const uint32_t alen,
                           uint8_t* const sdata, uint32_t& slen) = 0;

  /*
   * Called when the connection c has been closed.
   */
  virtual void onClosed(Connection& c) = 0;
};

}
