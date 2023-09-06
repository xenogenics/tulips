#pragma once

#include <tulips/api/Action.h>
#include <tulips/api/Status.h>
#include <tulips/stack/TCPv4.h>
#include <tulips/stack/tcpv4/Connection.h>
#include <tulips/system/Clock.h>
#include <tulips/transport/Device.h>
#include <cstdint>

namespace tulips::api::interface {

/**
 * Generic delegate class definition.
 */
template<typename ID>
struct Delegate
{
  /*
   * Virtual default destructor.
   */
  virtual ~Delegate() = default;

  /*
   * Callback when a connection has been established.
   *
   * @param id the connection's handle.
   * @param cookie a global user-defined state.
   * @param opts a reference to the connection's options to be altered.
   *
   * @return a user-defined state for the connection.
   */
  virtual void* onConnected(ID const& id, void* const cookie) = 0;

  /**
   * Callback when a packet has been acked. The delegate is not permitted
   * to send a response.
   *
   * @param id the connection's handle.
   * @param cookie the connection's user-defined state.
   *
   * @return an action to be taken upon completion of the callback.
   */
  virtual Action onAcked(ID const& id, void* const cookie) = 0;

  /**
   * Callback when a packet has been acked. The delegate is permitted to
   * send a response.
   *
   * @param id the connection's handle.
   * @param cookie the connection's user-defined state.
   * @param alen the amount of data available in the response frame.
   * @param sdata a pointer to the response area in the frame.
   * @param slen the effective size of the response data written.
   *
   * @return an action to be taken upon completion of the callback.
   */
  virtual Action onAcked(ID const& id, void* const cookie, const uint32_t alen,
                         uint8_t* const sdata, uint32_t& slen) = 0;

  /**
   * Callback when new data has been received. The delegate is not permitted
   * to send a response.
   *
   * @param id the connection's handle.
   * @param cookie the connection's user-defined state.
   * @param data the received data.
   * @param len the length of the received data.
   *
   * @return an action to be taken upon completion of the callback.
   */
  virtual Action onNewData(ID const& id, void* const cookie,
                           const uint8_t* const data, const uint32_t len) = 0;

  /**
   * Callback when new data has been received. The delegate is permitted to
   * send a response.
   *
   * @param id the connection's handle.
   * @param cookie the connection's user-defined state.
   * @param data the received data.
   * @param len the length of the received data.
   * @param alen the amount of data available in the response frame.
   * @param sdata a pointer to the response area in the frame.
   * @param slen the effective size of the response data written.
   *
   * @return an action to be taken upon completion of the callback.
   */
  virtual Action onNewData(ID const& id, void* const cookie,
                           const uint8_t* const data, const uint32_t len,
                           const uint32_t alen, uint8_t* const sdata,
                           uint32_t& slen) = 0;

  /*
   * Callback when a connection is closed.
   *
   * @param id the connection's handle.
   * @param cookie the connection's user-defined state.
   */
  virtual void onClosed(ID const& id, void* const cookie) = 0;
};

/**
 * Client class interface.
 */
class Client : public transport::Processor
{
public:
  using ID = uint16_t;
  using Delegate = interface::Delegate<ID>;

  static constexpr ID DEFAULT_ID = -1;

  /**
   * Open a new connection.
   *
   * @param id the new connection handle.
   *
   * @return the status of the operation.
   */
  virtual Status open(ID& id) { return open(0, id); }

  /**
   * Open a new connection, with options.
   *
   * @param options the TCP options to use.
   * @param id the new connection handle.
   *
   * @return the status of the operation.
   */
  virtual Status open(const uint8_t options, ID& id) = 0;

  /**
   * Connect a handle to a remote server using its IP and port.
   *
   * @param id the connection handle.
   * @param ripaddr the remote server's IP address.
   * @param rport the remote server's port.
   *
   * @return the status of the operation.
   */
  virtual Status connect(const ID id, stack::ipv4::Address const& ripaddr,
                         const stack::tcpv4::Port rport) = 0;

  /**
   * Abort a connection.
   *
   * @param id the connection's handle.
   *
   * @return the status of the operation.
   */
  virtual Status abort(const ID id) = 0;

  /**
   * Close a connection.
   *
   * @param id the connection's handle.
   *
   * @return the status of the operation.
   */
  virtual Status close(const ID id) = 0;

  /*
   * Check if a connection is closed or not.
   *
   * @param id the connection's handle.
   *
   * @return whether or not the connection is closed. True if the connection
   * does not exist.
   */
  virtual bool isClosed(const ID id) const = 0;

  /**
   * Send data through a connection. May send partial data.
   *
   * @param id the connection's handle.
   * @param len the length of the data.
   * @param data the data.
   * @param off the amount of data actually written.
   *
   * @return the status of the operation.
   */
  virtual Status send(const ID id, const uint32_t len,
                      const uint8_t* const data, uint32_t& off) = 0;

  /**
   * Get average latency for a connection.
   *
   * @param id the connection's handle.
   *
   * @return the average latency of the connection.
   */
  virtual system::Clock::Value averageLatency(const ID id) = 0;
};

/**
 * Server class interface.
 */
class Server : public transport::Processor
{
public:
  using ID = stack::tcpv4::Connection::ID;
  using Delegate = interface::Delegate<ID>;

  static constexpr ID DEFAULT_ID = -1;

  /**
   * Instruct the server to listen to a particular TCP port.
   *
   * @param port the port to listen too.
   * @param cookie user-defined data attached to the port.
   */
  virtual void listen(const stack::tcpv4::Port port, void* cookie) = 0;

  /**
   * Instruct the server to stop listening to a port.
   *
   * @param port the port to forget.
   */
  virtual void unlisten(const stack::tcpv4::Port port) = 0;

  /**
   * Set TCP options on a given connection.
   *
   * @param id the connection's handle.
   * @param options the options to set.
   *
   * @return the status of the operation.
   */
  virtual void setOptions(const ID id, const uint8_t options) = 0;

  /**
   * Clear TCP options on a given connection.
   *
   * @param id the connection's handle.
   * @param options the options to clear.
   *
   * @return the status of the operation.
   */
  virtual void clearOptions(const ID id, const uint8_t options) = 0;

  /**
   * Close a connection.
   *
   * @param id the connection's handle.
   *
   * @return the status of the operation.
   */
  virtual Status close(const ID id) = 0;

  /*
   * Check if a connection is closed or not.
   *
   * @param id the connection's handle.
   *
   * @return whether or not the connection is closed. True if the connection
   * does not exist.
   */
  virtual bool isClosed(const ID id) const = 0;

  /**
   * Send data through a connection. May send partial data.
   *
   * @param id the connection's handle.
   * @param len the length of the data.
   * @param data the data.
   * @param off the amount of data actually written.
   *
   * @return the status of the operation.
   */
  virtual Status send(const ID id, const uint32_t len,
                      const uint8_t* const data, uint32_t& off) = 0;
};

}
