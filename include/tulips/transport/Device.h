#pragma once

#include <tulips/api/Status.h>
#include <tulips/stack/IPv4.h>
#include <tulips/system/Logger.h>
#include <tulips/transport/Processor.h>
#include <tulips/transport/Producer.h>
#include <memory>
#include <string>
#include <unistd.h>

namespace tulips {

namespace stack::ethernet {
class Address;
}

namespace stack::ipv4 {
class Address;
}

namespace transport {

class Device : public Producer
{
public:
  enum Hint
  {
    VALIDATE_IP_CSUM = 0x1,
    VALIDATE_L4_CSUM = 0x2,
  };

  using Ref = std::unique_ptr<Device>;

  /*
   * The DEFAULT_MTU takes the value of the maximum size for the payload of an
   * Ethernet frame. It does NOT include the ethernet header.
   */
  static constexpr uint32_t DEFAULT_MTU = 1500;

  Device(system::Logger& log, std::string_view name)
    : m_log(log), m_name(name), m_hints(0)
  {}
  ~Device() override = default;

  /**
   * @return the device's name.
   */
  virtual std::string_view name() const { return m_name; }

  /**
   * @return the device's hardware address.
   */
  virtual stack::ethernet::Address const& address() const = 0;

  /**
   * @return the device's MTU.
   */
  virtual uint32_t mtu() const = 0;

  /**
   * Listen to a particular (simplified) flow signature.
   *
   * @param laddr the local IP address.
   * @param proto the IPv4 protocol.
   * @param lport the local L4 port.
   *
   * @return the status of the operation.
   */
  Status listen(const stack::ipv4::Protocol proto,
                stack::ipv4::Address const& laddr, const uint16_t lport)
  {
    return listen(proto, laddr, lport, stack::ipv4::Address::ANY, 0);
  }

  /**
   * Listen to a particular flow signature.
   *
   * @param proto the IPv4 protocol.
   * @param laddr the local IP address.
   * @param lport the local L4 port.
   * @param raddr the remote IP address.
   * @param rport the remote L4 port.
   *
   * @return the status of the operation.
   */
  virtual Status listen(const stack::ipv4::Protocol proto,
                        stack::ipv4::Address const& laddr, const uint16_t lport,
                        stack::ipv4::Address const& raddr,
                        const uint16_t rport) = 0;

  /**
   * Stop listening to a particular (simplified) flow signature.
   *
   * @param proto the IPv4 protocol.
   * @param laddr the local IP address.
   * @param lport the local L4 port.
   */
  void unlisten(const stack::ipv4::Protocol proto,
                stack::ipv4::Address const& laddr, const uint16_t lport)
  {
    return unlisten(proto, laddr, lport, stack::ipv4::Address::ANY, 0);
  }

  /**
   * Ask the device to stop listening to a particular flow signature.
   *
   * @param proto the IPv4 protocol.
   * @param laddr the local IP address.
   * @param lport the local L4 port.
   * @param raddr the remote IP address.
   * @param rport the remote L4 port.
   */
  virtual void unlisten(const stack::ipv4::Protocol proto,
                        stack::ipv4::Address const& laddr, const uint16_t lport,
                        stack::ipv4::Address const& raddr,
                        const uint16_t rport) = 0;

  /**
   * Poll the device input queues for activity. Call upon the rcv processor
   * when data is available. This operations is non-blocking.
   *
   * @param rcv the processor to handle the incoming data.
   *
   * @return the status of the operation.
   */
  virtual Status poll(Processor& rcv) = 0;

  /**
   * Wait on the device input queues for new data with a ns timeout. Call upon
   * the rcv processor when data is available. This operation is blocking
   *
   * @param rcv the processor to handle the incoming data.
   * @param ns the timeout of the operation.
   *
   * @return the status of the operation.
   */
  virtual Status wait(Processor& rcv, const uint64_t ns) = 0;

  /**
   * @return the size of a receive buffer as a power of 2.
   * @note maps directly to TCP's window scale.
   */
  virtual uint8_t receiveBufferLengthLog2() const = 0;

  /*
   * @return the number of receive buffers available.
   * @note maps directly to TCP's window size.
   */
  virtual uint16_t receiveBuffersAvailable() const = 0;

  /**
   * Identify a send buffer.
   *
   * @param buf the send buffer to indentify.
   *
   * @return true if the buffer is owned by the device.
   */
  virtual bool identify(const uint8_t* const buf) const = 0;

  /**
   * Give a hint to the device.
   *
   * @param h the hint to give.
   */
  void hint(const Hint h) { m_hints |= h; }

protected:
  system::Logger& m_log;
  std::string m_name;
  uint16_t m_hints;
};

}

}
