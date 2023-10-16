#pragma once

#include <tulips/transport/Device.h>
#include <string>
#include <vector>

namespace tulips::transport::bond {

class Device : public transport::Device
{
public:
  /*
   * Allocator.
   */

  static Ref allocate(system::Logger& log,
                      std::vector<transport::Device::Ref> devices,
                      std::string_view name)
  {
    return std::make_unique<Device>(log, std::move(devices), name);
  }

  /*
   * Constructor.
   */

  Device(system::Logger& log, std::vector<transport::Device::Ref> devices,
         std::string_view name);

  /*
   * Device interface.
   */

  std::string_view name() const override { return m_devices.front()->name(); }

  stack::ethernet::Address const& address() const override
  {
    return m_devices.front()->address();
  }

  Status listen(const stack::ipv4::Protocol proto,
                stack::ipv4::Address const& laddr, const uint16_t lport,
                stack::ipv4::Address const& raddr,
                const uint16_t rport) override;

  void unlisten(const stack::ipv4::Protocol proto,
                stack::ipv4::Address const& laddr, const uint16_t lport,
                stack::ipv4::Address const& raddr,
                const uint16_t rport) override;

  Status poll(Processor& proc) override;
  Status wait(Processor& proc, const uint64_t ns) override;

  uint32_t mtu() const override { return m_devices.front()->mtu(); }
  uint32_t mss() const override { return m_devices.front()->mss(); }

  uint8_t receiveBufferLengthLog2() const override
  {
    return m_devices.front()->receiveBufferLengthLog2();
  }

  bool identify(const uint8_t* const buf) const override;

  uint16_t receiveBuffersAvailable() const override;

  Status prepare(uint8_t*& buf) override;
  Status commit(const uint16_t len, uint8_t* const buf,
                const uint16_t mss = 0) override;
  Status release(uint8_t* const buf) override;

private:
  using Devices = std::vector<transport::Device::Ref>;

  Devices m_devices;
  size_t m_listens;
  size_t m_prepares;
};

}
