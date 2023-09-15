#pragma once

#include <tulips/transport/Device.h>

namespace tulips::transport::erase {

class Device : public transport::Device
{
public:
  Device(system::Logger& log, transport::Device& device);

  std::string_view name() const override { return m_device.name(); }

  stack::ethernet::Address const& address() const override
  {
    return m_device.address();
  }

  stack::ipv4::Address const& ip() const override { return m_device.ip(); }

  stack::ipv4::Address const& gateway() const override
  {
    return m_device.gateway();
  }

  stack::ipv4::Address const& netmask() const override
  {
    return m_device.netmask();
  }

  Status listen(UNUSED const stack::ipv4::Protocol proto,
                UNUSED const uint16_t lport,
                UNUSED stack::ipv4::Address const& raddr,
                UNUSED const uint16_t rport) override
  {
    return Status::Ok;
  }

  void unlisten(UNUSED const stack::ipv4::Protocol proto,
                UNUSED const uint16_t lport,
                UNUSED stack::ipv4::Address const& raddr,
                UNUSED const uint16_t rport) override
  {}

  Status poll(Processor& proc) override;
  Status wait(Processor& proc, const uint64_t ns) override;

  uint32_t mtu() const override { return m_device.mtu(); }

  uint32_t mss() const override { return m_device.mss(); }

  uint8_t receiveBufferLengthLog2() const override
  {
    return m_device.receiveBufferLengthLog2();
  }

  uint16_t receiveBuffersAvailable() const override
  {
    return m_device.receiveBuffersAvailable();
  }

  Status prepare(uint8_t*& buf) override;
  Status commit(const uint16_t len, uint8_t* const buf,
                const uint16_t mss = 0) override;
  Status release(uint8_t* const buf) override;

private:
  transport::Device& m_device;
};

}
