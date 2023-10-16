#pragma once

#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/system/Logger.h>
#include <tulips/transport/Device.h>
#include <list>
#include <memory>
#include <string>
#include <pthread.h>

namespace tulips::transport::tap {

class Device : public transport::Device
{
public:
  /*
   * Allocator.
   */

  static Ref allocate(system::Logger& log, std::string_view name)
  {
    return std::make_unique<Device>(log, name);
  }

  /*
   * Constructor and destructor.
   */

  Device(system::Logger& log, std::string_view devname);
  ~Device() override;

  /*
   * Device interface.
   */

  stack::ethernet::Address const& address() const override { return m_address; }

  Status listen(UNUSED const stack::ipv4::Protocol proto,
                UNUSED stack::ipv4::Address const& laddr,
                UNUSED const uint16_t lport,
                UNUSED stack::ipv4::Address const& raddr,
                UNUSED const uint16_t rport) override
  {

    return Status::Ok;
  }

  void unlisten(UNUSED const stack::ipv4::Protocol proto,
                UNUSED stack::ipv4::Address const& laddr,
                UNUSED const uint16_t lport,
                UNUSED stack::ipv4::Address const& raddr,
                UNUSED const uint16_t rport) override
  {}

  Status prepare(uint8_t*& buf) override;
  Status commit(const uint16_t len, uint8_t* const buf,
                const uint16_t mss = 0) override;
  Status release(uint8_t* const buf) override;

  Status poll(Processor& proc) override;
  Status wait(Processor& proc, const uint64_t ns) override;

  uint32_t mtu() const override { return m_mtu; }

  uint32_t mss() const override { return m_mtu + stack::ethernet::HEADER_LEN; }

  uint8_t receiveBufferLengthLog2() const override { return 11; }

  uint16_t receiveBuffersAvailable() const override { return 32; }

  bool identify([[maybe_unused]] const uint8_t* const buf) const override
  {
    return true;
  }

protected:
  stack::ethernet::Address m_address;
  int m_fd;
  uint32_t m_mtu;
  std::list<uint8_t*> m_buffers;
};

}
