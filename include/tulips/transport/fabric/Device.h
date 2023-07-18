#pragma once

#include <tulips/transport/Device.h>
#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/system/Compiler.h>
#include <cstdlib>
#include <limits>
#include <string>

namespace tulips::transport::fabric {

class Device : public transport::Device
{
public:
  Device(const uint16_t nbuf);
  Device(std::string const& ifn, const uint16_t nbuf);
  ~Device() override = default;

  stack::ethernet::Address const& address() const override { return m_address; }

  stack::ipv4::Address const& ip() const override { return m_ip; }

  stack::ipv4::Address const& gateway() const override { return m_dr; }

  stack::ipv4::Address const& netmask() const override { return m_nm; }

  Status listen(const uint16_t UNUSED port) override { return Status::Ok; }

  void unlisten(const uint16_t UNUSED port) override {}

  Status poll(Processor& proc) override;
  Status wait(Processor& proc, const uint64_t ns) override;

  Status prepare(uint8_t*& buf) override;
  Status commit(const uint32_t len, uint8_t* const buf,
                const uint16_t mss) override;

  uint32_t mtu() const override { return m_mtu - stack::ethernet::HEADER_LEN; }

  uint32_t mss() const override { return m_mtu; }

  uint8_t receiveBufferLengthLog2() const override { return 10; }

  uint16_t receiveBuffersAvailable() const override
  {
    return std::numeric_limits<uint16_t>::max();
  }

protected:
  stack::ethernet::Address m_address;
  stack::ipv4::Address m_ip;
  stack::ipv4::Address m_dr;
  stack::ipv4::Address m_nm;
  uint32_t m_mtu;
};

}
