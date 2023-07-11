#pragma once

#include <tulips/transport/Device.h>
#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <pthread.h>
#include <list>
#include <memory>
#include <string>

namespace tulips::transport::tap {

class Device : public transport::Device
{
public:
  Device(std::string const& devname, stack::ipv4::Address const& ip,
         stack::ipv4::Address const& nm, stack::ipv4::Address const& dr);
  ~Device();

  stack::ethernet::Address const& address() const { return m_address; }

  stack::ipv4::Address const& ip() const { return m_ip; }

  stack::ipv4::Address const& gateway() const { return m_dr; }

  stack::ipv4::Address const& netmask() const { return m_nm; }

  Status listen(UNUSED const uint16_t port) { return Status::Ok; }

  void unlisten(UNUSED const uint16_t port) {}

  Status prepare(uint8_t*& buf);
  Status commit(const uint32_t len, uint8_t* const buf, const uint16_t mss = 0);

  Status poll(Processor& proc);
  Status wait(Processor& proc, const uint64_t ns);

  uint32_t mtu() const { return m_mtu; }

  uint32_t mss() const { return m_mtu + stack::ethernet::HEADER_LEN; }

  uint8_t receiveBufferLengthLog2() const { return 11; }

  uint16_t receiveBuffersAvailable() const { return 32; }

protected:
  stack::ethernet::Address m_address;
  stack::ipv4::Address m_ip;
  stack::ipv4::Address m_dr;
  stack::ipv4::Address m_nm;
  int m_fd;
  uint32_t m_mtu;
  std::list<uint8_t*> m_buffers;
};

}
