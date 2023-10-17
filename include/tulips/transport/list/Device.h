#pragma once

#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/system/Compiler.h>
#include <tulips/system/Logger.h>
#include <tulips/transport/Device.h>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <list>
#include <new>
#include <string>
#include <pthread.h>

namespace tulips::transport::list {

class Device : public transport::Device
{
public:
  struct Packet
  {
    static Packet* allocate(const uint32_t mtu)
    {
      void* data = malloc(sizeof(Packet) + mtu);
      return new (data) Packet(mtu);
    }

    static void release(Packet* packet) { free(packet); }

    Packet() = delete;
    Packet(const uint32_t mtu) : mtu(mtu), len(0) {}

    Packet* clone() const
    {
      auto* c = allocate(mtu);
      memcpy(c->data, data, len);
      c->len = len;
      return c;
    }

    uint32_t mtu;
    uint32_t len;
    uint8_t data[];
  } PACKED;

  using List = std::list<Packet*>;

  static Ref allocate(system::Logger& log,
                      stack::ethernet::Address const& address,
                      const uint32_t mtu, List& rf, List& wf)
  {
    return std::make_unique<Device>(log, address, mtu, rf, wf);
  }

  Device(system::Logger& log, stack::ethernet::Address const& address,
         const uint32_t mtu, List& rf, List& wf);
  ~Device() override;

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

  Status poll(Processor& proc) override;
  Status wait(Processor& proc, const uint64_t ns) override;

  Status prepare(uint8_t*& buf) override;
  Status commit(const uint16_t len, uint8_t* const buf,
                const uint16_t mss) override;
  Status release(uint8_t* const buf) override;

  uint32_t mtu() const override { return m_mtu - stack::ethernet::HEADER_LEN; }

  uint32_t mss() const override { return m_mtu; }

  uint8_t receiveBufferLengthLog2() const override { return 10; }

  uint16_t receiveBuffersAvailable() const override
  {
    return std::numeric_limits<uint16_t>::max();
  }

  bool identify([[maybe_unused]] const uint8_t* const buf) const override
  {
    return true;
  }

  Status drop();

private:
  List m_packets;

protected:
  bool waitForInput(const uint64_t ns);

  stack::ethernet::Address m_address;
  uint32_t m_mtu;
  List& m_read;
  List& m_write;
  List m_sent;
  pthread_mutex_t m_mutex;
  pthread_cond_t m_cond;
};

}
