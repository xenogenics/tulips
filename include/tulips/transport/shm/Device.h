#pragma once

#include <tulips/fifo/fifo.h>
#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/system/Compiler.h>
#include <tulips/system/Logger.h>
#include <tulips/system/Utils.h>
#include <tulips/transport/Device.h>
#include <limits>
#include <string>
#include <pthread.h>

namespace tulips::transport::shm {

class Device : public transport::Device
{
public:
  Device(system::Logger& log, stack::ethernet::Address const& address,
         stack::ipv4::Address const& ip, stack::ipv4::Address const& dr,
         stack::ipv4::Address const& nm, tulips_fifo_t rf, tulips_fifo_t wf);
  ~Device() override;

  stack::ethernet::Address const& address() const override { return m_address; }

  stack::ipv4::Address const& ip() const override { return m_ip; }

  stack::ipv4::Address const& gateway() const override { return m_dr; }

  stack::ipv4::Address const& netmask() const override { return m_nm; }

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

  Status prepare(uint8_t*& buf) override;
  Status commit(const uint16_t len, uint8_t* const buf,
                const uint16_t mss = 0) override;
  Status release(uint8_t* const buf) override;

  uint32_t mtu() const override
  {
    return m_write->data_len - sizeof(Packet) - stack::ethernet::HEADER_LEN;
  }

  uint32_t mss() const override { return m_write->data_len - sizeof(Packet); }

  uint8_t receiveBufferLengthLog2() const override
  {
    return system::utils::log2(m_write->data_len);
  }

  uint16_t receiveBuffersAvailable() const override
  {
    if (tulips_fifo_empty(m_write) == TULIPS_FIFO_YES) {
      return m_write->depth;
    } else {
      uint64_t delta = m_write->read_count - m_write->write_count;
      if (delta > std::numeric_limits<uint16_t>::max()) {
        return std::numeric_limits<uint16_t>::max();
      }
      return delta;
    }
  }

  Status drop();

private:
  struct Packet
  {
    uint32_t len;
    uint8_t data[];
  } PACKED;

protected:
  bool waitForInput(const uint64_t ns);

  stack::ethernet::Address m_address;
  stack::ipv4::Address m_ip;
  stack::ipv4::Address m_dr;
  stack::ipv4::Address m_nm;
  tulips_fifo_t m_read;
  tulips_fifo_t m_write;
  tulips_fifo_t m_sent;
  pthread_mutex_t m_mutex;
  pthread_cond_t m_cond;
};

}
