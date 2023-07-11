#pragma once

#include <tulips/transport/Device.h>
#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/system/Compiler.h>
#include <tulips/system/Utils.h>
#include <tulips/fifo/fifo.h>
#include <limits>
#include <string>
#include <pthread.h>

namespace tulips::transport::shm {

class Device : public transport::Device
{
public:
  Device(stack::ethernet::Address const& address,
         stack::ipv4::Address const& ip, stack::ipv4::Address const& dr,
         stack::ipv4::Address const& nm, tulips_fifo_t rf, tulips_fifo_t wf);
  ~Device() override;

  stack::ethernet::Address const& address() const override { return m_address; }

  stack::ipv4::Address const& ip() const override { return m_ip; }

  stack::ipv4::Address const& gateway() const override { return m_dr; }

  stack::ipv4::Address const& netmask() const override { return m_nm; }

  Status listen(UNUSED const uint16_t port) override { return Status::Ok; }

  void unlisten(UNUSED const uint16_t port) override {}

  Status poll(Processor& proc) override;
  Status wait(Processor& proc, const uint64_t ns) override;

  Status prepare(uint8_t*& buf) override;
  Status commit(const uint32_t len, uint8_t* const buf,
                const uint16_t mss = 0) override;

  uint32_t mtu() const override
  {
    return write_fifo->data_len - sizeof(Packet) - stack::ethernet::HEADER_LEN;
  }

  uint32_t mss() const override
  {
    return write_fifo->data_len - sizeof(Packet);
  }

  uint8_t receiveBufferLengthLog2() const override
  {
    return system::utils::log2(write_fifo->data_len);
  }

  uint16_t receiveBuffersAvailable() const override
  {
    if (tulips_fifo_empty(write_fifo) == TULIPS_FIFO_YES) {
      return write_fifo->depth;
    } else {
      uint64_t delta = write_fifo->read_count - write_fifo->write_count;
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
  } __attribute__((packed));

protected:
  bool waitForInput(const uint64_t ns);

  stack::ethernet::Address m_address;
  stack::ipv4::Address m_ip;
  stack::ipv4::Address m_dr;
  stack::ipv4::Address m_nm;
  tulips_fifo_t read_fifo;
  tulips_fifo_t write_fifo;
  pthread_mutex_t m_mutex;
  pthread_cond_t m_cond;
};

}
