#pragma once

#include <tulips/transport/Device.h>
#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/system/Compiler.h>
#include <string>

namespace tulips::transport::npipe {

class Device : public transport::Device
{
public:
  Device(stack::ethernet::Address const& address,
         stack::ipv4::Address const& ip, stack::ipv4::Address const& nm,
         stack::ipv4::Address const& dr);

  stack::ethernet::Address const& address() const override { return m_address; }

  stack::ipv4::Address const& ip() const override { return m_ip; }

  stack::ipv4::Address const& gateway() const override { return m_dr; }

  stack::ipv4::Address const& netmask() const override { return m_nm; }

  Status listen(const uint16_t UNUSED port) override { return Status::Ok; }

  void unlisten(const uint16_t UNUSED port) override {}

  Status prepare(uint8_t*& buf) override;
  Status commit(const uint32_t len, uint8_t* const buf,
                const uint16_t mss = 0) override;

  Status poll(Processor& proc) override;
  Status wait(Processor& proc, const uint64_t ns) override;

  uint32_t mtu() const override { return DEFAULT_MTU; }

  uint32_t mss() const override
  {
    return DEFAULT_MTU + stack::ethernet::HEADER_LEN;
  }

  uint8_t receiveBufferLengthLog2() const override { return 11; }

  uint16_t receiveBuffersAvailable() const override { return 32; }

protected:
  static constexpr uint32_t BUFLEN = DEFAULT_MTU + stack::ethernet::HEADER_LEN;

  inline bool write(const uint32_t len, uint8_t* const buf)
  {
    ssize_t ret = 0;
    for (uint32_t s = 0; s < len; s += (uint32_t)ret) {
      ret = ::write(write_fd, buf + s, len - s);
      if (ret < 0) {
        return false;
      }
    }
    return true;
  }

  int waitForInput(const uint64_t ns);

  stack::ethernet::Address m_address;
  stack::ipv4::Address m_ip;
  stack::ipv4::Address m_dr;
  stack::ipv4::Address m_nm;
  uint8_t m_read_buffer[BUFLEN];
  uint8_t m_write_buffer[BUFLEN];
  int read_fd;
  int write_fd;
};

class ClientDevice : public Device
{
public:
  ClientDevice(stack::ethernet::Address const& address,
               stack::ipv4::Address const& ip, stack::ipv4::Address const& nm,
               stack::ipv4::Address const& dr, std::string const& rf,
               std::string const& wf);
};

class ServerDevice : public Device
{
public:
  ServerDevice(stack::ethernet::Address const& address,
               stack::ipv4::Address const& ip, stack::ipv4::Address const& nm,
               stack::ipv4::Address const& dr, std::string const& rf,
               std::string const& wf);

  ~ServerDevice() override;

private:
  std::string m_rf;
  std::string m_wf;
};

}
