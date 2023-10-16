#pragma once

#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/system/Compiler.h>
#include <tulips/system/Logger.h>
#include <tulips/transport/Device.h>
#include <string>

namespace tulips::transport::npipe {

class Device : public transport::Device
{
public:
  Device(system::Logger& log, stack::ethernet::Address const& address,
         stack::ipv4::Address const& ip, stack::ipv4::Address const& nm,
         stack::ipv4::Address const& dr);

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
      ret = ::write(m_wrfd, buf + s, len - s);
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
  int m_rdfd;
  int m_wrfd;
  uint16_t m_sent;
};

class ClientDevice : public Device
{
public:
  ClientDevice(system::Logger& log, stack::ethernet::Address const& address,
               stack::ipv4::Address const& ip, stack::ipv4::Address const& nm,
               stack::ipv4::Address const& dr, std::string_view rf,
               std::string_view wf);
};

class ServerDevice : public Device
{
public:
  ServerDevice(system::Logger& log, stack::ethernet::Address const& address,
               stack::ipv4::Address const& ip, stack::ipv4::Address const& nm,
               stack::ipv4::Address const& dr, std::string_view rf,
               std::string_view wf);

  ~ServerDevice() override;

private:
  std::string m_rf;
  std::string m_wf;
};

}
