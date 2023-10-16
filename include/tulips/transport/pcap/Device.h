#pragma once

#include <tulips/transport/Device.h>
#include <string>

#ifdef __OpenBSD__
#include <pcap.h>
#else
#include <pcap/pcap.h>
#endif

namespace tulips::transport::pcap {

class Device
  : public transport::Device
  , public Processor
{
public:
  Device(system::Logger& log, transport::Device& device, std::string_view name);
  ~Device() override;

  std::string_view name() const override { return m_device.name(); }

  stack::ethernet::Address const& address() const override
  {
    return m_device.address();
  }

  Status listen(const stack::ipv4::Protocol proto,
                stack::ipv4::Address const& laddr, const uint16_t lport,
                stack::ipv4::Address const& raddr,
                const uint16_t rport) override
  {
    return m_device.listen(proto, laddr, lport, raddr, rport);
  }

  void unlisten(const stack::ipv4::Protocol proto,
                stack::ipv4::Address const& laddr, const uint16_t lport,
                stack::ipv4::Address const& raddr,
                const uint16_t rport) override
  {
    m_device.unlisten(proto, laddr, lport, raddr, rport);
  }

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

  bool identify(const uint8_t* const buf) const override
  {
    return m_device.identify(buf);
  }

  Status prepare(uint8_t*& buf) override;
  Status commit(const uint16_t len, uint8_t* const buf,
                const uint16_t mss = 0) override;
  Status release(uint8_t* const buf) override;

private:
  Status run() override { return Status::Ok; }
  Status process(const uint16_t len, const uint8_t* const data,
                 const Timestamp ts) override;
  Status sent(const uint16_t len, uint8_t* const data) override;

  transport::Device& m_device;
  pcap_t* m_pcap;
  pcap_dumper_t* m_pcap_dumper;
  Processor* m_proc;
};

}
