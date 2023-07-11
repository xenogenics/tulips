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
  Device(transport::Device& device, std::string const& fn);
  ~Device() override;

  std::string const& name() const override { return m_device.name(); }

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

  Status listen(const uint16_t port) override { return m_device.listen(port); }

  void unlisten(const uint16_t port) override { m_device.unlisten(port); }

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
  Status commit(const uint32_t len, uint8_t* const buf,
                const uint16_t mss = 0) override;

private:
  Status run() override { return Status::Ok; }
  Status process(const uint16_t len, const uint8_t* const data) override;

  transport::Device& m_device;
  pcap_t* m_pcap;
  pcap_dumper_t* m_pcap_dumper;
  Processor* m_proc;
};

}
