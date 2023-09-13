#pragma once

#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/system/Logger.h>
#include <tulips/transport/Processor.h>
#include <cstdint>

namespace tulips::stack {

namespace ethernet {
class Processor;
}
#ifdef TULIPS_ENABLE_ICMP
namespace icmpv4 {
class Processor;
}
#endif
namespace tcpv4 {
class Processor;
}

namespace ipv4 {

class Processor : public transport::Processor
{
public:
  struct Statistics
  {
    size_t drop;   // Number of dropped packets at the IP layer.
    size_t recv;   // Number of received packets at the IP layer.
    size_t vhlerr; // Number of packets dropped (bad IP version or header len).
    size_t lenerr; // Number of packets dropped (bad IP len).
    size_t frgerr; // Number of packets dropped since they were IP fragments.
    size_t chkerr; // Number of packets dropped due to IP checksum errors.
  };

  Processor(system::Logger& log, Address const& ha);

  Status run() override;
  Status process(const uint16_t len, const uint8_t* const data,
                 const Timestamp ts) override;
  Status sent(uint8_t* const buf) override;

  Address const& sourceAddress() const { return m_srceAddress; }

  Address const& destinationAddress() const { return m_destAddress; }

  uint8_t protocol() const { return m_proto; }

  Processor& setEthernetProcessor(ethernet::Processor& eth)
  {
    m_eth = &eth;
    return *this;
  }

#ifdef TULIPS_ENABLE_RAW
  Processor& setRawProcessor(transport::Processor& raw)
  {
    m_raw = &raw;
    return *this;
  }
#endif

#ifdef TULIPS_ENABLE_ICMP
  Processor& setICMPv4Processor(icmpv4::Processor& icmp)
  {
    m_icmp = &icmp;
    return *this;
  }
#endif

  Processor& setTCPv4Processor(tcpv4::Processor& tcp)
  {
    m_tcp = &tcp;
    return *this;
  }

private:
  system::Logger& m_log;
  Address m_hostAddress;
  Address m_srceAddress;
  Address m_destAddress;
  uint8_t m_proto;
  Statistics m_stats;
  ethernet::Processor* m_eth;
#ifdef TULIPS_ENABLE_RAW
  transport::Processor* m_raw;
#endif
#ifdef TULIPS_ENABLE_ICMP
  icmpv4::Processor* m_icmp;
#endif
  tcpv4::Processor* m_tcp;
};

}
}
