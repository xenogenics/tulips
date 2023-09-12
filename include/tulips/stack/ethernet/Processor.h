#pragma once

#include <tulips/stack/Ethernet.h>
#include <tulips/system/Logger.h>
#include <tulips/transport/Processor.h>
#include <cstdint>

namespace tulips::stack {

#ifdef TULIPS_ENABLE_ARP
namespace arp {
class Processor;
}
#endif

namespace ipv4 {
class Processor;
}

namespace ethernet {

class Processor : public transport::Processor
{
public:
  Processor(system::Logger& log, Address const& ha);

  Status run() override;
  Status process(const uint16_t len, const uint8_t* const data,
                 const Timestamp ts) override;

  Address const& sourceAddress() { return m_srceAddress; }

  Address const& destinationAddress() { return m_destAddress; }

  uint16_t type() const { return m_type; }

#ifdef TULIPS_ENABLE_RAW
  Processor& setRawProcessor(transport::Processor& raw)
  {
    m_raw = &raw;
    return *this;
  }
#endif

#ifdef TULIPS_ENABLE_ARP
  Processor& setARPProcessor(arp::Processor& arp)
  {
    m_arp = &arp;
    return *this;
  }
#endif

  Processor& setIPv4Processor(ipv4::Processor& ip4)
  {
    m_ipv4 = &ip4;
    return *this;
  }

private:
  system::Logger& m_log;
  Address m_hostAddress;
  Address m_srceAddress;
  Address m_destAddress;
  uint16_t m_type;
#ifdef TULIPS_ENABLE_RAW
  transport::Processor* m_raw;
#endif
#ifdef TULIPS_ENABLE_ARP
  arp::Processor* m_arp;
#endif
  ipv4::Processor* m_ipv4;
};

}
}
