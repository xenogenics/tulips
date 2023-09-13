#pragma once

#include <tulips/stack/ICMPv4.h>
#include <tulips/stack/arp/Processor.h>
#include <tulips/stack/ethernet/Processor.h>
#include <tulips/stack/icmpv4/Request.h>
#include <tulips/stack/ipv4/Processor.h>
#include <tulips/system/Logger.h>
#include <tulips/transport/Processor.h>
#include <cstdint>
#include <map>

namespace tulips::stack::icmpv4 {

class Processor : public transport::Processor
{
public:
  Processor(system::Logger& log, ethernet::Producer& eth, ipv4::Producer& ip4);

  Status run() override { return Status::Ok; }
  Status process(const uint16_t len, const uint8_t* const data,
                 const Timestamp ts) override;
  Status sent(uint8_t* const buf) override;

  Request& attach(ethernet::Producer& eth, ipv4::Producer& ip4);
  void detach(Request& req);

  Processor& setEthernetProcessor(ethernet::Processor& eth)
  {
    m_ethin = &eth;
    return *this;
  }

  Processor& setIPv4Processor(ipv4::Processor& ipv4)
  {
    m_ip4in = &ipv4;
    return *this;
  }

  Processor& setARPProcessor(arp::Processor& arp)
  {
    m_arp = &arp;
    return *this;
  }

private:
  using Requests = std::map<Request::ID, Request*>;

  system::Logger& m_log;
  ethernet::Producer& m_ethout;
  ipv4::Producer& m_ip4out;
  ethernet::Processor* m_ethin;
  ipv4::Processor* m_ip4in;
  arp::Processor* m_arp;
  Statistics m_stats;
  Requests m_reqs;
  Request::ID m_ids;
};

}
