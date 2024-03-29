#pragma once

#include <tulips/stack/ARP.h>
#include <tulips/stack/ethernet/Producer.h>
#include <tulips/stack/ipv4/Producer.h>
#include <tulips/system/Compiler.h>
#include <tulips/system/Logger.h>
#include <tulips/system/Timer.h>
#include <tulips/transport/Processor.h>
#include <vector>
#include <unistd.h>

namespace tulips::stack::arp {

class Processor : public transport::Processor
{
public:
  Processor(system::Logger& log, ethernet::Producer& eth, ipv4::Producer& ip4);

  Status run() override;
  Status process(const uint16_t len, const uint8_t* const data,
                 const Timestamp ts) override;
  Status sent(const uint16_t len, uint8_t* const buf) override;

  bool has(ipv4::Address const& destipaddr);
  Status discover(ipv4::Address const& destipaddr);

  bool query(ipv4::Address const& destipaddr, ethernet::Address& ethaddr);
  void update(ipv4::Address const& ipaddr, ethernet::Address const& ethaddr);

private:
  struct Entry
  {
    Entry();

    ipv4::Address ipaddr;
    ethernet::Address ethaddr;
    uint8_t time;
  } PACKED;

  using Table = std::vector<Entry>;

  ipv4::Address const& hopAddress(ipv4::Address const& addr) const;

  system::Logger& m_log;
  ethernet::Producer& m_eth;
  ipv4::Producer& m_ipv4;
  Table m_table;
  uint8_t m_time;
  system::Timer m_timer;
};

}
