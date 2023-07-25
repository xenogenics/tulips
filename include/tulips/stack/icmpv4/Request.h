#pragma once

#include <tulips/stack/ICMPv4.h>
#include <tulips/stack/arp/Processor.h>
#include <tulips/stack/ethernet/Producer.h>
#include <tulips/stack/ipv4/Producer.h>
#include <cstdint>

namespace tulips::stack::icmpv4 {

class Request
{
public:
  using ID = uint16_t;

  Request(ethernet::Producer& eth, ipv4::Producer& ip4, arp::Processor& arp,
          const ID id);

  Status operator()(ipv4::Address const& dst);

private:
  enum State
  {
    IDLE,
    REQUEST,
    RESPONSE
  };

  ethernet::Producer& m_eth;
  ipv4::Producer& m_ip4;
  arp::Processor& m_arp;
  ID m_id;
  State m_state;
  uint16_t m_seq;

  friend class Processor;
};

}
