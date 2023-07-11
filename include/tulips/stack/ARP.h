#pragma once

#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <string>
#include <cstdint>

namespace tulips::stack::arp {

struct Header
{
  uint16_t hwtype;
  uint16_t protocol;
  uint8_t hwlen;
  uint8_t protolen;
  uint16_t opcode;
  ethernet::Address shwaddr;
  ipv4::Address sipaddr;
  ethernet::Address dhwaddr;
  ipv4::Address dipaddr;
} __attribute__((packed));

bool lookup(std::string const& eth, tulips::stack::ipv4::Address const& ip,
            tulips::stack::ethernet::Address& hw);

}
