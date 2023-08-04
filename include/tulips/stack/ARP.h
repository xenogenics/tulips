#pragma once

#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/system/Compiler.h>
#include <cstdint>
#include <string>

namespace tulips::stack::arp {

enum OpCode : uint16_t
{
  Request = 1,
  Reply = 2,
};

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
} PACKED;

bool lookup(std::string_view eth, tulips::stack::ipv4::Address const& ip,
            tulips::stack::ethernet::Address& hw);

}
