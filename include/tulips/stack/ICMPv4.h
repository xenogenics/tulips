#pragma once

#include <tulips/system/Compiler.h>
#include <cstdint>

namespace tulips::stack::icmpv4 {

/**
 * The ICMPv4 header.
 */
struct Header
{
  uint8_t type;
  uint8_t icode;
  uint16_t icmpchksum;
  uint16_t id;
  uint16_t seqno;
} PACKED;

static constexpr uint16_t USED HEADER_LEN = sizeof(Header);

static constexpr uint8_t USED ECHO_REPLY = 0;
static constexpr uint8_t USED ECHO = 8;

/**
 * The ICMPv4 statistics.
 */
struct Statistics
{
  uint64_t recv; // Number of received ICMP packets.
  uint64_t sent; // Number of sent ICMP packets.
};

/**
 * ICMPv4 checksum.
 */
uint16_t checksum(const uint8_t* const data);

}
