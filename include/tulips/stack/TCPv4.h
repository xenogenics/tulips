#pragma once

#include <tulips/stack/IPv4.h>
#include <tulips/system/Compiler.h>
#include <cstdint>
#include <limits>
#include <unistd.h>

namespace tulips::stack::tcpv4 {

/*
 * The TCPv4 port type.
 */
using Port = uint16_t;

/*
 * Sequence number limits.
 */
using SeqLimits = std::numeric_limits<uint32_t>;

/*
 * The TCPv4 header.
 */
struct Header
{
  Port srcport;
  Port destport;
  uint32_t seqno;
  uint32_t ackno;
  struct
  {
    uint8_t reserved : 4;
    uint8_t offset : 4;
  };
  uint8_t flags;
  uint16_t wnd;
  uint16_t chksum;
  uint16_t urgp;
  uint8_t opts[];
} __attribute__((packed));

#define HEADER_LEN_WITH_OPTS(__HDR)                                            \
  (((tulips::stack::tcpv4::Header*)(__HDR))->offset << 2)

static constexpr size_t USED HEADER_LEN = sizeof(Header);
static constexpr uint8_t USED RTO = 3;
static constexpr uint16_t USED HEADER_OVERHEAD = ipv4::HEADER_LEN + HEADER_LEN;

}
