#pragma once

#include <tulips/stack/IPv4.h>
#include <tulips/system/Compiler.h>
#include <cstdint>
#include <functional>
#include <limits>
#include <unistd.h>

namespace tulips::stack::tcpv4 {

/*
 * TCPv4 flags
 */
enum Flag : uint8_t
{
  FIN = 0x01,
  SYN = 0x02,
  RST = 0x04,
  PSH = 0x08,
  ACK = 0x10,
  URG = 0x20,
  ECE = 0x40,
  CWR = 0x80,
  CTL = 0x3f,
};

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
  Port dstport;
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
} PACKED;

#define HEADER_LEN_WITH_OPTS(__HDR)                                            \
  (((tulips::stack::tcpv4::Header*)(__HDR))->offset << 2)

static constexpr size_t USED HEADER_LEN = sizeof(Header);
static constexpr uint8_t USED RTO = 3;
static constexpr uint16_t USED HEADER_OVERHEAD = ipv4::HEADER_LEN + HEADER_LEN;

}

namespace std {

template<>
struct std::hash<tulips::stack::tcpv4::Header>
{
  uint64_t operator()(const tulips::stack::tcpv4::Header& header) const
  {
    return uint64_t(header.dstport) << 32 | uint64_t(header.srcport);
  }
};

}
