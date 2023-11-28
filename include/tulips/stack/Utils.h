#pragma once

#include <tulips/stack/IPv4.h>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <ostream>

namespace tulips::stack::utils {

uint16_t checksum(const uint16_t seed, const uint8_t* const data,
                  const uint16_t len);

void hexdump(const uint8_t* const data, const uint16_t len, std::ostream& out);

bool headerLength(const uint8_t* const packet, const uint32_t plen,
                  uint32_t& len);

inline uint16_t
cap(const uint32_t length)
{
  using uint16_limits = std::numeric_limits<uint16_t>;
  return length > uint16_limits::max() ? uint16_limits::max() : length;
}

uint32_t toeplitz(stack::ipv4::Address const& saddr,
                  stack::ipv4::Address const& daddr, const uint16_t sport,
                  const uint16_t dport, const size_t key_len,
                  const uint8_t* const key, const uint32_t init);

}
