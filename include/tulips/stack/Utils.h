#pragma once

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

}
