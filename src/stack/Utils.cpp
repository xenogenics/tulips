#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/stack/TCPv4.h>
#include <tulips/stack/Utils.h>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <ostream>
#include <arpa/inet.h>

namespace tulips::stack::utils {

uint16_t
checksum(const uint16_t seed, const uint8_t* const data, const uint16_t len)
{
  uint16_t t, sum = seed;
  const uint8_t* dataptr = data;
  const uint8_t* last_byte = data + len - 1;
  /*
   * If at least two more bytes.
   */
  while (dataptr < last_byte) {
    t = (dataptr[0] << 8) + dataptr[1];
    sum += t;
    if (sum < t) {
      sum++;
    }
    dataptr += 2;
  }
  if (dataptr == last_byte) {
    t = (dataptr[0] << 8) + 0;
    sum += t;
    if (sum < t) {
      sum++;
    }
  }
  /*
   * Return sum in host byte order
   */
  return sum;
}

#define HEXFMT(_n) "0x" << std::hex << std::setw(_n) << std::setfill('0')
#define RSTFMT std::dec << std::setfill(' ')

void
hexdump(const uint8_t* const data, const uint16_t len, std::ostream& out)
{
  uint16_t i;
  for (i = 0; i < len; i += 1) {
    if (i % 8 == 0) {
      out << HEXFMT(3) << i << RSTFMT << ": ";
    }
    out << HEXFMT(2) << (unsigned int)data[i] << RSTFMT;
    if ((i + 1) % 8 == 0) {
      out << std::endl;
    } else {
      out << " ";
    }
  }
  if (i % 8 != 0) {
    out << std::endl;
  }
}

bool
headerLength(const uint8_t* const packet, const uint32_t plen, uint32_t& len)
{
  const uint8_t* ip;
  const uint8_t* tcp;
  /*
   * Walk up the packet structure.
   */
  len = stack::ethernet::HEADER_LEN;
  ip = packet + stack::ethernet::HEADER_LEN;
  len += stack::ipv4::HEADER_LEN;
  tcp = ip + stack::ipv4::HEADER_LEN;
  len += HEADER_LEN_WITH_OPTS(tcp);
  /*
   * Check the result.
   */
  return len <= plen;
}

uint32_t
toeplitz(stack::ipv4::Address const& saddr, stack::ipv4::Address const& daddr,
         const uint16_t sport, const uint16_t dport, const size_t len,
         const uint8_t* const key, const uint32_t init)
{
  uint32_t ret = init;
  uint8_t tuple[12];
  /*
   * Copy the key in a local buffer.
   */
  uint8_t tmp[len];
  memcpy(tmp, key, len);
  /*
   * Swap the ports.
   */
  auto sport_ne = htons(sport);
  auto dport_ne = htons(dport);
  /*
   * Lay out the the RSS payload for hashing.
   */
  memcpy(tuple, saddr.data(), 4);
  memcpy(tuple + 4, daddr.data(), 4);
  memcpy(tuple + 8, &sport_ne, 2);
  memcpy(tuple + 10, &dport_ne, 2);
  /*
   * Hash the tuple.
   */
  for (auto i : tuple) {
    for (uint32_t j = 0; j < 8; j += 1) {
      /*
       * Update the hash if the bit is set.
       */
      if (i & (1 << (8 - j - 1))) {
        ret ^= ntohl(*(uint32_t*)tmp);
      }
      /*
       * Shift the key to the left.
       */
      for (size_t i = 0; i < len; i += 1) {
        tmp[i] = ((tmp[i] << 1) & 0xff) | ((tmp[(i + 1) % len] & 0x80) >> 7);
      }
    }
  }
  /*
   * Done.
   */
  return ret;
}

}
