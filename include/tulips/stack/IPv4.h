#pragma once

#include <tulips/system/Compiler.h>
#include <cstdint>
#include <string>

namespace tulips::stack::ipv4 {

/*
 * The IPv4 address.
 */
class Address
{
public:
  using Data = uint32_t;

  static const Address BROADCAST;

  Address();
  Address(Address const& o);
  Address(const uint8_t a0, const uint8_t a1, const uint8_t a2,
          const uint8_t a3);
  Address(std::string const& dst);

  inline Address& operator=(Address const& o)
  {
    if (this != &o) {
      m_data = o.m_data;
    }
    return *this;
  }

  inline bool operator==(Address const& o) const { return m_data == o.m_data; }

  inline bool operator!=(Address const& o) const { return m_data != o.m_data; }

  inline bool empty() const { return m_data == 0; }

  inline Data* data() { return &m_data; }

  inline const Data* data() const { return &m_data; }

  std::string toString() const;

private:
  union Alias
  {
    Data raw;
    uint8_t mbr[4];
  };

  Data m_data;

  friend class Producer;
  friend class Processor;
} __attribute__((packed));

/*
 * The IPv4 header.
 */
struct Header
{
  uint8_t vhl;
  uint8_t tos;
  uint16_t len;
  uint16_t ipid;
  uint8_t ipoffset[2];
  uint8_t ttl;
  uint8_t proto;
  uint16_t ipchksum;
  ipv4::Address srcipaddr;
  ipv4::Address destipaddr;
} __attribute__((packed));

static constexpr size_t USED HEADER_LEN = sizeof(Header);

static constexpr uint8_t USED PROTO_ICMP = 1;
static constexpr uint8_t USED PROTO_TCP = 6;
static constexpr uint8_t USED PROTO_TEST = 254;

/*
 * The IPv4 checksum.
 */
#if !(defined(TULIPS_HAS_HW_CHECKSUM) && defined(TULIPS_DISABLE_CHECKSUM_CHECK))
uint16_t checksum(const uint8_t* const data);
#endif

}
