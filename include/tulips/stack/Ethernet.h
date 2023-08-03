#pragma once

#include <tulips/system/Compiler.h>
#include <cstdint>
#include <string>
#include <unistd.h>

namespace tulips::stack::ethernet {

/*
 * The ethernet address class.
 */
class Address
{
public:
  using Data = uint8_t[6];

  static const Address BROADCAST;

  Address();
  Address(Address const& o);

  Address(const uint8_t a0, const uint8_t a1, const uint8_t a2,
          const uint8_t a3, const uint8_t a4, const uint8_t a5);

  Address(std::string_view dst);

  inline Address& operator=(Address const& o)
  {
    if (this != &o) {
      m_data[0] = o.m_data[0];
      m_data[1] = o.m_data[1];
      m_data[2] = o.m_data[2];
      m_data[3] = o.m_data[3];
      m_data[4] = o.m_data[4];
      m_data[5] = o.m_data[5];
    }
    return *this;
  }

  inline bool operator==(Address const& o) const
  {
    return m_data[0] == o.m_data[0] && m_data[1] == o.m_data[1] &&
           m_data[2] == o.m_data[2] && m_data[3] == o.m_data[3] &&
           m_data[4] == o.m_data[4] && m_data[5] == o.m_data[5];
  }

  inline bool operator!=(Address const& o) const
  {
    return m_data[0] != o.m_data[0] || m_data[1] != o.m_data[1] ||
           m_data[2] != o.m_data[2] || m_data[3] != o.m_data[3] ||
           m_data[4] != o.m_data[4] || m_data[5] != o.m_data[5];
  }

  Data& data() { return m_data; }

  Data const& data() const { return m_data; }

  std::string toString() const;

private:
  Data m_data;
} PACKED;

/*
 * The Ethernet header.
 */
struct Header
{
  Address dest;
  Address src;
  uint16_t type;
} PACKED;

static constexpr size_t USED HEADER_LEN = sizeof(Header);

static constexpr uint16_t USED ETHTYPE_ARP = 0x0806;
static constexpr uint16_t USED ETHTYPE_IP = 0x0800;

}
