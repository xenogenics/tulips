#include <tulips/stack/Ethernet.h>
#include <tulips/system/Utils.h>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace tulips::stack::ethernet {

const Address Address::BROADCAST(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);

/**
 * Address class definition
 */

Address::Address() : m_data()
{
  m_data[0] = 0;
  m_data[1] = 0;
  m_data[2] = 0;
  m_data[3] = 0;
  m_data[4] = 0;
  m_data[5] = 0;
}

Address::Address(Address const& o) : m_data()
{
  m_data[0] = o.m_data[0];
  m_data[1] = o.m_data[1];
  m_data[2] = o.m_data[2];
  m_data[3] = o.m_data[3];
  m_data[4] = o.m_data[4];
  m_data[5] = o.m_data[5];
}

Address::Address(const uint8_t a0, const uint8_t a1, const uint8_t a2,
                 const uint8_t a3, const uint8_t a4, const uint8_t a5)
  : m_data()
{
  m_data[0] = a0;
  m_data[1] = a1;
  m_data[2] = a2;
  m_data[3] = a3;
  m_data[4] = a4;
  m_data[5] = a5;
}

Address::Address(std::string const& dst) : m_data()
{
  std::vector<std::string> parts;
  system::utils::split(dst, ':', parts);
  if (parts.size() != 6) {
    throw std::invalid_argument("String is not a valid ethernet address");
  }
  for (int i = 0; i < 6; i += 1) {
    int value;
    std::istringstream(parts[i]) >> std::hex >> value;
    m_data[i] = value;
  }
}

std::string
Address::toString() const
{
  std::ostringstream oss;
  oss << std::hex << std::setw(2) << std::setfill('0')
      << (unsigned int)m_data[0] << ":" << std::setw(2) << std::setfill('0')
      << (unsigned int)m_data[1] << ":" << std::setw(2) << std::setfill('0')
      << (unsigned int)m_data[2] << ":" << std::setw(2) << std::setfill('0')
      << (unsigned int)m_data[3] << ":" << std::setw(2) << std::setfill('0')
      << (unsigned int)m_data[4] << ":" << std::setw(2) << std::setfill('0')
      << (unsigned int)m_data[5] << std::dec;
  return oss.str();
}

}
