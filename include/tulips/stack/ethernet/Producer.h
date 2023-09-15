#pragma once

#include <tulips/stack/Ethernet.h>
#include <tulips/system/Logger.h>
#include <tulips/transport/Producer.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <unistd.h>

namespace tulips::stack::ethernet {

class Producer : public transport::Producer
{
public:
  Producer(system::Logger& log, transport::Producer& prod, Address const& ha);

  uint32_t mss() const override { return m_prod.mss() - HEADER_LEN; }

  Status prepare(uint8_t*& buf) override;
  Status commit(const uint16_t len, uint8_t* const buf,
                const uint16_t mss = 0) override;
  Status release(uint8_t* const buf) override;

  Address const& hostAddress() { return m_hostAddress; }

  Producer& setDestinationAddress(Address const& addr)
  {
    m_destAddress = addr;
    return *this;
  }

  Producer& setType(const uint16_t type)
  {
    m_type = type;
    return *this;
  }

private:
  system::Logger& m_log;
  transport::Producer& m_prod;
  Address m_hostAddress;
  Address m_destAddress;
  uint16_t m_type;
};

}
