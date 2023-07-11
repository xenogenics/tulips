#pragma once

#include <tulips/stack/IPv4.h>
#include <tulips/stack/ethernet/Producer.h>
#include <tulips/transport/Producer.h>
#include <cstdint>
#include <string>

namespace tulips::stack::ipv4 {

class Producer : public transport::Producer
{
public:
  struct Statistics
  {
    size_t sent; // Number of sent packets at the IP layer.
  };

  Producer(ethernet::Producer& prod, Address const& ha);

  uint32_t mss() const override { return m_eth.mss() - HEADER_LEN; }

  Status prepare(uint8_t*& buf) override;
  Status commit(const uint32_t len, uint8_t* const buf,
                const uint16_t mss = 0) override;

  Address const& hostAddress() const { return m_hostAddress; }

  Producer& setDestinationAddress(Address const& addr)
  {
    m_destAddress = addr;
    return *this;
  }

  Address const& defaultRouterAddress() const { return m_defaultRouterAddress; }

  Producer& setDefaultRouterAddress(Address const& addr)
  {
    m_defaultRouterAddress = addr;
    return *this;
  }

  Address const& netMask() const { return m_netMask; }

  Producer& setNetMask(Address const& addr)
  {
    m_netMask = addr;
    return *this;
  }

  void setProtocol(const uint8_t proto) { m_proto = proto; }

  bool isLocal(Address const& addr) const
  {
    return (addr.m_data & m_netMask.m_data) ==
           (m_hostAddress.m_data & m_netMask.m_data);
  }

private:
  ethernet::Producer& m_eth;
  Address m_hostAddress;
  Address m_destAddress;
  Address m_defaultRouterAddress;
  Address m_netMask;
  uint8_t m_proto;
  uint16_t m_ipid;
  Statistics m_stats;
};

}
