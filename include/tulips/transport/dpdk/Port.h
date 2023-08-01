#pragma once

#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/transport/Device.h>
#include <tulips/transport/dpdk/AbstractionLayer.h>
#include <list>
#include <string>
#include <vector>
#include <dpdk/rte_ethdev.h>
#include <dpdk/rte_mempool.h>

namespace tulips::transport::dpdk {

class Port
{
public:
  Port(std::string const& ifn, const size_t width, const size_t depth);
  ~Port();

  Device::Ref next(stack::ipv4::Address const& ip,
                   stack::ipv4::Address const& dr,
                   stack::ipv4::Address const& nm);

private:
  /*
   * Private methods.
   */
  void configure(struct rte_eth_dev_info const& dev_info, const uint16_t nqus);

  void setupPoolsAndQueues(const uint16_t buflen, const uint16_t nqus,
                           const uint16_t ndsc);

  void setupReceiveSideScaling(struct rte_eth_dev_info const& dev_info);

  /*
   * Members.
   */
  static AbstractionLayer s_eal;

  uint16_t m_portid;
  stack::ethernet::Address m_address;
  uint32_t m_mtu;
  struct rte_eth_conf m_ethconf;
  size_t m_hlen;
  uint8_t* m_hkey;
  std::vector<struct rte_mempool*> m_rxpools;
  std::vector<struct rte_mempool*> m_txpools;
  std::list<uint16_t> m_free;
  size_t m_retasz;
};

}
