#pragma once

#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/system/Logger.h>
#include <tulips/transport/Device.h>
#include <tulips/transport/ena/RawProcessor.h>
#include <tulips/transport/ena/RedirectionTable.h>
#include <list>
#include <string>
#include <vector>
#include <dpdk/rte_ethdev.h>
#include <dpdk/rte_mempool.h>

namespace tulips::transport::ena {

class Port
{
public:
  Port(system::Logger& log, std::string_view ifn, const size_t width,
       const size_t txw, const size_t rxw);
  ~Port();

  void run();

  Device::Ref next(const bool bonded);

private:
  void configure(struct rte_eth_dev_info const& dev_info, const uint16_t nqus);

  void setupPoolsAndQueues(std::string_view ifn, const uint16_t buflen,
                           const uint16_t nqus);

  void setupReceiveSideScaling(struct rte_eth_dev_info const& dev_info);

  system::Logger& m_log;
  size_t m_ntxds;
  size_t m_nrxds;
  uint16_t m_portid;
  stack::ethernet::Address m_address;
  uint32_t m_mtu;
  struct rte_eth_conf m_ethconf;
  RedirectionTable::Ref m_reta;
  std::vector<struct rte_mempool*> m_rxpools;
  std::vector<struct rte_mempool*> m_txpools;
  std::list<uint16_t> m_free;
  Device::Ref m_admin;
  RawProcessor m_raw;
};

}
