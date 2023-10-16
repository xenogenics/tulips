#include <tulips/stack/Utils.h>
#include <tulips/transport/ena/Device.h>
#include <tulips/transport/ena/Port.h>
#include <tulips/transport/ena/RedirectionTable.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <dpdk/rte_ethdev.h>
#include <net/ethernet.h>
#include <rte_errno.h>

namespace tulips::transport::ena {

Port::Port(system::Logger& log, std::string_view ifn, const size_t width,
           const size_t txw, const size_t rxw)
  : m_log(log)
  , m_ntxds(0)
  , m_nrxds(0)
  , m_portid(0xFFFF)
  , m_address()
  , m_mtu()
  , m_ethconf()
  , m_reta()
  , m_rxpools()
  , m_txpools()
  , m_free()
  , m_admin()
  , m_raw()
{
  int ret = 0;
  /*
   * Collect the available ports.
   */
  std::vector<uint16_t> pids;
  uint16_t pid;
  RTE_ETH_FOREACH_DEV(pid)
  {
    pids.push_back(pid);
  }
  /*
   * Check that there is at least one available port.
   */
  if (pids.size() == 0) {
    throw std::runtime_error("No available ports");
  }
  /*
   * Find the appropriate port.
   */
  struct rte_eth_dev_info dev_info;
  for (auto pid : pids) {
    ret = rte_eth_dev_info_get(pid, &dev_info);
    if (ret < 0) {
      throw std::runtime_error("Failed to get device info");
    }
    auto dev_name = std::string(rte_dev_name(dev_info.device));
    if (ifn == dev_name) {
      m_portid = pid;
      break;
    }
  }
  /*
   * Check that we found the port.
   */
  if (m_portid == 0xFFFF) {
    throw std::runtime_error("Interface not found");
  }
  /*
   * Fetch the MAC address.
   */
  struct rte_ether_addr mac;
  ret = rte_eth_macaddr_get(m_portid, &mac);
  if (ret != 0) {
    throw std::runtime_error("Failed to fetch device's MAC address");
  }
  memcpy(m_address.data(), mac.addr_bytes, ETHER_ADDR_LEN);
  /*
   * Get the MTU.
   */
  uint16_t hwmtu = 0;
  ret = rte_eth_dev_get_mtu(m_portid, &hwmtu);
  if (ret < 0) {
    throw std::runtime_error("Failed to get device MTU");
  }
  m_mtu = hwmtu;
  /*
   * Compute the buffer length.
   */
  auto buflen = hwmtu + stack::ethernet::HEADER_LEN + RTE_PKTMBUF_HEADROOM;
  if (buflen < dev_info.min_rx_bufsize) {
    buflen = dev_info.min_rx_bufsize;
  }
  /*
   * Get the queue count.
   */
  auto ntxq = RTE_MIN(width, dev_info.max_tx_queues);
  auto nrxq = RTE_MIN(width, dev_info.max_rx_queues);
  auto nqus = RTE_MIN(nrxq, ntxq);
  /*
   * Get the TX descriptor count.
   */
  m_ntxds = RTE_MAX(txw, dev_info.tx_desc_lim.nb_min);
  m_ntxds = RTE_MIN(txw, dev_info.tx_desc_lim.nb_max);
  /*
   * Get the RX descriptor count.
   */
  m_nrxds = RTE_MAX(rxw, dev_info.rx_desc_lim.nb_min);
  m_nrxds = RTE_MIN(rxw, dev_info.rx_desc_lim.nb_max);
  /*
   * Print some device information.
   */
  log.debug("ENA", "driver: ", dev_info.driver_name);
  log.debug("ENA", "name: ", rte_dev_name(dev_info.device));
  log.debug("ENA", "hardware address: ", m_address.toString());
  log.debug("ENA", "MTU: ", m_mtu);
  log.debug("ENA", "TX queues: ", nqus, "/", dev_info.max_tx_queues);
  log.debug("ENA", "RX queues: ", nqus, "/", dev_info.max_rx_queues);
  log.debug("ENA", "TX buffers: ", m_ntxds, "/", dev_info.tx_desc_lim.nb_max);
  log.debug("ENA", "RX buffers: ", m_nrxds, "/", dev_info.rx_desc_lim.nb_max);
  log.debug("ENA", "buffer length: ", buflen);
  /*
   * Configure the device.
   */
  configure(dev_info, nqus);
  /*
   * Setup the pools and queues.
   */
  setupPoolsAndQueues(ifn, buflen, nqus);
  /*
   * Start the port.
   */
  ret = rte_eth_dev_start(m_portid);
  if (ret != 0) {
    throw std::runtime_error("Failed to start the device");
  }
  /*
   * Update the RSS state.
   */
  setupReceiveSideScaling(dev_info);
  /*
   * Reset the statistics of the port.
   */
  ret = rte_eth_stats_reset(m_portid);
  if (ret != 0) {
    switch (ret) {
      case -ENODEV: {
        m_log.debug("ENA", "reset stats failed: invalid port (", m_portid, ")");
        break;
      }
      case -ENOTSUP: {
        m_log.debug("ENA", "reset stats failed: not supported");
        break;
      }
      default: {
        m_log.debug("ENA", "reset stats failed: ", ret);
        break;
      }
    }
  }
  /*
   * Allocate the admin device.
   */
  m_admin = next(false);
}

Port::~Port()
{
  /*
   * Deallocate the admin device.
   */
  m_admin.reset();
  /*
   * Stop the device.
   */
  rte_eth_dev_stop(m_portid);
  /*
   * Clear the TX mempools.
   */
  for (auto mp : m_txpools) {
    rte_mempool_free(mp);
  }
  m_txpools.clear();
  /*
   * Clear the RX mempools.
   */
  for (auto mp : m_rxpools) {
    rte_mempool_free(mp);
  }
  m_rxpools.clear();
}

void
Port::run()
{
  if (m_admin->poll(m_raw) == Status::NoDataAvailable) {
    m_raw.run();
  }
}

Device::Ref
Port::next(const bool bound)
{
  /*
   * Return if there is no more queue available.
   */
  if (m_free.empty()) {
    return nullptr;
  }
  /*
   * Grab the next free queue ID.
   */
  auto qid = m_free.front();
  m_free.pop_front();
  /*
   * Grab the TX pool.
   */
  auto* txpool = m_txpools[qid];
  /*
   * Allocate the new device.
   */
  auto* dev = new ena::Device(m_log, m_portid, qid, m_ntxds, m_nrxds, *m_reta,
                              m_address, m_mtu, txpool, bound);
  /*
   * Add the device queue to the raw processor.
   */
  if (qid > 0 && !bound) {
    m_raw.add(dev->internalBuffer());
  }
  /*
   * Done.
   */
  return Device::Ref(dev);
}

void
Port::configure(UNUSED struct rte_eth_dev_info const& dev_info,
                const uint16_t nqus)
{
  /*
   * Erase the configurations.
   */
  memset(&m_ethconf, 0, sizeof(m_ethconf));
  /*
   * Update the device RX configuration presets.
   */
#ifdef TULIPS_HAS_HW_CHECKSUM
  if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM) {
    m_ethconf.txmode.offloads |= RTE_ETH_RX_OFFLOAD_IPV4_CKSUM;
  }
  if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_UDP_CKSUM) {
    m_ethconf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_UDP_CKSUM;
  }
  if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_CKSUM) {
    m_ethconf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_TCP_CKSUM;
  }
#endif
  /*
   * Update the device TX configuration presets.
   */
  m_ethconf.txmode.offloads = RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
#ifdef TULIPS_HAS_HW_CHECKSUM
  if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) {
    m_ethconf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
  }
  if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM) {
    m_ethconf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
  }
  if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) {
    m_ethconf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_TCP_CKSUM;
  }
#endif
  /*
   * Update the device receive-side scaling (RSS) configuration.
   */
  m_ethconf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
  /*
   * Configure the device.
   */
  auto ret = rte_eth_dev_configure(m_portid, nqus, nqus, &m_ethconf);
  if (ret != 0) {
    throw std::runtime_error("Failed to configure the device");
  }
}

void
Port::setupPoolsAndQueues(std::string_view ifn, const uint16_t buflen,
                          const uint16_t nqus)
{
  /*
   * Get the NUMA node.
   */
  auto node = rte_eth_dev_socket_id(m_portid);
  /*
   * Configure the RX queues.
   */
  for (size_t i = 0; i < nqus; i += 1) {
    char name[32];
    /*
     * Allocate the pool.
     */
    sprintf(name, "%*s_RX_%ld_", int(ifn.size()), ifn.data(), i);
    auto p = rte_pktmbuf_pool_create(name, m_nrxds, 0, 0, buflen, node);
    if (p == nullptr) {
      m_log.error("ENA", "create RX mempool failed: ", rte_strerror(rte_errno));
      throw std::runtime_error("Failed to create a RX mempool");
    }
    m_rxpools.push_back(p);
    /*
     * Setup the queue.
     */
    auto ret = rte_eth_rx_queue_setup(m_portid, i, m_nrxds, node, nullptr, p);
    if (ret != 0) {
      m_log.error("ENA", "setup RX queue failed: ", rte_strerror(rte_errno));
      throw std::runtime_error("Failed to setup a RX queue");
    }
  }
  /*
   * Configure the TX pools.
   */
  for (size_t i = 0; i < nqus; i += 1) {
    char name[32];
    /*
     * Allocate the pool.
     */
    sprintf(name, "%*s_TX_%ld_", int(ifn.size()), ifn.data(), i);
    auto p = rte_pktmbuf_pool_create(name, m_ntxds, 0, 8, buflen, node);
    if (p == nullptr) {
      m_log.error("ENA", "create TX mempool failed: ", rte_strerror(rte_errno));
      throw std::runtime_error("Failed to create a TX mempool");
    }
    m_txpools.push_back(p);
    /*
     * Setup the queue.
     */
    auto ret = rte_eth_tx_queue_setup(m_portid, i, m_ntxds, node, nullptr);
    if (ret != 0) {
      m_log.error("ENA", "setup TX queue failed: ", rte_strerror(rte_errno));
      throw std::runtime_error("Failed to setup a TX queue");
    }
  }
  /*
   * Update the free list. We reserve the 0th queue.
   */
  for (size_t i = 0; i < nqus; i += 1) {
    m_free.push_back(i);
  }
}

void
Port::setupReceiveSideScaling(struct rte_eth_dev_info const& dev_info)
{
  /*
   * Get the RSS configuration.
   */
  auto hlen = dev_info.hash_key_size;
  auto hkey = new uint8_t[hlen];
  struct rte_eth_rss_conf rss_conf = { .rss_key = hkey };
  auto ret = rte_eth_dev_rss_hash_conf_get(m_portid, &rss_conf);
  if (ret != 0) {
    delete[] hkey;
    throw std::runtime_error("Failed to get the RSS hashing configuration");
  }
  /*
   * Allocate the redirection table.
   */
  auto size = dev_info.reta_size;
  m_reta = RedirectionTable::allocate(m_portid, size, hlen, hkey);
}

}
