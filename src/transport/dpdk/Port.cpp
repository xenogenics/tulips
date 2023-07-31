#include <tulips/stack/Utils.h>
#include <tulips/transport/dpdk/Device.h>
#include <tulips/transport/dpdk/Port.h>
#include <tulips/transport/dpdk/Utils.h>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <dpdk/rte_ethdev.h>
#include <net/ethernet.h>

namespace {

static inline uint64_t
log2(const uint64_t x)
{
  uint64_t y;
  asm("\tbsr %1, %0\n" : "=r"(y) : "r"(x));
  return y;
}

}

namespace tulips::transport::dpdk {

AbstractionLayer Port::s_eal;

Port::Port(std::string const& ifn, const size_t width, const size_t depth)
  : m_portid(0xFFFF)
  , m_address()
  , m_mtu()
  , m_ethconf()
  , m_hlen(0)
  , m_hkey(nullptr)
  , m_rxpools()
  , m_txpools()
  , m_free()
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
   * Use the first port.
   */
  m_portid = pids.front();
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
  auto nrxq = RTE_MIN(width, dev_info.max_rx_queues);
  auto ntxq = RTE_MIN(width, dev_info.max_tx_queues);
  auto nqus = RTE_MIN(nrxq, ntxq);
  /*
   * Get the descriptor count.
   */
  auto nrxd = RTE_MAX(depth, dev_info.rx_desc_lim.nb_min);
  auto ntxd = RTE_MAX(nrxd, dev_info.tx_desc_lim.nb_min);
  auto ndsc = RTE_MAX(nrxd, ntxd);
  /*
   * Print some device information.
   */
  DPDK_LOG("driver: " << dev_info.driver_name);
  DPDK_LOG("name: " << rte_dev_name(dev_info.device));
  DPDK_LOG("hardware address: " << m_address.toString());
  DPDK_LOG("MTU: " << m_mtu);
  DPDK_LOG("queues: " << nqus);
  DPDK_LOG("descriptors: " << ndsc);
  DPDK_LOG("buffer length: " << buflen);
  /*
   * Configure the device.
   */
  configure(dev_info, nqus);
  /*
   * Setup the pools and queues.
   */
  setupPoolsAndQueues(buflen, nqus, ndsc);
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
}

Port::~Port()
{
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

Device::Ref
Port::next(stack::ipv4::Address const& ip, stack::ipv4::Address const& dr,
           stack::ipv4::Address const& nm)
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
   * Done.
   */
  auto* dev = new Device(m_portid, qid, m_retasz, m_hlen, m_hkey, m_address,
                         m_mtu, txpool, ip, dr, nm);
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
Port::setupPoolsAndQueues(const uint16_t buflen, const uint16_t nqus,
                          const uint16_t ndsc)
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
    sprintf(name, "RX(%ld)", i);
    auto rxpool = rte_pktmbuf_pool_create(name, ndsc, 0, 0, buflen, node);
    if (rxpool == nullptr) {
      throw std::runtime_error("Failed to create a RX mempool");
    }
    m_rxpools.push_back(rxpool);
    /*
     * Setup the queue.
     */
    auto ret = rte_eth_rx_queue_setup(m_portid, i, ndsc, node, nullptr, rxpool);
    if (ret != 0) {
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
    sprintf(name, "TX(%ld)", i);
    auto txpool = rte_pktmbuf_pool_create(name, ndsc, 0, 8, buflen, node);
    if (txpool == nullptr) {
      throw std::runtime_error("Failed to create a TX mempool");
    }
    m_txpools.push_back(txpool);
    /*
     * Setup the queue.
     */
    auto ret = rte_eth_tx_queue_setup(m_portid, i, ndsc, node, nullptr);
    if (ret != 0) {
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
  m_hlen = dev_info.hash_key_size;
  m_hkey = new uint8_t[m_hlen];
  struct rte_eth_rss_conf rss_conf = { .rss_key = m_hkey };
  auto ret = rte_eth_dev_rss_hash_conf_get(m_portid, &rss_conf);
  if (ret != 0) {
    throw std::runtime_error("Failed to get the RSS hashing configuration");
  }
  /*
   * Print the RSS configuration.
   */
  m_retasz = dev_info.reta_size;
  size_t retasz_log2 = log2(m_retasz);
#ifdef DPDK_VERBOSE
  std::ostringstream oss;
  for (size_t i = 0; i < m_hlen; i += 1) {
    oss << std::setw(2) << std::setfill('0') << std::hex << uint16_t(m_hkey[i]);
    oss << ((i + 1 < m_hlen) ? ":" : "");
  }
#endif
  DPDK_LOG("hash key length: " << size_t(rss_conf.rss_key_len));
  DPDK_LOG("hash key: " << oss.str());
  DPDK_LOG("reta size log2: " << retasz_log2);
  /*
   * Reset the RETA to point all entries to the 0th queue.
   */
  size_t count = 1 << (retasz_log2 < 6 ? retasz_log2 : retasz_log2 - 6);
  struct rte_eth_rss_reta_entry64 reta[count];
  for (size_t i = 0; i < count; i += 1) {
    reta[i].mask = uint64_t(-1);
    memset(reta[i].reta, 0, sizeof(reta[i].reta));
  }
  ret = rte_eth_dev_rss_reta_update(m_portid, reta, dev_info.reta_size);
  if (ret != 0) {
    throw std::runtime_error("Failed to reset the RETA to the 0th queue");
  }
}

}
