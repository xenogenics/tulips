#include "rte_config.h"
#include "rte_ether.h"
#include "rte_flow.h"
#include "rte_ip.h"
#include "rte_mbuf.h"
#include "rte_mbuf_core.h"
#include "rte_mempool.h"
#include <tulips/system/Compiler.h>
#include <tulips/system/Utils.h>
#include <tulips/transport/dpdk/Device.h>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <sstream>
#include <thread>
#include <dpdk/rte_dev.h>
#include <dpdk/rte_eal.h>
#include <dpdk/rte_ethdev.h>
#include <dpdk/rte_flow.h>
#include <net/ethernet.h>

#define DPDK_VERBOSE 1

#if DPDK_VERBOSE
#define DPDK_LOG(__args) LOG("DPDK", __args)
#else
#define DPDK_LOG(...) ((void)0)
#endif

namespace tulips::transport::dpdk {

AbstractionLayer Device::s_eal;

Device::Device(std::string const& ifn, stack::ipv4::Address const& ip,
               stack::ipv4::Address const& dr, stack::ipv4::Address const& nm,
               const uint16_t nbuf)
  : transport::Device(ifn)
  , m_portid(0xFFFF)
  , m_rxqpool(nullptr)
  , m_txqpool(nullptr)
  , m_ethconf()
  , m_rxqconf()
  , m_txqconf()
  , m_buflen(16384)
  , m_address()
  , m_ip(ip)
  , m_dr(dr)
  , m_nm(nm)
  , m_mtu(1500)
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
   * Print some device information.
   */
  DPDK_LOG("Device driver: " << dev_info.driver_name);
  DPDK_LOG("Device name: " << rte_dev_name(dev_info.device));
  DPDK_LOG("Device NUMA node: " << rte_dev_numa_node(dev_info.device));
  /*
   * Erase the configurations.
   */
  memset(&m_ethconf, 0, sizeof(m_ethconf));
  memset(&m_rxqconf, 0, sizeof(m_rxqconf));
  memset(&m_txqconf, 0, sizeof(m_txqconf));
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
   * Configure the device.
   */
  ret = rte_eth_dev_configure(m_portid, 1, 1, &m_ethconf);
  if (ret != 0) {
    throw std::runtime_error("Failed to configure the device");
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
   * Allocate the mempools.
   */
  m_rxqpool = rte_pktmbuf_pool_create("RX", nbuf, 0, 0, m_buflen,
                                      rte_eth_dev_socket_id(m_portid));
  if (m_rxqpool == nullptr) {
    throw std::runtime_error("Failed to create the RX mempool");
  }
  m_txqpool = rte_pktmbuf_pool_create("TX", nbuf, 0, 8, m_buflen,
                                      rte_eth_dev_socket_id(m_portid));
  if (m_txqpool == nullptr) {
    throw std::runtime_error("Failed to create the TX mempool");
  }
  /*
   * Update the RX configuration.
   */
  m_rxqconf.rx_free_thresh = 32;
  /*
   * Setup the RX queue.
   */
  rte_eth_rx_queue_setup(m_portid, 0, nbuf, rte_eth_dev_socket_id(m_portid),
                         &m_rxqconf, m_rxqpool);
  if (ret != 0) {
    throw std::runtime_error("Failed to setup the RX queue");
  }
  /*
   * Setup the TX queue.
   */
  rte_eth_tx_queue_setup(m_portid, 0, nbuf, rte_eth_dev_socket_id(m_portid),
                         &m_txqconf);
  if (ret != 0) {
    throw std::runtime_error("Failed to setup the TX queue");
  }
  /*
   * Start the port.
   */
  ret = rte_eth_dev_start(m_portid);
  if (ret != 0) {
    throw std::runtime_error("Failed to start the device");
  }
}

Device::~Device()
{
  /*
   * Delete the local MAC flow.
   */
  struct rte_flow_error flow_error;
  rte_flow_flush(m_portid, &flow_error);
  /*
   * Stop the device.
   */
  rte_eth_dev_stop(m_portid);
  /*
   * Clear the mempools.
   */
  rte_mempool_free(m_txqpool);
  rte_mempool_free(m_rxqpool);
}

Status
Device::listen(const uint16_t UNUSED port)
{
  /*
   * NOTE(xrg): by default, the ETH dev will get all the packets associated with
   * its MAC address. Some drivers don't allow masking the EtherType field of
   * the ETH mask (eg. Intel drivers) so we can't disable that behavior with a
   * low priority flow. Therefore, we simply let all traffic pass.
   */
  return Status::Ok;
}

void
Device::unlisten(const uint16_t UNUSED port)
{
  /*
   * NOTE(xrg): no-op, see above.
   */
}

Status
Device::poll(Processor& proc)
{
  /*
   * Process the incoming receive buffers.
   */
  struct rte_mbuf* mbufs[32];
  auto nbrx = rte_eth_rx_burst(m_portid, 0, mbufs, 32);
  /*
   * Check if there are any buffer.
   */
  if (nbrx == 0) {
    return Status::NoDataAvailable;
  }
  /*
   * Process the buffers.
   */
  for (auto i = 0; i < nbrx; i += 1) {
    auto* buf = mbufs[i];
    /*
     * Validate the IP checksum.
     */
#ifdef TULIPS_HAS_HW_CHECKSUM
    if (buf->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) {
      if (m_hints & Device::VALIDATE_IP_CSUM) {
        auto flags = buf->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK;
        if (flags == RTE_MBUF_F_RX_IP_CKSUM_BAD) {
          DPDK_LOG("invalid IP checksum, dropping packet");
          continue;
        }
      }
    }
    /*
     * Validate the L4 checksum.
     */
    if (buf->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK) {
      if (m_hints & Device::VALIDATE_L4_CSUM) {
        auto flags = buf->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK;
        if (flags == RTE_MBUF_F_RX_L4_CKSUM_BAD) {
          DPDK_LOG("invalid L4 checksum, dropping packet");
          continue;
        }
      }
    }
#endif
    /*
     * Grab the packet data and length.
     */
    auto* dat = rte_pktmbuf_mtod(buf, const uint8_t*);
    auto len = rte_pktmbuf_pkt_len(buf);
    /*
     * Process the packet.
     */
    proc.process(len, dat);
    /*
     * Free the packet.
     */
    rte_pktmbuf_free(buf);
  }
  /*
   * Done.
   */
  return Status::Ok;
}

Status
Device::wait(UNUSED Processor& proc, UNUSED const uint64_t ns)
{
  std::this_thread::sleep_for(std::chrono::nanoseconds(ns));
  return Device::poll(proc);
}

Status
Device::prepare(uint8_t*& buf)
{
  /*
   * Allocate a new buffer in the TX pool.
   */
  auto* mbuf = rte_pktmbuf_alloc(m_txqpool);
  if (mbuf == nullptr) {
    return Status::NoMoreResources;
  }
  /*
   * Grab the data region.
   */
  buf = rte_pktmbuf_mtod(mbuf, uint8_t*);
  /*
   * Update the private data with the mbuf address.
   */
  *reinterpret_cast<struct rte_mbuf**>(buf - 8) = mbuf;
  /*
   * Done.
   */
  return Status::Ok;
}

Status
Device::commit(const uint32_t len, uint8_t* const buf,
               UNUSED const uint16_t mss)
{
  uint16_t res = 0;
  /*
   * Grab the packet buffer.
   */
  auto* mbuf = *reinterpret_cast<struct rte_mbuf**>(buf - 8);
  /*
   * Update the packet buffer length.
   */
  mbuf->data_len = len;
  mbuf->pkt_len = len;
  /*
   * Update the IP offload flags.
   */
  DPDK_LOG(std::hex << mbuf->ol_flags << std::dec);
#ifdef TULIPS_HAS_HW_CHECKSUM
  auto* ether_hdr = reinterpret_cast<const struct rte_ether_hdr*>(buf);
  if (ether_hdr->ether_type == htons(RTE_ETHER_TYPE_IPV4)) {
    mbuf->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
  }
#endif
  /*
   * Update the L4 offload flags.
   */
#ifdef TULIPS_HAS_HW_CHECKSUM
  auto offset = sizeof(struct rte_ether_hdr);
  auto* ip_hdr = reinterpret_cast<const struct rte_ipv4_hdr*>(buf + offset);
  if (ip_hdr->next_proto_id == IPPROTO_UDP) {
    mbuf->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
  }
  if (ip_hdr->next_proto_id == IPPROTO_TCP) {
    mbuf->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
  }
#endif
  DPDK_LOG(std::hex << mbuf->ol_flags << std::dec);
  /*
   * Prepare the packet.
   */
  res = rte_eth_tx_prepare(m_portid, 0, &mbuf, 1);
  if (res != 1) {
    DPDK_LOG("Packet preparation for TX failed: " << rte_strerror(rte_errno));
    return Status::HardwareError;
  }
  /*
   * Send the packet.
   */
  res = rte_eth_tx_burst(m_portid, 0, &mbuf, 1);
  if (res != 1) {
    DPDK_LOG("Sending packet failed");
    return Status::HardwareError;
  }
  /*
   * Free the buffer.
   */
  rte_pktmbuf_free(mbuf);
  /*
   * Print the stats.
   */
  struct rte_eth_stats stats;
  res = rte_eth_stats_get(m_portid, &stats);
  if (res != 0) {
    return Status::HardwareError;
  }
  DPDK_LOG("Stats: IN=" << stats.ipackets << ", OUT=" << stats.opackets);
  /*
   * Done.
   */
  return Status::Ok;
}
}
