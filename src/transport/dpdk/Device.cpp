#include <tulips/system/Compiler.h>
#include <tulips/transport/dpdk/Device.h>
#include <tulips/transport/dpdk/Utils.h>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <sstream>
#include <thread>
#include <dpdk/rte_config.h>
#include <dpdk/rte_dev.h>
#include <dpdk/rte_eal.h>
#include <dpdk/rte_ethdev.h>
#include <dpdk/rte_ether.h>
#include <dpdk/rte_flow.h>
#include <dpdk/rte_ip.h>
#include <dpdk/rte_mbuf.h>
#include <dpdk/rte_mbuf_core.h>
#include <dpdk/rte_mempool.h>
#include <net/ethernet.h>

namespace tulips::transport::dpdk {

Device::Device(const uint16_t port_id, const uint16_t queue_id,
               stack::ethernet::Address const& address, const uint32_t mtu,
               struct rte_mempool* const txpool, stack::ipv4::Address const& ip,
               stack::ipv4::Address const& dr, stack::ipv4::Address const& nm)
  : transport::Device()
  , m_portid(port_id)
  , m_queueid(queue_id)
  , m_txpool(txpool)
  , m_address(address)
  , m_ip(ip)
  , m_dr(dr)
  , m_nm(nm)
  , m_mtu(mtu)
{
  DPDK_LOG("ip address: " << m_ip.toString());
  DPDK_LOG("netmask: " << m_nm.toString());
  DPDK_LOG("router address: " << m_dr.toString());
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
  auto nbrx = rte_eth_rx_burst(m_portid, m_queueid, mbufs, 32);
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
          rte_pktmbuf_free(buf);
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
          rte_pktmbuf_free(buf);
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
  auto* mbuf = rte_pktmbuf_alloc(m_txpool);
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
  mbuf->l2_len = sizeof(struct rte_ether_hdr);
  /*
   * Update the IP offload flags.
   */
  auto* ether_hdr = reinterpret_cast<const struct rte_ether_hdr*>(buf);
  if (ether_hdr->ether_type == htons(RTE_ETHER_TYPE_IPV4)) {
    mbuf->l3_len = sizeof(struct rte_ipv4_hdr);
#ifdef TULIPS_HAS_HW_CHECKSUM
    mbuf->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
#endif
  }
  /*
   * Update the L4 offload flags.
   */
  auto offset = sizeof(struct rte_ether_hdr);
  auto* ip_hdr = reinterpret_cast<const struct rte_ipv4_hdr*>(buf + offset);
  if (ip_hdr->next_proto_id == IPPROTO_UDP) {
    mbuf->l4_len = sizeof(struct rte_udp_hdr);
#ifdef TULIPS_HAS_HW_CHECKSUM
    mbuf->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
#endif
  }
  if (ip_hdr->next_proto_id == IPPROTO_TCP) {
    mbuf->l4_len = sizeof(struct rte_tcp_hdr);
#ifdef TULIPS_HAS_HW_CHECKSUM
    mbuf->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
#endif
  }
  /*
   * Prepare the packet. NOTE(xrg): we can probably skip this.
   */
  res = rte_eth_tx_prepare(m_portid, 0, &mbuf, 1);
  if (res != 1) {
    DPDK_LOG("Packet preparation for TX failed: " << rte_strerror(rte_errno));
    return Status::HardwareError;
  }
  /*
   * Send the packet.
   */
  res = rte_eth_tx_burst(m_portid, m_queueid, &mbuf, 1);
  if (res != 1) {
    DPDK_LOG("Sending packet failed");
    return Status::HardwareError;
  }
  /*
   * Free the buffer.
   */
  rte_pktmbuf_free(mbuf);
  /*
   * Done.
   */
  return Status::Ok;
}

}
