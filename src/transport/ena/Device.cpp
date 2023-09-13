#include "tulips/fifo/fifo.h"
#include <tulips/stack/IPv4.h>
#include <tulips/stack/Utils.h>
#include <tulips/system/CircularBuffer.h>
#include <tulips/system/Clock.h>
#include <tulips/system/Compiler.h>
#include <tulips/transport/ena/Device.h>
#include <chrono>
#include <cstddef>
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
#include <dpdk/rte_thash.h>
#include <net/ethernet.h>

namespace tulips::transport::ena {

Device::Device(system::Logger& log, const uint16_t port_id,
               const uint16_t queue_id, const size_t nbuf, const size_t htsz,
               const size_t hlen, const uint8_t* const hkey,
               stack::ethernet::Address const& address, const uint32_t mtu,
               struct rte_mempool* const txpool, stack::ipv4::Address const& ip,
               stack::ipv4::Address const& dr, stack::ipv4::Address const& nm)
  : transport::Device(log, "ena_" + std::to_string(queue_id))
  , m_portid(port_id)
  , m_queueid(queue_id)
  , m_nbuf(nbuf)
  , m_htsz(htsz)
  , m_hlen(hlen)
  , m_hkey(hkey)
  , m_txpool(txpool)
  , m_reta(new struct rte_eth_rss_reta_entry64[htsz >> 6])
  , m_buffer(system::CircularBuffer::allocate(16384))
  , m_packet(new uint8_t[16384])
  , m_sent(TULIPS_FIFO_DEFAULT_VALUE)
  , m_address(address)
  , m_ip(ip)
  , m_dr(dr)
  , m_nm(nm)
  , m_mtu(mtu)
{
  /*
   * Create the sent FIFOs.
   */
  tulips_fifo_create(m_nbuf, sizeof(SentBuffer), &m_sent);
  /*
   * Print some device information.
   */
  if (m_queueid > 0) {
    log.debug("ENA", "port id: ", port_id);
    log.debug("ENA", "queue id: ", queue_id);
    log.debug("ENA", "ip address: ", m_ip.toString());
    log.debug("ENA", "netmask: ", m_nm.toString());
    log.debug("ENA", "router address: ", m_dr.toString());
  }
}

Device::~Device()
{
  tulips_fifo_destroy(&m_sent);
  delete[] m_reta;
  m_reta = nullptr;
  delete[] m_packet;
  m_packet = nullptr;
}

Status
Device::listen(UNUSED const stack::ipv4::Protocol proto, const uint16_t lport,
               stack::ipv4::Address const& raddr, const uint16_t rport)
{
  /*
   * Hash the payload and get the table index.
   */
  auto hash = stack::utils::toeplitz(raddr, m_ip, rport, lport, m_hlen, m_hkey);
  uint64_t indx = hash % m_htsz;
  uint64_t slot = indx >> 6;
  uint64_t eidx = indx & 0x3F;
  /*
   * Clear the RETA.
   */
  memset(m_reta, 0, sizeof(struct rte_eth_rss_reta_entry64[m_htsz >> 6]));
  m_reta[slot].mask = 1ULL << eidx;
  /*
   * Query the RETA.
   */
  auto ret = rte_eth_dev_rss_reta_query(m_portid, m_reta, m_htsz);
  if (ret < 0) {
    m_log.error("ENA", "failed to query the RETA");
    return Status::HardwareError;
  }
  /*
   * Print the existing configuration for the index.
   */
  auto preq = m_reta[slot].reta[eidx];
  m_log.debug("ENA", "LS hash/index: ", std::hex, hash, std::dec, "/", indx);
  m_log.debug("ENA", "RETA queue: ", preq);
  /*
   * Check the configuration.
   */
  if (preq != 0 && preq != m_queueid) {
    m_log.error("ENA", "RETA queue allocation conflict: ", preq);
    return Status::HardwareError;
  }
  /*
   * Skip if the existing queue allocation matches our queue.
   */
  if (preq == m_queueid) {
    return Status::Ok;
  }
  /*
   * Prepare the RETA for an update.
   */
  memset(m_reta, 0, sizeof(struct rte_eth_rss_reta_entry64[m_htsz >> 6]));
  m_reta[slot].mask = 1ULL << eidx;
  m_reta[slot].reta[eidx] = m_queueid;
  /*
   * Update the RETA.
   */
  ret = rte_eth_dev_rss_reta_update(m_portid, m_reta, m_htsz);
  if (ret != 0) {
    m_log.error("ENA", "failed to update the RETA");
    return Status::HardwareError;
  }
  /*
   * Done.
   */
  return Status::Ok;
}

void
Device::unlisten(UNUSED const stack::ipv4::Protocol proto,
                 UNUSED const uint16_t lport,
                 UNUSED stack::ipv4::Address const& raddr,
                 UNUSED const uint16_t rport)
{
  /*
   * Hash the payload and get the table index.
   */
  auto hash = stack::utils::toeplitz(raddr, m_ip, rport, lport, m_hlen, m_hkey);
  uint64_t indx = hash % m_htsz;
  uint64_t slot = indx >> 6;
  uint64_t eidx = indx & 0x3F;
  /*
   * Prepare the RETA for an update.
   */
  memset(m_reta, 0, sizeof(struct rte_eth_rss_reta_entry64[m_htsz >> 6]));
  m_reta[slot].mask = 1ULL << eidx;
  m_reta[slot].reta[eidx] = m_queueid;
  /*
   * Update the RETA.
   */
  rte_eth_dev_rss_reta_update(m_portid, m_reta, m_htsz);
}

Status
Device::poll(Processor& proc)
{
  /*
   * Process the sent buffers.
   */
  while (tulips_fifo_empty(m_sent) == TULIPS_FIFO_NO) {
    SentBuffer* info;
    /*
     * Get the front of the FIFO..
     */
    if (tulips_fifo_front(m_sent, (void**)&info) != TULIPS_FIFO_OK) {
      return Status::HardwareError;
    }
    /*
     * Pop the FIFO.
     */
    if (tulips_fifo_pop(m_sent) != TULIPS_FIFO_OK) {
      return Status::HardwareError;
    }
    /*
     * Notify the processor.
     */
    auto ret = proc.sent(std::get<0>(*info), std::get<1>(*info));
    if (ret != Status::Ok) {
      return ret;
    }
  }
  /*
   * Process the internal buffer.
   */
  if (!m_buffer->empty()) {
    uint16_t len = 0;
    system::Clock::Value ts = 0;
    m_buffer->read_all((uint8_t*)&len, sizeof(len));
    m_buffer->read_all((uint8_t*)&ts, sizeof(ts));
    m_buffer->read_all(m_packet, len);
    proc.process(len, m_packet, ts);
  }
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
          m_log.error("ENA", "invalid IP checksum, dropping packet");
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
          m_log.error("ENA", "invalid L4 checksum, dropping packet");
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
    m_log.trace("ENA", "processing addr=", (void*)dat, " len=", len);
    proc.process(len, dat, system::Clock::read());
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
Device::wait(Processor& proc, const uint64_t ns)
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
  m_log.trace("ENA", "preparing buffer ", (void*)buf);
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
Device::commit(const uint16_t len, uint8_t* const buf,
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
  res = rte_eth_tx_prepare(m_portid, m_queueid, &mbuf, 1);
  if (res != 1) {
    auto error = rte_strerror(rte_errno);
    m_log.error("ENA", "packet preparation for TX failed: ", error);
    return Status::HardwareError;
  }
  /*
   * Send the packet.
   */
  res = rte_eth_tx_burst(m_portid, m_queueid, &mbuf, 1);
  if (res != 1) {
    auto error = rte_strerror(rte_errno);
    m_log.error("ENA", "sending packet failed: ", error);
    return Status::HardwareError;
  }
  m_log.trace("ENA", "committing buffer ", (void*)buf, " len ", len);
  /*
   * Free the buffer.
   */
  auto info = SentBuffer(len, buf);
  tulips_fifo_push(m_sent, &buf);
  /*
   * Done.
   */
  return Status::Ok;
}

Status
Device::release(uint8_t* const buf)
{
  m_log.trace("ENA", "releasing buffer ", (void*)buf);
  auto* mbuf = *reinterpret_cast<struct rte_mbuf**>(buf - 8);
  rte_pktmbuf_free(mbuf);
  return Status::Ok;
}

}
