#include <tulips/stack/IPv4.h>
#include <tulips/stack/Utils.h>
#include <tulips/system/CircularBuffer.h>
#include <tulips/system/Clock.h>
#include <tulips/system/Compiler.h>
#include <tulips/transport/ena/Device.h>
#include <tulips/transport/ena/RedirectionTable.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <stdexcept>
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
               const uint16_t queue_id, const uint16_t ntxbs,
               const uint16_t nrxbs, RedirectionTable& reta,
               stack::ethernet::Address const& address, const uint32_t mtu,
               struct rte_mempool* const txpool, const bool bound)
  : transport::Device(log, "ena_" + std::to_string(queue_id))
  , m_portid(port_id)
  , m_qid(queue_id)
  , m_ntxbs(ntxbs)
  , m_nrxbs(nrxbs)
  , m_reta(reta)
  , m_txpool(txpool)
  , m_bound(bound)
  , m_buffer(system::CircularBuffer::allocate(16384))
  , m_packet(new uint8_t[16384])
  , m_free()
  , m_sent()
  , m_laststats(0)
  , m_address(address)
  , m_mtu(mtu)
{
  /*
   * Reserve space in the sent queue .
   */
  m_free.reserve(m_ntxbs);
  m_sent.reserve(m_ntxbs);
  /*
   * Populate the free buffer list.
   */
  for (size_t i = 0; i < m_ntxbs; i += 1) {
    auto* mbuf = rte_pktmbuf_alloc(m_txpool);
    if (mbuf == nullptr) {
      throw std::runtime_error("send buffer allocation failed");
    }
    m_free.push_back(mbuf);
  }
  /*
   * Print some device information.
   */
  if (m_qid > 0) {
    log.debug("ENA", "port id: ", port_id);
    log.debug("ENA", "queue id: ", queue_id);
  }
}

Device::~Device()
{
  /*
   * Clean-up the unreleased send buffers.
   */
  while (!m_sent.empty()) {
    auto info = m_sent.back();
    m_sent.pop_back();
    auto* mbuf = *reinterpret_cast<struct rte_mbuf**>(std::get<1>(info) - 8);
    rte_pktmbuf_free(mbuf);
  }
  /*
   * Clean-up the free send buffers.
   */
  while (!m_free.empty()) {
    auto mbuf = m_free.back();
    m_free.pop_back();
    rte_pktmbuf_free(mbuf);
  }
  /*
   * Delete the packet buffer.
   */
  delete[] m_packet;
  m_packet = nullptr;
}

Status
Device::clearSentBuffers(Processor& proc)
{

  while (!m_sent.empty()) {
    /*
     * Remove the last item (constant time).
     */
    auto& info = m_sent.back();
    m_sent.pop_back();
    /*
     * Notify the processor.
     */
    auto ret = proc.sent(std::get<0>(info), std::get<1>(info));
    if (ret != Status::Ok) {
      return ret;
    }
  }
  /*
   * Done.
   */
  return Status::Ok;
}

Status
Device::listen(UNUSED const stack::ipv4::Protocol proto,
               stack::ipv4::Address const& laddr, const uint16_t lport,
               stack::ipv4::Address const& raddr, const uint16_t rport)
{
  return m_reta.match(laddr, lport, raddr, rport, m_qid);
}

void
Device::unlisten(UNUSED const stack::ipv4::Protocol proto,
                 UNUSED stack::ipv4::Address const& laddr,
                 UNUSED const uint16_t lport,
                 UNUSED stack::ipv4::Address const& raddr,
                 UNUSED const uint16_t rport)
{}

Status
Device::poll(Processor& proc)
{
  using system::Clock;
  /*
   * Define the RX buffer quota.
   */
  static const uint16_t RX_QUOTA = 32;
  static const size_t INFO_THRESHOLD = m_nrxbs >> 1;
  /*
   * Print statistics every 10 seconds.
   */
  static const size_t PERIOD = 10 * Clock::toTicks(system::Clock::SECOND);
  /*
   * Cap the execution of the processor to 25ms.
   */
  static const size_t TIME_QUOTA_NS = 25 * system::Clock::MILLISECOND;
  static const size_t TIME_QUOTA = Clock::toTicks(TIME_QUOTA_NS);
  const auto start_ts = Clock::instant();
  /*
   * Print the stats every seconds on queue 0.
   */
  if (m_qid == 0 && Clock::instant() - m_laststats >= PERIOD) {
    struct rte_eth_stats stats;
    rte_eth_stats_get(m_portid, &stats);
    m_log.debug("ENA", "TX: pkts=", stats.opackets, " byts=", stats.obytes,
                " errs=", stats.oerrors);
    m_log.debug("ENA", "RX: pkts=", stats.ipackets, " byts=", stats.ibytes,
                " errs=", stats.ierrors, " miss=", stats.imissed);
    m_laststats = Clock::instant();
  }
  /*
   * Clear buffers sent out-of-band.
   */
  auto ret = clearSentBuffers(proc);
  if (ret != Status::Ok) {
    return ret;
  }
  /*
   * Process the internal buffer.
   */
  if (!m_buffer->empty()) {
    uint16_t len = 0;
    system::Clock::Epoch ts = 0;
    /*
     * Read a packet.
     */
    m_buffer->readAll((uint8_t*)&len, sizeof(len));
    m_buffer->readAll((uint8_t*)&ts, sizeof(ts));
    m_buffer->readAll(m_packet, len);
    /*
     * Process the packet.
     */
    ret = proc.process(len, m_packet, ts);
    if (ret != Status::Ok) {
      return ret;
    }
    /*
     * Run the processor.
     *
     * NOTE(xrg): it may not be necessary to run the processor here as these
     * packets are only errand ARP/IP packets.
     */
    ret = proc.run();
    if (ret != Status::Ok) {
      return ret;
    }
  }
  /*
   * Poll the device while there is data.
   */
  size_t pktcnt = 0;
  size_t end_ts = Clock::instant();
  while (end_ts - start_ts < TIME_QUOTA) {
    ret = poll(proc, RX_QUOTA, pktcnt);
    end_ts = Clock::instant();
    if (ret != Status::Ok) {
      break;
    }
  }
  /*
   * Log how many buffer were processed.
   */
  if (pktcnt > 0) {
    auto ns = Clock::toNanos(end_ts - start_ts);
    if (pktcnt > INFO_THRESHOLD || ns > TIME_QUOTA_NS) {
      m_log.debug("ENA", "[", m_qid, "] received buffers ", pktcnt, "/",
                  m_nrxbs, ", processed in ", ns, "ns");
    } else {
      m_log.trace("ENA", "[", m_qid, "] received buffers ", pktcnt, "/",
                  m_nrxbs, ", processed in ", ns, "ns");
    }
  }
  /*
   * Done.
   */
  return ret;
}

Status
Device::poll(Processor& proc, const uint16_t nrxbs, size_t& pktcnt)
{
  /*
   * Process the incoming receive buffers.
   */
  struct rte_mbuf* mbufs[nrxbs];
  auto nbrx = rte_eth_rx_burst(m_portid, m_qid, mbufs, nrxbs);
  /*
   * Update the counter.
   */
  pktcnt += nbrx;
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
          m_log.error("ENA", "[", m_qid, "] bad IP checksum, dropping packet");
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
          m_log.error("ENA", "[", m_qid, "] bad L4 checksum, dropping packet");
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
    m_log.trace("ENA", "[", m_qid, "] processing buffer addr=", (void*)dat,
                " len=", len);
    auto ret = proc.process(len, dat, system::Clock::now());
    /*
     * Check the processor's status.
     */
    if (ret != Status::Ok && ret != Status::UnsupportedProtocol) {
      m_log.error("ENA", "[", m_qid,
                  "] error processing buffer: ", toString(ret));
      return ret;
    }
    /*
     * Free the packet.
     */
    rte_pktmbuf_free(buf);
    /*
     * Clear buffers sent in-band.
     */
    ret = clearSentBuffers(proc);
    if (ret != Status::Ok) {
      return ret;
    }
    /*
     * Run the processor.
     *
     * NOTE(xrg): we run the processor here to make sure that the internal
     * timers in the stack are advancing properly.
     */
    ret = proc.run();
    if (ret != Status::Ok) {
      return ret;
    }
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

bool
Device::identify(const uint8_t* const buf) const
{
  const auto* mbuf = *reinterpret_cast<struct rte_mbuf* const*>(buf - 8);
  return mbuf->pool == m_txpool;
}

Status
Device::prepare(uint8_t*& buf)
{
  /*
   * Make sure we have free TX buffers.
   */
  if (m_free.empty()) {
    m_log.trace("ENA", "[", m_qid, "] no more TX buffer on queue: ");
    return Status::NoMoreResources;
  }
  /*
   * Get a new TX buffer.
   */
  auto mbuf = m_free.back();
  m_free.pop_back();
  /*
   * Grab the data region.
   */
  buf = rte_pktmbuf_mtod(mbuf, uint8_t*);
  m_log.trace("ENA", "[", m_qid, "] preparing buffer ", (void*)buf, " ",
              (void*)mbuf);
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
  m_log.trace("ENA", "[", m_qid, "] committing buffer ", (void*)buf, " len ",
              len, " ", (void*)mbuf);
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
    } else if (ip_hdr->next_proto_id == IPPROTO_TCP) {
      mbuf->l4_len = sizeof(struct rte_tcp_hdr);
#ifdef TULIPS_HAS_HW_CHECKSUM
      mbuf->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
#endif
    }
  }
  /*
   * Prepare the packet.
   */
  res = rte_eth_tx_prepare(m_portid, m_qid, &mbuf, 1);
  if (res != 1) {
    auto error = rte_strerror(rte_errno);
    m_log.error("ENA", "[", m_qid, "] preparing packet for TX failed: ", error);
    return Status::HardwareError;
  }
  /*
   * Send the packet.
   */
  res = rte_eth_tx_burst(m_portid, m_qid, &mbuf, 1);
  if (res != 1) {
    auto error = rte_strerror(rte_errno);
    m_log.error("ENA", "[", m_qid, "] sending packet failed: ", error);
    return Status::HardwareError;
  }
  /*
   * Queue the buffer.
   */
  m_sent.emplace_back(len, buf);
  /*
   * Done.
   */
  return Status::Ok;
}

Status
Device::release(uint8_t* const buf)
{
  auto* mbuf = *reinterpret_cast<struct rte_mbuf**>(buf - 8);
  m_log.trace("ENA", "[", m_qid, "] releasing buffer ", (void*)buf, " ",
              (void*)mbuf, " (", m_free.size() + 1, "/", m_ntxbs, ")");
  rte_pktmbuf_reset(mbuf);
  m_free.push_back(mbuf);
  return Status::Ok;
}

}
