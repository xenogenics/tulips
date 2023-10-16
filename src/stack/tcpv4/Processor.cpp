#include "Debug.h"
#include <tulips/stack/IPv4.h>
#include <tulips/stack/TCPv4.h>
#include <tulips/stack/Utils.h>
#include <tulips/stack/tcpv4/Connection.h>
#include <tulips/stack/tcpv4/Options.h>
#include <tulips/stack/tcpv4/Processor.h>
#include <tulips/system/Compiler.h>
#include <tulips/system/Utils.h>
#include <cstring>

#ifdef __linux__
#include <arpa/inet.h>
#endif

namespace tulips::stack::tcpv4 {

Processor::Processor(system::Logger& log, transport::Device& device,
                     ethernet::Producer& eth, ipv4::Producer& ip4,
                     EventHandler& h, const size_t nconn)
  : m_log(log)
  , m_device(device)
  , m_ethto(eth)
  , m_ipv4to(ip4)
  , m_handler(h)
  , m_nconn(nconn)
  , m_ethfrom(nullptr)
  , m_ipv4from(nullptr)
  , m_iss(0)
  , m_mss(m_ipv4to.mss() - HEADER_LEN)
  , m_listenports()
  , m_conns()
  , m_index()
  , m_stats()
  , m_fast()
  , m_slow()
{
  /*
   * Arm the timers.
   */
  m_fast.set(system::Clock::MILLISECOND);
  m_slow.set(system::Clock::SECOND);
  /*
   * Resize the connections.
   */
  m_conns.resize(nconn);
  /*
   * Set the connection IDs.
   */
  for (uint16_t id = 0; id < nconn; id += 1) {
    m_conns[id].m_id = id;
  }
}

void
Processor::listen(const Port lport)
{
  auto const& lip = m_ipv4to.hostAddress();
  if (m_device.listen(ipv4::Protocol::TCP, lip, lport) == Status::Ok) {
    m_listenports.insert(htons(lport));
  }
}

void
Processor::unlisten(const Port port)
{
  m_device.unlisten(ipv4::Protocol::TCP, m_ipv4to.hostAddress(), port);
  m_listenports.erase(htons(port));
}

Status
Processor::run()
{
  /*
   * Check the fast timer.
   */
  if (m_fast.expired()) {
    /*
     * Reset the timer.
     */
    m_fast.reset();
    /*
     * Call the handler.
     */
    auto ret = onFastTimer();
    if (ret != Status::Ok) {
      return ret;
    }
  }
  /*
   * Check the slow timer.
   */
  if (m_slow.expired()) {
    /*
     * Reset the timer.
     */
    m_slow.reset();
    /*
     * Call the handler.
     */
    auto ret = onSlowTimer();
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
Processor::process(const uint16_t len, const uint8_t* const data,
                   const Timestamp ts)
{
  Connections::iterator e;
  /*
   * Update the stats.
   */
  m_stats.recv += 1;
  /*
   * Compute and check the TCP checksum.
   */
#ifndef TULIPS_DISABLE_CHECKSUM_CHECK
  uint16_t csum = checksum(m_ipv4from->sourceAddress(),
                           m_ipv4from->destinationAddress(), len, data);
  if (csum != 0xffff) {
    m_stats.drop += 1;
    m_stats.chkerr += 1;
    m_log.error("TCP", "invalid checksum (",
                m_ipv4from->sourceAddress().toString(), ", ",
                m_ipv4from->destinationAddress().toString(), ", ", len, ", 0x",
                std::hex, csum, std::dec, ")");
    return Status::CorruptedData;
  }
#endif
  /*
   * Check existing connections.
   */
  auto i = m_index.find(std::hash<Header>()(*INTCP));
  if (i != m_index.end()) {
    auto& c = m_conns[i->second];
    if (c.m_state != Connection::CLOSED &&
        c.matches(m_ipv4from->sourceAddress(), *INTCP)) {
      return process(c, len, data, ts);
    }
  }
  /*
   * If we didn't find and active connection, either this packet is an old
   * duplicate or this is a SYN packet. If the SYN flag isn't set, we send
   * a RST.
   */
  if ((INTCP->flags & Flag::CTL) != Flag::SYN) {
    m_stats.rst += 1;
    return sendReset(data);
  }
  /*
   * No matching connection found, so we send a RST packet.
   */
  if (m_listenports.count(INTCP->dstport) == 0) {
    m_stats.synrst += 1;
    return sendReset(data);
  }
  /*
   * Handle the new connection. First we check if there are any connections
   * available. Unused connections are kept in the same table as used
   * connections, but unused ones have the tcpstate set to CLOSED. Also,
   * connections in TIME_WAIT are kept track of and we'll use the oldest one if
   * no CLOSED connections are found.
   */
  for (e = m_conns.begin(); e != m_conns.end(); e++) {
    if (e->m_state == Connection::CLOSED) {
      break;
    }
  }
  /*
   * If no connection is available, take the oldest waiting connection
   */
  if (e == m_conns.end()) {
    for (auto c = m_conns.begin(); c != m_conns.end(); c++) {
      if (c->m_state == Connection::TIME_WAIT) {
        if (e == m_conns.end() || c->m_rtm > e->m_rtm) {
          e = c;
        }
      }
    }
  }
  /*
   * If all connections are used already, we drop packet and hope that the
   * remote end will retransmit the packet at a time when we have more spare
   * connections.
   */
  if (e == m_conns.end()) {
    m_stats.syndrop += 1;
    return Status::Ok;
  }
  /*
   * Update IP and Ethernet attributes
   */
  m_ipv4to.setProtocol(ipv4::Protocol::TCP);
  m_ipv4to.setDestinationAddress(m_ipv4from->sourceAddress());
  m_ethto.setDestinationAddress(m_ethfrom->sourceAddress());
  /*
   * Allocate a send buffer
   */
  uint8_t* sdat;
  Status ret = m_ipv4to.prepare(sdat);
  if (ret != Status::Ok) {
    return ret;
  }
  /*
   * Prepare the connection.
   */
  e->m_rethaddr = m_ethfrom->sourceAddress();
  e->m_ripaddr = m_ipv4from->sourceAddress();
  e->m_lport = INTCP->dstport;
  e->m_rport = INTCP->srcport;
  e->m_rcv_nxt = ntohl(INTCP->seqno) + 1;
  e->m_snd_nxt = m_iss;
  e->m_state = Connection::SYN_RCVD;
  e->m_wndlvl = WndLimits::max();
  e->m_atm = 0;
  e->m_opts = 0;
  e->m_ackdata = false;
  e->m_newdata = false;
  e->m_pshdata = false;
  e->m_wndscl = 0;
  e->m_window = ntohs(INTCP->wnd);
  e->m_segidx = 0;
  e->m_nrtx = 0; // Initial SYN send
  e->m_slen = 0;
  e->m_sdat = nullptr;
  e->m_initialmss = m_device.mtu() - HEADER_OVERHEAD;
  e->m_mss = e->m_initialmss;
  e->m_sa = 0;
  e->m_sv = 4; // Initial value of the RTT variance
  e->m_rto = RTO;
  e->m_rtm = RTO;
  /*
   * Prepare the connection segment. SYN segments don't contain any data but
   * have a size of 1 to increase the sequence number by 1.
   */
  Segment& seg = e->nextAvailableSegment();
  seg.set(1, e->m_snd_nxt, sdat);
  /*
   * Parse the TCP MSS option, if present.
   */
  if (INTCP->offset > 5) {
    uint16_t nbytes = (INTCP->offset - 5) << 2;
    Options::parse(m_log, *e, nbytes, data);
  }
  /*
   * Update the connection index.
   */
  m_index.insert({ std::hash<Connection>()(*e), e->id() });
  /*
   * Send the SYN/ACK.
   */
  return sendSynAck(*e, seg);
}

Status
Processor::sent(const uint16_t len, uint8_t* const data)
{
  m_log.trace("TCP4", "buffer ", (void*)data, " len ", len, " sent");
  /*
   * Release packets with no data have no segments (ACK & RST).
   */
  if (len == HEADER_LEN && (INTCP->flags & Flag::FIN) == 0) {
    return m_ipv4to.release(data);
  }
  /*
   * Otherwise, we only release once the segment has cleared.
   */
  return Status::Ok;
}

#if !(defined(TULIPS_HAS_HW_CHECKSUM) && defined(TULIPS_DISABLE_CHECKSUM_CHECK))
uint16_t
Processor::checksum(ipv4::Address const& src, ipv4::Address const& dst,
                    const uint16_t len, const uint8_t* const data)
{
  uint16_t sum;
  /*
   * IP protocol and length fields. This addition cannot carry.
   */
  sum = len + uint8_t(ipv4::Protocol::TCP);
  /*
   * Sum IP source and destination addresses.
   */
  sum = utils::checksum(sum, (uint8_t*)&src, sizeof(src));
  sum = utils::checksum(sum, (uint8_t*)&dst, sizeof(dst));
  /*
   * Sum TCP header and data.
   */
  sum = utils::checksum(sum, data, len);
  return sum == 0 ? 0xffff : htons(sum);
}
#endif

Status
Processor::onFastTimer()
{
  /*
   * Scan the connections.
   */
  for (auto& e : m_conns) {
    /*
     * Only care about established connections.
     */
    if (e.m_state != Connection::ESTABLISHED) {
      continue;
    }
    /*
     * Skip the connection if it does not have delayed ACKs.
     */
    if (!HAS_DELAYED_ACK(e)) {
      continue;
    }
    /*
     * Skip the connection if there is no active timer.
     */
    if (e.m_atm == 0) {
      continue;
    }
    /*
     * Skip the connection if the timer has not expired.
     */
    if (--e.m_atm > 0) {
      continue;
    }
    /*
     * Send the delayed ACK.
     */
    auto ret = sendAck(e);
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
Processor::onSlowTimer()
{

  /*
   * Increase the initial sequence number.
   */
  m_iss += 1;
  /*
   * Scan the connections.
   */
  for (auto& e : m_conns) {
    /*
     * Ignore closed connections
     */
    if (e.m_state == Connection::CLOSED) {
      continue;
    }
    /*
     * Handle connections that are just waiting to time out.
     */
    if (e.m_state == Connection::TIME_WAIT ||
        e.m_state == Connection::FIN_WAIT_2) {
      /*
       * Increase the connection's timer.
       */
      e.m_rtm += 1;
      /*
       * If it timed out, close the connection.
       */
      if (e.m_rtm == TIME_WAIT_TIMEOUT) {
        m_log.debug("TCP4", "<", e.id(), "> closed");
        close(e);
      }
      /*
       * Skip the connection.
       */
      continue;
    }
    /*
     * If the connection does not have any outstanding data, skip it.
     */
    if (!e.hasOutstandingSegments()) {
      continue;
    }
    /*
     * Check if the connection needs a retransmission.
     */
    if (--e.m_rtm > 0) {
      continue;
    }
    /*
     * Retransmission has expired, reset the connection.
     */
    if (e.hasExpired()) {
      m_log.debug("TCP4", "<", e.id(), "> aborting");
      m_handler.onTimedOut(e, system::Clock::read());
      return sendAbort(e);
    }
    /*
     * Exponential backoff.
     */
    e.m_rtm = RTO << (e.m_nrtx > 4 ? 4 : e.m_nrtx);
    e.m_nrtx += 1;
    /*
     * Ok, so we need to retransmit.
     */
    m_log.debug("TCP4", "<", e.id(), "> automatic repeat request (",
                size_t(e.m_nrtx), "/", MAXRTX, ")");
    m_log.debug("TCP4", "<", e.id(), "> segments available? ", std::boolalpha,
                e.hasAvailableSegments());
    m_log.debug("TCP4", "<", e.id(), "> segments outstanding? ", std::boolalpha,
                e.hasOutstandingSegments());
    return rexmit(e);
  }
  /*
   * Done.
   */
  return Status::Ok;
}

void
Processor::close(Connection& e)
{
  /*
   * Unlisten the connection's local port.
   */
  m_device.unlisten(ipv4::Protocol::TCP, m_ipv4to.hostAddress(), e.m_lport);
  m_index.erase(std::hash<Connection>()(e));
  /*
   * Clear the segments.
   */
  for (auto& s : e.m_segments) {
    if (s.m_len > 0) {
      m_ipv4to.release(s.m_dat);
      s.clear();
    }
  }
  /*
   * Release the current send buffer.
   */
  m_ipv4to.release(e.m_sdat);
  /*
   * Update its state.
   */
  e.m_state = Connection::CLOSED;
}

Status
Processor::process(Connection& e, const uint16_t len, const uint8_t* const data,
                   const Timestamp ts)
{
  /*
   * Gather the input packet information.
   */
  uint16_t plen;
  uint16_t window = ntohs(INTCP->wnd);
  const uint32_t seqno = ntohl(INTCP->seqno);
  const uint32_t ackno = ntohl(INTCP->ackno);
  /*
   * Reset connection data state
   */
  e.m_ackdata = false;
  e.m_newdata = false;
  e.m_pshdata = false;
  /*
   * We do a very naive form of TCP reset processing; we just accept any RST
   * and kill our connection. We should in fact check if the sequence number
   * of this reset is within our advertised window before we accept the reset.
   */
  if (INTCP->flags & Flag::RST) {
    m_log.debug("TCP4", "<", e.id(), "> RST received, aborting");
    m_handler.onAborted(e, ts);
    close(e);
    return Status::Ok;
  }
  /*
   * Calculated the length of the data, if the application has sent any data
   * to us. plen will contain the length of the actual TCP data.
   */
  uint16_t tcpHdrLen = HEADER_LEN_WITH_OPTS(INTCP);
  plen = len - tcpHdrLen;
  /*
   * Print the flow information if requested.
   */
  m_log.trace("FLOW", "<", e.id(), "> -> ", getFlags(*INTCP), " len:", plen,
              " seq:", seqno, " ack:", ackno, " seg:", size_t(e.m_segidx));
  /*
   * Check if the sequence number of the incoming packet is what we're
   * expecting next, except if we are expecting a SYN/ACK.
   */
  if (!(e.m_state == Connection::SYN_SENT &&
        (INTCP->flags & Flag::CTL) == (Flag::SYN | Flag::ACK))) {
    /*
     * If there is incoming data or is SYN or FIN is set.
     */
    if (plen > 0 || (INTCP->flags & (Flag::SYN | Flag::FIN)) != 0) {
      /*
       * Send an ACK with the proper seqno if the received seqno is wrong.
       */
      if (seqno != e.m_rcv_nxt) {
        m_log.debug("TCP4", "<", e.id(), "> sequence ACK: in=", seqno,
                    " exp=", e.m_rcv_nxt);
        return sendAck(e);
      }
    }
  }
  /*
   * Check if the incoming segment acknowledges any outstanding data. If so,
   * we update the sequence number, reset the length of the outstanding data,
   * calculate RTT estimations, and reset the retransmission timer.
   */
  if ((INTCP->flags & Flag::ACK) && e.hasOutstandingSegments()) {
    /*
     * Scan the available segments.
     */
    for (size_t i = 0; i < e.usedSegments(); i += 1) {
      /*
       * Get the oldest pending segment.
       */
      Segment& seg = e.segment();
      /*
       * Compute the expected ackno.
       */
      uint64_t explm = (uint64_t)seg.m_seq + seg.m_len;
      uint64_t acklm = ackno;
      /*
       * Linearly adjust the received ACK number to handle overflow cases.
       */
      if (ackno < seg.m_seq) {
        acklm += 1ULL << 32;
      }
      /*
       * Check if the peers is letting us know about something that went amok.
       * It can be either an OoO packet or a window size change.
       */
      if (ackno == seg.m_seq) {
        /*
         * Skip scanning if the ACK has payload (in-flight packet).
         */
        if (plen > 0) {
          break;
        }
        /*
         * In case of a window size change.
         */
        if (e.window() != e.window(window)) {
          e.m_window = window;
          m_log.debug("TCP4", "<", e.id(), "> peer wnd updated: ", e.window(),
                      " on seq:", ackno);
          /*
           * Do RTT estimation, unless we have done retransmissions. There is
           * no reason to have a REXMIT at this point.
           */
          if (e.m_nrtx == 0) {
            e.updateRttEstimation();
            e.m_rtm = e.m_rto;
          }
          /*
           * Skip scanning.
           */
          break;
        }
        /*
         * In case of an OoO packet, let the ARQ do its job.
         */
        m_log.debug("TCP4", "<", e.id(),
                    "> peer rexmit request on seq:", ackno);
        return rexmit(e);
      }
      /*
       * Check if it's partial ACK (common with TSO). The first check covers
       * the normal linear case. The second checks covers wrap-around
       * situations.
       */
      else if (acklm < explm) {
        m_stats.ackerr += 1;
        break;
      }
      /*
       * Housekeeping in case we have not processed an ACK yet.
       */
      if (!e.m_ackdata) {
        /*
         * Do RTT estimation, unless we have done retransmissions.
         */
        if (e.m_nrtx == 0) {
          e.updateRttEstimation();
        }
        /*
         * Clear the retransmission counter.
         */
        e.m_nrtx = 0;
        /*
         * Set the acknowledged flag.
         */
        e.m_ackdata = true;
        /*
         * Reset the retransmission timer.
         */
        e.m_rtm = e.m_rto;
      }
      /*
       * Release the buffer associated with the segment.
       */
      m_ipv4to.release(seg.m_dat);
      /*
       * Clear the current seqgment and go to the next segment. The compiler
       * will generate the wrap-around appropriate for the bit length of the
       * index.
       */
      seg.clear();
      e.m_segidx += 1;
      /*
       * Stop processing the segments if the ACK number is the one expected.
       */
      if (acklm == explm) {
        break;
      }
    }
  }
  /*
   * Do different things depending on in what state the connection is. CLOSED
   * and LISTEN are not handled here. CLOSE_WAIT is not implemented, since we
   * force the application to close when the peer sends a FIN (hence the
   * application goes directly from ESTABLISHED to LAST_ACK).
   */
  switch (e.m_state) {
    /*
     * In SYN_RCVD we have sent out a SYNACK in response to a SYN, and we are
     * waiting for an ACK that acknowledges the data we sent out the last
     * time. If so, we enter the ESTABLISHED state.
     */
    case Connection::SYN_RCVD: {
      /*
       * Process the ACK data if any.
       */
      if (e.m_ackdata) {
        m_log.debug("TCP4", "<", e.id(), "> established");
        /*
         * Send the connection event.
         */
        e.m_state = Connection::ESTABLISHED;
        m_handler.onConnected(e, ts);
        /*
         * Send the newdata event. Pass the packet data directly. At this
         * stage, no data has been buffered.
         */
        if (plen > 0) {
          e.m_rcv_nxt += plen;
          e.m_newdata = true;
          e.m_pshdata = (INTCP->flags & Flag::PSH) == Flag::PSH;
          m_handler.onNewData(e, data + tcpHdrLen, plen, ts);
          return sendAck(e);
        }
      }
      break;
    }
    /*
     * In SYN_SENT, we wait for a SYNACK that is sent in response to our SYN.
     * The rcv_nxt is set to sequence number in the SYNACK plus one, and we
     * send an ACK. We move into the ESTABLISHED state.
     */
    case Connection::SYN_SENT: {
      /*
       * Update the connection when established.
       */
      if (e.m_ackdata &&
          (INTCP->flags & Flag::CTL) == (Flag::SYN | Flag::ACK)) {
        m_log.debug("TCP4", "<", e.id(), "> established");
        /*
         * Update the connection info
         */
        e.m_state = Connection::ESTABLISHED;
        e.m_rcv_nxt = seqno + 1;
        e.m_window = window;
        /*
         * Parse the options.
         */
        if (INTCP->offset > 5) {
          uint16_t nbytes = (INTCP->offset - 5) << 2;
          Options::parse(m_log, e, nbytes, data);
        }
        /*
         * Send the connected event.
         */
        m_handler.onConnected(e, ts);
        /*
         * Send the newdata event. Pass the packet data directly. At this
         * stage, no data has been buffered.
         */
        if (plen > 0) {
          e.m_newdata = true;
          e.m_pshdata = (INTCP->flags & Flag::PSH) == Flag::PSH;
          m_handler.onNewData(e, data + tcpHdrLen, plen, ts);
        }
        return sendAck(e);
      }
      /*
       * Inform the application that the connection failed.
       */
      m_log.debug("TCP4", "<", e.id(), "> failed, aborting");
      m_handler.onAborted(e, ts);
      /*
       * The connection is closed after we send the RST.
       */
      return sendAbort(e);
    }
    /*
     * In the ESTABLISHED state, we call upon the application to feed data
     * into the m_buf. If the ACKDATA flag is set, the application
     * should put new data into the buffer, otherwise we are retransmitting
     * an old segment, and the application should put that data into the
     * buffer. If the incoming packet is a FIN, we should close the
     * connection on this side as well, and we send out a FIN and enter the
     * LAST_ACK state. We require that there is no outstanding data;
     * otherwise the sequence numbers will be screwed up.
     */
    case Connection::ESTABLISHED: {
      /*
       * Check if we received a FIN request and process it.
       */
      if (INTCP->flags & Flag::FIN) {
        /*
         * If some of our data is still in flight, ignore the FIN.
         */
        if (e.hasOutstandingSegments()) {
          m_log.debug("TCP4", "<", e.id(),
                      "> FIN received but outstanding data");
          return Status::Ok;
        }
        /*
         * Increase the expected next pointer.
         */
        e.m_rcv_nxt += plen + 1;
        /*
         * Process the embedded data.
         */
        if (plen > 0) {
          m_handler.onNewData(e, data + tcpHdrLen, plen, ts);
        }
        /*
         * Acknowledge the FIN. If we are here there is no more outstanding
         * segment, so one must be available. FIN segments don't contain any
         * data but have a size of 1 to increase the sequence number by 1.
         */
        m_log.debug("TCP4", "<", e.id(), "> last ACK");
        e.m_state = Connection::LAST_ACK;
        Segment& seg = e.nextAvailableSegment();
        seg.set(1, e.m_snd_nxt, e.m_sdat);
        e.resetSendBuffer();
        return sendFinAck(e, seg);
      }
      /*
       * Check the URG flag. If this is set, the segment carries urgent data
       * that we must pass to the application. NOTE: skip it for ts.
       */
      uint16_t urglen = 0;
      if ((INTCP->flags & Flag::URG) != 0) {
        urglen = ntohs(INTCP->urgp);
        plen -= urglen;
      }
      /*
       * If plen > 0 we have TCP data in the packet, and we flag this by
       * setting the NEWDATA flag and update the sequence number we
       * acknowledge.
       */
      if (plen > 0) {
        e.m_newdata = true;
        e.m_pshdata = (INTCP->flags & Flag::PSH) == Flag::PSH;
        e.m_rcv_nxt += plen;
      }
      /*
       * Update the peer window value.
       */
      e.m_window = window;
      /*
       * Check if the available buffer space advertised by the other end is
       * smaller than the initial MSS for this connection. If so, we set the
       * current MSS to the window size to ensure that the application does
       * not send more data than the other end can handle.
       */
      if (e.window() <= e.m_initialmss && e.window() > 0) {
        e.m_mss = e.window();
      }
      /*
       * If the remote host advertises a zero window or a window larger than
       * the initial negotiated window, we set the MSS to the initial MSS so
       * that the application will send an entire MSS of data. This data will
       * not be acknowledged by the receiver, and the application will
       * retransmit it. This is called the "persistent timer" and uses the
       * retransmission mechanim.
       */
      else {
        e.m_mss = e.m_initialmss;
      }
      /*
       * If this packet constitutes an ACK for outstanding data (flagged by
       * the ACKDATA flag, we should call the application since it might want
       * to send more data. If the incoming packet had data from the peer (as
       * flagged by the NEWDATA flag), the application must also be
       * notified.
       */
      if (e.m_ackdata || e.m_newdata) {
        /*
         * Check if the application can send.
         */
        bool can_send = e.hasAvailableSegments() && e.window() > e.m_slen;
        /*
         * Notify the application on an ACK.
         */
        if (e.m_ackdata) {
          /*
           * Check if we can send data as a result of the ACK. This is useful
           * to handle partial send without resorting to software TSO.
           */
          if (likely(can_send)) {
            uint32_t rlen = 0;
            uint32_t bound = e.window() < m_mss ? e.window() : m_mss;
            uint32_t alen = bound - e.m_slen;
            /*
             * Notify the handler.
             */
            auto* const buffer = e.m_sdat + HEADER_LEN + e.m_slen;
            auto action = m_handler.onAcked(e, ts, alen, buffer, rlen);
            /*
             * Bail out if the connection was aborted.
             */
            if (e.m_state == Connection::State::CLOSED) {
              m_log.debug("TCP4", "<", e.id(), "> connection aborted");
              break;
            }
            /*
             * Process the action.
             */
            switch (action) {
              case Action::Abort:
                m_log.debug("TCP4", "<", e.id(), "> onAcked() -> abort");
                m_handler.onAborted(e, ts);
                return sendAbort(e);
              case Action::Close:
                m_log.debug("TCP4", "<", e.id(), "> onAcked() -> close");
                return sendClose(e);
              default:
                break;
            }
            /*
             * Truncate to available length if necessary
             */
            if (rlen > alen) {
              rlen = alen;
            }
            e.m_slen += rlen;
            /*
             * Update the send state.
             */
            can_send = e.hasAvailableSegments() && e.window() > e.m_slen;
          }
          /*
           * If we cannot send anything, just notify the application.
           */
          else {
            /*
             * Notify the handler.
             */
            auto action = m_handler.onAcked(e, ts);
            /*
             * Bail out if the connection was aborted.
             */
            if (e.m_state == Connection::State::CLOSED) {
              m_log.debug("TCP4", "<", e.id(), "> connection aborted");
              break;
            }
            /*
             * Process the action.
             */
            switch (action) {
              case Action::Abort:
                m_log.debug("TCP4", "<", e.id(), "> onAcked() -> abort");
                m_handler.onAborted(e, ts);
                return sendAbort(e);
              case Action::Close:
                m_log.debug("TCP4", "<", e.id(), "> onAcked() -> close");
                return sendClose(e);
              default:
                break;
            }
          }
        }
        /*
         * Collect the connection's buffer state.
         */
        const uint8_t* dataptr = data + tcpHdrLen + urglen;
        const uint32_t datalen = plen;
        const uint32_t sendnxt = e.m_snd_nxt;
        /*
         * Notify the application on new data.
         */
        if (e.m_newdata) {
          /*
           * Decrease the local window.
           */
          e.m_wndlvl -= datalen;
          /*
           * Send an ACK immediately if the connection does not have
           * DELAYED_ACK or if the local window level is 0.
           */
          if (!HAS_DELAYED_ACK(e) || e.m_wndlvl == 0) {
            Status res;
            /*
             * If there is data in the send buffer, send it as well.
             */
            if (e.hasPendingSendData() && can_send) {
              res = sendNoDelay(e, Flag::PSH);
              can_send = e.hasAvailableSegments() && e.window() > 0;
            }
            /*
             * Otherwise, just send the ACK. This will cause the
             */
            else {
              res = sendAck(e);
            }
            /*
             * Check the status.
             */
            if (res != Status::Ok) {
              return res;
            }
          }
          /*
           * Notify the application and allow it to send a response.
           */
          if (likely(can_send)) {
            uint32_t rlen = 0;
            uint32_t bound = e.window() < m_mss ? e.window() : m_mss;
            uint32_t alen = bound - e.m_slen;
            /*
             * Call the handler.
             */
            auto action = m_handler.onNewData(e, dataptr, datalen, ts, alen,
                                              e.m_sdat + HEADER_LEN + e.m_slen,
                                              rlen);
            /*
             * Bail out if the connection was aborted.
             */
            if (e.m_state == Connection::State::CLOSED) {
              m_log.debug("TCP4", "<", e.id(), "> connection aborted");
              break;
            }
            /*
             * Execute the action.
             */
            switch (action) {
              case Action::Abort: {
                m_log.debug("TCP4", "<", e.id(), "> onNewData() -> abort");
                m_handler.onAborted(e, ts);
                return sendAbort(e);
              }
              case Action::Close: {
                m_log.debug("TCP4", "<", e.id(), "> onNewData() -> close");
                return sendClose(e);
              }
              default: {
                break;
              }
            }
            /*
             * Truncate to available length if necessary
             */
            if (rlen > alen) {
              rlen = alen;
            }
            /*
             * Increase the send buffer length.
             */
            if (rlen > 0) {
              m_log.trace("TCP", "<", e.id(), "> onNewData() -> ", rlen, "B");
              e.m_slen += rlen;
            }
          }
          /*
           * Notify the application.
           */
          else {
            /*
             * Call the handler.
             */
            auto action = m_handler.onNewData(e, dataptr, datalen, ts);
            /*
             * Bail out if the connection was aborted.
             */
            if (e.m_state == Connection::State::CLOSED) {
              m_log.debug("TCP4", "<", e.id(), "> connection aborted");
              break;
            }
            /*
             * Execute the action.
             */
            switch (action) {
              case Action::Abort: {
                m_log.debug("TCP4", "<", e.id(), "> onNewData() -> abort");
                m_handler.onAborted(e, ts);
                return sendAbort(e);
              }
              case Action::Close: {
                m_log.debug("TCP4", "<", e.id(), "> onNewData() -> close");
                return sendClose(e);
              }
              default: {
                break;
              }
            }
          }
        }
        /*
         * If there is any buffered send data, send it.
         */
        if (e.hasPendingSendData() && can_send) {
          return sendNoDelay(e, Flag::PSH);
        }
        /*
         * If the connection supports DELAYED_ACK, arm the ACK timer.
         */
        if (HAS_DELAYED_ACK(e)) {
          e.armAckTimer(sendnxt);
        }
        /*
         * Otherwise do nothing
         */
        return Status::Ok;
      }
      break;
    }
    /*
     * We can close this connection if the peer has acknowledged our FIN. This
     * is indicated by the ACKDATA flag.
     */
    case Connection::LAST_ACK: {
      if (e.m_ackdata) {
        m_log.debug("TCP4", "<", e.id(), "> closed");
        m_handler.onClosed(e, ts);
        close(e);
      }
      break;
    }
    /*
     * The application has closed the connection, but the remote host hasn't
     * closed its end yet. Thus we do nothing but wait for a FIN from the
     * other side.
     */
    case Connection::FIN_WAIT_1: {
      if (plen > 0) {
        e.m_rcv_nxt += plen;
      }
      /*
       * If we get a FIN, change the connection to TIME_WAIT or CLOSING.
       */
      if (INTCP->flags & Flag::FIN) {
        if (e.m_ackdata) {
          m_log.debug("TCP4", "<", e.id(), "> time-wait");
          e.m_state = Connection::TIME_WAIT;
          e.m_rtm = 0;
        } else {
          m_log.debug("TCP4", "<", e.id(), "> closing");
          e.m_state = Connection::CLOSING;
        }
        e.m_rcv_nxt += 1;
        m_handler.onClosed(e, ts);
        return sendAck(e);
      }
      /*
       * Otherwise, if we received an ACK, moved to FIN_WAIT_2.
       */
      else if (e.m_ackdata) {
        m_log.debug("TCP4", "<", e.id(), "> FIN wait #2");
        e.m_state = Connection::FIN_WAIT_2;
        return Status::Ok;
      }
      /*
       * ACK any received data.
       */
      if (plen > 0) {
        return sendAck(e);
      }
      return Status::Ok;
    }
    case Connection::FIN_WAIT_2: {
      if (plen > 0) {
        e.m_rcv_nxt += plen;
      }
      /*
       * If we get a FIN, moved to TIME_WAIT.
       */
      if (INTCP->flags & Flag::FIN) {
        m_log.debug("TCP4", "<", e.id(), "> time-wait");
        e.m_state = Connection::TIME_WAIT;
        e.m_rcv_nxt += 1;
        e.m_rtm = 0;
        m_handler.onClosed(e, ts);
        return sendAck(e);
      }
      /*
       * ACK any received data.
       */
      if (plen > 0) {
        return sendAck(e);
      }
      return Status::Ok;
    }
    case Connection::TIME_WAIT: {
      return sendAck(e);
    }
    /*
     * The user requested the connection to be closed.
     */
    case Connection::CLOSE: {
      /*
       * Check if there is still data in flight. In that case, keep waiting.
       */
      if (e.hasOutstandingSegments()) {
        break;
      }
      /*
       * Switch to FIN_WAIT_1. There is no more outstanding segment here so we
       * can grab one.
       */
      m_log.debug("TCP4", "<", e.id(), "> FIN wait #1");
      e.m_state = Connection::FIN_WAIT_1;
      Segment& seg = e.nextAvailableSegment();
      seg.set(1, e.m_snd_nxt, e.m_sdat);
      e.resetSendBuffer();
      /*
       * If there is some new data, ignore it.
       */
      if (plen > 0) {
        e.m_newdata = true;
        e.m_pshdata = (INTCP->flags & Flag::PSH) == Flag::PSH;
        e.m_rcv_nxt += plen;
      }
      /*
       * Send a FIN/ACK message. TCP does not require to send an ACK with FIN,
       * but Linux seems pretty bent on wanting one. So we play nice. FIN
       * segments don't contain any data but have a size of 1 to increase the
       * sequence number by 1.
       */
      return sendFinAck(e, seg);
    }
    case Connection::CLOSING: {
      if (e.m_ackdata) {
        m_log.debug("TCP4", "<", e.id(), "> time-wait");
        e.m_state = Connection::TIME_WAIT;
        e.m_rtm = 0;
      }
      break;
    }
    /*
     * Unhandled cases.
     */
    case Connection::CLOSED: {
      break;
    }
  }
  /*
   * Return status
   */
  return Status::Ok;
}
}
