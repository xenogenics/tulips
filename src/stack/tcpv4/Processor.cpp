#include "Debug.h"
#include <tulips/stack/IPv4.h>
#include <tulips/stack/TCPv4.h>
#include <tulips/stack/Utils.h>
#include <tulips/stack/tcpv4/Connection.h>
#include <tulips/stack/tcpv4/Options.h>
#include <tulips/stack/tcpv4/Processor.h>
#include <tulips/stack/tcpv4/Utils.h>
#include <tulips/system/Compiler.h>
#include <tulips/system/Utils.h>
#include <cstdint>
#include <cstring>

#ifdef __linux__
#include <arpa/inet.h>
#endif

namespace tulips::stack::tcpv4 {

Processor::Processor(system::Logger& log, transport::Device& device,
                     ethernet::Producer& eth, ipv4::Producer& ip4,
                     EventHandler& h)
  : m_log(log)
  , m_device(device)
  , m_ethto(eth)
  , m_ipv4to(ip4)
  , m_handler(h)
  , m_ethfrom(nullptr)
  , m_ipv4from(nullptr)
  , m_iss(0)
  , m_mss(m_ipv4to.mss() - HEADER_LEN)
  , m_listenports()
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
  m_conns.reserve(512);
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
     * Get the ticks and reset the timer.
     */
    auto ticks = m_fast.reset();
    /*
     * Call the handler.
     */
    auto ret = onFastTimer(ticks);
    if (ret != Status::Ok) {
      m_log.error("TCP", "error on FAST timer invocation: ", ret);
      return ret;
    }
  }
  /*
   * Check the slow timer.
   */
  if (m_slow.expired()) {
    /*
     * Get the ticks and reset the timer.
     */
    auto ticks = m_slow.reset();
    /*
     * Call the handler.
     */
    auto ret = onSlowTimer(ticks);
    if (ret != Status::Ok) {
      m_log.error("TCP", "error on SLOW timer invocation: ", ret);
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
    if (c->matches(m_ipv4from->sourceAddress(), *INTCP)) {
      if (c->m_state != Connection::CLOSED) {
        size_t bufcnt = 0;
        size_t buflen = 0;
        /*
         * Process the incoming packet.
         */
        auto ret = process(*c, len, data, ts);
        if (ret != Status::Ok) {
          return ret;
        }
        /*
         * Process any buffered packet.
         *
         * NOTE(xrg): stale frames are automatically ignored.
         */
        while (!c->m_fbuf.empty()) {
          auto const& frame = c->m_fbuf.peek();
          const uint32_t seqno = ntohl(frame.as<Header>().seqno);
          /*
           * Break if the frame is ahead.
           */
          if (SEQ_GT(seqno, c->m_rcv_nxt)) {
            break;
          }
          /*
           * Process the frame if the sequences match.
           */
          if (seqno == c->m_rcv_nxt) {
            auto ret = process(*c, frame.length(), frame.data(), ts);
            if (ret != Status::Ok) {
              return ret;
            }
          }
          /*
           * Update the counters.
           */
          bufcnt += 1;
          buflen += frame.length();
          /*
           * Pop the frame.
           */
          c->m_fbuf.pop();
        }
        /*
         * Log how many buffer we processed.
         */
        if (bufcnt > 0) {
          m_log.debug("TCP4", "<", c->id(), "> processed ", bufcnt,
                      " buffered frame(s) (", buflen, "B)");
        }
      }
      /*
       * Done.
       */
      return Status::Ok;
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
    if ((*e)->m_state == Connection::CLOSED) {
      break;
    }
  }
  /*
   * If no connection is available, take the oldest waiting connection
   */
  if (e == m_conns.end()) {
    for (auto c = m_conns.begin(); c != m_conns.end(); c++) {
      if ((*c)->m_state == Connection::TIME_WAIT) {
        if (e == m_conns.end() || (*c)->m_rtm > (*e)->m_rtm) {
          e = c;
        }
      }
    }
  }
  /*
   * If all connections are used already, allocate a new connection.
   */
  if (e == m_conns.end() && m_conns.size() < MAX_CONNECTIONS) {
    auto c = Connection::allocate(m_conns.size());
    m_conns.emplace_back(std::move(c));
    e = --m_conns.end();
  }
  /*
   * If we could not allocate a new connection, abort.
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
    m_log.error("TCP", "preparing buffer failed: ", ret);
    return ret;
  }
  /*
   * Prepare the connection.
   */
  (*e)->m_rethaddr = m_ethfrom->sourceAddress();
  (*e)->m_ripaddr = m_ipv4from->sourceAddress();
  (*e)->m_lport = INTCP->dstport;
  (*e)->m_rport = INTCP->srcport;
  (*e)->m_rcv_nxt = ntohl(INTCP->seqno) + 1;
  (*e)->m_snd_nxt = m_iss;
  (*e)->m_state = Connection::SYN_RCVD;
  (*e)->m_wndlvl = WndLimits::max();
  (*e)->m_atm = 0;
  (*e)->m_ktm = 0;
  (*e)->m_opts = 0;
  (*e)->m_ackdata = false;
  (*e)->m_newdata = false;
  (*e)->m_pshdata = false;
  (*e)->m_live = false;
  (*e)->m_wndscl = 0;
  (*e)->m_window = ntohs(INTCP->wnd);
  (*e)->m_nrtx = 0; // Initial SYN send
  (*e)->m_slen = 0;
  (*e)->m_sdat = nullptr;
  (*e)->m_initialmss = m_device.mtu() - HEADER_OVERHEAD;
  (*e)->m_mss = (*e)->m_initialmss;
  (*e)->m_sa = 0;
  (*e)->m_sv = 4; // Initial value of the RTT variance
  (*e)->m_rto = RTO;
  (*e)->m_rtm = RTO;
  /*
   * Prepare the connection segment. SYN segments don't contain any data but
   * have a size of 1 to increase the sequence number by 1.
   */
  Segment& seg = (*e)->m_segs->acquire();
  seg.set(1, (*e)->m_snd_nxt, sdat);
  /*
   * Parse the TCP MSS option, if present.
   */
  if (INTCP->offset > 5) {
    uint16_t nbytes = (INTCP->offset - 5) << 2;
    Options::parse(m_log, **e, nbytes, data);
  }
  /*
   * Update the connection index.
   */
  m_index.insert({ std::hash<Connection>()(**e), (*e)->id() });
  /*
   * Send the SYN/ACK.
   */
  return sendSynAck(**e, seg);
}

Status
Processor::sent(const uint16_t len, uint8_t* const data)
{
  m_log.trace("TCP4", "buffer ", (void*)data, " len ", len, " sent");
  /*
   * Release packets with no data segments (ACK, ACK-KeepAlive & RST).
   */
  if (len == HEADER_LEN || len == HEADER_LEN + 1) {
    if ((INTCP->flags & Flag::FIN) == 0) {
      return m_ipv4to.release(data);
    }
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
Processor::onFastTimer(const size_t ticks)
{
  /*
   * Scan the connections.
   */
  for (auto& e : m_conns) {
    /*
     * Only care about established connections.
     */
    if (e->m_state != Connection::ESTABLISHED) {
      continue;
    }
    /*
     * Skip the connection if it does not have delayed ACKs.
     */
    if (!HAS_DELAYED_ACK(*e)) {
      continue;
    }
    /*
     * Skip the connection if there is no active timer.
     */
    if (e->m_atm == 0) {
      continue;
    }
    /*
     * Update the delayed ack tick counter.
     */
    e->m_atm -= ticks > e->m_atm ? e->m_atm : ticks;
    /*
     * Skip the connection if the timer has not expired.
     */
    if (e->m_atm > 0) {
      continue;
    }
    /*
     * Send the delayed ACK.
     */
    auto ret = sendAck(*e, false);
    if (ret != Status::Ok) {
      m_log.error("TCP", "sending delayed ACK failed: ", ret);
      return ret;
    }
  }
  /*
   * Done.
   */
  return Status::Ok;
}

Status
Processor::onSlowTimer(const size_t ticks)
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
     * Ignore closed connections.
     */
    if (e->m_state == Connection::CLOSED) {
      continue;
    }
    /*
     * Handle connections that are just waiting to time out.
     */
    if (e->m_state == Connection::TIME_WAIT ||
        e->m_state == Connection::FIN_WAIT_2) {
      /*
       * Increase the connection's timer.
       */
      e->m_rtm += ticks;
      /*
       * If it timed out, close the connection.
       */
      if (e->m_rtm >= TIME_WAIT_TIMEOUT) {
        m_log.debug("TCP4", "<", e->id(), "> closed");
        close(*e);
      }
      /*
       * Done.
       */
      continue;
    }
    /*
     * Handle retransmissions.
     */
    if (e->m_segs->hasUsed()) {
      /*
       * Update the retransmission tick counter.
       */
      e->m_rtm -= ticks > e->m_rtm ? e->m_rtm : ticks;
      /*
       * Proceed with retransmissions.
       */
      if (e->m_rtm == 0) {
        /*
         * The connection has expired, reset it.
         */
        if (e->hasExpired()) {
          m_log.debug("TCP4", "<", e->id(), "> expired, aborting");
          /*
           * Abort the connection.
           */
          auto res = timeOut(*e);
          if (res != Status::Ok) {
            return res;
          }
          /*
           * Done.
           */
          continue;
        }
        /*
         * Exponential backoff.
         */
        e->m_rtm = RTO << (e->m_nrtx > 4 ? 4 : e->m_nrtx);
        e->m_nrtx += 1;
        /*
         * Print retransmission statistics.
         */
        m_log.debug("TCP4", "<", e->id(), "> automatic repeat request (",
                    size_t(e->m_nrtx), "/", MAXRTX, ")");
        m_log.debug("TCP4", "<", e->id(), "> segments available? ",
                    std::boolalpha, e->m_segs->hasFree());
        m_log.debug("TCP4", "<", e->id(), "> segments outstanding? ",
                    std::boolalpha, e->m_segs->hasUsed());
        /*
         * Retransmit.
         */
        auto ret = rexmit(*e);
        if (ret != Status::Ok) {
          return ret;
        }
      }
      /*
       * Done.
       */
      continue;
    }
    /*
     * Handle keep-alive.
     */
    if (e->m_state == Connection::ESTABLISHED && HAS_KEEP_ALIVE(*e)) {
      /*
       * Reset the live flag.
       */
      if (e->m_live) {
        e->m_live = false;
        e->m_ktm = KTO + 1;
        continue;
      }
      /*
       * Update the keep-alive tick counter.
       */
      e->m_ktm -= ticks > e->m_ktm ? e->m_ktm : ticks;
      /*
       * If the connection is not live, send the keep-alive.
       */
      if (e->m_ktm > 0 && e->m_segs->hasFree()) {
        m_log.trace("TCP4", "<", e->id(), "> KA ", int(e->m_ktm), "/", KTO);
        /*
         * Send the ACK.
         */
        auto ret = sendAck(*e, true);
        if (ret != Status::Ok) {
          return ret;
        }
        /*
         * Done.
         */
        continue;
      }
      /*
       * The keep-alive has expired.
       */
      m_log.debug("TCP4", "<", e->id(), "> expired, aborting");
      /*
       * Abort the connection.
       */
      auto res = timeOut(*e);
      if (res != Status::Ok) {
        return res;
      }
    }
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
   * Clear the frame buffer.
   */
  e.m_fbuf.clear();
  /*
   * Clear the segments.
   */
  for (auto& s : e.m_segs->container()) {
    if (s.length() > 0) {
      m_ipv4to.release(s.data());
      e.m_segs->release(s);
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
   * Reset the connection's data state
   */
  e.m_ackdata = false;
  e.m_newdata = false;
  e.m_pshdata = false;
  /*
   * Mark the connection live.
   */
  e.m_live = true;
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
              " seq:", seqno, " ack:", ackno,
              " seg:", size_t(e.m_segs->currentIndex()));
  /*
   * Check if the sequence number of the incoming packet is what we're
   * expecting next, except if we are expecting a SYN/ACK.
   */
  if (!(e.m_state == Connection::SYN_SENT &&
        (INTCP->flags & Flag::CTL) == (Flag::SYN | Flag::ACK))) {
    /*
     * If there is incoming data or if SYN or FIN is set.
     */
    if (plen > 0 || (INTCP->flags & (Flag::SYN | Flag::FIN)) != 0) {
      /*
       * And the sequence number is not expected.
       */
      if (seqno != e.m_rcv_nxt) {
        /*
         * Spurious rexmit, we just ignore those.
         */
        if (SEQ_LT(seqno, e.m_rcv_nxt)) {
          m_log.debug("TCP4", "<", e.id(), "> spurious rexmit of SEQ ", seqno);
        }
        /*
         * Out-of-order or dropped packet.
         */
        else {
          /*
           * Log the event.
           */
          if (e.m_fbuf.empty()) {
            const uint32_t diff = SEQ_DIFF(seqno, e.m_rcv_nxt);
            m_log.debug("TCP4", "<", e.id(), "> out-of-order SEQ: ", seqno,
                        " (", diff, "B), buffering");
          }
          /*
           * Push the frame in the buffer.
           */
          if (!e.m_fbuf.push(len, data, ts)) {
            const auto len = e.m_fbuf.length();
            m_log.debug("TCP4", "<", e.id(), "> still behind after ", len,
                        "B, aborting");
            return abort(e);
          }
        }
        /*
         * Reset the delayed ACK timer.
         */
        if (HAS_DELAYED_ACK(e)) {
          e.m_atm = 0;
        }
        /*
         * Send an ACK for the sequence number we expect.
         */
        return sendAck(e, false);
      }
    }
  }
  /*
   * Check if the incoming segment acknowledges any outstanding data. If so,
   * we update the sequence number, reset the length of the outstanding data,
   * calculate RTT estimations, and reset the retransmission timer.
   */
  if ((INTCP->flags & Flag::ACK) && e.m_segs->hasUsed()) {
    /*
     * Scan the available segments.
     *
     * NOTE(xrg): available segments are always contiguous. So we dont' bother
     * checking whether a segment is empty or not.
     */
    for (size_t i = 0; i < e.m_segs->used(); i += 1) {
      /*
       * Get the oldest pending segment.
       */
      Segment& seg = e.m_segs->currentSegment();
      /*
       * Compute the expected ackno.
       */
      uint64_t explm = (uint64_t)seg.seq() + seg.length();
      uint64_t acklm = ackno;
      /*
       * Linearly adjust the received ACK number to handle overflow cases.
       */
      if (ackno < seg.seq()) {
        acklm += 1ULL << 32;
      }
      /*
       * Check if the peers is letting us know about something that went amok.
       * It can be either an OoO packet or a window size change.
       */
      if (ackno == seg.seq()) {
        /*
         * Stop checking if the ACK is also a FIN or has payload. The current
         * segment could be in-flight and the server has not processed it yet.
         */
        if ((INTCP->flags & Flag::FIN) || plen > 0) {
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
      m_ipv4to.release(seg.data());
      /*
       * Clear the current segment and go to the next one.
       */
      e.m_segs->release(seg);
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
         * Update the connection info.
         */
        e.m_rcv_nxt += plen;
        e.m_newdata = plen > 0;
        e.m_pshdata = (INTCP->flags & Flag::PSH) == Flag::PSH;
        /*
         * Process any new data.
         */
        if (plen > 0) {
          auto res = sendAck(e, false);
          uint32_t rlen = 0;
          m_handler.onNewData(e, data + tcpHdrLen, plen, ts, 0, nullptr, rlen);
          return res;
        }
      }
      /*
       * Done.
       */
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
        e.m_window = window;
        e.m_rcv_nxt = seqno + 1;
        e.m_newdata = plen > 0;
        e.m_pshdata = (INTCP->flags & Flag::PSH) == Flag::PSH;
        /*
         * Parse the options.
         */
        if (INTCP->offset > 5) {
          uint16_t nbytes = (INTCP->offset - 5) << 2;
          Options::parse(m_log, e, nbytes, data);
        }
        /*
         * Send the ACK.
         */
        auto res = sendAck(e, false);
        /*
         * Notify the handler of the connection.
         */
        m_handler.onConnected(e, ts);
        /*
         * Notify the handler of any embedded data.
         */
        if (plen > 0) {
          uint32_t rlen = 0;
          m_handler.onNewData(e, data + tcpHdrLen, plen, ts, 0, nullptr, rlen);
        }
        /*
         * Done.
         */
        return res;
      }
      /*
       * Abort the connection and notify the handler.
       */
      m_log.debug("TCP4", "<", e.id(), "> failed, aborting");
      return abort(e);
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
        if (e.m_segs->hasUsed()) {
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
          uint32_t rlen = 0;
          m_handler.onNewData(e, data + tcpHdrLen, plen, ts, 0, nullptr, rlen);
        }
        /*
         * Acknowledge the FIN. If we are here there is no more outstanding
         * segment, so one must be available. FIN segments don't contain any
         * data but have a size of 1 to increase the sequence number by 1.
         */
        m_log.debug("TCP4", "<", e.id(), "> last ACK");
        e.m_state = Connection::LAST_ACK;
        Segment& seg = e.m_segs->acquire();
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
        bool can_send = e.m_segs->hasFree() && e.window() > e.m_slen;
        /*
         * Notify the application on an ACK.
         */
        if (e.m_ackdata) {
          const uint32_t bound = e.window() < m_mss ? e.window() : m_mss;
          /*
           * Declare the send parameters assuming we can send data back.
           */
          uint32_t savl = bound - e.m_slen;
          uint8_t* sdat = e.m_sdat + HEADER_LEN + e.m_slen;
          uint32_t slen = 0;
          /*
           * Reset the send parameters if we can't.
           */
          if (unlikely(!can_send)) {
            savl = 0;
            sdat = nullptr;
            slen = 0;
          }
          /*
           * Notify the handler.
           */
          auto res = m_handler.onAcked(e, ts, savl, sdat, slen);
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
          switch (res) {
            case Action::Abort: {
              m_log.debug("TCP4", "<", e.id(), "> onAcked() -> abort");
              return abort(e);
            }
            case Action::Close: {
              m_log.debug("TCP4", "<", e.id(), "> onAcked() -> close");
              return sendClose(e);
            }
            default: {
              break;
            }
          }
          /*
           * Truncate to available length if necessary
           */
          if (slen > savl) {
            slen = savl;
          }
          /*
           * Increase the send buffer length.
           */
          if (slen > 0) {
            m_log.trace("TCP", "<", e.id(), "> onAcked() -> ", slen, "B");
            e.m_slen += slen;
          }
          /*
           * Update the send state.
           */
          can_send = e.m_segs->hasFree() && e.window() > e.m_slen;
        }
        /*
         * Collect the connection's buffer state.
         */
        const uint8_t* rdat = data + tcpHdrLen + urglen;
        const uint32_t rlen = plen;
        const uint32_t snxt = e.m_snd_nxt;
        /*
         * Notify the application on new data.
         */
        if (e.m_newdata) {
          const uint32_t bound = e.window() < m_mss ? e.window() : m_mss;
          /*
           * Decrease the local window.
           */
          e.m_wndlvl -= rlen;
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
              can_send = e.m_segs->hasFree() && e.window() > 0;
            }
            /*
             * Otherwise, just send the ACK.
             */
            else {
              res = sendAck(e, false);
            }
            /*
             * Check the status.
             */
            if (res != Status::Ok) {
              return res;
            }
          }
          /*
           * Declare the send parameters assuming we can send data back.
           */
          uint32_t savl = bound - e.m_slen;
          uint8_t* sdat = e.m_sdat + HEADER_LEN + e.m_slen;
          uint32_t slen = 0;
          /*
           * Reset the send parameters if we can't.
           */
          if (unlikely(!can_send)) {
            savl = 0;
            sdat = nullptr;
            slen = 0;
          }
          /*
           * Call the handler.
           */
          auto res = m_handler.onNewData(e, rdat, rlen, ts, savl, sdat, slen);
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
          switch (res) {
            case Action::Abort: {
              m_log.debug("TCP4", "<", e.id(), "> onNewData() -> abort");
              return abort(e);
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
          if (slen > savl) {
            slen = savl;
          }
          /*
           * Increase the send buffer length.
           */
          if (slen > 0) {
            m_log.trace("TCP", "<", e.id(), "> onNewData() -> ", slen, "B");
            e.m_slen += slen;
          }
          /*
           * Update the send state.
           */
          can_send = e.m_segs->hasFree() && e.window() > e.m_slen;
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
          e.armAckTimer(snxt);
        }
        /*
         * Otherwise do nothing
         */
        return Status::Ok;
      }
      /*
       * Done.
       */
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
       * If we get a FIN, change the connection to TIME_WAIT if any pending
       * segment has been ACKEd, or CLOSING otherwise.
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
        auto ret = sendAck(e, false);
        m_handler.onClosed(e, ts);
        return ret;
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
        return sendAck(e, false);
      }
      /*
       * Done.
       */
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
        auto ret = sendAck(e, false);
        m_handler.onClosed(e, ts);
        return ret;
      }
      /*
       * ACK any received data.
       */
      if (plen > 0) {
        return sendAck(e, false);
      }
      /*
       * Done.
       */
      return Status::Ok;
    }
    case Connection::TIME_WAIT: {
      return sendAck(e, false);
    }
    /*
     * The user requested the connection to be closed.
     */
    case Connection::CLOSE: {
      /*
       * Check if there is still data in flight. In that case, keep waiting.
       */
      if (e.m_segs->hasUsed()) {
        break;
      }
      /*
       * Switch to FIN_WAIT_1. There is no more outstanding segment here so we
       * can grab one.
       */
      m_log.debug("TCP4", "<", e.id(), "> FIN wait #1");
      e.m_state = Connection::FIN_WAIT_1;
      Segment& seg = e.m_segs->acquire();
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
    default: {
      break;
    }
  }
  /*
   * Return status
   */
  return Status::Ok;
}
}
