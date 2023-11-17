#include "Debug.h"
#include <tulips/stack/IPv4.h>
#include <tulips/stack/TCPv4.h>
#include <tulips/stack/Utils.h>
#include <tulips/stack/tcpv4/Options.h>
#include <tulips/stack/tcpv4/Processor.h>
#include <tulips/system/Compiler.h>
#include <tulips/system/Utils.h>
#include <cstring>

#ifdef __linux__
#include <arpa/inet.h>
#endif

namespace tulips::stack::tcpv4 {

Status
Processor::sendNagle(Connection& e, const uint32_t bound)
{
  /*
   * If the send buffer is full, send immediately.
   */
  if (e.m_slen == bound) {
    Segment& seg = e.nextAvailableSegment();
    seg.set(e.m_slen, e.m_snd_nxt, e.m_sdat);
    e.resetSendBuffer();
    return send(e, seg, Flag::PSH);
  }
  /*
   * If there is data in flight, enqueue.
   */
  if (e.hasOutstandingSegments()) {
    return Status::Ok;
  }
  /*
   * Send the segment.
   */
  return sendNoDelay(e, Flag::PSH);
}

Status
Processor::sendNoDelay(Connection& e, const uint8_t flag)
{
  Segment& seg = e.nextAvailableSegment();
  seg.set(e.m_slen, e.m_snd_nxt, e.m_sdat);
  e.resetSendBuffer();
  return send(e, seg, flag);
}

Status
Processor::sendAbort(Connection& e)
{
  m_log.debug("TCP4", "<", e.id(), "> send RST");
  /*
   * Update the TCP headers.
   */
  uint8_t* outdata = e.m_sdat;
  OUTTCP->flags = Flag::RST;
  OUTTCP->flags |= e.m_newdata ? Flag::ACK : 0;
  OUTTCP->offset = 5;
  /*
   * Ignore any pending data.
   */
  e.m_slen = 0;
  /*
   * Send the packet.
   */
  return send(e, false);
}

Status
Processor::sendReset(const uint8_t* const data)
{
  uint8_t* outdata;
  /*
   * We do not send resets in response to resets.
   */
  if (INTCP->flags & Flag::RST) {
    return Status::Ok;
  }
  /*
   * Update IP and Ethernet attributes
   */
  m_ipv4to.setProtocol(ipv4::Protocol::TCP);
  m_ipv4to.setDestinationAddress(m_ipv4from->sourceAddress());
  m_ethto.setDestinationAddress(m_ethfrom->sourceAddress());
  /*
   * Allocate the send buffer
   */
  Status ret = m_ipv4to.prepare(outdata);
  if (ret != Status::Ok) {
    return ret;
  }
  /*
   * Update the flags.
   */
  m_stats.rst += 1;
  OUTTCP->flags = Flag::RST;
  OUTTCP->offset = 5;
  /*
   * Flip the seqno and ackno fields in the TCP header. We also have to
   * increase the sequence number we are acknowledging.
   */
  uint32_t c = ntohl(INTCP->seqno);
  OUTTCP->seqno = INTCP->ackno;
  OUTTCP->ackno = htonl(c + 1);
  /*
   * Swap port numbers.
   */
  uint16_t tmp16 = INTCP->srcport;
  OUTTCP->srcport = INTCP->dstport;
  OUTTCP->dstport = tmp16;
  /*
   * And send out the RST packet!
   */
  uint16_t mss = m_device.mtu() - HEADER_OVERHEAD;
  return send(m_ipv4from->sourceAddress(), HEADER_LEN, mss, outdata);
}

Status
Processor::sendClose(Connection& e)
{
  /*
   * This function MUST be called when segments are available. Making sure of
   * this is the responsibility of the caller.
   */
  if (!e.hasAvailableSegments()) {
    m_log.error("TCP4", "<", e.id(), "> close() without available segments");
    return Status::NoMoreResources;
  }
  /*
   * Send a FIN/ACK message. TCP does not require to send an ACK with FIN,
   * but Linux seems pretty bent on wanting one. So we play nice.
   */
  m_log.debug("TCP4", "<", e.id(), "> FIN wait #1");
  e.m_state = Connection::FIN_WAIT_1;
  Segment& seg = e.nextAvailableSegment();
  seg.set(1, e.m_snd_nxt, e.m_sdat);
  e.resetSendBuffer();
  return sendFinAck(e, seg);
}

Status
Processor::sendAck(Connection& e, const bool k)
{
  uint8_t bdat[e.m_mss];
  uint32_t blen = 0;
  /*
   * Save the pending send data. We only end-up here if we must send an ACK
   * and we cannot send the pending data (ie. no more available segments or
   * the peer window does not allow it).
   */
  if (unlikely(e.hasPendingSendData())) {
    memcpy(bdat, e.m_sdat, e.m_slen);
    blen = e.m_slen;
    e.m_slen = 0;
  }
  /*
   * Prepare the frame for an ACK.
   */
  uint8_t* outdata = e.m_sdat;
  OUTTCP->flags = Flag::ACK;
  OUTTCP->offset = 5;
  auto ret = send(e, k);
  /*
   * Restore any saved send data.
   */
  if (blen > 0) {
    memcpy(e.m_sdat, bdat, blen);
    e.m_slen = blen;
  }
  /*
   * Done.
   */
  return ret;
}

Status
Processor::sendSyn(Connection& e, Segment& s)
{
  uint8_t* outdata = s.m_dat;
  uint16_t len = HEADER_LEN + Options::MSS_LEN + Options::WSC_LEN + 1;
  OUTTCP->flags |= Flag::SYN;
  OUTTCP->offset = len >> 2;
  /*
   * We send out the TCP Maximum Segment Size option with our SYNACK.
   */
  OUTTCP->opts[0] = Options::WSC;
  OUTTCP->opts[1] = Options::WSC_LEN;
  OUTTCP->opts[2] = m_device.receiveBufferLengthLog2();
  OUTTCP->opts[3] = Options::MSS;
  OUTTCP->opts[4] = Options::MSS_LEN;
  /*
   * Update the MSS value.
   */
  auto* mssval = (uint16_t*)&OUTTCP->opts[5];
  *mssval = htons(e.m_initialmss);
  OUTTCP->opts[7] = Options::END;
  return send(e, len, s);
}

Status
Processor::send(Connection& e, const bool k)
{
  uint8_t* outdata = e.m_sdat;
  /*
   * We're done with the input processing. We are now ready to send a reply. Our
   * job is to fill in all the fields of the TCP and IP headers before
   * calculating the checksum and finally send the packet.
   */
  OUTTCP->ackno = htonl(e.m_rcv_nxt);
  OUTTCP->seqno = htonl(e.m_snd_nxt - uint32_t(k));
  OUTTCP->srcport = e.m_lport;
  OUTTCP->dstport = e.m_rport;
  /*
   * Update the window.
   */
  if (OUTTCP->flags & Flag::SYN) {
    uint32_t window = m_device.receiveBuffersAvailable()
                      << m_device.receiveBufferLengthLog2();
    OUTTCP->wnd = htons(utils::cap(window));
  } else {
    e.m_wndlvl = m_device.receiveBuffersAvailable()
                 << m_device.receiveBufferLengthLog2();
    OUTTCP->wnd = htons(m_device.receiveBuffersAvailable());
  }
  /*
   * Reallocate the send buffer before sending
   */
  Status ret = send(e.m_ripaddr, HEADER_LEN + size_t(k), e.m_mss, outdata);
  if (ret != Status::Ok) {
    return ret;
  }
  /*
   * Print the flow information.
   */
  m_log.trace("FLOW", "<", e.id(), "> <x ", getFlags(*OUTTCP),
              " len:0 seq:", e.m_snd_nxt, " ack:", e.m_rcv_nxt);
  /*
   * Update IP and Ethernet attributes
   */
  m_ipv4to.setProtocol(ipv4::Protocol::TCP);
  m_ipv4to.setDestinationAddress(e.m_ripaddr);
  m_ethto.setDestinationAddress(e.m_rethaddr);
  /*
   * Prepare a new buffer
   */
  return m_ipv4to.prepare(e.m_sdat);
}

Status
Processor::rexmit(Connection& e)
{
  m_stats.rexmit += 1;
  /*
   * Handle the retransmit dependending on the connection's state.
   */
  switch (e.m_state) {
    /*
     * In the SYN_RCVD state, we should retransmit our SYNACK.
     */
    case Connection::SYN_RCVD: {
      m_log.debug("TCP4", "<", e.id(), "> retransmit SYNACK");
      const auto len = HEADER_LEN + Options::MSS_LEN + Options::WSC_LEN + 1;
      return send(e, len, e.segment());
    }
    /*
     * In the SYN_SENT state, we retransmit out SYN.
     */
    case Connection::SYN_SENT: {
      m_log.debug("TCP4", "<", e.id(), "> retransmit SYN");
      const auto len = HEADER_LEN + Options::MSS_LEN + Options::WSC_LEN + 1;
      return send(e, len, e.segment());
    }
    /*
     * In the ESTABLISHED state, we resend the oldest segment.
     */
    case Connection::ESTABLISHED: {
      m_log.debug("TCP4", "<", e.id(), "> retransmit PSH");
      const auto len = e.segment().m_len + HEADER_LEN;
      return send(e, len, e.segment());
    }
    /*
     * In all these states we should retransmit a FINACK.
     */
    case Connection::FIN_WAIT_1:
    case Connection::CLOSING:
    case Connection::LAST_ACK: {
      m_log.debug("TCP4", "<", e.id(), "> retransmit FINACK");
      return send(e, HEADER_LEN, e.segment());
    }
    /*
     * For the other states, do nothing. In the CLOSE state, if we are still
     * there after the backoff that means we are still waiting for an ACK of a
     * PSH from the remote peer.
     */
    case Connection::CLOSE:
    case Connection::FIN_WAIT_2:
    case Connection::TIME_WAIT:
    case Connection::CLOSED:
    default: {
      break;
    }
  }
  /*
   * Done.
   */
  return Status::Ok;
}

Status
Processor::abort(Connection& e)
{
  /*
   * Abort the connection.
   */
  auto res = sendAbort(e);
  /*
   * Notify the handler and close the connection.
   */
  m_handler.onAborted(e, system::Clock::read());
  close(e);
  /*
   *Done.
   */
  return res;
}

Status
Processor::timeOut(Connection& e)
{
  /*
   * Abort the connection.
   */
  auto res = sendAbort(e);
  /*
   * Notify the handler and close the connection.
   */
  m_handler.onTimedOut(e, system::Clock::read());
  close(e);
  /*
   *Done.
   */
  return res;
}

Status
Processor::send(Connection& e, const uint32_t len, Segment& s)
{
  uint8_t* outdata = s.m_dat;
  const bool rexmit = s.m_seq != e.m_snd_nxt && OUTTCP->flags != Flag::ACK;
  /*
   * We're done with the input processing. We are now ready to send a reply. Our
   * job is to fill in all the fields of the TCP and IP headers before
   * calculating the checksum and finally send the packet.
   */
  OUTTCP->ackno = htonl(e.m_rcv_nxt);
  OUTTCP->seqno = htonl(s.m_seq);
  OUTTCP->srcport = e.m_lport;
  OUTTCP->dstport = e.m_rport;
  /*
   * Update the window.
   */
  if (OUTTCP->flags & Flag::SYN) {
    uint32_t window = m_device.receiveBuffersAvailable()
                      << m_device.receiveBufferLengthLog2();
    OUTTCP->wnd = htons(utils::cap(window));
  } else {
    e.m_wndlvl = m_device.receiveBuffersAvailable()
                 << m_device.receiveBufferLengthLog2();
    OUTTCP->wnd = htons(m_device.receiveBuffersAvailable());
  }
  /*
   * Reallocate the send buffer before sending
   */
  Status ret = send(e.m_ripaddr, len, e.m_mss, outdata);
  if (ret != Status::Ok) {
    return ret;
  }
  /*
   * Print the flow information.
   */
  m_log.trace("FLOW", "<", e.id(), (rexmit ? "> <+ " : "> <- "),
              getFlags(*OUTTCP), " len:", len, " seq:", s.m_seq,
              " ack:", e.m_rcv_nxt, " seg:", e.id(s),
              " lvl:", e.freeSegments());
  /*
   * Update the connection and segment state.
   */
  if (likely(!rexmit)) {
#ifdef TULIPS_ENABLE_LATENCY_MONITOR
    if (OUTTCP->flags & TCP_PSH) {
      m_handler.onSent(e);
    }
#endif
    e.m_snd_nxt += s.m_len;
  }
  /*
   * Update IP and Ethernet attributes
   */
  m_ipv4to.setProtocol(ipv4::Protocol::TCP);
  m_ipv4to.setDestinationAddress(e.m_ripaddr);
  m_ethto.setDestinationAddress(e.m_rethaddr);
  /*
   * Don't prepare a new buffer if we are rexmitting.
   */
  if (rexmit) {
    return Status::Ok;
  }
  /*
   * Prepare a new buffer
   */
  return m_ipv4to.prepare(e.m_sdat);
}

Status
Processor::send(UNUSED ipv4::Address const& dst, const uint32_t len,
                const uint16_t mss, uint8_t* const outdata)
{
  /*
   * Reset URG and checksum fields
   */
  OUTTCP->urgp = 0;
  OUTTCP->chksum = 0;
  OUTTCP->reserved = 0;
  /*
   * Calculate TCP checksum.
   */
#ifndef TULIPS_HAS_HW_CHECKSUM
  uint16_t csum = checksum(m_ipv4to.hostAddress(), dst, len, outdata);
  OUTTCP->chksum = ~csum;
#endif
  /*
   * Actually send
   */
  return m_ipv4to.commit(len, outdata, mss);
}

}
