#include "Debug.h"
#include "tulips/stack/IPv4.h"
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
  TCP_LOG("connection RST");
  m_device.unlisten(ipv4::Protocol::TCP, e.m_lport);
  e.m_state = Connection::CLOSED;
  uint8_t* outdata = e.m_sdat;
  OUTTCP->flags = Flag::RST;
  OUTTCP->flags |= e.m_newdata ? Flag::ACK : 0;
  OUTTCP->offset = 5;
  return send(e);
}

Status
Processor::sendClose(Connection& e)
{
  /*
   * This function MUST be called when segments are available. Making sure of
   * this is the responsibility of the caller.
   */
  if (!e.hasAvailableSegments()) {
    TCP_LOG("close() called without available segments");
    return Status::NoMoreResources;
  }
  /*
   * Send a FIN/ACK message. TCP does not require to send an ACK with FIN,
   * but Linux seems pretty bent on wanting one. So we play nice. NOTE Any data
   * pending in the send buffer is discarded.
   */
  TCP_LOG("connection FIN wait #1");
  e.m_state = Connection::FIN_WAIT_1;
  Segment& seg = e.nextAvailableSegment();
  seg.set(1, e.m_snd_nxt, e.m_sdat);
  e.resetSendBuffer();
  return sendFinAck(e, seg);
}

Status
Processor::sendAck(Connection& e)
{
  uint8_t* outdata = e.m_sdat;
  Status res;
  /*
   * An ACK might be sent even though there is pending data in the send buffer.
   * In that case, we should not erase that data and use a new buffer.
   */
  if (unlikely(e.hasPendingSendData())) {
    res = m_device.prepare(outdata);
    if (res != Status::Ok) {
      TCP_LOG("prepare() for sendAck() failed");
      return res;
    }
  }
  /*
   * Prepare the frame for an ACK.
   */
  OUTTCP->flags = Flag::ACK;
  OUTTCP->offset = 5;
  return send(e);
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
Processor::send(Connection& e)
{
  uint8_t* outdata = e.m_sdat;
  /*
   * We're done with the input processing. We are now ready to send a reply. Our
   * job is to fill in all the fields of the TCP and IP headers before
   * calculating the checksum and finally send the packet.
   */
  OUTTCP->ackno = htonl(e.m_rcv_nxt);
  OUTTCP->seqno = htonl(e.m_snd_nxt);
  OUTTCP->srcport = e.m_lport;
  OUTTCP->destport = e.m_rport;
  /*
   * If the connection has issued stop(), we advertise a zero window so
   * that the remote host will stop sending data.
   */
  if (e.m_state == Connection::STOPPED) {
    OUTTCP->wnd = 0;
  } else if (OUTTCP->flags & Flag::SYN) {
    uint32_t window = m_device.receiveBuffersAvailable()
                      << m_device.receiveBufferLengthLog2();
    OUTTCP->wnd = htons(utils::cap(window));
  } else {
    OUTTCP->wnd = htons(m_device.receiveBuffersAvailable());
  }
  /*
   * Reallocate the send buffer before sending
   */
  Status ret = send(e.m_ripaddr, HEADER_LEN, e.m_mss, e.m_sdat);
  if (ret != Status::Ok) {
    return ret;
  }
  /*
   * Print the flow information.
   */
  TCP_FLOW("<- " << getFlags(*OUTTCP) << " len:0 seq:" << e.m_snd_nxt
                 << " ack:" << e.m_rcv_nxt);
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
Processor::send(Connection& e, const uint32_t len, Segment& s)
{
  uint8_t* outdata = s.m_dat;
  const bool rexmit = s.m_seq != e.m_snd_nxt;
  /*
   * We're done with the input processing. We are now ready to send a reply. Our
   * job is to fill in all the fields of the TCP and IP headers before
   * calculating the checksum and finally send the packet.
   */
  OUTTCP->ackno = htonl(e.m_rcv_nxt);
  OUTTCP->seqno = htonl(s.m_seq);
  OUTTCP->srcport = e.m_lport;
  OUTTCP->destport = e.m_rport;
  /*
   * If the connection has issued stop(), we advertise a zero window so
   * that the remote host will stop sending data.
   */
  if (e.m_state == Connection::STOPPED) {
    OUTTCP->wnd = 0;
  } else if (OUTTCP->flags & Flag::SYN) {
    uint32_t window = m_device.receiveBuffersAvailable()
                      << m_device.receiveBufferLengthLog2();
    OUTTCP->wnd = htons(utils::cap(window));
  } else {
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
  TCP_FLOW((rexmit ? "<+ " : "<- ")
           << getFlags(*OUTTCP) << " len:" << s.m_len << " seq:" << s.m_seq
           << " ack:" << e.m_rcv_nxt << " seg:" << e.id(s)
           << " lvl:" << e.level());
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

Status
Processor::rexmit(Connection& e)
{
  m_stats.rexmit += 1;
  /*
   * Ok, so we need to retransmit. We do this differently depending on which
   * state we are in. In ESTABLISHED, we call upon the application so that it
   * may prepare the data for the retransmit. In SYN_RCVD, we resend the
   * SYNACK that we sent earlier and in LAST_ACK we have to retransmit our
   * FINACK.
   */
  switch (e.m_state) {
    /*
     * In the SYN_RCVD state, we should retransmit our SYNACK.
     */
    case Connection::SYN_RCVD: {
      TCP_LOG("retransmit SYNACK");
      Segment& seg = e.segment();
      seg.swap(e.m_sdat);
      e.resetSendBuffer();
      return sendSynAck(e, seg);
    }
    /*
     * In the SYN_SENT state, we retransmit out SYN.
     */
    case Connection::SYN_SENT: {
      TCP_LOG("retransmit SYN");
      Segment& seg = e.segment();
      seg.swap(e.m_sdat);
      e.resetSendBuffer();
      uint8_t* outdata = seg.m_dat;
      OUTTCP->flags = 0;
      return sendSyn(e, seg);
    }
    /*
     * In the ESTABLISHED state, we call upon the application to do the
     * actual retransmit after which we jump into the code for sending
     * out the packet (the apprexmit label).
     */
    case Connection::ESTABLISHED: {
      TCP_LOG("retransmit PSH");
      Segment& seg = e.segment();
      seg.swap(e.m_sdat);
      e.resetSendBuffer();
      return send(e, seg, Flag::PSH);
    }
    /*
     * In all these states we should retransmit a FINACK.
     */
    case Connection::FIN_WAIT_1:
    case Connection::CLOSING:
    case Connection::LAST_ACK: {
      TCP_LOG("retransmit FINACK");
      Segment& seg = e.segment();
      seg.swap(e.m_sdat);
      e.resetSendBuffer();
      return sendFinAck(e, e.segment());
    }
    /*
     * For the other states, do nothing. In the CLOSE state, if we are still
     * there after the backoff that means we are still waiting for an ACK
     * of a PSH from the remote peer.
     */
    case Connection::CLOSE:
    case Connection::FIN_WAIT_2:
    case Connection::TIME_WAIT:
    case Connection::STOPPED:
    case Connection::CLOSED:
    default: {
      break;
    }
  }
  return Status::Ok;
}

}
