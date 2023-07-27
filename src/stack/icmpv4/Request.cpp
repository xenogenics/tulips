#include <tulips/stack/icmpv4/Request.h>

#define OUTICMP ((Header*)outdata)

namespace tulips::stack::icmpv4 {

Request::Request(ethernet::Producer& eth, ipv4::Producer& ip4,
                 arp::Processor& arp, const ID id)
  : m_eth(eth), m_ip4(ip4), m_arp(arp), m_id(id), m_state(IDLE), m_seq(1)
{}

Status
Request::operator()(ipv4::Address const& dst)
{
  ethernet::Address deth;
  /*
   * Check our current status.
   */
  if (m_state == REQUEST) {
    return Status::OperationInProgress;
  }
  if (m_state == RESPONSE) {
    m_state = IDLE;
    m_seq += 1;
    return Status::OperationCompleted;
  }
  /*
   * Get a HW translation of the destination address
   */
  if (!m_arp.query(dst, deth)) {
    return Status::HardwareTranslationMissing;
  }
  /*
   * Setup the IP protocol
   */
  m_ip4.setDestinationAddress(dst);
  m_ip4.setProtocol(ipv4::Protocol::ICMP);
  /*
   * Grab a send buffer
   */
  uint8_t* data;
  Status ret = m_ip4.prepare(data);
  if (ret != Status::Ok) {
    return ret;
  }
  /*
   * Setup ICMP message
   */
  auto* hdr = reinterpret_cast<Header*>(data);
  hdr->type = stack::icmpv4::ECHO;
  hdr->icode = 0;
  hdr->id = m_id;
  hdr->seqno = m_seq;
  hdr->icmpchksum = 0;
  hdr->icmpchksum = ~stack::icmpv4::checksum(data);
  /*
   * Commit the buffer.
   */
  m_state = REQUEST;
  return m_ip4.commit(HEADER_LEN, data);
}

}
