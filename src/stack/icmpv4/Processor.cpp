#include <tulips/stack/icmpv4/Processor.h>
#include <tulips/system/Compiler.h>
#include <arpa/inet.h>

#define INICMP ((const Header*)data)
#define OUTICMP ((Header*)outdata)

namespace tulips::stack::icmpv4 {

Processor::Processor(system::Logger& log, ethernet::Producer& eth,
                     ipv4::Producer& ip4)
  : m_log(log)
  , m_ethout(eth)
  , m_ip4out(ip4)
  , m_ethin(nullptr)
  , m_ip4in(nullptr)
  , m_arp(nullptr)
  , m_stats()
  , m_reqs()
  , m_ids(0)
{
  memset(&m_stats, 0, sizeof(m_stats));
}

Request&
Processor::attach(ethernet::Producer& eth, ipv4::Producer& ip4)
{
  Request::ID nid = m_ids + 1;
  auto* req = new Request(eth, ip4, *m_arp, nid);
  m_reqs[nid] = req;
  return *req;
}

void
Processor::detach(Request& req)
{
  m_reqs.erase(req.m_id);
  delete &req;
}

Status
Processor::process(const uint16_t len, const uint8_t* const data)
{
  /*
   * Process the ICMP packet.
   */
  ++m_stats.recv;
  /*
   * Check if the message is valid.
   */
  if (INICMP->type != ECHO && INICMP->type != ECHO_REPLY) {
    return Status::ProtocolError;
  }
  /*
   * If it's a reply, mark the reply flag.
   */
  if (INICMP->type == ECHO_REPLY) {
    m_log.debug("ICMP4", "reply from ", m_ip4in->sourceAddress().toString());
    /*
     * Get request ID and check if the request is known.
     */
    Request::ID rid = INICMP->id;
    if (m_reqs.count(rid) == 0) {
      return Status::ProtocolError;
    }
    /*
     * Update the request state.
     */
    Request* req = m_reqs[rid];
    if (req->m_state != Request::REQUEST) {
      return Status::ProtocolError;
    }
    req->m_state = Request::RESPONSE;
    return Status::Ok;
  }
  /*
   * Log the request.
   */
  m_log.debug("ICMP4", "request from ", m_ip4in->sourceAddress().toString());
  /*
   * Update the IP and Ethernet attributes.
   */
  m_ip4out.setProtocol(ipv4::Protocol::ICMP);
  m_ip4out.setDestinationAddress(m_ip4in->sourceAddress());
  m_ethout.setDestinationAddress(m_ethin->sourceAddress());
  /*
   * Prepare a send buffer
   */
  uint8_t* outdata;
  Status ret = m_ip4out.prepare(outdata);
  if (ret != Status::Ok) {
    return ret;
  }
  /*
   * Copy the entire payload.
   */
  memcpy(outdata, data, len);
  /*
   * Change the ICMP type from ECHO to ECHO_REPLY.
   */
  OUTICMP->type = ECHO_REPLY;
  /*
   * Adjust the ICMP checksum.
   */
  if (INICMP->icmpchksum >= htons(0xffff - (ECHO << 8))) {
    OUTICMP->icmpchksum += htons(ECHO << 8) + 1;
  } else {
    OUTICMP->icmpchksum += htons(ECHO << 8);
  }
  /*
   * Send the packet
   */
  ++m_stats.sent;
  return m_ip4out.commit(len, outdata);
}

}
