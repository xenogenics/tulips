#include <tulips/stack/ipv4/Producer.h>
#include <cstdint>
#include <cstring>
#include <arpa/inet.h>

#define OUTIP ((Header*)outdata)

constexpr const uint8_t TTL = 64;

namespace tulips::stack::ipv4 {

Producer::Producer(system::Logger& log, ethernet::Producer& prod,
                   Address const& ha)
  : m_log(log)
  , m_eth(prod)
  , m_hostAddress(ha)
  , m_destAddress()
  , m_defaultRouterAddress()
  , m_netMask(Address::BROADCAST)
  , m_proto(0)
  , m_ipid(0)
  , m_stats()
{
  memset(&m_stats, 0, sizeof(m_stats));
}

Status
Producer::prepare(uint8_t*& buf)
{
  /*
   * Set ethernet attributes (ethernet destination address must be set!!)
   */
  m_eth.setType(ethernet::ETHTYPE_IP);
  /*
   * Grab a buffer
   */
  uint8_t* outdata;
  Status ret = m_eth.prepare(outdata);
  if (ret != Status::Ok) {
    return ret;
  }
  /*
   * Update state.
   */
  m_ipid += 1;
  /*
   * Prepare the content of the header
   */
  OUTIP->vhl = 0x45;
  OUTIP->tos = 0;
  OUTIP->len = HEADER_LEN;
  OUTIP->ipid = htons(m_ipid);
  OUTIP->ipoffset[0] = 0;
  OUTIP->ipoffset[1] = 0;
  OUTIP->ttl = TTL;
  OUTIP->proto = m_proto;
  OUTIP->ipchksum = 0;
  OUTIP->srcipaddr = m_hostAddress;
  OUTIP->destipaddr = m_destAddress;
  /*
   * Advance the buffer
   */
  buf = outdata + HEADER_LEN;
  return ret;
}

Status
Producer::commit(const uint32_t len, uint8_t* const buf, const uint16_t mss)
{
  uint8_t* outdata = buf - HEADER_LEN;
  uint32_t outlen = len + HEADER_LEN;
  /*
   * Fill in the remaining header fields.
   */
  OUTIP->len = htons(outlen);
  /*
   * Compute the checksum
   */
#ifndef TULIPS_HAS_HW_CHECKSUM
  OUTIP->ipchksum = ~checksum(outdata);
#endif
  /*
   * Commit the buffer.
   */
  m_stats.sent += 1;
  m_log.trace("IP4", "committing packet: ", len, "B");
  return m_eth.commit(outlen, outdata, mss);
}

Status
Producer::release(uint8_t* const buf)
{
  return m_eth.release(buf - HEADER_LEN);
}

}
