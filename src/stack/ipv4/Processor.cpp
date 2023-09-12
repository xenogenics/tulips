#include <tulips/stack/IPv4.h>
#include <tulips/stack/ipv4/Processor.h>
#ifdef TULIPS_ENABLE_ICMP
#include <tulips/stack/icmpv4/Processor.h>
#endif
#include <tulips/stack/tcpv4/Processor.h>
#include <tulips/system/Compiler.h>
#include <tulips/system/Utils.h>
#include <arpa/inet.h>

#define INIP ((const Header*)data)

namespace tulips::stack::ipv4 {

Processor::Processor(system::Logger& log, Address const& ha)
  : m_log(log)
  , m_hostAddress(ha)
  , m_srceAddress()
  , m_destAddress()
  , m_proto(0)
  , m_stats()
  , m_eth(nullptr)
#ifdef TULIPS_ENABLE_RAW
  , m_raw(nullptr)
#endif
#ifdef TULIPS_ENABLE_ICMP
  , m_icmp(nullptr)
#endif
  , m_tcp(nullptr)
{
  memset(&m_stats, 0, sizeof(m_stats));
}

Status
Processor::run()
{
  Status ret = Status::Ok;

  if (m_tcp) {
    ret = m_tcp->run();
  }
#ifdef TULIPS_ENABLE_ICMP
  if (m_icmp && ret == Status::Ok) {
    ret = m_icmp->run();
  }
#endif
#ifdef TULIPS_ENABLE_RAW
  if (m_raw && ret == Status::Ok) {
    ret = m_raw->run();
  }
#endif
  return ret;
}

Status
Processor::process(UNUSED const uint16_t len, const uint8_t* const data,
                   const Timestamp ts)
{
  Status ret;
  /*
   * Update stats
   */
  m_stats.recv += 1;
  /*
   * Check the version field.
   */
  if (INIP->vhl != 0x45) {
    ++m_stats.drop;
    ++m_stats.vhlerr;
    m_log.error("IP4", "invalid protocol type");
    return Status::ProtocolError;
  }
  /*
   * Check the fragment flag.
   */
  if ((INIP->ipoffset[0] & 0x3f) != 0 || INIP->ipoffset[1] != 0) {
    ++m_stats.drop;
    ++m_stats.frgerr;
    m_log.error("IP4", "IP fragment are not supported");
    return Status::ProtocolError;
  }
  /*
   * Check if the packet is destined for our IP address.
   */
  if (INIP->destipaddr != m_hostAddress) {
    ++m_stats.drop;
    m_log.error("IP4", "unknown destination address");
    return Status::ProtocolError;
  }
  /*
   * Compute and check the IP header checksum.
   */
#ifndef TULIPS_DISABLE_CHECKSUM_CHECK
  uint16_t sum = checksum(data);
  if (sum != 0xffff) {
    ++m_stats.drop;
    ++m_stats.chkerr;
    m_log.error("IP4", "data length: ", len);
    m_log.error("IP4", "invalid checksum: 0x", std::hex, sum, std::dec);
    return Status::CorruptedData;
  }
#endif
  /*
   * Extract the information
   */
  uint16_t iplen = ntohs(INIP->len) - HEADER_LEN;
  m_srceAddress = INIP->srcipaddr;
  m_destAddress = INIP->destipaddr;
  m_proto = INIP->proto;
  /*
   * Call the processors
   */
  switch (Protocol(m_proto)) {
    case Protocol::TCP: {
#ifdef TULIPS_STACK_RUNTIME_CHECK
      if (!m_tcp) {
        ret = Status::UnsupportedProtocol;
        break;
      }
#endif
      ret = m_tcp->process(iplen, data + HEADER_LEN, ts);
      break;
    }
#ifdef TULIPS_ENABLE_ICMP
    case Protocol::ICMP: {
#ifdef TULIPS_STACK_RUNTIME_CHECK
      if (!m_icmp) {
        ret = Status::UnsupportedProtocol;
        break;
      }
#endif
      ret = m_icmp->process(iplen, data + HEADER_LEN, ts);
      break;
    }
#endif
#ifdef TULIPS_ENABLE_RAW
    case Protocol::TEST: {
#ifdef TULIPS_STACK_RUNTIME_CHECK
      if (!m_raw) {
        ret = Status::UnsupportedProtocol;
        break;
      }
#endif
      ret = m_raw->process(iplen, data + HEADER_LEN, ts);
      break;
    }
#endif
    default: {
      ret = Status::UnsupportedProtocol;
      break;
    }
  }
  /*
   * Process the output
   */
  return ret;
}

}
