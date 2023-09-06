#include <tulips/api/Server.h>
#include <arpa/inet.h>

namespace tulips::api {

using namespace stack;

Server::Server(system::Logger& log, Delegate& delegate,
               transport::Device& device, const size_t nconn,
               const uint8_t options)
  : m_log(log)
  , m_delegate(delegate)
  , m_ethto(log, device, device.address())
  , m_ip4to(log, m_ethto, device.ip())
#ifdef TULIPS_ENABLE_ARP
  , m_arp(log, m_ethto, m_ip4to)
#endif
  , m_ethfrom(log, device.address())
  , m_ip4from(log, device.ip())
#ifdef TULIPS_ENABLE_ICMP
  , m_icmpv4from(log, m_ethto, m_ip4to)
#endif
#ifdef TULIPS_ENABLE_RAW
  , m_raw()
#endif
  , m_tcp(log, device, m_ethto, m_ip4to, *this, nconn)
  , m_options(options)
{
  /*
   * Hint the device about checksum.
   */
#ifdef TULIPS_DISABLE_CHECKSUM_CHECK
  device.hint(transport::Device::VALIDATE_IP_CSUM);
  device.hint(transport::Device::VALIDATE_L4_CSUM);
#endif
  /*
   * Connect the stack.
   */
  m_tcp.setEthernetProcessor(m_ethfrom).setIPv4Processor(m_ip4from);
#ifdef TULIPS_ENABLE_ICMP
  m_icmpv4from.setEthernetProcessor(m_ethfrom).setIPv4Processor(m_ip4from);
#endif
  m_ip4to.setDefaultRouterAddress(device.gateway())
    .setNetMask(ipv4::Address(device.netmask()));
  m_ip4from
    .setEthernetProcessor(m_ethfrom)
#ifdef TULIPS_ENABLE_RAW
    .setRawProcessor(m_raw)
#endif
#ifdef TULIPS_ENABLE_ICMP
    .setICMPv4Processor(m_icmpv4from)
#endif
    .setTCPv4Processor(m_tcp);
  m_ethfrom
#ifdef TULIPS_ENABLE_RAW
    .setRawProcessor(m_raw)
#endif
#ifdef TULIPS_ENABLE_ARP
    .setARPProcessor(m_arp)
#endif
    .setIPv4Processor(m_ip4from);
}

void
Server::listen(const stack::tcpv4::Port port, void* cookie)
{
  m_tcp.listen(port);
  m_cookies[htons(port)] = cookie;
}

void
Server::unlisten(const stack::tcpv4::Port port)
{
  m_tcp.unlisten(port);
  m_cookies.erase(htons(port));
}

void
Server::setOptions(const ID id, const uint8_t options)
{
  m_tcp.setOptions(id, options);
}

void
Server::clearOptions(const ID id, const uint8_t options)
{
  m_tcp.clearOptions(id, options);
}

Status
Server::close(const ID id)
{
  Status res = m_tcp.close(id);
  if (res == Status::Ok) {
    m_log.debug("APISRV", "closing connection ", id);
  }
  return res;
}

bool
Server::isClosed(const ID id) const
{
  return m_tcp.isClosed(id);
}

Status
Server::send(const ID id, const uint32_t len, const uint8_t* const data,
             uint32_t& off)
{
  return m_tcp.send(id, len, data, off);
}

void*
Server::cookie(const ID id) const
{
  return m_tcp.cookie(id);
}

void
Server::onConnected(tcpv4::Connection& c)
{
  void* srvdata = m_cookies[c.localPort()];
  void* appdata = m_delegate.onConnected(c.id(), srvdata);
  m_log.debug("APISRV", "connection ", c.id(), " connected");
  c.setCookie(appdata);
  c.setOptions(m_options);
}

void
Server::onAborted(tcpv4::Connection& c)
{
  m_delegate.onClosed(c.id(), c.cookie());
  c.setCookie(nullptr);
}

void
Server::onTimedOut(tcpv4::Connection& c)
{
  m_delegate.onClosed(c.id(), c.cookie());
  c.setCookie(nullptr);
}

void
Server::onClosed(tcpv4::Connection& c)
{
  m_delegate.onClosed(c.id(), c.cookie());
  m_log.debug("APISRV", "connection ", c.id(), " closed");
  c.setCookie(nullptr);
}

Action
Server::onAcked(stack::tcpv4::Connection& c)
{
  return m_delegate.onAcked(c.id(), c.cookie());
}

Action
Server::onAcked(stack::tcpv4::Connection& c, const uint32_t alen,
                uint8_t* const sdata, uint32_t& slen)
{
  return m_delegate.onAcked(c.id(), c.cookie(), alen, sdata, slen);
}

Action
Server::onNewData(stack::tcpv4::Connection& c, const uint8_t* const data,
                  const uint32_t len)
{
  return m_delegate.onNewData(c.id(), c.cookie(), data, len);
}

Action
Server::onNewData(stack::tcpv4::Connection& c, const uint8_t* const data,
                  const uint32_t len, const uint32_t alen, uint8_t* const sdata,
                  uint32_t& slen)
{
  return m_delegate.onNewData(c.id(), c.cookie(), data, len, alen, sdata, slen);
}

}
