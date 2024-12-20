#include <tulips/api/Client.h>
#include <tulips/stack/ARP.h>
#include <tulips/stack/tcpv4/Connection.h>
#include <tulips/system/Compiler.h>

namespace tulips::api {

using namespace stack;

/*
 * Client class definition.
 */

Client::Client(system::Logger& log, Delegate& dlg, transport::Device& device,
               stack::ipv4::Address const& ip, stack::ipv4::Address const& gw,
               stack::ipv4::Address const& nm)
  : m_log(log)
  , m_delegate(dlg)
  , m_dev(device)
  , m_ethto(log, m_dev, device.address())
  , m_ip4to(log, m_ethto, ip)
#ifdef TULIPS_ENABLE_ARP
  , m_arp(log, m_ethto, m_ip4to)
#endif
  , m_ethfrom(log, device.address())
  , m_ip4from(log, ip)
#ifdef TULIPS_ENABLE_ICMP
  , m_icmpv4from(log, m_ethto, m_ip4to)
#endif
#ifdef TULIPS_ENABLE_RAW
  , m_raw()
#endif
  , m_tcp(log, device, m_ethto, m_ip4to, *this)
  , m_cns()
{
  /*
   * Hint the device about checksum.
   */
#ifdef TULIPS_DISABLE_CHECKSUM_CHECK
  m_dev.hint(transport::Device::VALIDATE_IP_CSUM);
  m_dev.hint(transport::Device::VALIDATE_L4_CSUM);
#endif
  /*
   * Connect the stack.
   */
  m_tcp.setEthernetProcessor(m_ethfrom).setIPv4Processor(m_ip4from);
#ifdef TULIPS_ENABLE_ICMP
  m_icmpv4from.setEthernetProcessor(m_ethfrom).setIPv4Processor(m_ip4from);
#endif
  m_ip4to.setDefaultRouterAddress(gw).setNetMask(nm);
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
  /*
   * Reserve connections.
   */
  m_cns.reserve(512);
}

bool
Client::live() const
{
  /*
   * True if any connection is not closed.
   */
  for (auto const& c : m_cns) {
    if (c.state() != Connection::State::Closed) {
      return true;
    }
  }
  /*
   * False otherwise.
   */
  return false;
}

Status
Client::open(const ApplicationLayerProtocol alpn, const uint16_t options,
             ID& id)
{
  /*
   * Open the connection from the TCP end.
   */
  auto ret = m_tcp.open(id);
  if (ret != Status::Ok) {
    return ret;
  }
  /*
   * Check if we need to allocate the connection.
   */
  if (id == m_cns.size()) {
    m_cns.emplace_back();
  }
  /*
   * Save the options and return.
   */
  m_cns[id].open(alpn, options);
  return Status::Ok;
}

Status
Client::setHostName(const ID id, std::string_view hostname)
{
  /*
   * Check if connection ID is valid.
   */
  if (id >= m_cns.size()) {
    return Status::InvalidConnection;
  }
  /*
   * Get the connections.
   */
  auto& c = m_cns[id];
  /*
   * Check if the connection is the right state.
   */
  if (c.state() != Connection::State::Opened) {
    return Status::ResourceBusy;
  }
  /*
   * Set the hostname for the connection.
   */
  c.setHostName(hostname);
  return Status::Ok;
}

Status
Client::getHostName(const ID id, std::optional<std::string>& hostname)
{
  /*
   * Check if connection ID is valid.
   */
  if (id >= m_cns.size()) {
    return Status::InvalidConnection;
  }
  /*
   * Get the connections.
   */
  auto& c = m_cns[id];
  /*
   * Get the hostname.
   */
  hostname = c.hostName();
  return Status::Ok;
}

Status
Client::connect(const ID id, ipv4::Address const& ripaddr,
                const tcpv4::Port rport)
{
  Status ret;
  /*
   * Check if connection ID is valid.
   */
  if (id >= m_cns.size()) {
    return Status::InvalidConnection;
  }
  /*
   * Get the connection.
   */
  auto& c = m_cns[id];
  /*
   * Go through the states.
   */
  switch (c.state()) {
    case Connection::State::Closed: {
      m_log.error("APICLI", "<", id, "> connect() failed, connection closed");
      return Status::InvalidConnection;
    }
    case Connection::State::Opened: {
      ethernet::Address rhwaddr;
#ifdef TULIPS_ENABLE_ARP
      /*
       * Discover the remote address is we don't have a translation.
       */
      if (!m_arp.has(ripaddr)) {
        m_log.debug("APICLI", "<", id, "> closed -> resolving(",
                    ripaddr.toString(), ")");
        ret = m_arp.discover(ripaddr);
        if (ret == Status::Ok) {
          c.resolving();
          ret = Status::OperationInProgress;
        }
        break;
      }
      /*
       * Otherwise perform the query.
       */
      m_arp.query(ripaddr, rhwaddr);
#else
      ipv4::Address addr = ripaddr;
      if (!m_ip4to.isLocal(addr)) {
        addr = m_ip4to.defaultRouterAddress();
      }
      if (!arp::lookup(m_log, m_dev.name(), addr, rhwaddr)) {
        m_log.error("APICLI", "<", id, "> hardware translation missing for ",
                    addr.toString());
        ret = Status::HardwareTranslationMissing;
        break;
      }
#endif
      /*
       * Connect the client.
       */
      m_log.debug("APICLI", "<", id, "> closed -> connecting(",
                  ripaddr.toString(), ")");
      ret = m_tcp.connect(id, rhwaddr, ripaddr, rport);
      if (ret == Status::Ok) {
        c.connecting();
        ret = Status::OperationInProgress;
      }
      break;
    }
#ifdef TULIPS_ENABLE_ARP
    case Connection::State::Resolving: {
      if (m_arp.has(ripaddr)) {
        ethernet::Address rhwaddr;
        m_arp.query(ripaddr, rhwaddr);
        m_log.debug("APICLI", "<", id, "> closed -> connecting(",
                    ripaddr.toString(), ")");
        ret = m_tcp.connect(id, rhwaddr, ripaddr, rport);
        if (ret == Status::Ok) {
          c.connecting();
          ret = Status::OperationInProgress;
        }
      } else {
        ret = Status::OperationInProgress;
      }
      break;
    }
#endif
    case Connection::State::Connecting: {
      ret = Status::OperationInProgress;
      break;
    }
    case Connection::State::Connected: {
      m_log.debug("APICLI", "<", id, "> connected");
      ret = Status::Ok;
      break;
    }
    default: {
      ret = Status::ProtocolError;
      break;
    }
  }
  return ret;
}

Status
Client::abort(const ID id)
{
  m_log.debug("APICLI", "<", id, "> aborting");
  /*
   * Check if connection ID is valid.
   */
  if (id >= m_cns.size()) {
    return Status::InvalidConnection;
  }
  /*
   * Get the connection.
   */
  auto& c = m_cns[id];
  /*
   * Check if the connection is connected.
   */
  if (c.state() != Connection::State::Connected) {
    return Status::NotConnected;
  }
  /*
   * Close the connection.
   */
  return m_tcp.abort(id);
}

Status
Client::close(const ID id)
{
  m_log.debug("APICLI", "<", id, "> closing");
  /*
   * Check if connection ID is valid.
   */
  if (id >= m_cns.size()) {
    return Status::InvalidConnection;
  }
  /*
   * Get the connection.
   */
  auto& c = m_cns[id];
  /*
   * Check if the connection is connected.
   */
  if (c.state() != Connection::State::Connected) {
    return Status::NotConnected;
  }
  /*
   * Close the connection.
   */
  return m_tcp.close(id);
}

bool
Client::isClosed(const ID id) const
{
  /*
   * Check if connection ID is valid.
   */
  if (id >= m_cns.size()) {
    return true;
  }
  /*
   * Get the connection.
   */
  auto const& c = m_cns[id];
  /*
   * Done.
   */
  return c.state() == Connection::State::Closed;
}

Status
Client::get(const ID id, stack::ipv4::Address& laddr, stack::tcpv4::Port& lport,
            stack::ipv4::Address& raddr, stack::tcpv4::Port& rport) const
{
  /*
   * Check if connection ID is valid.
   */
  if (id >= m_cns.size()) {
    return Status::InvalidConnection;
  }
  /*
   * Get the info.
   */
  return m_tcp.get(id, laddr, lport, raddr, rport);
}

Status
Client::send(const ID id, const uint32_t len, const uint8_t* const data,
             uint32_t& off)
{
  /*
   * Skip if the length is 0.
   */
  if (len == 0) {
    return Status::InvalidArgument;
  }
  /*
   * Check if connection ID is valid.
   */
  if (id >= m_cns.size()) {
    return Status::InvalidConnection;
  }
  /*
   * Send the payload.
   */
  return m_tcp.send(id, len, data, off);
}

size_t
Client::averageLatency(UNUSED const ID id)
{
#ifdef TULIPS_ENABLE_LATENCY_MONITOR
  /*
   * Check if connection ID is valid.
   */
  if (id >= m_nconn) {
    return -1;
  }
  Connection& c = m_cns[id];
  /*
   * Compute the latency.
   */
  return c.latency();
#else
  return 0;
#endif
}

Client::ApplicationLayerProtocol
Client::applicationLayerProtocol(const ID id) const
{
  /*
   * Check if connection ID is valid.
   */
  if (id >= m_cns.size()) {
    return ApplicationLayerProtocol::None;
  }
  auto const& c = m_cns[id];
  /*
   * Compute the latency.
   */
  return c.applicationLayerProtocol();
}

void*
Client::cookie(const ID id) const
{
  /*
   * Check if connection ID is valid.
   */
  if (id >= m_cns.size()) {
    return nullptr;
  }
  /*
   * Compute the latency.
   */
  return m_tcp.cookie(id);
}

void
Client::onConnected(tcpv4::Connection& c, const Timestamp ts)
{
  auto& d = m_cns[c.id()];
  m_log.debug("APICLI", "<", c.id(), "> connected");
  d.connected();
  c.setCookie(m_delegate.onConnected(c.id(), nullptr, ts));
  c.setOptions(d.options());
}

void
Client::onAborted(tcpv4::Connection& c, const Timestamp ts)
{
  auto& d = m_cns[c.id()];
  /*
   * Close the connection.
   */
  m_log.debug("APICLI", "<", c.id(), "> aborted, closing");
  d.close();
  /*
   * Grab and erase the cookie.
   */
  auto cookie = c.cookie();
  c.setCookie(nullptr);
  /*
   * Call the delegate.
   */
  m_delegate.onClosed(c.id(), cookie, ts);
}

void
Client::onTimedOut(tcpv4::Connection& c, const Timestamp ts)
{
  auto& d = m_cns[c.id()];
  /*
   * Close the connection.
   */
  m_log.debug("APICLI", "<", c.id(), "> connection timed out, closing");
  d.close();
  /*
   * Grab and erase the cookie.
   */
  auto cookie = c.cookie();
  c.setCookie(nullptr);
  /*
   * Call the delegate.
   */
  m_delegate.onClosed(c.id(), cookie, ts);
}

void
Client::onClosed(tcpv4::Connection& c, const Timestamp ts)
{
  auto& d = m_cns[c.id()];
  /*
   * Close the connection.
   */
  m_log.debug("APICLI", "<", c.id(), "> closed");
  d.close();
  /*
   * Grab and erase the cookie.
   */
  auto cookie = c.cookie();
  c.setCookie(nullptr);
  /*
   * Call the delegate.
   */
  m_delegate.onClosed(c.id(), cookie, ts);
}

void
Client::onSent(UNUSED tcpv4::Connection& c, UNUSED const Timestamp ts)
{
#ifdef TULIPS_ENABLE_LATENCY_MONITOR
  m_cns[c.id()].markOnSent(ts);
#endif
}

Action
Client::onAcked(stack::tcpv4::Connection& c, const Timestamp ts,
                const uint32_t alen, uint8_t* const sdata, uint32_t& slen)
{
  /*
   * Update the latency monitor.
   */
#ifdef TULIPS_ENABLE_LATENCY_MONITOR
  m_cns[c.id()].markOnAcked(ts);
#endif
  /*
   * Call the delegate.
   */
  return m_delegate.onAcked(c.id(), c.cookie(), ts, alen, sdata, slen);
}

Action
Client::onNewData(stack::tcpv4::Connection& c, const uint8_t* const data,
                  const uint32_t len, const Timestamp ts, const uint32_t alen,
                  uint8_t* const sdata, uint32_t& slen)
{
  return m_delegate.onNewData(c.id(), c.cookie(), data, len,
                              c.isNewDataPushed(), ts, alen, sdata, slen);
}

}
