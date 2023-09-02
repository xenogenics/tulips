#include <tulips/api/Client.h>
#include <tulips/stack/ARP.h>
#include <tulips/system/Compiler.h>

#define LOG(_l, ...) m_log(system::Logger::Level::_l, "CLIENT", __VA_ARGS__)

namespace tulips {

using namespace stack;

/*
 * Connection class definition.
 */

Client::Connection::Connection()
  : state(State::Closed)
  , conn(-1)
#ifdef TULIPS_ENABLE_LATENCY_MONITOR
  , count(0)
  , pre(0)
  , lat(0)
  , history()
#endif
{}

/*
 * Client class definition.
 */

Client::Client(Delegate& dlg, system::Logger& log, transport::Device& device,
               const size_t nconn)
  : m_delegate(dlg)
  , m_log(log)
  , m_dev(device)
  , m_nconn(nconn)
  , m_ethto(log, m_dev, device.address())
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
  , m_cns()
  , m_idx()
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
  /*
   * Reserve connections.
   */
  m_cns.resize(nconn);
}

Status
Client::open(ID& id)
{
  for (size_t i = 0; i < m_nconn; i += 1) {
    if (m_cns[i].state == Connection::State::Closed) {
      m_cns[i].state = Connection::State::Opened;
      id = i;
      return Status::Ok;
    }
  }
  return Status::NoMoreResources;
}

Status
Client::connect(const ID id, ipv4::Address const& ripaddr,
                const tcpv4::Port rport)
{
  Status ret;
  /*
   * Check if connection ID is valid.
   */
  if (id >= m_nconn) {
    return Status::InvalidConnection;
  }
  Connection& c = m_cns[id];
  /*
   * Go through the states.
   */
  switch (c.state) {
    case Connection::State::Closed: {
      return Status::InvalidConnection;
    }
    case Connection::State::Opened: {
      ethernet::Address rhwaddr;
#ifdef TULIPS_ENABLE_ARP
      /*
       * Discover the remote address is we don't have a translation.
       */
      if (!m_arp.has(ripaddr)) {
        m_log.debug("APICLI", "closed -> resolving(", ripaddr.toString(), ")");
        ret = m_arp.discover(ripaddr);
        if (ret == Status::Ok) {
          c.state = Connection::State::Resolving;
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
      if (!arp::lookup(m_dev.name(), addr, rhwaddr)) {
        LOG("CLIENT", "hardware translation missing for " << addr.toString());
        ret = Status::HardwareTranslationMissing;
        break;
      }
#endif
      /*
       * Connect the client.
       */
      m_log.debug("APICLI", "closed -> connecting(", ripaddr.toString(), ")");
      ret = m_tcp.connect(rhwaddr, ripaddr, rport, c.conn);
      if (ret == Status::Ok) {
        c.state = Connection::State::Connecting;
        m_idx[c.conn] = id;
        ret = Status::OperationInProgress;
      }
      break;
    }
#ifdef TULIPS_ENABLE_ARP
    case Connection::State::Resolving: {
      if (m_arp.has(ripaddr)) {
        ethernet::Address rhwaddr;
        m_arp.query(ripaddr, rhwaddr);
        m_log.debug("APICLI", "closed -> connecting(", ripaddr.toString(), ")");
        ret = m_tcp.connect(rhwaddr, ripaddr, rport, c.conn);
        if (ret == Status::Ok) {
          c.state = Connection::State::Connecting;
          m_idx[c.conn] = id;
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
      m_log.debug("APICLI", "connected");
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
  m_log.debug("APICLI", "closing connection ", id);
  /*
   * Check if connection ID is valid.
   */
  if (id >= m_nconn) {
    return Status::InvalidConnection;
  }
  Connection& c = m_cns[id];
  /*
   * Check if the connection is connected.
   */
  if (c.state != Connection::State::Connected) {
    return Status::NotConnected;
  }
  /*
   * Close the connection.
   */
  return m_tcp.abort(c.conn);
}

Status
Client::close(const ID id)
{
  /*
   * Check if connection ID is valid.
   */
  if (id >= m_nconn) {
    return Status::InvalidConnection;
  }
  Connection& c = m_cns[id];
  /*
   * Check if the connection is connected.
   */
  if (c.state != Connection::State::Connected) {
    return Status::NotConnected;
  }
  /*
   * Close the connection.
   */
  Status res = m_tcp.close(c.conn);
  if (res == Status::Ok) {
    m_log.debug("APICLI", "closing connection ", id);
  }
  return res;
}

bool
Client::isClosed(const ID id) const
{
  /*
   * Check if connection ID is valid.
   */
  if (id >= m_nconn) {
    return true;
  }
  Connection const& c = m_cns[id];
  return c.state == Connection::State::Closed;
}

Status
Client::send(const ID id, const uint32_t len, const uint8_t* const data,
             uint32_t& off)
{
  /*
   * Check if connection ID is valid.
   */
  if (id >= m_nconn) {
    return Status::InvalidConnection;
  }
  Connection& c = m_cns[id];
  /*
   * Send the payload.
   */
#ifdef TULIPS_ENABLE_LATENCY_MONITOR
  c.pre = c.pre ?: system::Clock::read();
#endif
  return m_tcp.send(c.conn, len, data, off);
}

Status
Client::get(const ID id, stack::ipv4::Address& ripaddr,
            stack::tcpv4::Port& lport, stack::tcpv4::Port& rport)
{
  /*
   * Check if connection ID is valid.
   */
  if (id >= m_nconn) {
    return Status::InvalidConnection;
  }
  Connection& c = m_cns[id];
  /*
   * Get the info.
   */
  return m_tcp.get(c.conn, ripaddr, lport, rport);
}

system::Clock::Value
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
  uint64_t res = 0;
  if (c.count > 0) {
    res = system::Clock::nanosecondsOf(c.lat / c.count);
  }
  c.lat = 0;
  c.count = 0;
  return res;
#else
  return 0;
#endif
}

void*
Client::cookie(const ID id) const
{
  /*
   * Check if connection ID is valid.
   */
  if (id >= m_nconn) {
    return nullptr;
  }
  Connection const& c = m_cns[id];
  /*
   * Compute the latency.
   */
  return m_tcp.cookie(c.conn);
}

void
Client::onConnected(tcpv4::Connection& c)
{
  ID id = m_idx[c.id()];
  m_log.debug("APICLI", "connection ", c.id(), ":", id, " connected");
  Connection& d = m_cns[id];
  if (d.conn != c.id()) {
    m_log.debug("APICLI", "invalid connection for handle ", c.id(),
                ", ignoring");
    return;
  }
  uint8_t options = 0;
  d.state = Connection::State::Connected;
  c.setCookie(m_delegate.onConnected(id, nullptr, options));
  c.setOptions(options);
}

void
Client::onAborted(tcpv4::Connection& c)
{
  m_log.debug("APICLI", "connection aborted, closing");
  ID id = m_idx[c.id()];
  Connection& d = m_cns[id];
  if (d.conn != c.id()) {
    m_log.debug("APICLI", "invalid connection for handle ", c.id(),
                ", ignoring");
    return;
  }
  d.state = Connection::State::Closed;
  m_delegate.onClosed(id, c.cookie());
  c.setCookie(nullptr);
}

void
Client::onTimedOut(tcpv4::Connection& c)
{
  m_log.debug("APICLI", "connection timed out, closing");
  ID id = m_idx[c.id()];
  Connection& d = m_cns[id];
  if (d.conn != c.id()) {
    m_log.debug("APICLI", "invalid connection for handle ", c.id(),
                ", ignoring");
    return;
  }
  d.state = Connection::State::Closed;
  m_delegate.onClosed(id, c.cookie());
  c.setCookie(nullptr);
}

void
Client::onClosed(tcpv4::Connection& c)
{
  m_log.debug("APICLI", "connection closed");
  ID id = m_idx[c.id()];
  Connection& d = m_cns[id];
  if (d.conn != c.id()) {
    m_log.debug("APICLI", "invalid connection for handle ", c.id(),
                ", ignoring");
    return;
  }
  d.state = Connection::State::Closed;
  m_delegate.onClosed(id, c.cookie());
  c.setCookie(nullptr);
}

void
Client::onSent(UNUSED tcpv4::Connection& c)
{
#ifdef TULIPS_ENABLE_LATENCY_MONITOR
  ID id = m_idx[c.id()];
  Connection& d = m_cns[id];
  if (d.conn != c.id()) {
    LOG("invalid connection for handle " << c.id() << ", ignoring");
    return;
  }
  d.history.push_back(d.pre);
  d.pre = 0;
#endif
}

Action
Client::onAcked(tcpv4::Connection& c)
{
  ID id = m_idx[c.id()];
  Connection& d = m_cns[id];
  if (d.conn != c.id()) {
    m_log.debug("APICLI", "invalid connection for handle ", c.id(),
                ", ignoring");
    return Action::Abort;
  }
#ifdef TULIPS_ENABLE_LATENCY_MONITOR
  d.count += 1;
  d.lat += system::Clock::read() - d.history.front();
  d.history.pop_front();
#endif
  return m_delegate.onAcked(id, c.cookie());
}

Action
Client::onAcked(stack::tcpv4::Connection& c, const uint32_t alen,
                uint8_t* const sdata, uint32_t& slen)
{
  ID id = m_idx[c.id()];
  Connection& d = m_cns[id];
  if (d.conn != c.id()) {
    m_log.debug("APICLI", "invalid connection for handle ", c.id(),
                ", ignoring");
    return Action::Abort;
  }
#ifdef TULIPS_ENABLE_LATENCY_MONITOR
  d.count += 1;
  d.lat += system::Clock::read() - d.history.front();
  d.history.pop_front();
#endif
  return m_delegate.onAcked(id, c.cookie(), alen, sdata, slen);
}

Action
Client::onNewData(stack::tcpv4::Connection& c, const uint8_t* const data,
                  const uint32_t len)
{
  ID id = m_idx[c.id()];
  Connection& d = m_cns[id];
  if (d.conn != c.id()) {
    m_log.debug("APICLI", "invalid connection for handle ", c.id(),
                ", ignoring");
    return Action::Abort;
  }
  return m_delegate.onNewData(id, c.cookie(), data, len);
}

Action
Client::onNewData(stack::tcpv4::Connection& c, const uint8_t* const data,
                  const uint32_t len, const uint32_t alen, uint8_t* const sdata,
                  uint32_t& slen)
{
  ID id = m_idx[c.id()];
  Connection& d = m_cns[id];
  if (d.conn != c.id()) {
    m_log.debug("APICLI", "invalid connection for handle ", c.id(),
                ", ignoring");
    return Action::Abort;
  }
  return m_delegate.onNewData(id, c.cookie(), data, len, alen, sdata, slen);
}

}
