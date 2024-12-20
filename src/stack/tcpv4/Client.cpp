#include <tulips/stack/IPv4.h>
#include <tulips/stack/TCPv4.h>
#include <tulips/stack/Utils.h>
#include <tulips/stack/tcpv4/Options.h>
#include <tulips/stack/tcpv4/Processor.h>
#include <tulips/system/Compiler.h>
#include <tulips/system/Utils.h>
#include <algorithm>
#include <cstring>
#include <optional>

#ifdef __linux__
#include <arpa/inet.h>
#endif

namespace tulips::stack::tcpv4 {

uint16_t
Processor::findLocalPort() const
{
  /*
   * Look for a free port.
   */
  while (true) {
    /*
     * Compute a local port value.
     */
    auto lport = (system::Clock::instant() & 0x3FFF) + 10000;
    /*
     * Find a match.
     */
    auto match = std::find_if(
      m_conns.begin(), m_conns.end(), [lport](auto const& a) -> bool {
        return a->m_state != Connection::CLOSED && a->m_lport == htons(lport);
      });
    /*
     * Return if no match was found.
     */
    if (match == m_conns.end()) {
      return lport;
    }
  }
  /*
   * Make GCC happy.
   */
#if defined(__GNUC__) && defined(__GNUC_PREREQ)
  return 0;
#endif
}

Status
Processor::open(Connection::ID& id)
{
  std::optional<Connection::ID> match;
  /*
   * Scan the connections.
   */
  for (auto& e : m_conns) {
    /*
     * If a connection is closed, use it.
     */
    if (e->m_state == Connection::CLOSED) {
      match = e->m_id;
      break;
    }
    /*
     * Keep track of the time-wait connections.
     */
    if (e->m_state == Connection::TIME_WAIT) {
      if (!match || m_conns[*match]->m_rtm > e->m_rtm) {
        match = e->m_id;
      }
    }
  }
  /*
   * If we have a time-wait candidate, use it.
   */
  if (match) {
    m_conns[*match]->m_state = Connection::OPEN;
    id = *match;
    return Status::Ok;
  }
  /*
   * Last resort, we allocate a new connection.
   */
  auto c = Connection::allocate(m_conns.size());
  c->m_state = Connection::OPEN;
  id = c->id();
  m_conns.emplace_back(std::move(c));
  /*
   * Error if no connection if available.
   */
  return Status::Ok;
}

Status
Processor::abort(const Connection::ID id)
{
  /*
   * Check if the connection is valid.
   */
  if (id >= m_conns.size()) {
    return Status::InvalidConnection;
  }
  /*
   * Get the connection.
   */
  auto& c = m_conns[id];
  /*
   * Check the connection's state.
   */
  if (c->m_state == Connection::CLOSED) {
    return Status::InvalidConnection;
  }
  /*
   * Send the RST message. It MUST be done BEFORE calling the handler as the
   * connection's state is updated in sendAbort();
   */
  uint8_t* outdata = c->m_sdat;
  OUTTCP->flags = 0;
  auto ret = sendAbort(*c);
  /*
   * Notify the handler.
   */
  m_handler.onAborted(*c, system::Clock::now());
  /*
   * Done.
   */
  close(*c);
  return ret;
}

Status
Processor::close(const Connection::ID id)
{
  /*
   * Check if the connection is valid.
   */
  if (id >= m_conns.size()) {
    return Status::InvalidConnection;
  }
  /*
   * Get the connection.
   */
  auto& c = m_conns[id];
  /*
   * Check the connection's state.
   */
  if (c->m_state == Connection::OPEN) {
    c->m_state = Connection::CLOSED;
    return Status::Ok;
  }
  if (c->m_state != Connection::ESTABLISHED) {
    return Status::NotConnected;
  }
  /*
   * If we are already busy, return OK.
   */
  if (c->m_segs->hasUsed()) {
    c->m_state = Connection::CLOSE;
    return Status::Ok;
  }
  /*
   * Close the connection.
   */
  uint8_t* outdata = c->m_sdat;
  OUTTCP->flags = 0;
  return sendClose(*c);
}

Status
Processor::setOptions(const Connection::ID id, const uint8_t options)
{
  /*
   * Check if the connection is valid.
   */
  if (id >= m_conns.size()) {
    return Status::InvalidConnection;
  }
  /*
   * Get the connection.
   */
  auto& c = m_conns[id];
  /*
   * Set the options.
   */
  c->setOptions(options);
  return Status::Ok;
}

Status
Processor::clearOptions(const Connection::ID id, const uint8_t options)
{
  /*
   * Check if the connection is valid.
   */
  if (id >= m_conns.size()) {
    return Status::InvalidConnection;
  }
  /*
   * Get the connection.
   */
  auto& c = m_conns[id];
  /*
   * Clear the options.
   */
  c->clearOptions(options);
  return Status::Ok;
}

Status
Processor::connect(const Connection::ID id, ethernet::Address const& rhwaddr,
                   ipv4::Address const& ripaddr, const Port rport)
{
  /*
   * Check if the connection is valid.
   */
  if (id >= m_conns.size()) {
    return Status::InvalidConnection;
  }
  /*
   * Get the connection.
   */
  auto& c = m_conns[id];
  /*
   * Update IP and Ethernet attributes.
   */
  m_ipv4to.setProtocol(ipv4::Protocol::TCP);
  m_ipv4to.setDestinationAddress(ripaddr);
  m_ethto.setDestinationAddress(rhwaddr);
  /*
   * Allocate a send buffer.
   */
  uint8_t* outdata;
  Status ret = m_ipv4to.prepare(outdata);
  if (ret != Status::Ok) {
    return ret;
  }
  /*
   * Grab a local port.
   */
  auto const& lipaddr = m_ipv4to.hostAddress();
  Port lport = findLocalPort();
  /*
   * Add the filter to the device. Retry a few times as some devices rely on
   * RSS hash tables that are prone to collisions.
   */
  for (auto i = 0; i < 1024; i += 1) {
    ret = m_device.listen(ipv4::Protocol::TCP, lipaddr, lport, ripaddr, rport);
    if (ret == Status::Ok) {
      break;
    }
    lport = findLocalPort();
  }
  /*
   * Make sure we are now listening to the port.
   */
  if (ret != Status::Ok) {
    m_log.error("TCP4", "registering client-side filter failed");
    m_ipv4to.release(outdata);
    return ret;
  }
  /*
   * Prepare the connection.
   */
  c->m_rethaddr = rhwaddr;
  c->m_ripaddr = ripaddr;
  c->m_lport = htons(lport);
  c->m_rport = htons(rport);
  c->m_rcv_nxt = 0;
  c->m_snd_nxt = m_iss;
  c->m_state = Connection::SYN_SENT;
  c->m_wndlvl = WndLimits::max();
  c->m_atm = 0;
  c->m_ktm = 0;
  c->m_opts = 0;
  c->m_ackdata = false;
  c->m_newdata = false;
  c->m_pshdata = false;
  c->m_live = false;
  c->m_wndscl = 0;
  c->m_window = 0;
  c->m_nrtx = 1;
  c->m_slen = 0;
  c->m_sdat = nullptr;
  c->m_initialmss = m_device.mtu() - HEADER_OVERHEAD;
  c->m_mss = c->m_initialmss;
  c->m_sa = 0;
  c->m_sv = 16;
  c->m_rto = RTO;
  c->m_rtm = RTO;
  c->m_cookie = nullptr;
  /*
   * Update the connection index.
   */
  m_index.insert({ std::hash<Connection>()(*c), id });
  /*
   * Prepare the SYN. SYN segments don't contain any data but have a size of 1
   * to increase the sequence number by 1.
   */
  Segment& seg = c->m_segs->acquire();
  seg.set(1, c->m_snd_nxt, outdata);
  OUTTCP->flags = 0;
  /*
   * Send SYN.
   */
  if (sendSyn(*c, seg) != Status::Ok) {
    close(*c);
    return ret;
  }
  /*
   * Done.
   */
  return Status::Ok;
}

bool
Processor::isClosed(const Connection::ID id) const
{
  /*
   * Check if the connection is valid.
   */
  if (id >= m_conns.size()) {
    return true;
  }
  /*
   * Get the connection.
   */
  auto const& c = m_conns[id];
  /*
   * Check its state.
   */
  return c->m_state == Connection::CLOSED;
}

Status
Processor::send(const Connection::ID id, const uint32_t len,
                const uint8_t* const data, uint32_t& off)
{
  /*
   * Check if the connection is valid.
   */
  if (id >= m_conns.size()) {
    return Status::InvalidConnection;
  }
  /*
   * Get the connection.
   */
  auto& c = m_conns[id];
  /*
   * Check the connection state.
   */
  if (c->m_state != Connection::ESTABLISHED) {
    return Status::NotConnected;
  }
  if (HAS_NODELAY(*c) && !c->m_segs->hasFree()) {
    return Status::OperationInProgress;
  }
  if (len == 0 || data == nullptr) {
    return Status::InvalidArgument;
  }
  if (off >= len) {
    return Status::InvalidArgument;
  }
  /*
   * Transmit the data. The off parameter is used to store how much data has
   * been written. It is also used as an offset in case the previous write was
   * partial. It is up to the application to reset that offset once the full
   * payload has been transfered.
   */
  uint32_t bound = c->window() < m_mss ? c->window() : m_mss;
  uint32_t slen = len - off;
  /*
   * Check the various corner cases: the remote window can suddenly become
   * smaller than what we want to send or it is just too small to send anything
   * of value.
   */
  if (bound < c->m_slen) {
    return Status::OperationInProgress;
  }
  if (c->m_slen + slen > bound) {
    slen = bound - c->m_slen;
  }
  /*
   * Copy the payload if there is any.
   */
  if (slen != 0) {
    memcpy(c->m_sdat + HEADER_LEN + c->m_slen, data + off, slen);
    /*
     * Remember how much data we send out now so that we know when everything
     * has been acknowledged.
     */
    off += slen;
    c->m_slen = c->m_slen + slen;
  }
  /*
   * Check if we can send the current segment.
   */
  if (!c->m_segs->hasFree()) {
    return slen == 0 ? Status::OperationInProgress : Status::Ok;
  }
  /*
   * Send immediately if Nagle's algorithm has been disabled.
   */
  if (HAS_NODELAY(*c)) {
    m_log.trace("TCP", "<", id, "> client sending ", slen, "B");
    return sendNoDelay(*c, off == len ? Flag::PSH : 0);
  }
  /*
   * Otherwise, queue for sending.
   */
  return sendNagle(*c, bound);
}

Status
Processor::get(const Connection::ID id, ipv4::Address& laddr, Port& lport,
               ipv4::Address& raddr, Port& rport) const
{
  /*
   * Check if the connection is valid.
   */
  if (id >= m_conns.size()) {
    return Status::InvalidConnection;
  }
  /*
   * Get the connection.
   */
  auto const& c = m_conns[id];
  /*
   * Check the connection's state.
   */
  if (c->m_state != Connection::ESTABLISHED) {
    return Status::NotConnected;
  }
  /*
   * Get the connection info.
   */
  laddr = m_ipv4to.hostAddress();
  lport = ntohs(c->m_lport);
  raddr = c->m_ripaddr;
  rport = ntohs(c->m_rport);
  return Status::Ok;
}

void*
Processor::cookie(const Connection::ID id) const
{
  /*
   * Check if the connection is valid.
   */
  if (id >= m_conns.size()) {
    return nullptr;
  }
  auto const& c = m_conns[id];
  return c->cookie();
}

}
