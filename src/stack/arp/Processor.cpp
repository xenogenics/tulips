#include <tulips/stack/ARP.h>
#include <tulips/stack/Utils.h>
#include <tulips/stack/arp/Processor.h>
#include <tulips/system/Utils.h>
#include <arpa/inet.h>

#define INARP ((const Header*)data)
#define OUTARP ((Header*)outdata)
#define HEADER_LEN sizeof(Header)

constexpr const uint16_t HWTYPE_ETH = 1;
constexpr const uint8_t MAX_AGE = 120;
constexpr const size_t TABLE_SIZE = 32;

namespace tulips::stack::arp {

Processor::Entry::Entry() : ipaddr(), ethaddr(), time(0) {}

Processor::Processor(system::Logger& log, ethernet::Producer& eth,
                     ipv4::Producer& ip4)
  : m_log(log), m_eth(eth), m_ipv4(ip4), m_table(), m_time(0), m_timer()
{
  m_table.resize(TABLE_SIZE);
  m_timer.set(system::Clock::SECOND * 10);
}

Status
Processor::run()
{
  /*
   * Poll the timer
   */
  if (m_timer.expired()) {
    m_timer.reset();
    ++m_time;
    for (auto& e : m_table) {
      if (e.ipaddr.empty()) {
        continue;
      }
      if (m_time - e.time >= MAX_AGE) {
        m_log.debug("ARP", "clearing entry for ", e.ipaddr.toString());
        e.ipaddr = ipv4::Address();
      }
    }
  }
  return Status::Ok;
}

Status
Processor::process(const uint16_t len, const uint8_t* const data,
                   UNUSED const Timestamp ts)
{
  /*
   * Check if the incoming packet has the right size.
   */
  if (len < sizeof(Header)) {
    return Status::IncompleteData;
  }
  /*
   * Process the incoming request.
   */
  switch (ntohs(INARP->opcode)) {
    /*
     * ARP request. If it asked for our address, we send out a reply.
     */
    case OpCode::Request: {
      /*
       * Skip the request if it was not meant for us.
       */
      if (INARP->dipaddr != m_ipv4.hostAddress()) {
        m_log.debug("ARP", "X ", INARP->dipaddr.toString(), " <> ",
                    m_ipv4.hostAddress().toString());
        break;
      }
      /*
       * Update ethernet state
       */
      m_eth.setType(ethernet::ETHTYPE_ARP);
      m_eth.setDestinationAddress(INARP->shwaddr);
      /*
       * Prepare a send buffer
       */
      uint8_t* outdata;
      Status ret = m_eth.prepare(outdata);
      if (ret != Status::Ok) {
        return ret;
      }
      /*
       * We register the one who made the request in our ARP table, since it is
       * likely that we will do more communication with this host in the future.
       */
      update(INARP->sipaddr, INARP->shwaddr);
      /*
       * The reply opcode is 2.
       */
      OUTARP->opcode = htons(OpCode::Reply);
      OUTARP->hwtype = htons(HWTYPE_ETH);
      OUTARP->protocol = htons(ethernet::ETHTYPE_IP);
      OUTARP->hwlen = 6;
      OUTARP->protolen = 4;
      OUTARP->dhwaddr = INARP->shwaddr;
      OUTARP->shwaddr = m_eth.hostAddress();
      OUTARP->dipaddr = INARP->sipaddr;
      OUTARP->sipaddr = m_ipv4.hostAddress();
      /*
       * Let the device know we have some data
       */
      m_log.debug("ARP", "(", m_eth.hostAddress().toString(), ", ",
                  m_ipv4.hostAddress().toString(), ") -> ",
                  INARP->shwaddr.toString());
      m_eth.commit(HEADER_LEN, outdata);
      return Status::Ok;
    }
    /*
     * ARP reply. We insert or update the ARP table if it was meant for us.
     */
    case OpCode::Reply: {
      /*
       * Skip the request if it was not meant for us.
       */
      if (INARP->dipaddr != m_ipv4.hostAddress()) {
        break;
      }
      /*
       * Register the reply in the table.
       */
      m_log.debug("ARP", "+ ", INARP->sipaddr.toString(), " -> ",
                  INARP->shwaddr.toString());
      update(INARP->sipaddr, INARP->shwaddr);
      break;
    }
  }
  /*
   * Return our status
   */
  return Status::Ok;
}

Status
Processor::sent(uint8_t* const buf)
{
  return m_ipv4.release(buf);
}

bool
Processor::has(ipv4::Address const& destipaddr)
{
  ethernet::Address ethaddr;
  return query(destipaddr, ethaddr);
}

Status
Processor::discover(ipv4::Address const& destipaddr)
{
  /*
   * If we have the translation, nothing to do, otherwise discover.
   */
  if (has(destipaddr)) {
    return Status::Ok;
  }
  /*
   * Set the ethernet parameters.
   */
  ipv4::Address ipaddr = hopAddress(destipaddr);
  m_eth.setType(ethernet::ETHTYPE_ARP);
  m_eth.setDestinationAddress(ethernet::Address::BROADCAST);
  /*
   * Prepare a send buffer.
   */
  uint8_t* outdata;
  Status ret = m_eth.prepare(outdata);
  if (ret != Status::Ok) {
    /*
     * Skip the request if we cannot allocate a send buffer
     */
    return ret;
  }
  /*
   * Set the ARP parameters
   */
  OUTARP->dhwaddr = ethernet::Address();
  OUTARP->shwaddr = m_eth.hostAddress();
  OUTARP->dipaddr = ipaddr;
  OUTARP->sipaddr = m_ipv4.hostAddress();
  OUTARP->opcode = htons(OpCode::Request);
  OUTARP->hwtype = htons(HWTYPE_ETH);
  OUTARP->protocol = htons(ethernet::ETHTYPE_IP);
  OUTARP->hwlen = 6;
  OUTARP->protolen = 4;
  /*
   * Commit the message, return
   */
  m_log.debug("ARP", "? ", OUTARP->dipaddr.toString());
  return m_eth.commit(HEADER_LEN, outdata);
}

bool
Processor::query(ipv4::Address const& destipaddr, ethernet::Address& ethaddr)
{
  /*
   * Check if the IP is a broadcast IP
   */
  if (destipaddr == ipv4::Address::BROADCAST) {
    ethaddr = ethernet::Address::BROADCAST;
    return true;
  }
  /*
   * Check if the destination address is on the local network.
   */
  ipv4::Address const& ipaddr = hopAddress(destipaddr);
  /*
   * Loop-up the address in our table
   */
  for (auto& e : m_table) {
    if (e.ipaddr == ipaddr) {
      ethaddr = e.ethaddr;
      return true;
    }
  }
  return false;
}

void
Processor::update(ipv4::Address const& ipaddr, ethernet::Address const& ethaddr)
{
  Table::iterator e;
  /*
   * Walk through the ARP mapping table and try to find an entry to update. If
   * none is found, the IP -> MAC address mapping is inserted in the ARP table.
   */
  for (e = m_table.begin(); e != m_table.end(); e++) {
    /*
     * Only check those entries that are actually in use.
     */
    if (e->ipaddr.empty()) {
      continue;
    }
    /*
     * Check if the source IP address of the incoming packet matches the IP
     * address in this ARP table entry.
     */
    if (ipaddr != e->ipaddr) {
      continue;
    }
    /*
     * An old entry found, update this and return.
     */
    e->ethaddr = ethaddr;
    e->time = m_time;
    return;
  }
  /*
   * If we get here, no existing ARP table entry was found, so we create one.
   * First, we try to find an unused entry in the ARP table.
   */
  uint8_t oldest = 0;
  for (e = m_table.begin(); e != m_table.end(); e++) {
    if (e->ipaddr.empty()) {
      break;
    }
    oldest = e->time;
  }
  /*
   * If no unused entry is found, we try to find the oldest entry and throw it
   * away.
   */
  if (e == m_table.end()) {
    for (e = m_table.begin(); e != m_table.end(); e++) {
      if (e->time == oldest) {
        break;
      }
    }
  }
  /*
   * Now, i is the ARP table entry which we will fill with the new information.
   */
  e->ipaddr = ipaddr;
  e->ethaddr = ethaddr;
  e->time = m_time;
}

/*
 * Destination address was not on the local network, so we need to use
 * the default router's IP address instead of the destination address
 * when determining the MAC address.
 */
ipv4::Address const&
Processor::hopAddress(ipv4::Address const& addr) const
{
  if (!m_ipv4.isLocal(addr)) {
    return m_ipv4.defaultRouterAddress();
  }
  return addr;
}

}
