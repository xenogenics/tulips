#pragma once

#include <tulips/stack/TCPv4.h>
#include <tulips/stack/ethernet/Processor.h>
#include <tulips/stack/ethernet/Producer.h>
#include <tulips/stack/ipv4/Processor.h>
#include <tulips/stack/ipv4/Producer.h>
#include <tulips/stack/tcpv4/Connection.h>
#include <tulips/stack/tcpv4/EventHandler.h>
#include <tulips/system/Buffer.h>
#include <tulips/system/Logger.h>
#include <tulips/system/Timer.h>
#include <tulips/transport/Device.h>
#include <tulips/transport/Processor.h>
#include <cstdint>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#define INTCP ((const Header*)data)
#define OUTTCP ((Header*)outdata)

namespace tulips::stack::tcpv4 {

/*
 * Protocol constants.
 */
static constexpr int USED TIME_WAIT_TIMEOUT = 120;

/*
 * The TCPv4 statistics.
 */
struct Statistics
{
  uint64_t drop;    // Number of dropped TCP segments.
  uint64_t recv;    // Number of received TCP segments.
  uint64_t sent;    // Number of sent TCP segments.
  uint64_t chkerr;  // Number of TCP segments with a bad checksum.
  uint64_t ackerr;  // Number of TCP segments with a bad ACK number.
  uint64_t rst;     // Number of recevied TCP RST (reset) segments.
  uint64_t rexmit;  // Number of retransmitted TCP segments.
  uint64_t syndrop; // Number of dropped SYNs (no connection was avaliable).
  uint64_t synrst;  // Number of SYNs for closed ports, triggering a RST.
};

/*
 * The TCPv4 processor.
 */
class Processor : public transport::Processor
{
public:
  Processor(system::Logger& log, transport::Device& device,
            ethernet::Producer& eth, ipv4::Producer& ip4, EventHandler& h,
            const size_t nconn);

  /*
   * Processor interface.
   */

  Status run() override;
  Status process(const uint16_t len, const uint8_t* const data,
                 const Timestamp ts) override;
  Status sent(const uint16_t len, uint8_t* const data) override;

  /*
   * Server-side operations.
   */

  Processor& setEthernetProcessor(ethernet::Processor& eth)
  {
    m_ethfrom = &eth;
    return *this;
  }

  Processor& setIPv4Processor(ipv4::Processor& ip4)
  {
    m_ipv4from = &ip4;
    return *this;
  }

  void listen(const Port port);
  void unlisten(const Port port);

  /*
   * Client-side operations.
   */

  Status open(Connection::ID& id);
  Status abort(const Connection::ID id);
  Status close(const Connection::ID id);

  Status setOptions(const Connection::ID id, const uint8_t options);
  Status clearOptions(const Connection::ID id, const uint8_t options);

  Status connect(const Connection::ID id, ethernet::Address const& rhwaddr,
                 ipv4::Address const& ripaddr, const Port rport);

  bool isClosed(const Connection::ID id) const;

  /*
   * In the non-error cases, the send methods may return:
   * - OK : the payload has been written and/or pending data has been sent.
   * - OperationInProgress : no operation could have been performed.
   */

  Status send(const Connection::ID id, const uint32_t len,
              const uint8_t* const data, uint32_t& off);

  Status get(const Connection::ID id, ipv4::Address& laddr, Port& lport,
             ipv4::Address& raddr, Port& rport) const;

  void* cookie(const Connection::ID id) const;

  /*
   * Some connection related methods, mostly for testing.
   */

  inline Status hasOutstandingSegments(const Connection::ID id, bool& res)
  {
    /*
     * Check that the connection is valid.
     */
    if (id >= m_nconn) {
      return Status::InvalidConnection;
    }
    /*
     * Get the connection.
     */
    Connection& c = m_conns[id];
    /*
     * Check outstanding segments.
     */
    res = c.hasOutstandingSegments();
    return Status::Ok;
  }

private:
  using Ports = std::unordered_set<Port>;
  using Connections = std::vector<Connection>;
  using Index = std::unordered_map<uint64_t, Connection::ID>;

#if !(defined(TULIPS_HAS_HW_CHECKSUM) && defined(TULIPS_DISABLE_CHECKSUM_CHECK))
  static uint16_t checksum(ipv4::Address const& src, ipv4::Address const& dst,
                           const uint16_t len, const uint8_t* const data);
#endif

  /**
   * Process tasks on the fast timer.
   *
   * @param ticks elapsed ticks.
   *
   * @return the status of the operation.
   */
  Status onFastTimer(const size_t ticks);

  /**
   * Process tasks on the fast timer.
   *
   * @param ticks elapsed ticks.
   *
   * @return the status of the operation.
   */
  Status onSlowTimer(const size_t ticks);
  /**
   * Close a connection.
   *
   * @param e the connection to close.
   *
   * @return the status of the operation.
   */
  void close(Connection& e);

  /**
   * @return a new local port.
   */
  uint16_t findLocalPort() const;

  /**
   * Process the incoming packet for a given connection.
   *
   * @param e the connection.
   * @param len the length of the packet.
   * @param data the packet data.
   * @param ts the timestamp of the event.
   *
   * @return the status of the operation.
   */
  Status process(Connection& e, const uint16_t len, const uint8_t* const data,
                 const Timestamp ts);

  /**
   * Send the data present in the send buffer using Nagle's algorithm.
   *
   * @param e the connection to send the data on.
   * @param bound the maximum segment lenght.
   *
   * @return the status of the operation.
   */
  Status sendNagle(Connection& e, const uint32_t bound);

  /**
   * Send the data present in the send buffer immediately
   *
   * @param e the connection to send the data on.
   * @param flag any extra flag to apply to the packet.
   *
   * @return the status of the operation.
   */
  Status sendNoDelay(Connection& e, const uint8_t flag = 0);

  /**
   * Abort a connection. Any data in the send buffer is discarded.
   *
   * @param e the connection to abort.
   *
   * @return the status of the operation.
   */
  Status sendAbort(Connection& e);

  /**
   * Send a raw reset.
   *
   * @param data the input packet.
   *
   * @return the status of the operation.
   */
  Status sendReset(const uint8_t* const data);

  /**
   * Close a connection. A segment must be available.
   *
   * @param e the connection to close.
   *
   * @return the status of the operation.
   */
  Status sendClose(Connection& e);

  /**
   * Open a connection.
   *
   * @param e the connection to open.
   * @param s the segment to use.
   *
   * @return the status of the operation.
   */
  Status sendSyn(Connection& e, Segment& s);

  /**
   * Send an ACK on a connection. Any data present on the send buffer will be
   * saved and restored once the operation has completed.
   *
   * @param e the connection to send the ACK on.
   * @param k the ACK is a keep-alive message.
   *
   * @return the status of the operation.
   */
  Status sendAck(Connection& e, const bool k);

  /**
   * Respond to a connection request.
   *
   * @param e the connection to open.
   * @param s the segment to use.
   *
   * @return the status of the operation.
   */
  inline Status sendSynAck(Connection& e, Segment& s)
  {
    uint8_t* outdata = s.m_dat;
    OUTTCP->flags = Flag::ACK;
    return sendSyn(e, s);
  }

  /**
   * Send a connection close request.
   *
   * @param e the connection to open.
   * @param s the segment to use.
   *
   * @return the status of the operation.
   */
  inline Status sendFin(Connection& e, Segment& s)
  {
    uint8_t* outdata = s.m_dat;
    OUTTCP->flags |= Flag::FIN;
    OUTTCP->offset = 5;
    return send(e, HEADER_LEN, s);
  }

  /**
   * Response to a connection close request.
   *
   * @param e the connection to open.
   * @param s the segment to use.
   *
   * @return the status of the operation.
   */
  inline Status sendFinAck(Connection& e, Segment& s)
  {
    uint8_t* outdata = s.m_dat;
    OUTTCP->flags = Flag::ACK;
    return sendFin(e, s);
  }

  /**
   * Send the content of a connection's send buffer.
   *
   * @param e the connection.
   * @param k the message is a keep-alive.
   *
   * @return the status of the operation.
   */
  Status send(Connection& e, const bool k);

  /**
   * Handle abort condition for a given connection.
   *
   * @param e the connection.
   *
   * @return the status of the operation.
   */
  Status abort(Connection& e);

  /**
   * Handle time-out condition for a given connection.
   *
   * @param e the connection.
   *
   * @return the status of the operation.
   */
  Status timeOut(Connection& e);

  /**
   * Handle retransmits for a given connection.
   *
   * @param e the connection.
   *
   * @return the status of the operation.
   */
  Status rexmit(Connection& e);

  /**
   * Send a segment in the context of a connection.
   *
   * @param e the connection.
   * @param s the segment to send.
   * @param flags optional TCP flags.
   *
   * @return the status of the operation.
   */
  inline Status send(Connection& e, Segment& s, const uint8_t flags = 0)
  {
    uint8_t* outdata = s.m_dat;
    /*
     * Send PSH/ACK message. TCP does not require to send an ACK with PSH,
     * but Linux seems pretty bent on wanting one. So we play nice. Again.
     */
    OUTTCP->flags = flags | Flag::ACK;
    OUTTCP->offset = 5;
    /*
     * Since we are sending an ACK, we reset the ACK timer.
     */
    e.m_atm = 0;
    /*
     * Send the segment.
     */
    return send(e, s.m_len + HEADER_LEN, s);
  }

  /**
   * Send a segment in the context of a connection with a specific length.
   *
   * NOTE(xrg): the order of the arguments is necessary to alleviate ambiguities
   * between uint8_t and uint32_t.
   *
   * @param e the connection.
   * @param len the final length of the segment.
   * @param s the segment to send.
   *
   * @return the status of the operation.
   */
  Status send(Connection& e, const uint32_t len, Segment& s);

  /**
   * Raw send without neither a connection nor a segment.
   *
   * @param dst the destination address.
   * @param len the final length of the segment.
   * @param mss the MSS to use.
   * @param outdata buffer to send.
   *
   * @return the status of the operation.
   */
  Status send(ipv4::Address const& dst, const uint32_t len, const uint16_t mss,
              uint8_t* const outdata);

  system::Logger& m_log;
  transport::Device& m_device;
  ethernet::Producer& m_ethto;
  ipv4::Producer& m_ipv4to;
  EventHandler& m_handler;
  const size_t m_nconn;
  ethernet::Processor* m_ethfrom;
  ipv4::Processor* m_ipv4from;
  uint32_t m_iss;
  uint32_t m_mss;
  Ports m_listenports;
  Connections m_conns;
  Index m_index;
  Statistics m_stats;
  system::Timer m_fast;
  system::Timer m_slow;
};

}
