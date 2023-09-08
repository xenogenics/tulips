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
#include <set>
#include <stdexcept>
#include <vector>

#define OUTTCP ((Header*)outdata)

namespace tulips::stack::tcpv4 {

/*
 * Protocol constants.
 */
static constexpr int USED MAXRTX = 5;
static constexpr int USED MAXSYNRTX = 5;
static constexpr int USED TIME_WAIT_TIMEOUT = 120;

/*
 * The TCPv4 statistics.
 */
struct Statistics
{
  uint64_t drop;    // Number of dropped TCP segments.
  uint64_t recv;    // Number of recived TCP segments.
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

  Status run() override;
  Status process(const uint16_t len, const uint8_t* const data) override;

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

  /*
   * Server-side operations.
   */

  void listen(const Port port);
  void unlisten(const Port port);

  /*
   * Client-side operations.
   */

  Status setOptions(Connection::ID const& id, const uint8_t options);
  Status clearOptions(Connection::ID const& id, const uint8_t options);

  Status connect(ethernet::Address const& rhwaddr, ipv4::Address const& ripaddr,
                 const Port rport, Connection::ID& id);

  Status abort(Connection::ID const& id);
  Status close(Connection::ID const& id);

  bool isClosed(Connection::ID const& id) const;

  /*
   * In the non-error cases, the send methods may return:
   * - OK : the payload has been written and/or pending data has been sent.
   * - OperationInProgress : no operation could have been performed.
   */

  Status send(Connection::ID const& id, const uint32_t len,
              const uint8_t* const data, uint32_t& off);

  Status get(Connection::ID const& id, ipv4::Address& ripaddr, Port& lport,
             Port& rport);

  void* cookie(Connection::ID const& id) const;

  /*
   * Some connection related methods, mostly for testing.
   */

  inline Status hasOutstandingSegments(Connection::ID const& id, bool& res)
  {
    if (id >= m_nconn) {
      return Status::InvalidConnection;
    }
    Connection& c = m_conns[id];
    res = c.hasOutstandingSegments();
    return Status::Ok;
  }

private:
  using Ports = std::set<Port>;
  using Connections = std::vector<Connection>;

#if !(defined(TULIPS_HAS_HW_CHECKSUM) && defined(TULIPS_DISABLE_CHECKSUM_CHECK))
  static uint16_t checksum(ipv4::Address const& src, ipv4::Address const& dst,
                           const uint16_t len, const uint8_t* const data);
#endif

  Status process(Connection& e, const uint16_t len, const uint8_t* const data);
  Status reset(const uint16_t len, const uint8_t* const data);

  Status sendNagle(Connection& e, const uint32_t bound);
  Status sendNoDelay(Connection& e, const uint8_t flag = 0);

  Status sendAbort(Connection& e);
  Status sendClose(Connection& e);
  Status sendSyn(Connection& e, Segment& s);
  Status sendAck(Connection& e);

  inline Status sendSynAck(Connection& e, Segment& s)
  {
    uint8_t* outdata = s.m_dat;
    OUTTCP->flags = Flag::ACK;
    return sendSyn(e, s);
  }

  inline Status sendFin(Connection& e, Segment& s)
  {
    uint8_t* outdata = s.m_dat;
    OUTTCP->flags |= Flag::FIN;
    OUTTCP->offset = 5;
    return send(e, HEADER_LEN, s);
  }

  inline Status sendFinAck(Connection& e, Segment& s)
  {
    uint8_t* outdata = s.m_dat;
    OUTTCP->flags = Flag::ACK;
    return sendFin(e, s);
  }

  /**
   * Send an buffer in the context of a connection.
   *
   * @param e the connection.
   * @param outdata the buffer to send.
   *
   * @return the status of the operation.
   */
  Status send(Connection& e, uint8_t* const outdata);

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

  Status rexmit(Connection& e);

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
  Statistics m_stats;
  system::Timer m_timer;
};

}
