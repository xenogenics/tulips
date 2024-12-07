#pragma once

#include <tulips/stack/IPv4.h>
#include <tulips/stack/TCPv4.h>
#include <tulips/stack/ethernet/Producer.h>
#include <tulips/stack/ipv4/Producer.h>
#include <tulips/stack/tcpv4/FrameBuffer.h>
#include <tulips/stack/tcpv4/Options.h>
#include <tulips/stack/tcpv4/Segment.h>
#include <tulips/system/SpinLock.h>
#include <cstdint>
#include <functional>
#include <stdexcept>

namespace tulips::stack::tcpv4 {

/*
 * Protocol constants.
 */
static constexpr int USED MAXRTX = 5;
static constexpr int USED MAXSYNRTX = 5;

/*
 * We rely on the compiler to wrap around the value of the next segment. We
 * need at least 3 bits for NRTX to SEGM_B cannot be more that 5.
 */
#define SEGM_B 5
#define NRTX_B (8 - SEGM_B)

#define HAS_NODELAY(__e) ((__e).m_opts & Connection::NO_DELAY)
#define HAS_DELAYED_ACK(__e) ((__e).m_opts & Connection::DELAYED_ACK)
#define HAS_KEEP_ALIVE(__e) ((__e).m_opts & Connection::KEEP_ALIVE)

class Connection
{
public:
  using ID = uint16_t;

  enum State : uint8_t
  {
    CLOSE = 0x1,
    CLOSED = 0x2,
    CLOSING = 0x3,
    OPEN = 0x4,
    ESTABLISHED = 0x5,
    FIN_WAIT_1 = 0x6,
    FIN_WAIT_2 = 0x7,
    LAST_ACK = 0x8,
    SYN_RCVD = 0x9,
    SYN_SENT = 0xA,
    TIME_WAIT = 0xB,
  };

  enum Option : uint16_t
  {
    /**
     * Disable Nagle's algorithm.
     */
    NO_DELAY = 0x1,
    /**
     * Send grouped ACKs every 40ms.
     */
    DELAYED_ACK = 0x2,
    /**
     * Send a keep-alive probe every second, abort after 5 failures.
     */
    KEEP_ALIVE = 0x4,
  };

  Connection();

  inline ID id() const { return m_id; }

  inline uint16_t localPort() const { return m_lport; }

  inline uint16_t remotePort() const { return m_rport; }

  inline void* cookie() const { return m_cookie; }

  inline void setCookie(void* const cookie) { m_cookie = cookie; }

  inline void setOptions(const uint8_t opts) { m_opts |= opts; }

  inline void clearOptions(const uint8_t opts) { m_opts &= ~opts; }

  inline bool isNewDataPushed() const { return m_pshdata; }

private:
  static constexpr size_t SEGMENT_COUNT = 1 << SEGM_B;
  static constexpr size_t SEGMENT_BMASK = SEGMENT_COUNT - 1;

  /*
   * State.
   */

  inline bool isActive() const { return m_state != CLOSED; }

  inline bool hasPendingSendData() const { return m_slen != 0; }

  inline bool hasExpired() const
  {
    if (m_state == Connection::SYN_SENT || m_state == Connection::SYN_RCVD) {
      return m_nrtx == MAXSYNRTX;
    } else {
      return m_nrtx == MAXRTX;
    }
  }

  inline bool matches(ipv4::Address const& ripaddr, Header const& header) const
  {
    return header.dstport == m_lport && header.srcport == m_rport &&
           ripaddr == m_ripaddr;
  }

  inline uint32_t window() const { return (uint32_t)m_window << m_wndscl; }

  inline uint32_t window(const uint16_t wnd) const
  {
    return (uint32_t)wnd << m_wndscl;
  }

  inline void updateRttEstimation()
  {
    int8_t m = m_rto - m_rtm;
    /*
     * This is taken directly from VJs original code in his paper
     */
    m = m - (m_sa >> 3);
    m_sa += m;
    m = m < 0 ? -m : m;
    m = m - (m_sv >> 2);
    m_sv += m;
    m_rto = (m_sa >> 3) + m_sv;
  }

  inline void resetSendBuffer()
  {
    m_slen = 0;
    m_sdat = nullptr;
  }

  /*
   * Timers.
   */

  inline void armAckTimer(const uint32_t sendnxt)
  {
    if (m_newdata && m_atm == 0 && sendnxt == m_snd_nxt) {
      m_atm = ATO;
    }
  }

  /*
   * Segments.
   */

  inline bool hasAvailableSegments() const
  {
    for (size_t i = 0; i < SEGMENT_COUNT; i += 1) {
      if (m_segments[i].length() == 0) {
        return true;
      }
    }
    return false;
  }

  inline bool hasOutstandingSegments() const
  {
    for (size_t i = 0; i < SEGMENT_COUNT; i += 1) {
      if (m_segments[i].length() != 0) {
        return true;
      }
    }
    return false;
  }

  inline size_t segmentId(Segment const& s) const { return &s - m_segments; }

  inline Segment& segment() { return m_segments[m_segidx]; }

  inline Segment& nextAvailableSegment()
  {
    size_t idx = 0;
    for (size_t i = m_segidx; i < m_segidx + SEGMENT_COUNT; i += 1) {
      idx = i & SEGMENT_BMASK;
      if (m_segments[idx].length() == 0) {
        return m_segments[idx];
      }
    }
    throw std::runtime_error("have you called hasAvailableSegments()?");
  }

  inline size_t freeSegments() const
  {
    size_t count = 0;
    for (size_t i = 0; i < SEGMENT_COUNT; i += 1) {
      if (m_segments[i].length() == 0) {
        count += 1;
      }
    }
    return count;
  }

  inline size_t usedSegments() const
  {
    size_t count = 0;
    for (size_t i = 0; i < SEGMENT_COUNT; i += 1) {
      if (m_segments[i].length() > 0) {
        count += 1;
      }
    }
    return count;
  }

  /*
   * First cache line: member variables.
   */

  ID m_id;                      // 2 - Connection ID
                                //
  ethernet::Address m_rethaddr; // 6 - Ethernet address of the remote host
  ipv4::Address m_ripaddr;      // 4 - IP address of the remote host
                                //
  Port m_lport;                 // 2 - Local TCP port, in network byte order
  Port m_rport;                 // 2 - Remote TCP port, in network byte order
                                //
  uint32_t m_rcv_nxt;           // 4 - Sequence that we expect to receive next
  uint32_t m_snd_nxt;           // 4 - Sequence that was last sent by us

  struct
  {
    uint64_t m_state : 4;       //  4 - Connection state
    uint64_t m_ackdata : 1;     //  5 - Connection has been acked
    uint64_t m_newdata : 1;     //  6 - Connection has new data
    uint64_t m_pshdata : 1;     //  7 - Connection data is being pushed
    uint64_t m_live : 1;        //  8 - Connection is live
    uint64_t m_wndscl : 8;      // 16 - Remote peer window scale (max is 14)
    uint64_t m_window : 16;     // 32 - Remote peer window
    uint64_t m_segidx : SEGM_B; // 36 - Free segment index
    uint64_t m_nrtx : NRTX_B;   // 40 - Number of retransmissions (3 bit min)
    uint64_t m_slen : 24;       // 64 - Length of the send buffer
  };

  uint16_t m_initialmss; // 2 - Initial maximum segment size for the connection
  uint16_t m_mss;        // 2 - Current maximum segment size for the connection
                         //
  uint8_t m_sa;          // 1 - Retransmission time-out calculation state
  uint8_t m_sv;          // 1 - Retransmission time-out calculation state
  uint8_t m_rto;         // 1 - Retransmission time-out
  uint8_t m_rtm;         // 1 - Retransmission timer
                         //
  uint32_t m_wndlvl;     // 4 - Local window level
  uint8_t m_atm;         // 1 - Delayed ACK timer
  uint8_t m_ktm;         // 1 - Keep-alive timer
  uint16_t m_opts;       // 2 - Connection options (NO_DELAY, etc..)
                         //
  uint8_t* m_sdat;       // 8 - Send buffer
  void* m_cookie;        // 8 - Application state

  /*
   * Frame buffer.
   */

  FrameBuffer m_fb;

  /*
   * Next 4 cache lines: segments.
   *
   * Size is 16B per segment, 4 segments per cache line, for a maximum of 16
   * segments (segment index is 4 bits).
   */

  Segment m_segments[SEGMENT_COUNT] __attribute__((aligned(64)));

  /*
   * Friendship declaration.
   */

  friend class Processor;
  friend void Options::parse(system::Logger&, Connection&, const uint16_t,
                             const uint8_t* const);

} __attribute__((aligned(64)));

static_assert(sizeof(Connection) == (1 << SEGM_B) * sizeof(Segment) + 128,
              "Size of tcpv4::Connection is invalid");
}

namespace std {

template<>
struct hash<tulips::stack::tcpv4::Connection>
{
  uint64_t operator()(const tulips::stack::tcpv4::Connection& c) const
  {
    return uint64_t(c.localPort()) << 32 | uint64_t(c.remotePort());
  }
};

}
