#include <tulips/stack/tcpv4/Connection.h>

namespace tulips::stack::tcpv4 {

Connection::Connection()
  : m_id(-1)
  , m_rethaddr()
  , m_ripaddr()
  , m_lport(0)
  , m_rport(0)
  , m_rcv_nxt(0)
  , m_snd_nxt(0)
  , m_state(CLOSED)
  , m_ackdata(false)
  , m_newdata(false)
  , m_pshdata(false)
  , m_live(false)
  , m_wndscl(0)
  , m_window(0)
  , m_segidx(0)
  , m_nrtx(0)
  , m_slen(0)
  , m_initialmss(0)
  , m_mss(0)
  , m_sa(0)
  , m_sv(0)
  , m_rto(0)
  , m_rtm(0)
  , m_wndlvl(0)
  , m_atm(0)
  , m_opts(0)
  , m_sdat(nullptr)
  , m_cookie(nullptr)
  , m_fb()
  , m_segments()
{}

}
