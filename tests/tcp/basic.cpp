#include <tulips/stack/ethernet/Processor.h>
#include <tulips/stack/ethernet/Producer.h>
#include <tulips/stack/ipv4/Processor.h>
#include <tulips/stack/ipv4/Producer.h>
#include <tulips/stack/tcpv4/Processor.h>
#include <tulips/system/Compiler.h>
#include <tulips/system/Logger.h>
#include <tulips/transport/Processor.h>
#include <tulips/transport/list/Device.h>
#include <tulips/transport/pcap/Device.h>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>

using namespace tulips;
using namespace stack;
using namespace transport;

namespace {

class Client : public tcpv4::EventHandler
{
public:
  Client(std::string_view fn) : m_out(), m_connected(false)
  {
    auto path = std::filesystem::path(fn);
    m_out.open(path);
  }

  ~Client() override { m_out.close(); } // NOLINT(bugprone-exception-escape)

  void onConnected(UNUSED tcpv4::Connection& c,
                   UNUSED const Timestamp ts) override
  {
    m_out << "onConnected:" << std::endl;
    m_connected = true;
  }

  void onAborted(UNUSED tcpv4::Connection& c,
                 UNUSED const Timestamp ts) override
  {
    m_out << "onAborted:" << std::endl;
    m_connected = false;
  }

  void onTimedOut(UNUSED tcpv4::Connection& c,
                  UNUSED const Timestamp ts) override
  {
    m_out << "onTimedOut:" << std::endl;
  }

  void onSent(UNUSED tcpv4::Connection& c, UNUSED const Timestamp ts) override
  {
    m_out << "onSent:" << std::endl;
  }

  Action onAcked(UNUSED tcpv4::Connection& c, UNUSED const Timestamp ts,
                 UNUSED const uint32_t alen, UNUSED uint8_t* const sdata,
                 UNUSED uint32_t& slen) override
  {
    m_out << "onAcked:" << std::endl;
    return Action::Continue;
  }

  Action onNewData(UNUSED tcpv4::Connection& c,
                   UNUSED const uint8_t* const data, UNUSED const uint32_t len,
                   UNUSED const Timestamp ts, UNUSED const uint32_t alen,
                   UNUSED uint8_t* const sdata, UNUSED uint32_t& slen) override
  {
    m_out << "onNewData:" << std::endl;
    return Action::Continue;
  }

  void onClosed(UNUSED tcpv4::Connection& c, UNUSED const Timestamp ts) override
  {
    m_out << "onClosed:" << std::endl;
    m_connected = false;
  }

  bool isConnected() const { return m_connected; }

private:
  std::ofstream m_out;
  bool m_connected;
};

class Server : public tcpv4::EventHandler
{
public:
  Server(std::string_view fn)
    : m_out(), m_connected(false), m_cid(-1), m_rlen(0)
  {
    auto path = std::filesystem::path(fn);
    m_out.open(path);
  }

  ~Server() override { m_out.close(); } // NOLINT(bugprone-exception-escape)

  void onConnected(tcpv4::Connection& c, UNUSED const Timestamp ts) override
  {
    m_out << "onConnected:" << std::endl;
    m_connected = true;
    m_cid = c.id();
  }

  void onAborted(UNUSED tcpv4::Connection& c,
                 UNUSED const Timestamp ts) override
  {
    m_out << "onAborted:" << std::endl;
    m_connected = false;
    m_cid = -1;
  }

  void onTimedOut(UNUSED tcpv4::Connection& c,
                  UNUSED const Timestamp ts) override
  {
    m_out << "onTimedOut:" << std::endl;
  }

  void onSent(UNUSED tcpv4::Connection& c, UNUSED const Timestamp ts) override
  {
    m_out << "onSent:" << std::endl;
  }

  Action onAcked(UNUSED tcpv4::Connection& c, UNUSED const Timestamp ts,
                 UNUSED const uint32_t alen, UNUSED uint8_t* const sdata,
                 UNUSED uint32_t& slen) override
  {
    m_out << "onAcked:" << std::endl;
    return Action::Continue;
  }

  Action onNewData(UNUSED tcpv4::Connection& c,
                   UNUSED const uint8_t* const data, const uint32_t len,
                   UNUSED const Timestamp ts, UNUSED const uint32_t alen,
                   UNUSED uint8_t* const sdata, UNUSED uint32_t& slen) override
  {
    m_out << "onNewData:" << std::endl;
    m_rlen = len;
    return Action::Continue;
  }

  void onClosed(UNUSED tcpv4::Connection& c, UNUSED const Timestamp ts) override
  {
    m_out << "onClosed:" << std::endl;
    m_connected = false;
    m_cid = -1;
  }

  bool isConnected() const { return m_connected; }

  tcpv4::Connection::ID connectionID() const { return m_cid; }

  uint32_t receivedLength() const { return m_rlen; }

private:
  std::ofstream m_out;
  bool m_connected;
  tcpv4::Connection::ID m_cid;
  uint32_t m_rlen;
};

} // namespace

class TCP_Basic : public ::testing::Test
{
public:
  TCP_Basic()
    : m_log(system::Logger::Level::Trace)
    , m_clst()
    , m_slst()
    , m_cadr(0x10, 0x0, 0x0, 0x0, 0x10, 0x10)
    , m_sadr(0x10, 0x0, 0x0, 0x0, 0x20, 0x20)
    , m_bcast(10, 1, 0, 254)
    , m_nmask(255, 255, 255, 0)
    , m_cip4(10, 1, 0, 1)
    , m_sip4(10, 1, 0, 2)
    , m_cdev(nullptr)
    , m_sdev(nullptr)
    , m_cli_evt(nullptr)
    , m_cli_ip4_prod(nullptr)
    , m_cli_ip4_proc(nullptr)
    , m_cli_tcp(nullptr)
    , m_cli_eth_prod(nullptr)
    , m_cli_eth_proc(nullptr)
    , m_src_evt(nullptr)
    , m_src_ip4_prod(nullptr)
    , m_src_ip4_proc(nullptr)
    , m_src_tcp(nullptr)
    , m_src_eth_prod(nullptr)
    , m_src_eth_proc(nullptr)
  {}

protected:
  void SetUp() override
  {
    std::string tname(
      ::testing::UnitTest::GetInstance()->current_test_info()->name());
    /* * Build the devices.
     */
    auto clst = list::Device::allocate(m_log, m_cadr, 128, m_slst, m_clst);
    auto slst = list::Device::allocate(m_log, m_sadr, 128, m_clst, m_slst);
    /*
     * Build the pcap device
     */
    std::string cli_n = "tcp_basic.client." + tname;
    std::string src_n = "tcp_basic.server." + tname;
    m_cdev = transport::pcap::Device::allocate(m_log, std::move(clst), cli_n);
    m_sdev = transport::pcap::Device::allocate(m_log, std::move(slst), src_n);
    /*
     * Client stack
     */
    m_cli_evt = new Client(cli_n + ".log");
    m_cli_eth_prod = new ethernet::Producer(m_log, *m_cdev, m_cdev->address());
    m_cli_ip4_prod = new ipv4::Producer(m_log, *m_cli_eth_prod, m_cip4);
    m_cli_eth_proc = new ethernet::Processor(m_log, m_cdev->address());
    m_cli_ip4_proc = new ipv4::Processor(m_log, m_cip4);
    m_cli_tcp = new tcpv4::Processor(m_log, *m_cdev, *m_cli_eth_prod,
                                     *m_cli_ip4_prod, *m_cli_evt);
    /*
     * Client processor binding
     */
    (*m_cli_tcp)
      .setEthernetProcessor(*m_cli_eth_proc)
      .setIPv4Processor(*m_cli_ip4_proc);
    (*m_cli_ip4_prod).setDefaultRouterAddress(m_bcast).setNetMask(m_nmask);
    (*m_cli_ip4_proc)
      .setEthernetProcessor(*m_cli_eth_proc)
      .setTCPv4Processor(*m_cli_tcp);
    (*m_cli_eth_proc).setIPv4Processor(*m_cli_ip4_proc);
    /*
     * Server stack
     */
    m_src_evt = new Server(src_n + ".log");
    m_src_eth_prod = new ethernet::Producer(m_log, *m_sdev, m_sdev->address());
    m_src_ip4_prod = new ipv4::Producer(m_log, *m_src_eth_prod, m_sip4);
    m_src_eth_proc = new ethernet::Processor(m_log, m_sdev->address());
    m_src_ip4_proc = new ipv4::Processor(m_log, m_sip4);
    m_src_tcp = new tcpv4::Processor(m_log, *m_sdev, *m_src_eth_prod,
                                     *m_src_ip4_prod, *m_src_evt);
    /*
     * Server processor binding
     */
    (*m_src_tcp)
      .setEthernetProcessor(*m_src_eth_proc)
      .setIPv4Processor(*m_src_ip4_proc);
    (*m_src_ip4_prod).setDefaultRouterAddress(m_bcast).setNetMask(m_nmask);
    (*m_src_ip4_proc)
      .setEthernetProcessor(*m_src_eth_proc)
      .setTCPv4Processor(*m_src_tcp);
    (*m_src_eth_proc).setIPv4Processor(*m_src_ip4_proc);
    /*
     * TCP server listens
     */
    m_src_tcp->listen(1234);
  }

  void TearDown() override
  {
    /*
     * Reset the clock offset.
     */
    system::Clock::get().resetOffset();
    /*
     * Delete client stack.
     */
    delete m_cli_evt;
    delete m_cli_ip4_proc;
    delete m_cli_ip4_prod;
    delete m_cli_tcp;
    delete m_cli_eth_proc;
    delete m_cli_eth_prod;
    /*
     * Delete server stack.
     */
    delete m_src_evt;
    delete m_src_ip4_proc;
    delete m_src_ip4_prod;
    delete m_src_tcp;
    delete m_src_eth_proc;
    delete m_src_eth_prod;
  }

  system::ConsoleLogger m_log;
  list::Device::List m_clst;
  list::Device::List m_slst;
  ethernet::Address m_cadr;
  ethernet::Address m_sadr;
  ipv4::Address m_bcast;
  ipv4::Address m_nmask;
  ipv4::Address m_cip4;
  ipv4::Address m_sip4;
  transport::pcap::Device::Ref m_cdev;
  transport::pcap::Device::Ref m_sdev;
  Client* m_cli_evt;
  ipv4::Producer* m_cli_ip4_prod;
  ipv4::Processor* m_cli_ip4_proc;
  tcpv4::Processor* m_cli_tcp;
  ethernet::Producer* m_cli_eth_prod;
  ethernet::Processor* m_cli_eth_proc;
  Server* m_src_evt;
  ipv4::Producer* m_src_ip4_prod;
  ipv4::Processor* m_src_ip4_proc;
  tcpv4::Processor* m_src_tcp;
  ethernet::Producer* m_src_eth_prod;
  ethernet::Processor* m_src_eth_proc;
};

TEST_F(TCP_Basic, Connect)
{
  tcpv4::Connection::ID c;
  /*
   * Server listens, client connects
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->open(c));
  // Client sends SYN -- TCPv4.cpp:149
  ASSERT_EQ(Status::Ok, m_cli_tcp->connect(c, m_sadr, m_sip4, 1234));
  // Server responds with SYN/ACK -- TCPv4.cpp:437
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_src_eth_proc));
  // Client responds with ACK -- TCPv4.cpp:584
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  // Server acknowledge the connection -- TCPv4.cpp:560
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_src_eth_proc));
  // Both end points are connected
  ASSERT_TRUE(m_cli_evt->isConnected());
  ASSERT_TRUE(m_src_evt->isConnected());
  /*
   * Abort the connection and clean-up.
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->abort(c));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_src_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_src_eth_proc));
}

TEST_F(TCP_Basic, ConnectDisconnectFromClient)
{
  tcpv4::Connection::ID c;
  /*
   * Server listens, client connects
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->open(c));
  ASSERT_EQ(Status::Ok, m_cli_tcp->connect(c, m_sadr, m_sip4, 1234));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_src_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_src_eth_proc));
  ASSERT_TRUE(m_cli_evt->isConnected());
  ASSERT_TRUE(m_src_evt->isConnected());
  /*
   * Client disconnects, server closes
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->close(c));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_src_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_src_eth_proc));
  ASSERT_FALSE(m_cli_evt->isConnected());
  ASSERT_FALSE(m_src_evt->isConnected());
  /*
   * Abort the connection and clean-up.
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->abort(c));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_src_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_src_eth_proc));
}

TEST_F(TCP_Basic, ConnectDisconnectFromServer)
{
  tcpv4::Connection::ID c;
  /*
   * Server listens, client connects
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->open(c));
  ASSERT_EQ(Status::Ok, m_cli_tcp->connect(c, m_sadr, m_sip4, 1234));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_src_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_src_eth_proc));
  ASSERT_TRUE(m_cli_evt->isConnected());
  ASSERT_TRUE(m_src_evt->isConnected());
  /*
   * Client disconnects, server closes
   */
  ASSERT_EQ(Status::Ok, m_src_tcp->close(m_src_evt->connectionID()));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_src_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::NotConnected, m_cli_tcp->close(c));
  ASSERT_FALSE(m_cli_evt->isConnected());
  ASSERT_FALSE(m_src_evt->isConnected());
  /*
   * Advance the timers because of TIME WAIT.
   */
  for (int i = 0; i < 120; i += 1) {
    system::Clock::get().offsetBy(system::Clock::SECOND);
    ASSERT_EQ(Status::Ok, m_cli_eth_proc->run());
    ASSERT_EQ(Status::Ok, m_src_eth_proc->run());
  }
  /*
   * Abort the connection and clean-up.
   */
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_src_eth_proc));
}
