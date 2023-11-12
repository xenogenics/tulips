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
  Client(std::string_view fn) : m_out(), m_connected(false), m_delayedack(false)
  {
    auto path = std::filesystem::path(fn);
    m_out.open(path);
  }

  ~Client() override { m_out.close(); }

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

  void setDelayedAck() { m_delayedack = true; }

private:
  std::ofstream m_out;
  bool m_connected;
  bool m_delayedack;
};

class Server : public tcpv4::EventHandler
{
public:
  Server(std::string_view fn, const bool response = false)
    : m_out()
    , m_response(response)
    , m_connected(false)
    , m_cid(-1)
    , m_rlen(0)
    , m_close(false)
    , m_abort(false)
    , m_delayedack(false)
  {
    auto path = std::filesystem::path(fn);
    m_out.open(path);
  }

  ~Server() override { m_out.close(); }

  void onConnected(tcpv4::Connection& c, UNUSED const Timestamp ts) override
  {
    m_out << "onConnected:" << std::endl;
    if (m_response || m_delayedack) {
      c.setOptions(tcpv4::Connection::DELAYED_ACK);
    }
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

  Action onNewData(UNUSED tcpv4::Connection& c, const uint8_t* const data,
                   const uint32_t len, UNUSED const Timestamp ts,
                   UNUSED const uint32_t alen, uint8_t* const sdata,
                   uint32_t& slen) override
  {
    Action action = m_abort   ? Action::Abort
                    : m_close ? Action::Close
                              : Action::Continue;
    m_rlen = len;
    if (m_response) {
      memcpy(sdata, data, len);
      slen = len;
    }
    m_out << "onNewData:" << len << " slen:" << slen << std::endl;
    m_close = false;
    m_abort = false;
    return action;
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

  void enableResponse(const bool enb) { m_response = enb; }

  void closeUponNewData() { m_close = true; }

  void abortUponNewData() { m_abort = true; }

  void setDelayedAck() { m_delayedack = true; }

private:
  std::ofstream m_out;
  bool m_response;
  bool m_connected;
  tcpv4::Connection::ID m_cid;
  uint32_t m_rlen;
  bool m_close;
  bool m_abort;
  bool m_delayedack;
};

} // namespace

class TCP_Transmit : public ::testing::Test
{
public:
  TCP_Transmit()
    : m_log(system::Logger::Level::Trace)
    , m_clst()
    , m_slst()
    , m_cadr(0x10, 0x0, 0x0, 0x0, 0x10, 0x10)
    , m_sadr(0x10, 0x0, 0x0, 0x0, 0x20, 0x20)
    , m_bcast(10, 1, 0, 254)
    , m_nmask(255, 255, 255, 0)
    , m_cli_ip4(10, 1, 0, 1)
    , m_srv_ip4(10, 1, 0, 2)
    , m_cdev(nullptr)
    , m_sdev(nullptr)
    , m_cli_evt(nullptr)
    , m_cli_ip4_prod(nullptr)
    , m_cli_ip4_proc(nullptr)
    , m_cli_tcp(nullptr)
    , m_cli_eth_prod(nullptr)
    , m_cli_eth_proc(nullptr)
    , m_srv_evt(nullptr)
    , m_srv_ip4_prod(nullptr)
    , m_srv_ip4_proc(nullptr)
    , m_srv_tcp(nullptr)
    , m_srv_eth_prod(nullptr)
    , m_srv_eth_proc(nullptr)
  {}

protected:
  void SetUp() override
  {
    std::string tname(
      ::testing::UnitTest::GetInstance()->current_test_info()->name());
    /*
     * Build the devices.
     */
    auto clst = list::Device::allocate(m_log, m_cadr, 128, m_slst, m_clst);
    auto slst = list::Device::allocate(m_log, m_sadr, 128, m_clst, m_slst);
    /*
     * Build the pcap device
     */
    std::string cli_n = "tcp_transmit.client." + tname;
    std::string srv_n = "tcp_transmit.server." + tname;
    m_cdev = transport::pcap::Device::allocate(m_log, std::move(clst), cli_n);
    m_sdev = transport::pcap::Device::allocate(m_log, std::move(slst), srv_n);
    /*
     * Client stack
     */
    m_cli_evt = new Client(cli_n + ".log");
    m_cli_eth_prod = new ethernet::Producer(m_log, *m_cdev, m_cdev->address());
    m_cli_ip4_prod = new ipv4::Producer(m_log, *m_cli_eth_prod, m_cli_ip4);
    m_cli_eth_proc = new ethernet::Processor(m_log, m_cdev->address());
    m_cli_ip4_proc = new ipv4::Processor(m_log, m_cli_ip4);
    m_cli_tcp = new tcpv4::Processor(m_log, *m_cdev, *m_cli_eth_prod,
                                     *m_cli_ip4_prod, *m_cli_evt, 1);
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
    m_srv_evt = new Server(srv_n + ".log");
    m_srv_eth_prod = new ethernet::Producer(m_log, *m_sdev, m_sdev->address());
    m_srv_ip4_prod = new ipv4::Producer(m_log, *m_srv_eth_prod, m_srv_ip4);
    m_srv_eth_proc = new ethernet::Processor(m_log, m_sdev->address());
    m_srv_ip4_proc = new ipv4::Processor(m_log, m_srv_ip4);
    m_srv_tcp = new tcpv4::Processor(m_log, *m_sdev, *m_srv_eth_prod,
                                     *m_srv_ip4_prod, *m_srv_evt, 1);
    /*
     * Server processor binding
     */
    (*m_srv_tcp)
      .setEthernetProcessor(*m_srv_eth_proc)
      .setIPv4Processor(*m_srv_ip4_proc);
    (*m_srv_ip4_prod).setDefaultRouterAddress(m_bcast).setNetMask(m_nmask);
    (*m_srv_ip4_proc)
      .setEthernetProcessor(*m_srv_eth_proc)
      .setTCPv4Processor(*m_srv_tcp);
    (*m_srv_eth_proc).setIPv4Processor(*m_srv_ip4_proc);
    /*
     * TCP server listens
     */
    m_srv_tcp->listen(1234);
  }

  void TearDown() override
  {
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
    delete m_srv_evt;
    delete m_srv_ip4_proc;
    delete m_srv_ip4_prod;
    delete m_srv_tcp;
    delete m_srv_eth_proc;
    delete m_srv_eth_prod;
  }

  system::ConsoleLogger m_log;
  list::Device::List m_clst;
  list::Device::List m_slst;
  ethernet::Address m_cadr;
  ethernet::Address m_sadr;
  ipv4::Address m_bcast;
  ipv4::Address m_nmask;
  ipv4::Address m_cli_ip4;
  ipv4::Address m_srv_ip4;
  transport::pcap::Device::Ref m_cdev;
  transport::pcap::Device::Ref m_sdev;
  Client* m_cli_evt;
  ipv4::Producer* m_cli_ip4_prod;
  ipv4::Processor* m_cli_ip4_proc;
  tcpv4::Processor* m_cli_tcp;
  ethernet::Producer* m_cli_eth_prod;
  ethernet::Processor* m_cli_eth_proc;
  Server* m_srv_evt;
  ipv4::Producer* m_srv_ip4_prod;
  ipv4::Processor* m_srv_ip4_proc;
  tcpv4::Processor* m_srv_tcp;
  ethernet::Producer* m_srv_eth_prod;
  ethernet::Processor* m_srv_eth_proc;
};

TEST_F(TCP_Transmit, ConnectSend)
{
  tcpv4::Connection::ID c;
  /*
   * Server listens, client connects
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->open(c));
  ASSERT_EQ(Status::Ok, m_cli_tcp->connect(c, m_sadr, m_srv_ip4, 1234));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_TRUE(m_cli_evt->isConnected());
  ASSERT_TRUE(m_srv_evt->isConnected());
  /*
   * The client sends some data, #1
   */
  uint32_t res = 0;
  uint64_t pld = 0xdeadbeefULL;
  ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, 8, (uint8_t*)&pld, res));
  ASSERT_EQ(8, res);
  res = 0;
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  /*
   * The client sends some data, #2
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, 8, (uint8_t*)&pld, res));
  ASSERT_EQ(8, res);
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  /*
   * Abort the connection and clean-up.
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->abort(c));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_srv_eth_proc));
}

TEST_F(TCP_Transmit, ConnectSendWithResponse)
{
  tcpv4::Connection::ID c;
  /*
   * Enable response in the server.
   */
  m_srv_evt->enableResponse(true);
  /*
   * Server listens, client connects
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->open(c));
  ASSERT_EQ(Status::Ok, m_cli_tcp->connect(c, m_sadr, m_srv_ip4, 1234));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_TRUE(m_cli_evt->isConnected());
  ASSERT_TRUE(m_srv_evt->isConnected());
  /*
   * The client sends some data, #1
   */
  uint32_t res = 0;
  uint64_t pld = 0xdeadbeefULL;
  ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, 8, (uint8_t*)&pld, res));
  ASSERT_EQ(8, res);
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  /*
   * The client sends some data, #2
   */
  res = 0;
  ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, 8, (uint8_t*)&pld, res));
  ASSERT_EQ(8, res);
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  /*
   * Abort the connection and clean-up.
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->abort(c));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_srv_eth_proc));
}

TEST_F(TCP_Transmit, ConnectSendDisconnectFromClient)
{
  tcpv4::Connection::ID c;
  /*
   * Server listens, client connects
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->open(c));
  ASSERT_EQ(Status::Ok, m_cli_tcp->connect(c, m_sadr, m_srv_ip4, 1234));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_TRUE(m_cli_evt->isConnected());
  ASSERT_TRUE(m_srv_evt->isConnected());
  /*
   * The client sends some data, #1
   */
  uint32_t res = 0;
  uint64_t pld = 0xdeadbeefULL;
  ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, 8, (uint8_t*)&pld, res));
  ASSERT_EQ(8, res);
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  /*
   * The client sends some data, #2
   */
  res = 0;
  ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, 8, (uint8_t*)&pld, res));
  ASSERT_EQ(8, res);
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  /*
   * Client disconnects, server closes
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->close(c));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  /*
   * Advance the timers because of TIME WAIT.
   */
  for (int i = 0; i < 120; i += 1) {
    system::Clock::get().offsetBy(system::Clock::SECOND);
    ASSERT_EQ(Status::Ok, m_cli_eth_proc->run());
    ASSERT_EQ(Status::Ok, m_srv_eth_proc->run());
  }
  /*
   * Client closed.
   */
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_srv_eth_proc));
}

TEST_F(TCP_Transmit, ConnectSendDisconnectFromServer)
{
  tcpv4::Connection::ID c;
  /*
   * Server listens, client connects
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->open(c));
  ASSERT_EQ(Status::Ok, m_cli_tcp->connect(c, m_sadr, m_srv_ip4, 1234));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_TRUE(m_cli_evt->isConnected());
  ASSERT_TRUE(m_srv_evt->isConnected());
  /*
   * The client sends some data, #1
   */
  uint32_t res = 0;
  uint64_t pld = 0xdeadbeefULL;
  ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, 8, (uint8_t*)&pld, res));
  ASSERT_EQ(8, res);
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  /*
   * The client sends some data, #2
   */
  m_srv_evt->closeUponNewData();
  res = 0;
  ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, 8, (uint8_t*)&pld, res));
  ASSERT_EQ(8, res);
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_cli_eth_proc));
  /*
   * Client disconnects, server closes
   */
  ASSERT_EQ(Status::NotConnected, m_cli_tcp->close(c));
  /*
   * Advance the timers because of TIME WAIT.
   */
  for (int i = 0; i < 120; i += 1) {
    system::Clock::get().offsetBy(system::Clock::SECOND);
    ASSERT_EQ(Status::Ok, m_cli_eth_proc->run());
    ASSERT_EQ(Status::Ok, m_srv_eth_proc->run());
  }
  /*
   * Client closed.
   */
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_srv_eth_proc));
}

TEST_F(TCP_Transmit, ConnectSendDisconnectFromServerWithAckCombining)
{
  tcpv4::Connection::ID c;
  /*
   * Put the server in ACK combining mode.
   */
  m_cli_evt->setDelayedAck();
  m_srv_evt->setDelayedAck();
  /*
   * Server listens, client connects
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->open(c));
  ASSERT_EQ(Status::Ok, m_cli_tcp->connect(c, m_sadr, m_srv_ip4, 1234));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_TRUE(m_cli_evt->isConnected());
  ASSERT_TRUE(m_srv_evt->isConnected());
  /*
   * The client sends some data, #1
   */
  uint32_t res = 0;
  uint64_t pld = 0xdeadbeefULL;
  ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, 8, (uint8_t*)&pld, res));
  ASSERT_EQ(8, res);
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_cli_eth_proc));
  /*
   * Advance the timers because of ACK timer, #2.
   */
  for (int i = 0; i < tcpv4::ATO; i += 1) {
    system::Clock::get().offsetBy(system::Clock::MILLISECOND);
    ASSERT_EQ(Status::Ok, m_cli_eth_proc->run());
    ASSERT_EQ(Status::Ok, m_srv_eth_proc->run());
  }
  /*
   * Receive the ACK.
   */
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  /*
   * The client sends some data, #3
   */
  m_srv_evt->closeUponNewData();
  res = 0;
  ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, 8, (uint8_t*)&pld, res));
  ASSERT_EQ(8, res);
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_cli_eth_proc));
  /*
   * Client disconnects, server closes
   */
  ASSERT_EQ(Status::NotConnected, m_cli_tcp->close(c));
  /*
   * Advance the timers because of TIME WAIT.
   */
  for (int i = 0; i < 120; i += 1) {
    system::Clock::get().offsetBy(system::Clock::SECOND);
    ASSERT_EQ(Status::Ok, m_cli_eth_proc->run());
    ASSERT_EQ(Status::Ok, m_srv_eth_proc->run());
  }
  /*
   * Client closed.
   */
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_srv_eth_proc));
}

TEST_F(TCP_Transmit, ConnectSendAbortFromClient)
{
  tcpv4::Connection::ID c;
  /*
   * Server listens, client connects
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->open(c));
  ASSERT_EQ(Status::Ok, m_cli_tcp->connect(c, m_sadr, m_srv_ip4, 1234));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_TRUE(m_cli_evt->isConnected());
  ASSERT_TRUE(m_srv_evt->isConnected());
  /*
   * The client sends some data, #1
   */
  uint32_t res = 0;
  uint64_t pld = 0xdeadbeefULL;
  ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, 8, (uint8_t*)&pld, res));
  ASSERT_EQ(8, res);
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  /*
   * The client sends some data, #2
   */
  res = 0;
  ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, 8, (uint8_t*)&pld, res));
  ASSERT_EQ(8, res);
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  /*
   * Client aborts, server closes
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->abort(c));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_srv_eth_proc));
}

TEST_F(TCP_Transmit, ConnectSendAbortFromServer)
{
  tcpv4::Connection::ID c;
  /*
   * Server listens, client connects
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->open(c));
  ASSERT_EQ(Status::Ok, m_cli_tcp->connect(c, m_sadr, m_srv_ip4, 1234));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_TRUE(m_cli_evt->isConnected());
  ASSERT_TRUE(m_srv_evt->isConnected());
  /*
   * The client sends some data, #1
   */
  uint32_t res = 0;
  uint64_t pld = 0xdeadbeefULL;
  ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, 8, (uint8_t*)&pld, res));
  ASSERT_EQ(8, res);
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  /*
   * The client sends some data, #2
   */
  m_srv_evt->abortUponNewData();
  res = 0;
  ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, 8, (uint8_t*)&pld, res));
  ASSERT_EQ(8, res);
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_cli_eth_proc));
  /*
   * Client aborts, server closes
   */
  ASSERT_EQ(Status::NotConnected, m_cli_tcp->close(c));
}

TEST_F(TCP_Transmit, ConnectSendAbortFromServerWithAckCombining)
{
  tcpv4::Connection::ID c;
  /*
   * Put the server in ACK combining mode.
   */
  m_cli_evt->setDelayedAck();
  m_srv_evt->setDelayedAck();
  /*
   * Server listens, client connects
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->open(c));
  ASSERT_EQ(Status::Ok, m_cli_tcp->connect(c, m_sadr, m_srv_ip4, 1234));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_TRUE(m_cli_evt->isConnected());
  ASSERT_TRUE(m_srv_evt->isConnected());
  /*
   * The client sends some data, #1
   */
  uint32_t res = 0;
  uint64_t pld = 0xdeadbeefULL;
  ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, 8, (uint8_t*)&pld, res));
  ASSERT_EQ(8, res);
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_cli_eth_proc));
  /*
   * Advance the timers because of ACK timer, #2.
   */
  for (int i = 0; i < tcpv4::ATO; i += 1) {
    system::Clock::get().offsetBy(system::Clock::MILLISECOND);
    ASSERT_EQ(Status::Ok, m_cli_eth_proc->run());
    ASSERT_EQ(Status::Ok, m_srv_eth_proc->run());
  }
  /*
   * Receive the ACK.
   */
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  /*
   * The client sends some data, #3
   */
  m_srv_evt->abortUponNewData();
  res = 0;
  ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, 8, (uint8_t*)&pld, res));
  ASSERT_EQ(8, res);
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_cli_eth_proc));
  /*
   * Client aborts, server closes
   */
  ASSERT_EQ(Status::NotConnected, m_cli_tcp->close(c));
}
