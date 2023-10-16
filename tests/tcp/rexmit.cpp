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

  Action onAcked(UNUSED tcpv4::Connection& c,
                 UNUSED const Timestamp ts) override
  {
    m_out << "onAcked:" << std::endl;
    return Action::Continue;
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
                   UNUSED const Timestamp ts) override
  {
    m_out << "onNewData: " << len << "B" << std::endl;
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

  ~Server() override { m_out.close(); }

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

  Action onAcked(UNUSED tcpv4::Connection& c,
                 UNUSED const Timestamp ts) override
  {
    m_out << "onAcked:" << std::endl;
    return Action::Continue;
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
                   UNUSED const Timestamp ts) override
  {
    m_out << "onNewData:" << std::endl;
    m_rlen = len;
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

private:
  std::ofstream m_out;
  bool m_connected;
  tcpv4::Connection::ID m_cid;
  uint32_t m_rlen;
};

} // namespace

class TCP_Rexmit : public ::testing::Test
{
public:
  TCP_Rexmit()
    : m_log(system::Logger::Level::Trace)
    , m_cli_fifo()
    , m_srv_fifo()
    , m_cli_adr(0x10, 0x0, 0x0, 0x0, 0x10, 0x10)
    , m_srv_adr(0x10, 0x0, 0x0, 0x0, 0x20, 0x20)
    , m_bcast(10, 1, 0, 254)
    , m_nmask(255, 255, 255, 0)
    , m_cli_ip4(10, 1, 0, 1)
    , m_srv_ip4(10, 1, 0, 2)
    , m_client(nullptr)
    , m_server(nullptr)
    , m_cli_pcap(nullptr)
    , m_srv_pcap(nullptr)
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
    m_client = new list::Device(m_log, m_cli_adr, 128, m_srv_fifo, m_cli_fifo);
    m_server = new list::Device(m_log, m_srv_adr, 128, m_cli_fifo, m_srv_fifo);
    /*
     * Build the pcap device
     */
    std::string cli_n = "tcp_rexmit.client." + tname;
    std::string srv_n = "tcp_rexmit.server." + tname;
    m_cli_pcap = new transport::pcap::Device(m_log, *m_client, cli_n);
    m_srv_pcap = new transport::pcap::Device(m_log, *m_server, srv_n);
    /*
     * Client stack
     */
    m_cli_evt = new Client(cli_n + ".log");
    m_cli_eth_prod =
      new ethernet::Producer(m_log, *m_cli_pcap, m_cli_pcap->address());
    m_cli_ip4_prod = new ipv4::Producer(m_log, *m_cli_eth_prod, m_cli_ip4);
    m_cli_eth_proc = new ethernet::Processor(m_log, m_cli_pcap->address());
    m_cli_ip4_proc = new ipv4::Processor(m_log, m_cli_ip4);
    m_cli_tcp = new tcpv4::Processor(m_log, *m_cli_pcap, *m_cli_eth_prod,
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
    m_srv_eth_prod =
      new ethernet::Producer(m_log, *m_srv_pcap, m_srv_pcap->address());
    m_srv_ip4_prod = new ipv4::Producer(m_log, *m_srv_eth_prod, m_srv_ip4);
    m_srv_eth_proc = new ethernet::Processor(m_log, m_srv_pcap->address());
    m_srv_ip4_proc = new ipv4::Processor(m_log, m_srv_ip4);
    m_srv_tcp = new tcpv4::Processor(m_log, *m_srv_pcap, *m_srv_eth_prod,
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
    /*
     * Delete the pcap wrappers;
     */
    delete m_cli_pcap;
    delete m_srv_pcap;
    /*
     * Delete client and server.
     */
    delete m_client;
    delete m_server;
  }

  system::ConsoleLogger m_log;
  list::Device::List m_cli_fifo;
  list::Device::List m_srv_fifo;
  ethernet::Address m_cli_adr;
  ethernet::Address m_srv_adr;
  ipv4::Address m_bcast;
  ipv4::Address m_nmask;
  ipv4::Address m_cli_ip4;
  ipv4::Address m_srv_ip4;
  list::Device* m_client;
  list::Device* m_server;
  transport::pcap::Device* m_cli_pcap;
  transport::pcap::Device* m_srv_pcap;
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

TEST_F(TCP_Rexmit, ConnectSynRetransmit)
{
  tcpv4::Connection::ID c;
  /*
   * Server listens, client connects
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->open(c));
  ASSERT_EQ(Status::Ok, m_cli_tcp->connect(c, m_srv_adr, m_srv_ip4, 1234));
  /*
   * Client retransmits after 3 seconds
   */
  system::Clock::get().offsetBy(system::Clock::SECOND);
  ASSERT_EQ(Status::Ok, m_cli_eth_proc->run());
  system::Clock::get().offsetBy(system::Clock::SECOND);
  ASSERT_EQ(Status::Ok, m_cli_eth_proc->run());
  system::Clock::get().offsetBy(system::Clock::SECOND);
  ASSERT_EQ(Status::Ok, m_cli_eth_proc->run());
  /*
   * Server drops the extra SYN and responds.
   */
  ASSERT_EQ(Status::Ok, m_server->drop());
  ASSERT_EQ(Status::Ok, m_srv_pcap->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cli_pcap->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::Ok, m_srv_pcap->poll(*m_srv_eth_proc));
  ASSERT_TRUE(m_cli_evt->isConnected());
  ASSERT_TRUE(m_srv_evt->isConnected());
  /*
   * Abort the connection and clean-up.
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->abort(c));
  ASSERT_EQ(Status::Ok, m_srv_pcap->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_cli_pcap->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_srv_pcap->poll(*m_srv_eth_proc));
}

TEST_F(TCP_Rexmit, ConnectSynAckRetransmit)
{
  tcpv4::Connection::ID c;
  /*
   * Server listens, client connects
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->open(c));
  ASSERT_EQ(Status::Ok, m_cli_tcp->connect(c, m_srv_adr, m_srv_ip4, 1234));
  /*
   * Server responds and restransmits after 3 seconds
   */
  ASSERT_EQ(Status::Ok, m_srv_pcap->poll(*m_srv_eth_proc));
  system::Clock::get().offsetBy(system::Clock::SECOND);
  ASSERT_EQ(Status::Ok, m_srv_eth_proc->run());
  system::Clock::get().offsetBy(system::Clock::SECOND);
  ASSERT_EQ(Status::Ok, m_srv_eth_proc->run());
  system::Clock::get().offsetBy(system::Clock::SECOND);
  ASSERT_EQ(Status::Ok, m_srv_eth_proc->run());
  /*
   * Client drops the extra SYNACK and responds.
   */
  ASSERT_EQ(Status::Ok, m_client->drop());
  ASSERT_EQ(Status::Ok, m_cli_pcap->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::Ok, m_srv_pcap->poll(*m_srv_eth_proc));
  ASSERT_TRUE(m_cli_evt->isConnected());
  ASSERT_TRUE(m_srv_evt->isConnected());
  /*
   * Abort the connection and clean-up.
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->abort(c));
  ASSERT_EQ(Status::Ok, m_srv_pcap->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_cli_pcap->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_srv_pcap->poll(*m_srv_eth_proc));
}

TEST_F(TCP_Rexmit, ConnectSendRetransmit)
{
  tcpv4::Connection::ID c;
  /*
   * Server listens, client connects
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->open(c));
  ASSERT_EQ(Status::Ok, m_cli_tcp->connect(c, m_srv_adr, m_srv_ip4, 1234));
  ASSERT_EQ(Status::Ok, m_srv_pcap->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cli_pcap->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::Ok, m_srv_pcap->poll(*m_srv_eth_proc));
  ASSERT_TRUE(m_cli_evt->isConnected());
  ASSERT_TRUE(m_srv_evt->isConnected());
  /*
   * The client sends some data, #1
   */
  uint32_t res = 0;
  uint64_t pld = 0xdeadbeefULL;
  ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, 8, (uint8_t*)&pld, res));
  ASSERT_EQ(8, res);
  /*
   * Client retransmits after 3 seconds.
   */
  system::Clock::get().offsetBy(system::Clock::SECOND);
  ASSERT_EQ(Status::Ok, m_cli_eth_proc->run());
  system::Clock::get().offsetBy(system::Clock::SECOND);
  ASSERT_EQ(Status::Ok, m_cli_eth_proc->run());
  system::Clock::get().offsetBy(system::Clock::SECOND);
  ASSERT_EQ(Status::Ok, m_cli_eth_proc->run());
  /*
   * Server drops the extra packet and responds.
   */
  ASSERT_EQ(Status::Ok, m_server->drop());
  ASSERT_EQ(Status::Ok, m_srv_pcap->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cli_pcap->poll(*m_cli_eth_proc));
  /*
   * Abort the connection and clean-up.
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->abort(c));
  ASSERT_EQ(Status::Ok, m_srv_pcap->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_cli_pcap->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_srv_pcap->poll(*m_srv_eth_proc));
}
