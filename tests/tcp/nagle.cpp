#include "tulips/stack/TCPv4.h"
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
                   UNUSED const uint8_t* const data, const uint32_t len,
                   UNUSED const Timestamp ts, UNUSED const uint32_t alen,
                   UNUSED uint8_t* const sdata, UNUSED uint32_t& slen) override
  {
    m_out << "onNewData: " << len << "B" << std::endl;
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

  Action onNewData(UNUSED tcpv4::Connection& c, const uint8_t* const data,
                   const uint32_t len, UNUSED const Timestamp ts,
                   const uint32_t alen, uint8_t* const sdata,
                   uint32_t& slen) override
  {
    m_out << "onNewData:" << std::endl;
    if (data[1] == 0xAA) {
      uint8_t result[35] = { 0xFF, 0xBB };
      assert(alen >= 35);
      memcpy(sdata, result, 35);
      slen = 35;
    }
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

class TCP_Nagle : public ::testing::Test
{
public:
  TCP_Nagle()
    : m_logger(system::Logger::Level::Trace)
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
     * Build the devices. NOTE(xrg): the mss size below is very important to
     * make the tests work.
     */
    m_client = new list::Device(m_logger, m_cli_adr, m_cli_ip4, m_bcast,
                                m_nmask, 124, m_srv_fifo, m_cli_fifo);
    m_server = new list::Device(m_logger, m_srv_adr, m_srv_ip4, m_bcast,
                                m_nmask, 124, m_cli_fifo, m_srv_fifo);
    /*
     * Build the pcap device
     */
    std::string cli_n = "tcp_nagle.client." + tname;
    std::string srv_n = "tcp_nagle.server." + tname;
    m_cli_pcap = new transport::pcap::Device(m_logger, *m_client, cli_n);
    m_srv_pcap = new transport::pcap::Device(m_logger, *m_server, srv_n);
    /*
     * Client stack
     */
    m_cli_evt = new Client(cli_n + ".log");
    m_cli_eth_prod =
      new ethernet::Producer(m_logger, *m_cli_pcap, m_cli_pcap->address());
    m_cli_ip4_prod = new ipv4::Producer(m_logger, *m_cli_eth_prod, m_cli_ip4);
    m_cli_eth_proc = new ethernet::Processor(m_logger, m_cli_pcap->address());
    m_cli_ip4_proc = new ipv4::Processor(m_logger, m_cli_ip4);
    m_cli_tcp = new tcpv4::Processor(m_logger, *m_cli_pcap, *m_cli_eth_prod,
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
      new ethernet::Producer(m_logger, *m_srv_pcap, m_srv_pcap->address());
    m_srv_ip4_prod = new ipv4::Producer(m_logger, *m_srv_eth_prod, m_srv_ip4);
    m_srv_eth_proc = new ethernet::Processor(m_logger, m_srv_pcap->address());
    m_srv_ip4_proc = new ipv4::Processor(m_logger, m_srv_ip4);
    m_srv_tcp = new tcpv4::Processor(m_logger, *m_srv_pcap, *m_srv_eth_prod,
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

  system::ConsoleLogger m_logger;
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

TEST_F(TCP_Nagle, ConnectSendNagle)
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
  ASSERT_EQ(Status::Ok, m_srv_pcap->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cli_pcap->poll(*m_cli_eth_proc));
  ASSERT_EQ(8, m_srv_evt->receivedLength());
  /*
   * The client sends some data, #2
   */
  res = 0;
  ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, 8, (uint8_t*)&pld, res));
  ASSERT_EQ(8, res);
  res = 0;
  ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, 8, (uint8_t*)&pld, res));
  ASSERT_EQ(8, res);
  res = 0;
  ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, 8, (uint8_t*)&pld, res));
  ASSERT_EQ(8, res);
  ASSERT_EQ(Status::Ok, m_srv_pcap->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cli_pcap->poll(*m_cli_eth_proc));
  ASSERT_EQ(8, m_srv_evt->receivedLength());
  ASSERT_EQ(Status::Ok, m_srv_pcap->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cli_pcap->poll(*m_cli_eth_proc));
  ASSERT_EQ(16, m_srv_evt->receivedLength());
  /*
   * Abort the connection and clean-up.
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->abort(c));
  ASSERT_EQ(Status::Ok, m_srv_pcap->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_cli_pcap->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_srv_pcap->poll(*m_srv_eth_proc));
}

TEST_F(TCP_Nagle, ConnectSendConsecutiveNagle)
{
  tcpv4::Connection::ID c;
  const size_t PKTLEN = 35;
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
  uint8_t pld[PKTLEN] = { 0xFF };
  ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, PKTLEN, pld, res));
  ASSERT_EQ(PKTLEN, res);
  ASSERT_EQ(Status::Ok, m_srv_pcap->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cli_pcap->poll(*m_cli_eth_proc));
  ASSERT_EQ(PKTLEN, m_srv_evt->receivedLength());
  /*
   * The client sends some more data. This segment will be in-flight, activating
   * Nagle's algorigthm.
   */
  res = 0;
  ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, PKTLEN, (uint8_t*)&pld, res));
  ASSERT_EQ(PKTLEN, res);
  /*
   * Fill all segments.
   */
  for (int i = 0; i < 1 << SEGM_B; i += 1) {
    res = 0;
    pld[1] = 2 * i;
    ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, PKTLEN, (uint8_t*)&pld, res));
    ASSERT_EQ(PKTLEN, res);
    res = 0;
    pld[1] = 2 * i + 1;
    ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, PKTLEN, (uint8_t*)&pld, res));
    ASSERT_EQ(PKTLEN, res);
  }
  /*
   * No more segment to allow sending data.
   */
  res = 0;
  ASSERT_EQ(m_cli_tcp->send(c, PKTLEN, (uint8_t*)&pld, res),
            Status::OperationInProgress);
  /*
   * Receive the first payload.
   */
  ASSERT_EQ(Status::Ok, m_srv_pcap->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cli_pcap->poll(*m_cli_eth_proc));
  ASSERT_EQ(PKTLEN, m_srv_evt->receivedLength());
  /*
   * Receive the combined payloads.
   */
  for (int i = 0; i < 1 << SEGM_B; i += 1) {
    ASSERT_EQ(Status::Ok, m_srv_pcap->poll(*m_srv_eth_proc));
    ASSERT_EQ(Status::Ok, m_cli_pcap->poll(*m_cli_eth_proc));
    ASSERT_EQ(2 * PKTLEN, m_srv_evt->receivedLength());
  }
  /*
   * Abort the connection and clean-up.
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->abort(c));
  ASSERT_EQ(Status::Ok, m_srv_pcap->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_cli_pcap->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_srv_pcap->poll(*m_srv_eth_proc));
}

TEST_F(TCP_Nagle, ConnectSendNagleRecvThenAck)
{
  tcpv4::Connection::ID c;
  const size_t PKTLEN = 35;
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
   * Set delayed ACK on the server connection.
   */
  m_srv_tcp->setOptions(m_srv_evt->connectionID(),
                        tulips::stack::tcpv4::Connection::Option::DELAYED_ACK);
  /*
   * The client sends some data, #1.
   */
  uint32_t res = 0;
  uint8_t pld[PKTLEN] = { 0xFF, 0xAA };
  ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, PKTLEN, pld, res));
  ASSERT_EQ(PKTLEN, res);
  /*
   * The client sends some more data with the first segment in-flight.
   */
  res = 0;
  pld[1] = 0x2;
  ASSERT_EQ(Status::Ok, m_cli_tcp->send(c, PKTLEN, (uint8_t*)&pld, res));
  ASSERT_EQ(PKTLEN, res);
  /*
   * Receive the client payload and send back a response from the server.
   */
  ASSERT_EQ(Status::Ok, m_srv_pcap->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::Ok, m_cli_pcap->poll(*m_cli_eth_proc));
  ASSERT_EQ(PKTLEN, m_srv_evt->receivedLength());
  /*
   * Receive the server payload.
   */
  ASSERT_EQ(Status::Ok, m_srv_pcap->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_cli_pcap->poll(*m_cli_eth_proc));
  /*
   * Advance the timers because of ACK timer.
   */
  for (int i = 0; i < tcpv4::ATO; i += 1) {
    system::Clock::get().offsetBy(system::Clock::MILLISECOND);
    ASSERT_EQ(Status::Ok, m_cli_eth_proc->run());
    ASSERT_EQ(Status::Ok, m_srv_eth_proc->run());
  }
  /*
   * Receive the ACK.
   */
  ASSERT_EQ(Status::Ok, m_cli_pcap->poll(*m_cli_eth_proc));
  /*
   * Advance the timers again for good measure.
   */
  for (int i = 0; i < 4; i += 1) {
    system::Clock::get().offsetBy(system::Clock::MILLISECOND);
    ASSERT_EQ(Status::Ok, m_cli_eth_proc->run());
    ASSERT_EQ(Status::Ok, m_srv_eth_proc->run());
  }
  /*
   * Make sure nothing happened.
   */
  ASSERT_EQ(Status::NoDataAvailable, m_cli_pcap->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_srv_pcap->poll(*m_srv_eth_proc));
  /*
   * Abort the connection and clean-up.
   */
  ASSERT_EQ(Status::Ok, m_cli_tcp->abort(c));
  ASSERT_EQ(Status::Ok, m_srv_pcap->poll(*m_srv_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_cli_pcap->poll(*m_cli_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, m_srv_pcap->poll(*m_srv_eth_proc));
}
