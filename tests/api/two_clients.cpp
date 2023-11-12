#include <tulips/api/Client.h>
#include <tulips/api/Defaults.h>
#include <tulips/api/Server.h>
#include <tulips/system/Compiler.h>
#include <tulips/system/Logger.h>
#include <tulips/transport/Processor.h>
#include <tulips/transport/list/Device.h>
#include <tulips/transport/pcap/Device.h>
#include <gtest/gtest.h>

using namespace tulips;
using namespace stack;

namespace {

class ClientDelegate : public api::defaults::ClientDelegate
{
public:
  ClientDelegate() : m_data_received(false) {}

  tulips::Action onNewData(UNUSED api::Client::ID const& id,
                           UNUSED void* const cookie,
                           UNUSED const uint8_t* const data,
                           UNUSED const uint32_t len, UNUSED const Timestamp ts,
                           UNUSED const uint32_t alen,
                           UNUSED uint8_t* const sdata,
                           UNUSED uint32_t& slen) override
  {
    m_data_received = true;
    return tulips::Action::Continue;
  }

  bool dataReceived() const { return m_data_received; }

private:
  bool m_data_received;
};

class ServerDelegate : public api::defaults::ServerDelegate
{
public:
  using Connections = std::list<tulips::api::Server::ID>;

  ServerDelegate() : m_connections(), m_send_back(false) {}

  void* onConnected(api::Server::ID const& id, UNUSED void* const cookie,
                    UNUSED const Timestamp ts) override
  {
    m_connections.push_back(id);
    return nullptr;
  }

  Action onNewData(UNUSED api::Server::ID const& id, UNUSED void* const cookie,
                   const uint8_t* const data, const uint32_t len,
                   UNUSED const Timestamp ts, const uint32_t alen,
                   uint8_t* const sdata, uint32_t& slen) override
  {
    if (m_send_back && alen >= len) {
      memcpy(sdata, data, len);
      slen = len;
    }
    return Action::Continue;
  }

  void onClosed(tulips::api::Server::ID const& id, UNUSED void* const cookie,
                UNUSED const Timestamp ts) override
  {
    m_connections.remove(id);
  }

  Connections const& connections() const { return m_connections; }

  void doSendBack(const bool v) { m_send_back = v; }

private:
  Connections m_connections;
  bool m_send_back;
};

}

class API_TwoClients : public ::testing::Test
{
public:
  API_TwoClients()
    : m_log(system::Logger::Level::Trace)
    , m_clst()
    , m_slst()
    , m_cadr(0x10, 0x0, 0x0, 0x0, 0x10, 0x10)
    , m_sadr(0x10, 0x0, 0x0, 0x0, 0x20, 0x20)
    , m_cip4(10, 1, 0, 1)
    , m_sip4(10, 1, 0, 2)
    , m_cdev(nullptr)
    , m_sdev(nullptr)
    , m_c1dlg()
    , m_c2dlg()
    , m_client1(nullptr)
    , m_client2(nullptr)
    , m_sdlg()
    , m_server(nullptr)
  {}

protected:
  void SetUp() override
  {
    ipv4::Address route(10, 1, 0, 254);
    ipv4::Address nmask(255, 255, 255, 0);
    std::string tname(
      ::testing::UnitTest::GetInstance()->current_test_info()->name());
    /*
     * Build the devices.
     */
    auto clst =
      transport::list::Device::allocate(m_log, m_cadr, 1514, m_slst, m_clst);
    auto slst =
      transport::list::Device::allocate(m_log, m_sadr, 1514, m_clst, m_slst);
    /*
     * Build the pcap device
     */
    std::string pcap_client = "api_2clients.client." + tname;
    std::string pcap_server = "api_2clients.server." + tname;
    m_cdev =
      transport::pcap::Device::allocate(m_log, std::move(clst), pcap_client);
    m_sdev =
      transport::pcap::Device::allocate(m_log, std::move(slst), pcap_server);
    /*
     * Create the clients.
     */
    m_client1 =
      api::Client::allocate(m_log, m_c1dlg, *m_cdev, 1, m_cip4, route, nmask);
    m_client2 =
      api::Client::allocate(m_log, m_c2dlg, *m_cdev, 1, m_cip4, route, nmask);
    /*
     * Create the server.
     */
    m_server =
      api::Server::allocate(m_log, m_sdlg, *m_sdev, 2, m_sip4, route, nmask);
    /*
     * Server listens.
     */
    m_server->listen(12345, nullptr);
  }

  system::ConsoleLogger m_log;
  transport::list::Device::List m_clst;
  transport::list::Device::List m_slst;
  ethernet::Address m_cadr;
  ethernet::Address m_sadr;
  ipv4::Address m_cip4;
  ipv4::Address m_sip4;
  transport::pcap::Device::Ref m_cdev;
  transport::pcap::Device::Ref m_sdev;
  ClientDelegate m_c1dlg;
  ClientDelegate m_c2dlg;
  api::Client::Ref m_client1;
  api::Client::Ref m_client2;
  ServerDelegate m_sdlg;
  api::Server::Ref m_server;
};

TEST_F(API_TwoClients, ConnectTwo)
{
  api::Client::ID id1 = api::Client::DEFAULT_ID, id2 = api::Client::DEFAULT_ID;
  ipv4::Address dst_ip(10, 1, 0, 2);
  /*
   * Connection client 1.
   */
  ASSERT_EQ(Status::Ok, m_client1->open(id1));
  ASSERT_EQ(Status::OperationInProgress,
            m_client1->connect(id1, dst_ip, 12345));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client1));
  ASSERT_EQ(Status::OperationInProgress,
            m_client1->connect(id1, dst_ip, 12345));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client1));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client1->connect(id1, dst_ip, 12345));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_client1));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_server));
  /*
   * Connection client 2.
   */
  ASSERT_EQ(Status::Ok, m_client2->open(id2));
  ASSERT_EQ(Status::OperationInProgress,
            m_client2->connect(id2, dst_ip, 12345));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client2));
  ASSERT_EQ(Status::OperationInProgress,
            m_client2->connect(id2, dst_ip, 12345));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client2));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client2->connect(id2, dst_ip, 12345));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_client2));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_server));
  /*
   * Abort the connection and clean-up.
   */
  ASSERT_EQ(Status::Ok, m_client1->abort(id1));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_client1));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client2->abort(id2));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_client2));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_server));
}

TEST_F(API_TwoClients, ConnectTwoAndDisconnectFromServer)
{
  api::Client::ID id1 = api::Client::DEFAULT_ID, id2 = api::Client::DEFAULT_ID;
  ipv4::Address dst_ip(10, 1, 0, 2);
  /*
   * Connection client 1.
   */
  ASSERT_EQ(Status::Ok, m_client1->open(id1));
  ASSERT_EQ(Status::OperationInProgress,
            m_client1->connect(id1, dst_ip, 12345));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client1));
  ASSERT_EQ(Status::OperationInProgress,
            m_client1->connect(id1, dst_ip, 12345));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client1));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client1->connect(id1, dst_ip, 12345));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_client1));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_server));
  /*
   * Connection client 2.
   */
  ASSERT_EQ(Status::Ok, m_client2->open(id2));
  ASSERT_EQ(Status::OperationInProgress,
            m_client2->connect(id2, dst_ip, 12345));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client2));
  ASSERT_EQ(Status::OperationInProgress,
            m_client2->connect(id2, dst_ip, 12345));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client2));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client2->connect(id2, dst_ip, 12345));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_client2));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_server));
  /*
   * Disconnect the first connection.
   */
  ASSERT_EQ(2, m_sdlg.connections().size());
  tulips::api::Server::ID c0 = m_sdlg.connections().front();
  ASSERT_EQ(Status::Ok, m_server->close(c0));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client1));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client1));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_client1));
  /*
   * Disconnect the second connection.
   */
  ASSERT_EQ(1, m_sdlg.connections().size());
  tulips::api::Server::ID c1 = m_sdlg.connections().front();
  ASSERT_EQ(Status::Ok, m_server->close(c1));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client2));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client2));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_client2));
  /*
   * Advance the timers because of TIME WAIT.
   */
  for (int i = 0; i < 120; i += 1) {
    system::Clock::get().offsetBy(system::Clock::SECOND);
    ASSERT_EQ(Status::Ok, m_client1->run());
    ASSERT_EQ(Status::Ok, m_client2->run());
    ASSERT_EQ(Status::Ok, m_server->run());
  }
  /*
   * Clean-up.
   */
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_client1));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_client2));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_server));
  /*
   * Final checks.
   */
  ASSERT_EQ(0, m_sdlg.connections().size());
}

TEST_F(API_TwoClients, ConnectSend)
{
  api::Client::ID id = api::Client::DEFAULT_ID;
  ipv4::Address dst_ip(10, 1, 0, 2);
  /*
   * Connect client.
   */
  ASSERT_EQ(Status::Ok, m_client1->open(id));
  ASSERT_EQ(Status::OperationInProgress,
            m_client1->connect(id, dst_ip, 12345)); /* ARP REQ */
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client1));
  ASSERT_EQ(Status::OperationInProgress,
            m_client1->connect(id, dst_ip, 12345)); /* SYN REQ */
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client1));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client1->connect(id, dst_ip, 12345));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_client1));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_server));
  /*
   * Client sends.
   */
  uint32_t rem = 0;
  uint64_t data = 0xdeadbeef;
  ASSERT_EQ(Status::Ok,
            m_client1->send(id, sizeof(data), (uint8_t*)&data, rem));
  ASSERT_EQ(sizeof(data), rem);
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client1));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_client1));
  /*
   * Abort the connection and clean-up.
   */
  ASSERT_EQ(Status::Ok, m_client1->abort(id));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_client1));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_server));
}

TEST_F(API_TwoClients, ConnectSendReceive)
{
  api::Client::ID id = api::Client::DEFAULT_ID;
  ipv4::Address dst_ip(10, 1, 0, 2);
  /*
   * Ask the server to send the data back.
   */
  m_sdlg.doSendBack(true);
  /*
   * Connect client.
   */
  ASSERT_EQ(Status::Ok, m_client1->open(id));
  ASSERT_EQ(Status::OperationInProgress, m_client1->connect(id, dst_ip, 12345));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client1));
  ASSERT_EQ(Status::OperationInProgress, m_client1->connect(id, dst_ip, 12345));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client1));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client1->connect(id, dst_ip, 12345));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_client1));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_server));
  /*
   * Client sends, server sends back and client receives.
   */
  uint32_t rem = 0;
  uint64_t data = 0xdeadbeef;
  ASSERT_EQ(Status::Ok,
            m_client1->send(id, sizeof(data), (uint8_t*)&data, rem));
  ASSERT_EQ(sizeof(data), rem);
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client1));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client1));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_client1));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_server));
  ASSERT_TRUE(m_c1dlg.dataReceived());
  /*
   * Abort the connection and clean-up.
   */
  ASSERT_EQ(Status::Ok, m_client1->abort(id));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_client1));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_server));
}
