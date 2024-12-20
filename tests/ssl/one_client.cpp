#include <tulips/api/Defaults.h>
#include <tulips/ssl/Client.h>
#include <tulips/ssl/Server.h>
#include <tulips/system/Compiler.h>
#include <tulips/system/Logger.h>
#include <tulips/transport/Processor.h>
#include <tulips/transport/list/Device.h>
#include <tulips/transport/pcap/Device.h>
#include <gtest/gtest.h>

using namespace tulips;
using namespace stack;

namespace {

class ServerDelegate : public api::defaults::ServerDelegate
{
public:
  ServerDelegate() : m_action(Action::Continue) {}

  tulips::Action onNewData(UNUSED api::Client::ID const& id,
                           UNUSED void* const cookie, const uint8_t* const data,
                           UNUSED const uint32_t len, UNUSED const bool pushed,
                           UNUSED const Timestamp ts,
                           UNUSED const uint32_t alen,
                           UNUSED uint8_t* const sdata,
                           UNUSED uint32_t& slen) override
  {
    uint64_t& value = *(uint64_t*)data;
    return value != 0xdeadbeef ? Action::Abort : m_action;
  }

  void abortOnReceive() { m_action = Action::Abort; }

  void closeOnReceive() { m_action = Action::Close; }

private:
  Action m_action;
};

}

class SSL_OneClient : public ::testing::Test
{
public:
  SSL_OneClient()
    : m_log(system::Logger::Level::Trace)
    , m_cadr(0x10, 0x0, 0x0, 0x0, 0x10, 0x10)
    , m_sadr(0x10, 0x0, 0x0, 0x0, 0x20, 0x20)
    , m_cip4(10, 1, 0, 1)
    , m_sip4(10, 1, 0, 2)
    , m_clst()
    , m_slst()
    , m_cdev(nullptr)
    , m_sdev(nullptr)
    , m_cdlg()
    , m_client(nullptr)
    , m_sdlg()
    , m_server(nullptr)
  {}

  void connectClient(ipv4::Address const& dst_ip, const uint16_t port,
                     api::Client::ID& id)
  {
    /*
     * Client opens a connection.
     */
    ASSERT_EQ(Status::Ok, m_client->open(id));
    /*
     * Client tries to connect, go through ARP.
     */
    ASSERT_EQ(Status::OperationInProgress, m_client->connect(id, dst_ip, port));
    ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
    ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client));
    /*
     * Client tries to connect, establish a connection.
     */
    ASSERT_EQ(Status::OperationInProgress, m_client->connect(id, dst_ip, port));
    ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
    ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client));
    ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
    /*
     * Client tries to connect, go through SSL handshake.
     */
    ASSERT_EQ(Status::OperationInProgress, m_client->connect(id, dst_ip, port));
    ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
    ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client));
    ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client));
    ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
    ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
    ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client));
    ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client));
    ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
    /*
     * Client is connected, no more data exchanged.
     */
    ASSERT_EQ(Status::Ok, m_client->connect(id, dst_ip, port));
    ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_client));
    ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_server));
  }

  void expireTimeWait()
  {
    for (int i = 0; i <= tcpv4::TIME_WAIT_TIMEOUT; i += 1) {
      system::Clock::get().offsetBy(system::Clock::SECOND);
      ASSERT_EQ(Status::Ok, m_client->run());
      ASSERT_EQ(Status::Ok, m_server->run());
    }
  }

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
    auto cdev =
      transport::list::Device::allocate(m_log, m_cadr, 9014, m_slst, m_clst);
    auto sdev =
      transport::list::Device::allocate(m_log, m_sadr, 9014, m_clst, m_slst);
    /*
     * Build the pcap device
     */
    std::string cnam = "api_secure.client." + tname;
    std::string snam = "api_secure.server." + tname;
    m_cdev = transport::pcap::Device::allocate(m_log, std::move(cdev), cnam);
    m_sdev = transport::pcap::Device::allocate(m_log, std::move(sdev), snam);
    /*
     * Define the source root and the security files.
     */
    std::string sourceRoot(TULIPS_SOURCE_ROOT);
    std::string certFile(sourceRoot + "/support/transport.cert");
    std::string keyFile(sourceRoot + "/support/transport.key");
    /*
     * Create the client.
     */
    m_client = ssl::Client::allocate(m_log, m_cdlg, *m_cdev, m_cip4, route,
                                     nmask, tulips::ssl::Protocol::TLS,
                                     certFile, keyFile);
    /*
     * Create the server.
     */
    m_server = ssl::Server::allocate(m_log, m_sdlg, *m_sdev, m_sip4, route,
                                     nmask, tulips::ssl::Protocol::TLS,
                                     certFile, keyFile);
  }

  void TearDown() override { system::Clock::get().resetOffset(); }

  system::ConsoleLogger m_log;
  ethernet::Address m_cadr;
  ethernet::Address m_sadr;
  ipv4::Address m_cip4;
  ipv4::Address m_sip4;
  transport::list::Device::List m_clst;
  transport::list::Device::List m_slst;
  transport::pcap::Device::Ref m_cdev;
  transport::pcap::Device::Ref m_sdev;
  api::defaults::ClientDelegate m_cdlg;
  ssl::Client::Ref m_client;
  ServerDelegate m_sdlg;
  ssl::Server::Ref m_server;
};

TEST_F(SSL_OneClient, ListenConnectAndAbort)
{
  api::Client::ID id = api::Client::DEFAULT_ID;
  ipv4::Address dst_ip(10, 1, 0, 2);
  /*
   * Server listens
   */
  m_server->listen(12345, nullptr);
  /*
   * Client connects.
   */
  connectClient(dst_ip, 12345, id);
  /*
   * Client aborts the connection.
   */
  ASSERT_EQ(Status::Ok, m_client->abort(id));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  /*
   * Client is closed.
   */
  ASSERT_TRUE(m_client->isClosed(id));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_client));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_server));
}

TEST_F(SSL_OneClient, ListenConnectAndClose)
{
  api::Client::ID id = api::Client::DEFAULT_ID;
  ipv4::Address dst_ip(10, 1, 0, 2);
  /*
   * Server listens
   */
  m_server->listen(12345, nullptr);
  /*
   * Client connects.
   */
  connectClient(dst_ip, 12345, id);
  /*
   * Client closes the connection, go through SSL shutdown.
   */
  ASSERT_EQ(Status::OperationInProgress, m_client->close(id));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client));
  /*
   * Advance the timers because of TIME WAIT.
   */
  expireTimeWait();
  /*
   * Client is closed.
   */
  ASSERT_TRUE(m_client->isClosed(id));
  ASSERT_TRUE(m_server->isClosed(0));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_client));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_server));
}

TEST_F(SSL_OneClient, ListenConnectAndCloseFromServer)
{
  api::Client::ID id = api::Client::DEFAULT_ID;
  ipv4::Address dst_ip(10, 1, 0, 2);
  /*
   * Server listens
   */
  m_server->listen(12345, nullptr);
  /*
   * Client connects.
   */
  connectClient(dst_ip, 12345, id);
  /*
   * Server closes the connection, go through SSL shutdown.
   */
  ASSERT_EQ(Status::OperationInProgress, m_server->close(0));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  /*
   * Advance the timers because of TIME WAIT.
   */
  expireTimeWait();
  /*
   * Client is closed.
   */
  ASSERT_TRUE(m_client->isClosed(id));
  ASSERT_TRUE(m_server->isClosed(0));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_client));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_server));
}

TEST_F(SSL_OneClient, ListenConnectSendAndAbortFromServer)
{
  api::Client::ID id = api::Client::DEFAULT_ID;
  ipv4::Address dst_ip(10, 1, 0, 2);
  /*
   * Server listens
   */
  m_sdlg.abortOnReceive();
  m_server->listen(12345, nullptr);
  /*
   * Client connects.
   */
  connectClient(dst_ip, 12345, id);
  /*
   * Client sends a piece of data, and the server aborts the connection.
   */
  uint32_t rem = 0;
  uint64_t data = 0xdeadbeef;
  ASSERT_EQ(Status::Ok,
            m_client->send(id, sizeof(data), (const uint8_t*)&data, rem));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client));
  /*
   * Client is closed.
   */
  ASSERT_TRUE(m_client->isClosed(id));
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_client));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_server));
}

TEST_F(SSL_OneClient, ListenConnectSendAndCloseFromServer)
{
  api::Client::ID id = api::Client::DEFAULT_ID;
  ipv4::Address dst_ip(10, 1, 0, 2);
  /*
   * Server listens
   */
  m_sdlg.closeOnReceive();
  m_server->listen(12345, nullptr);
  /*
   * Client connects.
   */
  connectClient(dst_ip, 12345, id);
  /*
   * Client sends a piece of data, and the server closes the connection.
   */
  uint32_t rem = 0;
  uint64_t data = 0xdeadbeef;
  ASSERT_EQ(Status::Ok,
            m_client->send(id, sizeof(data), (const uint8_t*)&data, rem));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_cdev->poll(*m_client));
  ASSERT_EQ(Status::Ok, m_sdev->poll(*m_server));
  /*
   * Advance the timers because of TIME WAIT.
   */
  for (int i = 0; i < 120; i += 1) {
    system::Clock::get().offsetBy(system::Clock::SECOND);
    ASSERT_EQ(Status::Ok, m_client->run());
    ASSERT_EQ(Status::Ok, m_server->run());
  }
  /*
   * Make sure the connection is closed.
   */
  ASSERT_TRUE(m_client->isClosed(id));
  /*
   * Clean-up.
   */
  ASSERT_EQ(Status::NoDataAvailable, m_cdev->poll(*m_client));
  ASSERT_EQ(Status::NoDataAvailable, m_sdev->poll(*m_server));
}
