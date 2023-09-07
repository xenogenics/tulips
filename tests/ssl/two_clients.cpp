#include "tulips/system/Logger.h"
#include <tulips/api/Defaults.h>
#include <tulips/ssl/Client.h>
#include <tulips/ssl/Server.h>
#include <tulips/system/Compiler.h>
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
                           UNUSED const uint32_t len) override
  {
    m_data_received = true;
    return tulips::Action::Continue;
  }

  tulips::Action onNewData(UNUSED api::Client::ID const& id,
                           UNUSED void* const cookie,
                           UNUSED const uint8_t* const data,
                           UNUSED const uint32_t len,
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

  void* onConnected(api::Server::ID const& id,
                    UNUSED void* const cookie) override
  {
    m_connections.push_back(id);
    return nullptr;
  }

  Action onNewData(UNUSED api::Server::ID const& id, UNUSED void* const cookie,
                   const uint8_t* const data, const uint32_t len,
                   const uint32_t alen, uint8_t* const sdata,
                   uint32_t& slen) override
  {
    if (m_send_back && alen >= len) {
      memcpy(sdata, data, len);
      slen = len;
    }
    return Action::Continue;
  }

  void onClosed(tulips::api::Server::ID const& id,
                UNUSED void* const cookie) override
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

class SSL_TwoClients : public ::testing::Test
{
public:
  SSL_TwoClients()
    : m_logger(system::Logger::Level::Trace)
    , m_client_list()
    , m_server_list()
    , m_client_adr(0x10, 0x0, 0x0, 0x0, 0x10, 0x10)
    , m_server_adr(0x10, 0x0, 0x0, 0x0, 0x20, 0x20)
    , m_client_ip4(10, 1, 0, 1)
    , m_server_ip4(10, 1, 0, 2)
    , m_client_ldev(nullptr)
    , m_server_ldev(nullptr)
    , m_client_pcap(nullptr)
    , m_server_pcap(nullptr)
    , m_client_delegate()
    , m_client(nullptr)
    , m_server_delegate()
    , m_server(nullptr)
  {}

  void connectClient(ipv4::Address const& dst_ip, const int port,
                     api::Client::ID& id)
  {
    /*
     * Client tries to connect, establish a connection.
     */
    ASSERT_EQ(Status::OperationInProgress, m_client->connect(id, dst_ip, port));
    ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
    ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
    /*
     * Client tries to connect, go through SSL handshake.
     */
    ASSERT_EQ(Status::OperationInProgress, m_client->connect(id, dst_ip, port));
    ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
    ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
    ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
    ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
    ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
    ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
    ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
    ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
    ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
    /*
     * We are connected.
     */
    ASSERT_EQ(Status::Ok, m_client->connect(id, dst_ip, port));
    ASSERT_EQ(Status::NoDataAvailable, m_client_pcap->poll(*m_client));
    ASSERT_EQ(Status::NoDataAvailable, m_server_pcap->poll(*m_server));
  }

  void abortClient(const api::Client::ID& id)
  {
    /*
     * Client tries to close.
     */
    ASSERT_EQ(Status::Ok, m_client->abort(id));
    ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
    /*
     * We are closed.
     */
    ASSERT_EQ(Status::NotConnected, m_client->close(id));
    ASSERT_EQ(Status::NoDataAvailable, m_client_pcap->poll(*m_client));
    ASSERT_EQ(Status::NoDataAvailable, m_server_pcap->poll(*m_server));
  }

  void disconnectClient(const api::Client::ID& id)
  {
    /*
     * Client tries to close.
     */
    ASSERT_EQ(Status::OperationInProgress, m_client->close(id));
    ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
    ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
    ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
    ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
    ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
    ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
    ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
    /*
     * We are closed.
     */
    ASSERT_EQ(Status::NotConnected, m_client->close(id));
    ASSERT_EQ(Status::NoDataAvailable, m_client_pcap->poll(*m_client));
    ASSERT_EQ(Status::NoDataAvailable, m_server_pcap->poll(*m_server));
  }

  void connect1stClient(ipv4::Address const& dst_ip, const int port,
                        api::Client::ID& id)
  {
    ASSERT_EQ(Status::Ok, m_client->open(id));
    /*
     * Client tries to connect, go through ARP.
     */
    ASSERT_EQ(Status::OperationInProgress, m_client->connect(id, dst_ip, port));
    ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
    ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
    /*
     * Connect the client.
     */
    connectClient(dst_ip, port, id);
  }

  void connect2ndClient(ipv4::Address const& dst_ip, const int port,
                        api::Client::ID& id)
  {
    ASSERT_EQ(Status::Ok, m_client->open(id));
    /*
     * Connect the client.
     */
    connectClient(dst_ip, port, id);
  }

  void disconnectClientFromServer(const api::Server::ID id)
  {
    ASSERT_EQ(Status::OperationInProgress, m_server->close(id));
    ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
    ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
    ASSERT_EQ(Status::OperationInProgress, m_server->close(id));
    ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
    ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
    ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
    ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
    ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
    ASSERT_EQ(Status::NoDataAvailable, m_server_pcap->poll(*m_server));
    ASSERT_EQ(Status::NoDataAvailable, m_client_pcap->poll(*m_client));
    expireTimeWait();
    ASSERT_TRUE(m_server->isClosed(id));
  }

  void expireTimeWait()
  {
    for (int i = 0; i < tcpv4::TIME_WAIT_TIMEOUT; i += 1) {
      system::Clock::get().offsetBy(system::Clock::get().cyclesPerSecond());
      ASSERT_EQ(Status::Ok, m_server->run());
    }
  }

protected:
  void SetUp() override
  {
    ipv4::Address bcast(10, 1, 0, 254);
    ipv4::Address nmask(255, 255, 255, 0);
    std::string tname(
      ::testing::UnitTest::GetInstance()->current_test_info()->name());
    /*
     * Build the devices.
     */
    m_client_ldev =
      new transport::list::Device(m_logger, m_client_adr, m_client_ip4, bcast,
                                  nmask, 9014, m_server_list, m_client_list);
    m_server_ldev =
      new transport::list::Device(m_logger, m_server_adr, m_server_ip4, bcast,
                                  nmask, 9014, m_client_list, m_server_list);
    /*
     * Build the pcap device
     */
    std::string pcap_client = "api_2clients.client." + tname;
    std::string pcap_server = "api_2clients.server." + tname;
    m_client_pcap =
      new transport::pcap::Device(m_logger, *m_client_ldev, pcap_client);
    m_server_pcap =
      new transport::pcap::Device(m_logger, *m_server_ldev, pcap_server);
    /*
     * Define the source root and the security files.
     */
    std::string sourceRoot(TULIPS_SOURCE_ROOT);
    std::string cert(sourceRoot + "/support/transport.cert");
    std::string key(sourceRoot + "/support/transport.key");
    /*
     * Create the client.
     */
    m_client = new ssl::Client(m_logger, m_client_delegate, *m_client_pcap,
                               tulips::ssl::Protocol::TLS, cert, key, 2);
    /*
     * Create the server.
     */
    m_server = new ssl::Server(m_logger, m_server_delegate, *m_server_pcap,
                               tulips::ssl::Protocol::TLS, cert, key, 2);
    /*
     * Server listens.
     */
    m_server->listen(12345, nullptr);
  }

  void TearDown() override
  {
    /*
     * Delete client, server.
     */
    delete m_server;
    delete m_client;
    /*
     * Delete the pcap wrappers;
     */
    delete m_client_pcap;
    delete m_server_pcap;
    /*
     * Delete client and server.
     */
    delete m_client_ldev;
    delete m_server_ldev;
  }

  system::ConsoleLogger m_logger;
  transport::list::Device::List m_client_list;
  transport::list::Device::List m_server_list;
  ethernet::Address m_client_adr;
  ethernet::Address m_server_adr;
  ipv4::Address m_client_ip4;
  ipv4::Address m_server_ip4;
  transport::list::Device* m_client_ldev;
  transport::list::Device* m_server_ldev;
  transport::pcap::Device* m_client_pcap;
  transport::pcap::Device* m_server_pcap;
  ClientDelegate m_client_delegate;
  ssl::Client* m_client;
  ServerDelegate m_server_delegate;
  ssl::Server* m_server;
};

TEST_F(SSL_TwoClients, ConnectTwoAndAbort)
{
  api::Client::ID id[2] = { api::Client::DEFAULT_ID, api::Client::DEFAULT_ID };
  ipv4::Address dst_ip(10, 1, 0, 2);
  /*
   * Connect the clients.
   */
  connect1stClient(dst_ip, 12345, id[0]);
  connect2ndClient(dst_ip, 12345, id[1]);
  ASSERT_EQ(2, m_server_delegate.connections().size());
  /*
   * Abort the first connection.
   */
  abortClient(id[0]);
  ASSERT_EQ(1, m_server_delegate.connections().size());
  /*
   * Abort the second connection.
   */
  abortClient(id[1]);
  ASSERT_EQ(0, m_server_delegate.connections().size());
}

TEST_F(SSL_TwoClients, ConnectTwoAndClose)
{
  api::Client::ID id[2] = { api::Client::DEFAULT_ID, api::Client::DEFAULT_ID };
  ipv4::Address dst_ip(10, 1, 0, 2);
  /*
   * Connect the clients.
   */
  connect1stClient(dst_ip, 12345, id[0]);
  connect2ndClient(dst_ip, 12345, id[1]);
  ASSERT_EQ(2, m_server_delegate.connections().size());
  /*
   * Disconnect the first connection.
   */
  disconnectClient(id[0]);
  ASSERT_EQ(1, m_server_delegate.connections().size());
  /*
   * Disconnect the second connection.
   */
  disconnectClient(id[1]);
  ASSERT_EQ(0, m_server_delegate.connections().size());
}

TEST_F(SSL_TwoClients, ConnectTwoAndCloseFromServer)
{
  api::Client::ID id[2] = { api::Client::DEFAULT_ID, api::Client::DEFAULT_ID };
  ipv4::Address dst_ip(10, 1, 0, 2);
  /*
   * Connect the clients.
   */
  connect1stClient(dst_ip, 12345, id[0]);
  connect2ndClient(dst_ip, 12345, id[1]);
  ASSERT_EQ(2, m_server_delegate.connections().size());
  /*
   * Disconnect the first connection.
   */
  tulips::api::Server::ID c0 = m_server_delegate.connections().front();
  disconnectClientFromServer(c0);
  ASSERT_EQ(1, m_server_delegate.connections().size());
  /*
   * Disconnect the second connection.
   */
  tulips::api::Server::ID c1 = m_server_delegate.connections().front();
  disconnectClientFromServer(c1);
  ASSERT_EQ(0, m_server_delegate.connections().size());
}

TEST_F(SSL_TwoClients, ConnectSendAndClose)
{
  api::Client::ID id = api::Client::DEFAULT_ID;
  ipv4::Address dst_ip(10, 1, 0, 2);
  /*
   * Connect client.
   */
  connect1stClient(dst_ip, 12345, id);
  /*
   * Client sends.
   */
  uint32_t rem = 0;
  uint64_t data = 0xdeadbeef;
  ASSERT_EQ(Status::Ok, m_client->send(id, sizeof(data), (uint8_t*)&data, rem));
  ASSERT_EQ(sizeof(data), rem);
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::NoDataAvailable, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::NoDataAvailable, m_client_pcap->poll(*m_client));
  /*
   * Disconnect the client.
   */
  disconnectClient(id);
  ASSERT_EQ(0, m_server_delegate.connections().size());
}

TEST_F(SSL_TwoClients, ConnectSendReceiveAndClose)
{
  api::Client::ID id = api::Client::DEFAULT_ID;
  ipv4::Address dst_ip(10, 1, 0, 2);
  /*
   * Ask the server to send the data back.
   */
  m_server_delegate.doSendBack(true);
  /*
   * Connect client.
   */
  connect1stClient(dst_ip, 12345, id);
  /*
   * Client sends, server sends back and client receives.
   */
  uint32_t rem = 0;
  uint64_t data = 0xdeadbeef;
  ASSERT_EQ(Status::Ok, m_client->send(id, sizeof(data), (uint8_t*)&data, rem));
  ASSERT_EQ(sizeof(data), rem);
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::NoDataAvailable, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::NoDataAvailable, m_server_pcap->poll(*m_server));
  ASSERT_TRUE(m_client_delegate.dataReceived());
  /*
   * Disconnect the client.
   */
  disconnectClient(id);
  ASSERT_EQ(0, m_server_delegate.connections().size());
}
