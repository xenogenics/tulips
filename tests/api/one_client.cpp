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
using namespace transport;

namespace {

class ServerDelegate : public api::defaults::ServerDelegate
{
public:
  ServerDelegate()
    : m_listenCookie(0)
    , m_action(Action::Continue)
    , m_id(api::Server::DEFAULT_ID)
  {}

  void* onConnected(api::Server::ID const& id, void* const cookie,
                    UNUSED const Timestamp ts) override
  {
    if (cookie != nullptr) {
      m_listenCookie = *reinterpret_cast<size_t*>(cookie);
    }
    m_id = id;
    return nullptr;
  }

  Action onNewData(UNUSED api::Server::ID const& id, UNUSED void* const cookie,
                   UNUSED const uint8_t* const data, UNUSED const uint32_t len,
                   UNUSED const Timestamp ts, UNUSED const uint32_t alen,
                   UNUSED uint8_t* const sdata, UNUSED uint32_t& slen) override
  {
    return m_action;
  }

  bool isListenCookieValid() const { return m_listenCookie == 0xdeadbeef; }

  void abortOnReceive() { m_action = Action::Abort; }

  void closeOnReceive() { m_action = Action::Close; }

  api::Server::ID id() { return m_id; }

private:
  size_t m_listenCookie;
  Action m_action;
  api::Server::ID m_id;
};

} // namespace

class API_OneClient : public ::testing::Test
{
public:
  API_OneClient()
    : m_logger(system::Logger::Level::Trace)
    , m_client_adr(0x10, 0x0, 0x0, 0x0, 0x10, 0x10)
    , m_server_adr(0x10, 0x0, 0x0, 0x0, 0x20, 0x20)
    , m_client_ip4(10, 1, 0, 1)
    , m_server_ip4(10, 1, 0, 2)
    , m_client_list()
    , m_server_list()
    , m_client_ldev(nullptr)
    , m_server_ldev(nullptr)
    , m_client_pcap(nullptr)
    , m_server_pcap(nullptr)
    , m_client_delegate()
    , m_client(nullptr)
    , m_server_delegate()
    , m_server(nullptr)
  {}

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
    m_client_ldev = new list::Device(m_logger, m_client_adr, m_client_ip4,
                                     bcast, nmask, 1514, m_server_list,
                                     m_client_list);
    m_server_ldev = new list::Device(m_logger, m_server_adr, m_server_ip4,
                                     bcast, nmask, 1514, m_client_list,
                                     m_server_list);
    /*
     * Build the pcap device
     */
    std::string pcap_client = "api_1client.client." + tname;
    std::string pcap_server = "api_1client.server." + tname;
    m_client_pcap =
      new transport::pcap::Device(m_logger, *m_client_ldev, pcap_client);
    m_server_pcap =
      new transport::pcap::Device(m_logger, *m_server_ldev, pcap_server);
    /*
     * Create the client.
     */
    m_client = new api::Client(m_logger, m_client_delegate, *m_client_pcap, 2);
    /*
     * Create the server.
     */
    m_server = new api::Server(m_logger, m_server_delegate, *m_server_pcap, 2);
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
  ethernet::Address m_client_adr;
  ethernet::Address m_server_adr;
  ipv4::Address m_client_ip4;
  ipv4::Address m_server_ip4;
  list::Device::List m_client_list;
  list::Device::List m_server_list;
  list::Device* m_client_ldev;
  list::Device* m_server_ldev;
  transport::pcap::Device* m_client_pcap;
  transport::pcap::Device* m_server_pcap;
  api::defaults::ClientDelegate m_client_delegate;
  api::Client* m_client;
  ServerDelegate m_server_delegate;
  api::Server* m_server;
};

TEST_F(API_OneClient, OpenClose)
{
  api::Client::ID id1 = api::Client::DEFAULT_ID;
  api::Client::ID id2 = api::Client::DEFAULT_ID;
  api::Client::ID id3 = api::Client::DEFAULT_ID;
  ASSERT_EQ(Status::Ok, m_client->open(id1));
  ASSERT_EQ(Status::Ok, m_client->open(id2));
  ASSERT_EQ(Status::NoMoreResources, m_client->open(id3));
  ASSERT_EQ(Status::NotConnected, m_client->close(id2));
  ASSERT_EQ(Status::NotConnected, m_client->close(id1));
}

TEST_F(API_OneClient, ListenConnectAndAbort)
{
  api::Client::ID id = api::Client::DEFAULT_ID;
  ipv4::Address dst_ip(10, 1, 0, 2);
  // Server listens
  m_server->listen(12345, nullptr);
  // Client opens a connection
  ASSERT_EQ(Status::Ok, m_client->open(id));
  // Client tries to connect -- sends ARP request
  ASSERT_EQ(Status::OperationInProgress, m_client->connect(id, dst_ip, 12345));
  // Server responds to the ARP request
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  // Client processes the reponse
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  // Client tries to connect -- sends SYN request
  ASSERT_EQ(Status::OperationInProgress, m_client->connect(id, dst_ip, 12345));
  // Server responds with SYN/ACK
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  // Client responds with ACK -- TCPv4.cpp:584
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  // Server acknowledge the connection -- TCPv4.cpp:560
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  // Client tries to connect
  ASSERT_EQ(Status::Ok, m_client->connect(id, dst_ip, 12345));
  // Client aborts -- sends RST
  ASSERT_EQ(Status::Ok, m_client->abort(id));
  // Server processes RST
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  // Client closed
  ASSERT_TRUE(m_client->isClosed(id));
  // Client and server close the connections
  ASSERT_EQ(Status::NoDataAvailable, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::NoDataAvailable, m_server_pcap->poll(*m_server));
}

TEST_F(API_OneClient, ListenConnectAndClose)
{
  api::Client::ID id = api::Client::DEFAULT_ID;
  ipv4::Address dst_ip(10, 1, 0, 2);
  // Server listens
  m_server->listen(12345, nullptr);
  // Client opens a connection
  ASSERT_EQ(Status::Ok, m_client->open(id));
  // Client tries to connect -- sends ARP request
  ASSERT_EQ(Status::OperationInProgress, m_client->connect(id, dst_ip, 12345));
  // Server responds to the ARP request
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  // Client processes the reponse
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  // Client tries to connect -- sends SYN request
  ASSERT_EQ(Status::OperationInProgress, m_client->connect(id, dst_ip, 12345));
  // Server responds with SYN/ACK
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  // Client responds with ACK -- TCPv4.cpp:584
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  // Server acknowledge the connection -- TCPv4.cpp:560
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  // Client tries to connect
  ASSERT_EQ(Status::Ok, m_client->connect(id, dst_ip, 12345));
  // Client closes -- sends FIN
  ASSERT_EQ(Status::Ok, m_client->close(id));
  // Server responds with FIN/ACK
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  // Client responds with ACK -- TCPv4.cpp:584
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  // Server acknowledge the disconnection
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  /*
   * Advance the timers because of TIME WAIT.
   */
  for (int i = 0; i < 120; i += 1) {
    system::Clock::get().offsetBy(system::Clock::SECOND);
    ASSERT_EQ(Status::Ok, m_client->run());
    ASSERT_EQ(Status::Ok, m_server->run());
  }
  /*
   * Client and server closed
   */
  ASSERT_TRUE(m_client->isClosed(id));
  ASSERT_TRUE(m_server->isClosed(0));
  ASSERT_EQ(Status::NoDataAvailable, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::NoDataAvailable, m_server_pcap->poll(*m_server));
}

TEST_F(API_OneClient, ListenConnectAndCloseFromServer)
{
  api::Client::ID id = api::Client::DEFAULT_ID;
  ipv4::Address dst_ip(10, 1, 0, 2);
  /*
   * Server listens
   */
  m_server->listen(12345, nullptr);
  /*
   * Client opens a connection
   */
  ASSERT_EQ(Status::Ok, m_client->open(id));
  ASSERT_EQ(Status::OperationInProgress, m_client->connect(id, dst_ip, 12345));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::OperationInProgress, m_client->connect(id, dst_ip, 12345));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  /*
   * Client is connected.
   */
  ASSERT_EQ(Status::Ok, m_client->connect(id, dst_ip, 12345));
  ASSERT_EQ(Status::NoDataAvailable, m_client_pcap->poll(*m_server));
  ASSERT_EQ(Status::NoDataAvailable, m_server_pcap->poll(*m_server));
  /*
   * Server closes -- sends FIN
   */
  ASSERT_EQ(Status::Ok, m_server->close(0));
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  /*
   * Advance the timers because of TIME WAIT.
   */
  for (int i = 0; i < 120; i += 1) {
    system::Clock::get().offsetBy(system::Clock::SECOND);
    ASSERT_EQ(Status::Ok, m_client->run());
    ASSERT_EQ(Status::Ok, m_server->run());
  }
  /*
   * Client closed.
   */
  ASSERT_TRUE(m_client->isClosed(id));
  ASSERT_TRUE(m_server->isClosed(0));
  ASSERT_EQ(Status::NoDataAvailable, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::NoDataAvailable, m_server_pcap->poll(*m_server));
}

TEST_F(API_OneClient, ConnectCookie)
{
  api::Client::ID id = api::Client::DEFAULT_ID;
  size_t cookie = 0xdeadbeef;
  ipv4::Address dst_ip(10, 1, 0, 2);
  /*
   * Listen to connections.
   */
  m_server->listen(12345, &cookie);
  /*
   * Listen and connect.
   */
  ASSERT_EQ(Status::Ok, m_client->open(id));
  ASSERT_EQ(Status::OperationInProgress, m_client->connect(id, dst_ip, 12345));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::OperationInProgress, m_client->connect(id, dst_ip, 12345));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client->connect(id, dst_ip, 12345));
  /*
   * Check if the cookie was found.
   */
  ASSERT_TRUE(m_server_delegate.isListenCookieValid());
  /*
   * Abort the connection and clean-up.
   */
  ASSERT_EQ(Status::Ok, m_client->abort(id));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::NoDataAvailable, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::NoDataAvailable, m_server_pcap->poll(*m_server));
}

TEST_F(API_OneClient, ConnectTwo)
{
  api::Client::ID id1 = api::Client::DEFAULT_ID, id2 = api::Client::DEFAULT_ID;
  size_t cookie = 0xdeadbeef;
  ipv4::Address dst_ip(10, 1, 0, 2);
  /*
   * Listen to connections.
   */
  m_server->listen(12345, &cookie);
  /*
   * Connection client 1.
   */
  ASSERT_EQ(Status::Ok, m_client->open(id1));
  ASSERT_EQ(Status::OperationInProgress, m_client->connect(id1, dst_ip, 12345));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::OperationInProgress, m_client->connect(id1, dst_ip, 12345));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client->connect(id1, dst_ip, 12345));
  ASSERT_EQ(Status::NoDataAvailable, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::NoDataAvailable, m_server_pcap->poll(*m_server));
  /*
   * Connection client 2.
   */
  ASSERT_EQ(Status::Ok, m_client->open(id2));
  ASSERT_EQ(Status::OperationInProgress, m_client->connect(id2, dst_ip, 12345));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client->connect(id2, dst_ip, 12345));
  ASSERT_EQ(Status::NoDataAvailable, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::NoDataAvailable, m_server_pcap->poll(*m_server));
  /*
   * Abort the connection and clean-up.
   */
  ASSERT_EQ(Status::Ok, m_client->abort(id1));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::NoDataAvailable, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::NoDataAvailable, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client->abort(id2));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::NoDataAvailable, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::NoDataAvailable, m_server_pcap->poll(*m_server));
}

TEST_F(API_OneClient, ConnectAndCloseTwo)
{
  api::Client::ID id1 = api::Client::DEFAULT_ID, id2 = api::Client::DEFAULT_ID;
  size_t cookie = 0xdeadbeef;
  ipv4::Address dst_ip(10, 1, 0, 2);
  /*
   * Listen to connections.
   */
  m_server->listen(12345, &cookie);
  /*
   * Connection client 1.
   */
  ASSERT_EQ(Status::Ok, m_client->open(id1));
  ASSERT_EQ(Status::OperationInProgress,
            m_client->connect(id1, dst_ip, 12345)); /* ARP REQ */
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::OperationInProgress,
            m_client->connect(id1, dst_ip, 12345)); /* SYN REQ */
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client->connect(id1, dst_ip, 12345));
  ASSERT_EQ(Status::NoDataAvailable, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::NoDataAvailable, m_server_pcap->poll(*m_server));
  /*
   * Connection client 2.
   */
  ASSERT_EQ(Status::Ok, m_client->open(id2));
  ASSERT_EQ(Status::OperationInProgress,
            m_client->connect(id2, dst_ip, 12345)); /* SYN REQ */
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client->connect(id2, dst_ip, 12345));
  ASSERT_EQ(Status::NoDataAvailable, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::NoDataAvailable, m_server_pcap->poll(*m_server));
  /*
   * Closing connection 1.
   */
  ASSERT_EQ(Status::Ok, m_client->close(id1));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  /*
   * Closing connection 2.
   */
  ASSERT_EQ(Status::Ok, m_client->close(id2));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  /*
   * Advance the timers because of TIME WAIT.
   */
  for (int i = 0; i < 120; i += 1) {
    system::Clock::get().offsetBy(system::Clock::SECOND);
    ASSERT_EQ(Status::Ok, m_client->run());
    ASSERT_EQ(Status::Ok, m_server->run());
  }
  /*
   * Make sure the connections are closed.
   */
  ASSERT_TRUE(m_client->isClosed(id1));
  ASSERT_TRUE(m_server->isClosed(0));
  ASSERT_TRUE(m_client->isClosed(id2));
  ASSERT_TRUE(m_server->isClosed(1));
  /*
   * Clean-up.
   */
  ASSERT_EQ(Status::NoDataAvailable, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::NoDataAvailable, m_server_pcap->poll(*m_server));
}

TEST_F(API_OneClient, ListenConnectSendAndAbortFromServer)
{
  api::Client::ID id = api::Client::DEFAULT_ID;
  ipv4::Address dst_ip(10, 1, 0, 2);
  /*
   * Server listens.
   */
  m_server_delegate.abortOnReceive();
  m_server->listen(12345, nullptr);
  /*
   * Client opens a connection.
   */
  ASSERT_EQ(Status::Ok, m_client->open(id));
  /*
   * Client connects.
   */
  ASSERT_EQ(Status::OperationInProgress, m_client->connect(id, dst_ip, 12345));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::OperationInProgress, m_client->connect(id, dst_ip, 12345));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client->connect(id, dst_ip, 12345));
  /*
   * Client sends and server aborts.
   */
  uint32_t rem = 0;
  uint64_t data = 0xdeadbeef;
  ASSERT_EQ(Status::Ok,
            m_client->send(id, sizeof(data), (const uint8_t*)&data, rem));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  /*
   * Client connections is closed.
   */
  ASSERT_TRUE(m_client->isClosed(id));
  ASSERT_EQ(Status::NoDataAvailable, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::NoDataAvailable, m_client_pcap->poll(*m_client));
}

TEST_F(API_OneClient, ListenConnectSendAndAbortFromServerWithDelayedACK)
{
  api::Client::ID id = api::Client::DEFAULT_ID;
  ipv4::Address dst_ip(10, 1, 0, 2);
  /*
   * Server listens.
   */
  m_server_delegate.abortOnReceive();
  m_server->listen(12345, nullptr);
  /*
   * Client opens a connection.
   */
  ASSERT_EQ(Status::Ok, m_client->open(id));
  /*
   * Client connects.
   */
  ASSERT_EQ(Status::OperationInProgress, m_client->connect(id, dst_ip, 12345));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::OperationInProgress, m_client->connect(id, dst_ip, 12345));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client->connect(id, dst_ip, 12345));
  /*
   * Set the delayed ACK option.
   */
  m_server->setOptions(m_server_delegate.id(), tcpv4::Connection::DELAYED_ACK);
  /*
   * Client sends and server aborts.
   */
  uint32_t rem = 0;
  uint64_t data = 0xdeadbeef;
  ASSERT_EQ(Status::Ok,
            m_client->send(id, sizeof(data), (const uint8_t*)&data, rem));
  ASSERT_EQ(Status::Ok, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::Ok, m_client_pcap->poll(*m_client));
  /*
   * Client connections is closed.
   */
  ASSERT_TRUE(m_client->isClosed(id));
  ASSERT_EQ(Status::NoDataAvailable, m_server_pcap->poll(*m_server));
  ASSERT_EQ(Status::NoDataAvailable, m_client_pcap->poll(*m_client));
}
