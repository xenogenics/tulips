#include <tulips/stack/IPv4.h>
#include <tulips/stack/arp/Processor.h>
#include <tulips/stack/ethernet/Processor.h>
#include <tulips/stack/ethernet/Producer.h>
#include <tulips/stack/ipv4/Processor.h>
#include <tulips/stack/ipv4/Producer.h>
#include <tulips/system/Compiler.h>
#include <tulips/transport/Processor.h>
#include <tulips/transport/list/Device.h>
#include <tulips/transport/pcap/Device.h>
#include <gtest/gtest.h>

using namespace tulips;
using namespace stack;
using namespace transport;

namespace {

class ClientProcessor : public Processor
{
public:
  ClientProcessor() : m_data(0) {}

  Status run() override { return Status::Ok; }

  Status process(UNUSED const uint16_t len, const uint8_t* const data,
                 UNUSED Timestamp ts) override
  {
    m_data = *(uint64_t*)data;
    return Status::Ok;
  }

  Status sent(UNUSED const uint16_t len, UNUSED uint8_t* const data) override
  {
    return Status::Ok;
  }

  uint64_t data() const { return m_data; }

private:
  uint64_t m_data;
};

class ServerProcessor : public Processor
{
public:
  ServerProcessor() : m_ipv4to(nullptr), m_ipv4from(nullptr), m_data(0) {}

  Status run() override { return Status::Ok; }

  Status process(UNUSED const uint16_t len, const uint8_t* const data,
                 UNUSED Timestamp ts) override
  {
    m_data = *(uint64_t*)data;
    m_ipv4to->setProtocol(ipv4::Protocol::TEST);
    m_ipv4to->setDestinationAddress(m_ipv4from->sourceAddress());
    uint8_t* outdata;
    m_ipv4to->prepare(outdata);
    *(uint64_t*)outdata = 0xdeadc0deULL;
    return m_ipv4to->commit(8, outdata);
  }

  Status sent(UNUSED const uint16_t len, uint8_t* const data) override
  {
    return m_ipv4to->release(data);
  }

  ServerProcessor& setIPv4Producer(ipv4::Producer& ip4)
  {
    m_ipv4to = &ip4;
    return *this;
  }

  ServerProcessor& setIPv4Processor(ipv4::Processor& ip4)
  {
    m_ipv4from = &ip4;
    return *this;
  }

  uint64_t data() const { return m_data; }

private:
  ipv4::Producer* m_ipv4to;
  ipv4::Processor* m_ipv4from;
  uint64_t m_data;
};

} // namespace

TEST(ARP_Basic, RequestResponse)
{
  std::string tname(
    ::testing::UnitTest::GetInstance()->current_test_info()->name());
  /*
   * Create the console logger.
   */
  auto logger = system::ConsoleLogger(system::Logger::Level::Trace);
  /*
   * Create the transport FIFOs.
   */
  list::Device::List cfifo;
  list::Device::List sfifo;
  /*
   * Define the stack parameters.
   */
  ethernet::Address client_adr(0x10, 0x0, 0x0, 0x0, 0x10, 0x10);
  ethernet::Address server_adr(0x10, 0x0, 0x0, 0x0, 0x20, 0x20);
  ipv4::Address client_ip4(10, 1, 0, 1);
  ipv4::Address server_ip4(10, 1, 0, 2);
  ipv4::Address route(10, 1, 0, 254);
  ipv4::Address nmask(255, 255, 255, 0);
  /*
   * Build the devices.
   */
  auto clst = list::Device::allocate(logger, client_adr, 128, sfifo, cfifo);
  auto slst = list::Device::allocate(logger, server_adr, 128, cfifo, sfifo);
  /*
   * Build the pcap device
   */
  auto cnam = "arp_client_" + tname;
  auto cdev = transport::pcap::Device::allocate(logger, std::move(clst), cnam);
  auto snam = "arp_server_" + tname;
  auto sdev = transport::pcap::Device::allocate(logger, std::move(slst), snam);
  /*
   * Client stack
   */
  ethernet::Producer client_eth_prod(logger, *cdev, cdev->address());
  ipv4::Producer client_ip4_prod(logger, client_eth_prod,
                                 ipv4::Address(10, 1, 0, 1));
  ipv4::Processor client_ip4_proc(logger, ipv4::Address(10, 1, 0, 1));
  ethernet::Processor client_eth_proc(logger, cdev->address());
  arp::Processor client_arp(logger, client_eth_prod, client_ip4_prod);
  ClientProcessor client_proc;
  /*
   * Bind the stack
   */
  client_ip4_prod.setDestinationAddress(ipv4::Address(10, 1, 0, 2))
    .setNetMask(ipv4::Address(255, 255, 255, 0));
  client_ip4_proc.setEthernetProcessor(client_eth_proc)
    .setRawProcessor(client_proc);
  client_eth_proc.setARPProcessor(client_arp).setIPv4Processor(client_ip4_proc);
  /*
   * Server stack
   */
  ethernet::Producer server_eth_prod(logger, *sdev, sdev->address());
  ipv4::Producer server_ip4_prod(logger, server_eth_prod,
                                 ipv4::Address(10, 1, 0, 2));
  ethernet::Processor server_eth_proc(logger, sdev->address());
  ipv4::Processor server_ip4_proc(logger, ipv4::Address(10, 1, 0, 2));
  arp::Processor server_arp(logger, server_eth_prod, server_ip4_prod);
  ServerProcessor server_proc;
  /*
   * Bind the stack
   */
  server_proc.setIPv4Producer(server_ip4_prod)
    .setIPv4Processor(server_ip4_proc);
  server_ip4_prod.setDestinationAddress(ipv4::Address(10, 1, 0, 2))
    .setNetMask(ipv4::Address(255, 255, 255, 0));
  server_ip4_proc.setEthernetProcessor(server_eth_proc)
    .setRawProcessor(server_proc);
  server_eth_proc.setARPProcessor(server_arp).setIPv4Processor(server_ip4_proc);
  /*
   * Client sends the ARP discovery
   */
  client_arp.discover(ipv4::Address(10, 1, 0, 2));
  ASSERT_EQ(Status::Ok, sdev->poll(server_eth_proc));
  ASSERT_EQ(Status::Ok, cdev->poll(client_eth_proc));
  /*
   * Client sends payload to server
   */
  uint8_t* data;
  ethernet::Address dest;
  ASSERT_TRUE(client_arp.query(ipv4::Address(10, 1, 0, 2), dest));
  client_eth_prod.setDestinationAddress(dest);
  client_ip4_prod.setProtocol(ipv4::Protocol::TEST);
  ASSERT_EQ(Status::Ok, client_ip4_prod.prepare(data));
  *(uint64_t*)data = 0xdeadbeefULL;
  ASSERT_EQ(Status::Ok, client_ip4_prod.commit(8, data));
  ASSERT_EQ(Status::Ok, sdev->poll(server_eth_proc));
  ASSERT_EQ(0xdeadbeefULL, server_proc.data());
  ASSERT_EQ(Status::Ok, cdev->poll(client_eth_proc));
  ASSERT_EQ(0xdeadc0de, client_proc.data());
  ASSERT_EQ(Status::Ok, client_ip4_prod.release(data));
  /*
   * Clean-up.
   */
  ASSERT_EQ(Status::NoDataAvailable, cdev->poll(client_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, sdev->poll(server_eth_proc));
}
