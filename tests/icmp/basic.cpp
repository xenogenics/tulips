#include "tulips/system/Logger.h"
#include <tulips/stack/arp/Processor.h>
#include <tulips/stack/ethernet/Processor.h>
#include <tulips/stack/ethernet/Producer.h>
#include <tulips/stack/icmpv4/Processor.h>
#include <tulips/stack/ipv4/Processor.h>
#include <tulips/stack/ipv4/Producer.h>
#include <tulips/transport/Processor.h>
#include <tulips/transport/pcap/Device.h>
#include <tulips/transport/shm/Device.h>
#include <gtest/gtest.h>

using namespace tulips;
using namespace stack;

TEST(ICMP_Basic, RequestResponse)
{
  std::string tname(
    ::testing::UnitTest::GetInstance()->current_test_info()->name());
  /*
   * Create the console logger.
   */
  auto logger = system::ConsoleLogger(system::Logger::Level::Trace);
  /*
   * Create the transport FIFOs
   */
  tulips_fifo_t client_fifo = TULIPS_FIFO_DEFAULT_VALUE;
  tulips_fifo_t server_fifo = TULIPS_FIFO_DEFAULT_VALUE;
  /*
   * Build the FIFOs
   */
  tulips_fifo_create(64, 32, &client_fifo);
  tulips_fifo_create(64, 32, &server_fifo);
  /*
   * Build the devices
   */
  ethernet::Address client_adr(0x10, 0x0, 0x0, 0x0, 0x10, 0x10);
  ethernet::Address server_adr(0x10, 0x0, 0x0, 0x0, 0x20, 0x20);
  ipv4::Address client_ip4(10, 1, 0, 1);
  ipv4::Address server_ip4(10, 1, 0, 2);
  ipv4::Address bcast(10, 1, 0, 254);
  ipv4::Address nmask(255, 255, 255, 0);
  transport::shm::Device client(client_adr, client_ip4, bcast, nmask,
                                server_fifo, client_fifo);
  transport::shm::Device server(server_adr, server_ip4, bcast, nmask,
                                client_fifo, server_fifo);
  /*
   * Build the pcap device
   */
  transport::pcap::Device client_pcap(client, "icmp_client_" + tname + ".pcap");
  transport::pcap::Device server_pcap(server, "icmp_server_" + tname + ".pcap");
  /*
   * Client stack
   */
  ethernet::Producer client_eth_prod(logger, client_pcap, client.address());
  ipv4::Producer client_ip4_prod(logger, client_eth_prod,
                                 ipv4::Address(10, 1, 0, 1));
  ethernet::Processor client_eth_proc(logger, client.address());
  ipv4::Processor client_ip4_proc(logger, ipv4::Address(10, 1, 0, 1));
  arp::Processor client_arp(logger, client_eth_prod, client_ip4_prod);
  icmpv4::Processor client_icmp4(logger, client_eth_prod, client_ip4_prod);
  /*
   * Bind the stack
   */
  client_icmp4.setEthernetProcessor(client_eth_proc)
    .setARPProcessor(client_arp)
    .setIPv4Processor(client_ip4_proc);
  client_ip4_prod.setNetMask(ipv4::Address(255, 255, 255, 0));
  client_ip4_proc.setEthernetProcessor(client_eth_proc)
    .setICMPv4Processor(client_icmp4);
  client_eth_proc.setARPProcessor(client_arp).setIPv4Processor(client_ip4_proc);
  /*
   * Server stack
   */
  ethernet::Producer server_eth_prod(logger, server_pcap, server.address());
  ipv4::Producer server_ip4_prod(logger, server_eth_prod,
                                 ipv4::Address(10, 1, 0, 2));
  ethernet::Processor server_eth_proc(logger, server.address());
  ipv4::Processor server_ip4_proc(logger, ipv4::Address(10, 1, 0, 2));
  arp::Processor server_arp(logger, server_eth_prod, server_ip4_prod);
  icmpv4::Processor server_icmp4(logger, server_eth_prod, server_ip4_prod);
  /*
   * Bind the stack
   */
  server_icmp4.setARPProcessor(server_arp)
    .setEthernetProcessor(server_eth_proc)
    .setIPv4Processor(server_ip4_proc);
  server_ip4_prod.setNetMask(ipv4::Address(255, 255, 255, 0));
  server_ip4_proc.setEthernetProcessor(server_eth_proc)
    .setICMPv4Processor(server_icmp4);
  server_eth_proc.setARPProcessor(server_arp).setIPv4Processor(server_ip4_proc);
  /*
   * Get an ICMP request.
   */
  icmpv4::Request& req = client_icmp4.attach(client_eth_prod, client_ip4_prod);
  /*
   * ARP negotiation
   */
  client_arp.discover(ipv4::Address(10, 1, 0, 2));
  ASSERT_EQ(Status::Ok, server_pcap.poll(server_eth_proc));
  ASSERT_EQ(Status::Ok, client_pcap.poll(client_eth_proc));
  /*
   * Ping #1
   */
  ASSERT_EQ(Status::Ok, req(ipv4::Address(10, 1, 0, 2)));
  ASSERT_EQ(Status::OperationInProgress, req(ipv4::Address(10, 1, 0, 2)));
  ASSERT_EQ(Status::Ok, server_pcap.poll(server_eth_proc));
  ASSERT_EQ(Status::Ok, client_pcap.poll(client_eth_proc));
  ASSERT_EQ(Status::OperationCompleted, req(ipv4::Address(10, 1, 0, 2)));
  /*
   * Ping #2
   */
  ASSERT_EQ(Status::Ok, req(ipv4::Address(10, 1, 0, 2)));
  ASSERT_EQ(Status::OperationInProgress, req(ipv4::Address(10, 1, 0, 2)));
  ASSERT_EQ(Status::Ok, server_pcap.poll(server_eth_proc));
  ASSERT_EQ(Status::Ok, client_pcap.poll(client_eth_proc));
  ASSERT_EQ(Status::OperationCompleted, req(ipv4::Address(10, 1, 0, 2)));
  /*
   * Detach the request.
   */
  client_icmp4.detach(req);
  /*
   * Destroy the FIFOs
   */
  tulips_fifo_destroy(&client_fifo);
  tulips_fifo_destroy(&server_fifo);
}
