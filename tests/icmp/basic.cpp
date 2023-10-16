#include <tulips/stack/arp/Processor.h>
#include <tulips/stack/ethernet/Processor.h>
#include <tulips/stack/ethernet/Producer.h>
#include <tulips/stack/icmpv4/Processor.h>
#include <tulips/stack/ipv4/Processor.h>
#include <tulips/stack/ipv4/Producer.h>
#include <tulips/system/Logger.h>
#include <tulips/transport/Processor.h>
#include <tulips/transport/list/Device.h>
#include <tulips/transport/pcap/Device.h>
#include <gtest/gtest.h>

using namespace tulips;
using namespace stack;
using namespace transport;

TEST(ICMP_Basic, RequestResponse)
{
  std::string tname(
    ::testing::UnitTest::GetInstance()->current_test_info()->name());
  /*
   * Create the console logger.
   */
  auto log = system::ConsoleLogger(system::Logger::Level::Trace);
  /*
   * Create the transport FIFOs.
   */
  list::Device::List cli_fifo;
  list::Device::List srv_fifo;
  /*
   * Define the parameters.
   */
  ethernet::Address cli_adr(0x10, 0x0, 0x0, 0x0, 0x10, 0x10);
  ethernet::Address srv_adr(0x10, 0x0, 0x0, 0x0, 0x20, 0x20);
  ipv4::Address cli_ip4(10, 1, 0, 1);
  ipv4::Address srv_ip4(10, 1, 0, 2);
  ipv4::Address bcast(10, 1, 0, 254);
  ipv4::Address nmask(255, 255, 255, 0);
  /*
   * Build the devices.
   */
  auto cdev = list::Device::allocate(log, cli_adr, 128, srv_fifo, cli_fifo);
  auto sdev = list::Device::allocate(log, srv_adr, 128, cli_fifo, srv_fifo);
  /*
   * Build the pcap device
   */
  cdev = transport::pcap::Device::allocate(log, std::move(cdev),
                                           "icmp_cli_" + tname);
  sdev = transport::pcap::Device ::allocate(log, std::move(sdev),
                                            "icmp_srv_" + tname);
  /*
   * Client stack
   */
  ethernet::Producer cli_eth_prod(log, *cdev, cdev->address());
  ipv4::Producer cli_ip4_prod(log, cli_eth_prod, ipv4::Address(10, 1, 0, 1));
  ethernet::Processor cli_eth_proc(log, cdev->address());
  ipv4::Processor cli_ip4_proc(log, ipv4::Address(10, 1, 0, 1));
  arp::Processor cli_arp(log, cli_eth_prod, cli_ip4_prod);
  icmpv4::Processor cli_icmp4(log, cli_eth_prod, cli_ip4_prod);
  /*
   * Bind the stack
   */
  cli_icmp4.setEthernetProcessor(cli_eth_proc)
    .setARPProcessor(cli_arp)
    .setIPv4Processor(cli_ip4_proc);
  cli_ip4_prod.setNetMask(ipv4::Address(255, 255, 255, 0));
  cli_ip4_proc.setEthernetProcessor(cli_eth_proc).setICMPv4Processor(cli_icmp4);
  cli_eth_proc.setARPProcessor(cli_arp).setIPv4Processor(cli_ip4_proc);
  /*
   * Server stack
   */
  ethernet::Producer srv_eth_prod(log, *sdev, sdev->address());
  ipv4::Producer srv_ip4_prod(log, srv_eth_prod, ipv4::Address(10, 1, 0, 2));
  ethernet::Processor srv_eth_proc(log, sdev->address());
  ipv4::Processor srv_ip4_proc(log, ipv4::Address(10, 1, 0, 2));
  arp::Processor srv_arp(log, srv_eth_prod, srv_ip4_prod);
  icmpv4::Processor srv_icmp4(log, srv_eth_prod, srv_ip4_prod);
  /*
   * Bind the stack
   */
  srv_icmp4.setARPProcessor(srv_arp)
    .setEthernetProcessor(srv_eth_proc)
    .setIPv4Processor(srv_ip4_proc);
  srv_ip4_prod.setNetMask(ipv4::Address(255, 255, 255, 0));
  srv_ip4_proc.setEthernetProcessor(srv_eth_proc).setICMPv4Processor(srv_icmp4);
  srv_eth_proc.setARPProcessor(srv_arp).setIPv4Processor(srv_ip4_proc);
  /*
   * Get an ICMP request.
   */
  icmpv4::Request& req = cli_icmp4.attach(cli_eth_prod, cli_ip4_prod);
  /*
   * ARP negotiation
   */
  cli_arp.discover(ipv4::Address(10, 1, 0, 2));
  ASSERT_EQ(Status::Ok, sdev->poll(srv_eth_proc));
  ASSERT_EQ(Status::Ok, cdev->poll(cli_eth_proc));
  /*
   * Ping #1
   */
  ASSERT_EQ(Status::Ok, req(ipv4::Address(10, 1, 0, 2)));
  ASSERT_EQ(Status::OperationInProgress, req(ipv4::Address(10, 1, 0, 2)));
  ASSERT_EQ(Status::Ok, sdev->poll(srv_eth_proc));
  ASSERT_EQ(Status::Ok, cdev->poll(cli_eth_proc));
  ASSERT_EQ(Status::OperationCompleted, req(ipv4::Address(10, 1, 0, 2)));
  /*
   * Ping #2
   */
  ASSERT_EQ(Status::Ok, req(ipv4::Address(10, 1, 0, 2)));
  ASSERT_EQ(Status::OperationInProgress, req(ipv4::Address(10, 1, 0, 2)));
  ASSERT_EQ(Status::Ok, sdev->poll(srv_eth_proc));
  ASSERT_EQ(Status::Ok, cdev->poll(cli_eth_proc));
  ASSERT_EQ(Status::OperationCompleted, req(ipv4::Address(10, 1, 0, 2)));
  /*
   * Detach the request.
   */
  cli_icmp4.detach(req);
  /*
   * Clean-up.
   */
  ASSERT_EQ(Status::NoDataAvailable, sdev->poll(srv_eth_proc));
  ASSERT_EQ(Status::NoDataAvailable, cdev->poll(cli_eth_proc));
}
