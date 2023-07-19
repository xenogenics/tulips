#include "rte_flow.h"
#include "rte_mbuf.h"
#include "rte_mempool.h"
#include <tulips/system/Compiler.h>
#include <tulips/system/Utils.h>
#include <tulips/transport/dpdk/Device.h>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <sstream>
#include <dpdk/rte_dev.h>
#include <dpdk/rte_eal.h>
#include <dpdk/rte_ethdev.h>
#include <dpdk/rte_flow.h>

#define FABRIC_VERBOSE 1

#if FABRIC_VERBOSE
#define FABRIC_LOG(__args) LOG("FABRIC", __args)
#else
#define FABRIC_LOG(...) ((void)0)
#endif

namespace tulips::transport::dpdk {

AbstractionLayer Device::s_eal;

Device::Device(UNUSED const uint16_t nbuf)
  : transport::Device("dpdk")
  , m_portid(0)
  , m_mempool(nullptr)
  , m_ethconf()
  , m_rxqconf()
  , m_txqconf()
  , m_address()
  , m_ip()
  , m_dr()
  , m_nm()
  , m_mtu(1500)
{
  int ret = 0;
  /*
   * Collect the available ports.
   */
  std::vector<uint16_t> pids;
  uint16_t pid;
  RTE_ETH_FOREACH_DEV(pid)
  {
    pids.push_back(pid);
  }
  FABRIC_LOG("Found " << pids.size() << " ports");
  /*
   * Use the first port.
   */
  m_portid = pids.front();
  /*
   * Check that there is at least one available port.
   */
  if (pids.size() == 0) {
    throw std::runtime_error("No available ports");
  }
  /*
   * Get the device info for the first port.
   */
  struct rte_eth_dev_info dev_info;
  ret = rte_eth_dev_info_get(m_portid, &dev_info);
  if (ret < 0) {
    throw std::runtime_error("Failed to get device info");
  }
  /*
   * Print some device information.
   */
  FABRIC_LOG("Device driver: " << dev_info.driver_name);
  FABRIC_LOG("Device name: " << rte_dev_name(dev_info.device));
  FABRIC_LOG("Device NUMA node: " << rte_dev_numa_node(dev_info.device));
  /*
   * Erase the configurations.
   */
  memset(&m_ethconf, 0, sizeof(m_ethconf));
  memset(&m_macaddr, 0, sizeof(m_macaddr));
  memset(&m_rxqconf, 0, sizeof(m_rxqconf));
  memset(&m_txqconf, 0, sizeof(m_txqconf));
  /*
   * Configure the device.
   */
  ret = rte_eth_dev_configure(m_portid, 1, 1, &m_ethconf);
  if (ret != 0) {
    throw std::runtime_error("Failed to configure the device");
  }
  /*
   * Fetch the MAC address.
   */
  ret = rte_eth_macaddr_get(m_portid, &m_macaddr);
  if (ret != 0) {
    throw std::runtime_error("Failed to fetch device's MAC address");
  }
  /*
   * Allocate the mempool.
   */
  uint16_t buflen = m_mtu + stack::ethernet::HEADER_LEN;
  m_mempool = rte_pktmbuf_pool_create("SOME_NAME", nbuf, 0, 0, buflen,
                                      rte_eth_dev_socket_id(m_portid));
  if (m_mempool == nullptr) {
    throw std::runtime_error("Failed to create a mempool");
  }
  /*
   * Update the RX configuration.
   */
  m_rxqconf.rx_free_thresh = 32;
  /*
   * Setup the RX queue.
   */
  rte_eth_rx_queue_setup(m_portid, 0, nbuf, rte_eth_dev_socket_id(m_portid),
                         &m_rxqconf, m_mempool);
  if (ret != 0) {
    throw std::runtime_error("Failed to setup the RX queue");
  }
  /*
   * Setup the TX queue.
   */
  rte_eth_tx_queue_setup(m_portid, 0, nbuf, rte_eth_dev_socket_id(m_portid),
                         &m_txqconf);
  if (ret != 0) {
    throw std::runtime_error("Failed to setup the TX queue");
  }
  /*
   * Start the port.
   */
  ret = rte_eth_dev_start(m_portid);
  if (ret != 0) {
    throw std::runtime_error("Failed to start the device");
  }
}

Device::Device(UNUSED std::string const& ifn, UNUSED const uint16_t nbuf)
  : transport::Device("dpdk")
  , m_portid(0)
  , m_mempool(nullptr)
  , m_ethconf()
  , m_rxqconf()
  , m_txqconf()
  , m_address()
  , m_ip()
  , m_dr()
  , m_nm()
  , m_mtu()
{}

Device::~Device()
{
  /*
   * Delete the local MAC flow.
   */
  struct rte_flow_error flow_error;
  rte_flow_flush(m_portid, &flow_error);
  /*
   * Stop the device.
   */
  rte_eth_dev_stop(m_portid);
  /*
   * Clear the mempool.
   */
  if (m_mempool != nullptr) {
    rte_mempool_free(m_mempool);
  }
}

Status
Device::listen(const uint16_t UNUSED port)
{
#if 0
  /*
   * Define the local MAC flow attributes.
   */
  struct rte_flow_attr flow_attr;
  memset(&flow_attr, 0, sizeof(flow_attr));
  flow_attr.ingress = 1;
  /*
   * Define the local MAC flow queue.
   */
  struct rte_flow_action_queue flow_queue = { .index = 0 };
  /*
   * Define the local MAC flow actions.
   */
  struct rte_flow_action flow_action[2];
  memset(flow_action, 0, sizeof(flow_action));
  flow_action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
  flow_action[0].conf = &flow_queue;
  flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;
  /*
   * Define the local MAC flow ETH pattern.
   */
  struct rte_flow_item_eth flow_eth_spec;
  memset(&flow_eth_spec, 0, sizeof(flow_eth_spec));
  memcpy(&flow_eth_spec.hdr.dst_addr, &m_macaddr, sizeof(m_macaddr));
  struct rte_flow_item_eth flow_eth_mask;
  memset(&flow_eth_mask, 0, sizeof(flow_eth_mask));
  memset(&flow_eth_mask.hdr.dst_addr, 0xFF, sizeof(m_macaddr));
  /*
   * Define the local MAC flow pattern stack.
   */
  struct rte_flow_item flow_pattern[2] = { { .type = RTE_FLOW_ITEM_TYPE_ETH,
                                             .spec = &flow_eth_spec,
                                             .last = nullptr,
                                             .mask = &flow_eth_mask },
                                           { .type = RTE_FLOW_ITEM_TYPE_END,
                                             .spec = nullptr,
                                             .last = nullptr,
                                             .mask = nullptr } };
  /*
   * Validate the local MAC flow.
   */
  struct rte_flow_error flow_error;
  ret = rte_flow_validate(m_portid, &flow_attr, flow_pattern, flow_action,
                          &flow_error);
  if (ret != 0) {
    FABRIC_LOG("Invalid local MAC flow: " << flow_error.message);
    throw std::runtime_error("Failed to validate the local MAC flow");
  }
  /*
   * Create the local MAC flow.
   */
  m_ethflow = rte_flow_create(m_portid, &flow_attr, flow_pattern, flow_action,
                              &flow_error);
#endif
  return Status::UnsupportedOperation;
}

void
Device::unlisten(const uint16_t UNUSED port)
{}

Status
Device::poll(UNUSED Processor& proc)
{
  return Status::UnsupportedOperation;
}

Status
Device::wait(UNUSED Processor& proc, UNUSED const uint64_t ns)
{
  return Status::UnsupportedOperation;
}

Status
Device::prepare(UNUSED uint8_t*& buf)
{
  return Status::UnsupportedOperation;
}

Status
Device::commit(UNUSED const uint32_t len, UNUSED uint8_t* const buf,
               UNUSED const uint16_t mss)
{
  return Status::UnsupportedOperation;
}

}
