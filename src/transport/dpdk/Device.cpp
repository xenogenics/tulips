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

#define FABRIC_VERBOSE 1

#if FABRIC_VERBOSE
#define FABRIC_LOG(__args) LOG("FABRIC", __args)
#else
#define FABRIC_LOG(...) ((void)0)
#endif

namespace tulips::transport::dpdk {

Device::Device(UNUSED const uint16_t nbuf)
  : transport::Device("dpdk"), m_address(), m_ip(), m_dr(), m_nm(), m_mtu()
{
  const char* const arguments[] = { "dpdk", "--in-memory", "--no-telemetry",
                                    "-c",   "1",           "--log-level=*:8" };
  int ret = 0;
  /*
   * Initialize the EAL.
   */
  ret = rte_eal_init(6, (char**)arguments);
  if (ret < 0) {
    throw std::runtime_error("Failed to initialize EAL");
  }
  /*
   * Print the available ports.
   */
  std::vector<uint16_t> pids;
  uint16_t pid;
  RTE_ETH_FOREACH_DEV(pid)
  {
    pids.push_back(pid);
  }
  FABRIC_LOG("Found " << pids.size() << " ports");
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
  ret = rte_eth_dev_info_get(pids.front(), &dev_info);
  if (ret < 0) {
    throw std::runtime_error("Failed to get device info");
  }

  /*
   * Print some device information.
   */
  FABRIC_LOG("Device name: " << rte_dev_name(dev_info.device));
}

Device::Device(UNUSED std::string const& ifn, UNUSED const uint16_t nbuf)
  : transport::Device("dpdk"), m_address(), m_ip(), m_dr(), m_nm(), m_mtu()
{}

Device::~Device()
{
  rte_eal_cleanup();
}

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
