#include <tulips/transport/dpdk/AbstractionLayer.h>
#include <stdexcept>
#include <dpdk/rte_eal.h>

namespace tulips::transport::dpdk {

AbstractionLayer::AbstractionLayer()
{
  const char* const arguments[] = {
    "dpdk", "--in-memory", "--no-telemetry", "-c", "1", "--log-level=lib.*:6"
  };
  int ret = rte_eal_init(6, (char**)arguments);
  if (ret < 0) {
    throw std::runtime_error("Failed to initialize EAL");
  }
}

AbstractionLayer::~AbstractionLayer()
{
  rte_eal_cleanup();
}

}
