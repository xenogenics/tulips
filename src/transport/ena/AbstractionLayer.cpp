#include "tulips/system/Logger.h"
#include <tulips/transport/ena/AbstractionLayer.h>
#include <cstdio>
#include <mutex>
#include <stdexcept>
#include <dpdk/rte_eal.h>
#include <dpdk/rte_log.h>

namespace {

ssize_t
logWrite(void* cookie, const char* buf, size_t size)
{
  auto& logger = *reinterpret_cast<tulips::system::Logger*>(cookie);
  logger.debug("ENADRV", std::string_view(buf, size - 1));
  return size;
}

}

namespace tulips::transport::ena {

AbstractionLayer::Ref
AbstractionLayer::allocate(system::Logger& log)
{
  /*
   * Define the cookie IOs.
   */
  cookie_io_functions_t ios = {
    .read = nullptr,
    .write = logWrite,
    .seek = nullptr,
    .close = nullptr,
  };
  /*
   * Create the pseudo log file.
   */
  auto logfile = fopencookie(&log, "w", ios);
  /*
   * Buile the EAL.
   */
  return Ref(new AbstractionLayer(logfile));
}

AbstractionLayer::AbstractionLayer(FILE* const logfile) : m_logfile(logfile)
{
  /*
   * Define the arguments.
   */
  const char* const ARGUMENTS[7] = {
    (char*)"dpdk", (char*)"--in-memory", (char*)"--no-telemetry",
    (char*)"-c",   (char*)"1",           (char*)"--log-level=*:6",
    nullptr,
  };
  /*
   * Open the pseudo log stream.
   */
  rte_openlog_stream(logfile);
  /*
   * Initialize the abstraction layer.
   */
  int ret = rte_eal_init(6, (char**)ARGUMENTS);
  if (ret < 0) {
    throw std::runtime_error("Failed to initialize EAL");
  }
}

AbstractionLayer::~AbstractionLayer()
{
  rte_eal_cleanup();
  fclose(m_logfile);
}

}
