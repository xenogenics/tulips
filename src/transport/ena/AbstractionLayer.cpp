#include <tulips/system/Logger.h>
#include <tulips/transport/ena/AbstractionLayer.h>
#include <cstdio>
#include <mutex>
#include <stdexcept>
#include <pthread.h>
#include <sched.h>
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
  constexpr const size_t ARG_COUNT = 8;
  /*
   * Define the arguments.
   *
   * NOTE(xrg): regarding CPU affinity, DPDK tries to be smart but, in the end,
   * makes our life very difficult. It uses the exclusion set of the reserved
   * CPU cores (-l) and the current thread's CPU set to affine control threads
   * like the interrupt thread. To force it to use CPU 0, we need to temporarily
   * restrict the current thread's CPU set to 0 so that DPDK would fall back to
   * the main lcore affinity (0).
   */
  const char* const ARGUMENTS[ARG_COUNT] = {
    (char*)"dpdk",
    (char*)"--in-memory",
    (char*)"--no-telemetry",
    (char*)"-l",
    (char*)"0",
    (char*)"--main-lcore=0",
    (char*)"--log-level=*:6",
    nullptr,
  };
  /*
   * Open the pseudo log stream.
   */
  rte_openlog_stream(logfile);
  /*
   * Save the current CPU set.
   */
  cpu_set_t original;
  CPU_ZERO(&original);
  pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t), &original);
  /*
   * Restrict the current CPU set to core 0.
   */
  cpu_set_t restricted;
  CPU_ZERO(&restricted);
  CPU_SET(0, &restricted);
  pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &restricted);
  /*
   * Initialize the abstraction layer.
   */
  int ret = rte_eal_init(ARG_COUNT - 1, (char**)ARGUMENTS);
  if (ret < 0) {
    throw std::runtime_error("Failed to initialize EAL");
  }
  /*
   * Restore the original CPU set.
   */
  pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &original);
}

AbstractionLayer::~AbstractionLayer()
{
  rte_eal_cleanup();
  fclose(m_logfile);
}

}
