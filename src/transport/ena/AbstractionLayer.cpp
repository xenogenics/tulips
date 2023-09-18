#include <tulips/transport/ena/AbstractionLayer.h>
#include <cstdio>
#include <mutex>
#include <stdexcept>
#include <dpdk/rte_eal.h>
#include <dpdk/rte_log.h>

namespace {

static std::once_flag s_setup;
static std::once_flag s_cleanup;

ssize_t
logWrite(void* cookie, const char* buf, size_t size)
{
  auto& logger = *reinterpret_cast<tulips::system::Logger*>(cookie);
  logger.debug("ENADRV", std::string_view(buf, size - 1));
  return size;
}

}

namespace tulips::transport::ena {

AbstractionLayer::AbstractionLayer(system::Logger& logger)
  : m_args(), m_logfile(nullptr)
{
  std::call_once(s_setup, [this, &logger]() {
    /*
     * Build the arguments.
     *
     * NOTE(xrg): using a static variable does not work, for some reason
     * rte_eal_init SIGSEGV when assigning the last item of the array.
     */
    m_args[0] = (char*)"dpdk";
    // m_args[1] = (char*)"--in-memory";
    // m_args[2] = (char*)"--no-telemetry";
    // m_args[3] = (char*)"-c";
    // m_args[4] = (char*)"1";
    // m_args[5] = (char*)"--log-level=*:6";
    m_args[1] = nullptr;
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
    this->m_logfile = fopencookie(&logger, "w", ios);
    /*
     * Open the pseudo log stream.
     */
    rte_openlog_stream(this->m_logfile);
    /*
     * Initialize the abstraction layer.
     */
    int ret = rte_eal_init(1, (char**)m_args);
    if (ret < 0) {
      throw std::runtime_error("Failed to initialize EAL");
    }
  });
}

AbstractionLayer::~AbstractionLayer()
{
  std::call_once(s_cleanup, [this]() {
    if (m_logfile != nullptr) {
      rte_eal_cleanup();
      fclose(m_logfile);
    }
  });
}

}
