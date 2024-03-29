#include <tulips/system/Clock.h>
#include <tulips/system/Compiler.h>
#include <tulips/system/Utils.h>
#include <tulips/transport/npipe/Device.h>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <stdexcept>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

namespace tulips::transport::npipe {

/*
 * Base device class
 */

Device::Device(system::Logger& log, stack::ethernet::Address const& address,
               stack::ipv4::Address const& ip, stack::ipv4::Address const& nm,
               stack::ipv4::Address const& dr)
  : transport::Device(log, "npipe")
  , m_address(address)
  , m_ip(ip)
  , m_dr(dr)
  , m_nm(nm)
  , m_read_buffer()
  , m_write_buffer()
  , m_rdfd(-1)
  , m_wrfd(-1)
  , m_sent(0)
{
  memset(m_read_buffer, 0, BUFLEN);
  memset(m_write_buffer, 0, BUFLEN);
  signal(SIGPIPE, SIG_IGN);
  m_log.debug("NPIPE", "IP address: ", ip.toString());
  m_log.debug("NPIPE", "netmask: ", nm.toString());
  m_log.debug("NPIPE", "default router: ", dr.toString());
}

Status
Device::prepare(uint8_t*& buf)
{
  m_log.debug("NPIPE", "preparing ", mss(), "B");
  buf = m_write_buffer;
  return Status::Ok;
}

Status
Device::commit(const uint16_t len, uint8_t* const buf,
               UNUSED const uint16_t mss)
{
  /*
   * Send the length first.
   */
  if (!write(sizeof(len), (uint8_t*)&len)) {
    m_log.error("NPIPE", "write error: ", strerror(errno));
    return Status::HardwareLinkLost;
  }
  /*
   * Send the payload.
   */
  if (!write(len, buf)) {
    m_log.error("NPIPE", "write error: ", strerror(errno));
    return Status::HardwareLinkLost;
  }
  /*
   * Success.
   */
  m_log.debug("NPIPE", "commit ", len, "B");
  m_sent = true;
  return Status::Ok;
}

Status
Device::release(UNUSED uint8_t* const buf)
{
  m_log.trace("NPIPE", "releasing buffer ", (void*)buf);
  /*
   * NOTE(xrg): the NPIPE device does not support out-of-order buffer release.
   */
  return Status::Ok;
}

Status
Device::poll(Processor& proc)
{
  ssize_t ret = 0;
  uint32_t len = 0;
  /*
   * Check if any data was sent.
   */
  if (m_sent > 0) {
    auto ret = proc.sent(m_sent, m_write_buffer);
    if (ret != Status::Ok) {
      return ret;
    }
    m_sent = 0;
  }
  /*
   * Read length first.
   */
  ret = ::read(m_rdfd, &len, sizeof(len));
  if (ret < 0) {
    if (errno == EAGAIN) {
      return Status::NoDataAvailable;
    }
    m_log.error("NPIPE", "read error: ", strerror(errno));
    return Status::HardwareLinkLost;
  }
  if (ret == 0) {
    m_log.error("NPIPE", "read error: ", strerror(errno));
    return Status::HardwareLinkLost;
  }
  /*
   * Now read the payload.
   */
  do {
    ret = ::read(m_rdfd, m_read_buffer, len);
    if (ret == 0 || (ret < 0 && errno != EAGAIN)) {
      m_log.error("NPIPE", "read error: ", strerror(errno));
      return Status::HardwareLinkLost;
    }
  } while (ret < 0);
  /*
   * Process the data.
   */
  m_log.debug("NPIPE", "process ", len, "B");
  return proc.process(len, m_read_buffer, system::Clock::now());
}

Status
Device::wait(Processor& proc, const uint64_t ns)
{
  if (waitForInput(ns) == 0) {
    return Status::NoDataAvailable;
  }
  return poll(proc);
}

int
Device::waitForInput(const uint64_t ns)
{
  int us = static_cast<int>(ns / 1000);
  struct timeval tv = { .tv_sec = 0, .tv_usec = us == 0 ? 1 : us };

  fd_set fdset;
  FD_ZERO(&fdset);
  FD_SET(m_rdfd, &fdset);

  return ::select(m_rdfd + 1, &fdset, nullptr, nullptr, &tv);
}

/*
 * Client device class
 */

ClientDevice::ClientDevice(system::Logger& log,
                           stack::ethernet::Address const& address,
                           stack::ipv4::Address const& ip,
                           stack::ipv4::Address const& nm,
                           stack::ipv4::Address const& dr, std::string_view rf,
                           std::string_view wf)
  : Device(log, address, ip, nm, dr)
{
  /*
   * Print some information.
   */
  m_log.debug("NPIPE", "read fifo: ", rf);
  m_log.debug("NPIPE", "write fifo: ", wf);
  /*
   * Open the FIFOs.
   */
  auto rp = std::string(rf);
  m_rdfd = open(rp.c_str(), O_RDONLY);
  if (m_rdfd < 0) {
    throw std::runtime_error(strerror(errno));
  }
  if (fcntl(m_rdfd, F_SETFL, O_NONBLOCK)) {
    throw std::runtime_error(strerror(errno));
  }
  auto wp = std::string(wf);
  m_wrfd = open(wp.c_str(), O_WRONLY);
  if (m_wrfd < 0) {
    throw std::runtime_error(strerror(errno));
  }
}

/*
 * Server device class
 */

ServerDevice::ServerDevice(system::Logger& log,
                           stack::ethernet::Address const& address,
                           stack::ipv4::Address const& ip,
                           stack::ipv4::Address const& nm,
                           stack::ipv4::Address const& dr, std::string_view rf,
                           std::string_view wf)
  : Device(log, address, ip, nm, dr), m_rf(rf), m_wf(wf)
{
  int ret = 0;
  /*
   * Print some information.
   */
  m_log.debug("NPIPE", "read fifo: ", rf);
  m_log.debug("NPIPE", "write fifo: ", wf);
  /*
   * Erase the FIFOs
   */
  unlink(m_rf.c_str());
  unlink(m_wf.c_str());
  /*
   * Create the FIFOs
   */
  ret = mkfifo(m_rf.c_str(), S_IRUSR | S_IWUSR);
  if (ret) {
    throw std::runtime_error(strerror(errno));
  }
  ret = mkfifo(m_wf.c_str(), S_IRUSR | S_IWUSR);
  if (ret) {
    throw std::runtime_error(strerror(errno));
  }
  /*
   * Open the FIFOs
   */
  m_wrfd = open(m_wf.c_str(), O_WRONLY);
  if (m_wrfd < 0) {
    throw std::runtime_error(strerror(errno));
  }
  sleep(1);
  m_rdfd = open(m_rf.c_str(), O_RDONLY);
  if (m_rdfd < 0) {
    throw std::runtime_error(strerror(errno));
  }
  if (fcntl(m_rdfd, F_SETFL, O_NONBLOCK)) {
    throw std::runtime_error(strerror(errno));
  }
}

ServerDevice::~ServerDevice()
{
  /*
   * Erase the FIFOs
   */
  unlink(m_rf.c_str());
  unlink(m_wf.c_str());
}

}
