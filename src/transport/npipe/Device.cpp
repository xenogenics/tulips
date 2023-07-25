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

#define NPIPE_VERBOSE 0
#define NPIPE_HEXDUMP 0

#if NPIPE_VERBOSE
#define NPIPE_LOG(__args) LOG("NPIPE", __args)
#else
#define NPIPE_LOG(...) ((void)0)
#endif

namespace tulips::transport::npipe {

/*
 * Base device class
 */

Device::Device(stack::ethernet::Address const& address,
               stack::ipv4::Address const& ip, stack::ipv4::Address const& nm,
               stack::ipv4::Address const& dr)
  : transport::Device("npipe")
  , m_address(address)
  , m_ip(ip)
  , m_dr(dr)
  , m_nm(nm)
  , m_read_buffer()
  , m_write_buffer()
  , read_fd(-1)
  , write_fd(-1)
{
  memset(m_read_buffer, 0, BUFLEN);
  memset(m_write_buffer, 0, BUFLEN);
  signal(SIGPIPE, SIG_IGN);
  LOG("NPIPE", "IP address: " << ip.toString());
  LOG("NPIPE", "netmask: " << nm.toString());
  LOG("NPIPE", "default router: " << dr.toString());
}

Status
Device::prepare(uint8_t*& buf)
{
  NPIPE_LOG("prepare " << mss() << "B");
  buf = m_write_buffer;
  return Status::Ok;
}

Status
Device::commit(const uint32_t len, uint8_t* const buf,
               UNUSED const uint16_t mss)
{
  /*
   * Send the length first.
   */
  if (!write(sizeof(len), (uint8_t*)&len)) {
    LOG("NPIPE", "write error: " << strerror(errno));
    return Status::HardwareLinkLost;
  }
  /*
   * Send the payload.
   */
  if (!write(len, buf)) {
    LOG("NPIPE", "write error: " << strerror(errno));
    return Status::HardwareLinkLost;
  }
  /*
   * Success.
   */
  NPIPE_LOG("commit " << len << "B => " << ret << "B");
#if NPIPE_VERBOSE && NPIPE_HEXDUMP
  stack::utils::hexdump(buf, len, std::cout);
#endif
  return Status::Ok;
}

Status
Device::poll(Processor& proc)
{
  ssize_t ret = 0;
  uint32_t len = 0;
  /*
   * Read length first.
   */
  ret = ::read(read_fd, &len, sizeof(len));
  if (ret < 0) {
    if (errno == EAGAIN) {
      return Status::NoDataAvailable;
    }
    LOG("NPIPE", "read error: " << strerror(errno));
    return Status::HardwareLinkLost;
  }
  if (ret == 0) {
    LOG("NPIPE", "read error: " << strerror(errno));
    return Status::HardwareLinkLost;
  }
  /*
   * Now read the payload.
   */
  do {
    ret = ::read(read_fd, m_read_buffer, len);
    if (ret == 0 || (ret < 0 && errno != EAGAIN)) {
      LOG("NPIPE", "read error: " << strerror(errno));
      return Status::HardwareLinkLost;
    }
  } while (ret < 0);
  /*
   * Process the data.
   */
  NPIPE_LOG("process " << len << "B");
#if NPIPE_VERBOSE && NPIPE_HEXDUMP
  stack::utils::hexdump(m_read_buffer, len, std::cout);
#endif
  return proc.process(len, m_read_buffer);
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
  FD_SET(read_fd, &fdset);

  return ::select(read_fd + 1, &fdset, nullptr, nullptr, &tv);
}

/*
 * Client device class
 */

ClientDevice::ClientDevice(stack::ethernet::Address const& address,
                           stack::ipv4::Address const& ip,
                           stack::ipv4::Address const& nm,
                           stack::ipv4::Address const& dr,
                           std::string const& rf, std::string const& wf)
  : Device(address, ip, nm, dr)
{
  /*
   * Print some information.
   */
  LOG("NPIPE", "read fifo: " << rf);
  LOG("NPIPE", "write fifo: " << wf);
  /*
   * Open the FIFOs.
   */
  read_fd = open(rf.c_str(), O_RDONLY);
  if (read_fd < 0) {
    throw std::runtime_error(strerror(errno));
  }
  if (fcntl(read_fd, F_SETFL, O_NONBLOCK)) {
    throw std::runtime_error(strerror(errno));
  }
  write_fd = open(wf.c_str(), O_WRONLY);
  if (write_fd < 0) {
    throw std::runtime_error(strerror(errno));
  }
}

/*
 * Server device class
 */

ServerDevice::ServerDevice(stack::ethernet::Address const& address,
                           stack::ipv4::Address const& ip,
                           stack::ipv4::Address const& nm,
                           stack::ipv4::Address const& dr,
                           std::string const& rf, std::string const& wf)
  : Device(address, ip, nm, dr), m_rf(rf), m_wf(wf)
{
  int ret = 0;
  /*
   * Print some information.
   */
  LOG("NPIPE", "read fifo: " << rf);
  LOG("NPIPE", "write fifo: " << wf);
  /*
   * Erase the FIFOs
   */
  unlink(rf.c_str());
  unlink(wf.c_str());
  /*
   * Create the FIFOs
   */
  ret = mkfifo(rf.c_str(), S_IRUSR | S_IWUSR);
  if (ret) {
    throw std::runtime_error(strerror(errno));
  }
  ret = mkfifo(wf.c_str(), S_IRUSR | S_IWUSR);
  if (ret) {
    throw std::runtime_error(strerror(errno));
  }
  /*
   * Open the FIFOs
   */
  write_fd = open(wf.c_str(), O_WRONLY);
  if (write_fd < 0) {
    throw std::runtime_error(strerror(errno));
  }
  sleep(1);
  read_fd = open(rf.c_str(), O_RDONLY);
  if (read_fd < 0) {
    throw std::runtime_error(strerror(errno));
  }
  if (fcntl(read_fd, F_SETFL, O_NONBLOCK)) {
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
