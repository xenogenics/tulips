#include <tulips/fifo/errors.h>
#include <tulips/stack/Utils.h>
#include <tulips/system/Clock.h>
#include <tulips/system/Compiler.h>
#include <tulips/transport/shm/Device.h>
#include <cstdlib>
#include <ctime>

constexpr const size_t RETRY_COUNT = 1;

namespace tulips::transport::shm {

Device::Device(system::Logger& log, stack::ethernet::Address const& address,
               stack::ipv4::Address const& ip, stack::ipv4::Address const& dr,
               stack::ipv4::Address const& nm, tulips_fifo_t rf,
               tulips_fifo_t wf)
  : transport::Device(log, "shm")
  , m_address(address)
  , m_ip(ip)
  , m_dr(dr)
  , m_nm(nm)
  , read_fifo(rf)
  , write_fifo(wf)
  , m_mutex()
  , m_cond()
{
  pthread_mutex_init(&m_mutex, nullptr);
  pthread_cond_init(&m_cond, nullptr);
}

Device::~Device()
{
  pthread_cond_destroy(&m_cond);
  pthread_mutex_destroy(&m_mutex);
}

Status
Device::poll(Processor& proc)
{
  bool empty = false;
  /*
   * Check the FIFO for data
   */
  for (size_t i = 0; i < RETRY_COUNT; i += 1) {
    empty = tulips_fifo_empty(read_fifo) == TULIPS_FIFO_YES;
    if (!empty) {
      break;
    }
  }
  /*
   * If there is no data, wait if requested otherwise return
   */
  if (empty) {
    return Status::NoDataAvailable;
  }
  /*
   * Process the data
   */
  Packet* packet = nullptr;
  if (tulips_fifo_front(read_fifo, (void**)&packet) != TULIPS_FIFO_OK) {
    return Status::HardwareError;
  }
  m_log.trace("SHM", "processing packet: ", packet->len, "B, ", packet);
  Status ret = proc.process(packet->len, packet->data, system::Clock::read());
  tulips_fifo_pop(read_fifo);
  return ret;
}

Status
Device::wait(Processor& proc, const uint64_t ns)
{
  /*
   * If there is no data, wait if requested otherwise return
   */
  if (waitForInput(ns)) {
    return Status::NoDataAvailable;
  }
  /*
   * Process the data
   */
  return poll(proc);
}

Status
Device::prepare(uint8_t*& buf)
{
  if (tulips_fifo_full(write_fifo) == TULIPS_FIFO_YES) {
    return Status::NoMoreResources;
  }
  Packet* packet = nullptr;
  tulips_fifo_prepare(write_fifo, (void**)&packet);
  m_log.debug("SHM", "preparing packet: ", mss(), "B, ", packet);
  buf = packet->data;
  return Status::Ok;
}

Status
Device::commit(const uint32_t len, uint8_t* const buf,
               UNUSED const uint16_t mss)
{
  auto* packet = (Packet*)(buf - sizeof(uint32_t));
  m_log.trace("SHM", "committing packet: ", len, "B, ", packet);
  packet->len = len;
  tulips_fifo_commit(write_fifo);
  pthread_cond_signal(&m_cond);
  return Status::Ok;
}

Status
Device::drop()
{
  if (tulips_fifo_empty(read_fifo) == TULIPS_FIFO_YES) {
    return Status::NoDataAvailable;
  }
  tulips_fifo_pop(read_fifo);
  return Status::Ok;
}

/*
 * This implementation is very expensive...
 */
bool
Device::waitForInput(const uint64_t ns)
{
  uint32_t us = ns / 1000;
  struct timespec ts = { .tv_sec = 0, .tv_nsec = us == 0 ? 1 : us };
  pthread_mutex_lock(&m_mutex);
  pthread_cond_timedwait(&m_cond, &m_mutex, &ts);
  pthread_mutex_unlock(&m_mutex);
  return tulips_fifo_empty(read_fifo) == TULIPS_FIFO_YES;
}

}
