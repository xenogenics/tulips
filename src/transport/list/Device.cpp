#include <tulips/system/Clock.h>
#include <tulips/system/Compiler.h>
#include <tulips/system/Utils.h>
#include <tulips/transport/list/Device.h>
#include <algorithm>
#include <cstdlib>
#include <ctime>

namespace tulips::transport::list {

Device::Device(system::Logger& log, stack::ethernet::Address const& address,
               const uint32_t mtu, List& rf, List& wf)
  : transport::Device(log, "list")
  , m_packets()
  , m_address(address)
  , m_mtu(mtu)
  , m_read(rf)
  , m_write(wf)
  , m_sent()
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
  /*
   * Process the sent packets.
   */
  while (!m_sent.empty()) {
    auto p = m_sent.front();
    m_sent.pop_front();
    m_log.trace("LIST", "packet sent: ", p);
    auto ret = proc.sent(p->len, p->data);
    if (ret != Status::Ok) {
      return ret;
    }
  }
  /*
   * If there is no data, return.
   */
  if (m_read.empty()) {
    return Status::NoDataAvailable;
  }
  /*
   * Process the data.
   */
  Packet* packet = m_read.front();
  m_log.trace("LIST", "processing packet: ", size_t(packet->len), "B, ",
              packet);
  Status ret = proc.process(packet->len, packet->data, system::Clock::read());
  m_read.pop_front();
  Packet::release(packet);
  return ret;
}

Status
Device::wait(Processor& proc, const uint64_t ns)
{
  /*
   * If there is no data, wait if requested otherwise return
   */
  if (m_read.empty() && waitForInput(ns)) {
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
  auto packet = Packet::allocate(m_mtu);
  m_log.debug("LIST", "preparing packet: ", mss(), "B, ", packet);
  buf = packet->data;
  m_packets.push_back(packet);
  return Status::Ok;
}

Status
Device::commit(const uint16_t len, uint8_t* const buf,
               UNUSED const uint16_t mss)
{
  auto packet = (Packet*)(buf - sizeof(Packet));
  m_log.trace("LIST", "committing packet: ", len, "B, ", packet);
  packet->len = len;
  m_packets.remove(packet);
  m_write.push_back(packet->clone());
  m_sent.push_back(packet);
  pthread_cond_signal(&m_cond);
  return Status::Ok;
}

Status
Device::release(uint8_t* const buf)
{
  auto packet = (Packet*)(buf - sizeof(Packet));
  m_log.trace("LIST", "releasing packet: ", packet);
  Packet::release(packet);
  return Status::Ok;
}

Status
Device::drop()
{
  if (m_read.empty()) {
    return Status::NoDataAvailable;
  }
  auto packet = m_read.front();
  m_read.pop_front();
  Packet::release(packet);
  return Status::Ok;
}

/*
 * This implementation is very expensive...
 */
bool
Device::waitForInput(const uint64_t ns)
{
  uint32_t us = ns / 1000;
  struct timespec ts = { .tv_sec = 0, .tv_nsec = us == 0 ? 1000 : us };
  pthread_cond_timedwait(&m_cond, &m_mutex, &ts);
  return m_read.empty();
}

}
