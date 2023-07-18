#include <tulips/transport/list/Device.h>
#include <tulips/system/Compiler.h>
#include <cstdlib>
#include <ctime>

#define LIST_VERBOSE 0

#if LIST_VERBOSE
#define LIST_LOG(__args) LOG("LIST", __args)
#else
#define LIST_LOG(...) ((void)0)
#endif

namespace tulips::transport::list {

Device::Device(stack::ethernet::Address const& address,
               stack::ipv4::Address const& ip, stack::ipv4::Address const& dr,
               stack::ipv4::Address const& nm, const uint32_t mtu, List& rf,
               List& wf)
  : transport::Device("shm")
  , m_packets()
  , m_address(address)
  , m_ip(ip)
  , m_dr(dr)
  , m_nm(nm)
  , m_mtu(mtu)
  , m_read(rf)
  , m_write(wf)
  , m_mutex()
  , m_cond()
{
  pthread_mutex_init(&m_mutex, nullptr);
  pthread_cond_init(&m_cond, nullptr);
}

Device::~Device()
{
  /*
   * Deallocate any uncommitted packets.
   */
  for (auto p : m_packets) {
    Packet::release(p);
  }
  m_packets.clear();
  /*
   * Clear resources.
   */
  pthread_cond_destroy(&m_cond);
  pthread_mutex_destroy(&m_mutex);
}

Status
Device::poll(Processor& proc)
{
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
  LIST_LOG("processing packet: " << packet->len << "B, " << packet);
  Status ret = proc.process(packet->len, packet->data);
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
  Packet* packet = m_read.front();
  LIST_LOG("processing packet: " << packet->len << "B, " << packet);
  Status ret = proc.process(packet->len, packet->data);
  m_read.pop_front();
  Packet::release(packet);
  return ret;
}

Status
Device::prepare(uint8_t*& buf)
{
  auto* packet = Packet::allocate(m_mtu);
  LIST_LOG("preparing packet: " << mss() << "B, " << packet);
  buf = packet->data;
  m_packets.push_back(packet);
  return Status::Ok;
}

Status
Device::commit(const uint32_t len, uint8_t* const buf,
               UNUSED const uint16_t mss)
{
  auto* packet = (Packet*)(buf - sizeof(uint32_t));
  LIST_LOG("committing packet: " << len << "B, " << packet);
  packet->len = len;
  m_write.push_back(packet);
  pthread_cond_signal(&m_cond);
  m_packets.remove(packet);
  return Status::Ok;
}

Status
Device::drop()
{
  if (m_read.empty()) {
    return Status::NoDataAvailable;
  }
  Packet* packet = m_read.front();
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
