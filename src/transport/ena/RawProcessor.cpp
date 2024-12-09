#include <tulips/stack/Ethernet.h>
#include <tulips/system/SpinLock.h>
#include <tulips/transport/ena/RawProcessor.h>
#include <mutex>
#include <netinet/in.h>

namespace tulips::transport::ena {

Status
RawProcessor::process(const uint16_t len, const uint8_t* const data,
                      const Timestamp ts)
{
  std::lock_guard<system::SpinLock> lock(m_lock);
  const auto* eth = reinterpret_cast<const stack::ethernet::Header*>(data);
  /*
   * Push all non-IP packets to the internal buffers.
   *
   * NOTE(xrg): this is a non-critical process, so we drop the packet if the
   * target buffer is full.
   */
  if (ntohs(eth->type) != stack::ethernet::ETHTYPE_IP) {
    for (auto const& buffer : m_buffers) {
      buffer->push(len, data, ts);
    }
  }
  /*
   * Done.
   */
  return Status::Ok;
}

Status
RawProcessor::sent(UNUSED const uint16_t len, UNUSED uint8_t* const data)
{
  return Status::Ok;
}

void
RawProcessor::add(system::FrameBuffer::Ref const& buffer)
{
  std::lock_guard<system::SpinLock> lock(m_lock);
  m_buffers.push_back(buffer);
}

}
