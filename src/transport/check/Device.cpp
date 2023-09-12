#include <tulips/transport/check/Device.h>
#include <cstdlib>
#include <stdexcept>

namespace tulips::transport::check {

Device::Device(system::Logger& log, transport::Device& device)
  : transport::Device(log, "check")
  , m_device(device)
  , m_proc(nullptr)
  , m_buffer(nullptr)
{}

Status
Device::poll(Processor& proc)
{
  m_proc = &proc;
  return m_device.poll(*this);
}

Status
Device::wait(Processor& proc, const uint64_t ns)
{
  m_proc = &proc;
  return m_device.wait(*this, ns);
}

Status
Device::process(const uint16_t len, const uint8_t* const data,
                const Timestamp ts)
{
  if (!check(data, len)) {
    throw std::runtime_error("Empty packet has been received !");
  }
  return m_proc->process(len, data, ts);
}

Status
Device::prepare(uint8_t*& buf)
{
  Status ret = m_device.prepare(buf);
  m_buffer = buf;
  return ret;
}

Status
Device::commit(const uint32_t len, uint8_t* const buf, const uint16_t mss)
{
  if (!check(m_buffer, len)) {
    throw std::runtime_error("Empty packet has been received !");
  }
  return m_device.commit(len, buf, mss);
}

bool
Device::check(const uint8_t* const data, const size_t len)
{
  for (size_t i = 0; i < len; i += 1) {
    if (data[i] != 0) {
      return true;
    }
  }
  return false;
}

}
