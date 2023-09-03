#include <tulips/transport/erase/Device.h>
#include <cstdlib>
#include <cstring>

namespace tulips::transport::erase {

Device::Device(system::Logger& log, transport::Device& device)
  : transport::Device(log, "erase"), m_device(device)
{}

Status
Device::poll(Processor& proc)
{
  return m_device.poll(proc);
}

Status
Device::wait(Processor& proc, const uint64_t ns)
{
  return m_device.wait(proc, ns);
}

Status
Device::prepare(uint8_t*& buf)
{
  Status ret = m_device.prepare(buf);
  if (ret == Status::Ok) {
    memset(buf, 0, mss());
  }
  return ret;
}

Status
Device::commit(const uint32_t len, uint8_t* const buf, const uint16_t mss)
{
  return m_device.commit(len, buf, mss);
}

}
