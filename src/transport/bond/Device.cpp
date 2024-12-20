#include <tulips/stack/Ethernet.h>
#include <tulips/transport/bond/Device.h>
#include <algorithm>
#include <cstdint>
#include <limits>
#include <thread>

namespace tulips::transport::bond {

Device::Device(system::Logger& log, std::vector<transport::Device::Ref> devices,
               std::string_view name)
  : transport::Device(log, name)
  , m_log(log)
  , m_devices(std::move(devices))
  , m_listens(0)
  , m_prepares(0)
{
  /*
   * Check if all devices have the same MAC address.
   */
  auto isValid = std::all_of(
    m_devices.cbegin(), m_devices.cend(), [this](auto const& device) -> bool {
      return device->address() == m_devices.front()->address();
    });
  /*
   * Fail if not.
   */
  if (!isValid) {
    throw std::runtime_error("MAC addresses of bonded devices must identical");
  }
}

Status
Device::listen(const stack::ipv4::Protocol proto,
               stack::ipv4::Address const& laddr, const uint16_t lport,
               stack::ipv4::Address const& raddr, const uint16_t rport)
{
  auto index = m_listens % m_devices.size();
  auto status = m_devices[index]->listen(proto, laddr, lport, raddr, rport);
  if (status == Status::Ok) {
    m_log.debug("BOND", "[", index, "] bound to ", raddr.toString(), ":",
                rport);
    m_listens += 1;
  }
  return status;
}

void
Device::unlisten(const stack::ipv4::Protocol proto,
                 stack::ipv4::Address const& laddr, const uint16_t lport,
                 stack::ipv4::Address const& raddr, const uint16_t rport)
{
  for (auto& device : m_devices) {
    device->unlisten(proto, laddr, lport, raddr, rport);
  }
}

Status
Device::poll(Processor& proc)
{
  auto result = Status::NoDataAvailable;
  /*
   * Poll all the devices.
   */
  for (auto& device : m_devices) {
    switch (auto status = device->poll(proc)) {
      case Status::Ok: {
        result = Status::Ok;
        break;
      }
      case Status::NoDataAvailable: {
        break;
      }
      default: {
        return status;
      }
    }
  }
  /*
   * Done.
   */
  return result;
}

Status
Device::wait(Processor& proc, const uint64_t ns)
{
  /*
   * TODO(xrg): ideally we would need a smarter system that would allow us to
   * wait on shared completion queues. Sleeping is acceptable as we never really
   * wait anyway.
   */
  std::this_thread::sleep_for(std::chrono::nanoseconds(ns));
  return Device::poll(proc);
}

uint16_t
Device::receiveBuffersAvailable() const
{
  uint16_t count = std::numeric_limits<uint16_t>::max();
  /*
   * Compute the lowest amount of buffers among the devices.
   */
  for (auto const& device : m_devices) {
    if (device->receiveBuffersAvailable() < count) {
      count = device->receiveBuffersAvailable();
    }
  }
  /*
   * Done.
   */
  return count;
}

bool
Device::identify(const uint8_t* const buf) const
{
  /*
   * Scan the bound devices for a match.
   */
  for (auto const& device : m_devices) {
    if (device->identify(buf)) {
      return true;
    }
  }
  /*
   * Not found otherwise.
   */
  return false;
}

Status
Device::prepare(uint8_t*& buf)
{
  auto index = m_prepares++ % m_devices.size();
  return m_devices[index]->prepare(buf);
}

Status
Device::commit(const uint16_t len, uint8_t* const buf, const uint16_t mss)
{
  /*
   * Commit the buffer on the owning device.
   */
  for (auto& device : m_devices) {
    if (device->identify(buf)) {
      return device->commit(len, buf, mss);
    }
  }
  /*
   * Fail if not found.
   */
  return Status::InvalidArgument;
}

Status
Device::release(uint8_t* const buf)
{
  /*
   * Release the buffer on the owning device.
   */
  for (auto& device : m_devices) {
    if (device->identify(buf)) {
      return device->release(buf);
    }
  }
  /*
   * Fail if not found.
   */
  return Status::InvalidArgument;
}

}
