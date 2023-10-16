#include <tulips/transport/bond/Device.h>

namespace tulips::transport::bond {

Device::Device(system::Logger& log, std::vector<transport::Device::Ref> devices,
               std::string_view name)
  : transport::Device(log, name), m_devices(std::move(devices))
{}

}
