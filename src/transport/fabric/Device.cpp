#include <cstdint>
#include <tulips/transport/fabric/Device.h>
#include <tulips/system/Compiler.h>
#include <cstdlib>
#include <ctime>

#define FABRIC_VERBOSE 1

#if FABRIC_VERBOSE
#define FABRIC_LOG(__args) LOG("FABRIC", __args)
#else
#define FABRIC_LOG(...) ((void)0)
#endif

namespace tulips::transport::fabric {

Device::Device(UNUSED const uint16_t nbuf)
  : transport::Device("fabric"), m_address(), m_ip(), m_dr(), m_nm(), m_mtu()
{}

Device::Device(UNUSED std::string const& ifn, UNUSED const uint16_t nbuf)
  : transport::Device("fabric"), m_address(), m_ip(), m_dr(), m_nm(), m_mtu()
{}

Status
Device::poll(UNUSED Processor& proc)
{
  return Status::UnsupportedOperation;
}

Status
Device::wait(UNUSED Processor& proc, UNUSED const uint64_t ns)
{
  return Status::UnsupportedOperation;
}

Status
Device::prepare(UNUSED uint8_t*& buf)
{
  return Status::UnsupportedOperation;
}

Status
Device::commit(UNUSED const uint32_t len, UNUSED uint8_t* const buf,
               UNUSED const uint16_t mss)
{
  return Status::UnsupportedOperation;
}

}
