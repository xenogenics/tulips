#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/transport/Utils.h>
#include <string>

namespace tulips::transport::utils {

bool
getInterfaceInformation(UNUSED std::string_view ifn,
                        UNUSED stack::ethernet::Address& hwaddr,
                        UNUSED uint32_t& mtu)
{
  return false;
}

bool
getInterfaceInformation(UNUSED std::string_view ifn,
                        UNUSED stack::ethernet::Address& hwaddr,
                        UNUSED uint32_t& mtu,
                        UNUSED stack::ipv4::Address& ipaddr,
                        UNUSED stack::ipv4::Address& draddr,
                        UNUSED stack::ipv4::Address& ntmask)
{
  return false;
}

}
