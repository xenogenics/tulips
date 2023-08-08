#include <tulips/stack/ARP.h>
#include <tulips/system/Utils.h>

#ifdef ARP_VERBOSE
#define ARP_LOG(__args) LOG("ARP", __args)
#else
#define ARP_LOG(...)
#endif

namespace tulips::stack::arp {

namespace stub {

extern bool lookup(std::string_view eth, ipv4::Address const& ip,
                   ethernet::Address& hw);

}

bool
lookup(std::string_view eth, tulips::stack::ipv4::Address const& ip,
       tulips::stack::ethernet::Address& hw)
{
  if (stub::lookup(eth, ip, hw)) {
    ARP_LOG(ip.toString() << " -> " << hw.toString());
    return true;
  }
  return false;
}

}
