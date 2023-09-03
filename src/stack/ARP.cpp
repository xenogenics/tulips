#include <tulips/stack/ARP.h>
#include <tulips/system/Logger.h>
#include <tulips/system/Utils.h>

namespace tulips::stack::arp {

namespace stub {

extern bool lookup(system::Logger& log, std::string_view eth,
                   ipv4::Address const& ip, ethernet::Address& hw);

}

bool
lookup(system::Logger& log, std::string_view eth,
       tulips::stack::ipv4::Address const& ip,
       tulips::stack::ethernet::Address& hw)
{
  if (stub::lookup(log, eth, ip, hw)) {
    log.debug("ARP", ip.toString(), " -> ", hw.toString());
    return true;
  }
  return false;
}

}
