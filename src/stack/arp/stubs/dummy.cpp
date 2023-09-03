#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/system/Compiler.h>
#include <tulips/system/Logger.h>

namespace tulips::stack::arp::stub {

bool
lookup(UNUSED system::Logger& log, UNUSED std::string_view eth,
       UNUSED tulips::stack::ipv4::Address const& ip,
       UNUSED tulips::stack::ethernet::Address& hw)
{
  return false;
}

}
