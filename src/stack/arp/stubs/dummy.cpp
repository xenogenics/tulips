#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/system/Compiler.h>

namespace tulips::stack::arp::stub {

bool
lookup(UNUSED std::string const& eth,
       UNUSED tulips::stack::ipv4::Address const& ip,
       UNUSED tulips::stack::ethernet::Address& hw)
{
  return false;
}

}
