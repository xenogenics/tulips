#pragma once

#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <string>
#include <cstdint>

namespace tulips::transport::utils {

bool getInterfaceInformation(std::string const& ifn,
                             stack::ethernet::Address& hwaddr, uint32_t& mtu);

bool getInterfaceInformation(std::string const& ifn,
                             stack::ipv4::Address& ipaddr,
                             stack::ipv4::Address& ntmask,
                             stack::ipv4::Address& draddr);

}
