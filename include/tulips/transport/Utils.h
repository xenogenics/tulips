#pragma once

#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/system/Logger.h>
#include <cstdint>
#include <string>

namespace tulips::transport::utils {

bool getInterfaceInformation(system::Logger& log, std::string_view ifn,
                             stack::ethernet::Address& hwaddr, uint32_t& mtu);

bool getInterfaceInformation(system::Logger& log, std::string_view ifn,
                             stack::ipv4::Address& ipaddr,
                             stack::ipv4::Address& ntmask,
                             stack::ipv4::Address& draddr);

}
