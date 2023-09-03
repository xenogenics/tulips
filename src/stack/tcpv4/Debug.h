#pragma once

#include <tulips/stack/TCPv4.h>
#include <string>

std::string getFlags(tulips::stack::tcpv4::Header const& hdr);
