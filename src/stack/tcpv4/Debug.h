#pragma once

#include <tulips/stack/TCPv4.h>
#include <string>

#ifdef TCP_FLOW_VERBOSE
#define TCP_FLOW(__args) LOG("PKT", __args)
#else
#define TCP_FLOW(...) ((void)0)
#endif

std::string getFlags(tulips::stack::tcpv4::Header const& hdr);
