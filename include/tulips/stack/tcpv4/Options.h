#pragma once

#include <tulips/system/Compiler.h>
#include <cstdint>

namespace tulips::stack::tcpv4 {

class Connection;

namespace Options {

static constexpr int USED END = 0;     // End of TCP options list
static constexpr int USED NOOP = 1;    // "No-operation" TCP option
static constexpr int USED MSS = 2;     // Maximum segment size TCP option
static constexpr int USED MSS_LEN = 4; // Length of TCP MSS option
static constexpr int USED WSC = 3;     // Window scaling option
static constexpr int USED WSC_LEN = 3; // Length of the TCP WSC option

void parse(Connection& e, const uint16_t len, const uint8_t* const data);

}

}
