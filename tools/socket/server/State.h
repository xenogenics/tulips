#pragma once

#include <cstdint>
#include <set>
#include <utils/State.h>

namespace tulips::tools::socket::server {

using Ports = std::set<uint16_t>;

struct State : public utils::State
{
  State();

  Ports ports;
};

}
