#pragma once

#include <utils/State.h>
#include <cstdint>
#include <set>

namespace tulips::tools::socket::server {

using Ports = std::set<uint16_t>;

struct State : public utils::State
{
  State();

  Ports ports;
};

}
