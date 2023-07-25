#pragma once

#include <tulips/stack/IPv4.h>
#include <map>
#include <utils/State.h>

namespace tulips::tools::socket::client {

using Connection = std::pair<stack::ipv4::Address, uint16_t>;
using Connections = std::map<int, Connection>;

struct State : public utils::State
{
  State();

  Connections connections;
};

}
