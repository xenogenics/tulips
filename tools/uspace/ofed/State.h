#pragma once

#include <set>
#include <string>
#include <uspace/ofed/Poller.h>
#include <utils/State.h>

namespace tulips::tools::uspace::ofed {

using IDs = std::set<api::Client::ID>;

struct State : public utils::State
{
  State(stack::ipv4::Address const& ip, stack::ipv4::Address const& dr,
        stack::ipv4::Address const& nm, const bool pcap = false);
  State(std::string_view dev, stack::ipv4::Address const& ip,
        stack::ipv4::Address const& dr, stack::ipv4::Address const& nm,
        const bool pcap = false);

  Poller poller;
  IDs ids;
};

}
