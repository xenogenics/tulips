#pragma once

#include <set>
#include <string>
#include <uspace/ofed/Poller.h>
#include <utils/State.h>

namespace tulips::tools::uspace::ofed {

using IDs = std::set<Client::ID>;

struct State : public utils::State
{
  State(const bool pcap = false);
  State(std::string const& dev, const bool pcap = false);

  Poller poller;
  IDs ids;
};

}
