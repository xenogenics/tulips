#pragma once

#include <uspace/fabric/Poller.h>
#include <utils/State.h>
#include <set>
#include <string>

namespace tulips::tools::uspace::fabric {

using IDs = std::set<Client::ID>;

struct State : public utils::State
{
  State(const bool pcap = false);
  State(std::string const& dev, const bool pcap = false);

  Poller poller;
  IDs ids;
};

}
