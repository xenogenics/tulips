#pragma once

#include <uspace/dpdk/Poller.h>
#include <utils/State.h>
#include <set>
#include <string>

namespace tulips::tools::uspace::dpdk {

using IDs = std::set<Client::ID>;

struct State : public utils::State
{
  State(const bool pcap = false);
  State(std::string const& dev, const bool pcap = false);

  Poller poller;
  IDs ids;
};

}
