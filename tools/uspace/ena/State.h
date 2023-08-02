#pragma once

#include <tulips/transport/ena/Device.h>
#include <tulips/transport/ena/Port.h>
#include <map>
#include <string>
#include <uspace/ena/Poller.h>
#include <utils/State.h>

namespace tulips::tools::uspace::ena {

using IDs = std::map<Client::ID, size_t>;

struct State : public utils::State
{
  State(std::string const& iff, const bool pcap = false);

  std::string interface;
  transport::ena::Port port;
  bool with_pcap;
  std::vector<poller::Poller::Ref> pollers;
  IDs ids;
};

}
