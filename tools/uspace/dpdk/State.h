#pragma once

#include <tulips/transport/dpdk/Device.h>
#include <tulips/transport/dpdk/Port.h>
#include <map>
#include <string>
#include <uspace/dpdk/Poller.h>
#include <utils/State.h>

namespace tulips::tools::uspace::dpdk {

using IDs = std::map<Client::ID, size_t>;

struct State : public utils::State
{
  State(std::string const& iff, const bool pcap = false);

  std::string interface;
  transport::dpdk::Port port;
  bool with_pcap;
  std::vector<poller::Poller::Ref> pollers;
  IDs ids;
};

}
