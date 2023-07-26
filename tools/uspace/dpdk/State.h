#pragma once

#include <tulips/transport/dpdk/Device.h>
#include <set>
#include <string>
#include <uspace/dpdk/Poller.h>
#include <utils/State.h>

namespace tulips::tools::uspace::dpdk {

using IDs = std::set<Client::ID>;

struct State : public utils::State
{
  State(transport::Device::Ref device, const bool pcap = false);

  Poller poller;
  IDs ids;
};

}
