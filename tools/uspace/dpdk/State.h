#pragma once

#include <tulips/transport/dpdk/Device.h>
#include <utils/State.h>
#include <set>
#include <string>

namespace tulips::tools::uspace::dpdk {

struct State : public utils::State
{
  State(const bool pcap = false);
  State(std::string const& dev, const bool pcap = false);

  transport::dpdk::Device* device;
};

}
