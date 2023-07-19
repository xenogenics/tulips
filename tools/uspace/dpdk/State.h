#pragma once

#include <tulips/transport/dpdk/Device.h>
#include <set>
#include <string>
#include <uspace/dpdk/Poller.h>
#include <utils/State.h>

namespace tulips::tools::uspace::dpdk {

struct State : public utils::State
{
  State(std::string const& dev, stack::ipv4::Address const& ip,
        stack::ipv4::Address const& dr, stack::ipv4::Address const& nm,
        const bool pcap = false);

  Poller poller;
};

}
