#include <uspace/dpdk/State.h>

namespace tulips::tools::uspace::dpdk {

State::State(UNUSED const bool pcap) : utils::State() {}

State::State(UNUSED std::string const& dev, UNUSED const bool pcap)
  : utils::State(), device(nullptr)
{}

}
