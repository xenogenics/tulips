#include <uspace/dpdk/State.h>

namespace tulips::tools::uspace::dpdk {

State::State(const bool pcap) : utils::State(), poller(pcap), ids() {}

State::State(std::string const& dev, const bool pcap)
  : utils::State(), poller(dev, pcap), ids()
{}

}
