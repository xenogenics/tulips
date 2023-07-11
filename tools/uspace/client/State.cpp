#include <uspace/client/State.h>

namespace tulips::tools::uspace::client {

State::State(const bool pcap) : utils::State(), poller(pcap), ids() {}

State::State(std::string const& dev, const bool pcap)
  : utils::State(), poller(dev, pcap), ids()
{}

}
