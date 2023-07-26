#include <uspace/dpdk/State.h>

namespace tulips::tools::uspace::dpdk {

State::State(std::string const& iff, const bool pcap)
  : utils::State(), interface(iff), port(iff, 8, 32), with_pcap(pcap), pollers()
{}

}
