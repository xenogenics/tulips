#include <uspace/ena/State.h>

namespace tulips::tools::uspace::ena {

State::State(std::string const& iff, const bool pcap)
  : utils::State(), interface(iff), port(iff, 8, 32), with_pcap(pcap), pollers()
{}

}
