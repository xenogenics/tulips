#include <uspace/ofed/State.h>

namespace tulips::tools::uspace::ofed {

State::State(system::Logger& log, const bool pcap)
  : utils::State(), poller(log, pcap), ids()
{}

State::State(system::Logger& log, std::string_view dev, const bool pcap)
  : utils::State(), poller(log, dev, pcap), ids()
{}

}
