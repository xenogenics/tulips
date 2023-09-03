#include <uspace/ofed/State.h>

namespace tulips::tools::uspace::ofed {

State::State(const bool pcap) : utils::State(), poller(logger, pcap), ids() {}

State::State(std::string_view dev, const bool pcap)
  : utils::State(), poller(logger, dev, pcap), ids()
{}

}
