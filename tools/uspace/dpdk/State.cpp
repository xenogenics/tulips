#include <uspace/dpdk/State.h>

namespace tulips::tools::uspace::dpdk {

State::State(transport::Device::Ref device, const bool pcap)
  : utils::State(), poller(std::move(device), pcap)
{}

}
