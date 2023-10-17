#include <uspace/ofed/State.h>

namespace tulips::tools::uspace::ofed {

State::State(stack::ipv4::Address const& ip, stack::ipv4::Address const& dr,
             stack::ipv4::Address const& nm, const bool pcap)
  : utils::State(), poller(logger, ip, dr, nm, pcap), ids()
{}

State::State(std::string_view dev, stack::ipv4::Address const& ip,
             stack::ipv4::Address const& dr, stack::ipv4::Address const& nm,
             const bool pcap)
  : utils::State(), poller(logger, dev, ip, dr, nm, pcap), ids()
{}

}
