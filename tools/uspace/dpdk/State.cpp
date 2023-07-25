#include <uspace/dpdk/State.h>

namespace tulips::tools::uspace::dpdk {

State::State(std::string const& dev, stack::ipv4::Address const& ip,
             stack::ipv4::Address const& dr, stack::ipv4::Address const& nm,
             const bool pcap)
  : utils::State(), poller(dev, ip, dr, nm, pcap)
{}

}
