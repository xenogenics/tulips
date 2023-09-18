#pragma once

#include <tulips/transport/Processor.h>
#include <tulips/transport/ena/AbstractionLayer.h>
#include <tulips/transport/ena/Device.h>
#include <tulips/transport/ena/Port.h>
#include <map>
#include <set>
#include <string>
#include <uspace/ena/Poller.h>
#include <utils/State.h>

namespace tulips::tools::uspace::ena {

using IDs = std::map<size_t, std::set<api::Client::ID>>;

class State : public utils::State
{
public:
  State(std::string_view iff, const bool pcap, const bool ssl);
  ~State() override;

  std::string interface;
  transport::ena::AbstractionLayer::Ref eal;
  transport::ena::Port port;
  bool with_pcap;
  bool with_ssl;
  std::vector<poller::Poller::Ref> pollers;
  IDs ids;

private:
  static void* entrypoint(void* data)
  {
    auto* poller = reinterpret_cast<State*>(data);
    poller->run();
    return nullptr;
  }

  void run();

  volatile bool m_run;
  pthread_t m_thread;
};

}
