#pragma once

#include <tulips/system/Logger.h>
#include <tulips/transport/Processor.h>
#include <tulips/transport/ena/Device.h>
#include <tulips/transport/ena/Port.h>
#include <map>
#include <string>
#include <uspace/ena/Poller.h>
#include <utils/State.h>

namespace tulips::tools::uspace::ena {

using IDs = std::map<Client::ID, size_t>;

class State : public utils::State
{
public:
  State(system::Logger& log, std::string_view iff, const bool pcap = false);
  ~State() override;

  system::Logger& logger;
  std::string interface;
  transport::ena::Port port;
  bool with_pcap;
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
