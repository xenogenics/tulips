#pragma once

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
  State(std::string const& iff, const bool pcap = false);

  std::string interface;
  transport::ena::Port port;
  bool with_pcap;
  std::vector<poller::Poller::Ref> pollers;
  IDs ids;

private:
  class RawProcessor : public transport::Processor
  {
  public:
    Status run() override { return Status::Ok; }

    Status process(UNUSED const uint16_t len,
                   UNUSED const uint8_t* const data) override
    {
      return Status::Ok;
    }
  };

  static void* entrypoint(void* data)
  {
    auto* poller = reinterpret_cast<State*>(data);
    poller->run();
    return nullptr;
  }

  void run();

  volatile bool m_run;
  pthread_t m_thread;
  RawProcessor m_raw;
};

}
