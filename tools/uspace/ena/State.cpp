#include <chrono>
#include <thread>
#include <uspace/ena/State.h>

namespace tulips::tools::uspace::ena {

State::State(std::string const& iff, const bool pcap)
  : utils::State()
  , interface(iff)
  , port(iff, 8, 32)
  , with_pcap(pcap)
  , pollers()
  , m_run(true)
  , m_thread()
{
  pthread_create(&m_thread, nullptr, &State::entrypoint, this);
}

State::~State()
{
  m_run = false;
  pthread_join(m_thread, nullptr);
}

void
State::run()
{
  while (m_run) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    port.run();
  }
}

}