#include <chrono>
#include <thread>
#include <uspace/ena/State.h>

namespace tulips::tools::uspace::ena {

State::State(system::Logger& log, std::string_view iff, const bool pcap)
  : utils::State()
  , logger(log)
  , interface(iff)
  , port(log, iff, 8, 32)
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
