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
  , m_raw()
{
  pthread_create(&m_thread, nullptr, &State::entrypoint, this);
}

void
State::run()
{
  while (m_run) {
    if (port.wait(m_raw, 100000000ULL) == Status::NoDataAvailable) {
      m_raw.run();
    }
  }
}

}
