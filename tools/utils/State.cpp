#include <utils/State.h>

namespace tulips::tools::utils {

State::State()
  : keep_running(true), commands(), logger(system::Logger::Level::Trace)
{}

}
