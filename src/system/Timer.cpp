#include <tulips/system/Timer.h>

namespace tulips::system {

Timer::Timer() : m_start(0), m_interval(0) {}

void
Timer::set(const Clock::Value interval)
{
  m_interval = interval;
  m_start = Clock::read();
}

void
Timer::reset()
{
  m_start = Clock::read();
}

}
