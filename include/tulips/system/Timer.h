#pragma once

#include "Clock.h"

namespace tulips::system {

class Timer
{
public:
  inline void set(const size_t interval_ns)
  {
    m_interval = Clock::toTicks(interval_ns);
    m_start = Clock::instant();
  }

  inline void reset() { m_start = Clock::instant(); }

  inline bool expired() const
  {
    return Clock::instant() - m_start >= m_interval;
  }

  inline size_t ticks() const
  {
    return (Clock::instant() - m_start) / m_interval;
  }

private:
  Clock::Instant m_start = 0;
  size_t m_interval = 0;
};

}
