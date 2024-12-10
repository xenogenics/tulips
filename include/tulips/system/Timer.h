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

  inline size_t reset()
  {
    const auto end = Clock::instant();
    const auto dlt = end - m_start;
    const auto res = dlt / m_interval;
    m_start = end;
    return res;
  }

  inline bool expired() const
  {
    return Clock::instant() - m_start >= m_interval;
  }

private:
  Clock::Instant m_start = 0;
  size_t m_interval = 0;
};

}
