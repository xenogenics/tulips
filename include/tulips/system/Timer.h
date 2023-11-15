#pragma once

#include "Clock.h"

namespace tulips::system {

class Timer
{
public:
  inline void set(const Clock::Value interval)
  {
    m_interval = interval;
    m_start = Clock::read();
  }

  inline void reset(const Clock::Value ts) { m_start = ts; }

  inline bool expired(const Clock::Value ts) const
  {
    return ts - m_start >= m_interval;
  }

  inline size_t ticks(const Clock::Value ts) const
  {
    return (ts - m_start) / m_interval;
  }

private:
  Clock::Value m_start = 0;
  Clock::Value m_interval = 0;
};

}
