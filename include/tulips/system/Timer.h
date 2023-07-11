#pragma once

#include "Clock.h"

namespace tulips::system {

class Timer
{
public:
  Timer();

  void set(const Clock::Value interval);
  void reset();

  inline int expired() const { return Clock::read() - m_start >= m_interval; }

private:
  Clock::Value m_start;
  Clock::Value m_interval;
};

}
