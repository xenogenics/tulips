#pragma once

#include <atomic>
#include <cstdint>
#include <pthread.h>

namespace tulips::system {

class SpinLock
{
public:
  SpinLock() : m_flag() {}

  inline void lock()
  {
    do {
      /* Busy wait */
    } while (m_flag.test_and_set());
  }

  inline void unlock() { m_flag.clear(); }

private:
  std::atomic_flag m_flag;
};

}
