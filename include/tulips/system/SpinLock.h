#pragma once

#include <cstdint>
#include <pthread.h>

namespace tulips::system {

class SpinLock
{
public:
  class Guard
  {
  public:
    inline Guard(SpinLock& lock) : m_lock(lock)
    {
      while (__sync_val_compare_and_swap(&lock.m_lock, 0, 1)) {
      }
    }

    inline ~Guard() { m_lock.m_lock = 0; }

  private:
    SpinLock& m_lock;
  };

  SpinLock() : m_lock(0) {}

private:
  volatile uint8_t m_lock;
};

}
