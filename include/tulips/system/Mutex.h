#pragma once

#include <pthread.h>

namespace tulips::system {

class Mutex
{
public:
  class Guard
  {
  public:
    Guard(Mutex& lock) : m_lock(lock) { pthread_mutex_lock(&m_lock.m_lock); }

    ~Guard() { pthread_mutex_unlock(&m_lock.m_lock); }

  private:
    Mutex& m_lock;
  };

  Mutex() : m_lock() { pthread_mutex_init(&m_lock, nullptr); }

  ~Mutex() { pthread_mutex_destroy(&m_lock); }

private:
  pthread_mutex_t m_lock;
};

}
