#pragma once

#include <cstdint>
#include <ctime>

#if defined(__x86_64__)
#include <x86intrin.h>
#endif

namespace tulips::system {

class Clock
{
public:
  using Epoch = uint64_t;
  using Instant = uint64_t;

  static const size_t TICKS_PER_SECOND;

  static constexpr const size_t SECOND = 1000000000ULL;
  static constexpr const size_t MILLISECOND = 1000000ULL;

  inline static Clock& get()
  {
    static Clock clock;
    return clock;
  }

#ifdef TULIPS_CLOCK_HAS_OFFSET
  inline static Epoch instant() { return cycles() + toTicks(get().offset()); }
  inline static Epoch now() { return clock() + get().offset(); }

  inline void offsetBy(const size_t offset) { m_offset += offset; }
  inline Epoch offset() const { return m_offset; }
#else
  inline static Instant instant() { return cycles(); }
  inline static Epoch now() { return clock(); }
#endif

  inline static size_t toNanos(const size_t v)
  {
    return (v * SECOND) / TICKS_PER_SECOND;
  }

  inline static size_t toTicks(const size_t v)
  {
    return (v * TICKS_PER_SECOND) / SECOND;
  }

private:
  inline static uint64_t clock()
  {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
  }

#if defined(__x86_64__)
  inline static Instant cycles() { return __rdtsc(); }
#elif defined(__aarch64__)
  inline static Instant cycles() { return clock() / 1000; }
#else
#error "Processor architecture not supported"
#endif

#ifdef TULIPS_CLOCK_HAS_OFFSET
  size_t m_offset = 0;
#endif
};
}
