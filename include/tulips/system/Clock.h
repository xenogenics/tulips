#pragma once

#if defined(rdtsc)
#undef rdtsc
#endif

#include <cstdint>

#define CLOCK_SECOND tulips::system::Clock::get().cyclesPerSecond()

namespace tulips::system {

class Clock
{
public:
  using Value = uint64_t;

  inline static Clock& get()
  {
    static Clock clock;
    return clock;
  }

  inline Value cyclesPerSecond() { return m_cps; }

#ifdef TULIPS_CLOCK_HAS_OFFSET
  inline static Value read() { return rdtsc() + get().offset(); }

  inline void offsetBy(const Value offset) { m_offset += offset; }

  inline Value offset() const { return m_offset; }
#else
  inline static Value read() { return rdtsc(); }
#endif

  inline static uint64_t nanosecondsOf(const Value v)
  {
    static Value cps = get().cyclesPerSecond();
    return v * 1000000000ULL / cps;
  }

private:
  Clock();

  inline static uint64_t rdtsc()
  {
    uint64_t a, d;
    __asm__ __volatile__("rdtsc" : "=a"(a), "=d"(d));
    return (a | (d << 32));
  }

  static uint64_t getCPS();

  Value m_cps;
#ifdef TULIPS_CLOCK_HAS_OFFSET
  Value m_offset;
#endif
};

}
