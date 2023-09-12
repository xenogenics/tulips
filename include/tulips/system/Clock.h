#pragma once

#include <cstdint>
#include <ctime>

namespace tulips::system {

class Clock
{
public:
  using Value = uint64_t;

  static constexpr const Value SECOND = 1000000000ULL;

  inline static Clock& get()
  {
    static Clock clock;
    return clock;
  }

#ifdef TULIPS_CLOCK_HAS_OFFSET
  inline static Value read() { return clock() + get().offset(); }

  inline void offsetBy(const Value offset) { m_offset += offset; }

  inline Value offset() const { return m_offset; }
#else
  inline static Value read() { return clock(); }
#endif

private:
  inline static Value clock()
  {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
  }

#ifdef TULIPS_CLOCK_HAS_OFFSET
  Value m_offset = 0;
#endif
};

}
