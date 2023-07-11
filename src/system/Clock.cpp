#include <tulips/system/Clock.h>
#include <ctime>

namespace tulips::system {

Clock::Clock()
  : m_cps(0)
#ifdef TULIPS_CLOCK_HAS_OFFSET
  , m_offset(0)
#endif
{
  m_cps = getCPS();
}

uint64_t
Clock::getCPS()
{
  struct timespec ts = { 1, 0 };
  uint64_t res = 0, tsc = rdtsc();
  nanosleep(&ts, nullptr);
  res = rdtsc() - tsc;
  return res;
}

}
