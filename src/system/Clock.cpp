#include <tulips/system/Clock.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>

#if defined(__x86_64__)
namespace {

constexpr size_t N_SAMPLES = 100;
constexpr size_t PERIOD_MS = 1;

long double
ticksPerSecond()
{
  std::array<long double, N_SAMPLES> ns_per_tick;
  /*
   * Run the calibration loop.
   *
   * Use C++ "steady_clock" since cppreference.com recommends against using
   * hrtime.  Busy wait for 5ms based on the std::chrono clock and time that
   * with our high reolution low overhead clock. Assuming the steady clock has
   * a resonable resolution, 5ms should be long enough to wait. At a 1GHz clock,
   * that is still 5MT, and even at a 1MHz clock it's 5kT.
   */
  for (size_t i = 0; i < N_SAMPLES; i += 1) {
    auto start = std::chrono::steady_clock::now();
    asm volatile("" : : : "memory");
    uint64_t startTick = __rdtsc();
    auto end = start + std::chrono::milliseconds(PERIOD_MS);
    /*
     * Busy wait.
     */
    decltype(start) now;
    uint64_t endTick = 0;
    do {
      now = std::chrono::steady_clock::now();
      endTick = __rdtsc();
    } while (now < end);
    asm volatile("" : : : "memory");
    /*
     * Compute the deltas (second-per-tick).
     */
    auto elapsed_in_ticks = static_cast<long double>(endTick - startTick);
    auto delay_in_ns = static_cast<long double>((now - start).count());
    ns_per_tick[i] = delay_in_ns / elapsed_in_ticks;
  }
  /*
   * Select the median.
   */
  std::sort(ns_per_tick.begin(), ns_per_tick.end());
  return std::llround(1e9L / ns_per_tick[N_SAMPLES / 2]);
}

}
#endif

namespace tulips::system {

#if defined(__x86_64__)
const size_t Clock::TICKS_PER_SECOND = ticksPerSecond();
#elif defined(__aarch64__)
const size_t Clock::TICKS_PER_SECOND = Clock::MILLISECOND;
#else
#error "Processor architecture not supported"
#endif

}
