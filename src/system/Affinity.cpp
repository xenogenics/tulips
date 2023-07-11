#include <tulips/system/Affinity.h>
#include <pthread.h>
#include <unistd.h>

#if defined(__linux__)
#include <sched.h>
#endif

namespace tulips::system {

bool
setCurrentThreadAffinity(const long cpuid)
{
  /*
   * Check if the CPU ID is valid.
   */
  const long num_cores = sysconf(_SC_NPROCESSORS_ONLN);
  if (cpuid >= num_cores) {
    return false;
  }
#if defined(__linux__)
  /*
   * Build the CPUSET.
   */
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(cpuid, &cpuset);
  /*
   * Set the main thread's affinity.
   */
  pthread_t self = pthread_self();
  return pthread_setaffinity_np(self, sizeof(cpu_set_t), &cpuset) == 0;
#else
  return false;
#endif
}

}
