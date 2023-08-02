#include <tulips/system/Utils.h>

#define DPDK_VERBOSE 1

#if DPDK_VERBOSE
#define DPDK_LOG(__args) LOG("DPDK", __args)
#else
#define DPDK_LOG(...) ((void)0)
#endif
