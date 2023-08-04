#include <tulips/system/Utils.h>

#ifdef TRANS_VERBOSE
#define ENA_LOG(__args) LOG("ENA", __args)
#else
#define ENA_LOG(...) ((void)0)
#endif
