#pragma once

#if !defined(likely) && !defined(unlikely)
#define likely(__x) __builtin_expect((__x), 1)
#define unlikely(__x) __builtin_expect((__x), 0)
#endif

#define USED __attribute__((used))
#define UNUSED __attribute__((unused))
