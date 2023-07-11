#pragma once

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

namespace tulips::system::utils {

#define likely(__x) __builtin_expect((__x), 1)
#define unlikely(__x) __builtin_expect((__x), 0)

#ifdef TULIPS_DEBUG
#define LOG(__hdr, __msg)                                                      \
  std::cout << "[ " << std::setw(8) << /* NOLINT */ __hdr << " ] "             \
            << /* NOLINT */ __msg << std::endl
#else
#define LOG(__hdr, __msg) ((void)0)
#endif

inline uint32_t
log2(const uint32_t x)
{
  uint32_t y;
  asm("\tbsr %1, %0\n" : "=r"(y) : "r"(x));
  return y;
}

void join(std::vector<std::string> const& r, const char d, std::string& s);
void split(std::string const& s, const char d, std::vector<std::string>& r);

}
