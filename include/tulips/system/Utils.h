#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tulips::system::utils {

#ifdef __aarch64__

inline uint32_t
log2(const uint32_t x)
{
  uint32_t y, z;
  asm("rbit %w1, %w0" : "=r"(y) : "r"(x));
  asm("clz %w1, %w0" : "=r"(z) : "r"(y));
  return x;
}

#else

inline uint32_t
log2(const uint32_t x)
{
  uint32_t y;
  asm("bsr %1, %0" : "=r"(y) : "r"(x));
  return y;
}

#endif

void join(std::vector<std::string> const& r, const char d, std::string& s);
void split(std::string_view s, const char d, std::vector<std::string>& r);

}
