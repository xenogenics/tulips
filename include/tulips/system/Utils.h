#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tulips::system::utils {

inline uint32_t
log2(const uint32_t x)
{
  uint32_t y;
  asm("\tbsr %1, %0\n" : "=r"(y) : "r"(x));
  return y;
}

void join(std::vector<std::string> const& r, const char d, std::string& s);
void split(std::string_view s, const char d, std::vector<std::string>& r);

}
