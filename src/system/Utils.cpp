#include <tulips/system/Utils.h>

namespace tulips::system::utils {

void
join(std::vector<std::string> const& r, const char d, std::string& s)
{
  auto cit = r.begin();
  s = *cit++;
  for (; cit != r.end(); cit++) {
    s += d + *cit;
  }
}

void
split(std::string const& s, const char d, std::vector<std::string>& r)
{
  r.clear();
  if (s.empty()) {
    return;
  }
  std::string buffer;
  for (char c : s) {
    if (c == d) {
      if (!buffer.empty()) {
        r.push_back(buffer);
        buffer.clear();
      }
    } else {
      buffer.push_back(c);
    }
  }
  r.push_back(buffer);
}

}
