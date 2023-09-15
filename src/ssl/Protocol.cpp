#include <tulips/ssl/Protocol.h>

namespace tulips::ssl {

std::string
toString(const Protocol type)
{
  switch (type) {
    case Protocol::Auto:
      return "Auto";
    case Protocol::SSLv3:
      return "SSLv3";
    case Protocol::TLS:
      return "TLS";
  }
#if defined(__GNUC__) && defined(__GNUC_PREREQ)
  return "";
#endif
}

}
