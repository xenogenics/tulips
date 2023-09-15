#pragma once

#include <string>

namespace tulips::ssl {

enum class Protocol
{
  Auto,
  SSLv3,
  TLS,
};

std::string toString(const Protocol type);

}
