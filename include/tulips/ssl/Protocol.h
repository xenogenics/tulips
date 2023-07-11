#pragma once

#include <string>

namespace tulips::ssl {

enum class Protocol
{
  SSLv3,
  TLS,
};

std::string toString(const Protocol type);

}
