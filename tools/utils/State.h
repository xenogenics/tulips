#pragma once

#include <utils/Command.h>

namespace tulips::tools::utils {

struct State
{
  State();
  virtual ~State() = default;

  bool keep_running;
  Commands commands;
};

}
