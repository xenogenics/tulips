#pragma once

#include <tulips/system/Logger.h>
#include <cstdio>
#include <memory>

namespace tulips::transport::ena {

class AbstractionLayer
{
public:
  using Ref = std::unique_ptr<AbstractionLayer>;

  static Ref allocate(system::Logger& logger);

  ~AbstractionLayer();

private:
  AbstractionLayer(FILE* const logfile);

  FILE* m_logfile;
};

}
