#pragma once

#include <tulips/system/Logger.h>
#include <cstdio>

namespace tulips::transport::ena {

class AbstractionLayer
{
public:
  AbstractionLayer(system::Logger& logger);
  ~AbstractionLayer();

private:
  char* m_args[7];
  FILE* m_logfile;
};

}
