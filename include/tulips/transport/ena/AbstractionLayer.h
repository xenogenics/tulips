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
  FILE* m_logfile;
};

}
