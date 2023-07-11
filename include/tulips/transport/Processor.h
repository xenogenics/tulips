#pragma once

#include <tulips/api/Status.h>
#include <cstdint>

namespace tulips::transport {

class Processor
{
public:
  /**
   * Virtual destructor.
   */
  virtual ~Processor() = default;

  /**
   * Run the processor when data is not available. This is usually called
   * periodically as a result of a timer event.
   *
   * @return the status of the operation.
   */
  virtual Status run() = 0;

  /**
   * Process an incoming piece of data. The processing must be done without copy
   * as much as possible.
   *
   * @param len the length of the piece of data.
   * @param data the piece of data.
   *
   * @return the status of the operation.
   */
  virtual Status process(const uint16_t len, const uint8_t* const data) = 0;
};

}
