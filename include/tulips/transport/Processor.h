#pragma once

#include <tulips/api/Status.h>
#include <tulips/system/Clock.h>
#include <cstdint>

namespace tulips::transport {

class Processor
{
public:
  using Timestamp = system::Clock::Value;

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
   * @param ts the timestamp of the data.
   *
   * @return the status of the operation.
   */
  virtual Status process(const uint16_t len, const uint8_t* const data,
                         const Timestamp ts) = 0;

  /**
   * Notify the processor that a buffer has been sent.
   *
   * @param len the length of the piece of data.
   * @param data the piece of data.
   *
   * @return the status of the operation.
   */
  virtual Status sent(const uint16_t len, uint8_t* const data) = 0;
};

}
