#pragma once

#include <tulips/api/Status.h>
#include <cstdint>

namespace tulips::transport {

class Producer
{
public:
  virtual ~Producer() = default;

  /**
   * @return the producer's segment size.
   */
  virtual uint32_t mss() const = 0;

  /*
   * Prepare an asynchronous send buffer to use in a future commit. The buffer
   * is at least of the size of mss().
   *
   * @param buf a reference to an uint8_t pointer to hold the new buffer.
   *
   * @return the status of the operation.
   */
  virtual Status prepare(uint8_t*& buf) = 0;

  /*
   * Commit a prepared buffer.
   *
   * @param len the length of the contained data.
   * @param buf the previously prepared buffer.
   * @param mss the mss to use in case of segmentation offload.
   *
   * @return the status of the operation.
   */
  virtual Status commit(const uint32_t len, uint8_t* const buf,
                        const uint16_t mss = 0) = 0;
};

}
