#pragma once

#include <tulips/stack/Utils.h>
#include <cstdint>

namespace tulips::system {

class Buffer
{
public:
  static Buffer* allocate(const uint32_t size);
  static void release(Buffer* buffer);

  bool append(const uint32_t len, const uint8_t* const data);

  inline void reset() { m_fill = 0; }

  inline const uint8_t* data() const { return m_data; }

  inline uint32_t available() const { return m_size - m_fill; }

  inline uint32_t fill() const { return m_fill; }

  inline uint16_t window() const { return stack::utils::cap(available()); }

  inline bool empty() const { return m_fill == 0; }

private:
  Buffer(const uint32_t size);

  uint32_t m_size;
  uint32_t m_fill;
  uint8_t m_data[];
} __attribute__((aligned(16)));

}
