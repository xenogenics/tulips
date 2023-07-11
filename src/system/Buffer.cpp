#include <tulips/system/Buffer.h>
#include <cstring>
#include <new>

namespace tulips::system {

Buffer*
Buffer::allocate(const uint32_t size)
{
  void* data = new uint8_t[size + sizeof(Buffer)];
  return new (data) Buffer(size);
}

void
Buffer::release(Buffer* buffer)
{
  delete[] buffer;
}

bool
Buffer::append(const uint32_t len, const uint8_t* const data)
{
  /*
   * Abort if there is not enough place left in the buffer.
   */
  if (m_fill + len > m_size) {
    return false;
  }
  /*
   * Append the data;
   */
  memcpy(&m_data[m_fill], data, len);
  m_fill += len;
  return true;
}

Buffer::Buffer(const uint32_t size) : m_size(size), m_fill(0) {}

}
