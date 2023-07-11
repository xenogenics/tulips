#include <tulips/stack/Utils.h>
#include <tulips/system/CircularBuffer.h>
#include <tulips/system/Utils.h>
#include <stdexcept>
#include <sys/mman.h>
#include <unistd.h>

#define BUFFER_VERBOSE 1

#if BUFFER_VERBOSE
#define BUFFER_LOG(__args) LOG("BUFFER", __args)
#else
#define BUFFER_LOG(...)
#endif

namespace tulips::system {

CircularBuffer::CircularBuffer(const size_t size)
  : m_size(fit(size))
  , m_mask(m_size - 1)
  , m_data(nullptr)
  , m_read(0)
  , m_write(0)
{
  BUFFER_LOG("create with length: " << m_size << "B");
  /*
   * Create a temporary file.
   */
  char path[] = "/tmp/cb-XXXXXX";
  int fd = mkstemp(path);
  if (fd < 0) {
    throw std::runtime_error("cannot create temporary file");
  }
  /*
   * Unlink the file.
   */
  if (unlink(path) < 0) {
    throw std::runtime_error("cannot unlink temporary file");
  }
  /*
   * Truncate the file.
   */
  if (ftruncate(fd, (off_t)size) < 0) {
    throw std::runtime_error("cannot truncate temporary file");
  }
  /*
   * Create an anonymous mapping.
   */
  void* data;
  data =
    mmap(nullptr, m_size << 1, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (data == MAP_FAILED) {
    throw std::runtime_error("cannot create anonymous mapping");
  }
  /*
   * Map the file in the region.
   */
  void* a;
  a = mmap(data, m_size, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED, fd, 0);
  if (a != data) {
    throw std::runtime_error("cannot map file to anonymous mapping");
  }
  a = mmap((uint8_t*)data + m_size, m_size, PROT_READ | PROT_WRITE,
           MAP_FIXED | MAP_SHARED, fd, 0);
  if (a != (uint8_t*)data + m_size) {
    throw std::runtime_error("cannot map file to anonymous mapping");
  }
  /*
   * Clean-up.
   */
  close(fd);
  m_data = (uint8_t*)data;
}

CircularBuffer::~CircularBuffer()
{
  munmap(m_data, m_size << 1);
}

size_t
CircularBuffer::fit(const size_t size)
{
  size_t npages = size / getpagesize();
  size_t result = npages * getpagesize();
  if (result < size) {
    result += getpagesize();
  }
  return result;
}

}
