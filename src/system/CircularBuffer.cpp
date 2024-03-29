#include <tulips/stack/Utils.h>
#include <tulips/system/CircularBuffer.h>
#include <tulips/system/Utils.h>
#include <stdexcept>
#include <sys/mman.h>
#include <unistd.h>

namespace {

static size_t
next_pow2(const size_t v)
{
  return v == 1 ? 1 : 1 << (64 - __builtin_clzl(v - 1));
}

}

namespace tulips::system {

CircularBuffer::CircularBuffer(const size_t hint) : m_read(), m_write()
{
  auto size = fit(hint);
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
  if (ftruncate(fd, (off_t)hint) < 0) {
    throw std::runtime_error("cannot truncate temporary file");
  }
  /*
   * Create an anonymous mapping.
   */
  auto anon_flags = MAP_ANONYMOUS | MAP_PRIVATE;
  void* data = mmap(nullptr, size << 1, PROT_NONE, anon_flags, -1, 0);
  if (data == /* NOLINT */ MAP_FAILED) {
    throw std::runtime_error("cannot create anonymous mapping");
  }
  /*
   * Map the file in the region.
   */
  auto map_flags = MAP_FIXED | MAP_SHARED;
#ifdef __linux__
  map_flags |= MAP_POPULATE;
#endif
  void* a = mmap(data, size, PROT_READ | PROT_WRITE, map_flags, fd, 0);
  if (a != data) {
    throw std::runtime_error("cannot map file to anonymous mapping");
  }
  a = mmap((uint8_t*)data + size, size, PROT_READ | PROT_WRITE,
           MAP_FIXED | MAP_SHARED, fd, 0);
  if (a != (uint8_t*)data + size) {
    throw std::runtime_error("cannot map file to anonymous mapping");
  }
  /*
   * Setup the contexts.
   */
  m_read.setup(size, (uint8_t*)data);
  m_write.setup(size, (uint8_t*)data);
  /*
   * Clean-up.
   */
  close(fd);
}

CircularBuffer::~CircularBuffer()
{
  munmap(m_read.data, m_read.size << 1);
}

size_t
CircularBuffer::fit(const size_t size)
{
  /*
   * Fit the requested size into page sizes.
   */
  size_t npages = size / getpagesize();
  size_t result = npages * getpagesize();
  if (result < size) {
    result += getpagesize();
  }
  /*
   * Round-up the the next power of 2.
   */
  return next_pow2(result);
}

}
