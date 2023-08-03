#pragma once

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>

namespace tulips::system {

class alignas(64) CircularBuffer
{
public:
  /**
   * Shared reference type.
   */
  using Ref = std::shared_ptr<CircularBuffer>;

  /**
   * Construct a new buffer and return a shared reference.
   *
   * @param the requested size of the buffer.
   */
  static Ref allocate(const size_t size)
  {
    return std::make_shared<CircularBuffer>(size);
  }

  /**
   * Construct a new buffer.
   *
   * @param the requested size of the buffer.
   */
  CircularBuffer(const size_t size);

  /**
   * Destructor.
   */
  ~CircularBuffer();

  /**
   * Check if the buffer is empty from the reader point of view.
   *
   * @return true if the buffer is empty, false otherwise.
   */
  inline bool empty() const
  {
    auto read = m_read.counter.load(std::memory_order_relaxed);
    auto write = m_write.counter.load(std::memory_order_acquire);
    return read == write;
  }

  /**
   * Check if the buffer is full from the writer point of view.
   *
   * @return true if the buffer is full, false otherwise.
   */
  inline bool full() const
  {
    auto read = m_read.counter.load(std::memory_order_acquire);
    auto write = m_write.counter.load(std::memory_order_relaxed);
    return write - read == m_write.size;
  }

  /**
   * Read some data from the buffer.
   *
   * @param buffer the target buffer to copy the data into.
   * @param len the request length.
   *
   * @return the actual length of the data read.
   */
  inline size_t read(uint8_t* const buffer, const size_t len)
  {
    const size_t delta = read_available();
    size_t n = len > delta ? delta : len;
    memcpy(buffer, readAt(), n);
    m_read.counter.store(m_read.counter + n, std::memory_order_release);
    return n;
  }

  /**
   * Read an exact amount of data from the buffer.
   *
   * @param buffer the target buffer to copy the data into.
   * @param len the request length.
   */
  inline void read_all(uint8_t* const buffer, const size_t len)
  {
    /*
     * Busy wait for the data to be available.
     */
    while (read_available() < len) {
    }
    /*
     * Read the data.
     */
    memcpy(buffer, readAt(), len);
    m_read.counter.store(m_read.counter + len, std::memory_order_release);
  }

  /**
   * Write some data into the buffer.
   *
   * @param buffer the source buffer to copy the data from.
   * @param len the request length.
   *
   * @return the actual length of the data written.
   */
  inline size_t write(const uint8_t* const buffer, const size_t len)
  {
    const size_t delta = write_available();
    size_t n = len > delta ? delta : len;
    memcpy(writeAt(), buffer, n);
    m_write.counter.store(m_write.counter + n, std::memory_order_release);
    return n;
  }

  /**
   * Write all the data into the buffer.
   *
   * @param buffer the source buffer to copy the data from.
   * @param len the request length.
   */
  inline void write_all(const uint8_t* const buffer, const size_t len)
  {
    /*
     * Busy wait until there is enough space available.
     */
    while (write_available() < len) {
    }
    /*
     * Write the data.
     */
    memcpy(writeAt(), buffer, len);
    m_write.counter.store(m_write.counter + len, std::memory_order_release);
  }

  /**
   * Check how much data is available to read from the reader point of view.
   *
   * @return the amount of data available to read.
   */
  inline size_t read_available() const
  {
    auto read = m_read.counter.load(std::memory_order_relaxed);
    auto write = m_write.counter.load(std::memory_order_acquire);
    return write - read;
  }

  /**
   * Check how much space is available to write from the writer point of view.
   *
   * @return the amount of space available to write.
   */
  inline size_t write_available() const
  {
    auto read = m_read.counter.load(std::memory_order_acquire);
    auto write = m_write.counter.load(std::memory_order_relaxed);
    return m_write.size - (write - read);
  }

  /**
   * Reset the buffer.
   */
  inline void reset()
  {
    m_read.reset();
    m_write.reset();
  }

  /**
   * @return the current read pointer.
   */
  inline const uint8_t* readAt() const
  {
    auto read = m_read.counter.load(std::memory_order_relaxed);
    return &m_read.data[read & m_read.mask];
  }

  /**
   * @return the current write pointer.
   */
  inline uint8_t* writeAt() const
  {
    auto write = m_write.counter.load(std::memory_order_relaxed);
    return &m_write.data[write & m_write.mask];
  }

  /**
   * Advance the read pointer by a given offset.
   *
   * @param len the offset to advance the read pointer by.
   */
  inline void skip(const size_t len)
  {
    const size_t delta = read_available();
    size_t n = len > delta ? delta : len;
    m_read.counter.store(m_read.counter + n, std::memory_order_release);
  }

private:
  struct alignas(64) Context
  {
    size_t size = 0;
    size_t mask = 0;
    uint8_t* data = nullptr;
    std::atomic<size_t> counter = 0;

    void setup(const size_t s, uint8_t* const d)
    {
      size = s;
      mask = s - 1;
      data = d;
    }

    void reset() { counter = 0; }
  };

  static size_t fit(const size_t size);

  Context m_read;
  Context m_write;
};

}
