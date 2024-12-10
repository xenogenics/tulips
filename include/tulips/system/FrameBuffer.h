#pragma once

#include <tulips/stack/TCPv4.h>
#include <tulips/system/CircularBuffer.h>
#include <tulips/system/Clock.h>
#include <tulips/system/Compiler.h>
#include <cstdint>
#include <cstring>
#include <type_traits>

namespace tulips::system {

/*
 * Frame.
 */

class Frame
{
public:
  /**
   * @return the frame's timestamp.
   */
  inline constexpr Clock::Epoch timestamp() const { return m_ts; }

  /**
   * @return the frame's length.
   */
  inline constexpr uint32_t length() const { return m_length; }

  /**
   * @return the raw data pointer.
   */
  inline constexpr const uint8_t* data() const { return m_data; }

  /**
   * Cast the content to a trivially-copyable type.
   *
   * @return a reference to the content as T.
   */
  template<typename T>
  inline T const& as() const
  {
    static_assert(std::is_trivially_copyable<T>::value);
    return *reinterpret_cast<const T*>(m_data);
  }

private:
  Frame() = default;

  /**
   * Reset the frame's content.
   *
   * @param len the frame's length.
   * @param data the frame's data.
   * @param ts the frame's timestamp.
   */
  inline void reset(const uint32_t len, const uint8_t* const data,
                    const Clock::Epoch ts)
  {
    m_ts = ts;
    m_length = len;
    memcpy(m_data, data, len);
  }

  Clock::Epoch m_ts;
  uint32_t m_length;
  uint8_t m_data[];

  friend class FrameBuffer;
} PACKED;

/*
 * Frame buffer.
 */

class FrameBuffer
{
public:
  /**
   * Shared reference type.
   */
  using Ref = std::shared_ptr<FrameBuffer>;

  /**
   * Construct a new buffer and return a shared reference.
   *
   * @param the requested size of the buffer.
   */
  static Ref allocate(const size_t size)
  {
    return std::make_shared<FrameBuffer>(size);
  }

  /**
   * Default constructor.
   */
  FrameBuffer(const size_t capacity);

  /**
   * Push a frame into the buffer.
   *
   * @param len the length of the frame's data.
   * @param data the frame's data.
   * @param ts the frame's timestamp.
   */
  bool push(const uint32_t len, const uint8_t* const data, const Clock::Epoch);

  /**
   * Pop the current frame from the buffer.
   */
  void pop();

  /**
   * @return the current frame in the buffer.
   */
  Frame const& peek() const;

  /**
   * @return the length of the buffer.
   */
  size_t length() const { return m_buffer->readAvailable(); }

  /**
   * @return true if the buffer is empty.
   */
  bool empty() const { return m_buffer->empty(); }

  /**
   * Clear the buffer.
   */
  void clear() { m_buffer->reset(); }

private:
  system::CircularBuffer::Ref m_buffer;
};

}
