#pragma once

#include <tulips/stack/TCPv4.h>
#include <tulips/system/CircularBuffer.h>
#include <cstdint>
#include <cstring>

namespace tulips::stack::tcpv4 {

/*
 * Frame.
 */

class Frame
{
public:
  Frame() = default;

  inline void reset(const uint32_t len, const uint8_t* const data)
  {
    m_length = len;
    memcpy(m_data, data, len);
  }

  inline constexpr uint32_t length() const { return m_length; }

  inline Header const& header() const
  {
    return *reinterpret_cast<const Header*>(m_data);
  }

  inline constexpr const uint8_t* data() const { return m_data; }

private:
  uint32_t m_length;
  uint8_t m_data[];
};

/*
 * Frame buffer.
 */

struct FrameBuffer
{
public:
  FrameBuffer();

  bool push(const uint32_t len, const uint8_t* const data);
  Frame const& peek() const;
  void pop();

  void catchUp(const uint32_t seq);

  bool empty() const { return m_buffer->empty(); }
  void clear() { m_buffer->reset(); }

private:
  system::CircularBuffer::Ref m_buffer;
};
}
