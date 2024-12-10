#include <tulips/stack/tcpv4/Utils.h>
#include <tulips/system/CircularBuffer.h>
#include <tulips/system/FrameBuffer.h>
#include <stdexcept>
#include <netinet/in.h>

namespace tulips::system {

FrameBuffer::FrameBuffer(const size_t capacity)
  : m_buffer(system::CircularBuffer::allocate(capacity))
{}

bool
FrameBuffer::push(const uint32_t len, const uint8_t* const data,
                  const Clock::Epoch ts)
{
  const uint32_t flen = len + sizeof(Frame);
  /*
   * Prepare the length of the frame.
   */
  auto buffer = m_buffer->prepare(flen);
  if (buffer == nullptr) {
    return false;
  }
  /*
   * Copy the frame.
   */
  auto& frame = *reinterpret_cast<Frame*>(buffer);
  frame.reset(len, data, ts);
  /*
   * Commit the frame.
   */
  m_buffer->commit(flen);
  /*
   * Done.
   */
  return true;
}

void
FrameBuffer::pop()
{
  /*
   * Bail-out if the buffer is empty.
   */
  if (m_buffer->empty()) {
    return;
  }
  /*
   * Get the current frame's length.
   */
  auto& frame = peek();
  auto flen = frame.length() + sizeof(Frame);
  /*
   * Skip the current frame.
   */
  m_buffer->skip(flen);
}

Frame const&
FrameBuffer::peek() const
{
  /*
   * Sanity check.
   */
  if (m_buffer->empty()) {
    throw std::runtime_error("have you called empty()?");
  }
  /*
   * Wrap the buffer into a frame.
   */
  auto buffer = m_buffer->readAt();
  auto const& frame = *reinterpret_cast<const Frame*>(buffer);
  /*
   * Done.
   */
  return frame;
}

}
