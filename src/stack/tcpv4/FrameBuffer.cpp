#include <tulips/stack/tcpv4/FrameBuffer.h>
#include <tulips/stack/tcpv4/Utils.h>
#include <tulips/system/CircularBuffer.h>
#include <stdexcept>
#include <netinet/in.h>

namespace tulips::stack::tcpv4 {

static constexpr const size_t CAPACITY = 256ULL * 1024ULL;

FrameBuffer::FrameBuffer()
  : m_buffer(system::CircularBuffer::allocate(CAPACITY))
{}

bool
FrameBuffer::push(const uint32_t len, const uint8_t* const data)
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
  frame.reset(len, data);
  /*
   * Commit the frame.
   */
  m_buffer->commit(flen);
  /*
   * Done.
   */
  return true;
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

void
FrameBuffer::catchUp(const uint32_t seq)
{
  /*
   * Bail-out if the buffer is empty.
   */
  if (m_buffer->empty()) {
    return;
  }
  /*
   * Get the buffer information.
   */
  const auto* ptr = m_buffer->readAt();
  size_t len = 0;
  /*
   * Scan the packets for a matching sequence number.
   */
  while (len < m_buffer->readAvailable()) {
    auto const& frame = *reinterpret_cast<const Frame*>(ptr + len);
    const uint32_t fseq = ntohl(frame.header().seqno);
    /*
     * Bail out if seq <= fseq.
     */
    if (SEQ_LE(seq, fseq)) {
      break;
    }
    /*
     * Move to the next frame.
     */
    len += frame.length() + sizeof(Frame);
  }
  /*
   * Skip stale frames.
   */
  m_buffer->skip(len);
}

}
