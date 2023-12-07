#include <tulips/api/Status.h>
#include <tulips/stack/tcpv4/ReorderBuffer.h>
#include <cstring>
#include <limits>

namespace tulips::stack::tcpv4 {

ReorderBuffer::ReorderBuffer(const size_t capacity)
  : m_capacity(capacity)
  , m_level(0)
  , m_seqat(0)
  , m_seqnx(0)
  , m_ackno(0)
  , m_data(nullptr)
{
  m_data = new uint8_t[capacity];
}

ReorderBuffer::~ReorderBuffer()
{
  delete[] m_data;
}

Status
ReorderBuffer::process(const uint32_t expsq, uint32_t& seqno, uint32_t& ackno,
                       uint16_t& len, const uint8_t*& data)
{
  /*
   * Initial condition.
   */
  if (m_level == 0) {
    m_seqat = expsq;
    m_seqnx = seqno;
    m_ackno = ackno;
  }
  /*
   * Get the current write index.
   */
  const size_t wridx = linear(seqno) - m_seqat;
  /*
   * Check if we can store the packet.
   */
  if (wridx + len > m_capacity) {
    m_level = 0;
    return Status::NoMoreResources;
  }
  /*
   * Filter duplicates.
   */
  if (m_seqnx != seqno && memcmp(m_data + wridx, data, len) == 0) {
    return Status::IncompleteData;
  }
  /*
   * Copy the data and increase the level.
   */
  memcpy(m_data + wridx, data, len);
  m_level = m_level + len;
  /*
   * Update the internal state.
   */
  if (linear(seqno) >= linear(m_seqnx)) {
    m_seqnx = seqno + len;
    m_ackno = ackno;
  }
  /*
   * Check if we are done.
   */
  if (m_level == window()) {
    /*
     * Return the state.
     */
    seqno = m_seqat;
    ackno = m_ackno;
    len = m_level;
    data = m_data;
    /*
     * Reset and done.
     */
    m_level = 0;
    return Status::Ok;
  }
  /*
   * Done.
   */
  return Status::IncompleteData;
}

}
