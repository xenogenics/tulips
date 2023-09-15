#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace tulips::stack::tcpv4 {

class Segment
{
public:
  Segment() = default;

private:
  inline void set(const uint32_t len, const uint32_t seq, uint8_t* const dat)
  {
    m_len = len;
    m_seq = seq;
    m_dat = dat;
  }

  inline void mark(const uint32_t seq) { m_seq = seq; }

  inline void clear()
  {
    m_len = 0;
    m_seq = 0;
    m_dat = nullptr;
  }

  /*
   * The len field is used to check if the segment was fully acknowledged. It
   * is also used to check if the segment is valid (=0).
   */
  uint32_t m_len; // 4 - Length of the data that was sent
  uint32_t m_seq; // 4 - Sequence number of the segment
  uint8_t* m_dat; // 8 - Data that was sent

  friend class Connection;
  friend class Processor;
} __attribute__((aligned(16)));

static_assert(sizeof(Segment) == 16, "Invalid size for tcpv4::Segment");

}
