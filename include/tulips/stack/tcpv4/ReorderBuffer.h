#pragma once

#include <tulips/api/Status.h>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>

namespace tulips::stack::tcpv4 {

class ReorderBuffer
{
public:
  using Ref = std::unique_ptr<ReorderBuffer>;

  static Ref allocate(const size_t capacity)
  {
    return Ref(new ReorderBuffer(capacity));
  }

  ~ReorderBuffer();

  Status process(const uint32_t expsq, uint32_t& seqno, uint32_t& ackno,
                 uint16_t& len, const uint8_t*& data);

  constexpr bool expecting() const { return m_level != 0; }

  constexpr size_t level() const { return m_level; }

  constexpr size_t window() const { return linear(m_seqnx) - m_seqat; }

private:
  ReorderBuffer(const size_t);

  constexpr uint64_t linear(const uint32_t v) const
  {
    uint64_t seqno = v;
    if (seqno < m_seqat) {
      seqno += (uint64_t(1) << 32);
    }
    return seqno;
  }

  const size_t m_capacity;
  size_t m_level;
  uint32_t m_seqat;
  uint32_t m_seqnx;
  uint32_t m_ackno;
  uint8_t* m_data;
};

}
