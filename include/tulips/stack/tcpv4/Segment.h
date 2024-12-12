#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>

namespace tulips::stack::tcpv4 {

/*
 * Segment.
 */

class Segment
{
public:
  Segment() = default;

  inline void set(const uint32_t len, const uint32_t seq, uint8_t* const dat)
  {
    m_len = len;
    m_seq = seq;
    m_dat = dat;
  }

  inline void clear()
  {
    m_len = 0;
    m_seq = 0;
    m_dat = nullptr;
  }

  inline constexpr uint32_t length() const { return m_len; }

  inline constexpr uint32_t seq() const { return m_seq; }

  inline constexpr uint8_t* data() { return m_dat; }

private:
  /*
   * The len field is used to check if the segment was fully acknowledged. It is
   * also used to check if the segment is valid (=0).
   */
  uint32_t m_len; // 4 - Length of the data that was sent
  uint32_t m_seq; // 4 - Sequence number of the segment
  uint8_t* m_dat; // 8 - Data that was sent
} __attribute__((aligned(16)));

static_assert(sizeof(Segment) == 16, "Invalid size for tcpv4::Segment");

/*
 * Segments.
 */

template<size_t CAPACITY, size_t MASK>
class Segments
{
public:
  /**
   * Reference type.
   */
  using Ref = std::unique_ptr<Segments>;

  /**
   * Allocator.
   */
  static Ref allocate() { return std::make_unique<Segments>(); }

  /**
   * Constructor.
   */
  Segments() : m_current(0), m_used(0), m_data() {}

  /**
   * @return the current index.
   */
  inline constexpr auto currentIndex() { return m_current; }

  /**
   * @return the current segment.
   */
  inline constexpr auto& currentSegment() { return m_data[m_current]; }

  /**
   * @return true if the connection has free segments.
   */
  inline constexpr auto hasFree() const { return free() > 0; }

  /**
   * @return the connection's free segments count.
   */
  inline constexpr auto free() const { return size_t(CAPACITY - m_used); }

  /**
   * @return true if the connection has used segments.
   */
  inline constexpr auto hasUsed() const { return used() > 0; }

  /**
   * @return the connection's used segments count.
   */
  inline constexpr auto used() const { return size_t(m_used); }

  /**
   * @return a new segment.
   */
  inline auto& acquire()
  {
    size_t idx = 0;
    for (size_t i = m_current; i < m_current + CAPACITY; i += 1) {
      idx = i & MASK;
      if (m_data[idx].length() == 0) {
        m_used += 1;
        return m_data[idx];
      }
    }
    throw std::runtime_error("have you called hasFree()?");
  }

  /**
   * Release a segment.
   *
   * @param seg the segment to release.
   */
  inline bool release(Segment& seg)
  {
    auto idx = index(seg);
    /*
     * Make sure we are releasing the current segment.
     */
    if (idx != m_current) {
      return false;
    }
    /*
     * Clear the segment and update the counters.
     */
    m_data[idx].clear();
    m_current = (m_current + 1) & MASK;
    m_used -= 1;
    /*
     * Done.
     */
    return true;
  }

  /**
   * Return the index of a segment.
   *
   * @param seq the segment.
   *
   * @return the segment's index.
   */
  inline size_t index(Segment const& seg) const { return &seg - m_data; }

  /**
   * @return the segment container.
   */
  inline constexpr auto& container() { return m_data; }

private:
  uint32_t m_current;
  uint32_t m_used;
  Segment m_data[CAPACITY];
};

}
