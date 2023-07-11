#include <tulips/stack/tcpv4/Segment.h>

namespace tulips::stack::tcpv4 {

Segment::Segment() : m_len(0), m_seq(0), m_dat(nullptr) {}

}
