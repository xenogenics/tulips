#include "Debug.h"
#include <tulips/stack/tcpv4/Processor.h>

using tulips::stack::tcpv4::Flag;
using tulips::stack::tcpv4::Header;

std::string
getFlags(Header const& hdr)
{
  std::string res = "[........]";
  /*
   * Mark the present flags.
   */
  if (hdr.flags & Flag::FIN) {
    res[1] = 'F';
  }
  if (hdr.flags & Flag::SYN) {
    res[2] = 'S';
  }
  if (hdr.flags & Flag::RST) {
    res[3] = 'R';
  }
  if (hdr.flags & Flag::PSH) {
    res[4] = 'P';
  }
  if (hdr.flags & Flag::ACK) {
    res[5] = 'A';
  }
  if (hdr.flags & Flag::URG) {
    res[6] = 'U';
  }
  if (hdr.flags & Flag::ECE) {
    res[7] = 'E';
  }
  if (hdr.flags & Flag::CWR) {
    res[8] = 'C';
  }
  return res;
}
