#include "Debug.h"
#include <tulips/stack/tcpv4/Processor.h>

std::string
getFlags(tulips::stack::tcpv4::Header const& hdr)
{
  std::string res = "[........]";
  /*
   * Mark the present flags.
   */
  if (hdr.flags & TCP_FIN) {
    res[1] = 'F';
  }
  if (hdr.flags & TCP_SYN) {
    res[2] = 'S';
  }
  if (hdr.flags & TCP_RST) {
    res[3] = 'R';
  }
  if (hdr.flags & TCP_PSH) {
    res[4] = 'P';
  }
  if (hdr.flags & TCP_ACK) {
    res[5] = 'A';
  }
  if (hdr.flags & TCP_URG) {
    res[6] = 'U';
  }
  if (hdr.flags & TCP_ECE) {
    res[7] = 'E';
  }
  if (hdr.flags & TCP_CWR) {
    res[8] = 'C';
  }
  return res;
}
