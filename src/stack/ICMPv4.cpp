#include <tulips/stack/ICMPv4.h>
#include <tulips/stack/Utils.h>
#include <arpa/inet.h>

namespace tulips::stack::icmpv4 {

/**
 * ICMPv4 checksum.
 */
uint16_t
checksum(const uint8_t* const data)
{
  uint16_t sum = utils::checksum(0, data, sizeof(Header));
  return (sum == 0) ? 0xffff : htons(sum);
}

}
