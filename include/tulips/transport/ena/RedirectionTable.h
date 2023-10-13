#pragma once

#include <tulips/api/Status.h>
#include <tulips/stack/IPv4.h>
#include <tulips/system/SpinLock.h>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <vector>
#include <dpdk/rte_ethdev.h>

namespace tulips::transport::ena {

class RedirectionTable
{
public:
  /*
   * Types.
   */

  using Ref = std::unique_ptr<RedirectionTable>;

  /*
   * Allocator.
   */

  static Ref allocate(const uint16_t portid, const size_t size,
                      const size_t hlen, const uint8_t* const hkey)
  {
    return Ref(new RedirectionTable(portid, size, hlen, hkey));
  }

  /*
   * Life cycle.
   */

  ~RedirectionTable();

  /*
   * Flow registration.
   */

  Status set(stack::ipv4::Address const& laddr, const uint16_t lport,
             stack::ipv4::Address const& raddr, const uint16_t rport,
             const uint16_t queueid);

  Status clear(stack::ipv4::Address const& laddr, const uint16_t lport,
               stack::ipv4::Address const& raddr, const uint16_t rport,
               const uint16_t queueid);

private:
  /*
   * Constructor.
   */

  RedirectionTable(const uint16_t portid, const size_t size, const size_t hlen,
                   const uint8_t* const hkey);

  /*
   * Attributes.
   */

  uint16_t m_portid;
  size_t m_size;
  size_t m_hlen;
  const uint8_t* m_hkey;
  system::SpinLock m_lock;
  std::vector<size_t> m_cache;
  struct rte_eth_rss_reta_entry64* m_table;
};

}
