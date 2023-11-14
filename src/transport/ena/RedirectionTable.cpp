#include <tulips/stack/Utils.h>
#include <tulips/system/SpinLock.h>
#include <tulips/transport/ena/RedirectionTable.h>
#include <mutex>

namespace tulips::transport::ena {

RedirectionTable::RedirectionTable(const uint16_t portid, const size_t nqus,
                                   const size_t size, const size_t hlen,
                                   const uint8_t* const hkey)
  : m_portid(portid)
  , m_size(size)
  , m_hlen(hlen)
  , m_hkey(hkey)
  , m_table(new struct rte_eth_rss_reta_entry64[size >> 6])
{
  auto count = size >> 6;
  auto partlen = size / (nqus - 1);
  /*
   * Reset the RETA.
   */
  for (size_t i = 0; i < count; i += 1) {
    m_table[i].mask = uint64_t(-1);
    memset(m_table[i].reta, 0, sizeof(m_table[i].reta));
  }
  /*
   * Partition the RETA.
   *
   * NOTE(xrg): we don't allocate any slot for queue 0 as its sole purpose it to
   * handle L2 messages.
   */
  for (size_t i = 0; i < nqus - 1; i += 1) {
    for (size_t j = 0; j < partlen; j += 1) {
      auto indx = i * partlen + j;
      auto slot = indx >> 6;
      auto eidx = indx & 0x3F;
      m_table[slot].reta[eidx] = i + 1;
    }
  }
  /*
   * Allocate any remaining slots to the last queue.
   */
  for (size_t i = (nqus - 1) * partlen; i < size; i += 1) {
    auto slot = i >> 6;
    auto eidx = i & 0x3F;
    m_table[slot].reta[eidx] = nqus - 1;
  }
  /*
   * Update the RETA.
   */
  auto ret = rte_eth_dev_rss_reta_update(m_portid, m_table, m_size);
  if (ret != 0) {
    throw std::runtime_error("Failed to setup the redirection table");
  }
}

RedirectionTable::~RedirectionTable()
{
  delete[] m_hkey;
  m_hkey = nullptr;
  delete[] m_table;
  m_table = nullptr;
}

Status
RedirectionTable::match(stack::ipv4::Address const& laddr, const uint16_t lport,
                        stack::ipv4::Address const& raddr, const uint16_t rport,
                        const uint16_t queueid)
{
  using stack::utils::toeplitz;
  /*
   * Hash the payload and get the table index.
   */
  auto hash = toeplitz(raddr, laddr, rport, lport, m_hlen, m_hkey);
  uint64_t indx = hash % m_size;
  uint64_t slot = indx >> 6;
  uint64_t eidx = indx & 0x3F;
  /*
   * Check the entry.
   */
  auto preq = m_table[slot].reta[eidx];
  if (preq != queueid) {
    return Status::ResourceBusy;
  }
  /*
   * Done.
   */
  return Status::Ok;
}

}
