#include <tulips/stack/Utils.h>
#include <tulips/system/SpinLock.h>
#include <tulips/transport/ena/RedirectionTable.h>
#include <mutex>

namespace tulips::transport::ena {

RedirectionTable::RedirectionTable(const uint16_t portid, const size_t size,
                                   const size_t hlen, const uint8_t* const hkey)
  : m_portid(portid)
  , m_size(size)
  , m_hlen(hlen)
  , m_hkey(hkey)
  , m_lock()
  , m_cache()
  , m_table(new struct rte_eth_rss_reta_entry64[size >> 6])
{
  auto count = size >> 6;
  /*
   * Reset the RETA to point all entries to the 0th queue.
   */
  for (size_t i = 0; i < count; i += 1) {
    m_table[i].mask = uint64_t(-1);
    memset(m_table[i].reta, 0, sizeof(m_table[i].reta));
  }
  /*
   * Update the RETA.
   */
  auto ret = rte_eth_dev_rss_reta_update(m_portid, m_table, m_size);
  if (ret != 0) {
    throw std::runtime_error("Failed to reset the RETA to the 0th queue");
  }
  /*
   * Resize the internal cache.
   */
  m_cache.resize(size);
}

Status
RedirectionTable::set(stack::ipv4::Address const& laddr, const uint16_t lport,
                      stack::ipv4::Address const& raddr, const uint16_t rport,
                      const uint16_t queueid)
{
  using stack::utils::toeplitz;
  /*
   * Lock the table.
   */
  auto lock = std::lock_guard(m_lock);
  /*
   * Hash the payload and get the table index.
   */
  auto hash = toeplitz(raddr, laddr, rport, lport, m_hlen, m_hkey);
  uint64_t indx = hash % m_size;
  uint64_t slot = indx >> 6;
  uint64_t eidx = indx & 0x3F;
  /*
   * Prepare the RETA for an query.
   */
  memset(m_table, 0, sizeof(struct rte_eth_rss_reta_entry64[m_size >> 6]));
  m_table[slot].mask = 1ULL << eidx;
  /*
   * Query the RETA.
   */
  auto ret = rte_eth_dev_rss_reta_query(m_portid, m_table, m_size);
  if (ret < 0) {
    return Status::HardwareError;
  }
  /*
   * Check the existing entry.
   */
  auto preq = m_table[slot].reta[eidx];
  if (preq != 0 && preq != queueid) {
    return Status::ResourceBusy;
  }
  /*
   * Check if we need to update the RETA.
   */
  if (preq == 0) {
    /*
     * Prepare the RETA for an update.
     */
    memset(m_table, 0, sizeof(struct rte_eth_rss_reta_entry64[m_size >> 6]));
    m_table[slot].mask = 1ULL << eidx;
    m_table[slot].reta[eidx] = queueid;
    /*
     * Update the RETA.
     */
    auto ret = rte_eth_dev_rss_reta_update(m_portid, m_table, m_size);
    if (ret != 0) {
      return Status::HardwareError;
    }
  }
  /*
   * Update the cache and return.
   */
  m_cache[indx] += 1;
  return Status::Ok;
}

Status
RedirectionTable::clear(stack::ipv4::Address const& laddr, const uint16_t lport,
                        stack::ipv4::Address const& raddr, const uint16_t rport,
                        const uint16_t queueid)
{
  using stack::utils::toeplitz;
  /*
   * Lock the table.
   */
  auto lock = std::lock_guard(m_lock);
  /*
   * Hash the payload and get the table index.
   */
  auto hash = toeplitz(raddr, laddr, rport, lport, m_hlen, m_hkey);
  uint64_t indx = hash % m_size;
  uint64_t slot = indx >> 6;
  uint64_t eidx = indx & 0x3F;
  /*
   * Prepare the RETA for a query.
   */
  memset(m_table, 0, sizeof(struct rte_eth_rss_reta_entry64[m_size >> 6]));
  m_table[slot].mask = 1ULL << eidx;
  /*
   * Query the RETA.
   */
  auto ret = rte_eth_dev_rss_reta_query(m_portid, m_table, m_size);
  if (ret < 0) {
    return Status::HardwareError;
  }
  /*
   * Check the existing entry.
   */
  auto preq = m_table[slot].reta[eidx];
  if (preq != queueid) {
    return Status::InvalidArgument;
  }
  /*
   * Update the cache.
   */
  m_cache[indx] -= 1;
  /*
   * Check if we need to update the RETA.
   */
  if (m_cache[indx] == 0) {
    /*
     * Prepare the RETA for an update.
     */
    memset(m_table, 0, sizeof(struct rte_eth_rss_reta_entry64[m_size >> 6]));
    m_table[slot].mask = 1ULL << eidx;
    m_table[slot].reta[eidx] = 0;
    /*
     * Update the RETA.
     */
    auto ret = rte_eth_dev_rss_reta_update(m_portid, m_table, m_size);
    if (ret != 0) {
      return Status::HardwareError;
    }
  }
  /*
   * Done.
   */
  return Status::Ok;
}

RedirectionTable::~RedirectionTable()
{
  delete[] m_table;
  m_table = nullptr;
}

}
