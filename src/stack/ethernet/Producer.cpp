#include <tulips/stack/ethernet/Producer.h>
#include <arpa/inet.h>

namespace tulips::stack::ethernet {

Producer::Producer(system::Logger& log, transport::Producer& prod,
                   Address const& ha)
  : m_log(log), m_prod(prod), m_hostAddress(ha), m_destAddress(), m_type(0)
{}

Status
Producer::prepare(uint8_t*& buf)
{
  /*
   * Grab a buffer
   */
  uint8_t* tmp;
  Status ret = m_prod.prepare(tmp);
  if (ret != Status::Ok) {
    return ret;
  }
  /*
   * Prepare the header
   */
  auto* hdr = reinterpret_cast<Header*>(tmp);
  hdr->src = m_hostAddress;
  hdr->dest = m_destAddress;
  hdr->type = htons(m_type);
  /*
   * Advance that buffer
   */
  buf = tmp + HEADER_LEN;
  return ret;
}

Status
Producer::commit(const uint32_t len, uint8_t* const buf, const uint16_t mss)
{
  m_log.trace("ETH", "committing frame: ", len, "B");
  return m_prod.commit(len + HEADER_LEN, buf - HEADER_LEN, mss);
}

}
