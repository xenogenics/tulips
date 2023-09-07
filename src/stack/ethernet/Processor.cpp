#include <tulips/stack/ethernet/Processor.h>
#include <tulips/system/Utils.h>
#ifdef TULIPS_ENABLE_ARP
#include <tulips/stack/arp/Processor.h>
#endif
#include <tulips/stack/ipv4/Processor.h>
#include <arpa/inet.h>

namespace tulips::stack::ethernet {

Processor::Processor(system::Logger& log, Address const& ha)
  : m_log(log)
  , m_hostAddress(ha)
  , m_srceAddress()
  , m_destAddress()
  , m_type(0)
#ifdef TULIPS_ENABLE_RAW
  , m_raw(nullptr)
#endif
#ifdef TULIPS_ENABLE_ARP
  , m_arp(nullptr)
#endif
  , m_ipv4(nullptr)
{}

Status
Processor::run()
{
  Status ret = Status::Ok;
  /*
   * Reset the state
   */
  m_srceAddress = Address();
  m_destAddress = Address();
  m_type = 0;
  /*
   * Run the processors
   */
#ifdef TULIPS_ENABLE_RAW
  if (m_raw) {
    ret = m_raw->run();
  }
#endif
#ifdef TULIPS_ENABLE_ARP
  if (m_arp && ret == Status::Ok) {
    ret = m_arp->run();
  }
#endif
  if (m_ipv4 && ret == Status::Ok) {
    ret = m_ipv4->run();
  }
  return ret;
}

Status
Processor::process(const uint16_t len, const uint8_t* const data)
{
  m_log.trace("ETH", "processing frame: ", len, "B");
  /*
   * Grab the incoming information
   */
  const auto* hdr = reinterpret_cast<const Header*>(data);
  m_srceAddress = hdr->src;
  m_destAddress = hdr->dest;
  m_type = ntohs(hdr->type);
  /*
   * Process the remaing buffer
   */
  Status ret;
  switch (m_type) {
#ifdef TULIPS_ENABLE_ARP
    case ETHTYPE_ARP: {
#ifdef TULIPS_STACK_RUNTIME_CHECK
      if (!m_arp) {
        ret = Status::UnsupportedProtocol;
        break;
      }
#endif
      ret = m_arp->process(len - HEADER_LEN, data + HEADER_LEN);
      break;
    }
#endif
    case ETHTYPE_IP: {
#ifdef TULIPS_STACK_RUNTIME_CHECK
      if (!m_ipv4) {
        ret = Status::UnsupportedProtocol;
        break;
      }
#endif
      ret = m_ipv4->process(len - HEADER_LEN, data + HEADER_LEN);
      break;
    }
    default: {
#ifdef TULIPS_ENABLE_RAW
      if (m_type <= 1500) {
#ifdef TULIPS_STACK_RUNTIME_CHECK
        if (!m_raw) {
          ret = Status::UnsupportedProtocol;
          break;
        }
#endif
        ret = m_raw->process(m_type, data + HEADER_LEN);
        break;
      }
#endif
      ret = Status::UnsupportedProtocol;
      break;
    }
  }
  /*
   * Process outputs
   */
  return ret;
}

}
