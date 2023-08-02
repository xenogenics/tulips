#pragma once

#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/transport/Device.h>
#include <tulips/transport/ena/AbstractionLayer.h>
#include <list>
#include <string>
#include <vector>
#include <dpdk/rte_ethdev.h>
#include <dpdk/rte_mempool.h>

namespace tulips::transport::ena {

class Port : transport::Device
{
public:
  /*
   * Constructor.
   */

  Port(std::string const& ifn, const size_t width, const size_t depth);
  ~Port() override;

  stack::ethernet::Address const& address() const override { return m_address; }

  /*
   * Device interface.
   */

  stack::ipv4::Address const& ip() const override
  {
    return stack::ipv4::Address::ANY;
  }

  stack::ipv4::Address const& gateway() const override
  {
    return stack::ipv4::Address::ANY;
  }

  stack::ipv4::Address const& netmask() const override
  {
    return stack::ipv4::Address::ANY;
  }

  Status listen(UNUSED const stack::ipv4::Protocol proto,
                UNUSED const uint16_t lport,
                UNUSED stack::ipv4::Address const& raddr,
                UNUSED const uint16_t rport) override
  {
    return Status::UnsupportedOperation;
  }

  void unlisten(UNUSED const stack::ipv4::Protocol proto,
                UNUSED const uint16_t lport,
                UNUSED stack::ipv4::Address const& raddr,
                UNUSED const uint16_t rport) override
  {}

  Status poll(Processor& proc) override;
  Status wait(Processor& proc, const uint64_t ns) override;

  Status prepare(UNUSED uint8_t*& buf) override
  {
    return Status::UnsupportedOperation;
  }

  Status commit(UNUSED const uint32_t len, UNUSED uint8_t* const buf,
                UNUSED const uint16_t mss) override
  {
    return Status::UnsupportedOperation;
  }

  uint32_t mtu() const override { return m_mtu - stack::ethernet::HEADER_LEN; }

  uint32_t mss() const override { return m_mtu; }

  uint8_t receiveBufferLengthLog2() const override { return 11; }

  uint16_t receiveBuffersAvailable() const override { return 0; }

  /*
   * Device enumerator.
   */

  Device::Ref next(stack::ipv4::Address const& ip,
                   stack::ipv4::Address const& dr,
                   stack::ipv4::Address const& nm);

private:
  /*
   * Private methods.
   */
  void configure(struct rte_eth_dev_info const& dev_info, const uint16_t nqus);

  void setupPoolsAndQueues(const uint16_t buflen, const uint16_t nqus,
                           const uint16_t ndsc);

  void setupReceiveSideScaling(struct rte_eth_dev_info const& dev_info);

  /*
   * Members.
   */
  static AbstractionLayer s_eal;

  uint16_t m_portid;
  stack::ethernet::Address m_address;
  uint32_t m_mtu;
  struct rte_eth_conf m_ethconf;
  size_t m_hlen;
  uint8_t* m_hkey;
  std::vector<struct rte_mempool*> m_rxpools;
  std::vector<struct rte_mempool*> m_txpools;
  std::list<uint16_t> m_free;
  size_t m_retasz;
};

}
