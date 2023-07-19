#pragma once

#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/system/Compiler.h>
#include <tulips/transport/Device.h>
#include <tulips/transport/dpdk/AbstractionLayer.h>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <string>
#include <dpdk/rte_ethdev.h>
#include <dpdk/rte_mempool.h>

namespace tulips::transport::dpdk {

class Device : public transport::Device
{
public:
  Device(const uint16_t nbuf);
  Device(std::string const& ifn, const uint16_t nbuf);
  ~Device() override;

  stack::ethernet::Address const& address() const override { return m_address; }

  stack::ipv4::Address const& ip() const override { return m_ip; }

  stack::ipv4::Address const& gateway() const override { return m_dr; }

  stack::ipv4::Address const& netmask() const override { return m_nm; }

  Status listen(const uint16_t UNUSED port) override { return Status::Ok; }

  void unlisten(const uint16_t UNUSED port) override {}

  Status poll(Processor& proc) override;
  Status wait(Processor& proc, const uint64_t ns) override;

  Status prepare(uint8_t*& buf) override;
  Status commit(const uint32_t len, uint8_t* const buf,
                const uint16_t mss) override;

  uint32_t mtu() const override { return m_mtu - stack::ethernet::HEADER_LEN; }

  uint32_t mss() const override { return m_mtu; }

  uint8_t receiveBufferLengthLog2() const override { return 11; }

  uint16_t receiveBuffersAvailable() const override
  {
    /*
     * TODO(xrg): check OFED.
     */
    return std::numeric_limits<uint16_t>::max();
  }

private:
  static AbstractionLayer s_eal;

  uint16_t m_portid;
  struct rte_mempool* m_mempool;
  struct rte_eth_conf m_ethconf;
  struct rte_ether_addr m_macaddr;
  struct rte_eth_rxconf m_rxqconf;
  struct rte_eth_txconf m_txqconf;

protected:
  stack::ethernet::Address m_address;
  stack::ipv4::Address m_ip;
  stack::ipv4::Address m_dr;
  stack::ipv4::Address m_nm;
  uint32_t m_mtu;
};

}
