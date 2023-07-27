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
  ~Device() override = default;

  stack::ethernet::Address const& address() const override { return m_address; }

  stack::ipv4::Address const& ip() const override { return m_ip; }

  stack::ipv4::Address const& gateway() const override { return m_dr; }

  stack::ipv4::Address const& netmask() const override { return m_nm; }

  Status listen(const stack::ipv4::Protocol proto, const uint16_t lport,
                stack::ipv4::Address const& raddr,
                const uint16_t rport) override;

  void unlisten(const stack::ipv4::Protocol proto, const uint16_t lport,
                stack::ipv4::Address const& raddr,
                const uint16_t rport) override;

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
  Device(const uint16_t port_id, const uint16_t queue_id,
         stack::ethernet::Address const& m_address, const uint32_t m_mtu,
         struct rte_mempool* const txpool, stack::ipv4::Address const& ip,
         stack::ipv4::Address const& dr, stack::ipv4::Address const& nm);

  uint16_t m_portid;
  uint16_t m_queueid;
  struct rte_mempool* m_txpool;

  friend class Port;

protected:
  stack::ethernet::Address m_address;
  stack::ipv4::Address m_ip;
  stack::ipv4::Address m_dr;
  stack::ipv4::Address m_nm;
  uint32_t m_mtu;
};

}
