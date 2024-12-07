#pragma once

#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/system/CircularBuffer.h>
#include <tulips/system/Compiler.h>
#include <tulips/transport/Device.h>
#include <tulips/transport/ena/AbstractionLayer.h>
#include <tulips/transport/ena/RedirectionTable.h>
#include <cstdint>
#include <cstdlib>
#include <vector>
#include <dpdk/rte_ethdev.h>
#include <dpdk/rte_mempool.h>

namespace tulips::transport::ena {

class Device : public transport::Device
{
public:
  /*
   * Destructor.
   */

  ~Device() override;

  /*
   * Device interface.
   */

  stack::ethernet::Address const& address() const override { return m_address; }

  Status listen(const stack::ipv4::Protocol proto,
                stack::ipv4::Address const& laddr, const uint16_t lport,
                stack::ipv4::Address const& raddr,
                const uint16_t rport) override;

  void unlisten(const stack::ipv4::Protocol proto,
                stack::ipv4::Address const& laddr, const uint16_t lport,
                stack::ipv4::Address const& raddr,
                const uint16_t rport) override;

  Status poll(Processor& proc) override;
  Status wait(Processor& proc, const uint64_t ns) override;

  Status prepare(uint8_t*& buf) override;
  Status commit(const uint16_t len, uint8_t* const buf,
                const uint16_t mss) override;
  Status release(uint8_t* const buf) override;

  uint32_t mtu() const override { return m_mtu - stack::ethernet::HEADER_LEN; }

  uint32_t mss() const override { return m_mtu; }

  uint8_t receiveBufferLengthLog2() const override { return 11; }

  uint16_t receiveBuffersAvailable() const override { return m_nrxbs; }

  bool identify(const uint8_t* const buf) const override;

private:
  using SentBuffer = std::tuple<uint16_t, uint8_t*>;

  Device(system::Logger& log, const uint16_t port_id, const uint16_t queue_id,
         const uint16_t ntxbs, const uint16_t nrxbs, RedirectionTable& reta,
         stack::ethernet::Address const& m_address, const uint32_t m_mtu,
         struct rte_mempool* const txpool, const bool bound);

  system::CircularBuffer::Ref internalBuffer() { return m_buffer; }

  Status clearSentBuffers(Processor& proc);

  Status poll(Processor& proc, const uint16_t nbrx, size_t& pktcnt);

  uint16_t m_portid;
  uint16_t m_qid;
  uint16_t m_ntxbs;
  uint16_t m_nrxbs;
  RedirectionTable& m_reta;
  struct rte_mempool* m_txpool;
  bool m_bound;
  system::CircularBuffer::Ref m_buffer;
  uint8_t* m_packet;
  std::vector<struct rte_mbuf*> m_free;
  std::vector<SentBuffer> m_sent;
  uint64_t m_laststats;

  friend class Port;

protected:
  stack::ethernet::Address m_address;
  uint32_t m_mtu;
};

}
