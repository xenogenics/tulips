#pragma once

#include <tulips/fifo/fifo.h>
#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/transport/Device.h>
#include <cstdint>
#include <map>
#include <string>
#include <infiniband/verbs.h>

namespace tulips::transport::ofed {

class Device : public transport::Device
{
public:
  static constexpr size_t EVENT_CLEANUP_THRESHOLD = 16;
  static constexpr size_t INLINE_DATA_THRESHOLD = 256;

  static constexpr int POST_RECV_THRESHOLD = 32;
  static constexpr uint32_t RECV_BUFLEN = 2 * 1024;

  Device(const uint16_t nbuf);
  Device(std::string const& ifn, const uint16_t nbuf);
  ~Device() override;

  stack::ethernet::Address const& address() const override { return m_address; }

  stack::ipv4::Address const& ip() const override { return m_ip; }

  stack::ipv4::Address const& gateway() const override { return m_dr; }

  stack::ipv4::Address const& netmask() const override { return m_nm; }

  uint32_t mtu() const override { return m_mtu; }

  uint8_t receiveBufferLengthLog2() const override { return 11; }

  uint16_t receiveBuffersAvailable() const override
  {
    return m_nbuf - m_pending;
  }

  Status listen(const stack::ipv4::Protocol proto, const uint16_t lport,
                stack::ipv4::Address const& raddr,
                const uint16_t rport) override;

  void unlisten(const stack::ipv4::Protocol proto, const uint16_t lport,
                stack::ipv4::Address const& raddr,
                const uint16_t rport) override;

  Status poll(Processor& proc) override;
  Status wait(Processor& proc, const uint64_t ns) override;

  uint32_t mss() const override { return m_buflen; }

  Status prepare(uint8_t*& buf) override;
  Status commit(const uint32_t len, uint8_t* const buf,
                const uint16_t mss = 0) override;

private:
  using Filters = std::map<uint16_t, ibv_flow*>;

  void construct(std::string const& ifn, const uint16_t nbuf);
  Status postReceive(const uint16_t id);

  uint16_t m_nbuf;
  uint16_t m_pending;
  int m_port;
  ibv_context* m_context;
  stack::ethernet::Address m_address;
  stack::ipv4::Address m_ip;
  stack::ipv4::Address m_dr;
  stack::ipv4::Address m_nm;
  uint32_t m_hwmtu;
  uint32_t m_mtu;
  size_t m_buflen;
  ibv_pd* m_pd;
  ibv_comp_channel* m_comp;
  size_t m_events;
  ibv_cq* m_sendcq;
  ibv_cq* m_recvcq;
  ibv_qp* m_qp;
  uint8_t* m_sendbuf;
  uint8_t* m_recvbuf;
  ibv_mr* m_sendmr;
  ibv_mr* m_recvmr;
  tulips_fifo_t m_fifo;
  ibv_flow* m_bcast;
  ibv_flow* m_flow;
  Filters m_filters;
};

}
