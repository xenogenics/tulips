#pragma once

#include <tulips/stack/Ethernet.h>
#include <tulips/stack/IPv4.h>
#include <tulips/transport/Device.h>
#include <cstdint>
#include <map>
#include <string>
#include <vector>
#include <infiniband/verbs.h>

namespace tulips::transport::ofed {

class Device : public transport::Device
{
public:
  /*
   * Constants.
   */

  static constexpr size_t EVENT_CLEANUP_THRESHOLD = 16;
  static constexpr size_t INLINE_DATA_THRESHOLD = 256;

  static constexpr int POST_RECV_THRESHOLD = 32;
  static constexpr uint32_t RECV_BUFLEN = 2 * 1024;

  /*
   * Allocators.
   */

  static Ref allocate(system::Logger& log, const uint16_t nbuf)
  {
    return std::make_unique<Device>(log, nbuf);
  }

  static Ref allocate(system::Logger& log, std::string_view ifn,
                      const uint16_t nbuf)
  {
    return std::make_unique<Device>(log, ifn, nbuf);
  }

  /*
   * Constructors and destructor.
   */

  Device(system::Logger& log, const uint16_t nbuf);
  Device(system::Logger& log, std::string_view ifn, const uint16_t nbuf);
  ~Device() override;

  /*
   * Device interface.
   */

  stack::ethernet::Address const& address() const override { return m_address; }

  uint32_t mtu() const override { return m_mtu; }

  uint8_t receiveBufferLengthLog2() const override { return 11; }

  uint16_t receiveBuffersAvailable() const override
  {
    return m_nbuf - m_pending;
  }

  bool identify([[maybe_unused]] const uint8_t* const buf) const override
  {
    /*
     * NOTE(xrg): this MUST be implemented in case we want to enable bonding.
     */
    return true;
  }

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

  uint32_t mss() const override { return m_buflen; }

  Status prepare(uint8_t*& buf) override;
  Status commit(const uint16_t len, uint8_t* const buf,
                const uint16_t mss = 0) override;
  Status release(uint8_t* const buf) override;

private:
  using Filters = std::map<uint16_t, ibv_flow*>;
  using SentBuffer = std::tuple<uint16_t, uint8_t*>;

  void construct(std::string_view ifn, const uint16_t nbuf);
  Status postReceive(const uint16_t id);

  uint16_t m_nbuf;
  uint16_t m_pending;
  int m_port;
  ibv_context* m_context;
  stack::ethernet::Address m_address;
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
  std::vector<uint8_t*> m_free;
  std::vector<SentBuffer> m_sent;
  ibv_flow* m_bcast;
  ibv_flow* m_flow;
  Filters m_filters;
};

}
