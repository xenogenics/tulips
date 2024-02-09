#pragma once

#include <tulips/api/Connection.h>
#include <tulips/api/Interface.h>
#ifdef TULIPS_ENABLE_ARP
#include <tulips/stack/arp/Processor.h>
#endif
#ifdef TULIPS_ENABLE_ICMP
#include <tulips/stack/icmpv4/Processor.h>
#endif
#include <tulips/stack/tcpv4/Processor.h>
#include <tulips/system/Compiler.h>
#include <tulips/system/Logger.h>
#include <tulips/transport/Device.h>
#include <list>
#include <map>
#include <optional>
#include <vector>
#include <unistd.h>

namespace tulips::api {

class Client final
  : public interface::Client
  , public stack::tcpv4::EventHandler
{
public:
  /*
   * Types.
   */

  using api::interface::Client::ApplicationLayerProtocol;
  using interface::Client::Timestamp;

  /*
   * Allocator.
   */

  static Ref allocate(system::Logger& log, Delegate& dlg,
                      transport::Device& device, const size_t nconn,
                      stack::ipv4::Address const& ip,
                      stack::ipv4::Address const& gw,
                      stack::ipv4::Address const& nm)
  {
    return std::make_unique<Client>(log, dlg, device, nconn, ip, gw, nm);
  }

  /*
   * Constructor and destructor.
   */

  Client(system::Logger& log, Delegate& dlg, transport::Device& device,
         const size_t nconn, stack::ipv4::Address const& ip,
         stack::ipv4::Address const& gw, stack::ipv4::Address const& nm);
  ~Client() override = default;

  /*
   * Device interface.
   */

  inline Status run() override { return m_ethfrom.run(); }

  inline Status process(const uint16_t len, const uint8_t* const data,
                        const Timestamp ts) override
  {
    return m_ethfrom.process(len, data, ts);
  }

  inline Status sent(const uint16_t len, uint8_t* const data) override
  {
    return m_ethfrom.sent(len, data);
  }

  /*
   * Client interface.
   */

  bool live() const override;

  using interface::Client::open;

  Status open(const ApplicationLayerProtocol alpn, const uint16_t options,
              ID& id) override;

  Status setHostName(const ID id, std::string_view hn) override;

  Status getHostName(const ID id, std::optional<std::string>& hn) override;

  Status connect(const ID id, stack::ipv4::Address const& ripaddr,
                 const stack::tcpv4::Port rport) override;

  Status abort(const ID id) override;

  Status close(const ID id) override;

  bool isClosed(const ID id) const override;

  Status get(const ID id, stack::ipv4::Address& laddr,
             stack::tcpv4::Port& lport, stack::ipv4::Address& raddr,
             stack::tcpv4::Port& rport) const override;

  Status send(const ID id, const uint32_t len, const uint8_t* const data,
              uint32_t& off) override;

  size_t averageLatency(const ID id) override;

  /*
   * Client-specific interface.
   */

  ApplicationLayerProtocol applicationLayerProtocol(const ID id) const;

  void* cookie(const ID id) const;

private:
  using Connections = std::vector<Connection>;

#ifdef TULIPS_ENABLE_RAW
  class RawProcessor : public Processor
  {
  public:
    Status run() override { return Status::Ok; }

    Status process(UNUSED const uint16_t len, UNUSED const uint8_t* const data,
                   UNUSED const Timestamp ts) override
    {
      return Status::Ok;
    }

    Status sent(UNUSED const uint16_t len, UNUSED uint8_t* const buf) override
    {
      return Status::Ok;
    }
  };
#endif

  void onConnected(stack::tcpv4::Connection& c, const Timestamp ts) override;
  void onAborted(stack::tcpv4::Connection& c, const Timestamp ts) override;
  void onTimedOut(stack::tcpv4::Connection& c, const Timestamp ts) override;
  void onClosed(stack::tcpv4::Connection& c, const Timestamp ts) override;
  void onSent(stack::tcpv4::Connection& c, const Timestamp ts) override;

  Action onAcked(stack::tcpv4::Connection& c, const Timestamp ts,
                 const uint32_t alen, uint8_t* const sdata,
                 uint32_t& slen) override;

  Action onNewData(stack::tcpv4::Connection& c, const uint8_t* const data,
                   const uint32_t len, const Timestamp ts, const uint32_t alen,
                   uint8_t* const sdata, uint32_t& slen) override;

  system::Logger& m_log;
  Delegate& m_delegate;
  transport::Device& m_dev;
  size_t m_nconn;
  stack::ethernet::Producer m_ethto;
  stack::ipv4::Producer m_ip4to;
#ifdef TULIPS_ENABLE_ARP
  stack::arp::Processor m_arp;
#endif
  stack::ethernet::Processor m_ethfrom;
  stack::ipv4::Processor m_ip4from;
#ifdef TULIPS_ENABLE_ICMP
  stack::icmpv4::Processor m_icmpv4from;
#endif
#ifdef TULIPS_ENABLE_RAW
  RawProcessor m_raw;
#endif
  stack::tcpv4::Processor m_tcp;
  Connections m_cns;
};

}
