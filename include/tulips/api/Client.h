#pragma once

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
#include <vector>
#include <unistd.h>

namespace tulips::api {

class Client
  : public interface::Client
  , public stack::tcpv4::EventHandler
{
public:
  Client(system::Logger& log, Delegate& dlg, transport::Device& device,
         const size_t nconn);
  ~Client() override = default;

  /**
   * Device interface.
   */

  inline Status run() override { return m_ethfrom.run(); }

  inline Status process(const uint16_t len, const uint8_t* const data) override
  {
    return m_ethfrom.process(len, data);
  }

  /**
   * Client interface.
   */

  Status open(ID& id) override;

  Status connect(const ID id, stack::ipv4::Address const& ripaddr,
                 const stack::tcpv4::Port rport) override;

  Status abort(const ID id) override;

  Status close(const ID id) override;

  bool isClosed(const ID id) const override;

  Status send(const ID id, const uint32_t len, const uint8_t* const data,
              uint32_t& off) override;

  system::Clock::Value averageLatency(const ID id) override;

  /**
   * Get information about a connection.
   *
   * @param id the connection's handle.
   * @param ripaddr the connection's remote IP address.
   * @param lport the connection's local port.
   * @param rport the connection's remote port.
   *
   * @return the status of the operation.
   */
  Status get(const ID id, stack::ipv4::Address& ripaddr,
             stack::tcpv4::Port& lport, stack::tcpv4::Port& rport);

  /*
   * @param id the connection's handle.
   *
   * @return the user-allocate cookie for the connection.
   */
  void* cookie(const ID id) const;

private:
  struct Connection
  {
    enum class State
    {
      Closed,
      Opened,
#ifdef TULIPS_ENABLE_ARP
      Resolving,
#endif
      Connecting,
      Connected
    };

    using History = std::list<system::Clock::Value>;

    Connection();

    State state;
    stack::tcpv4::Connection::ID conn;
#ifdef TULIPS_ENABLE_LATENCY_MONITOR
    size_t count;
    system::Clock::Value pre;
    system::Clock::Value lat;
    History history;
#endif
  };

  using Connections = std::vector<Connection>;
  using ConnectionIndex = std::map<stack::tcpv4::Connection::ID, ID>;

#ifdef TULIPS_ENABLE_RAW
  class RawProcessor : public Processor
  {
  public:
    Status run() override { return Status::Ok; }

    Status process(UNUSED const uint16_t len,
                   UNUSED const uint8_t* const data) override
    {
      return Status::Ok;
    }
  };
#endif

  void onConnected(stack::tcpv4::Connection& c) override;
  void onAborted(stack::tcpv4::Connection& c) override;
  void onTimedOut(stack::tcpv4::Connection& c) override;
  void onClosed(stack::tcpv4::Connection& c) override;
  void onSent(stack::tcpv4::Connection& c) override;

  Action onAcked(stack::tcpv4::Connection& c) override;

  Action onAcked(stack::tcpv4::Connection& c, const uint32_t alen,
                 uint8_t* const sdata, uint32_t& slen) override;

  Action onNewData(stack::tcpv4::Connection& c, const uint8_t* const data,
                   const uint32_t len) override;

  Action onNewData(stack::tcpv4::Connection& c, const uint8_t* const data,
                   const uint32_t len, const uint32_t alen,
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
  ConnectionIndex m_idx;
};

}
