#pragma once

#include <tulips/api/Client.h>
#include <tulips/api/Interface.h>
#include <tulips/ssl/Connection.h>
#include <tulips/ssl/Protocol.h>

namespace tulips::ssl {

class Client final
  : public api::interface::Client
  , public api::interface::Client::Delegate
{
public:
  /*
   * Types.
   */

  using api::interface::Client::ApplicationLayerProtocol;
  using api::interface::Client::Timestamp;

  /*
   * Allocators.
   */

  static Ref allocate(system::Logger& log,
                      api::interface::Client::Delegate& delegate,
                      transport::Device& device, stack::ipv4::Address const& ip,
                      stack::ipv4::Address const& gw,
                      stack::ipv4::Address const& nm, const Protocol type,
                      const bool save_keys)
  {
    return std::make_unique<Client>(log, delegate, device, ip, gw, nm, type,
                                    save_keys);
  }

  static Ref allocate(system::Logger& log,
                      api::interface::Client::Delegate& delegate,
                      transport::Device& device, stack::ipv4::Address const& ip,
                      stack::ipv4::Address const& gw,
                      stack::ipv4::Address const& nm, const Protocol type,
                      std::string_view cert, std::string_view key)
  {
    return std::make_unique<Client>(log, delegate, device, ip, gw, nm, type,
                                    cert, key);
  }

  /*
   * Constructors and destructor.
   */

  Client(system::Logger& log, api::interface::Client::Delegate& delegate,
         transport::Device& device, stack::ipv4::Address const& ip,
         stack::ipv4::Address const& gw, stack::ipv4::Address const& nm,
         const Protocol type, const bool save_keys);

  Client(system::Logger& log, api::interface::Client::Delegate& delegate,
         transport::Device& device, stack::ipv4::Address const& ip,
         stack::ipv4::Address const& gw, stack::ipv4::Address const& nm,
         const Protocol type, std::string_view cert, std::string_view key);

  ~Client() override;

  /*
   * Processor interface.
   */

  inline Status run() override { return m_client.run(); }

  inline Status process(const uint16_t len, const uint8_t* const data,
                        const Timestamp ts) override
  {
    return m_client.process(len, data, ts);
  }

  inline Status sent(const uint16_t len, uint8_t* const data) override
  {
    return m_client.sent(len, data);
  }

  /*
   * Client interface.
   */

  bool live() const override;

  using api::interface::Client::open;

  Status open(const ApplicationLayerProtocol alpn, const uint16_t options,
              ID& id) override;

  Status abort(const ID id) override;

  Status close(const ID id) override;

  Status setHostName(const ID id, std::string_view hn) override;

  Status getHostName(const ID id, std::optional<std::string>& hn) override;

  Status connect(const ID id, stack::ipv4::Address const& ripaddr,
                 const stack::tcpv4::Port rport) override;

  bool isClosed(const ID id) const override;

  Status get(const ID id, stack::ipv4::Address& laddr,
             stack::tcpv4::Port& lport, stack::ipv4::Address& raddr,
             stack::tcpv4::Port& rport) const override;

  Status send(const ID id, const uint32_t len, const uint8_t* const data,
              uint32_t& off) override;

  size_t averageLatency(const ID id) override;

  /*
   * Client delegate.
   */

  void* onConnected(ID const& id, void* const cookie,
                    const Timestamp ts) override;

  Action onAcked(ID const& id, void* const cookie, const Timestamp ts,
                 const uint32_t alen, uint8_t* const sdata,
                 uint32_t& slen) override;

  Action onNewData(ID const& id, void* const cookie, const uint8_t* const data,
                   const uint32_t len, const bool pushed, const Timestamp ts,
                   const uint32_t alen, uint8_t* const sdata,
                   uint32_t& slen) override;

  void onClosed(ID const& id, void* const cookie, const Timestamp ts) override;

private:
  using Connections = std::vector<Connection>;

  Status flush(const ID id);

  api::interface::Client::Delegate& m_delegate;
  system::Logger& m_log;
  tulips::api::Client m_client;
  void* m_ssl;
  bool m_savekeys;
  Connections m_cns;
};

}
