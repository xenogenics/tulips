#pragma once

#include <tulips/api/Interface.h>
#include <tulips/api/Server.h>
#include <tulips/ssl/Connection.h>
#include <tulips/ssl/Protocol.h>

namespace tulips::ssl {

class Server
  : public api::interface::Server
  , public api::interface::Server::Delegate
{
public:
  /**
   * Type alias import.
   */
  using api::interface::Server::Timestamp;

  /**
   * Constructor and destructor.
   */
  Server(system::Logger& log, api::interface::Server::Delegate& delegate,
         transport::Device& device, const ssl::Protocol type,
         std::string_view cert, std::string_view key, const size_t nconn,
         stack::ipv4::Address const& ip, stack::ipv4::Address const& gw,
         stack::ipv4::Address const& nm);
  ~Server() override;

  /**
   * Device interface.
   */

  inline Status run() override { return m_server->run(); }

  inline Status process(const uint16_t len, const uint8_t* const data,
                        const Timestamp ts) override
  {
    return m_server->process(len, data, ts);
  }

  inline Status sent(const uint16_t len, uint8_t* const data) override
  {
    return m_server->sent(len, data);
  }

  /**
   * Server interface.
   */

  inline void setOptions(const ID id, const uint8_t options) override
  {
    m_server->setOptions(id, options);
  }

  inline void clearOptions(const ID id, const uint8_t options) override
  {
    m_server->clearOptions(id, options);
  }

  Status close(const ID id) override;

  bool isClosed(const ID id) const override;

  Status send(const ID id, const uint32_t len, const uint8_t* const data,
              uint32_t& off) override;

  inline void listen(const stack::tcpv4::Port port, void* cookie) override
  {
    m_server->listen(port, cookie);
  }

  inline void unlisten(const stack::tcpv4::Port port) override
  {
    m_server->unlisten(port);
  }

  /**
   * Server delegate.
   */

  void* onConnected(ID const& id, void* const cookie,
                    const Timestamp ts) override;

  Action onAcked(ID const& id, void* const cookie, const Timestamp ts) override;

  Action onAcked(ID const& id, void* const cookie, const Timestamp ts,
                 const uint32_t alen, uint8_t* const sdata,
                 uint32_t& slen) override;

  Action onNewData(ID const& id, void* const cookie, const uint8_t* const data,
                   const uint32_t len, const Timestamp ts) override;

  Action onNewData(ID const& id, void* const cookie, const uint8_t* const data,
                   const uint32_t len, const Timestamp ts, const uint32_t alen,
                   uint8_t* const sdata, uint32_t& slen) override;

  void onClosed(ID const& id, void* const cookie, const Timestamp ts) override;

private:
  using Connections = std::vector<Connection>;

  Status flush(const ID id);

  api::interface::Server::Delegate& m_delegate;
  system::Logger& m_log;
  std::unique_ptr<api::Server> m_server;
  size_t m_nconn;
  void* m_ssl;
  Connections m_cns;
};

}
