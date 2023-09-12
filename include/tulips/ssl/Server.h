#pragma once

#include <tulips/api/Interface.h>
#include <tulips/api/Server.h>
#include <tulips/ssl/Protocol.h>

namespace tulips::ssl {

class Server
  : public api::interface::Server
  , public api::interface::Server::Delegate
{
public:
  Server(system::Logger& log, api::interface::Server::Delegate& delegate,
         transport::Device& device, const ssl::Protocol type,
         std::string_view cert, std::string_view key, const size_t nconn);
  ~Server() override;

  inline Status run() override { return m_server->run(); }

  inline Status process(const uint16_t len, const uint8_t* const data) override
  {
    return m_server->process(len, data);
  }

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
  Status flush(const ID id, void* const cookie);

  api::interface::Server::Delegate& m_delegate;
  system::Logger& m_log;
  transport::Device& m_dev;
  std::unique_ptr<api::Server> m_server;
  void* m_context;
};

}
