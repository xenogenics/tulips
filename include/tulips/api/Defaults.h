#pragma once

#include <tulips/api/Client.h>
#include <tulips/api/Server.h>

namespace tulips::api::defaults {

class ClientDelegate : public Client::Delegate
{
public:
  using Client::Delegate::Timestamp;

  void* onConnected(Client::ID const& id, void* const cookie,
                    const Timestamp ts) override;

  Action onAcked(Client::ID const& id, void* const cookie, const Timestamp ts,
                 const uint32_t savl, uint8_t* const sdat,
                 uint32_t& slen) override;

  Action onNewData(Client::ID const& id, void* const cookie,
                   const uint8_t* const rdat, const uint32_t rlen,
                   const Timestamp ts, const uint32_t savl, uint8_t* const sdat,
                   uint32_t& slen) override;

  void onClosed(Client::ID const& id, void* const cookie,
                const Timestamp ts) override;
};

class ServerDelegate : public Server::Delegate
{
public:
  using Server::Delegate::Timestamp;

  void* onConnected(Server::ID const& id, void* const cookie,
                    const Timestamp ts) override;

  Action onAcked(Server::ID const& id, void* const cookie, const Timestamp ts,
                 const uint32_t savl, uint8_t* const sdat,
                 uint32_t& slen) override;

  Action onNewData(Server::ID const& id, void* const cookie,
                   const uint8_t* const rdat, const uint32_t rlen,
                   const Timestamp ts, const uint32_t savl, uint8_t* const sdat,
                   uint32_t& slen) override;

  void onClosed(Server::ID const& id, void* const cookie,
                const Timestamp ts) override;
};

}
