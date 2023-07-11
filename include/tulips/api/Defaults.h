#pragma once

#include <tulips/api/Client.h>
#include <tulips/api/Server.h>

namespace tulips::defaults {

class ClientDelegate : public Client::Delegate
{
public:
  void* onConnected(Client::ID const& id, void* const cookie,
                    uint8_t& opts) override;

  Action onAcked(Client::ID const& id, void* const cookie) override;

  Action onAcked(Client::ID const& id, void* const cookie, const uint32_t alen,
                 uint8_t* const sdata, uint32_t& slen) override;

  Action onNewData(Client::ID const& id, void* const cookie,
                   const uint8_t* const data, const uint32_t len) override;

  Action onNewData(Client::ID const& id, void* const cookie,
                   const uint8_t* const data, const uint32_t len,
                   const uint32_t alen, uint8_t* const sdata,
                   uint32_t& slen) override;

  void onClosed(Client::ID const& id, void* const cookie) override;
};

class ServerDelegate : public Server::Delegate
{
public:
  void* onConnected(Server::ID const& id, void* const cookie,
                    uint8_t& opts) override;

  Action onAcked(Server::ID const& id, void* const cookie) override;

  Action onAcked(Server::ID const& id, void* const cookie, const uint32_t alen,
                 uint8_t* const sdata, uint32_t& slen) override;

  Action onNewData(Server::ID const& id, void* const cookie,
                   const uint8_t* const data, const uint32_t len) override;

  Action onNewData(Server::ID const& id, void* const cookie,
                   const uint8_t* const data, const uint32_t len,
                   const uint32_t alen, uint8_t* const sdata,
                   uint32_t& slen) override;

  void onClosed(Server::ID const& id, void* const cookie) override;
};

}
