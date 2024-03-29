#pragma once

#include <tulips/api/Defaults.h>
#include <tulips/stack/IPv4.h>
#include <tulips/system/Logger.h>
#include <tulips/transport/Device.h>
#include <tulips/transport/ena/Device.h>
#include <tulips/transport/pcap/Device.h>
#include <memory>
#include <string>
#include <pthread.h>
#include <utils/Command.h>

namespace tulips::tools::uspace::ena::poller {

class Poller
{
public:
  using Ref = std::unique_ptr<Poller>;

  Poller(system::Logger& log, transport::Device::Ref dev,
         stack::ipv4::Address const& ip, stack::ipv4::Address const& dr,
         stack::ipv4::Address const& nm, const bool pcap, const bool ssl);
  Poller(Poller&&) = default;
  ~Poller();

  Status connect(stack::ipv4::Address const& ripaddr,
                 const stack::tcpv4::Port rport, api::Client::ID& id);

  Status close(const api::Client::ID id);

  Status get(const api::Client::ID id, stack::ipv4::Address& ripaddr,
             stack::tcpv4::Port& lport, stack::tcpv4::Port& rport);

  Status write(const api::Client::ID id, std::string_view data);

private:
  enum class Action
  {
    Connect,
    Close,
    Closing,
    Info,
    Write,
    None
  };

  static void* entrypoint(void* data)
  {
    auto* poller = reinterpret_cast<Poller*>(data);
    poller->run();
    return nullptr;
  }

  void run();

  std::string m_name;
  transport::Device::Ref m_device;
  api::defaults::ClientDelegate m_delegate;
  std::unique_ptr<api::interface::Client> m_client;
  volatile bool m_run;
  pthread_t m_thread;
  pthread_mutex_t m_mutex;
  pthread_cond_t m_cond;
  Action m_action;
  stack::ipv4::Address m_raddr;
  stack::tcpv4::Port m_lport;
  stack::tcpv4::Port m_rport;
  api::Client::ID m_id;
  Status m_status;
  std::string m_data;
};

void populate(utils::Commands& cmds);

}
