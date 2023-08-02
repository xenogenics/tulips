#pragma once

#include <tulips/api/Client.h>
#include <tulips/api/Defaults.h>
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

  Poller(transport::Device::Ref dev, const bool pcap);
  Poller(Poller&&) = default;
  ~Poller();

  Status connect(stack::ipv4::Address const& ripaddr,
                 const stack::tcpv4::Port rport, Client::ID& id);

  Status close(const Client::ID id);

  Status get(const Client::ID id, stack::ipv4::Address& ripaddr,
             stack::tcpv4::Port& lport, stack::tcpv4::Port& rport);

  Status write(const Client::ID id, std::string const& data);

private:
  enum class Action
  {
    Connect,
    Close,
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

  const bool m_capture;
  transport::Device::Ref m_dev;
  transport::pcap::Device* m_pcap;
  transport::Device* m_device;
  defaults::ClientDelegate m_delegate;
  Client m_client;
  volatile bool m_run;
  pthread_t m_thread;
  pthread_mutex_t m_mutex;
  pthread_cond_t m_cond;
  Action m_action;
  stack::ipv4::Address m_ripaddr;
  stack::tcpv4::Port m_lport;
  stack::tcpv4::Port m_rport;
  Client::ID m_id;
  Status m_status;
  std::string m_data;
};

void populate(utils::Commands& cmds);

}
