#include <tulips/api/Client.h>
#include <tulips/api/Defaults.h>
#include <tulips/system/Logger.h>
#include <tulips/transport/Device.h>
#include <tulips/transport/ofed/Device.h>
#include <tulips/transport/pcap/Device.h>
#include <string>
#include <pthread.h>

namespace tulips::tools::uspace::ofed {

class Poller
{
public:
  Poller(system::Logger& log, stack::ipv4::Address const& ip,
         stack::ipv4::Address const& dr, stack::ipv4::Address const& nm,
         const bool pcap);
  Poller(system::Logger& log, std::string_view dev,
         stack::ipv4::Address const& ip, stack::ipv4::Address const& dr,
         stack::ipv4::Address const& nm, const bool pcap);
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

  static transport::Device::Ref makeDevice(system::Logger& log,
                                           const bool pcap);

  static transport::Device::Ref makeDevice(system::Logger& log,
                                           std::string_view dev,
                                           const bool pcap);

  void run();

  transport::Device::Ref m_device;
  api::defaults::ClientDelegate m_delegate;
  api::Client m_client;
  volatile bool m_run;
  pthread_t m_thread;
  pthread_mutex_t m_mutex;
  pthread_cond_t m_cond;
  Action m_action;
  stack::ipv4::Address m_ripaddr;
  stack::tcpv4::Port m_lport;
  stack::tcpv4::Port m_rport;
  api::Client::ID m_id;
  Status m_status;
  std::string m_data;
};

}
