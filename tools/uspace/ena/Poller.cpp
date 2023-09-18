#include "tulips/ssl/Protocol.h"
#include <tulips/api/Client.h>
#include <tulips/ssl/Client.h>
#include <tulips/transport/Device.h>
#include <iostream>
#include <linenoise/linenoise.h>
#include <uspace/ena/Poller.h>
#include <uspace/ena/State.h>

namespace tulips::tools::uspace::ena::poller {

/*
 * Poller.
 */

Poller::Poller(system::Logger& log, transport::Device::Ref dev, const bool pcap,
               const bool ssl)
  : m_capture(pcap)
  , m_dev(std::move(dev))
  , m_pcap(pcap ? new transport::pcap::Device(log, *m_dev, m_dev->name())
                : nullptr)
  , m_device(pcap ? (transport::Device*)m_pcap
                  : (transport::Device*)m_dev.get())
  , m_delegate()
  , m_client()
  , m_run(true)
  , m_thread()
  , m_mutex()
  , m_cond()
  , m_action(Action::None)
  , m_ripaddr()
  , m_lport()
  , m_rport()
  , m_id()
  , m_status()
{
  /*
   * Build the client.
   */
  if (ssl) {
    auto proto = ssl::Protocol::Auto;
    m_client = std::make_unique<ssl::Client>(log, m_delegate, *m_device, proto,
                                             32, false);
  } else {
    m_client = std::make_unique<api::Client>(log, m_delegate, *m_device, 32);
  }
  /*
   * Build the thread.
   */
  pthread_mutex_init(&m_mutex, nullptr);
  pthread_cond_init(&m_cond, nullptr);
  pthread_create(&m_thread, nullptr, &Poller::entrypoint, this);
}

Poller::~Poller()
{
  m_run = false;
  /*
   * Clean-up runtime variables.
   */
  pthread_join(m_thread, nullptr);
  pthread_cond_destroy(&m_cond);
  pthread_mutex_destroy(&m_mutex);
  /*
   * Clean-up devices.
   */
  if (m_capture) {
    delete m_pcap;
  }
}

Status
Poller::connect(stack::ipv4::Address const& ripaddr,
                const stack::tcpv4::Port rport, api::Client::ID& id)
{
  Status result;
  pthread_mutex_lock(&m_mutex);
  /*
   * Get a client ID.
   */
  result = m_client->open(id);
  /*
   * Connect the client.
   */
  if (result == Status::Ok) {
    m_ripaddr = ripaddr;
    m_rport = rport;
    m_id = id;
    do {
      m_action = Action::Connect;
      pthread_cond_wait(&m_cond, &m_mutex);
    } while (m_status == Status::OperationInProgress);
    result = m_status;
  }
  /*
   * Return the result.
   */
  pthread_mutex_unlock(&m_mutex);
  return result;
}

Status
Poller::close(const api::Client::ID id)
{
  Status result;
  pthread_mutex_lock(&m_mutex);
  /*
   * Ask the poller to close the connection.
   */
  m_action = Action::Close;
  m_id = id;
  pthread_cond_wait(&m_cond, &m_mutex);
  result = m_status;
  /*
   * Return the result.
   */
  pthread_mutex_unlock(&m_mutex);
  return result;
}

Status
Poller::get(const api::Client::ID id, stack::ipv4::Address& ripaddr,
            stack::tcpv4::Port& lport, stack::tcpv4::Port& rport)
{
  Status result;
  pthread_mutex_lock(&m_mutex);
  /*
   * Ask the poller to grab the connection info.
   */
  m_action = Action::Info;
  m_id = id;
  pthread_cond_wait(&m_cond, &m_mutex);
  result = m_status;
  ripaddr = m_ripaddr;
  lport = m_lport;
  rport = m_rport;
  /*
   * Return the result.
   */
  pthread_mutex_unlock(&m_mutex);
  return result;
}

Status
Poller::write(const api::Client::ID id, std::string_view data)
{
  Status result;
  pthread_mutex_lock(&m_mutex);
  /*
   * Ask the poller to close the connection.
   */
  m_action = Action::Write;
  m_id = id;
  m_data = data;
  pthread_cond_wait(&m_cond, &m_mutex);
  result = m_status;
  /*
   * Return the result.
   */
  pthread_mutex_unlock(&m_mutex);
  return result;
}

void
Poller::run()
{
  bool closing = false;
  uint32_t off = 0;
  /*
   * Thread run loop.
   */
  while (m_run) {
    /*
     * Poll the device.
     */
    if (m_device->wait(*m_client, 100000000ULL) == Status::NoDataAvailable) {
      m_client->run();
    }
    /*
     * Check any incoming commands from the user.
     */
    pthread_mutex_lock(&m_mutex);
    switch (m_action) {
      case Action::Connect: {
        m_status = m_client->connect(m_id, m_ripaddr, m_rport);
        m_action = Action::None;
        pthread_cond_signal(&m_cond);
        break;
      }
      case Action::Close: {
        /*
         * Check if the connection is closing.
         */
        if (closing) {
          if (m_client->isClosed(m_id)) {
            closing = false;
            m_action = Action::None;
            pthread_cond_signal(&m_cond);
          }
        }
        /*
         * Try to close the connection.
         */
        else {
          m_status = m_client->close(m_id);
          if (m_status != Status::Ok) {
            m_action = Action::None;
            pthread_cond_signal(&m_cond);
          } else {
            closing = true;
          }
        }
        break;
      }
      case Action::Info: {
        m_status = m_client->get(m_id, m_ripaddr, m_lport, m_rport);
        m_action = Action::None;
        pthread_cond_signal(&m_cond);
        break;
      }
      case Action::Write: {
        m_status = m_client->send(m_id, m_data.length(),
                                  (const uint8_t*)m_data.c_str(), off);
        switch (m_status) {
          case Status::Ok: {
            if (off == m_data.length()) {
              off = 0;
              m_action = Action::None;
              pthread_cond_signal(&m_cond);
            }
            break;
          }
          case Status::OperationInProgress: {
            break;
          }
          default: {
            off = 0;
            m_action = Action::None;
            pthread_cond_signal(&m_cond);
            break;
          }
        }
        break;
      }
      case Action::None: {
        break;
      }
    }
    pthread_mutex_unlock(&m_mutex);
  }
}

/*
 * Open a poller.
 */

class Open : public utils::Command
{
public:
  Open() : Command("open a new poller"), m_hint(" <ip> <dr> <nm>") {}

  void help(UNUSED utils::Arguments const& args) override
  {
    std::cout << "Usage: open IP GATEWAY NETMASK" << std::endl;
  }

  void execute(utils::State& us, utils::Arguments const& args) override
  try {
    auto& s = dynamic_cast<State&>(us);
    /*
     * Check arity.
     */
    if (args.size() != 4) {
      help(args);
      return;
    }
    /*
     * Parse the IP address.
     */
    stack::ipv4::Address ip(args[1]);
    /*
     * Parse the default route.
     */
    stack::ipv4::Address dr(args[2]);
    /*
     * Parse the netmask.
     */
    stack::ipv4::Address nm(args[3]);
    /*
     * Create a new poller.
     */
    s.pollers.emplace_back(
      new Poller(s.logger, s.port.next(ip, dr, nm), s.with_pcap, s.with_ssl));
    /*
     * Print the poller ID.
     */
    std::cout << "New poller: " << s.pollers.size() - 1 << std::endl;
  } catch (...) {
    help(args);
  }

  char* hint(UNUSED utils::State& s, int* color, UNUSED int* bold) override
  {
    *color = LN_GREEN;
    return (char*)m_hint.c_str();
  }

private:
  std::string m_hint;
};

/*
 * Helpers.
 */

void
populate(UNUSED utils::Commands& cmds)
{
  cmds["open"] = new Open;
}

}
