#include <tulips/stack/IPv4.h>
#include <uspace/ofed/Poller.h>

namespace tulips::tools::uspace::ofed {

Poller::Poller(system::Logger& log, stack::ipv4::Address const& ip,
               stack::ipv4::Address const& dr, stack::ipv4::Address const& nm,
               const bool pcap)
  : m_device(makeDevice(log, pcap))
  , m_delegate()
  , m_client(log, m_delegate, *m_device, ip, dr, nm)
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
  pthread_create(&m_thread, nullptr, &Poller::entrypoint, this);
  pthread_mutex_init(&m_mutex, nullptr);
  pthread_cond_init(&m_cond, nullptr);
}

Poller::Poller(system::Logger& log, std::string_view dev,
               stack::ipv4::Address const& ip, stack::ipv4::Address const& dr,
               stack::ipv4::Address const& nm, const bool pcap)
  : m_device(makeDevice(log, dev, pcap))
  , m_delegate()
  , m_client(log, m_delegate, *m_device, ip, dr, nm)
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
  pthread_create(&m_thread, nullptr, &Poller::entrypoint, this);
  pthread_mutex_init(&m_mutex, nullptr);
  pthread_cond_init(&m_cond, nullptr);
}

Poller::~Poller()
{
  m_run = false;
  pthread_join(m_thread, nullptr);
  pthread_cond_destroy(&m_cond);
  pthread_mutex_destroy(&m_mutex);
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
  result = m_client.open(id);
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

transport::Device::Ref
Poller::makeDevice(system::Logger& log, const bool pcap)
{
  transport::Device::Ref device;
  /*
   * Build the OFED device.
   */
  auto ofed = transport::ofed::Device::allocate(log, 128);
  auto name = std::string(ofed->name());
  /*
   * Initialize the device.
   */
  if (pcap) {
    device = transport::pcap::Device::allocate(log, std::move(ofed), name);
  } else {
    device = std::move(ofed);
  }
  /*
   * Done.
   */
  return device;
}

transport::Device::Ref
Poller::makeDevice(system::Logger& log, std::string_view dev, const bool pcap)
{
  transport::Device::Ref device;
  /*
   * Build the OFED device.
   */
  auto ofed = transport::ofed::Device::allocate(log, dev, 128);
  auto name = std::string(ofed->name());
  /*
   * Initialize the device.
   */
  if (pcap) {
    device = transport::pcap::Device::allocate(log, std::move(ofed), name);
  } else {
    device = std::move(ofed);
  }
  /*
   * Done.
   */
  return device;
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
    if (m_device->wait(m_client, 100000000ULL) == Status::NoDataAvailable) {
      m_client.run();
    }
    /*
     * Check any incoming commands from the user.
     */
    pthread_mutex_lock(&m_mutex);
    switch (m_action) {
      case Action::Connect: {
        m_status = m_client.connect(m_id, m_ripaddr, m_rport);
        m_action = Action::None;
        pthread_cond_signal(&m_cond);
        break;
      }
      case Action::Close: {
        /*
         * Check if the connection is closing.
         */
        if (closing) {
          if (m_client.isClosed(m_id)) {
            closing = false;
            m_action = Action::None;
            pthread_cond_signal(&m_cond);
          }
        }
        /*
         * Try to close the connection.
         */
        else {
          m_status = m_client.close(m_id);
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
        stack::ipv4::Address laddr;
        m_status = m_client.get(m_id, laddr, m_lport, m_ripaddr, m_rport);
        m_action = Action::None;
        pthread_cond_signal(&m_cond);
        break;
      }
      case Action::Write: {
        m_status = m_client.send(m_id, m_data.length(),
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

}
