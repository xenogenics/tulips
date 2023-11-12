#include <tulips/api/Client.h>
#include <tulips/api/Defaults.h>
#include <tulips/api/Server.h>
#include <tulips/apps/TCPLatency.h>
#include <tulips/ssl/Client.h>
#include <tulips/ssl/Server.h>
#include <tulips/stack/Utils.h>
#include <tulips/stack/ethernet/Producer.h>
#include <tulips/system/Affinity.h>
#include <tulips/system/Clock.h>
#include <tulips/system/Compiler.h>
#include <tulips/transport/pcap/Device.h>
#include <csignal>
#include <iostream>
#include <sstream>

using namespace tulips;
using namespace stack;
using namespace transport;

/*
 * 100ms wait delay.
 */
constexpr size_t WAIT_DELAY = 100000000ULL;

static bool show_latency = false;
static bool keep_running = true;
static size_t alarm_delay = 0;
static size_t sends = 0;
static size_t successes = 0;
static size_t iterations = 0;

static void
signal_handler(UNUSED int signal)
{
  keep_running = false;
}

static void
alarm_handler(UNUSED int signal)
{
  show_latency = true;
  alarm(alarm_delay);
}

namespace tulips::apps::tcplatency {

namespace Client {

enum class State
{
  Connect,
  Run,
  Closing
};

class Delegate : public api::defaults::ClientDelegate
{
public:
  using api::defaults::ClientDelegate::Timestamp;

  void* onConnected(UNUSED tulips::api::Client::ID const& id,
                    UNUSED void* const cookie,
                    UNUSED const Timestamp ts) override
  {
    return nullptr;
  }
};

int
run(Options const& options, transport::Device::Ref dev)
{
  Device::Ref device;
  /*
   * Create the console logger.
   */
  auto log = system::ConsoleLogger(system::Logger::Level::Trace);
  /*
   * Signal handler
   */
  signal(SIGINT, signal_handler);
  signal(SIGALRM, alarm_handler);
  /*
   * Set the alarm
   */
  alarm_delay = options.interval();
  alarm(alarm_delay);
  /*
   * Run as sender.
   */
  uint8_t data[options.length()];
  State state = State::Connect;
  /*
   * Check if we should wrap the device in a PCAP device.
   */
  if (options.dumpPackets()) {
    device = transport::pcap::Device::allocate(log, std::move(dev), "client");
  } else {
    device = std::move(dev);
  }
  /*
   * Define the client delegate.
   */
  Client::Delegate delegate;
  /*
   * Build the client.
   */
  api::interface::Client* client = nullptr;
  if (options.withSSL()) {
    client = new tulips::ssl::Client(log, delegate, *device, 1,
                                     options.source(), options.route(),
                                     options.mask(), tulips::ssl::Protocol::TLS,
                                     options.sslCert(), options.sslKey());
  } else {
    client = new tulips::api::Client(log, delegate, *device, 1,
                                     options.source(), options.route(),
                                     options.mask());
  }
  /*
   * Set the CPU affinity.
   */
  if (options.cpuId() >= 0) {
    if (!system::setCurrentThreadAffinity(options.cpuId())) {
      throw std::runtime_error("Cannot set CPU ID");
    }
  }
  /*
   * Open a connection.
   */
  tulips::api::Client::ID id;
  auto alpn = api::interface::Client::ApplicationLayerProtocol::None;
  auto opts = options.noDelay() ? tcpv4::Connection::NO_DELAY : 0;
  client->open(alpn, opts, id);
  /*
   * Latency timer.
   */
  system::Timer timer;
  if (options.usDelay() != 0) {
    timer.set((system::Clock::SECOND * options.usDelay()) / 1000000ULL);
  }
  /*
   * Run loop.
   */
  bool keep_running_local = keep_running;
  uint32_t res = 0;
  size_t last = 0, iter = 0;
  while (keep_running_local) {
    /*
     * Process the stack
     */
    if (options.wait()) {
      switch (device->wait(*client, WAIT_DELAY)) {
        case Status::Ok: {
          break;
        }
        case Status::NoDataAvailable: {
          client->run();
          break;
        }
        default: {
          std::cout << "Unknown error, aborting" << std::endl;
          keep_running_local = false;
          continue;
        }
      }
    } else {
      switch (device->poll(*client)) {
        case Status::Ok: {
          break;
        }
        case Status::NoDataAvailable: {
          if ((iter++ & 0x1FULL) == 0) {
            client->run();
          }
          break;
        }
        default: {
          std::cout << "Unknown error, aborting" << std::endl;
          keep_running_local = false;
          continue;
        }
      }
    }
    /*
     * Process the application
     */
    switch (state) {
      case State::Connect: {
        keep_running_local = keep_running;
        switch (client->connect(id, options.destination(), options.port())) {
          case Status::Ok: {
            state = State::Run;
            break;
          }
          case Status::OperationInProgress: {
            break;
          }
          default: {
            keep_running_local = false;
            break;
          }
        }
        break;
      }
      case State::Run: {
        /*
         * Show client latency if requested.
         */
        if (show_latency) {
          size_t cur = sends, delta = (cur - last) / alarm_delay;
          double hits = (double)successes / (double)iterations * 100.0;
          last = cur;
          successes = 0;
          iterations = 0;
          show_latency = false;
          if (delta > 0) {
            std::ostringstream oss;
            oss << std::setprecision(2) << std::fixed;
            oss << delta;
            options.noDelay() ? oss << " round-trips/s" : oss << " sends/s";
            oss << ", hits: " << hits << "%, latency: ";
            auto lat = (double)client->averageLatency(id);
            if (lat > 1e9L) {
              oss << (lat / 1e9L) << " s";
            } else if (lat > 1e6L) {
              oss << (lat / 1e6L) << " ms";
            } else if (lat > 1e3L) {
              oss << (lat / 1e3L) << " us";
            } else {
              oss << lat << " ns";
            }
            std::cout << oss.str() << std::endl;
          }
        }
        /*
         * Process the delay.
         */
        if (options.usDelay() != 0) {
          if (!timer.expired()) {
            break;
          }
          timer.reset();
        }
        /*
         * Check if we need to stop.
         */
        if (!keep_running) {
          client->close(id);
          state = State::Closing;
          break;
        }
        /*
         * Process the iteration.
         */
        iterations += 1;
        auto* payload = reinterpret_cast<uint64_t*>(data);
        *payload = sends;
        Status status = client->send(id, options.length(), data, res);
        switch (status) {
          case Status::Ok: {
            successes += 1;
            if (res == options.length()) {
              sends += 1;
              res = 0;
            }
            if (options.count() > 0 && sends == options.count()) {
              keep_running = false;
            }
            break;
          }
          case Status::OperationInProgress: {
            break;
          }
          default: {
            std::cout << "TCP send error, stopping" << std::endl;
            keep_running_local = false;
            break;
          }
        }
        break;
      }
      case State::Closing: {
        if (client->close(id) == Status::NotConnected && client->isClosed(id)) {
          keep_running_local = false;
        }
        break;
      }
    }
  }
  /*
   * Done.
   */
  return 0;
}

}

namespace Server {

class Delegate : public api::defaults::ServerDelegate
{
public:
  Delegate(const uint8_t options)
    : m_options(options), m_next(0), m_bytes(0), m_server(nullptr)
  {}

  void* onConnected(const api::Server::ID& id, UNUSED void* const cookie,
                    UNUSED const Timestamp ts) override
  {
    m_server->setOptions(id, m_options);
    return nullptr;
  }

  Action onNewData(UNUSED tulips::api::Server::ID const& id,
                   UNUSED void* const cookie, const uint8_t* const data,
                   const uint32_t len, UNUSED const Timestamp ts,
                   UNUSED const uint32_t alen, UNUSED uint8_t* const sdata,
                   UNUSED uint32_t& slen) override
  {
    size_t const& header = *reinterpret_cast<const size_t*>(data);
    if (header != m_next) {
      std::cout << "header error: next=" << m_next << " cur=" << header
                << std::endl;
    }
    m_next += 1;
    m_bytes += len;
    return Action::Continue;
  }

  void setServer(api::interface::Server* server) { m_server = server; }

  double throughput(const uint64_t sec)
  {
    static uint64_t prev = 0;
    uint64_t delta = m_bytes - prev;
    prev = m_bytes;
    return (double)(delta << 3) / (double)sec;
  }

private:
  uint8_t m_options;
  size_t m_next;
  uint64_t m_bytes;
  api::interface::Server* m_server;
};

int
run(Options const& options, transport::Device::Ref dev)
{
  Device::Ref device;
  /*
   * Create the console logger.
   */
  auto log = system::ConsoleLogger(system::Logger::Level::Trace);
  /*
   * Signal handler
   */
  signal(SIGINT, signal_handler);
  signal(SIGALRM, alarm_handler);
  /*
   * Set the alarm
   */
  alarm_delay = options.interval();
  alarm(alarm_delay);
  /*
   * Run as receiver.
   */
  size_t iter = 0;
  auto opts = options.noDelay() ? tcpv4::Connection::NO_DELAY : 0;
  Delegate delegate(opts);
  /*
   * Check if we should wrap the device in a PCAP device.
   */
  if (options.dumpPackets()) {
    device = transport::pcap::Device::allocate(log, std::move(dev), "server");
  } else {
    device = std::move(dev);
  }
  /*
   * Initialize the server
   */
  api::interface::Server* server = nullptr;
  if (options.withSSL()) {
    server = new tulips::ssl::Server(
      log, delegate, *device, options.connections(), options.source(),
      options.route(), options.mask(), tulips::ssl::Protocol::TLS,
      options.sslCert(), options.sslKey());
  } else {
    server = new tulips::api::Server(log, delegate, *device,
                                     options.connections(), options.source(),
                                     options.route(), options.mask());
  }
  delegate.setServer(server);
  /*
   * Listen to the local ports.
   */
  for (auto p : options.ports()) {
    server->listen(p, nullptr);
  }
  /*
   * Set the CPU affinity.
   */
  if (options.cpuId() >= 0) {
    if (!system::setCurrentThreadAffinity(options.cpuId())) {
      throw std::runtime_error("Cannot set CPU ID");
    }
  }
  /*
   * Latency timer.
   */
  system::Timer timer;
  if (options.usDelay() != 0) {
    timer.set((system::Clock::SECOND * options.usDelay()) / 1000000ULL);
  }
  /*
   * Listen to incoming data.
   */
  while (keep_running) {
    /*
     * Process the artificial delay.
     */
    if (options.usDelay() != 0) {
      if (!timer.expired()) {
        continue;
      }
      timer.reset();
    }
    /*
     * Process the stack
     */
    if (options.wait()) {
      switch (device->wait(*server, WAIT_DELAY)) {
        case Status::Ok: {
          break;
        }
        case Status::NoDataAvailable: {
          server->run();
          break;
        }
        default: {
          std::cout << "Unknown error, aborting" << std::endl;
          keep_running = false;
          continue;
        }
      }
    } else {
      switch (device->poll(*server)) {
        case Status::Ok: {
          break;
        }
        case Status::NoDataAvailable: {
          if ((iter++ & 0x1FULL) == 0) {
            server->run();
          }
          break;
        }
        default: {
          std::cout << "Unknown error, aborting" << std::endl;
          keep_running = false;
          continue;
        }
      }
    }
    /*
     * Print latency if necessary.
     */
    if (show_latency) {
      double tps = delegate.throughput(alarm_delay);
      show_latency = false;
      if (tps > 0) {
        std::ostringstream oss;
        oss << std::setprecision(2) << std::fixed;
        oss << "throughput = ";
        if (tps > 1e9L) {
          oss << (tps / 1e9L) << " Gb/s";
        } else if (tps > 1e6L) {
          oss << (tps / 1e6L) << " Mb/s";
        } else if (tps > 1e3L) {
          oss << (tps / 1e3L) << " Kb/s";
        } else {
          oss << tps << " b/s";
        }
        std::cout << oss.str() << std::endl;
      }
    }
  }
  /*
   * Done.
   */
  return 0;
}

}

}
