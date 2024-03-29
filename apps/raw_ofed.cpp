#include <tulips/stack/ethernet/Processor.h>
#include <tulips/stack/ethernet/Producer.h>
#include <tulips/system/Affinity.h>
#include <tulips/system/Clock.h>
#include <tulips/transport/ofed/Device.h>
#include <tulips/transport/pcap/Device.h>
#include <csignal>
#include <cstdint>
#include <pthread.h>
#include <tclap/CmdLine.h>

using namespace tulips;
using namespace stack;
using namespace transport;

static bool show_latency = false;
static bool keep_running = true;
static size_t alarm_delay = 0;
static size_t counter = 0;

/*
 * Raw processor.
 */

class RawProcessor : public Processor
{
public:
  RawProcessor()
    : m_ethto(nullptr)
    , m_ethfrom(nullptr)
    , m_last(system::Clock::now())
    , m_lat(0)
    , m_count(0)
  {}

  Status run() override { return Status::Ok; }

  Status process(UNUSED const uint16_t len, const uint8_t* const data,
                 UNUSED const Timestamp ts) override
  {
    uint64_t value = *(uint64_t*)data;
    /*
     * Get the timing data.
     */
    if (m_last > 0) {
      m_lat += system::Clock::instant() - m_last;
    }
    /*
     * Process the response.
     */
    value += 1;
    return send(sizeof(value), (uint8_t*)&value, true);
  }

  Status sent(UNUSED const uint16_t len, uint8_t* const data) override
  {
    return m_ethto->release(data);
  }

  Status send(const uint16_t len, const uint8_t* const data,
              const bool swap = false)
  {
    m_ethto->setType(len);
    memcpy(m_buffer, data, len);
    m_last = system::Clock::now();
    Status ret = m_ethto->commit(len, m_buffer);
    if (ret != Status::Ok) {
      return ret;
    }
    m_count += 1;
    if (swap) {
      m_ethto->setDestinationAddress(m_ethfrom->sourceAddress());
    }
    return m_ethto->prepare(m_buffer);
  }

  RawProcessor& setEthernetProducer(ethernet::Producer& eth)
  {
    m_ethto = &eth;
    m_ethto->prepare(m_buffer);
    return *this;
  }

  RawProcessor& setEthernetProcessor(ethernet::Processor& eth)
  {
    m_ethfrom = &eth;
    return *this;
  }

  size_t averageLatency()
  {
    uint64_t res = 0;
    if (m_count > 0) {
      res = system::Clock::toNanos(m_lat) / m_count;
    }
    m_lat = 0;
    m_count = 0;
    return res;
  }

private:
  ethernet::Producer* m_ethto;
  ethernet::Processor* m_ethfrom;
  system::Clock::Epoch m_last;
  system::Clock::Epoch m_lat;
  size_t m_count;
  uint8_t* m_buffer;
};

int
main_raw(const bool sender, const size_t ival, const bool pcap, const bool wait,
         std::string_view ifn, std::string_view dst, const int usdly,
         const int cpuid)
{
  /*
   * Create the console logger.
   */
  auto log = system::ConsoleLogger(system::Logger::Level::Trace);
  /*
   * Create an OFED device
   */
  Device::Ref dev;
  auto ofed = ofed::Device::allocate(log, ifn, 32);
  /*
   * Open the pcap device
   */
  if (pcap) {
    if (sender) {
      dev = transport::pcap::Device::allocate(log, std::move(ofed), "client");
    } else {
      dev = transport::pcap::Device::allocate(log, std::move(ofed), "server");
    }
  } else {
    dev = std::move(ofed);
  }
  /*
   * Process the CPU ID.
   */
  if (cpuid >= 0 && !system::setCurrentThreadAffinity(cpuid)) {
    throw std::runtime_error("Cannot set CPU ID: " + std::to_string(cpuid));
  }
  /*
   * Processor
   */
  RawProcessor proc;
  ethernet::Producer eth_prod(log, *dev, dev->address());
  ethernet::Processor eth_proc(log, dev->address());
  eth_prod.setType(sizeof(counter)).setDestinationAddress(dst);
  eth_proc.setRawProcessor(proc);
  proc.setEthernetProducer(eth_prod).setEthernetProcessor(eth_proc);
  /*
   * Run as sender.
   */
  if (sender) {
    /*
     * Set the alarm
     */
    alarm_delay = ival;
    alarm(ival);
    /*
     * Send the first message.
     */
    proc.send(sizeof(counter), (uint8_t*)&counter);
    /*
     * Run loop.
     */
    while (keep_running) {
      if (show_latency) {
        show_latency = false;
        std::cout << "Latency = " << proc.averageLatency() << "ns" << std::endl;
      }
      wait ? dev->wait(eth_proc, 1000000) : dev->poll(eth_proc);
      if (usdly != 0) {
        usleep(usdly);
      }
    }
  }
  /*
   * Run as receiver.
   */
  else {
    /*
     * Set the alarm
     */
    alarm_delay = ival;
    alarm(ival);
    /*
     * Run loop.
     */
    while (keep_running) {
      if (show_latency) {
        show_latency = false;
        std::cout << "Latency = " << proc.averageLatency() << "ns" << std::endl;
      }
      wait ? dev->wait(eth_proc, 1000000) : dev->poll(eth_proc);
      if (usdly > 0) {
        usleep(usdly);
      }
    }
  }
  /*
   * Done.
   */
  return 0;
}

/*
 * Execution control.
 */

void
signal_handler(UNUSED int signal)
{
  keep_running = false;
}

void
alarm_handler(UNUSED int signal)
{
  show_latency = true;
  alarm(alarm_delay);
}

/*
 * General main.
 */

struct Options
{
  Options(TCLAP::CmdLine& cmd)
    : usd("u", "us", "uS delay between sends", false, 1000, "DELAY", cmd)
    , snd("s", "sender", "Sender mode", cmd)
    , hwa("M", "mac", "Remote ethernet address", false, "", "MAC", cmd)
    , pcp("P", "pcap", "Dump packets", cmd)
    , dly("i", "interval", "Statistics interval", false, 10, "INTERVAL", cmd)
    , iff("I", "interface", "Network interface", true, "", "INTERFACE", cmd)
    , wai("w", "wait", "Wait instead of poll", cmd)
    , cpu("", "cpu", "CPU affinity", false, -1, "CPUID")

  {}

  TCLAP::ValueArg<int> usd;
  TCLAP::SwitchArg snd;
  TCLAP::ValueArg<std::string> hwa;
  TCLAP::SwitchArg pcp;
  TCLAP::ValueArg<size_t> dly;
  TCLAP::ValueArg<std::string> iff;
  TCLAP::SwitchArg wai;
  TCLAP::ValueArg<int> cpu;
};

int
main(int argc, char** argv)
try {
  TCLAP::CmdLine cmd("TULIPS OFED RAW TEST", ' ', "1.0");
  Options opts(cmd);
  cmd.parse(argc, argv);
  /*
   * Signal handler
   */
  signal(SIGINT, signal_handler);
  signal(SIGALRM, alarm_handler);
  /*
   * Run the proper mode of operation.
   */
  if (!opts.hwa.isSet()) {
    std::cerr << "Remote ethernet address must be set in RAW mode" << std::endl;
    return __LINE__;
  }
  /*
   * Run the main loop.
   */
  return main_raw(opts.snd.isSet(), opts.dly.getValue(), opts.pcp.isSet(),
                  opts.wai.isSet(), opts.iff.getValue(), opts.hwa.getValue(),
                  opts.usd.getValue(), opts.cpu.getValue());
} catch (std::exception const& e) {
  std::cerr << e.what() << std::endl;
  return -1;
}
