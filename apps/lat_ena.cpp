#include <tulips/apps/Options.h>
#include <tulips/apps/TCPLatency.h>
#include <tulips/transport/ena/AbstractionLayer.h>
#include <tulips/transport/ena/Device.h>
#include <tulips/transport/ena/Port.h>
#include <chrono>
#include <thread>
#include <tclap/CmdLine.h>

using namespace tulips;
using namespace apps::tcplatency;
using namespace transport;

void
runPort(transport::ena::Port& port, std::atomic<bool>& keep_running)
{
  while (keep_running) {
    port.run();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}

int
main(int argc, char** argv)
try {
  TCLAP::CmdLine cmd("TULIPS ENA Test", ' ', "1.0");
  apps::Options opts(cmd);
  cmd.parse(argc, argv);
  /*
   * Make sure the options are sane.
   */
  if (!opts.isSane()) {
    return __LINE__;
  }
  /*
   * Create the console logger.
   */
  auto logger = system::ConsoleLogger(system::Logger::Level::Trace);
  /*
   * Make sure the interface is set.
   */
  if (!opts.hasInterface()) {
    std::cerr << "--interface must be set" << std::endl;
    return -1;
  }
  /*
   * Allocate the EAL and the port.
   */
  auto eal = transport::ena::AbstractionLayer::allocate(logger);
  auto port = transport::ena::Port(logger, opts.interface(), 2, 1024, 2048);
  /*
   * Get an ENA device.
   */
  auto device = port.next(logger, false);
  /*
   * Start the port thread.
   */
  std::atomic<bool> keep_running = true;
  auto pthr = std::thread(runPort, std::ref(port), std::ref(keep_running));
  /*
   * Call the main function.
   */
  int res = opts.isSender() ? Client::run(opts, std::move(device))
                            : Server::run(opts, std::move(device));
  /*
   * Terminate the port thread.
   */
  keep_running = false;
  pthr.join();
  /*
   * Clean-up.
   */
  return res;
} catch (std::exception const& e) {
  std::cerr << e.what() << std::endl;
  return -1;
}
