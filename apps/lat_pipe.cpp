#include <tulips/apps/Options.h>
#include <tulips/apps/TCPLatency.h>
#include <tulips/transport/npipe/Device.h>
#include <iostream>
#include <tclap/CmdLine.h>

using namespace tulips;
using namespace transport;
using namespace apps::tcplatency;

int
main(int argc, char** argv)
try {
  TCLAP::CmdLine cmd("TULIPS Pipe Test", ' ', "1.0");
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
   * Create the tunnel device.
   */
  Device::Ref device;
  if (opts.isSender()) {
    device = transport::npipe::ClientDevice::allocate(
      logger, opts.linkAddress(), opts.source(), opts.mask(), opts.route(),
      "server.fifo", "client.fifo");
  } else {
    device = transport::npipe::ServerDevice::allocate(
      logger, opts.linkAddress(), opts.source(), opts.mask(), opts.route(),
      "client.fifo", "server.fifo");
  }
  /*
   * Call the main function.
   */
  int res = opts.isSender() ? Client::run(opts, std::move(device))
                            : Server::run(opts, std::move(device));
  /*
   * Done.
   */
  return res;
} catch (std::exception const& e) {
  std::cerr << e.what() << std::endl;
  return -1;
}
