#include <tulips/apps/Options.h>
#include <tulips/apps/TCPLatency.h>
#include <tulips/transport/ofed/Device.h>
#include <tclap/CmdLine.h>

using namespace tulips;
using namespace apps::tcplatency;
using namespace transport;

int
main(int argc, char** argv)
try {
  TCLAP::CmdLine cmd("TULIPS OFED Test", ' ', "1.0");
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
   * Create an OFED device.
   */
  Device::Ref device;
  if (opts.hasInterface()) {
    device = ofed::Device::allocate(logger, opts.interface(), 1024);
  } else {
    device = ofed::Device::allocate(logger, 1024);
  }
  /*
   * Call the main function.
   */
  int res = opts.isSender() ? Client::run(opts, std::move(device))
                            : Server::run(opts, std::move(device));
  /*
   * Clean-up.
   */
  return res;
} catch (std::exception const& e) {
  std::cerr << e.what() << std::endl;
  return -1;
}
