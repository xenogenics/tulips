#include <tulips/apps/Options.h>
#include <tulips/apps/TCPLatency.h>
#include <tulips/transport/npipe/Device.h>
#include <iostream>
#include <tclap/CmdLine.h>

using namespace tulips;
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
   * Create the tunnel device.
   */
  transport::npipe::Device* device;
  if (opts.isSender()) {
    device = new transport::npipe::ClientDevice(
      opts.linkAddress(), opts.source(), opts.mask(), opts.route(),
      "server.fifo", "client.fifo");
  } else {
    device = new transport::npipe::ServerDevice(
      opts.linkAddress(), opts.source(), opts.mask(), opts.route(),
      "client.fifo", "server.fifo");
  }
  /*
   * Call the main function.
   */
  int res = opts.isSender() ? Client::run(opts, *device)
                            : Server::run(opts, *device);
  /*
   * Clean-up and return.
   */
  delete device;
  return res;
} catch (std::exception const& e) {
  std::cerr << e.what() << std::endl;
  return -1;
}
