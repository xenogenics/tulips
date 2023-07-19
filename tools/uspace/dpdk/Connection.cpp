#include <tulips/system/Compiler.h>
#include <tulips/system/Utils.h>
#include <iostream>
#include <sstream>
#include <linenoise/linenoise.h>
#include <uspace/dpdk/Connection.h>
#include <uspace/dpdk/State.h>

namespace tulips::tools::uspace::dpdk::connection {

/*
 * Close.
 */

class Close : public utils::Command
{
public:
  Close() : Command("close the device") {}

  void help(UNUSED utils::Arguments const& args) override
  {
    std::cout << "Usage: close" << std::endl;
  }

  void execute(utils::State& us, utils::Arguments const& args) override
  {
    auto& s = dynamic_cast<State&>(us);
    /*
     * Check arity.
     */
    if (args.size() != 1) {
      help(args);
      return;
    }
    /*
     * Check that no device has been allocated.
     */
    if (s.device == nullptr) {
      std::cout << "Error: no open device." << std::endl;
      return;
    }
    /*
     * Close the device.
     */
    delete s.device;
    s.device = nullptr;
  }
};

/*
 * Open.
 */

class Open : public utils::Command
{
public:
  Open() : Command("open a device") {}

  void help(UNUSED utils::Arguments const& args) override
  {
    std::cout << "Usage: open" << std::endl;
  }

  void execute(utils::State& us, utils::Arguments const& args) override
  {
    auto& s = dynamic_cast<State&>(us);
    /*
     * Check arity.
     */
    if (args.size() != 1) {
      help(args);
      return;
    }
    /*
     * Make sure no device has been allocated.
     */
    if (s.device != nullptr) {
      std::cout << "Error: device already open." << std::endl;
      return;
    }
    /*
     * Open a device.
     */
    s.device = new transport::dpdk::Device(128);
  }
};

/*
 * Helpers.
 */

void
populate(utils::Commands& cmds)
{
  cmds["close"] = new Close;
  cmds["open"] = new Open;
}
}
