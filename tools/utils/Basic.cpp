#include <tulips/system/Compiler.h>
#include <iomanip>
#include <iostream>
#include <utils/Basic.h>
#include <utils/State.h>

namespace tulips::tools::utils::basic {

/*
 * Quit.
 */

class Help : public Command
{
public:
  Help() : Command("print this help") {}

  void help(UNUSED Arguments const& args) override
  {
    std::cout << "Print this help." << std::endl;
  }

  void execute(State& s, Arguments const& args) override
  {
    if (args.size() == 1) {
      Commands::const_iterator it;
      /*
       * Get the size of the larges item.
       */
      size_t l = 0;
      for (it = s.commands.begin(); it != s.commands.end(); it++) {
        l = it->first.length() > l ? it->first.length() : l;
      }
      /*
       * Display the commands.
       */
      for (it = s.commands.begin(); it != s.commands.end(); it++) {
        std::cout << std::setw((int)l + 1) << std::left << it->first << "-- "
                  << it->second->about() << std::endl;
      }
    } else if (s.commands.count(args[1]) == 0) {
      std::cout << "Invalid command: " << args[1] << std::endl;
    } else {
      s.commands[args[1]]->help(args);
    }
  }
};

/*
 * Quit.
 */

class Quit : public Command
{
public:
  Quit() : Command("leave the tool") {}

  void help(UNUSED Arguments const& args) override
  {
    std::cout << "Leave the client." << std::endl;
  }

  void execute(State& s, UNUSED Arguments const& args) override
  {
    s.keep_running = false;
  }
};

/*
 * Helpers.
 */

void
populate(Commands& cmds)
{
  cmds["help"] = new Help;
  cmds["quit"] = new Quit;
}

}
