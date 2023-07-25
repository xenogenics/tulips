#include <tulips/system/Utils.h>
#include <cstring>
#include <map>
#include <string>
#include <vector>
#include <linenoise/linenoise.h>
#include <socket/server/Listener.h>
#include <socket/server/State.h>
#include <tclap/CmdLine.h>
#include <utils/Basic.h>

using namespace tulips;
using namespace tools;
using namespace socket;

/*
 * Hint handling.
 */

char*
hints(const char* buf, int* color, int* bold, void* cookie)
{
  std::string e(buf);
  auto* state = reinterpret_cast<utils::State*>(cookie);
  if (state->commands.count(e) != 0) {
    return state->commands[e]->hint(*state, color, bold);
  }
  return nullptr;
}

/*
 * Completion handling.
 */

void
completion(const char* buf, linenoiseCompletions* lc, void* cookie)
{
  std::string e(buf);
  auto* state = reinterpret_cast<utils::State*>(cookie);
  auto it = state->commands.lower_bound(e);
  while (it != state->commands.end() && it->first.length() >= e.length() &&
         it->first.substr(0, e.length()) == e) {
    linenoiseAddCompletion(lc, it->first.c_str());
    it++;
  }
}

/*
 * Execution control.
 */

void
execute(utils::State& s, std::string const& line)
{
  std::vector<std::string> args;
  tulips::system::utils::split(line, ' ', args);
  if (args.empty()) {
    return;
  }
  if (s.commands.count(args[0]) == 0) {
    std::cout << "Invalid command: " << args[0] << "." << std::endl;
    return;
  }
  s.commands[args[0]]->execute(s, args);
}

/*
 * General main.
 */

int
main(int argc, char** argv)
try {
  TCLAP::CmdLine cmdL("TULIPS receptor", ' ', "1.0");
  cmdL.parse(argc, argv);
  /*
   * Linenoise.
   */
  linenoiseSetCompletionCallback(completion);
  linenoiseSetHintsCallback(hints);
  linenoiseHistorySetMaxLen(1000);
  /*
   * Commands.
   */
  server::State state;
  utils::basic::populate(state.commands);
  server::listener::populate(state.commands);
  /*
   * Main loop.
   */
  char* line;
  while (state.keep_running && (line = linenoise("> ", &state)) != nullptr) {
    if (strlen(line) > 0) {
      linenoiseHistoryAdd(line);
    }
    execute(state, line);
    free(line);
  }
  /*
   * Clean-up.
   */
  return 0;
} catch (std::exception const& e) {
  std::cerr << e.what() << std::endl;
  return -1;
}
