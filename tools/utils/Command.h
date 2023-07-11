#pragma once

#include <map>
#include <string>
#include <vector>

namespace tulips::tools::utils {

/*
 * Forward declarations.
 */

struct State;

/*
 * Arguments.
 */

using Arguments = std::vector<std::string>;

/*
 * Command.
 */

class Command
{
public:
  Command(std::string const& about);
  virtual ~Command() = default;

  std::string const& about() const;
  virtual void help(Arguments const& args) = 0;

  virtual void execute(State& s, Arguments const& args) = 0;
  virtual char* hint(State& s, int* color, int* bold);

private:
  std::string m_about;
};

/*
 * Commands.
 */

using Commands = std::map<std::string, Command*>;

}
