#include <tulips/system/Compiler.h>
#include <utils/Command.h>
#include <utils/State.h>

namespace tulips::tools::utils {

Command::Command(std::string const& about) : m_about(about) {}

std::string const&
Command::about() const
{
  return m_about;
}

char*
Command::hint(UNUSED State& s, UNUSED int* color, UNUSED int* bold)
{
  return nullptr;
}

}
