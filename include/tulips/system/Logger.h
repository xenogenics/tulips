#pragma once

#include <sstream>
#include <string_view>

namespace tulips::system {

class Logger
{
public:
  enum class Level : uint8_t
  {
    Error,
    Warning,
    Info,
    Debug,
    Trace
  };

  Logger(const Level level) : m_level(level) {}

  template<typename... Args>
  void log(const Level level, Args&&... args)
  {
    if (level <= m_level) {
      log(args...);
    }
  }

  template<typename Arg, typename... Args>
  void log(Arg&& arg, Args&&... args)
  {
    m_buffer << arg;
    log(args...);
  }

  template<typename Arg>
  void log(Arg&& arg)
  {
    m_buffer << arg;
    flush(m_buffer.str());
    m_buffer.str("");
  }

protected:
  virtual void flush(std::string&& value) = 0;

private:
  Level m_level;
  std::ostringstream m_buffer;
};

}
