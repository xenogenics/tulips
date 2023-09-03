#pragma once

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string_view>

namespace tulips::system {

/*
 * Base logger class.
 */

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
  void error(std::string_view hdr, Args&&... args)
  {
    log(Level::Error, hdr, args...);
  }

  template<typename... Args>
  void warning(std::string_view hdr, Args&&... args)
  {
    log(Level::Warning, hdr, args...);
  }

  template<typename... Args>
  void info(std::string_view hdr, Args&&... args)
  {
    log(Level::Info, hdr, args...);
  }

  template<typename... Args>
  void debug(std::string_view hdr, Args&&... args)
  {
    log(Level::Debug, hdr, args...);
  }

  template<typename... Args>
  void trace(std::string_view hdr, Args&&... args)
  {
    log(Level::Trace, hdr, args...);
  }

protected:
  virtual void flush(std::string_view hdr, std::string&& value) = 0;

private:
  template<typename... Args>
  void log(const Level level, std::string_view hdr, Args&&... args)
  {
    if (level <= m_level) {
      log(hdr, args...);
    }
  }

  template<typename Arg, typename... Args>
  void log(std::string_view hdr, Arg&& arg, Args&&... args)
  {
    m_buffer << arg;
    log(hdr, args...);
  }

  template<typename Arg>
  void log(std::string_view hdr, Arg&& arg)
  {
    m_buffer << arg;
    flush(hdr, m_buffer.str());
    m_buffer.str("");
  }

  Level m_level;
  std::ostringstream m_buffer;
};

/*
 * Console logger class.
 */

class ConsoleLogger final : public Logger
{
public:
  ConsoleLogger(const Level level) : Logger(level) {}

protected:
  void flush(std::string_view hdr, std::string&& value) final
  {
    std::cout << "[ " << std::setw(8) << hdr << " ] " << value << std::endl;
  }
};

}
