#pragma once

#include <tulips/system/Compiler.h>
#include <tulips/system/SpinLock.h>
#include <iomanip>
#include <iostream>
#include <mutex>
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
    Error = 0,
    Warning = 1,
    Info = 2,
    Debug = 3,
    Trace = 4
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
  virtual void flush(const Level level, std::string_view hdr,
                     std::string&& value) = 0;

private:
  template<typename... Args>
  void log(const Level level, std::string_view hdr, Args&&... args)
  {
    if (level <= m_level) {
      unpack(level, hdr, args...);
    }
  }

  template<typename Arg, typename... Args>
  void unpack(const Level level, std::string_view hdr, Arg&& arg,
              Args&&... args)
  {
    m_buffer << arg;
    log(level, hdr, args...);
  }

  template<typename Arg>
  void unpack(const Level level, std::string_view hdr, Arg&& arg)
  {
    m_buffer << arg;
    flush(level, hdr, m_buffer.str());
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
  void flush(UNUSED const Level level, std::string_view hdr,
             std::string&& value) final
  {
    std::cout << "[ " << std::setw(8) << hdr << " ] " << value << std::endl;
  }
};

/*
 * Buffered logger class.
 */

class BufferedLogger final : public Logger
{
public:
  BufferedLogger(const Level level) : Logger(level), m_lock(), m_stream() {}

  std::string content()
  {

    std::lock_guard<system::SpinLock> lock(m_lock);
    return m_stream.str();
  }

protected:
  void flush(UNUSED const Level level, std::string_view hdr,
             std::string&& value) final
  {
    std::lock_guard<system::SpinLock> lock(m_lock);
    m_stream << "[ " << std::setw(8) << hdr << " ] " << value << std::endl;
  }

private:
  system::SpinLock m_lock;
  std::ostringstream m_stream;
};

}
