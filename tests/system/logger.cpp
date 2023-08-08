#include <tulips/system/Compiler.h>
#include <tulips/system/Logger.h>
#include <gtest/gtest.h>

using namespace tulips;

namespace {

class Logger : public system::Logger
{
public:
  Logger(const Level level) : system::Logger(level), m_data() {}

  std::string_view data() const { return m_data; }

protected:
  void flush(UNUSED std::string&& value) override { m_data = value; }

private:
  std::string m_data;
};

}

TEST(Logger, BackToBack)
{
  Logger logger(Logger::Level::Debug);
  logger.log(Logger::Level::Debug, "Hello, ", "world!");
  ASSERT_EQ(logger.data(), "Hello, world!");
  logger.log(Logger::Level::Debug, "Hello, ", "world!");
  ASSERT_EQ(logger.data(), "Hello, world!");
}

TEST(Logger, SameLevel)
{
  Logger logger(Logger::Level::Debug);
  logger.log(Logger::Level::Debug, "Hello, ", "world!");
  ASSERT_EQ(logger.data(), "Hello, world!");
}

TEST(Logger, HigherLevel)
{
  Logger logger(Logger::Level::Debug);
  logger.log(Logger::Level::Trace, "Hello, ", "world!");
  ASSERT_TRUE(logger.data().empty());
}

TEST(Logger, LowerLevel)
{
  Logger logger(Logger::Level::Debug);
  logger.log(Logger::Level::Info, "Hello, ", "world!");
  ASSERT_EQ(logger.data(), "Hello, world!");
}
