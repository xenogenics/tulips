#include <tulips/system/Clock.h>
#include <gtest/gtest.h>

int
main(int argc, char* argv[])
{
  tulips::system::Clock::get();
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
