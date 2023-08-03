#include <tulips/system/CircularBuffer.h>
#include <tulips/system/Compiler.h>
#include <thread>
#include <gtest/gtest.h>

using namespace tulips;

TEST(CircularBuffer, RegularLength)
{
  constexpr const size_t ITERATIONS = 1000000;
  auto cb = system::CircularBuffer::allocate(1024);
  /*
   * Create the reader thread.
   */
  auto reader = std::thread([cb]() {
    for (size_t i = 0; i < ITERATIONS; i += 1) {
      size_t value = 0;
      cb->read_all((uint8_t*)&value, sizeof(value));
      ASSERT_EQ(i, value);
    }
  });
  /*
   * Create the writer thread.
   */
  auto writer = std::thread([cb]() {
    for (size_t i = 0; i < ITERATIONS; i += 1) {
      cb->write_all((uint8_t*)&i, sizeof(i));
    }
  });
  /*
   * Join the threads.
   */
  reader.join();
  writer.join();
}

TEST(CircularBuffer, IrregularLength)
{
  constexpr const size_t ITERATIONS = 1000000;
  auto cb = system::CircularBuffer::allocate(1024);
  /*
   * Define the irregular structure.
   */
  struct S
  {
    size_t i;
    bool v;
  } PACKED;
  /*
   * Create the reader thread.
   */
  auto reader = std::thread([cb]() {
    for (size_t i = 0; i < ITERATIONS; i += 1) {
      S value;
      cb->read_all((uint8_t*)&value, sizeof(value));
      ASSERT_EQ(i, value.i);
    }
  });
  /*
   * Create the writer thread.
   */
  auto writer = std::thread([cb]() {
    for (size_t i = 0; i < ITERATIONS; i += 1) {
      auto value = S{ .i = i, .v = false };
      cb->write_all((uint8_t*)&value, sizeof(value));
    }
  });
  /*
   * Join the threads.
   */
  reader.join();
  writer.join();
}
