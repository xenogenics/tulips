#include "tulips/stack/Utils.h"
#include <tulips/stack/tcpv4/ReorderBuffer.h>
#include <cstdint>
#include <limits>
#include <gtest/gtest.h>

using namespace tulips;
using namespace stack;

#define SELECT(__off, __len)                                                   \
  cur = exp + (__off);                                                         \
  dat = &source[(__off)];                                                      \
  len = __len;

TEST(TCP_ReorderBuffer, Single)
{
  Status res = Status::Ok;
  auto rb = tcpv4::ReorderBuffer::allocate(1024);
  uint8_t source[] = { 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };
  /*
   * Setup the state.
   */
  const uint8_t* dat = nullptr;
  uint16_t len = 0;
  uint32_t cur = 0;
  uint32_t exp = 10;
  uint32_t ack = 0;
  /*
   * Process the first buffer.
   */
  SELECT(5, 3);
  res = rb->process(exp, cur, ack, len, dat);
  ASSERT_EQ(Status::IncompleteData, res);
  /*
   * Process the second buffer.
   */
  SELECT(0, 5);
  res = rb->process(exp, cur, ack, len, dat);
  ASSERT_EQ(Status::Ok, res);
  /*
   * Check.
   */
  ASSERT_EQ(8, len);
  ASSERT_EQ(0, memcmp(source, dat, 8));
}

TEST(TCP_ReorderBuffer, SingleWithDuplicate)
{
  Status res = Status::Ok;
  auto rb = tcpv4::ReorderBuffer::allocate(1024);
  uint8_t source[] = { 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };
  /*
   * Setup the state.
   */
  const uint8_t* dat = nullptr;
  uint16_t len = 0;
  uint32_t cur = 0;
  uint32_t exp = 10;
  uint32_t ack = 0;
  /*
   * Process the first buffer.
   */
  SELECT(5, 3);
  res = rb->process(exp, cur, ack, len, dat);
  ASSERT_EQ(Status::IncompleteData, res);
  /*
   * Process a duplicate of the first buffer.
   */
  SELECT(5, 3);
  res = rb->process(exp, cur, ack, len, dat);
  ASSERT_EQ(Status::IncompleteData, res);
  /*
   * Process the second buffer.
   */
  SELECT(0, 5);
  res = rb->process(exp, cur, ack, len, dat);
  ASSERT_EQ(Status::Ok, res);
  /*
   * Check.
   */
  ASSERT_EQ(8, len);
  ASSERT_EQ(0, memcmp(source, dat, 8));
}

TEST(TCP_ReorderBuffer, SingleDropped)
{
  Status res = Status::Ok;
  auto rb = tcpv4::ReorderBuffer::allocate(6);
  uint8_t source[] = { 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };
  /*
   * Setup the state.
   */
  const uint8_t* dat = nullptr;
  uint16_t len = 0;
  uint32_t cur = 0;
  uint32_t exp = 10;
  uint32_t ack = 0;
  /*
   * Process the first buffer.
   */
  SELECT(1, 3);
  res = rb->process(exp, cur, ack, len, dat);
  ASSERT_EQ(Status::IncompleteData, res);
  /*
   * Process the second buffer.
   */
  SELECT(4, 4);
  res = rb->process(exp, cur, ack, len, dat);
  ASSERT_EQ(Status::NoMoreResources, res);
}

TEST(TCP_ReorderBuffer, Multiple)
{
  Status res;
  auto rb = tcpv4::ReorderBuffer::allocate(1024);
  uint8_t source[] = { 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };
  /*
   * Setup the state.
   */
  const uint8_t* dat = nullptr;
  uint16_t len = 0;
  uint32_t cur = 0;
  uint32_t exp = 10;
  uint32_t ack = 0;
  /*
   * Process the first buffer.
   */
  SELECT(2, 2);
  res = rb->process(exp, cur, ack, len, dat);
  ASSERT_EQ(Status::IncompleteData, res);
  /*
   * Process the second buffer.
   */
  SELECT(6, 2);
  res = rb->process(exp, cur, ack, len, dat);
  ASSERT_EQ(Status::IncompleteData, res);
  /*
   * Process the third buffer.
   */
  SELECT(4, 2);
  res = rb->process(exp, cur, ack, len, dat);
  ASSERT_EQ(Status::IncompleteData, res);
  /*
   * Process the fourth buffer.
   */
  SELECT(0, 2);
  res = rb->process(exp, cur, ack, len, dat);
  ASSERT_EQ(Status::Ok, res);
  /*
   * Check.
   */
  ASSERT_EQ(8, len);
  ASSERT_EQ(0, memcmp(source, dat, 8));
}

TEST(TCP_ReorderBuffer, MultipleOverflow)
{
  Status res;
  auto rb = tcpv4::ReorderBuffer::allocate(1024);
  uint8_t source[] = { 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };
  /*
   * Setup the state.
   */
  const uint8_t* dat = nullptr;
  uint16_t len = 0;
  uint32_t cur = 0;
  uint32_t exp = std::numeric_limits<uint32_t>::max() - 2;
  uint32_t ack = 0;
  /*
   * Process the first buffer.
   */
  SELECT(2, 2);
  res = rb->process(exp, cur, ack, len, dat);
  ASSERT_EQ(Status::IncompleteData, res);
  /*
   * Process the second buffer.
   */
  SELECT(6, 2);
  res = rb->process(exp, cur, ack, len, dat);
  ASSERT_EQ(Status::IncompleteData, res);
  /*
   * Process the third buffer.
   */
  SELECT(4, 2);
  res = rb->process(exp, cur, ack, len, dat);
  ASSERT_EQ(Status::IncompleteData, res);
  /*
   * Process the fourth buffer.
   */
  SELECT(0, 2);
  res = rb->process(exp, cur, ack, len, dat);
  ASSERT_EQ(Status::Ok, res);
  /*
   * Check.
   */
  ASSERT_EQ(8, len);
  ASSERT_EQ(0, memcmp(source, dat, 8));
}
