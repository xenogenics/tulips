#include <tulips/stack/Utils.h>
#include <cstddef>
#include <gtest/gtest.h>

using namespace tulips;

static constexpr size_t KEY_LEN = 40;

static uint8_t DYNAMIC_KEY[KEY_LEN] = {
  0x00, 0x8b, 0xe0, 0x5e, 0xd4, 0xa5, 0x54, 0xf8, 0x3c, 0xf8,
  0x08, 0x75, 0x07, 0x2c, 0x4e, 0x8b, 0x6f, 0x1d, 0xbf, 0x10,
  0x3b, 0x04, 0x3b, 0x41, 0xb3, 0xa4, 0xa4, 0xae, 0x56, 0xc9,
  0xa4, 0xec, 0x13, 0x76, 0xa0, 0xaf, 0x04, 0x10, 0x81, 0x66,
};

static const uint8_t STATIC_KEY[KEY_LEN] = {
  0xbe, 0xac, 0x01, 0xfa, 0x6a, 0x42, 0xb7, 0x3b, 0x80, 0x30,
  0xf2, 0x0c, 0x77, 0xcb, 0x2d, 0xa3, 0xae, 0x7b, 0x30, 0xb4,
  0xd0, 0xca, 0x2b, 0xcb, 0x43, 0xa3, 0x8f, 0xb0, 0x41, 0x67,
  0x25, 0x3d, 0x25, 0x5b, 0x0e, 0xc2, 0x6d, 0x5a, 0x56, 0xda,
};

TEST(Stack, RssHashingDynamic)
{
  using stack::utils::toeplitz;
  /*
   * Define the tuple entries.
   */
  auto saddr = stack::ipv4::Address(10, 1, 0, 1);
  auto daddr = stack::ipv4::Address(10, 1, 0, 2);
  auto sport = uint16_t(8888);
  auto dport = uint16_t(9999);
  /*
   * Compute the hash.
   */
  auto h = toeplitz(saddr, daddr, sport, dport, KEY_LEN, DYNAMIC_KEY, 0);
  ASSERT_EQ(0xd90a078c, h);
}

TEST(Stack, RssHashingStatic)
{
  using stack::utils::toeplitz;
  /*
   * Define the tuple entries.
   */
  auto saddr = stack::ipv4::Address(10, 1, 0, 1);
  auto daddr = stack::ipv4::Address(10, 1, 0, 2);
  auto sport = uint16_t(8888);
  auto dport = uint16_t(9999);
  /*
   * Compute the hash.
   */
  auto h = toeplitz(saddr, daddr, sport, dport, KEY_LEN, STATIC_KEY, -1);
  ASSERT_EQ(0x108ad839, h);
}
