/**
 * @file tests/unit/test_confighttp.cpp
 * @brief Test the admin server's sign-in throttle and first-run restriction.
 */

// test imports
#include "../tests_common.h"

// standard includes
#include <chrono>

// local imports
#include <src/confighttp.h>

using namespace std::literals;

TEST(LoginThrottleTest, NormalizesSourcesAndExpiresBudgets) {
  using clock_t = confighttp::login_throttle_t::clock_t;
  confighttp::login_throttle_t throttle {16, 2, std::chrono::seconds(10)};
  const auto start = clock_t::time_point {};
  const auto ipv4 = boost::asio::ip::make_address("192.0.2.10");
  const auto mapped_ipv4 = boost::asio::ip::make_address("::ffff:192.0.2.10");
  const auto ipv6_a = boost::asio::ip::make_address("2001:db8:1234:5678::1");
  const auto ipv6_b = boost::asio::ip::make_address("2001:db8:1234:5678::ffff");

  EXPECT_EQ(confighttp::login_throttle_t::source_key(ipv4), confighttp::login_throttle_t::source_key(mapped_ipv4));
  EXPECT_EQ(confighttp::login_throttle_t::source_key(ipv6_a), confighttp::login_throttle_t::source_key(ipv6_b));

  throttle.record_failure(mapped_ipv4, start);
  throttle.record_failure(ipv4, start);
  EXPECT_TRUE(throttle.is_blocked(ipv4, start));
  EXPECT_FALSE(throttle.is_blocked(ipv4, start + std::chrono::seconds(11)));
}

TEST(ConfigHttpBootstrapTest, OnlyLoopbackMayCreateTheFirstAccount) {
  EXPECT_FALSE(confighttp::bootstrap_allowed(boost::asio::ip::make_address("192.0.2.50")));
  EXPECT_FALSE(confighttp::bootstrap_allowed(boost::asio::ip::make_address("2001:db8::50")));
  EXPECT_TRUE(confighttp::bootstrap_allowed(boost::asio::ip::make_address("127.0.0.1")));
  EXPECT_TRUE(confighttp::bootstrap_allowed(boost::asio::ip::make_address("::1")));
}
