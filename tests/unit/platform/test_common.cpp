/**
 * @file tests/unit/platform/test_common.cpp
 * @brief Test src/platform/common.*.
 */
#include "../../tests_common.h"

#include <array>
#include <boost/asio/ip/host_name.hpp>
#include <src/platform/common.h>
#include <string>
#include <string_view>
#include <thread>

#ifdef _WIN32
  #include <windows.h>
#else
  #include <pthread.h>
  #ifdef __FreeBSD__
    #include <pthread_np.h>
  #endif
#endif

TEST(HostnameTests, TestAsioEquality) {
  // These should be equivalent on all platforms for ASCII hostnames
  ASSERT_EQ(platf::get_host_name(), boost::asio::ip::host_name());
}

TEST(ThreadNameTests, HonorsStringViewAndPlatformLimits) {
  constexpr std::string_view backing_name {"thread_name_longer_than_limit::ignored"};
  constexpr std::string_view requested_name = backing_name.substr(0, backing_name.find("::"));

#ifdef _WIN32
  HRESULT query_result = E_FAIL;
  std::wstring actual_name;
#else
  int query_result = -1;
  std::string actual_name;
#endif

  std::thread named_thread {[&]() {
    platf::set_thread_name(requested_name);

#ifdef _WIN32
    PWSTR thread_description = nullptr;
    query_result = GetThreadDescription(GetCurrentThread(), &thread_description);
    if (SUCCEEDED(query_result)) {
      actual_name = thread_description;
      LocalFree(thread_description);
    }
#else
    std::array<char, 64> thread_name {};
  #ifdef __FreeBSD__
    pthread_get_name_np(pthread_self(), thread_name.data(), thread_name.size());
    query_result = 0;
  #else
    query_result = pthread_getname_np(pthread_self(), thread_name.data(), thread_name.size());
  #endif
    actual_name = thread_name.data();
#endif
  }};
  named_thread.join();

#ifdef _WIN32
  ASSERT_TRUE(SUCCEEDED(query_result));
  EXPECT_EQ(actual_name, L"thread_name_longer_than_limit");
#else
  ASSERT_EQ(query_result, 0);
  #if defined(__linux__) || defined(__FreeBSD__)
  EXPECT_EQ(actual_name, "thread_name_lon");
  #else
  EXPECT_EQ(actual_name, "thread_name_longer_than_limit");
  #endif
#endif
}
