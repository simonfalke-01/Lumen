/**
 * @file tests/unit/test_httpcommon.cpp
 * @brief Test src/httpcommon.*.
 */
// test imports
#include "../tests_common.h"

// standard imports
#include <atomic>
#include <chrono>
#include <filesystem>
#include <format>
#include <future>
#include <stdexcept>
#include <thread>

// lib imports
#include <curl/curl.h>

// local imports
#include <src/httpcommon.h>

TEST(HttpCommonStateFileTest, TransactionsSerializeAndFailedMutationDoesNotCommit) {
  const auto state_file = std::filesystem::temp_directory_path() /
                          std::format("lumen-state-{}.json", std::chrono::steady_clock::now().time_since_epoch().count());
  std::error_code ignored;
  std::filesystem::remove(state_file, ignored);

  std::promise<void> first_mutation_started;
  auto first_mutation_started_future = first_mutation_started.get_future();
  std::atomic<bool> pairing_update_succeeded {false};
  std::atomic<bool> credential_update_succeeded {false};
  std::jthread pairing_writer([&]() {
    pairing_update_succeeded = http::update_state_file(state_file.string(), [&](http::state_file_tree_t &tree) {
      tree.put("root.uniqueid", "paired-state");
      first_mutation_started.set_value();
      std::this_thread::sleep_for(std::chrono::milliseconds(25));
    });
  });

  first_mutation_started_future.wait();
  std::jthread credential_writer([&]() {
    credential_update_succeeded = http::update_state_file(state_file.string(), [](http::state_file_tree_t &tree) {
      tree.put("username", "admin");
      tree.put("password", "encoded-password");
      tree.put("salt", "salt");
    });
  });
  pairing_writer.join();
  credential_writer.join();

  EXPECT_TRUE(pairing_update_succeeded);
  EXPECT_TRUE(credential_update_succeeded);
  http::state_file_tree_t committed;
  ASSERT_TRUE(http::read_state_file(state_file.string(), committed));
  EXPECT_EQ(committed.get<std::string>("root.uniqueid"), "paired-state");
  EXPECT_EQ(committed.get<std::string>("username"), "admin");

  EXPECT_FALSE(http::update_state_file(state_file.string(), [](http::state_file_tree_t &tree) {
    tree.put("must_not_commit", true);
    throw std::runtime_error("injected mutation failure");
  }));
  http::state_file_tree_t after_failure;
  ASSERT_TRUE(http::read_state_file(state_file.string(), after_failure));
  EXPECT_FALSE(after_failure.get_optional<bool>("must_not_commit"));
  EXPECT_EQ(after_failure.get<std::string>("root.uniqueid"), "paired-state");
  EXPECT_EQ(after_failure.get<std::string>("username"), "admin");

  std::filesystem::remove(state_file, ignored);
}

struct UrlEscapeTest: BaseTest, testing::WithParamInterface<std::tuple<std::string, std::string>> {};

TEST_P(UrlEscapeTest, Run) {
  const auto &[input, expected] = GetParam();
  ASSERT_EQ(http::url_escape(input), expected);
}

INSTANTIATE_TEST_SUITE_P(
  UrlEscapeTests,
  UrlEscapeTest,
  testing::Values(
    std::make_tuple("igdb_0123456789", "igdb_0123456789"),
    std::make_tuple("../../../", "..%2F..%2F..%2F"),
    std::make_tuple("..*\\", "..%2A%5C")
  )
);

struct UrlGetHostTest: BaseTest, testing::WithParamInterface<std::tuple<std::string, std::string>> {};

TEST_P(UrlGetHostTest, Run) {
  const auto &[input, expected] = GetParam();
  ASSERT_EQ(http::url_get_host(input), expected);
}

INSTANTIATE_TEST_SUITE_P(
  UrlGetHostTests,
  UrlGetHostTest,
  testing::Values(
    std::make_tuple("https://images.igdb.com/example.txt", "images.igdb.com"),
    std::make_tuple("http://localhost:8080", "localhost"),
    std::make_tuple("nonsense!!}{::", "")
  )
);

struct DownloadFileTest: BaseTest, testing::WithParamInterface<std::tuple<std::string, std::string>> {};

TEST_P(DownloadFileTest, Run) {
  const auto &[url, filename] = GetParam();
  const std::string test_dir = platf::appdata().string() + "/tests/";
  std::string path = test_dir + filename;
  ASSERT_TRUE(http::download_file(url, path, CURL_SSLVERSION_TLSv1_0));
}

#ifdef SUNSHINE_BUILD_FLATPAK
// requires running `npm run serve` prior to running the tests
constexpr const char *URL_1 = "http://0.0.0.0:3000/hello.txt";
constexpr const char *URL_2 = "http://0.0.0.0:3000/hello-redirect.txt";
#else
constexpr const char *URL_1 = "https://httpbin.org/base64/aGVsbG8h";
constexpr const char *URL_2 = "https://httpbin.org/redirect-to?url=/base64/aGVsbG8h";
#endif

INSTANTIATE_TEST_SUITE_P(
  DownloadFileTests,
  DownloadFileTest,
  testing::Values(
    std::make_tuple(URL_1, "hello.txt"),
    std::make_tuple(URL_2, "hello-redirect.txt")
  )
);
