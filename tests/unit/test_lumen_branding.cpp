/**
 * @file tests/unit/test_lumen_branding.cpp
 * @brief Tests for Lumen's authoritative runtime identity and compatibility defaults.
 */

#include "../tests_common.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <src/config.h>
#include <src/platform/common.h>

/**
 * @brief Verify new installations use Lumen configuration and log filenames.
 */
TEST(LumenBrandingTest, UsesAuthoritativeDefaultFileNames) {
  EXPECT_EQ(std::filesystem::path {config::sunshine.config_file}.filename(), "lumen.conf");
  EXPECT_EQ(std::filesystem::path {config::sunshine.log_file}.filename(), "lumen.log");
}

/**
 * @brief Verify GameStream discovery advertises the Lumen service identity.
 */
TEST(LumenBrandingTest, UsesAuthoritativeDiscoveryServiceName) {
  EXPECT_EQ(platf::SERVICE_NAME, "Lumen");
}

/**
 * @brief Verify a copied legacy config is preserved and gains the authoritative filename.
 */
TEST(LumenBrandingTest, CopiesLegacyConfigFileWithoutDeletingIt) {
  const auto unique_suffix = std::chrono::steady_clock::now().time_since_epoch().count();
  const auto test_directory = std::filesystem::temp_directory_path() / ("lumen-config-file-migration-test-" + std::to_string(unique_suffix));
  const auto legacy_config = test_directory / "sunshine.conf";
  const auto lumen_config = test_directory / "lumen.conf";
  std::filesystem::create_directories(test_directory);
  std::ofstream {legacy_config} << "port = 48000\n";

  auto selected_config = lumen_config.string();
  config::migrate_legacy_config_file(selected_config, false);

  EXPECT_EQ(selected_config, lumen_config.string());
  EXPECT_TRUE(std::filesystem::exists(legacy_config));
  EXPECT_TRUE(std::filesystem::exists(lumen_config));
  std::filesystem::remove_all(test_directory);
}

/**
 * @brief Verify explicit config paths never trigger legacy discovery.
 */
TEST(LumenBrandingTest, LeavesExplicitConfigPathUntouched) {
  const auto unique_suffix = std::chrono::steady_clock::now().time_since_epoch().count();
  const auto test_directory = std::filesystem::temp_directory_path() / ("lumen-explicit-config-test-" + std::to_string(unique_suffix));
  const auto legacy_config = test_directory / "sunshine.conf";
  const auto lumen_config = test_directory / "lumen.conf";
  std::filesystem::create_directories(test_directory);
  std::ofstream {legacy_config};

  auto selected_config = lumen_config.string();
  config::migrate_legacy_config_file(selected_config, true);

  EXPECT_EQ(selected_config, lumen_config.string());
  EXPECT_FALSE(std::filesystem::exists(lumen_config));
  EXPECT_TRUE(std::filesystem::exists(legacy_config));
  std::filesystem::remove_all(test_directory);
}

/**
 * @brief Verify an existing authoritative config always wins over legacy state.
 */
TEST(LumenBrandingTest, KeepsExistingAuthoritativeConfig) {
  const auto unique_suffix = std::chrono::steady_clock::now().time_since_epoch().count();
  const auto test_directory = std::filesystem::temp_directory_path() / ("lumen-existing-config-test-" + std::to_string(unique_suffix));
  const auto legacy_config = test_directory / "sunshine.conf";
  const auto lumen_config = test_directory / "lumen.conf";
  std::filesystem::create_directories(test_directory);
  std::ofstream {legacy_config} << "port = 48000\n";
  std::ofstream {lumen_config} << "port = 49000\n";

  auto selected_config = lumen_config.string();
  config::migrate_legacy_config_file(selected_config, false);

  EXPECT_EQ(selected_config, lumen_config.string());
  std::ifstream authoritative_stream {lumen_config};
  std::string authoritative_contents;
  std::getline(authoritative_stream, authoritative_contents);
  EXPECT_EQ(authoritative_contents, "port = 49000");
  authoritative_stream.close();
  std::filesystem::remove_all(test_directory);
}

/**
 * @brief Verify nonstandard filenames never trigger Sunshine discovery.
 */
TEST(LumenBrandingTest, IgnoresNonstandardConfigFileName) {
  const auto unique_suffix = std::chrono::steady_clock::now().time_since_epoch().count();
  const auto test_directory = std::filesystem::temp_directory_path() / ("lumen-nonstandard-config-test-" + std::to_string(unique_suffix));
  const auto legacy_config = test_directory / "sunshine.conf";
  const auto custom_config = test_directory / "custom.conf";
  std::filesystem::create_directories(test_directory);
  std::ofstream {legacy_config};

  auto selected_config = custom_config.string();
  config::migrate_legacy_config_file(selected_config, false);

  EXPECT_EQ(selected_config, custom_config.string());
  EXPECT_FALSE(std::filesystem::exists(custom_config));
  std::filesystem::remove_all(test_directory);
}

/**
 * @brief Verify missing legacy state leaves the authoritative destination untouched.
 */
TEST(LumenBrandingTest, HandlesAbsentLegacyConfig) {
  const auto unique_suffix = std::chrono::steady_clock::now().time_since_epoch().count();
  const auto test_directory = std::filesystem::temp_directory_path() / ("lumen-absent-legacy-test-" + std::to_string(unique_suffix));
  const auto lumen_config = test_directory / "lumen.conf";
  std::filesystem::create_directories(test_directory);

  auto selected_config = lumen_config.string();
  config::migrate_legacy_config_file(selected_config, false);

  EXPECT_EQ(selected_config, lumen_config.string());
  EXPECT_FALSE(std::filesystem::exists(lumen_config));
  std::filesystem::remove_all(test_directory);
}

/**
 * @brief Verify migration never writes authoritative state into an upstream directory.
 */
TEST(LumenBrandingTest, RefusesToWriteIntoSunshineDirectory) {
  const auto unique_suffix = std::chrono::steady_clock::now().time_since_epoch().count();
  const auto test_directory = std::filesystem::temp_directory_path() / ("lumen-upstream-boundary-test-" + std::to_string(unique_suffix)) / "sunshine";
  const auto legacy_config = test_directory / "sunshine.conf";
  const auto lumen_config = test_directory / "lumen.conf";
  std::filesystem::create_directories(test_directory);
  std::ofstream {legacy_config} << "port = 48000\n";

  auto selected_config = lumen_config.string();
  config::migrate_legacy_config_file(selected_config, false);

  EXPECT_EQ(selected_config, lumen_config.string());
  EXPECT_FALSE(std::filesystem::exists(lumen_config));
  EXPECT_TRUE(std::filesystem::exists(legacy_config));
  std::filesystem::remove_all(test_directory.parent_path());
}

/**
 * @brief Verify directory migration publishes a complete copy and preserves its source.
 */
TEST(LumenBrandingTest, CopiesLegacyDirectoryWithoutDeletingSource) {
  const auto unique_suffix = std::chrono::steady_clock::now().time_since_epoch().count();
  const auto test_root = std::filesystem::temp_directory_path() / ("lumen-directory-copy-test-" + std::to_string(unique_suffix));
  const auto legacy_directory = test_root / "sunshine";
  const auto lumen_directory = test_root / "lumen";
  std::filesystem::create_directories(legacy_directory / "credentials");
  std::ofstream {legacy_directory / "apps.json"} << "{}\n";
  std::ofstream {legacy_directory / "credentials" / "cacert.pem"} << "certificate\n";

  std::string error_message;
  ASSERT_TRUE(config::copy_legacy_config_directory(
    legacy_directory.string(),
    lumen_directory.string(),
    error_message
  )) << error_message;

  EXPECT_TRUE(std::filesystem::exists(legacy_directory / "apps.json"));
  EXPECT_TRUE(std::filesystem::exists(lumen_directory / "apps.json"));
  EXPECT_TRUE(std::filesystem::exists(lumen_directory / "credentials" / "cacert.pem"));
  std::filesystem::remove_all(test_root);
}

/**
 * @brief Verify a destination creation failure never redirects writes into legacy state.
 */
TEST(LumenBrandingTest, KeepsLegacyDirectoryOnDestinationFailure) {
  const auto unique_suffix = std::chrono::steady_clock::now().time_since_epoch().count();
  const auto test_root = std::filesystem::temp_directory_path() / ("lumen-directory-failure-test-" + std::to_string(unique_suffix));
  const auto legacy_directory = test_root / "sunshine";
  const auto blocked_parent = test_root / "blocked";
  const auto lumen_directory = blocked_parent / "lumen";
  std::filesystem::create_directories(legacy_directory);
  std::ofstream {legacy_directory / "apps.json"} << "{}\n";
  std::ofstream {blocked_parent} << "not a directory\n";

  std::string error_message;
  EXPECT_FALSE(config::copy_legacy_config_directory(
    legacy_directory.string(),
    lumen_directory.string(),
    error_message
  ));
  EXPECT_FALSE(error_message.empty());
  EXPECT_TRUE(std::filesystem::exists(legacy_directory / "apps.json"));
  EXPECT_FALSE(std::filesystem::exists(lumen_directory));
  std::filesystem::remove_all(test_root);
}

#ifndef _WIN32
/**
 * @brief Verify migration rejects symlinked files without publishing a destination.
 */
TEST(LumenBrandingTest, RejectsLegacyFileSymlink) {
  const auto unique_suffix = std::chrono::steady_clock::now().time_since_epoch().count();
  const auto test_root = std::filesystem::temp_directory_path() / ("lumen-file-symlink-test-" + std::to_string(unique_suffix));
  const auto legacy_directory = test_root / "sunshine";
  const auto lumen_directory = test_root / "lumen";
  const auto external_file = test_root / "external.json";
  std::filesystem::create_directories(legacy_directory);
  std::ofstream {external_file} << "{}\n";
  std::filesystem::create_symlink(external_file, legacy_directory / "apps.json");

  std::string error_message;
  EXPECT_FALSE(config::copy_legacy_config_directory(
    legacy_directory.string(),
    lumen_directory.string(),
    error_message
  ));
  EXPECT_FALSE(error_message.empty());
  EXPECT_FALSE(std::filesystem::exists(lumen_directory));
  EXPECT_TRUE(std::filesystem::is_symlink(legacy_directory / "apps.json"));
  std::filesystem::remove_all(test_root);
}

/**
 * @brief Verify migration rejects symlinked directories without publishing a destination.
 */
TEST(LumenBrandingTest, RejectsLegacyDirectorySymlink) {
  const auto unique_suffix = std::chrono::steady_clock::now().time_since_epoch().count();
  const auto test_root = std::filesystem::temp_directory_path() / ("lumen-directory-symlink-test-" + std::to_string(unique_suffix));
  const auto legacy_directory = test_root / "sunshine";
  const auto lumen_directory = test_root / "lumen";
  const auto external_directory = test_root / "external";
  std::filesystem::create_directories(legacy_directory);
  std::filesystem::create_directories(external_directory);
  std::filesystem::create_directory_symlink(external_directory, legacy_directory / "credentials");

  std::string error_message;
  EXPECT_FALSE(config::copy_legacy_config_directory(
    legacy_directory.string(),
    lumen_directory.string(),
    error_message
  ));
  EXPECT_FALSE(error_message.empty());
  EXPECT_FALSE(std::filesystem::exists(lumen_directory));
  EXPECT_TRUE(std::filesystem::is_symlink(legacy_directory / "credentials"));
  std::filesystem::remove_all(test_root);
}
#endif
