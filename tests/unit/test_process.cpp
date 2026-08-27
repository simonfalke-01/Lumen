/**
 * @file tests/unit/test_process.cpp
 * @brief Test src/process.* functions.
 */
// test imports
#include "../tests_common.h"

// standard imports
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <vector>

// local imports
#include <src/process.h>

namespace fs = std::filesystem;

class ProcessPNGTest: public BaseTest {
protected:
  void SetUp() override {
    BaseTest::SetUp();
    // Create test directory
    test_dir = fs::temp_directory_path() / "sunshine_process_png_test";  // NOSONAR(cpp:S5443): safe for tests
    fs::create_directories(test_dir);
  }

  void TearDown() override {
    // Clean up test directory
    if (fs::exists(test_dir)) {
      fs::remove_all(test_dir);
    }
    BaseTest::TearDown();
  }

  // Helper function to create a file with specific content
  void createTestFile(const fs::path &path, const std::vector<unsigned char> &content) const {
    std::ofstream file(path, std::ios::binary);
    file.write(reinterpret_cast<const char *>(content.data()), content.size());
    file.close();
  }

  fs::path test_dir;
};

// Tests for check_valid_png function
TEST_F(ProcessPNGTest, CheckValidPNG_ValidSignature) {
  // Valid PNG signature
  const std::vector<unsigned char> valid_png_data = {
    0x89,
    0x50,
    0x4E,
    0x47,
    0x0D,
    0x0A,
    0x1A,
    0x0A,  // PNG signature
    // Add some dummy data to make it more realistic
    0x00,
    0x00,
    0x00,
    0x0D,
    0x49,
    0x48,
    0x44,
    0x52
  };

  const fs::path test_file = test_dir / "valid.png";
  createTestFile(test_file, valid_png_data);

  EXPECT_TRUE(proc::check_valid_png(test_file));
}

TEST(ProcessLaunchEnvironmentTest, PreservesExactModernRefreshAndLegacyIntegerCompatibility) {
  boost::process::v1::environment env {boost::this_process::environment()};
  rtsp_stream::launch_session_t launch {};
  launch.width = 3456;
  launch.height = 2160;
  launch.fps = 60;
  launch.refresh_numerator = 60'000;
  launch.refresh_denominator = 1'001;
  launch.enable_hdr = true;
  launch.host_audio = false;
  launch.surround_info = 0x003f0006;
  launch.surround_params = "642012345";

  proc::apply_launch_environment(env, 7, "Desktop", launch);

  EXPECT_EQ(env["LUMEN_CLIENT_REFRESH_NUMERATOR"].to_string(), "60000");
  EXPECT_EQ(env["LUMEN_CLIENT_REFRESH_DENOMINATOR"].to_string(), "1001");
  EXPECT_NEAR(std::stod(env["LUMEN_CLIENT_FPS"].to_string()), 60'000.0 / 1'001.0, 1e-12);
  EXPECT_EQ(env["LUMEN_CLIENT_HDR"].to_string(), "true");
  EXPECT_EQ(env["LUMEN_CLIENT_HOST_AUDIO"].to_string(), "false");
  EXPECT_EQ(env["LUMEN_CLIENT_AUDIO_CONFIGURATION"].to_string(), "5.1");
  EXPECT_EQ(env["LUMEN_CLIENT_AUDIO_SURROUND_PARAMS"].to_string(), "642012345");
  EXPECT_EQ(env["SUNSHINE_CLIENT_FPS"].to_string(), "60");
}

TEST(ProcessLaunchEnvironmentTest, LegacyLaunchFallsBackToIntegerRefreshRational) {
  boost::process::v1::environment env {boost::this_process::environment()};
  rtsp_stream::launch_session_t launch {};
  launch.fps = 120;
  launch.surround_info = 2;

  proc::apply_launch_environment(env, 1, "Legacy", launch);

  EXPECT_EQ(env["LUMEN_CLIENT_FPS"].to_string(), "120");
  EXPECT_EQ(env["LUMEN_CLIENT_REFRESH_NUMERATOR"].to_string(), "120");
  EXPECT_EQ(env["LUMEN_CLIENT_REFRESH_DENOMINATOR"].to_string(), "1");
  EXPECT_EQ(env["SUNSHINE_CLIENT_FPS"].to_string(), "120");
}

TEST(ProcessLifecycleTest, CancellationRequiresAnAuthorizedLegacyCertificate) {
  boost::process::v1::environment env {boost::this_process::environment()};
  proc::ctx_t desktop {};
  desktop.name = "Desktop";
  desktop.id = "881";
  desktop.exit_timeout = std::chrono::seconds {0};
  std::vector<proc::ctx_t> apps;
  apps.emplace_back(std::move(desktop));
  proc::proc_t process {std::move(env), std::move(apps)};

  auto launch = std::make_shared<rtsp_stream::launch_session_t>();
  launch->client_cert = "certificate-a";
  ASSERT_EQ(process.execute(881, launch), 0);
  ASSERT_EQ(process.running(), 881);

  EXPECT_FALSE(process.terminate_if_owned_by_certificate("certificate-b"));
  EXPECT_EQ(process.running(), 881);
  process.authorize_cancel_by_certificate("certificate-b", launch->process_generation);
  EXPECT_TRUE(process.terminate_if_owned_by_certificate("certificate-b"));
  EXPECT_EQ(process.running(), 0);
  EXPECT_FALSE(process.terminate_if_owned_by_certificate("certificate-a"));
}

TEST(ProcessLifecycleTest, GenerationFencesLateLegacyOwnersFromReplacementAndProtocolV3Processes) {
  boost::process::v1::environment env {boost::this_process::environment()};
  proc::ctx_t desktop {};
  desktop.name = "Desktop";
  desktop.id = "881";
  desktop.exit_timeout = std::chrono::seconds {0};
  std::vector<proc::ctx_t> apps;
  apps.emplace_back(std::move(desktop));
  proc::proc_t process {std::move(env), std::move(apps)};

  auto legacy = std::make_shared<rtsp_stream::launch_session_t>();
  legacy->client_cert = "certificate-a";
  ASSERT_EQ(process.execute(881, legacy), 0);
  const auto legacy_generation = legacy->process_generation;

  auto protocol_v3 = std::make_shared<rtsp_stream::launch_session_t>();
  ASSERT_EQ(process.execute(881, protocol_v3), 0);
  const auto protocol_v3_generation = protocol_v3->process_generation;
  ASSERT_GT(protocol_v3_generation, legacy_generation);

  bool stale_publish_called {};
  EXPECT_FALSE(process.publish_legacy_session(
    legacy_generation,
    "certificate-a",
    [&]() {
      stale_publish_called = true;
      return true;
    }
  ));
  EXPECT_FALSE(stale_publish_called);
  EXPECT_FALSE(process.authorize_cancel_by_certificate("certificate-a", legacy_generation));
  EXPECT_FALSE(process.terminate_if_owned_by_certificate("certificate-a"));

  bool cross_protocol_publish_called {};
  EXPECT_FALSE(process.publish_legacy_session(
    protocol_v3_generation,
    "certificate-a",
    [&]() {
      cross_protocol_publish_called = true;
      return true;
    }
  ));
  EXPECT_FALSE(cross_protocol_publish_called);
  EXPECT_EQ(process.running(), 881);
}

TEST(ProcessLifecycleTest, ActivePublicationSerializesAgainstConcurrentProcessReplacement) {
  boost::process::v1::environment env {boost::this_process::environment()};
  proc::ctx_t desktop {};
  desktop.name = "Desktop";
  desktop.id = "881";
  desktop.exit_timeout = std::chrono::seconds {0};
  std::vector<proc::ctx_t> apps;
  apps.emplace_back(std::move(desktop));
  proc::proc_t process {std::move(env), std::move(apps)};

  auto legacy = std::make_shared<rtsp_stream::launch_session_t>();
  legacy->client_cert = "certificate-a";
  ASSERT_EQ(process.execute(881, legacy), 0);

  std::promise<void> publish_entered;
  auto publish_started = publish_entered.get_future();
  std::promise<void> release_publish;
  auto publish_release = release_publish.get_future().share();
  auto publication = std::async(std::launch::async, [&]() {
    return process.publish_legacy_session(
      legacy->process_generation,
      legacy->client_cert,
      [&]() {
        publish_entered.set_value();
        publish_release.wait();
        return true;
      }
    );
  });
  ASSERT_EQ(publish_started.wait_for(std::chrono::seconds {1}), std::future_status::ready);

  auto protocol_v3 = std::make_shared<rtsp_stream::launch_session_t>();
  std::promise<void> replacement_entered;
  auto replacement_started = replacement_entered.get_future();
  auto replacement = std::async(std::launch::async, [&]() {
    replacement_entered.set_value();
    return process.execute(881, protocol_v3);
  });
  ASSERT_EQ(replacement_started.wait_for(std::chrono::seconds {1}), std::future_status::ready);
  EXPECT_EQ(replacement.wait_for(std::chrono::milliseconds {20}), std::future_status::timeout);

  release_publish.set_value();
  EXPECT_TRUE(publication.get());
  EXPECT_EQ(replacement.get(), 0);
  EXPECT_GT(protocol_v3->process_generation, legacy->process_generation);
  EXPECT_FALSE(process.terminate_if_owned_by_certificate(legacy->client_cert));
}

TEST_F(ProcessPNGTest, CheckValidPNG_WrongSignature) {
  // Invalid PNG signature (wrong magic bytes)
  const std::vector<unsigned char> invalid_png_data = {
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00
  };

  const fs::path test_file = test_dir / "invalid.png";
  createTestFile(test_file, invalid_png_data);

  EXPECT_FALSE(proc::check_valid_png(test_file));
}

TEST_F(ProcessPNGTest, CheckValidPNG_TooShort) {
  // File too short (less than 8 bytes)
  const std::vector<unsigned char> short_data = {
    0x89,
    0x50,
    0x4E,
    0x47
  };

  const fs::path test_file = test_dir / "short.png";
  createTestFile(test_file, short_data);

  EXPECT_FALSE(proc::check_valid_png(test_file));
}

TEST_F(ProcessPNGTest, CheckValidPNG_EmptyFile) {
  // Empty file
  const std::vector<unsigned char> empty_data = {};

  const fs::path test_file = test_dir / "empty.png";
  createTestFile(test_file, empty_data);

  EXPECT_FALSE(proc::check_valid_png(test_file));
}

TEST_F(ProcessPNGTest, CheckValidPNG_NonExistentFile) {
  // File doesn't exist
  const fs::path test_file = test_dir / "nonexistent.png";

  EXPECT_FALSE(proc::check_valid_png(test_file));
}

TEST_F(ProcessPNGTest, CheckValidPNG_RealFile) {
  // Test with the actual sunshine.png from the project root

  // Only run this test if the file exists
  if (const fs::path sunshine_png = fs::path(SUNSHINE_SOURCE_DIR) / "sunshine.png"; fs::exists(sunshine_png)) {
    EXPECT_TRUE(proc::check_valid_png(sunshine_png));
  } else {
    GTEST_SKIP() << "sunshine.png not found in project root";
  }
}

TEST_F(ProcessPNGTest, CheckValidPNG_JPEGFile) {
  // JPEG signature (not PNG)
  const std::vector<unsigned char> jpeg_data = {
    0xFF,
    0xD8,
    0xFF,
    0xE0,
    0x00,
    0x10,
    0x4A,
    0x46
  };

  const fs::path test_file = test_dir / "fake.png";
  createTestFile(test_file, jpeg_data);

  EXPECT_FALSE(proc::check_valid_png(test_file));
}

TEST_F(ProcessPNGTest, CheckValidPNG_PartialSignature) {
  // Partial PNG signature (first 4 bytes correct, rest wrong)
  const std::vector<unsigned char> partial_png_data = {
    0x89,
    0x50,
    0x4E,
    0x47,
    0x00,
    0x00,
    0x00,
    0x00
  };

  const fs::path test_file = test_dir / "partial.png";
  createTestFile(test_file, partial_png_data);

  EXPECT_FALSE(proc::check_valid_png(test_file));
}

// Tests for validate_app_image_path function
TEST_F(ProcessPNGTest, ValidateAppImagePath_EmptyPath) {
  // Empty path should return default
  const std::string result = proc::validate_app_image_path("");
  EXPECT_EQ(result, DEFAULT_APP_IMAGE_PATH);
}

TEST_F(ProcessPNGTest, ValidateAppImagePath_NonPNGExtension) {
  // Non-PNG extension should return default
  const std::string result = proc::validate_app_image_path("image.jpg");
  EXPECT_EQ(result, DEFAULT_APP_IMAGE_PATH);
}

TEST_F(ProcessPNGTest, ValidateAppImagePath_CaseInsensitiveExtension) {
  // Test that .PNG (uppercase) is recognized
  // Create a valid PNG file
  const std::vector<unsigned char> valid_png_data = {
    0x89,
    0x50,
    0x4E,
    0x47,
    0x0D,
    0x0A,
    0x1A,
    0x0A,
    0x00,
    0x00,
    0x00,
    0x0D,
    0x49,
    0x48,
    0x44,
    0x52
  };

  const fs::path test_file = test_dir / "test.PNG";
  createTestFile(test_file, valid_png_data);

  const std::string result = proc::validate_app_image_path(test_file.string());
  // Should accept uppercase .PNG extension
  EXPECT_NE(result, DEFAULT_APP_IMAGE_PATH);
}

TEST_F(ProcessPNGTest, ValidateAppImagePath_NonExistentFile) {
  // Non-existent PNG file should return default
  const std::string result = proc::validate_app_image_path("/nonexistent/path/image.png");
  EXPECT_EQ(result, DEFAULT_APP_IMAGE_PATH);
}

TEST_F(ProcessPNGTest, ValidateAppImagePath_InvalidPNGSignature) {
  // File with .png extension but invalid signature should return default
  const std::vector<unsigned char> invalid_data = {
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00
  };

  const fs::path test_file = test_dir / "invalid.png";
  createTestFile(test_file, invalid_data);

  const std::string result = proc::validate_app_image_path(test_file.string());
  EXPECT_EQ(result, DEFAULT_APP_IMAGE_PATH);
}

TEST_F(ProcessPNGTest, ValidateAppImagePath_ValidPNG) {
  // Valid PNG file should return the path
  const std::vector<unsigned char> valid_png_data = {
    0x89,
    0x50,
    0x4E,
    0x47,
    0x0D,
    0x0A,
    0x1A,
    0x0A,
    0x00,
    0x00,
    0x00,
    0x0D,
    0x49,
    0x48,
    0x44,
    0x52
  };

  const fs::path test_file = test_dir / "valid.png";
  createTestFile(test_file, valid_png_data);

  const std::string result = proc::validate_app_image_path(test_file.string());
  EXPECT_EQ(result, test_file.string());
}

TEST_F(ProcessPNGTest, ValidateAppImagePath_OldSteamDefault) {
  // Test the special case for old steam image path
  const std::string result = proc::validate_app_image_path("./assets/steam.png");
  EXPECT_EQ(result, SUNSHINE_ASSETS_DIR "/steam.png");
}
