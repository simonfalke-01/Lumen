/**
 * @file tests/integration/test_virtual_hid_driver_isolation.cpp
 * @brief Guard static-input and dynamic-gamepad driver lifetime boundaries.
 */

// standard includes
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

// third-party includes
#include <gtest/gtest.h>

namespace {
  /**
   * @brief Read one repository source file for a structural boundary assertion.
   *
   * @param relative_path Repository-relative source path.
   * @return Complete source text.
   */
  std::string read_source(const std::filesystem::path &relative_path) {
    const auto path = std::filesystem::path {SUNSHINE_SOURCE_DIR} / relative_path;
    std::ifstream stream {path};
    EXPECT_TRUE(stream.is_open()) << path;
    return {
      std::istreambuf_iterator<char> {stream},
      std::istreambuf_iterator<char> {},
    };
  }
}  // namespace

TEST(VirtualHidDriverIsolationTest, StaticResetCannotReachDynamicGamepadLifecycle) {
  const auto source = read_source("src/platform/windows/virtual_hid_driver/Driver.c");
  const auto reset_begin = source.find("static NTSTATUS LumenVhidResetAndRelease");
  const auto reset_end = source.find("VOID LumenVhidEvtVhfReadyForNextReadReport", reset_begin);
  ASSERT_NE(reset_begin, std::string::npos);
  ASSERT_NE(reset_end, std::string::npos);
  const auto reset = source.substr(reset_begin, reset_end - reset_begin);

  EXPECT_NE(reset.find("LumenVhidSubmitNeutralState"), std::string::npos);
  EXPECT_NE(reset.find("LumenVhidDeleteVhf"), std::string::npos);
  EXPECT_NE(reset.find("LumenVhidCreateAndStart"), std::string::npos);
  EXPECT_EQ(reset.find("LumenVhidGamepad"), std::string::npos);
  EXPECT_EQ(reset.find("gamepads["), std::string::npos);
}

TEST(VirtualHidDriverIsolationTest, FileCleanupRemovesOwnedGamepadsBeforeStaticReset) {
  const auto source = read_source("src/platform/windows/virtual_hid_driver/Driver.c");
  const auto cleanup_begin = source.find("VOID LumenVhidEvtFileCleanup");
  const auto cleanup_end = source.find("VOID LumenVhidEvtDeviceCleanup", cleanup_begin);
  ASSERT_NE(cleanup_begin, std::string::npos);
  ASSERT_NE(cleanup_end, std::string::npos);
  const auto cleanup = source.substr(cleanup_begin, cleanup_end - cleanup_begin);
  const auto dynamic_cleanup = cleanup.find("LumenVhidGamepadCleanupFile(context, file_object)");
  const auto static_reset = cleanup.find("LumenVhidResetAndRelease(context)");

  ASSERT_NE(dynamic_cleanup, std::string::npos);
  ASSERT_NE(static_reset, std::string::npos);
  EXPECT_LT(dynamic_cleanup, static_reset);
}

TEST(VirtualHidDriverIsolationTest, VigemFeedbackWorkerIsJoinableAndGenerationFenced) {
  const auto source = read_source("src/platform/windows/input.cpp");

  EXPECT_NE(source.find("std::jthread worker"), std::string::npos);
  EXPECT_NE(source.find("CancelIoEx"), std::string::npos);
  EXPECT_NE(source.find("notification.worker.request_stop()"), std::string::npos);
  EXPECT_NE(source.find("notification.worker.join()"), std::string::npos);
  EXPECT_NE(source.find("gamepad.notification.generation != generation"), std::string::npos);
  EXPECT_EQ(source.find("vigem_target_x360_register_notification"), std::string::npos);
  EXPECT_EQ(source.find("task_pool.push(&vigem_t::rumble"), std::string::npos);
}
