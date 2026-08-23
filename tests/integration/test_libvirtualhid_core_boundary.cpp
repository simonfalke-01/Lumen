/**
 * @file tests/integration/test_libvirtualhid_core_boundary.cpp
 * @brief Guard Lumen's portable-only libvirtualhid source boundary.
 */

// standard includes
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

// third-party includes
#include <gtest/gtest.h>

TEST(LibvirtualhidCoreBoundaryTest, WhitelistsOnlyPortableProfileReportAndTypeSources) {
  const auto source_path = std::filesystem::path {SUNSHINE_SOURCE_DIR} /
                           "cmake/dependencies/libvirtualhid_core.cmake";
  std::ifstream stream {source_path};
  ASSERT_TRUE(stream.is_open()) << source_path;
  const std::string contents {
    std::istreambuf_iterator<char> {stream},
    std::istreambuf_iterator<char> {},
  };
  const auto list_begin = contents.find("set(LUMEN_LIBVIRTUALHID_CORE_SOURCES");
  const auto list_end = contents.find("\n\nadd_library(lumen_lvh_core", list_begin);
  ASSERT_NE(list_begin, std::string::npos);
  ASSERT_NE(list_end, std::string::npos);
  const auto source_list = contents.substr(list_begin, list_end - list_begin);

  EXPECT_NE(source_list.find("src/core/profiles.cpp"), std::string::npos);
  EXPECT_NE(source_list.find("src/core/report.cpp"), std::string::npos);
  EXPECT_NE(source_list.find("src/core/types.cpp"), std::string::npos);
  EXPECT_EQ(source_list.find("src/core/backend.cpp"), std::string::npos);
  EXPECT_EQ(source_list.find("src/core/gamepad_adapter.cpp"), std::string::npos);
  EXPECT_EQ(source_list.find("src/core/runtime.cpp"), std::string::npos);
  EXPECT_EQ(source_list.find("src/platform/"), std::string::npos);
  EXPECT_EQ(source_list.find("license.cpp"), std::string::npos);
}

TEST(LibvirtualhidCoreBoundaryTest, NeverImportsUpstreamKeyboardMouseOrSendInputBackend) {
  const auto source_path = std::filesystem::path {SUNSHINE_SOURCE_DIR} /
                           "cmake/dependencies/libvirtualhid_core.cmake";
  std::ifstream stream {source_path};
  ASSERT_TRUE(stream.is_open()) << source_path;
  const std::string contents {
    std::istreambuf_iterator<char> {stream},
    std::istreambuf_iterator<char> {},
  };

  EXPECT_EQ(contents.find("windows_backend.cpp"), std::string::npos);
  EXPECT_EQ(contents.find("keyboard_mouse_adapter"), std::string::npos);
  EXPECT_EQ(contents.find("libvirtualhid::Keyboard"), std::string::npos);
  EXPECT_EQ(contents.find("libvirtualhid::Mouse"), std::string::npos);
  EXPECT_EQ(contents.find("SendInput"), std::string::npos);
}

TEST(LibvirtualhidCoreBoundaryTest, WindowsFacadeImportsOnlyApprovedPidHelpers) {
  const auto source_path = std::filesystem::path {SUNSHINE_SOURCE_DIR} /
                           "cmake/dependencies/libvirtualhid_core.cmake";
  std::ifstream stream {source_path};
  ASSERT_TRUE(stream.is_open()) << source_path;
  const std::string contents {
    std::istreambuf_iterator<char> {stream},
    std::istreambuf_iterator<char> {},
  };
  const auto facade_begin = contents.find("add_library(lumen_lvh_gamepad_core STATIC");
  const auto facade_end = contents.find("add_library(Lumen::libvirtualhid_gamepad_core", facade_begin);
  ASSERT_NE(facade_begin, std::string::npos);
  ASSERT_NE(facade_end, std::string::npos);
  const auto facade_sources = contents.substr(facade_begin, facade_end - facade_begin);

  EXPECT_NE(facade_sources.find("generic_pid_protocol.hpp"), std::string::npos);
  EXPECT_NE(facade_sources.find("generic_pid_rumble.hpp"), std::string::npos);
  EXPECT_NE(facade_sources.find("libvirtualhid_gamepad_core.cpp"), std::string::npos);
  EXPECT_EQ(facade_sources.find("windows_backend.cpp"), std::string::npos);
  EXPECT_EQ(facade_sources.find("control_protocol.hpp"), std::string::npos);
  EXPECT_EQ(facade_sources.find("broker"), std::string::npos);
  EXPECT_EQ(facade_sources.find("license"), std::string::npos);
  EXPECT_EQ(facade_sources.find("keyboard"), std::string::npos);
  EXPECT_EQ(facade_sources.find("mouse"), std::string::npos);
}
