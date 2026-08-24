/**
 * @file tests/integration/test_msquic_shim_isolation.cpp
 * @brief Guard the MSVC/MsQuic and MinGW/Lumen ABI boundary.
 */

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <string>

namespace {
  std::string source(const std::filesystem::path &relative) {
    std::ifstream input {std::filesystem::path {SUNSHINE_SOURCE_DIR} / relative};
    EXPECT_TRUE(input.is_open());
    return {std::istreambuf_iterator<char> {input}, std::istreambuf_iterator<char> {}};
  }
}  // namespace

TEST(MsQuicShimIsolation, PortableHeaderHasNoWindowsOrMsQuicDependency) {
  const auto header = source("src/platform/windows/msquic_shim/lumen_msquic_shim.h");
  EXPECT_EQ(header.find("#include <windows.h>"), std::string::npos);
  EXPECT_EQ(header.find("#include <msquic.h>"), std::string::npos);
  EXPECT_NE(header.find("LUMEN_MSQUIC_SHIM_ABI_VERSION 3u"), std::string::npos);
  EXPECT_NE(header.find("lumen_msquic_connection_event"), std::string::npos);
  EXPECT_NE(header.find("lumen_msquic_stream_event"), std::string::npos);
}

TEST(MsQuicShimIsolation, OfficialHeaderIsConfinedToMsvcShimTranslationUnit) {
  const auto shim = source("src/platform/windows/msquic_shim/lumen_msquic_shim.cpp");
  const auto server = source("src/protocol_v3/quic_server.cpp");
  EXPECT_NE(shim.find("#include <msquic.h>"), std::string::npos);
  EXPECT_EQ(server.find("#include <msquic.h>"), std::string::npos);
  EXPECT_EQ(server.find("QUIC_API_ENABLE_PREVIEW_FEATURES"), std::string::npos);
  EXPECT_EQ(server.find("ConnectionExportKeyingMaterial"), std::string::npos);
  EXPECT_NE(server.find("lumen_msquic_shim.h"), std::string::npos);
}

TEST(MsQuicShimIsolation, ProjectIsAnMsvcDllAndStagesPinnedRuntime) {
  const auto project = source("src/platform/windows/msquic_shim/LumenMsQuicShim.vcxproj");
  const auto dependency = source("cmake/dependencies/msquic.cmake");
  const auto targets = source("cmake/targets/common.cmake");
  EXPECT_NE(project.find("<ConfigurationType>DynamicLibrary</ConfigurationType>"), std::string::npos);
  EXPECT_NE(project.find("<PlatformToolset>v143</PlatformToolset>"), std::string::npos);
  EXPECT_NE(dependency.find("Lumen::MsQuicShim"), std::string::npos);
  EXPECT_EQ(dependency.find("add_library(MsQuic::MsQuic"), std::string::npos);
  EXPECT_NE(targets.find("LUMEN_MSQUIC_SHIM_RUNTIME"), std::string::npos);
  EXPECT_NE(targets.find("LUMEN_MSQUIC_LICENSE"), std::string::npos);
}
