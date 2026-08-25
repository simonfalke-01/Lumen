/**
 * @file tests/unit/test_protocol_v3_start_mode.cpp
 * @brief Canonical Lumen consumer for the language-neutral START/mode vectors.
 */

#include "src/protocol_v3/start_mode_contract.h"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>

namespace {
  namespace start_mode = lumen::protocol_v3::start_mode;

  const nlohmann::json &start_mode_fixture() {
    static const auto fixture = [] {
      const auto path = std::filesystem::path {SUNSHINE_SOURCE_DIR} /
                        "docs/protocols/vectors/start_mode_vectors.json";
      std::ifstream input {path};
      if (!input) {
        throw std::runtime_error("Unable to open START/mode vectors: " + path.string());
      }
      return nlohmann::json::parse(input);
    }();
    return fixture;
  }
}  // namespace

TEST(ProtocolV3StartMode, CheckedInBoundaryVectorsMatchTheProductionContract) {
  const auto &fixture = start_mode_fixture();
  ASSERT_EQ(fixture.at("schema"), "umbra-lumen-start-mode/1");
  ASSERT_EQ(fixture.at("contract").at("start_keys").size(), 18U);
  ASSERT_EQ(fixture.at("contract").at("host_audio_key"), 18U);
  ASSERT_EQ(fixture.at("contract").at("host_audio_type"), "bool");

  for (const auto &vector : fixture.at("vectors")) {
    const start_mode::Mode mode {
      vector.at("width").get<std::uint64_t>(),
      vector.at("height").get<std::uint64_t>(),
      vector.at("refresh_numerator").get<std::uint64_t>(),
      vector.at("refresh_denominator").get<std::uint64_t>(),
      vector.at("codec").get<std::uint64_t>(),
      vector.at("bit_depth").get<std::uint64_t>(),
      vector.at("chroma").get<std::uint64_t>(),
      vector.at("dynamic_range").get<std::uint64_t>(),
      vector.at("codec_flags").get<std::uint64_t>(),
      vector.at("fidelity").get<std::uint64_t>(),
    };
    EXPECT_EQ(start_mode::name(start_mode::admit(mode)), vector.at("expected").get<std::string>())
      << vector.at("id").get<std::string>();
  }
}
