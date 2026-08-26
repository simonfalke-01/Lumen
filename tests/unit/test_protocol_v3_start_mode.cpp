/**
 * @file tests/unit/test_protocol_v3_start_mode.cpp
 * @brief Canonical Lumen consumer for the language-neutral START/mode vectors.
 */

#include "src/platform/windows/virtual_display_driver/LumenModeValidationPolicy.h"
#include "src/platform/windows/virtual_display_status.h"
#include "src/protocol_v3/start_mode_contract.h"

#include <array>
#include <cstdint>
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

  const nlohmann::json &vdd_gate5_fixture() {
    static const auto fixture = [] {
      const auto path = std::filesystem::path {SUNSHINE_SOURCE_DIR} /
                        "docs/protocols/vectors/vdd_gate5_contract.json";
      std::ifstream input {path};
      if (!input) {
        throw std::runtime_error("Unable to open Gate5 VDD vectors: " + path.string());
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
    const auto &presentation = vector.at("presentation");
    const auto microphone = vector.at("microphone").get<std::string>();
    const auto host_audio_valid = vector.at("host_audio").is_boolean();
    const start_mode::Request request {
      mode,
      vector.at("bitrate_kbps").get<std::uint64_t>(),
      vector.at("profile").get<std::uint64_t>(),
      presentation.at("mode").get<std::uint64_t>(),
      presentation.at("queue_depth").get<std::uint64_t>(),
      microphone == "mono",
      microphone == "none" || microphone == "mono",
      host_audio_valid ? vector.at("host_audio").get<bool>() : false,
      host_audio_valid,
    };
    EXPECT_EQ(start_mode::name(start_mode::admit(request)), vector.at("expected").get<std::string>())
      << vector.at("id").get<std::string>();
  }
}

TEST(ProtocolV3StartMode, Gate5VddFixturePinsAdmissionFormatsAndTypedStatus) {
  const auto &fixture = vdd_gate5_fixture();
  ASSERT_EQ(fixture.at("schema"), "lumen-vdd-gate5/1");
  ASSERT_EQ(
    fixture.at("producer").at("source_baseline"),
    "c581323405375a82c9243181a1361ac22fcc1b40"
  );
  const auto &contract = fixture.at("contract");
  EXPECT_EQ(contract.at("minimum_width"), start_mode::minimum_width);
  EXPECT_EQ(contract.at("maximum_width"), start_mode::maximum_width);
  EXPECT_EQ(contract.at("minimum_height"), start_mode::minimum_height);
  EXPECT_EQ(contract.at("maximum_height"), start_mode::maximum_height);
  EXPECT_EQ(contract.at("sdr").at("texture_format"), "bgra8");
  EXPECT_EQ(contract.at("sdr").at("surface_color_space"), "srgb");
  EXPECT_EQ(contract.at("hdr10").at("texture_format"), "rgba16_float");
  EXPECT_EQ(contract.at("hdr10").at("surface_color_space"), "scrgb");

  const std::array capture_states {
    platf::virtual_display::capture_path_status_e::inactive,
    platf::virtual_display::capture_path_status_e::direct,
    platf::virtual_display::capture_path_status_e::fallback,
    platf::virtual_display::capture_path_status_e::quarantined,
    platf::virtual_display::capture_path_status_e::unavailable,
  };
  ASSERT_EQ(contract.at("capture_states").size(), capture_states.size());
  for (std::size_t index = 0; index < capture_states.size(); ++index) {
    EXPECT_EQ(
      contract.at("capture_states").at(index),
      platf::virtual_display::capture_path_status_name(capture_states[index])
    );
  }

  for (const auto &vector : fixture.at("modes")) {
    const auto hdr = vector.at("dynamic_range") == "hdr10";
    const LUMEN_VDD_MODE mode {
      vector.at("width").get<std::uint32_t>(),
      vector.at("height").get<std::uint32_t>(),
      vector.at("refresh_numerator").get<std::uint32_t>(),
      vector.at("refresh_denominator").get<std::uint32_t>(),
      static_cast<std::uint8_t>(hdr ? LUMEN_VDD_DYNAMIC_RANGE_HDR10 : LUMEN_VDD_DYNAMIC_RANGE_SDR),
      vector.at("bits_per_channel").get<std::uint8_t>(),
      LUMEN_VDD_POLICY_LATENCY,
      LUMEN_VDD_FIDELITY_LOSSLESS,
    };
    EXPECT_EQ(lumen::vdd::mode::valid(mode), vector.at("admitted").get<bool>())
      << vector.at("id").get<std::string>();
  }
}
