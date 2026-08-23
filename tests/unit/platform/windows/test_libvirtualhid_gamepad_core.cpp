/**
 * @file tests/unit/platform/windows/test_libvirtualhid_gamepad_core.cpp
 * @brief Test Lumen's gamepad-only portable libvirtualhid facade.
 */

// standard includes
#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

// local includes
#include <src/platform/windows/libvirtualhid_gamepad_core.h>

// third-party includes
#include <gtest/gtest.h>

namespace {
  namespace core = platf::win_gamepad::lvh_core;
  using platf::win_gamepad::profile_kind_e;
}  // namespace

TEST(LibvirtualhidGamepadCoreTest, UsesCanonicalUsbPlaystationProfiles) {
  const auto dualshock4 = core::profile(profile_kind_e::dualshock4);
  const auto dualsense = core::profile(profile_kind_e::dualsense);

  EXPECT_EQ(dualshock4.vendor_id, 0x054C);
  EXPECT_EQ(dualshock4.product_id, 0x05C4);
  EXPECT_EQ(dualshock4.report_id, 0x01);
  EXPECT_EQ(dualshock4.input_size, 64U);
  EXPECT_EQ(dualshock4.output_size, 32U);
  EXPECT_TRUE(dualshock4.capabilities.motion);
  EXPECT_TRUE(dualshock4.capabilities.touchpad);

  EXPECT_EQ(dualsense.vendor_id, 0x054C);
  EXPECT_EQ(dualsense.product_id, 0x0CE6);
  EXPECT_EQ(dualsense.report_id, 0x01);
  EXPECT_EQ(dualsense.input_size, 64U);
  EXPECT_EQ(dualsense.output_size, 48U);
  EXPECT_TRUE(dualsense.capabilities.adaptive_triggers);
}

TEST(LibvirtualhidGamepadCoreTest, UsesWindowsEffectiveGenericAndXboxSeriesProfiles) {
  const auto generic = core::profile(profile_kind_e::generic);
  const auto xbox_series = core::profile(profile_kind_e::xbox_series);

  EXPECT_EQ(generic.output_size, 22U);
  EXPECT_EQ(generic.descriptor.size(), 1079U);
  EXPECT_EQ(xbox_series.version, 0x0509U);
}

TEST(LibvirtualhidGamepadCoreTest, PacksStableWindowsGenericVector) {
  auto profile = core::profile(profile_kind_e::generic);
  core::normalized_state_t state;
  state.buttons = core::button_bit(core::button_e::a) |
                  core::button_bit(core::button_e::start) |
                  core::button_bit(core::button_e::dpad_left);
  state.left_stick = {1.0F, -1.0F};
  state.right_stick = {0.5F, -0.5F};
  state.left_trigger = 0.25F;
  state.right_trigger = 1.0F;
  const std::vector<std::uint8_t> expected {
    0x01,
    0x81,
    0x40,
    0xFF,
    0xFF,
    0xBF,
    0xBF,
    0xBF,
    0x00,
  };

  EXPECT_EQ(core::pack(profile, state), expected);
}

TEST(LibvirtualhidGamepadCoreTest, PreservesAuxiliaryStateDuringFacadeConversion) {
  const auto profile = core::profile(profile_kind_e::dualsense);
  core::normalized_state_t state;
  state.buttons = core::button_bit(core::button_e::a);
  state.acceleration = core::vector3_t {1.0F, 2.0F, 3.0F};
  state.gyroscope = core::vector3_t {4.0F, 5.0F, 6.0F};
  state.battery = core::battery_t {core::battery_state_e::charging, 80};
  state.touchpad_contacts[0] = {.id = 3, .active = true, .x = 0.5F, .y = 0.25F};

  const auto report = core::pack(profile, state);

  ASSERT_EQ(report.size(), 64U);
  EXPECT_EQ(report[8] & 0x20, 0x20);
  EXPECT_NE(report[16] | report[17], 0);
  EXPECT_NE(report[22] | report[23], 0);
  EXPECT_EQ(report[33] & 0x7F, 3);
  EXPECT_EQ(report[33] & 0x80, 0);
  EXPECT_EQ(report[53] & 0x0F, 8);
  EXPECT_EQ(report[53] >> 4, 1);
}

TEST(LibvirtualhidGamepadCoreTest, RejectsMutatedProfileDefinitions) {
  core::normalized_state_t state;
  auto profile = core::profile(profile_kind_e::generic);
  ++profile.product_id;

  EXPECT_TRUE(core::pack(profile, state).empty());
  EXPECT_TRUE(core::parse_outputs(profile, {0x01, 0x00}).empty());
}

TEST(LibvirtualhidGamepadCoreTest, PreservesUnknownOutputAsRawEvent) {
  const auto profile = core::profile(profile_kind_e::xbox_one);
  const std::vector<std::uint8_t> report {0xFE, 0x01, 0x02, 0x03};

  const auto outputs = core::parse_outputs(profile, report);

  ASSERT_EQ(outputs.size(), 1U);
  EXPECT_EQ(outputs[0].kind, core::output_kind_e::raw_report);
  EXPECT_EQ(outputs[0].raw_report, report);
}

TEST(LibvirtualhidGamepadCoreTest, GenericPidFacadeSchedulesAndExpiresConstantForce) {
  core::generic_pid_rumble_t decoder;
  const auto started_at = core::generic_pid_rumble_t::time_point_t {} + std::chrono::seconds {1};
  const std::vector<std::uint8_t> set_effect {
    0x11,
    0x01,
    0x01,
    0x0A,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0xFF,
  };
  const std::vector<std::uint8_t> magnitude {0x15, 0x01, 0x10, 0x27};
  const std::vector<std::uint8_t> start {0x1A, 0x01, 0x01, 0x01};

  EXPECT_TRUE(decoder.handle_output_report(set_effect, started_at).recognized);
  EXPECT_TRUE(decoder.handle_output_report(magnitude, started_at).recognized);
  const auto active = decoder.handle_output_report(start, started_at);
  ASSERT_TRUE(active.recognized);
  EXPECT_TRUE(active.rumble_changed);
  EXPECT_EQ(active.strength, UINT16_MAX);
  ASSERT_TRUE(decoder.next_transition());
  EXPECT_EQ(*decoder.next_transition(), started_at + std::chrono::milliseconds {10});

  const auto expired = decoder.advance(started_at + std::chrono::milliseconds {10});
  EXPECT_TRUE(expired.recognized);
  EXPECT_TRUE(expired.rumble_changed);
  EXPECT_EQ(expired.strength, 0U);
  EXPECT_FALSE(decoder.next_transition());
}

TEST(LibvirtualhidGamepadCoreTest, GenericPidFacadeRejectsUnknownReport) {
  core::generic_pid_rumble_t decoder;
  const std::array<std::uint8_t, 2> unknown {0xFE, 0x00};

  const auto result = decoder.handle_output_report(unknown);

  EXPECT_FALSE(result.recognized);
  EXPECT_FALSE(result.rumble_changed);
  EXPECT_EQ(result.strength, 0U);
}

TEST(LibvirtualhidGamepadCoreTest, PublicHeaderExposesOnlyLumenOwnedTypes) {
  const auto header_path = std::filesystem::path {SUNSHINE_SOURCE_DIR} /
                           "src/platform/windows/libvirtualhid_gamepad_core.h";
  std::ifstream stream {header_path};
  ASSERT_TRUE(stream.is_open()) << header_path;
  const std::string contents {
    std::istreambuf_iterator<char> {stream},
    std::istreambuf_iterator<char> {},
  };

  EXPECT_EQ(contents.find("<libvirtualhid/"), std::string::npos);
  EXPECT_EQ(contents.find("lvh::"), std::string::npos);
  EXPECT_EQ(contents.find("Runtime"), std::string::npos);
  EXPECT_EQ(contents.find("Backend"), std::string::npos);
  EXPECT_EQ(contents.find("License"), std::string::npos);
}
