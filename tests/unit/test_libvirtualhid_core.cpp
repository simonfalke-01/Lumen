/**
 * @file tests/unit/test_libvirtualhid_core.cpp
 * @brief Integration tests for Lumen's portable libvirtualhid core target.
 */

// standard includes
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

// libvirtualhid includes
#include <libvirtualhid/profiles.hpp>
#include <libvirtualhid/report.hpp>
#include <libvirtualhid/types.hpp>

// third-party includes
#include <gtest/gtest.h>

namespace {
  /**
   * @brief Compute an FNV-1a fingerprint for a descriptor golden vector.
   *
   * @param bytes Descriptor bytes to fingerprint.
   * @return Stable 64-bit descriptor fingerprint.
   */
  std::uint64_t descriptor_fingerprint(std::span<const std::uint8_t> bytes) {
    auto result = UINT64_C(14695981039346656037);
    for (const auto byte : bytes) {
      result ^= byte;
      result *= UINT64_C(1099511628211);
    }
    return result;
  }

  /**
   * @brief Read a little-endian 16-bit value from a packed report.
   *
   * @param bytes Packed report bytes.
   * @param offset Offset of the value.
   * @return Decoded unsigned value.
   */
  std::uint16_t read_u16_le(std::span<const std::uint8_t> bytes, std::size_t offset) {
    return static_cast<std::uint16_t>(
      bytes[offset] | static_cast<std::uint16_t>(bytes[offset + 1U] << 8U)
    );
  }
}  // namespace

TEST(LibvirtualhidCoreTest, ExposesEverySupportedGamepadProfile) {
  using enum lvh::GamepadProfileKind;

  constexpr std::array supported_profiles {
    generic,
    xbox_360,
    xbox_one,
    xbox_series,
    dualsense,
    switch_pro,
    dualshock4,
  };

  const auto profiles = lvh::profiles::built_in_gamepad_profiles();
  ASSERT_EQ(profiles.size(), supported_profiles.size());

  for (const auto kind : supported_profiles) {
    const auto profile = lvh::profiles::gamepad_profile(kind);
    ASSERT_TRUE(profile.has_value());
    EXPECT_EQ(profile->device_type, lvh::DeviceType::gamepad);
    EXPECT_EQ(profile->gamepad_kind, kind);
    EXPECT_FALSE(profile->report_descriptor.empty());
    EXPECT_GT(profile->input_report_size, 0U);
  }

  EXPECT_FALSE(lvh::profiles::gamepad_profile(static_cast<lvh::GamepadProfileKind>(0xFF)).has_value());
}

TEST(LibvirtualhidCoreTest, PacksStableGenericInputVector) {
  lvh::GamepadState state;
  state.buttons.set(lvh::GamepadButton::a);
  state.buttons.set(lvh::GamepadButton::start);
  state.buttons.set(lvh::GamepadButton::dpad_left);
  state.left_stick = {.x = 1.0F, .y = -1.0F};
  state.right_stick = {.x = 0.5F, .y = -0.5F};
  state.left_trigger = 0.25F;
  state.right_trigger = 1.0F;

  constexpr std::array<std::uint8_t, 9> expected {
    0x01,
    0x81,
    0x40,
    0xFF,
    0xFF,
    0xBF,
    0xBF,
    0x40,
    0xFF,
  };
  const auto report = lvh::reports::pack_input_report(lvh::profiles::generic_gamepad(), state);

  EXPECT_EQ(report, std::vector<std::uint8_t>(expected.begin(), expected.end()));
}

TEST(LibvirtualhidCoreTest, PreservesOutputVectorAcrossParsingBoundary) {
  const auto profile = lvh::profiles::xbox_360();
  const std::vector<std::uint8_t> wire_report {
    profile.report_id,
    0x34,
    0x12,
    0xCD,
    0xAB,
  };

  const auto output = lvh::reports::parse_output_report(profile, wire_report);

  EXPECT_EQ(output.kind, lvh::GamepadOutputKind::rumble);
  EXPECT_EQ(output.low_frequency_rumble, 0x1234);
  EXPECT_EQ(output.high_frequency_rumble, 0xABCD);
  EXPECT_EQ(output.raw_report, wire_report);
}

TEST(LibvirtualhidCoreTest, UsesUsbFramingForWindowsPlayStationProfiles) {
  const auto dualshock4 = lvh::profiles::dualshock4_usb();
  const auto dualsense = lvh::profiles::dualsense_usb();

  EXPECT_EQ(dualshock4.gamepad_kind, lvh::GamepadProfileKind::dualshock4);
  EXPECT_EQ(dualshock4.bus_type, lvh::BusType::usb);
  EXPECT_EQ(dualshock4.report_id, 0x01);
  EXPECT_EQ(dualshock4.input_report_size, 64U);

  EXPECT_EQ(dualsense.gamepad_kind, lvh::GamepadProfileKind::dualsense);
  EXPECT_EQ(dualsense.bus_type, lvh::BusType::usb);
  EXPECT_EQ(dualsense.report_id, 0x01);
  EXPECT_EQ(dualsense.input_report_size, 64U);
}

TEST(LibvirtualhidCoreTest, KeepsExactBuiltInProfileIdentityVectors) {
  struct profile_vector_t {
    std::string_view name;
    lvh::DeviceProfile profile;
    lvh::BusType bus;
    std::uint16_t vendor_id;
    std::uint16_t product_id;
    std::uint16_t version;
    std::uint8_t report_id;
    std::size_t input_size;
    std::size_t output_size;
  };

  const std::array vectors {
    profile_vector_t {"generic", lvh::profiles::generic_gamepad(), lvh::BusType::usb, 0x1209, 0x0001, 0x0001, 0x01, 9, 9},
    profile_vector_t {"xbox-360", lvh::profiles::xbox_360(), lvh::BusType::usb, 0x045E, 0x028E, 0x0114, 0x01, 9, 5},
    profile_vector_t {"xbox-one", lvh::profiles::xbox_one(), lvh::BusType::usb, 0x045E, 0x02EA, 0x0408, 0x00, 17, 8},
    profile_vector_t {"xbox-series", lvh::profiles::xbox_series(), lvh::BusType::usb, 0x045E, 0x0B12, 0x0500, 0x00, 17, 8},
    profile_vector_t {"dualshock4-usb", lvh::profiles::dualshock4_usb(), lvh::BusType::usb, 0x054C, 0x05C4, 0x0100, 0x01, 64, 32},
    profile_vector_t {"dualshock4-bluetooth", lvh::profiles::dualshock4_bluetooth(), lvh::BusType::bluetooth, 0x054C, 0x05C4, 0x0100, 0x11, 78, 78},
    profile_vector_t {"dualsense-usb", lvh::profiles::dualsense_usb(), lvh::BusType::usb, 0x054C, 0x0CE6, 0x8111, 0x01, 64, 48},
    profile_vector_t {"dualsense-bluetooth", lvh::profiles::dualsense_bluetooth(), lvh::BusType::bluetooth, 0x054C, 0x0CE6, 0x8111, 0x31, 78, 78},
    profile_vector_t {"switch-pro", lvh::profiles::switch_pro(), lvh::BusType::usb, 0x057E, 0x2009, 0x8111, 0x30, 64, 64},
  };

  for (const auto &vector : vectors) {
    SCOPED_TRACE(vector.name);
    EXPECT_EQ(vector.profile.device_type, lvh::DeviceType::gamepad);
    EXPECT_EQ(vector.profile.bus_type, vector.bus);
    EXPECT_EQ(vector.profile.vendor_id, vector.vendor_id);
    EXPECT_EQ(vector.profile.product_id, vector.product_id);
    EXPECT_EQ(vector.profile.version, vector.version);
    EXPECT_EQ(vector.profile.report_id, vector.report_id);
    EXPECT_EQ(vector.profile.input_report_size, vector.input_size);
    EXPECT_EQ(vector.profile.output_report_size, vector.output_size);
  }
}

TEST(LibvirtualhidCoreTest, KeepsExactBuiltInDescriptorVectors) {
  struct descriptor_vector_t {
    std::string_view name;
    lvh::DeviceProfile profile;
    std::size_t size;
    std::uint64_t fingerprint;
  };

  const std::array vectors {
    descriptor_vector_t {"generic", lvh::profiles::generic_gamepad(), 111, UINT64_C(0x51674B6EC7BA181D)},
    descriptor_vector_t {"xbox-360", lvh::profiles::xbox_360(), 113, UINT64_C(0x8AF81CE94B527914)},
    descriptor_vector_t {"xbox-one", lvh::profiles::xbox_one(), 262, UINT64_C(0x3DFA54DB4A381D9C)},
    descriptor_vector_t {"xbox-series", lvh::profiles::xbox_series(), 262, UINT64_C(0x2F9C9FECE78B8376)},
    descriptor_vector_t {"dualshock4-usb", lvh::profiles::dualshock4_usb(), 467, UINT64_C(0xAC9684BB5D52886A)},
    descriptor_vector_t {"dualshock4-bluetooth", lvh::profiles::dualshock4_bluetooth(), 142, UINT64_C(0x8739F514EA2FAE23)},
    descriptor_vector_t {"dualsense-usb", lvh::profiles::dualsense_usb(), 273, UINT64_C(0x1DD683F6E486F236)},
    descriptor_vector_t {"dualsense-bluetooth", lvh::profiles::dualsense_bluetooth(), 279, UINT64_C(0xA205337669563449)},
    descriptor_vector_t {"switch-pro", lvh::profiles::switch_pro(), 203, UINT64_C(0x5595265A51347CD)},
  };

  for (const auto &vector : vectors) {
    SCOPED_TRACE(vector.name);
    EXPECT_EQ(vector.profile.report_descriptor.size(), vector.size);
    EXPECT_EQ(descriptor_fingerprint(vector.profile.report_descriptor), vector.fingerprint);
  }
}

TEST(LibvirtualhidCoreTest, PacksExactXboxSeriesInputVector) {
  using enum lvh::GamepadButton;

  lvh::GamepadState state;
  state.buttons.set(a);
  state.buttons.set(start);
  state.buttons.set(dpad_left);
  state.buttons.set(guide);
  state.buttons.set(misc1);
  state.left_stick = {1.0F, -1.0F};
  state.right_stick = {0.5F, -0.5F};
  state.left_trigger = 0.25F;
  state.right_trigger = 1.0F;
  state.battery = lvh::GamepadBattery {.state = lvh::GamepadBatteryState::discharging, .percentage = 80};

  const auto report = lvh::reports::pack_input_report(lvh::profiles::xbox_series(), state);
  ASSERT_EQ(report.size(), 17U);
  EXPECT_EQ(read_u16_le(report, 0), 0xFFFF);
  EXPECT_EQ(read_u16_le(report, 2), 0xFFFF);
  EXPECT_EQ(read_u16_le(report, 4), 0xBFFF);
  EXPECT_EQ(read_u16_le(report, 6), 0xBFFF);
  EXPECT_EQ(read_u16_le(report, 8), 256);
  EXPECT_EQ(read_u16_le(report, 10), 1023);
  EXPECT_EQ(read_u16_le(report, 12), 0x0881);
  EXPECT_EQ(report[14], 7);
  EXPECT_EQ(report[15], 1);
  EXPECT_EQ(report[16], 204);
}

TEST(LibvirtualhidCoreTest, PacksExactSwitchProInputVector) {
  using enum lvh::GamepadButton;

  lvh::GamepadState state;
  state.buttons.set(a);
  state.buttons.set(b);
  state.buttons.set(start);
  state.buttons.set(guide);
  state.buttons.set(misc1);
  state.buttons.set(dpad_left);
  state.left_stick = {1.0F, -1.0F};
  state.right_stick = {0.5F, -0.5F};
  state.left_trigger = 0.25F;

  const auto report = lvh::reports::pack_input_report(lvh::profiles::switch_pro(), state);
  const std::array<std::uint8_t, 12> expected_prefix {
    0x30,
    0x00,
    0x81,
    0x0C,
    0x32,
    0x88,
    0xFF,
    0x0F,
    0x00,
    0xFF,
    0x0B,
    0x40,
  };

  ASSERT_EQ(report.size(), 64U);
  EXPECT_TRUE(std::ranges::equal(expected_prefix, std::span {report}.first(expected_prefix.size())));
}

TEST(LibvirtualhidCoreTest, PacksDualSenseAuxiliaryStateWithoutDiscardingButtons) {
  lvh::GamepadState state;
  state.buttons.set(lvh::GamepadButton::a);
  state.buttons.set(lvh::GamepadButton::left_shoulder);
  state.acceleration = lvh::Vector3 {.x = 1.0F, .y = 2.0F, .z = 3.0F};
  state.gyroscope = lvh::Vector3 {.x = 4.0F, .y = 5.0F, .z = 6.0F};
  state.battery = lvh::GamepadBattery {.state = lvh::GamepadBatteryState::charging, .percentage = 80};
  state.touchpad_contacts[0] = {.id = 3, .active = true, .x = 0.5F, .y = 0.25F};

  const auto report = lvh::reports::pack_input_report(lvh::profiles::dualsense_usb(), state);

  ASSERT_EQ(report.size(), 64U);
  EXPECT_EQ(report[8] & 0x20, 0x20);
  EXPECT_NE(read_u16_le(report, 16), 0);
  EXPECT_NE(read_u16_le(report, 22), 0);
  EXPECT_EQ(report[33] & 0x7F, 3);
  EXPECT_EQ(report[33] & 0x80, 0);
  EXPECT_EQ(report[53] & 0x0F, 8);
  EXPECT_EQ(report[53] >> 4, 1);
}

TEST(LibvirtualhidCoreTest, ParsesXboxMotorAndTriggerRumbleVector) {
  const std::vector<std::uint8_t> report {0x0F, 25, 50, 75, 100, 10, 0, 0};

  const auto outputs = lvh::reports::parse_output_reports(lvh::profiles::xbox_series(), report);

  ASSERT_EQ(outputs.size(), 2U);
  EXPECT_EQ(outputs[0].kind, lvh::GamepadOutputKind::rumble);
  EXPECT_EQ(outputs[0].low_frequency_rumble, 49151U);
  EXPECT_EQ(outputs[0].high_frequency_rumble, 65535U);
  EXPECT_EQ(outputs[1].kind, lvh::GamepadOutputKind::trigger_rumble);
  EXPECT_EQ(outputs[1].left_trigger_rumble, 16384U);
  EXPECT_EQ(outputs[1].right_trigger_rumble, 32768U);
}

TEST(LibvirtualhidCoreTest, KeepsMalformedOutputAsOneRawEvent) {
  const std::vector<std::uint8_t> report {0x0F, 25, 50};

  const auto outputs = lvh::reports::parse_output_reports(lvh::profiles::xbox_series(), report);

  ASSERT_EQ(outputs.size(), 1U);
  EXPECT_EQ(outputs[0].kind, lvh::GamepadOutputKind::raw_report);
  EXPECT_EQ(outputs[0].raw_report, report);
}
