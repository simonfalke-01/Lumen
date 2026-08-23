/**
 * @file tests/unit/platform/windows/test_dynamic_gamepad_profiles.cpp
 * @brief Golden parity tests for Lumen's trusted driver-side gamepad profiles.
 */

// standard includes
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

// local includes
#include <src/platform/windows/virtual_hid_driver/DynamicGamepadProfiles.c>

// libvirtualhid includes
#include <libvirtualhid/profiles.hpp>
#include <libvirtualhid/report.hpp>

// upstream Windows-effective profile helpers
#include <third-party/libvirtualhid/src/platform/windows/shared/generic_pid_protocol.hpp>

// third-party includes
#include <gtest/gtest.h>

namespace {
  using profile_factory_t = lvh::DeviceProfile (*)();

  struct profile_parity_vector_t {
    std::string_view name;
    std::uint32_t driver_kind;
    profile_factory_t core_factory;
  };

  const std::array profile_vectors {
    profile_parity_vector_t {"generic", LUMEN_VHID_GAMEPAD_PROFILE_GENERIC, lvh::profiles::generic_gamepad},
    profile_parity_vector_t {"xbox-one", LUMEN_VHID_GAMEPAD_PROFILE_XBOX_ONE, lvh::profiles::xbox_one},
    profile_parity_vector_t {"xbox-series", LUMEN_VHID_GAMEPAD_PROFILE_XBOX_SERIES, lvh::profiles::xbox_series},
    profile_parity_vector_t {"dualsense-usb", LUMEN_VHID_GAMEPAD_PROFILE_DUALSENSE, lvh::profiles::dualsense_usb},
    profile_parity_vector_t {"switch-pro", LUMEN_VHID_GAMEPAD_PROFILE_SWITCH_PRO, lvh::profiles::switch_pro},
    profile_parity_vector_t {"dualshock4-usb", LUMEN_VHID_GAMEPAD_PROFILE_DUALSHOCK4, lvh::profiles::dualshock4_usb},
  };
}  // namespace

TEST(DynamicGamepadProfilesTest, SupportedBitmapIncludesOnlyDynamicVhfProfiles) {
  constexpr auto expected =
    LUMEN_VHID_GAMEPAD_PROFILE_BIT(LUMEN_VHID_GAMEPAD_PROFILE_GENERIC) |
    LUMEN_VHID_GAMEPAD_PROFILE_BIT(LUMEN_VHID_GAMEPAD_PROFILE_XBOX_ONE) |
    LUMEN_VHID_GAMEPAD_PROFILE_BIT(LUMEN_VHID_GAMEPAD_PROFILE_XBOX_SERIES) |
    LUMEN_VHID_GAMEPAD_PROFILE_BIT(LUMEN_VHID_GAMEPAD_PROFILE_DUALSENSE) |
    LUMEN_VHID_GAMEPAD_PROFILE_BIT(LUMEN_VHID_GAMEPAD_PROFILE_SWITCH_PRO) |
    LUMEN_VHID_GAMEPAD_PROFILE_BIT(LUMEN_VHID_GAMEPAD_PROFILE_DUALSHOCK4);

  EXPECT_EQ(LumenVhidGamepadSupportedProfiles(), expected);
  EXPECT_EQ(
    LumenVhidGamepadSupportedProfiles() &
      LUMEN_VHID_GAMEPAD_PROFILE_BIT(LUMEN_VHID_GAMEPAD_PROFILE_XBOX_360_RESERVED),
    0U
  );
}

TEST(DynamicGamepadProfilesTest, RejectsReservedAndUnknownProfiles) {
  EXPECT_EQ(LumenVhidGamepadProfileLookup(LUMEN_VHID_GAMEPAD_PROFILE_XBOX_360_RESERVED), nullptr);
  EXPECT_EQ(LumenVhidGamepadProfileLookup(LUMEN_VHID_GAMEPAD_PROFILE_COUNT), nullptr);
  EXPECT_EQ(LumenVhidGamepadProfileLookup(UINT32_MAX), nullptr);
}

TEST(DynamicGamepadProfilesTest, MatchesPortableCoreIdentityAndReportSizes) {
  for (const auto &vector : profile_vectors) {
    SCOPED_TRACE(vector.name);
    const auto *driver = LumenVhidGamepadProfileLookup(vector.driver_kind);
    const auto core = vector.core_factory();
    ASSERT_NE(driver, nullptr);
    EXPECT_EQ(driver->kind, vector.driver_kind);
    EXPECT_EQ(driver->vendor_id, core.vendor_id);
    EXPECT_EQ(driver->product_id, core.product_id);
    const auto expected_version =
      vector.driver_kind == LUMEN_VHID_GAMEPAD_PROFILE_XBOX_SERIES ? 0x0509U : core.version;
    const auto expected_output_size =
      vector.driver_kind == LUMEN_VHID_GAMEPAD_PROFILE_GENERIC ?
        lvh::detail::windows::generic_pid_output_report_size :
        core.output_report_size;
    EXPECT_EQ(driver->version_number, expected_version);
    EXPECT_EQ(driver->input_report_id, core.report_id);
    EXPECT_EQ(driver->input_report_size, core.input_report_size);
    EXPECT_EQ(driver->output_report_size, expected_output_size);
    EXPECT_EQ(driver->reserved, 0U);
  }
}

TEST(DynamicGamepadProfilesTest, MatchesPortableCoreDescriptorBytes) {
  for (const auto &vector : profile_vectors) {
    SCOPED_TRACE(vector.name);
    const auto *driver = LumenVhidGamepadProfileLookup(vector.driver_kind);
    const auto core = vector.core_factory();
    ASSERT_NE(driver, nullptr);
    ASSERT_NE(driver->report_descriptor, nullptr);
    const auto expected = vector.driver_kind == LUMEN_VHID_GAMEPAD_PROFILE_GENERIC ?
                            lvh::detail::windows::make_generic_pid_report_descriptor(core.report_descriptor) :
                            core.report_descriptor;
    ASSERT_EQ(driver->report_descriptor_size, expected.size());
    EXPECT_TRUE(std::ranges::equal(std::span {driver->report_descriptor, driver->report_descriptor_size}, expected));
  }
}

TEST(DynamicGamepadProfilesTest, UsesWindowsDirectInputTriggerPolarityForGenericProfile) {
  lvh::GamepadState state;
  state.left_trigger = 0.25F;
  state.right_trigger = 1.0F;
  const auto portable = lvh::reports::pack_input_report(lvh::profiles::generic_gamepad(), state);

  const auto windows = lvh::detail::windows::make_generic_windows_input_report(portable);

  ASSERT_EQ(portable.size(), 9U);
  ASSERT_EQ(windows.size(), portable.size());
  EXPECT_EQ(portable[7], 64U);
  EXPECT_EQ(portable[8], 255U);
  EXPECT_EQ(windows[7], 191U);
  EXPECT_EQ(windows[8], 0U);
}
