/**
 * @file tests/unit/platform/windows/test_virtual_hid_gamepad_protocol.cpp
 * @brief Test the versioned Lumen dynamic-gamepad control ABI.
 */

// standard includes
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <type_traits>

// local includes
#include <src/platform/windows/virtual_hid_protocol.h>

// third-party includes
#include <gtest/gtest.h>

TEST(VirtualHidGamepadProtocolTest, KeepsBaseAndGamepadAbiVersionsIndependent) {
  EXPECT_EQ(LUMEN_VHID_ABI_VERSION, 2U);
  EXPECT_EQ(LUMEN_VHID_GAMEPAD_ABI_VERSION, 1U);
}

TEST(VirtualHidGamepadProtocolTest, ReservesXbox360ForVigem) {
  EXPECT_EQ(LUMEN_VHID_GAMEPAD_PROFILE_XBOX_360_RESERVED, 1U);
  EXPECT_EQ(LUMEN_VHID_GAMEPAD_PROFILE_COUNT, 7U);
  EXPECT_EQ(
    LUMEN_VHID_GAMEPAD_PROFILE_BIT(LUMEN_VHID_GAMEPAD_PROFILE_XBOX_360_RESERVED),
    UINT64_C(0x2)
  );
}

TEST(VirtualHidGamepadProtocolTest, LimitsDynamicDevicesAndReports) {
  EXPECT_EQ(LUMEN_VHID_MAX_GAMEPADS, 16U);
  EXPECT_EQ(LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE, 256U);
  EXPECT_EQ(LUMEN_VHID_GAMEPAD_SESSION_TOKEN_SIZE, 32U);
}

TEST(VirtualHidGamepadProtocolTest, UsesExactAuthenticatedHandleLayout) {
  EXPECT_EQ(sizeof(LUMEN_VHID_GAMEPAD_HANDLE), 48U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_HANDLE, device_id), 0U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_HANDLE, generation), 8U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_HANDLE, session_token), 16U);
}

TEST(VirtualHidGamepadProtocolTest, UsesExactCapabilitiesLayout) {
  EXPECT_EQ(sizeof(LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE), 40U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE, version), 0U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE, capability_flags), 12U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE, supported_profiles), 16U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE, max_devices), 24U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE, max_output_report_size), 36U);
}

TEST(VirtualHidGamepadProtocolTest, UsesExactCreateLayouts) {
  EXPECT_EQ(sizeof(LUMEN_VHID_GAMEPAD_CREATE_REQUEST), 24U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_CREATE_REQUEST, client_device_id), 8U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_CREATE_REQUEST, profile), 16U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_CREATE_REQUEST, reserved), 20U);

  EXPECT_EQ(sizeof(LUMEN_VHID_GAMEPAD_CREATE_RESPONSE), 80U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_CREATE_RESPONSE, handle), 8U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_CREATE_RESPONSE, profile), 56U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_CREATE_RESPONSE, feature_flags), 60U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_CREATE_RESPONSE, reserved0), 71U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_CREATE_RESPONSE, output_report_size), 76U);
}

TEST(VirtualHidGamepadProtocolTest, UsesExactAuthenticatedOperationLayouts) {
  EXPECT_EQ(sizeof(LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST), 56U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST, handle), 8U);

  EXPECT_EQ(sizeof(LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST), 320U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST, handle), 8U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST, report_size), 56U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST, reserved), 60U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST, report), 64U);

  EXPECT_EQ(sizeof(LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE), 320U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE, handle), 8U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE, report_size), 56U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE, reserved), 60U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE, report), 64U);
}

TEST(VirtualHidGamepadProtocolTest, UsesDistinctBufferedIoctls) {
  const std::uint32_t ioctls[] {
    IOCTL_LUMEN_VHID_GAMEPAD_GET_CAPABILITIES,
    IOCTL_LUMEN_VHID_GAMEPAD_CREATE,
    IOCTL_LUMEN_VHID_GAMEPAD_DESTROY,
    IOCTL_LUMEN_VHID_GAMEPAD_SUBMIT_REPORT,
    IOCTL_LUMEN_VHID_GAMEPAD_READ_OUTPUT,
    IOCTL_LUMEN_VHID_GAMEPAD_RESET_RUNTIME,
  };

  for (std::size_t index = 0; index < std::size(ioctls); ++index) {
    EXPECT_EQ(ioctls[index] & 3U, METHOD_BUFFERED);
    for (std::size_t other = index + 1U; other < std::size(ioctls); ++other) {
      EXPECT_NE(ioctls[index], ioctls[other]);
    }
  }
}

TEST(VirtualHidGamepadProtocolTest, KeepsExtensionMessagesTriviallyCopyable) {
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VHID_GAMEPAD_HANDLE>);
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE>);
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VHID_GAMEPAD_CREATE_REQUEST>);
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VHID_GAMEPAD_CREATE_RESPONSE>);
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST>);
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST>);
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE>);
}
