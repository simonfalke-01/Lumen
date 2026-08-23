/**
 * @file tests/unit/platform/windows/test_dynamic_gamepad_validation.cpp
 * @brief Test portable validation primitives used by the dynamic-gamepad driver.
 */

// standard includes
#include <array>
#include <cstddef>
#include <cstdint>

// local includes
#include <src/platform/windows/virtual_hid_driver/DynamicGamepadValidation.h>

// third-party includes
#include <gtest/gtest.h>

TEST(DynamicGamepadValidationTest, AcceptsOnlyCurrentExactRequestHeader) {
  EXPECT_TRUE(LumenVhidGamepadValidHeader(
    LUMEN_VHID_GAMEPAD_ABI_VERSION,
    sizeof(LUMEN_VHID_GAMEPAD_CREATE_REQUEST),
    sizeof(LUMEN_VHID_GAMEPAD_CREATE_REQUEST)
  ));
  EXPECT_FALSE(LumenVhidGamepadValidHeader(
    LUMEN_VHID_GAMEPAD_ABI_VERSION + 1U,
    sizeof(LUMEN_VHID_GAMEPAD_CREATE_REQUEST),
    sizeof(LUMEN_VHID_GAMEPAD_CREATE_REQUEST)
  ));
  EXPECT_FALSE(LumenVhidGamepadValidHeader(
    LUMEN_VHID_GAMEPAD_ABI_VERSION,
    sizeof(LUMEN_VHID_GAMEPAD_CREATE_REQUEST) - 1U,
    sizeof(LUMEN_VHID_GAMEPAD_CREATE_REQUEST)
  ));
  EXPECT_FALSE(LumenVhidGamepadValidHeader(
    LUMEN_VHID_GAMEPAD_ABI_VERSION,
    sizeof(LUMEN_VHID_GAMEPAD_CREATE_REQUEST) + 1U,
    sizeof(LUMEN_VHID_GAMEPAD_CREATE_REQUEST)
  ));
}

TEST(DynamicGamepadValidationTest, CreateRejectsNonzeroReservedField) {
  LUMEN_VHID_GAMEPAD_CREATE_REQUEST request {};
  request.version = LUMEN_VHID_GAMEPAD_ABI_VERSION;
  request.size = sizeof(request);
  request.profile = LUMEN_VHID_GAMEPAD_PROFILE_GENERIC;
  EXPECT_TRUE(LumenVhidGamepadValidCreateRequest(&request));

  request.reserved = 1;

  EXPECT_FALSE(LumenVhidGamepadValidCreateRequest(&request));
}

TEST(DynamicGamepadValidationTest, CreateRejectsReservedAndUnknownProfiles) {
  LUMEN_VHID_GAMEPAD_CREATE_REQUEST request {};
  request.version = LUMEN_VHID_GAMEPAD_ABI_VERSION;
  request.size = sizeof(request);
  request.profile = LUMEN_VHID_GAMEPAD_PROFILE_XBOX_360_RESERVED;
  EXPECT_FALSE(LumenVhidGamepadValidCreateRequest(&request));

  request.profile = LUMEN_VHID_GAMEPAD_PROFILE_COUNT;
  EXPECT_FALSE(LumenVhidGamepadValidCreateRequest(&request));
  request.profile = UINT32_MAX;
  EXPECT_FALSE(LumenVhidGamepadValidCreateRequest(&request));
  EXPECT_FALSE(LumenVhidGamepadValidCreateRequest(nullptr));
}

TEST(DynamicGamepadValidationTest, SubmitRejectsNonzeroReservedField) {
  LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST request {};
  request.version = LUMEN_VHID_GAMEPAD_ABI_VERSION;
  request.size = sizeof(request);
  request.report_size = 1;
  EXPECT_TRUE(LumenVhidGamepadValidSubmitRequestHeader(&request));

  request.reserved = 1;

  EXPECT_FALSE(LumenVhidGamepadValidSubmitRequestHeader(&request));
}

TEST(DynamicGamepadValidationTest, SubmitRejectsEmptyAndOversizedReports) {
  LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST request {};
  request.version = LUMEN_VHID_GAMEPAD_ABI_VERSION;
  request.size = sizeof(request);
  request.report_size = 0;
  EXPECT_FALSE(LumenVhidGamepadValidSubmitRequestHeader(&request));

  request.report_size = LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE + 1U;
  EXPECT_FALSE(LumenVhidGamepadValidSubmitRequestHeader(&request));
  EXPECT_FALSE(LumenVhidGamepadValidSubmitRequestHeader(nullptr));
}

TEST(DynamicGamepadValidationTest, AcceptsOnlyExactSessionToken) {
  std::array<std::uint8_t, LUMEN_VHID_GAMEPAD_SESSION_TOKEN_SIZE> expected {};
  for (std::size_t index = 0; index < expected.size(); ++index) {
    expected[index] = static_cast<std::uint8_t>(index + 1U);
  }
  auto wrong = expected;
  wrong.front() ^= 0x80;

  EXPECT_TRUE(LumenVhidGamepadTokenEqual(expected.data(), expected.data()));
  EXPECT_FALSE(LumenVhidGamepadTokenEqual(expected.data(), wrong.data()));
  EXPECT_FALSE(LumenVhidGamepadTokenEqual(nullptr, expected.data()));
  EXPECT_FALSE(LumenVhidGamepadTokenEqual(expected.data(), nullptr));
}

TEST(DynamicGamepadValidationTest, AcceptsOnlyExactNumberedInputReport) {
  LUMEN_VHID_GAMEPAD_PROFILE profile {};
  profile.input_report_id = 0x30;
  profile.input_report_size = 64;
  std::array<std::uint8_t, 64> report {};
  report[0] = 0x30;

  EXPECT_TRUE(LumenVhidGamepadValidInputReport(&profile, report.data(), report.size()));
  report[0] = 0x31;
  EXPECT_FALSE(LumenVhidGamepadValidInputReport(&profile, report.data(), report.size()));
  report[0] = 0x30;
  EXPECT_FALSE(LumenVhidGamepadValidInputReport(&profile, report.data(), report.size() - 1U));
  EXPECT_FALSE(LumenVhidGamepadValidInputReport(&profile, report.data(), report.size() + 1U));
  EXPECT_FALSE(LumenVhidGamepadValidInputReport(&profile, nullptr, report.size()));
  EXPECT_FALSE(LumenVhidGamepadValidInputReport(nullptr, report.data(), report.size()));
}

TEST(DynamicGamepadValidationTest, AcceptsUnnumberedInputReportWithoutSyntheticId) {
  LUMEN_VHID_GAMEPAD_PROFILE profile {};
  profile.input_report_id = 0;
  profile.input_report_size = 17;
  std::array<std::uint8_t, 17> report {};
  report[0] = 0xFF;

  EXPECT_TRUE(LumenVhidGamepadValidInputReport(&profile, report.data(), report.size()));
}
