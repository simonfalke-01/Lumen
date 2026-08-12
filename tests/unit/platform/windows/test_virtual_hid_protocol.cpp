/**
 * @file tests/unit/platform/windows/test_virtual_hid_protocol.cpp
 * @brief Test the host-buildable Lumen Virtual HID protocol contract.
 */
#include <gtest/gtest.h>

// local includes
#include <src/platform/windows/virtual_hid_protocol.h>

// standard includes
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>

namespace {
  /**
   * @brief Build a valid protocol message header for one fixed-size operation.
   *
   * @param operation Protocol operation identifier.
   * @param total_size Complete operation structure size.
   * @param minor Protocol minor version.
   * @return Populated protocol message header.
   */
  LUMEN_VHID_MESSAGE_HEADER valid_header(
    std::uint16_t operation,
    std::size_t total_size,
    std::uint16_t minor = LUMEN_VHID_PROTOCOL_MINOR
  ) {
    return {
      LUMEN_VHID_PROTOCOL_MAGIC,
      LUMEN_VHID_PROTOCOL_MAJOR,
      minor,
      sizeof(LUMEN_VHID_MESSAGE_HEADER),
      operation,
      static_cast<std::uint32_t>(total_size),
      0
    };
  }

  /**
   * @brief Valid report metadata case.
   */
  struct report_metadata_case_t {
    std::uint16_t device_kind;  ///< Protocol device kind.
    std::uint16_t report_id;  ///< HID report identifier.
    std::uint16_t payload_size;  ///< Complete HID report size.
  };

  /**
   * @brief Parameterized fixture for valid report metadata tuples.
   */
  class valid_report_metadata_test: public testing::TestWithParam<report_metadata_case_t> {};
}  // namespace

TEST(VirtualHidProtocolTest, UsesFrozenMessageHeaderLayout) {
  EXPECT_EQ(sizeof(LUMEN_VHID_MESSAGE_HEADER), 20);
  EXPECT_EQ(offsetof(LUMEN_VHID_MESSAGE_HEADER, magic), 0);
  EXPECT_EQ(offsetof(LUMEN_VHID_MESSAGE_HEADER, protocol_major), 4);
  EXPECT_EQ(offsetof(LUMEN_VHID_MESSAGE_HEADER, protocol_minor), 6);
  EXPECT_EQ(offsetof(LUMEN_VHID_MESSAGE_HEADER, header_size), 8);
  EXPECT_EQ(offsetof(LUMEN_VHID_MESSAGE_HEADER, operation), 10);
  EXPECT_EQ(offsetof(LUMEN_VHID_MESSAGE_HEADER, total_size), 12);
  EXPECT_EQ(offsetof(LUMEN_VHID_MESSAGE_HEADER, flags), 16);
}

TEST(VirtualHidProtocolTest, UsesFrozenControlStructureLayouts) {
  EXPECT_EQ(sizeof(LUMEN_VHID_GET_CAPABILITIES_REQUEST), 20);
  EXPECT_EQ(sizeof(LUMEN_VHID_GET_CAPABILITIES_RESPONSE), 72);
  EXPECT_EQ(sizeof(LUMEN_VHID_CLAIM_SESSION_REQUEST), 40);
  EXPECT_EQ(sizeof(LUMEN_VHID_CLAIM_SESSION_RESPONSE), 40);
  EXPECT_EQ(sizeof(LUMEN_VHID_SESSION_REQUEST), 32);
  EXPECT_EQ(sizeof(LUMEN_VHID_SESSION_RESPONSE), 40);
  EXPECT_EQ(sizeof(LUMEN_VHID_SUBMIT_REPORT_REQUEST), 560);
  EXPECT_EQ(sizeof(LUMEN_VHID_SUBMIT_REPORT_RESPONSE), 40);
  EXPECT_EQ(offsetof(LUMEN_VHID_SUBMIT_REPORT_REQUEST, payload), 48);
}

TEST(VirtualHidProtocolTest, UsesFrozenReportLayouts) {
  EXPECT_EQ(sizeof(LUMEN_VHID_KEYBOARD_REPORT), 30);
  EXPECT_EQ(sizeof(LUMEN_VHID_RELATIVE_MOUSE_REPORT), 10);
  EXPECT_EQ(sizeof(LUMEN_VHID_ABSOLUTE_MOUSE_REPORT), 10);
  EXPECT_EQ(offsetof(LUMEN_VHID_KEYBOARD_REPORT, key_bitmap), 2);
  EXPECT_EQ(offsetof(LUMEN_VHID_RELATIVE_MOUSE_REPORT, x), 2);
  EXPECT_EQ(offsetof(LUMEN_VHID_ABSOLUTE_MOUSE_REPORT, x), 2);
}

TEST(VirtualHidProtocolTest, KeepsSharedStructuresTriviallyCopyable) {
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VHID_MESSAGE_HEADER>);
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VHID_GET_CAPABILITIES_RESPONSE>);
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VHID_CLAIM_SESSION_REQUEST>);
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VHID_SESSION_REQUEST>);
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VHID_SUBMIT_REPORT_REQUEST>);
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VHID_KEYBOARD_REPORT>);
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VHID_RELATIVE_MOUSE_REPORT>);
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VHID_ABSOLUTE_MOUSE_REPORT>);
}

TEST(VirtualHidProtocolTest, KeepsAllControlOperationsMethodBuffered) {
  constexpr std::array<std::uint32_t, 5> ioctls {
    IOCTL_LUMEN_VHID_GET_PROTOCOL_CAPABILITIES,
    IOCTL_LUMEN_VHID_CLAIM_INPUT_SESSION,
    IOCTL_LUMEN_VHID_SUBMIT_INPUT_REPORT,
    IOCTL_LUMEN_VHID_RESET_INPUT_SESSION,
    IOCTL_LUMEN_VHID_RELEASE_INPUT_SESSION
  };

  for (const auto ioctl : ioctls) {
    EXPECT_EQ(ioctl & 3U, METHOD_BUFFERED);
  }
}

TEST(VirtualHidProtocolTest, KeepsControlAndReportSizesWithinFrozenLimits) {
  EXPECT_EQ(LUMEN_VHID_MAX_CONTROL_SIZE, 4096);
  EXPECT_EQ(LUMEN_VHID_MAX_REPORT_PAYLOAD, 512);
  EXPECT_LE(sizeof(LUMEN_VHID_SUBMIT_REPORT_REQUEST), LUMEN_VHID_MAX_CONTROL_SIZE);
  EXPECT_LE(sizeof(LUMEN_VHID_KEYBOARD_REPORT), LUMEN_VHID_MAX_REPORT_PAYLOAD);
  EXPECT_LE(sizeof(LUMEN_VHID_RELATIVE_MOUSE_REPORT), LUMEN_VHID_MAX_REPORT_PAYLOAD);
  EXPECT_LE(sizeof(LUMEN_VHID_ABSOLUTE_MOUSE_REPORT), LUMEN_VHID_MAX_REPORT_PAYLOAD);
}

TEST(VirtualHidProtocolTest, AddsCheckedSizesWithoutOverflow) {
  std::size_t result = 0;

  ASSERT_TRUE(lumen_vhid_checked_add_size(48, 512, &result));
  EXPECT_EQ(result, 560);
}

TEST(VirtualHidProtocolTest, RejectsCheckedSizeOverflow) {
  std::size_t result = 123;

  EXPECT_FALSE(lumen_vhid_checked_add_size(std::numeric_limits<std::size_t>::max(), 1, &result));
  EXPECT_EQ(result, 123);
}

TEST(VirtualHidProtocolTest, RejectsNullCheckedSizeResult) {
  EXPECT_FALSE(lumen_vhid_checked_add_size(1, 2, nullptr));
}

TEST(VirtualHidProtocolTest, AcceptsExactMessageHeader) {
  const auto header = valid_header(
    LUMEN_VHID_OPERATION_CLAIM_INPUT_SESSION,
    sizeof(LUMEN_VHID_CLAIM_SESSION_REQUEST)
  );

  EXPECT_TRUE(lumen_vhid_validate_message_header(
    &header,
    sizeof(LUMEN_VHID_CLAIM_SESSION_REQUEST),
    LUMEN_VHID_OPERATION_CLAIM_INPUT_SESSION,
    sizeof(LUMEN_VHID_CLAIM_SESSION_REQUEST)
  ));
}

TEST(VirtualHidProtocolTest, AcceptsFutureMinorForKnownOperation) {
  const auto header = valid_header(
    LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
    sizeof(LUMEN_VHID_GET_CAPABILITIES_REQUEST),
    static_cast<std::uint16_t>(LUMEN_VHID_PROTOCOL_MINOR + 1)
  );

  EXPECT_TRUE(lumen_vhid_validate_message_header(
    &header,
    sizeof(header),
    LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
    sizeof(header)
  ));
}

TEST(VirtualHidProtocolTest, RejectsNullMessageHeader) {
  EXPECT_FALSE(lumen_vhid_validate_message_header(
    nullptr,
    sizeof(LUMEN_VHID_MESSAGE_HEADER),
    LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
    sizeof(LUMEN_VHID_MESSAGE_HEADER)
  ));
}

TEST(VirtualHidProtocolTest, RejectsMessageOverControlLimit) {
  auto header = valid_header(
    LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
    LUMEN_VHID_MAX_CONTROL_SIZE + 1U
  );

  EXPECT_FALSE(lumen_vhid_validate_message_header(
    &header,
    LUMEN_VHID_MAX_CONTROL_SIZE + 1U,
    LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
    LUMEN_VHID_MAX_CONTROL_SIZE + 1U
  ));
}

TEST(VirtualHidProtocolTest, RejectsTruncatedMessageHeader) {
  const auto header = valid_header(
    LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
    sizeof(LUMEN_VHID_GET_CAPABILITIES_REQUEST)
  );

  EXPECT_FALSE(lumen_vhid_validate_message_header(
    &header,
    sizeof(header) - 1,
    LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
    sizeof(header)
  ));
}

TEST(VirtualHidProtocolTest, RejectsBadProtocolMagic) {
  auto header = valid_header(LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES, sizeof(LUMEN_VHID_MESSAGE_HEADER));
  header.magic ^= 1U;

  EXPECT_FALSE(lumen_vhid_validate_message_header(
    &header,
    sizeof(header),
    LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
    sizeof(header)
  ));
}

TEST(VirtualHidProtocolTest, RejectsIncompatibleProtocolMajor) {
  auto header = valid_header(LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES, sizeof(LUMEN_VHID_MESSAGE_HEADER));
  ++header.protocol_major;

  EXPECT_FALSE(lumen_vhid_validate_message_header(
    &header,
    sizeof(header),
    LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
    sizeof(header)
  ));
}

TEST(VirtualHidProtocolTest, RejectsWrongHeaderSize) {
  auto header = valid_header(LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES, sizeof(LUMEN_VHID_MESSAGE_HEADER));
  --header.header_size;

  EXPECT_FALSE(lumen_vhid_validate_message_header(
    &header,
    sizeof(header),
    LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
    sizeof(header)
  ));
}

TEST(VirtualHidProtocolTest, RejectsWrongOperation) {
  auto header = valid_header(LUMEN_VHID_OPERATION_CLAIM_INPUT_SESSION, sizeof(LUMEN_VHID_MESSAGE_HEADER));

  EXPECT_FALSE(lumen_vhid_validate_message_header(
    &header,
    sizeof(header),
    LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
    sizeof(header)
  ));
}

TEST(VirtualHidProtocolTest, RejectsUnknownOperationAtMaximumMinor) {
  constexpr auto unknown_operation = std::numeric_limits<std::uint16_t>::max();
  const auto header = valid_header(unknown_operation, sizeof(LUMEN_VHID_MESSAGE_HEADER), UINT16_MAX);

  EXPECT_FALSE(lumen_vhid_validate_message_header(
    &header,
    sizeof(header),
    unknown_operation,
    sizeof(header)
  ));
}

TEST(VirtualHidProtocolTest, RejectsMismatchedTotalSize) {
  auto header = valid_header(LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES, sizeof(LUMEN_VHID_MESSAGE_HEADER));
  ++header.total_size;

  EXPECT_FALSE(lumen_vhid_validate_message_header(
    &header,
    sizeof(header),
    LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
    sizeof(header)
  ));
}

TEST(VirtualHidProtocolTest, RejectsNonzeroHeaderFlags) {
  auto header = valid_header(LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES, sizeof(LUMEN_VHID_MESSAGE_HEADER));
  header.flags = 1;

  EXPECT_FALSE(lumen_vhid_validate_message_header(
    &header,
    sizeof(header),
    LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
    sizeof(header)
  ));
}

TEST(VirtualHidProtocolTest, RejectsDeterministicMalformedHeaderCorpus) {
  std::uint32_t state = 0xC001D00DU;

  for (int case_index = 0; case_index < 4096; ++case_index) {
    std::array<std::uint8_t, sizeof(LUMEN_VHID_MESSAGE_HEADER)> bytes {};
    for (auto &byte : bytes) {
      state ^= state << 13;
      state ^= state >> 17;
      state ^= state << 5;
      byte = static_cast<std::uint8_t>(state);
    }

    LUMEN_VHID_MESSAGE_HEADER header {};
    std::memcpy(&header, bytes.data(), bytes.size());
    EXPECT_FALSE(lumen_vhid_validate_message_header(
      &header,
      sizeof(header),
      LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
      sizeof(header)
    ));
  }
}

TEST(VirtualHidProtocolTest, NegotiatesCompatibleProtocolAndCapabilities) {
  std::uint16_t negotiated_minor = UINT16_MAX;

  ASSERT_TRUE(lumen_vhid_negotiate_protocol(
    LUMEN_VHID_PROTOCOL_MAJOR,
    LUMEN_VHID_PROTOCOL_MINOR,
    LUMEN_VHID_OPERATION_SUBMIT_INPUT_REPORT,
    LUMEN_VHID_CAP_REQUIRED,
    LUMEN_VHID_CAP_REQUIRED,
    &negotiated_minor
  ));
  EXPECT_EQ(negotiated_minor, LUMEN_VHID_PROTOCOL_MINOR);
}

TEST(VirtualHidProtocolTest, NegotiatesDownFromFutureClientMinor) {
  std::uint16_t negotiated_minor = UINT16_MAX;

  ASSERT_TRUE(lumen_vhid_negotiate_protocol(
    LUMEN_VHID_PROTOCOL_MAJOR,
    static_cast<std::uint16_t>(LUMEN_VHID_PROTOCOL_MINOR + 5),
    LUMEN_VHID_OPERATION_CLAIM_INPUT_SESSION,
    LUMEN_VHID_CAP_REQUIRED,
    LUMEN_VHID_CAP_REQUIRED,
    &negotiated_minor
  ));
  EXPECT_EQ(negotiated_minor, LUMEN_VHID_PROTOCOL_MINOR);
}

TEST(VirtualHidProtocolTest, RejectsNegotiationWithIncompatibleMajor) {
  std::uint16_t negotiated_minor = 0;

  EXPECT_FALSE(lumen_vhid_negotiate_protocol(
    LUMEN_VHID_PROTOCOL_MAJOR + 1U,
    LUMEN_VHID_PROTOCOL_MINOR,
    LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
    0,
    LUMEN_VHID_CAP_REQUIRED,
    &negotiated_minor
  ));
}

TEST(VirtualHidProtocolTest, RejectsNegotiationWithMissingCapability) {
  std::uint16_t negotiated_minor = 0;

  EXPECT_FALSE(lumen_vhid_negotiate_protocol(
    LUMEN_VHID_PROTOCOL_MAJOR,
    LUMEN_VHID_PROTOCOL_MINOR,
    LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
    LUMEN_VHID_CAP_REQUIRED,
    LUMEN_VHID_CAP_REQUIRED & ~LUMEN_VHID_CAP_MOUSE_ABSOLUTE,
    &negotiated_minor
  ));
}

TEST(VirtualHidProtocolTest, AcceptsNegotiationWithExtraDriverCapability) {
  constexpr std::uint64_t future_capability = UINT64_C(1) << 63;
  std::uint16_t negotiated_minor = UINT16_MAX;

  EXPECT_TRUE(lumen_vhid_negotiate_protocol(
    LUMEN_VHID_PROTOCOL_MAJOR,
    LUMEN_VHID_PROTOCOL_MINOR,
    LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
    LUMEN_VHID_CAP_REQUIRED,
    LUMEN_VHID_CAP_REQUIRED | future_capability,
    &negotiated_minor
  ));
}

TEST(VirtualHidProtocolTest, RejectsNegotiationForUnknownOperation) {
  std::uint16_t negotiated_minor = 0;

  EXPECT_FALSE(lumen_vhid_negotiate_protocol(
    LUMEN_VHID_PROTOCOL_MAJOR,
    LUMEN_VHID_PROTOCOL_MINOR,
    UINT16_MAX,
    0,
    LUMEN_VHID_CAP_REQUIRED,
    &negotiated_minor
  ));
}

TEST(VirtualHidProtocolTest, AcceptsFirstSequenceAfterClaim) {
  EXPECT_TRUE(lumen_vhid_is_next_sequence(0, false, 1));
}

TEST(VirtualHidProtocolTest, AcceptsOnlyContiguousSequence) {
  EXPECT_TRUE(lumen_vhid_is_next_sequence(41, false, 42));
  EXPECT_FALSE(lumen_vhid_is_next_sequence(41, false, 0));
  EXPECT_FALSE(lumen_vhid_is_next_sequence(41, false, 41));
  EXPECT_FALSE(lumen_vhid_is_next_sequence(41, false, 40));
  EXPECT_FALSE(lumen_vhid_is_next_sequence(41, false, 43));
}

TEST(VirtualHidProtocolTest, AcceptsTerminalSequenceOnlyAsExactNextValue) {
  EXPECT_TRUE(lumen_vhid_is_next_sequence(UINT64_MAX - 1U, false, UINT64_MAX));
  EXPECT_FALSE(lumen_vhid_is_next_sequence(UINT64_MAX - 2U, false, UINT64_MAX));
}

TEST(VirtualHidProtocolTest, RejectsSequenceAfterTerminalExhaustion) {
  EXPECT_FALSE(lumen_vhid_is_next_sequence(UINT64_MAX, true, 1));
  EXPECT_FALSE(lumen_vhid_is_next_sequence(UINT64_MAX, false, 1));
}

TEST_P(valid_report_metadata_test, AcceptsMatchingDeviceReportAndSize) {
  const auto &test_case = GetParam();

  EXPECT_TRUE(lumen_vhid_validate_report_metadata(
    test_case.device_kind,
    test_case.report_id,
    test_case.payload_size
  ));
}

INSTANTIATE_TEST_SUITE_P(
  AllReports,
  valid_report_metadata_test,
  testing::Values(
    report_metadata_case_t {
      LUMEN_VHID_DEVICE_KIND_KEYBOARD,
      LUMEN_VHID_REPORT_ID_KEYBOARD,
      sizeof(LUMEN_VHID_KEYBOARD_REPORT)
    },
    report_metadata_case_t {
      LUMEN_VHID_DEVICE_KIND_MOUSE,
      LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE,
      sizeof(LUMEN_VHID_RELATIVE_MOUSE_REPORT)
    },
    report_metadata_case_t {
      LUMEN_VHID_DEVICE_KIND_MOUSE,
      LUMEN_VHID_REPORT_ID_MOUSE_ABSOLUTE,
      sizeof(LUMEN_VHID_ABSOLUTE_MOUSE_REPORT)
    }
  )
);

TEST(VirtualHidProtocolTest, RejectsUnknownDeviceKind) {
  EXPECT_FALSE(lumen_vhid_validate_report_metadata(
    0,
    LUMEN_VHID_REPORT_ID_KEYBOARD,
    sizeof(LUMEN_VHID_KEYBOARD_REPORT)
  ));
}

TEST(VirtualHidProtocolTest, RejectsReportForWrongDeviceKind) {
  EXPECT_FALSE(lumen_vhid_validate_report_metadata(
    LUMEN_VHID_DEVICE_KIND_KEYBOARD,
    LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE,
    sizeof(LUMEN_VHID_RELATIVE_MOUSE_REPORT)
  ));
}

TEST(VirtualHidProtocolTest, RejectsUnknownReportId) {
  EXPECT_FALSE(lumen_vhid_validate_report_metadata(
    LUMEN_VHID_DEVICE_KIND_MOUSE,
    UINT16_MAX,
    sizeof(LUMEN_VHID_RELATIVE_MOUSE_REPORT)
  ));
}

TEST(VirtualHidProtocolTest, RejectsTruncatedReportPayload) {
  EXPECT_FALSE(lumen_vhid_validate_report_metadata(
    LUMEN_VHID_DEVICE_KIND_KEYBOARD,
    LUMEN_VHID_REPORT_ID_KEYBOARD,
    sizeof(LUMEN_VHID_KEYBOARD_REPORT) - 1U
  ));
}

TEST(VirtualHidProtocolTest, RejectsOversizedReportPayload) {
  EXPECT_FALSE(lumen_vhid_validate_report_metadata(
    LUMEN_VHID_DEVICE_KIND_MOUSE,
    LUMEN_VHID_REPORT_ID_MOUSE_ABSOLUTE,
    sizeof(LUMEN_VHID_ABSOLUTE_MOUSE_REPORT) + 1U
  ));
}
