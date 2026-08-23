/**
 * @file tests/unit/platform/windows/test_virtual_hid_protocol.cpp
 * @brief Test the host-buildable lean Virtual HID ABI.
 */
#include <gtest/gtest.h>

// local includes
#include <src/platform/windows/virtual_hid_protocol.h>

// standard includes
#include <cstddef>
#include <cstdint>
#include <type_traits>

TEST(VirtualHidProtocolTest, UsesExactAbiVersionAndInfoLayout) {
  EXPECT_EQ(LUMEN_VHID_ABI_VERSION, 2U);
  EXPECT_EQ(sizeof(LUMEN_VHID_GET_INFO_RESPONSE), 8U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GET_INFO_RESPONSE, abi_version), 0U);
  EXPECT_EQ(offsetof(LUMEN_VHID_GET_INFO_RESPONSE, ready), 4U);
}

TEST(VirtualHidProtocolTest, UsesExactPackedReportLayouts) {
  EXPECT_EQ(sizeof(LUMEN_VHID_KEYBOARD_REPORT), 30U);
  EXPECT_EQ(sizeof(LUMEN_VHID_RELATIVE_MOUSE_REPORT), 10U);
  EXPECT_EQ(sizeof(LUMEN_VHID_ABSOLUTE_MOUSE_REPORT), 10U);
  EXPECT_EQ(sizeof(LUMEN_VHID_CONSUMER_REPORT), 9U);
  EXPECT_EQ(offsetof(LUMEN_VHID_KEYBOARD_REPORT, key_bitmap), 2U);
  EXPECT_EQ(offsetof(LUMEN_VHID_RELATIVE_MOUSE_REPORT, x), 2U);
  EXPECT_EQ(offsetof(LUMEN_VHID_ABSOLUTE_MOUSE_REPORT, x), 2U);
  EXPECT_EQ(offsetof(LUMEN_VHID_CONSUMER_REPORT, usages), 1U);
}

TEST(VirtualHidProtocolTest, UsesOneFixedTaggedSubmitRequest) {
  EXPECT_EQ(sizeof(LUMEN_VHID_SUBMIT_REPORT_REQUEST), 34U);
  EXPECT_EQ(offsetof(LUMEN_VHID_SUBMIT_REPORT_REQUEST, report_kind), 0U);
  EXPECT_EQ(offsetof(LUMEN_VHID_SUBMIT_REPORT_REQUEST, report), 4U);
}

TEST(VirtualHidProtocolTest, KeepsReportsAndRequestsTriviallyCopyable) {
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VHID_GET_INFO_RESPONSE>);
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VHID_KEYBOARD_REPORT>);
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VHID_RELATIVE_MOUSE_REPORT>);
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VHID_ABSOLUTE_MOUSE_REPORT>);
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VHID_CONSUMER_REPORT>);
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VHID_SUBMIT_REPORT_REQUEST>);
}

TEST(VirtualHidProtocolTest, UsesFourMethodBufferedOperations) {
  EXPECT_EQ(IOCTL_LUMEN_VHID_GET_INFO & 3U, METHOD_BUFFERED);
  EXPECT_EQ(IOCTL_LUMEN_VHID_CLAIM & 3U, METHOD_BUFFERED);
  EXPECT_EQ(IOCTL_LUMEN_VHID_SUBMIT_REPORT & 3U, METHOD_BUFFERED);
  EXPECT_EQ(IOCTL_LUMEN_VHID_RESET_AND_RELEASE & 3U, METHOD_BUFFERED);
}

TEST(VirtualHidProtocolTest, UsesDistinctKindsAndReportIds) {
  EXPECT_EQ(LUMEN_VHID_REPORT_KIND_KEYBOARD, 1U);
  EXPECT_EQ(LUMEN_VHID_REPORT_KIND_RELATIVE_MOUSE, 2U);
  EXPECT_EQ(LUMEN_VHID_REPORT_KIND_CONSUMER, 3U);
  EXPECT_EQ(LUMEN_VHID_REPORT_KIND_ABSOLUTE_MOUSE, 4U);
  EXPECT_EQ(LUMEN_VHID_REPORT_ID_KEYBOARD, 1U);
  EXPECT_EQ(LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE, 2U);
  EXPECT_EQ(LUMEN_VHID_REPORT_ID_CONSUMER, 3U);
  EXPECT_EQ(LUMEN_VHID_REPORT_ID_MOUSE_ABSOLUTE, 4U);
  EXPECT_EQ(LUMEN_VHID_MOUSE_COLLECTION_COUNT, 2U);
}
