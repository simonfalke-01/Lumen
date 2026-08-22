/**
 * @file tests/unit/platform/windows/test_virtual_microphone_protocol.cpp
 * @brief Test the host-buildable Lumen virtual microphone ABI.
 */
#include <gtest/gtest.h>

// local includes
#include <src/platform/windows/virtual_microphone_protocol.h>

// standard includes
#include <cstddef>
#include <cstdint>
#include <type_traits>

TEST(VirtualMicrophoneProtocolTest, UsesExactFixedPcmIdentity) {
  EXPECT_EQ(LUMEN_VMIC_ABI_VERSION, 1U);
  EXPECT_EQ(LUMEN_VMIC_SAMPLE_RATE_HZ, 48000U);
  EXPECT_EQ(LUMEN_VMIC_CHANNEL_COUNT, 1U);
  EXPECT_EQ(LUMEN_VMIC_BITS_PER_SAMPLE, 16U);
  EXPECT_EQ(LUMEN_VMIC_MAX_WRITE_FRAMES, 960U);
}

TEST(VirtualMicrophoneProtocolTest, UsesExactAbiAndOpenLayouts) {
  EXPECT_EQ(sizeof(LUMEN_VMIC_QUERY_ABI_RESPONSE), 16U);
  EXPECT_EQ(offsetof(LUMEN_VMIC_QUERY_ABI_RESPONSE, abi_version), 0U);
  EXPECT_EQ(offsetof(LUMEN_VMIC_QUERY_ABI_RESPONSE, sample_rate_hz), 4U);
  EXPECT_EQ(offsetof(LUMEN_VMIC_QUERY_ABI_RESPONSE, channel_count), 8U);
  EXPECT_EQ(offsetof(LUMEN_VMIC_QUERY_ABI_RESPONSE, bits_per_sample), 10U);
  EXPECT_EQ(offsetof(LUMEN_VMIC_QUERY_ABI_RESPONSE, max_write_frames), 12U);

  EXPECT_EQ(sizeof(LUMEN_VMIC_OPEN_STREAM_REQUEST), 16U);
  EXPECT_EQ(offsetof(LUMEN_VMIC_OPEN_STREAM_REQUEST, requested_generation), 0U);
  EXPECT_EQ(offsetof(LUMEN_VMIC_OPEN_STREAM_REQUEST, sample_rate_hz), 8U);
  EXPECT_EQ(offsetof(LUMEN_VMIC_OPEN_STREAM_REQUEST, channel_count), 12U);
  EXPECT_EQ(offsetof(LUMEN_VMIC_OPEN_STREAM_REQUEST, bits_per_sample), 14U);
}

TEST(VirtualMicrophoneProtocolTest, UsesExactBoundedWriteLayout) {
  EXPECT_EQ(LUMEN_VMIC_WRITE_PCM_HEADER_SIZE, 12U);
  EXPECT_EQ(sizeof(LUMEN_VMIC_WRITE_PCM_REQUEST), 1932U);
  EXPECT_EQ(LUMEN_VMIC_MAX_WRITE_PCM_REQUEST_SIZE, 1932U);
  EXPECT_EQ(offsetof(LUMEN_VMIC_WRITE_PCM_REQUEST, generation), 0U);
  EXPECT_EQ(offsetof(LUMEN_VMIC_WRITE_PCM_REQUEST, frame_count), 8U);
  EXPECT_EQ(offsetof(LUMEN_VMIC_WRITE_PCM_REQUEST, samples), 12U);
}

TEST(VirtualMicrophoneProtocolTest, UsesExactResetAndStatisticsLayouts) {
  EXPECT_EQ(sizeof(LUMEN_VMIC_RESET_REQUEST), 8U);
  EXPECT_EQ(offsetof(LUMEN_VMIC_RESET_REQUEST, generation), 0U);

  EXPECT_EQ(sizeof(LUMEN_VMIC_QUERY_STATS_RESPONSE), 56U);
  EXPECT_EQ(offsetof(LUMEN_VMIC_QUERY_STATS_RESPONSE, generation), 0U);
  EXPECT_EQ(offsetof(LUMEN_VMIC_QUERY_STATS_RESPONSE, accepted_frames), 8U);
  EXPECT_EQ(offsetof(LUMEN_VMIC_QUERY_STATS_RESPONSE, stale_writes), 16U);
  EXPECT_EQ(offsetof(LUMEN_VMIC_QUERY_STATS_RESPONSE, overflow_drops), 24U);
  EXPECT_EQ(offsetof(LUMEN_VMIC_QUERY_STATS_RESPONSE, underflow_samples), 32U);
  EXPECT_EQ(offsetof(LUMEN_VMIC_QUERY_STATS_RESPONSE, resets), 40U);
  EXPECT_EQ(offsetof(LUMEN_VMIC_QUERY_STATS_RESPONSE, current_fill_frames), 48U);
  EXPECT_EQ(offsetof(LUMEN_VMIC_QUERY_STATS_RESPONSE, capacity_frames), 52U);
}

TEST(VirtualMicrophoneProtocolTest, KeepsAllMessagesTriviallyCopyable) {
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VMIC_QUERY_ABI_RESPONSE>);
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VMIC_OPEN_STREAM_REQUEST>);
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VMIC_WRITE_PCM_REQUEST>);
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VMIC_RESET_REQUEST>);
  EXPECT_TRUE(std::is_trivially_copyable_v<LUMEN_VMIC_QUERY_STATS_RESPONSE>);
}

TEST(VirtualMicrophoneProtocolTest, UsesFiveDistinctBufferedOperations) {
  EXPECT_EQ(IOCTL_LUMEN_VMIC_QUERY_ABI & 3U, METHOD_BUFFERED);
  EXPECT_EQ(IOCTL_LUMEN_VMIC_OPEN_STREAM & 3U, METHOD_BUFFERED);
  EXPECT_EQ(IOCTL_LUMEN_VMIC_WRITE_PCM & 3U, METHOD_BUFFERED);
  EXPECT_EQ(IOCTL_LUMEN_VMIC_RESET & 3U, METHOD_BUFFERED);
  EXPECT_EQ(IOCTL_LUMEN_VMIC_QUERY_STATS & 3U, METHOD_BUFFERED);

  EXPECT_NE(IOCTL_LUMEN_VMIC_QUERY_ABI, IOCTL_LUMEN_VMIC_OPEN_STREAM);
  EXPECT_NE(IOCTL_LUMEN_VMIC_OPEN_STREAM, IOCTL_LUMEN_VMIC_WRITE_PCM);
  EXPECT_NE(IOCTL_LUMEN_VMIC_WRITE_PCM, IOCTL_LUMEN_VMIC_RESET);
  EXPECT_NE(IOCTL_LUMEN_VMIC_RESET, IOCTL_LUMEN_VMIC_QUERY_STATS);
}
