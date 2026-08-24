/**
 * @file tests/unit/test_rtsp_packet_size.cpp
 * @brief Tests for client-announced RTSP video packet-size validation.
 */

// standard includes
#include <limits>

// local includes
#include "../tests_common.h"
#include "src/config.h"
#include "src/rtsp.h"

TEST(RtspPacketSizeTest, EnforcesLowerAndUnencryptedTransportBounds) {
  EXPECT_FALSE(rtsp_stream::validate_video_packet_size(config::PACKETSIZE_MIN - 1, false));
  EXPECT_TRUE(rtsp_stream::validate_video_packet_size(config::PACKETSIZE_MIN, false));
  EXPECT_TRUE(rtsp_stream::validate_video_packet_size(65491, false));
  EXPECT_FALSE(rtsp_stream::validate_video_packet_size(65492, false));
  EXPECT_FALSE(rtsp_stream::validate_video_packet_size(config::PACKETSIZE_MAX, false));
}

TEST(RtspPacketSizeTest, ReservesTheEncryptedVideoPrefix) {
  EXPECT_TRUE(rtsp_stream::validate_video_packet_size(65459, true));
  EXPECT_FALSE(rtsp_stream::validate_video_packet_size(65460, true));
  EXPECT_FALSE(rtsp_stream::validate_video_packet_size(-1, true));
  EXPECT_FALSE(rtsp_stream::validate_video_packet_size(std::numeric_limits<std::int64_t>::max(), true));
}

TEST(RtspPacketSizeTest, StrictParserRejectsMalformedAndOverflowingAnnouncements) {
  EXPECT_EQ(rtsp_stream::parse_video_packet_size("1400", false), 1400);
  EXPECT_EQ(rtsp_stream::parse_video_packet_size("65459", true), 65459);
  EXPECT_FALSE(rtsp_stream::parse_video_packet_size("", false));
  EXPECT_FALSE(rtsp_stream::parse_video_packet_size("+1400", false));
  EXPECT_FALSE(rtsp_stream::parse_video_packet_size("1400 ", false));
  EXPECT_FALSE(rtsp_stream::parse_video_packet_size("1400junk", false));
  EXPECT_FALSE(rtsp_stream::parse_video_packet_size("999999999999999999999999999999999999", false));
}
