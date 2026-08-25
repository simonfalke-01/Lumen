/**
 * @file tests/unit/test_stream.cpp
 * @brief Test src/stream.*
 */

#include <cstdint>
#include <functional>
#include <future>
#include <src/input.h>
#include <src/stream.h>
#include <src/protocol_v3/media_pipeline.h>
#include <string>
#include <vector>

namespace stream {
  std::vector<uint8_t> concat_and_insert(uint64_t insert_size, uint64_t slice_size, const std::string_view &data1, const std::string_view &data2);
}

#include "../tests_common.h"

TEST(ConcatAndInsertTests, ConcatNoInsertionTest) {
  char b1[] = {'a', 'b'};
  char b2[] = {'c', 'd', 'e'};
  auto res = stream::concat_and_insert(0, 2, std::string_view {b1, sizeof(b1)}, std::string_view {b2, sizeof(b2)});
  auto expected = std::vector<uint8_t> {'a', 'b', 'c', 'd', 'e'};
  ASSERT_EQ(res, expected);
}

TEST(ConcatAndInsertTests, ConcatLargeStrideTest) {
  char b1[] = {'a', 'b'};
  char b2[] = {'c', 'd', 'e'};
  auto res = stream::concat_and_insert(1, sizeof(b1) + sizeof(b2) + 1, std::string_view {b1, sizeof(b1)}, std::string_view {b2, sizeof(b2)});
  auto expected = std::vector<uint8_t> {0, 'a', 'b', 'c', 'd', 'e'};
  ASSERT_EQ(res, expected);
}

TEST(ConcatAndInsertTests, ConcatSmallStrideTest) {
  char b1[] = {'a', 'b'};
  char b2[] = {'c', 'd', 'e'};
  auto res = stream::concat_and_insert(1, 1, std::string_view {b1, sizeof(b1)}, std::string_view {b2, sizeof(b2)});
  auto expected = std::vector<uint8_t> {0, 'a', 0, 'b', 0, 'c', 0, 'd', 0, 'e'};
  ASSERT_EQ(res, expected);
}

TEST(VirtualDisplayCleanupTest, StopsFrameSourceBeforeReleasingDisplayLease) {
  std::vector<std::string> operations;
  const auto released = stream::ordered_virtual_display_cleanup(
    [&operations]() noexcept {
      operations.emplace_back("stop-source");
    },
    [&operations]() noexcept {
      operations.emplace_back("release-lease");
      return true;
    }
  );

  EXPECT_TRUE(released);
  EXPECT_EQ(operations, (std::vector<std::string> {"stop-source", "release-lease"}));
}

TEST(VirtualDisplayCleanupTest, LegacyHdrFallsBackOnlyAfterSafeOptionalRollback) {
  EXPECT_TRUE(stream::allow_legacy_physical_hdr_fallback(true, true, true));
  EXPECT_FALSE(stream::allow_legacy_physical_hdr_fallback(false, true, true));
  EXPECT_FALSE(stream::allow_legacy_physical_hdr_fallback(true, false, true));
  EXPECT_FALSE(stream::allow_legacy_physical_hdr_fallback(true, true, false));
}

TEST(ProtocolV3AudioConfigurationTest, AppliesExplicitHostPlaybackPolicyAndExactTuple) {
  lumen::protocol_v3::media::NegotiatedMediaConfig selection;
  selection.audio = {
    .sample_rate = 48'000,
    .frame_samples = 240,
    .channels = 6,
    .layout = 2,
    .streams = 4,
    .coupled_streams = 2,
    .mapping = {0, 1, 2, 3, 4, 5, 0xff, 0xff},
    .bitrate_bps = 256'000,
  };

  for (const bool host_audio : {false, true}) {
    selection.host_audio = host_audio;
    audio::config_t configured {};
    stream::configure_protocol_v3_audio(configured, selection);

    EXPECT_EQ(configured.packetDuration, 5);
    EXPECT_EQ(configured.channels, 6);
    EXPECT_EQ(configured.mask, 0x3f);
    EXPECT_EQ(configured.bitrate, 256'000);
    EXPECT_EQ(configured.flags[audio::config_t::HOST_AUDIO], host_audio);
    EXPECT_TRUE(configured.flags[audio::config_t::CONTINUOUS_AUDIO]);
    EXPECT_TRUE(configured.flags[audio::config_t::CUSTOM_SURROUND_PARAMS]);
    EXPECT_EQ(configured.customStreamParams.channelCount, 6);
    EXPECT_EQ(configured.customStreamParams.streams, 4);
    EXPECT_EQ(configured.customStreamParams.coupledStreams, 2);
    EXPECT_TRUE(std::ranges::equal(
      configured.customStreamParams.mapping,
      selection.audio.mapping
    ));
  }
}

TEST(ProtocolV3ControllerFeedbackTest, DelayedGenerationCannotRetargetAReusedControllerSlot) {
  const auto delayed = platf::gamepad_feedback_msg_t::make_rumble(
    {2, 7, 1},
    0x1111,
    0x2222
  );
  const auto current = platf::gamepad_feedback_msg_t::make_rumble(
    {2, 7, 2},
    0x3333,
    0x4444
  );

  EXPECT_FALSE(stream::protocol_v3_feedback_is_current_for_test(delayed, 7, 2));
  EXPECT_FALSE(stream::protocol_v3_feedback_is_current_for_test(current, 8, 2));
  EXPECT_TRUE(stream::protocol_v3_feedback_is_current_for_test(current, 7, 2));
  EXPECT_EQ(delayed.identity.controller_generation, 1U);
}

TEST(ProtocolV3InputResetTest, RealOrderedInjectorFailureReportsRejectedCompletion) {
  auto platform_input = input::init();
  auto mail = std::make_shared<safe::mail_raw_t>();
  auto session_input = input::alloc(mail);
  ASSERT_TRUE(session_input);

  std::promise<bool> completion;
  auto result = completion.get_future();
  ASSERT_TRUE(input::passthrough_state(
    session_input,
    [](const input::ordered_injector_t &injector) {
      return injector(std::vector<std::uint8_t>(sizeof(std::uint64_t), 0));
    },
    false,
    [&completion](const bool applied) {
      completion.set_value(applied);
    }
  ));
  ASSERT_EQ(result.wait_for(std::chrono::seconds {1}), std::future_status::ready);
  EXPECT_FALSE(result.get());

  input::reset(session_input);
  platform_input.reset();
}
