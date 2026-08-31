/**
 * @file tests/unit/test_stream.cpp
 * @brief Test src/stream.*
 */

#include <cstdint>
#include <functional>
#include <future>
#include <src/input.h>
#include <src/stream.h>
#include <stdexcept>
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

TEST(StreamSessionLifecycleTest, PublishesStartingBeforeWorkersAndCommittedStateBeforeRunning) {
  const auto probe = stream::session::startup_order_probe_for_test();

  EXPECT_EQ(probe.worker_observed_state, stream::session::state_e::STARTING);
  EXPECT_TRUE(probe.stop_transitioned);
  EXPECT_TRUE(probe.worker_observed_committed_startup);
  EXPECT_EQ(probe.final_state, stream::session::state_e::STOPPING);
}

TEST(StreamSessionLifecycleTest, ThrowAfterOneWorkerRollsBackPromptlyWithoutEnteringWorkerBody) {
  const auto probe = stream::session::startup_failure_probe_for_test(false);

  EXPECT_TRUE(probe.controlled_failure);
  EXPECT_TRUE(probe.worker_joined);
  EXPECT_FALSE(probe.worker_entered_body);
  EXPECT_FALSE(probe.commit_called);
  EXPECT_EQ(probe.final_state, stream::session::state_e::STOPPED);
}

TEST(StreamSessionLifecycleTest, CommitFailureRollsBackConstructedWorkerWithoutEnteringBody) {
  const auto probe = stream::session::startup_failure_probe_for_test(true);

  EXPECT_TRUE(probe.controlled_failure);
  EXPECT_TRUE(probe.worker_joined);
  EXPECT_FALSE(probe.worker_entered_body);
  EXPECT_TRUE(probe.commit_called);
  EXPECT_EQ(probe.final_state, stream::session::state_e::STOPPED);
}

TEST(StreamSessionLifecycleTest, ConstructionFailureRejectsControlClaimAndRemovesEveryPeerAlias) {
  const auto probe = stream::session::control_rollback_probe_for_test(false);

  EXPECT_TRUE(probe.controlled_failure);
  EXPECT_TRUE(probe.unclaimed_session_rejected_while_starting);
  EXPECT_TRUE(probe.peer_alias_rejected_while_starting);
  EXPECT_TRUE(probe.session_registration_removed);
  EXPECT_TRUE(probe.peer_alias_removed);
  EXPECT_TRUE(probe.all_bound_peers_disconnected);
  EXPECT_TRUE(probe.bound_peer_cleared);
  EXPECT_TRUE(probe.lookup_after_owner_release_rejected);
}

TEST(StreamSessionLifecycleTest, CommitFailureRejectsControlClaimAndRemovesEveryPeerAlias) {
  const auto probe = stream::session::control_rollback_probe_for_test(true);

  EXPECT_TRUE(probe.controlled_failure);
  EXPECT_TRUE(probe.unclaimed_session_rejected_while_starting);
  EXPECT_TRUE(probe.peer_alias_rejected_while_starting);
  EXPECT_TRUE(probe.session_registration_removed);
  EXPECT_TRUE(probe.peer_alias_removed);
  EXPECT_TRUE(probe.all_bound_peers_disconnected);
  EXPECT_TRUE(probe.bound_peer_cleared);
  EXPECT_TRUE(probe.lookup_after_owner_release_rejected);
}

TEST(VirtualDisplayDirectLossContract, RequiredDirectSourceTerminatesWhileLegacyFallbackRequiresSafeRollback) {
  video::config_t direct_required {};
  direct_required.virtual_display_direct_required = true;
  EXPECT_EQ(video::capture_reinitialization_action(direct_required), video::capture_reinitialization_e::terminate);
  EXPECT_FALSE(stream::allow_legacy_physical_hdr_fallback(false, true, true));
  EXPECT_FALSE(stream::allow_legacy_physical_hdr_fallback(true, false, true));
  EXPECT_TRUE(stream::allow_legacy_physical_hdr_fallback(true, true, true));
}

TEST(StreamAudioPacketQueueProductionTest, EnforcesCapacityAndCloseWakeup) {
  using result_e = audio::AudioPacketDestination::enqueue_result_e;
  const auto probe = stream::audio_packet_queue_probe_for_test();

  EXPECT_EQ(probe.first_enqueue, result_e::enqueued);
  EXPECT_EQ(probe.full_enqueue, result_e::backpressure);
  EXPECT_TRUE(probe.first_pop_present);
  EXPECT_EQ(probe.first_pop_tag, 0x11);
  EXPECT_EQ(probe.refill_enqueue, result_e::enqueued);
  EXPECT_FALSE(probe.pop_after_repeated_close_present);
  EXPECT_EQ(probe.enqueue_after_repeated_close, result_e::closed);
  EXPECT_TRUE(probe.waiter_blocked_before_close);
  EXPECT_TRUE(probe.waiter_ready_after_close);
  EXPECT_FALSE(probe.waiter_pop_present);
}

TEST(StreamAudioDestinationProductionTest, LegacySharedQueuePreservesOwnersAndIndependentClose) {
  using result_e = audio::AudioPacketDestination::enqueue_result_e;
  const auto probe = stream::audio_destination_isolation_probe_for_test();

  EXPECT_EQ(probe.legacy_first_enqueue, result_e::enqueued);
  EXPECT_EQ(probe.legacy_second_while_full, result_e::backpressure);
  EXPECT_EQ(probe.legacy_first_pop_owner, 1);
  EXPECT_EQ(probe.legacy_first_pop_tag, 0xa1);
  EXPECT_EQ(probe.legacy_second_after_pop, result_e::enqueued);
  EXPECT_EQ(probe.legacy_second_pop_owner, 2);
  EXPECT_EQ(probe.legacy_second_pop_tag, 0xb2);
  EXPECT_EQ(probe.legacy_first_after_close, result_e::closed);
  EXPECT_EQ(probe.legacy_second_after_first_close, result_e::enqueued);
  EXPECT_EQ(probe.legacy_second_after_close_owner, 2);
  EXPECT_EQ(probe.legacy_second_after_close_tag, 0xb3);
  EXPECT_EQ(probe.legacy_second_after_owner_expiry, result_e::closed);
}

TEST(StreamLegacyUdpPeerRoutingTest, ConcurrentVideoAndAudioPingsPreserveSocketSpecificPeers) {
  const auto probe = stream::legacy_udp_peer_isolation_probe_for_test();

  EXPECT_NE(probe.video_source_port, 0U);
  EXPECT_NE(probe.audio_source_port, 0U);
  EXPECT_NE(probe.video_source_port, probe.audio_source_port);
  EXPECT_EQ(probe.video_ping_count, 64U);
  EXPECT_EQ(probe.audio_ping_count, 64U);
  EXPECT_TRUE(probe.every_video_peer_isolated);
  EXPECT_TRUE(probe.every_audio_peer_isolated);
  EXPECT_EQ(probe.routed_video_port, probe.video_source_port);
  EXPECT_EQ(probe.routed_audio_port, probe.audio_source_port);
  EXPECT_TRUE(probe.audio_datagram_reached_audio_socket);
  EXPECT_FALSE(probe.audio_datagram_reached_video_socket);
}
