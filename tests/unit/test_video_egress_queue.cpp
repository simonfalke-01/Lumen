/**
 * @file tests/unit/test_video_egress_queue.cpp
 * @brief Tests for fair bounded per-session video egress scheduling.
 */

// standard includes
#include <chrono>
#include <future>
#include <thread>
#include <vector>

// lib includes
#include <gtest/gtest.h>

// local includes
#include "src/video_egress_queue.h"

using namespace std::chrono_literals;

namespace {
  /**
   * @brief Construct a generic encoded frame for scheduler tests.
   *
   * @param frame_index Monotonic frame identifier.
   * @param idr Whether the frame is independently decodable as an IDR.
   * @param rfi Whether the frame follows reference-frame invalidation.
   * @return Encoded frame with the requested dependency metadata.
   */
  video::packet_t make_frame(
    const std::int64_t frame_index,
    const bool idr = false,
    const bool rfi = false
  ) {
    auto frame = std::make_unique<video::packet_raw_generic>(
      std::vector<std::uint8_t> {static_cast<std::uint8_t>(frame_index)},
      frame_index,
      idr
    );
    frame->after_ref_frame_invalidation = rfi;
    return frame;
  }

  /** @brief Production Latency registration with one queued frame and a bounded deadline. */
  video::egress_queue_t::registration_policy_t latency_policy(
    const std::chrono::nanoseconds max_age = 1h
  ) {
    return {1, max_age};
  }

  /** @brief Production Quality/legacy registration using the requested FIFO bound. */
  video::egress_queue_t::registration_policy_t fifo_policy(const std::size_t capacity) {
    return {capacity, std::chrono::nanoseconds::zero()};
  }

  /**
   * @brief Pop one scheduled frame and return its frame index.
   *
   * @param queue Scheduler under test.
   * @param expected_session Session expected to own the next fair turn.
   * @return Popped encoded-frame index.
   */
  std::int64_t pop_frame(
    video::egress_queue_t &queue,
    const video::egress_queue_t::session_key_t expected_session
  ) {
    auto frame = queue.pop();
    EXPECT_TRUE(frame.has_value());
    if (!frame) {
      return -1;
    }
    EXPECT_EQ(frame->session, expected_session);
    return frame->packet->frame_index();
  }
}  // namespace

TEST(VideoEgressQueueTest, LatencyOverflowIsSessionLocalAndRestartsAtRfi) {
  video::egress_queue_t queue {2};
  int latency_session {};
  int quality_session {};
  std::vector<video::egress_queue_t::recovery_request_t> recoveries;

  ASSERT_TRUE(queue.register_session(
    &latency_session,
    video::egress_queue_t::behavior_e::latency,
    latency_policy(),
    [&recoveries](const auto &request) {
      recoveries.push_back(request);
    }
  ));
  ASSERT_TRUE(queue.register_session(
    &quality_session,
    video::egress_queue_t::behavior_e::fifo,
    fifo_policy(2),
    {}
  ));

  EXPECT_EQ(queue.push(&latency_session, make_frame(1)), video::egress_queue_t::enqueue_e::queued);
  EXPECT_EQ(queue.push(&latency_session, make_frame(2)), video::egress_queue_t::enqueue_e::dropped_overflow);
  EXPECT_EQ(queue.push(&quality_session, make_frame(10)), video::egress_queue_t::enqueue_e::queued);
  EXPECT_EQ(queue.push(&quality_session, make_frame(11)), video::egress_queue_t::enqueue_e::queued);

  ASSERT_EQ(recoveries.size(), 1U);
  EXPECT_EQ(recoveries.front().first_frame, 1);
  EXPECT_EQ(recoveries.front().last_frame, 2);
  EXPECT_EQ(recoveries.front().dropped_frames, 2U);
  EXPECT_EQ(recoveries.front().depth_after_drop, 0U);

  ASSERT_TRUE(queue.telemetry(&quality_session));
  EXPECT_EQ(queue.telemetry(&quality_session)->current_depth, 2U);
  EXPECT_EQ(pop_frame(queue, &quality_session), 10);
  EXPECT_EQ(pop_frame(queue, &quality_session), 11);

  EXPECT_EQ(
    queue.push(&latency_session, make_frame(3)),
    video::egress_queue_t::enqueue_e::dropped_awaiting_recovery
  );
  EXPECT_EQ(
    queue.push(&latency_session, make_frame(4, false, true)),
    video::egress_queue_t::enqueue_e::queued_recovery
  );
  EXPECT_EQ(pop_frame(queue, &latency_session), 4);

  const auto latency_telemetry = queue.unregister_session(&latency_session);
  ASSERT_TRUE(latency_telemetry);
  EXPECT_EQ(latency_telemetry->dropped_frames, 3U);
  EXPECT_EQ(latency_telemetry->overflow_events, 1U);
  EXPECT_EQ(latency_telemetry->gated_drops, 1U);
  EXPECT_EQ(latency_telemetry->recovery_requests, 1U);
  EXPECT_EQ(latency_telemetry->recovery_restarts, 1U);
  EXPECT_EQ(latency_telemetry->peak_depth, 1U);
  EXPECT_EQ(latency_telemetry->configured_capacity, 1U);
  EXPECT_EQ(latency_telemetry->configured_max_queue_age, 1h);

  const auto quality_telemetry = queue.unregister_session(&quality_session);
  ASSERT_TRUE(quality_telemetry);
  EXPECT_EQ(quality_telemetry->dropped_frames, 0U);
  EXPECT_EQ(quality_telemetry->dequeued_frames, 2U);
}

TEST(VideoEgressQueueTest, QualityOverflowPreservesRetainedFifoAndReservesIdr) {
  video::egress_queue_t queue {2};
  int session {};
  std::vector<video::egress_queue_t::recovery_request_t> recoveries;

  ASSERT_TRUE(queue.register_session(
    &session,
    video::egress_queue_t::behavior_e::fifo,
    fifo_policy(2),
    [&recoveries](const auto &request) {
      recoveries.push_back(request);
    }
  ));

  EXPECT_EQ(queue.push(&session, make_frame(1)), video::egress_queue_t::enqueue_e::queued);
  EXPECT_EQ(queue.push(&session, make_frame(2)), video::egress_queue_t::enqueue_e::queued);
  EXPECT_EQ(queue.push(&session, make_frame(3)), video::egress_queue_t::enqueue_e::dropped_overflow);
  EXPECT_EQ(
    queue.push(&session, make_frame(4)),
    video::egress_queue_t::enqueue_e::dropped_awaiting_recovery
  );
  EXPECT_EQ(
    queue.push(&session, make_frame(5, true)),
    video::egress_queue_t::enqueue_e::queued_recovery
  );

  ASSERT_EQ(recoveries.size(), 1U);
  EXPECT_EQ(recoveries.front().first_frame, 2);
  EXPECT_EQ(recoveries.front().last_frame, 3);
  EXPECT_EQ(recoveries.front().dropped_frames, 2U);
  EXPECT_EQ(recoveries.front().depth_after_drop, 1U);
  EXPECT_EQ(pop_frame(queue, &session), 1);
  EXPECT_EQ(pop_frame(queue, &session), 5);

  const auto telemetry = queue.unregister_session(&session);
  ASSERT_TRUE(telemetry);
  EXPECT_EQ(telemetry->dropped_frames, 3U);
  EXPECT_EQ(telemetry->overflow_events, 1U);
  EXPECT_EQ(telemetry->gated_drops, 1U);
  EXPECT_EQ(telemetry->replacement_drops, 1U);
  EXPECT_EQ(telemetry->recovery_requests, 1U);
  EXPECT_EQ(telemetry->recovery_restarts, 1U);
  EXPECT_EQ(telemetry->current_depth, 0U);
}

TEST(VideoEgressQueueTest, ReadySessionsAreServedRoundRobin) {
  video::egress_queue_t queue {3};
  int first_session {};
  int second_session {};

  ASSERT_TRUE(queue.register_session(&first_session, video::egress_queue_t::behavior_e::fifo, fifo_policy(3), {}));
  ASSERT_TRUE(queue.register_session(&second_session, video::egress_queue_t::behavior_e::fifo, fifo_policy(3), {}));

  EXPECT_EQ(queue.push(&first_session, make_frame(1)), video::egress_queue_t::enqueue_e::queued);
  EXPECT_EQ(queue.push(&first_session, make_frame(2)), video::egress_queue_t::enqueue_e::queued);
  EXPECT_EQ(queue.push(&second_session, make_frame(10)), video::egress_queue_t::enqueue_e::queued);
  EXPECT_EQ(queue.push(&second_session, make_frame(11)), video::egress_queue_t::enqueue_e::queued);

  EXPECT_EQ(pop_frame(queue, &first_session), 1);
  EXPECT_EQ(pop_frame(queue, &second_session), 10);
  EXPECT_EQ(pop_frame(queue, &first_session), 2);
  EXPECT_EQ(pop_frame(queue, &second_session), 11);

  EXPECT_TRUE(queue.unregister_session(&first_session));
  EXPECT_TRUE(queue.unregister_session(&second_session));
}

TEST(VideoEgressQueueTest, UnregisterWaitsForSenderLeaseAndDropsOnlyQueuedFrames) {
  video::egress_queue_t queue {2};
  int session {};
  ASSERT_TRUE(queue.register_session(&session, video::egress_queue_t::behavior_e::fifo, fifo_policy(2), {}));
  ASSERT_EQ(queue.push(&session, make_frame(1)), video::egress_queue_t::enqueue_e::queued);
  ASSERT_EQ(queue.push(&session, make_frame(2)), video::egress_queue_t::enqueue_e::queued);

  auto sender_lease = queue.pop();
  ASSERT_TRUE(sender_lease);
  auto unregister = std::async(std::launch::async, [&queue, &session]() {
    return queue.unregister_session(&session);
  });

  EXPECT_EQ(unregister.wait_for(20ms), std::future_status::timeout);
  sender_lease.reset();
  EXPECT_EQ(unregister.wait_for(1s), std::future_status::ready);

  const auto telemetry = unregister.get();
  ASSERT_TRUE(telemetry);
  EXPECT_EQ(telemetry->dequeued_frames, 1U);
  EXPECT_EQ(telemetry->lifecycle_drops, 1U);
  EXPECT_EQ(telemetry->dropped_frames, 1U);
  EXPECT_EQ(
    queue.push(&session, make_frame(3)),
    video::egress_queue_t::enqueue_e::unknown_session
  );

  queue.stop();
  EXPECT_FALSE(queue.pop());
  EXPECT_TRUE(queue.reset());
}

TEST(VideoEgressQueueTest, LatencyAgeDeadlineDropsChainAndRequiresFreshRestart) {
  video::egress_queue_t queue {32};
  int latency_session {};
  std::vector<video::egress_queue_t::recovery_request_t> recoveries;
  ASSERT_TRUE(queue.register_session(
    &latency_session,
    video::egress_queue_t::behavior_e::latency,
    latency_policy(2ms),
    [&recoveries](const auto &request) {
      recoveries.push_back(request);
    }
  ));

  EXPECT_EQ(queue.push(&latency_session, make_frame(1)), video::egress_queue_t::enqueue_e::queued);
  std::this_thread::sleep_for(5ms);
  EXPECT_FALSE(queue.pop_for(1ms));
  ASSERT_EQ(recoveries.size(), 1U);
  EXPECT_EQ(recoveries.front().first_frame, 1);
  EXPECT_EQ(recoveries.front().last_frame, 1);
  EXPECT_EQ(recoveries.front().dropped_frames, 1U);

  auto telemetry = queue.telemetry(&latency_session);
  ASSERT_TRUE(telemetry);
  EXPECT_EQ(telemetry->age_expiration_events, 1U);
  EXPECT_EQ(telemetry->expired_frames, 1U);
  EXPECT_EQ(telemetry->dropped_frames, 1U);
  EXPECT_GT(telemetry->last_expired_age, telemetry->configured_max_queue_age);
  EXPECT_GE(telemetry->max_expired_age, telemetry->last_expired_age);
  EXPECT_EQ(telemetry->current_depth, 0U);

  EXPECT_EQ(
    queue.push(&latency_session, make_frame(2)),
    video::egress_queue_t::enqueue_e::dropped_awaiting_recovery
  );
  EXPECT_EQ(
    queue.push(&latency_session, make_frame(3, true)),
    video::egress_queue_t::enqueue_e::queued_recovery
  );
  EXPECT_EQ(pop_frame(queue, &latency_session), 3);

  EXPECT_EQ(queue.push(&latency_session, make_frame(4)), video::egress_queue_t::enqueue_e::queued);
  std::this_thread::sleep_for(5ms);
  EXPECT_EQ(
    queue.push(&latency_session, make_frame(5)),
    video::egress_queue_t::enqueue_e::dropped_expired
  );
  ASSERT_EQ(recoveries.size(), 2U);
  EXPECT_EQ(recoveries.back().first_frame, 4);
  EXPECT_EQ(recoveries.back().last_frame, 5);
  EXPECT_EQ(recoveries.back().dropped_frames, 2U);
  EXPECT_EQ(
    queue.push(&latency_session, make_frame(6, false, true)),
    video::egress_queue_t::enqueue_e::queued_recovery
  );
  EXPECT_EQ(pop_frame(queue, &latency_session), 6);

  telemetry = queue.telemetry(&latency_session);
  ASSERT_TRUE(telemetry);
  EXPECT_EQ(telemetry->age_expiration_events, 2U);
  EXPECT_EQ(telemetry->expired_frames, 2U);
  EXPECT_TRUE(queue.unregister_session(&latency_session));
}

TEST(VideoEgressQueueTest, RegistrationRejectsLatencyWithoutOneFrameBoundAndDeadline) {
  video::egress_queue_t queue {32};
  int session {};
  EXPECT_FALSE(queue.register_session(
    &session,
    video::egress_queue_t::behavior_e::latency,
    {2, 1ms},
    {}
  ));
  EXPECT_FALSE(queue.register_session(
    &session,
    video::egress_queue_t::behavior_e::latency,
    {1, std::chrono::nanoseconds::zero()},
    {}
  ));
  EXPECT_FALSE(queue.register_session(
    &session,
    video::egress_queue_t::behavior_e::fifo,
    {32, 1ms},
    {}
  ));
}
