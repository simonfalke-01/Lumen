/**
 * @file tests/unit/test_lsp_host_forward_path.cpp
 * @brief Direct aggregate host-forward priority and protect-once retry checks.
 */

#include "src/protocol_lsp/runtime/host_forward_path.h"
#include "src/protocol_lsp/runtime/udp_socket.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <gtest/gtest.h>
#include <mutex>
#include <span>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace {
  using namespace std::chrono_literals;
  namespace lsp = lumen::lsp;
  namespace runtime = lumen::lsp::runtime;

  struct FakeForwardSocket {
    std::mutex mutex;
    std::condition_variable condition;
    std::vector<std::vector<std::uint8_t>> submissions;
    std::vector<std::pair<std::uint64_t, runtime::HostForwardLane>> completions;
    std::vector<std::tuple<std::uint64_t, runtime::HostForwardLane, std::uint64_t>> timed_completions;
    std::vector<std::pair<std::uint64_t, runtime::HostForwardCompletion>> terminal;
    std::vector<bool> pressure;
    bool would_block_once {};

    static runtime::UdpSendResult send(
      void *context,
      const lsp::PeerEndpoint &,
      const std::span<const std::uint8_t> datagram
    ) noexcept {
      auto &self = *static_cast<FakeForwardSocket *>(context);
      std::scoped_lock lock(self.mutex);
      self.submissions.emplace_back(datagram.begin(), datagram.end());
      if (std::exchange(self.would_block_once, false)) {
        self.condition.notify_all();
        return runtime::UdpSendResult::would_block;
      }
      self.condition.notify_all();
      return runtime::UdpSendResult::sent;
    }

    static void completed(
      void *context,
      const std::uint64_t token,
      const runtime::HostForwardLane lane,
      const runtime::HostForwardCompletion completion,
      const std::uint64_t completed_at_microseconds,
      const std::size_t,
      const std::uint16_t
    ) noexcept {
      auto &self = *static_cast<FakeForwardSocket *>(context);
      {
        std::scoped_lock lock(self.mutex);
        self.terminal.emplace_back(token, completion);
        if (completion == runtime::HostForwardCompletion::sent) {
          self.completions.emplace_back(token, lane);
          self.timed_completions.emplace_back(token, lane, completed_at_microseconds);
        }
      }
      self.condition.notify_all();
    }

    static void backpressure(void *context, const bool blocked) noexcept {
      auto &self = *static_cast<FakeForwardSocket *>(context);
      {
        std::scoped_lock lock(self.mutex);
        self.pressure.push_back(blocked);
      }
      self.condition.notify_all();
    }

    bool wait_for_completions(const std::size_t count) {
      std::unique_lock lock(mutex);
      return condition.wait_for(lock, 2s, [&]() {
        return completions.size() >= count;
      });
    }
  };

  static_assert(!std::is_copy_constructible_v<runtime::HostForwardLease>);
  static_assert(!std::is_copy_assignable_v<runtime::HostForwardLease>);
  static_assert(std::is_nothrow_move_constructible_v<runtime::HostForwardLease>);

  lsp::PeerEndpoint loopback_peer() {
    return {
      .family = lsp::IpAddressFamily::ipv4,
      .local_address = "127.0.0.1",
      .local_port = 48'030,
      .remote_address = "127.0.0.1",
      .remote_port = 49'001,
    };
  }

  runtime::HostForwardPath make_path(FakeForwardSocket &socket) {
    return runtime::HostForwardPath {{
      .peer = loopback_peer(),
      .generation = 7,
      .pacing_bits_per_second = 1'000'000'000,
      .path_payload_bytes = 1'200,
      .callbacks = {
        .context = &socket,
        .send_datagram = FakeForwardSocket::send,
        .completed = FakeForwardSocket::completed,
        .backpressure_changed = FakeForwardSocket::backpressure,
      },
    }};
  }

  runtime::HostForwardPath make_large_path(FakeForwardSocket &socket) {
    return runtime::HostForwardPath {{
      .peer = loopback_peer(),
      .generation = 8,
      .pacing_bits_per_second = 1'000'000'000,
      .path_payload_bytes = 1'400,
      .probe_payload_ceiling = 1'472,
      .callbacks = {
        .context = &socket,
        .send_datagram = FakeForwardSocket::send,
        .completed = FakeForwardSocket::completed,
        .backpressure_changed = FakeForwardSocket::backpressure,
      },
    }};
  }

  void fill_and_commit(
    runtime::HostForwardPath &path,
    const runtime::HostForwardLane lane,
    const std::uint8_t marker,
    const std::uint64_t token
  ) {
    auto lease = path.acquire(lane);
    ASSERT_TRUE(lease.has_value());
    ASSERT_GE(lease->storage.size(), 32U);
    std::ranges::fill(lease->storage.first(32), marker);
    ASSERT_EQ(path.commit(*lease, 32, 0, token), runtime::HostForwardSubmitResult::accepted);
  }
}  // namespace

TEST(LspHostForwardPath, AudioPreemptsQueuedVideoAndChargesCompleteIpBytes) {
  FakeForwardSocket socket;
  auto path = make_path(socket);
  ASSERT_TRUE(path.ready());

  fill_and_commit(path, runtime::HostForwardLane::video, 0x44, 1);
  fill_and_commit(path, runtime::HostForwardLane::audio, 0x22, 2);
  ASSERT_TRUE(path.start());
  ASSERT_TRUE(socket.wait_for_completions(2));
  path.close();
  path.join();

  ASSERT_EQ(socket.completions.size(), 2U);
  EXPECT_EQ(socket.completions[0].first, 2U);
  EXPECT_EQ(socket.completions[0].second, runtime::HostForwardLane::audio);
  EXPECT_EQ(socket.completions[1].first, 1U);
  const auto snapshot = path.snapshot();
  EXPECT_EQ(snapshot.sent_datagrams, 2U);
  EXPECT_EQ(snapshot.sent_protected_bytes, 64U);
  EXPECT_EQ(snapshot.sent_charged_bytes, 2U * (32U + 28U));
}

TEST(LspHostForwardPath, SharedCongestionFloorPreservesUrgentInputPreemption) {
  FakeForwardSocket socket;
  auto path = make_path(socket);
  ASSERT_TRUE(path.ready());

  fill_and_commit(path, runtime::HostForwardLane::congestion_feedback, 0xc1, 1);
  fill_and_commit(path, runtime::HostForwardLane::congestion_feedback, 0xc2, 2);
  fill_and_commit(path, runtime::HostForwardLane::video, 0x44, 3);
  fill_and_commit(path, runtime::HostForwardLane::input_feedback, 0x11, 4);
  ASSERT_TRUE(path.start());
  ASSERT_TRUE(socket.wait_for_completions(4));
  path.close();
  path.join();

  ASSERT_EQ(socket.completions.size(), 4U);
  EXPECT_EQ(socket.completions[0].first, 4U);
  ASSERT_EQ(socket.timed_completions.size(), 4U);
  const auto first_feedback = std::ranges::find_if(socket.timed_completions, [](const auto &completion) {
    return std::get<0>(completion) == 1U;
  });
  const auto second_feedback = std::ranges::find_if(socket.timed_completions, [](const auto &completion) {
    return std::get<0>(completion) == 2U;
  });
  ASSERT_NE(first_feedback, socket.timed_completions.end());
  ASSERT_NE(second_feedback, socket.timed_completions.end());
  EXPECT_GE(
    std::get<2>(*second_feedback) - std::get<2>(*first_feedback),
    500U
  );
}

TEST(LspHostForwardPath, LateQueuedCongestionFeedbackDoesNotRequireOtherTrafficToWake) {
  FakeForwardSocket socket;
  auto path = make_path(socket);
  ASSERT_TRUE(path.start());
  fill_and_commit(path, runtime::HostForwardLane::congestion_feedback, 0xc1, 1);
  ASSERT_TRUE(socket.wait_for_completions(1));
  fill_and_commit(path, runtime::HostForwardLane::congestion_feedback, 0xc2, 2);
  ASSERT_TRUE(socket.wait_for_completions(2));
  path.close();
  path.join();
  ASSERT_EQ(socket.timed_completions.size(), 2U);
  EXPECT_GE(std::get<2>(socket.timed_completions[1]) - std::get<2>(socket.timed_completions[0]), 500U);
}

TEST(LspHostForwardPath, WouldBlockRetriesIdenticalProtectedBytesWithoutRecharging) {
  FakeForwardSocket socket;
  socket.would_block_once = true;
  auto path = make_path(socket);
  ASSERT_TRUE(path.start());
  fill_and_commit(path, runtime::HostForwardLane::video, 0xa5, 9);
  ASSERT_TRUE(socket.wait_for_completions(1));
  path.close();
  path.join();

  ASSERT_EQ(socket.submissions.size(), 2U);
  EXPECT_EQ(socket.submissions[0], socket.submissions[1]);
  ASSERT_EQ(socket.pressure.size(), 2U);
  EXPECT_TRUE(socket.pressure[0]);
  EXPECT_FALSE(socket.pressure[1]);
  const auto snapshot = path.snapshot();
  EXPECT_EQ(snapshot.would_block_events, 1U);
  EXPECT_EQ(snapshot.sent_datagrams, 1U);
  EXPECT_EQ(snapshot.sent_charged_bytes, 32U + 28U);
}

TEST(LspHostForwardPath, CloseDoesNotInvalidateAnOutstandingDirectWriteLease) {
  FakeForwardSocket socket;
  auto path = make_path(socket);
  auto lease = path.acquire(runtime::HostForwardLane::video);
  ASSERT_TRUE(lease.has_value());
  std::ranges::fill(lease->storage.first(64), 0x6c);

  path.close();
  EXPECT_TRUE(std::ranges::all_of(lease->storage.first(64), [](const std::uint8_t value) {
    return value == 0x6c;
  }));
  EXPECT_EQ(path.commit(*lease, 64, 0, 4), runtime::HostForwardSubmitResult::closed);
  path.join();
}

TEST(LspHostForwardPath, PmtuDecreaseRetiresQueuedOversizeMediaButRetainsProbeCeiling) {
  FakeForwardSocket socket;
  auto path = make_large_path(socket);
  auto lease = path.acquire(runtime::HostForwardLane::video);
  ASSERT_TRUE(lease.has_value());
  std::ranges::fill(lease->storage.first(1'300), 0x31);
  ASSERT_EQ(path.commit(*lease, 1'300, 0, 33), runtime::HostForwardSubmitResult::accepted);

  ASSERT_TRUE(path.reconfigure(500'000'000, 1'200));
  ASSERT_EQ(socket.terminal.size(), 1U);
  EXPECT_EQ(socket.terminal[0].first, 33U);
  EXPECT_EQ(socket.terminal[0].second, runtime::HostForwardCompletion::message_too_large);
  const auto snapshot = path.snapshot();
  EXPECT_EQ(snapshot.path_payload_bytes, 1'200U);
  EXPECT_EQ(snapshot.probe_payload_ceiling, 1'472U);

  auto probe = path.acquire(runtime::HostForwardLane::path_probe);
  ASSERT_TRUE(probe.has_value());
  std::ranges::fill(probe->storage.first(1'400), 0x7f);
  EXPECT_EQ(path.commit(*probe, 1'400, 0, 34), runtime::HostForwardSubmitResult::accepted);
  path.close();
  path.join();
}

TEST(LspHostForwardPath, BulkCannotConsumeVideoRecoveryOrCongestionFeedbackReservations) {
  FakeForwardSocket socket;
  auto path = make_path(socket);
  std::array<std::optional<runtime::HostForwardLease>, 4> bulk;
  for (auto &lease : bulk) {
    lease = path.acquire(runtime::HostForwardLane::bulk);
    ASSERT_TRUE(lease.has_value());
  }
  EXPECT_FALSE(path.acquire(runtime::HostForwardLane::bulk).has_value());
  EXPECT_TRUE(path.acquire(runtime::HostForwardLane::video).has_value());
  EXPECT_TRUE(path.acquire(runtime::HostForwardLane::recovery).has_value());
  EXPECT_TRUE(path.acquire(runtime::HostForwardLane::path_probe).has_value());
  EXPECT_TRUE(path.acquire(runtime::HostForwardLane::congestion_feedback).has_value());
}

TEST(LspHostForwardPath, WrongOwnerCannotDisarmOrCommitAnotherPathsLease) {
  FakeForwardSocket socket_a;
  FakeForwardSocket socket_b;
  auto path_a = make_path(socket_a);
  auto path_b = make_path(socket_b);
  auto lease_a = path_a.acquire(runtime::HostForwardLane::video);
  auto lease_b = path_b.acquire(runtime::HostForwardLane::video);
  ASSERT_TRUE(lease_a.has_value());
  ASSERT_TRUE(lease_b.has_value());
  std::ranges::fill(lease_a->storage.first(32), 0xaa);
  std::ranges::fill(lease_b->storage.first(32), 0xbb);

  EXPECT_EQ(path_b.commit(*lease_a, 32, 0, 41), runtime::HostForwardSubmitResult::invalid);
  EXPECT_TRUE(lease_a->valid());
  path_b.cancel(*lease_a);
  EXPECT_TRUE(lease_a->valid());
  EXPECT_TRUE(std::ranges::all_of(lease_b->storage.first(32), [](const std::uint8_t value) {
    return value == 0xbb;
  }));

  EXPECT_EQ(path_a.commit(*lease_a, 32, 0, 42), runtime::HostForwardSubmitResult::accepted);
  EXPECT_EQ(path_b.commit(*lease_b, 32, 0, 43), runtime::HostForwardSubmitResult::accepted);
  path_a.close();
  path_b.close();
  path_a.join();
  path_b.join();
}

TEST(LspHostForwardPath, DeadlineAwareAcquireStreamsFramesLargerThanSlotCapacity) {
  FakeForwardSocket socket;
  auto path = make_path(socket);
  for (std::uint64_t token = 1; token <= 16; ++token) {
    fill_and_commit(path, runtime::HostForwardLane::video, static_cast<std::uint8_t>(token), token);
  }
  EXPECT_FALSE(path.acquire(runtime::HostForwardLane::video).has_value());
  ASSERT_TRUE(path.start());

  const auto deadline = runtime::monotonic_microseconds() + 1'000'000U;
  auto streamed = path.acquire_until(runtime::HostForwardLane::video, deadline);
  ASSERT_TRUE(streamed.has_value());
  path.cancel(*streamed);
  ASSERT_TRUE(socket.wait_for_completions(16));
  path.close();
  path.join();
}

TEST(LspHostForwardPath, ProducerCompletionTargetBypassesGlobalLookup) {
  FakeForwardSocket global;
  FakeForwardSocket producer;
  auto path = make_path(global);
  ASSERT_TRUE(path.start());
  auto lease = path.acquire(runtime::HostForwardLane::audio);
  ASSERT_TRUE(lease.has_value());
  std::ranges::fill(lease->storage.first(32), 0x5a);
  ASSERT_EQ(
    path.commit(
      *lease,
      32,
      0,
      77,
      {.context = &producer, .completed = FakeForwardSocket::completed}
    ),
    runtime::HostForwardSubmitResult::accepted
  );
  ASSERT_TRUE(producer.wait_for_completions(1));
  path.close();
  path.join();
  EXPECT_TRUE(global.completions.empty());
  ASSERT_EQ(producer.completions.size(), 1U);
  EXPECT_EQ(producer.completions[0].first, 77U);
}
