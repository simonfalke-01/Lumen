/**
 * @file tests/unit/test_protocol_v3_response_cache.cpp
 * @brief Exact response-retirement and host-pressure tests for protocol v3.
 */

#include "src/protocol_v3/control_session.h"

#include <array>
#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <vector>

namespace {
  namespace control = lumen::protocol_v3::control_session;
  namespace quic = lumen::protocol_v3::quic_server;

  std::shared_ptr<const std::vector<std::uint8_t>> bytes(
    const std::size_t size,
    const std::uint8_t fill = 0x5a
  ) {
    return std::make_shared<const std::vector<std::uint8_t>>(size, fill);
  }

  TEST(ProtocolV3ResponseCache, ExactReplayConflictAndRetiredFloorAreStable) {
    control::ResponseCacheCoordinator cache;
    const auto started = quic::MonotonicClock::time_point {};
    const std::array<std::uint8_t, 3> request {1, 2, 3};

    auto admitted = cache.reserve(11, 1, request, 64, started);
    ASSERT_EQ(admitted.decision, control::ResponseCacheCoordinator::Decision::reserved);
    ASSERT_TRUE(admitted.reservation);
    const auto response = bytes(12);
    ASSERT_TRUE(cache.commit(std::move(*admitted.reservation), response, started));

    const auto replay = cache.reserve(11, 1, request, 64, started + std::chrono::seconds {119});
    EXPECT_EQ(replay.decision, control::ResponseCacheCoordinator::Decision::replay);
    EXPECT_EQ(replay.replay, response);

    const std::array<std::uint8_t, 3> conflict {1, 2, 4};
    EXPECT_EQ(
      cache.reserve(11, 1, conflict, 64, started + std::chrono::seconds {119}).decision,
      control::ResponseCacheCoordinator::Decision::request_id_conflict
    );
    EXPECT_EQ(
      cache.reserve(11, 1, request, 64, started + std::chrono::seconds {120}).decision,
      control::ResponseCacheCoordinator::Decision::retired
    );
  }

  TEST(ProtocolV3ResponseCache, EntryRetirementAllowsMoreThanOneThousandRequests) {
    control::ResponseCacheCoordinator cache;
    const auto now = quic::MonotonicClock::time_point {};
    for (std::uint64_t request_number = 1; request_number <= 1'001; ++request_number) {
      const auto request_id = request_number * 2 - 1;
      const std::array<std::uint8_t, 8> request {
        static_cast<std::uint8_t>(request_id >> 56U),
        static_cast<std::uint8_t>(request_id >> 48U),
        static_cast<std::uint8_t>(request_id >> 40U),
        static_cast<std::uint8_t>(request_id >> 32U),
        static_cast<std::uint8_t>(request_id >> 24U),
        static_cast<std::uint8_t>(request_id >> 16U),
        static_cast<std::uint8_t>(request_id >> 8U),
        static_cast<std::uint8_t>(request_id),
      };
      auto admission = cache.reserve(22, request_id, request, 64, now);
      ASSERT_EQ(admission.decision, control::ResponseCacheCoordinator::Decision::reserved);
      ASSERT_TRUE(admission.reservation);
      ASSERT_TRUE(cache.commit(std::move(*admission.reservation), bytes(16), now));
    }
    const std::array<std::uint8_t, 8> first {0, 0, 0, 0, 0, 0, 0, 1};
    EXPECT_EQ(
      cache.reserve(22, 1, first, 64, now).decision,
      control::ResponseCacheCoordinator::Decision::retired
    );
  }

  TEST(ProtocolV3ResponseCache, LocalAndHostBytePressureEvictOldestCompletedEntries) {
    control::ResponseCacheCoordinator cache;
    const auto now = quic::MonotonicClock::time_point {};
    const std::array<std::uint8_t, 1> request {1};
    constexpr std::size_t large_response = 920U * 1024U;

    for (std::uint64_t connection = 1; connection <= 9; ++connection) {
      auto admission = cache.reserve(connection, 1, request, large_response, now);
      ASSERT_EQ(admission.decision, control::ResponseCacheCoordinator::Decision::reserved);
      ASSERT_TRUE(cache.commit(std::move(*admission.reservation), bytes(large_response), now));
    }
    EXPECT_EQ(
      cache.reserve(1, 1, request, 64, now).decision,
      control::ResponseCacheCoordinator::Decision::retired
    );

    auto second = cache.reserve(9, 2, request, 200U * 1024U, now);
    ASSERT_EQ(second.decision, control::ResponseCacheCoordinator::Decision::reserved);
    ASSERT_TRUE(cache.commit(std::move(*second.reservation), bytes(200U * 1024U), now));
    EXPECT_EQ(
      cache.reserve(9, 1, request, 64, now).decision,
      control::ResponseCacheCoordinator::Decision::retired
    );
  }

  TEST(ProtocolV3ResponseCache, ReservationCancellationAndDisconnectReleaseCapacity) {
    control::ResponseCacheCoordinator cache;
    const auto now = quic::MonotonicClock::time_point {};
    const std::array<std::uint8_t, 1> request {1};
    {
      auto admission = cache.reserve(44, 1, request, 900U * 1024U, now);
      ASSERT_EQ(admission.decision, control::ResponseCacheCoordinator::Decision::reserved);
    }
    auto retried = cache.reserve(44, 1, request, 900U * 1024U, now);
    ASSERT_EQ(retried.decision, control::ResponseCacheCoordinator::Decision::reserved);
    ASSERT_TRUE(cache.commit(std::move(*retried.reservation), bytes(900U * 1024U), now));
    cache.disconnect(44);
    EXPECT_EQ(
      cache.reserve(44, 1, request, 900U * 1024U, now).decision,
      control::ResponseCacheCoordinator::Decision::reserved
    );
  }

  TEST(ProtocolV3ResponseCache, SharedHostBudgetObservesCacheChargeAndDisconnectRelease) {
    auto budget = std::make_shared<lumen::protocol_v3::resource_budget::ResourceBudgetCoordinator>();
    control::ResponseCacheCoordinator cache {budget};
    const auto now = quic::MonotonicClock::time_point {};
    const std::array<std::uint8_t, 2> request {1, 2};
    auto admission = cache.reserve(55, 1, request, 1'024, now);
    ASSERT_EQ(admission.decision, control::ResponseCacheCoordinator::Decision::reserved);
    ASSERT_TRUE(cache.commit(std::move(*admission.reservation), bytes(16), now));
    const auto class_index = static_cast<std::size_t>(
      lumen::protocol_v3::resource_budget::ResourceClass::cached_responses
    );
    EXPECT_GT(budget->snapshot().classes[class_index].current, 0U);
    cache.disconnect(55);
    EXPECT_EQ(budget->snapshot().classes[class_index].current, 0U);
  }
}  // namespace
