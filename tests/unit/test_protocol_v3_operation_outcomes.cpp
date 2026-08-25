/** @file Bounded cross-connection protocol-v3 START/STOP outcome-store tests. */

#include "src/protocol_v3/operation_outcomes.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>

namespace {
  namespace outcomes = lumen::protocol_v3::operation_outcomes;
  namespace control = lumen::protocol_v3::control_session;

  outcomes::Identifier identifier(const std::uint8_t value) {
    outcomes::Identifier output {};
    output.back() = value == 0 ? 1 : value;
    return output;
  }

  outcomes::Identifier indexed_identifier(const std::size_t value) {
    outcomes::Identifier output {};
    output[output.size() - 2] = static_cast<std::uint8_t>((value >> 8U) & 0xffU);
    output.back() = static_cast<std::uint8_t>(value & 0xffU);
    if (output[output.size() - 2] == 0 && output.back() == 0) {
      output.back() = 1;
    }
    return output;
  }

  outcomes::Digest digest(const std::uint8_t value) {
    outcomes::Digest output {};
    output.back() = value == 0 ? 1 : value;
    return output;
  }

  outcomes::Replay replay(const std::size_t bytes) {
    return {
      .fields = control::cbor::Value::Map {{1, 0U}, {2, 1U}},
      .encoded_bytes = bytes,
    };
  }

  TEST(ProtocolV3OperationOutcomes, StopsFillExactly256AndThe257thFailsBeforeMutation) {
    outcomes::Store store;
    const auto now = outcomes::Clock::time_point {};
    const auto client = identifier(1);
    const auto session = identifier(2);
    for (std::size_t index = 1; index <= outcomes::Store::maximum_records; ++index) {
      EXPECT_EQ(store.begin_stop(client, indexed_identifier(index), digest(static_cast<std::uint8_t>(index)), session, now).match, outcomes::Match::inserted);
    }
    EXPECT_EQ(store.size(), 256U);
    EXPECT_EQ(
      store.begin_stop(client, identifier(1), digest(0x7f), identifier(3), now).match,
      outcomes::Match::conflict
    );
    EXPECT_EQ(
      store.begin_stop(identifier(4), identifier(1), digest(4), identifier(5), now).match,
      outcomes::Match::saturated
    );
    EXPECT_EQ(store.size(), 256U);
  }

  TEST(ProtocolV3OperationOutcomes, ReplayByteLimitAdmitsBelowAndAtButRejectsAbove) {
    const auto now = outcomes::Clock::time_point {};
    const auto client = identifier(1);
    const auto token = identifier(2);
    const auto session = identifier(3);
    const auto key_digest = digest(4);

    constexpr auto exact_payload_cap =
      outcomes::Store::maximum_replay_bytes - outcomes::Store::fixed_record_charge;
    for (const auto bytes : {exact_payload_cap - 1, exact_payload_cap}) {
      outcomes::Store store;
      ASSERT_EQ(store.begin_stop(client, token, key_digest, session, now).match, outcomes::Match::inserted);
      EXPECT_TRUE(store.complete(outcomes::Operation::stop, client, token, key_digest, replay(bytes), now));
      EXPECT_EQ(store.replay_bytes(), bytes);
    }

    outcomes::Store store;
    ASSERT_EQ(store.begin_stop(client, token, key_digest, session, now).match, outcomes::Match::inserted);
    EXPECT_FALSE(store.complete(
      outcomes::Operation::stop,
      client,
      token,
      key_digest,
      replay(exact_payload_cap + 1),
      now
    ));
    const auto current = store.lookup(outcomes::Operation::stop, client, token, key_digest, now);
    EXPECT_EQ(current.match, outcomes::Match::exact);
    EXPECT_EQ(current.state, outcomes::State::active);
    EXPECT_EQ(store.replay_bytes(), 0U);
  }

  TEST(ProtocolV3OperationOutcomes, TerminalTtlIsExactly600SecondsWithoutLookupExtension) {
    outcomes::Store store;
    const auto now = outcomes::Clock::time_point {};
    const auto client = identifier(1);
    const auto token = identifier(2);
    const auto key_digest = digest(3);
    ASSERT_EQ(store.begin_stop(client, token, key_digest, identifier(4), now).match, outcomes::Match::inserted);
    ASSERT_TRUE(store.complete(outcomes::Operation::stop, client, token, key_digest, replay(7), now));
    EXPECT_EQ(store.lookup(outcomes::Operation::stop, client, token, key_digest, now + std::chrono::milliseconds {599999}).match, outcomes::Match::exact);
    EXPECT_EQ(store.lookup(outcomes::Operation::stop, client, token, key_digest, now + std::chrono::milliseconds {600000}).match, outcomes::Match::missing);
    EXPECT_EQ(store.lookup(outcomes::Operation::stop, client, token, key_digest, now + std::chrono::milliseconds {600001}).match, outcomes::Match::missing);
  }

  TEST(ProtocolV3OperationOutcomes, ExactDigestReplaysAndDifferentDigestConflicts) {
    outcomes::Store store;
    const auto now = outcomes::Clock::time_point {};
    const auto client = identifier(1);
    const auto token = identifier(2);
    const auto key_digest = digest(3);
    ASSERT_EQ(store.begin_stop(client, token, key_digest, identifier(4), now).match, outcomes::Match::inserted);
    ASSERT_TRUE(store.complete(outcomes::Operation::stop, client, token, key_digest, replay(13), now));
    const auto exact = store.lookup(outcomes::Operation::stop, client, token, key_digest, now + std::chrono::seconds {1});
    EXPECT_EQ(exact.match, outcomes::Match::exact);
    ASSERT_TRUE(exact.replay.has_value());
    EXPECT_EQ(exact.replay->encoded_bytes, 13U);
    EXPECT_EQ(store.lookup(outcomes::Operation::stop, client, token, digest(4), now).match, outcomes::Match::conflict);
  }

  TEST(ProtocolV3OperationOutcomes, ActiveRecordsAreNeverEvictedToMakeRoom) {
    outcomes::Store store;
    const auto now = outcomes::Clock::time_point {};
    for (std::size_t index = 1; index <= outcomes::Store::maximum_records; ++index) {
      ASSERT_EQ(
        store.begin_stop(identifier(1), indexed_identifier(index), digest(static_cast<std::uint8_t>(index)), identifier(2), now).match,
        outcomes::Match::inserted
      );
    }
    EXPECT_EQ(
      store.begin_stop(identifier(3), identifier(4), digest(5), identifier(6), now).match,
      outcomes::Match::saturated
    );
    EXPECT_EQ(store.size(), outcomes::Store::maximum_records);
  }

  TEST(ProtocolV3OperationOutcomes, StartReservesAndStopConsumesOneSlot) {
    outcomes::Store store;
    const auto now = outcomes::Clock::time_point {};
    const auto client = identifier(1);
    const auto session = identifier(2);
    ASSERT_EQ(store.begin_start(client, identifier(3), digest(4), session, now).match, outcomes::Match::inserted);
    EXPECT_EQ(store.size(), 1U);
    EXPECT_EQ(store.reserved_stop_slots(), 1U);
    EXPECT_EQ(store.begin_stop(client, identifier(5), digest(6), session, now).match, outcomes::Match::inserted);
    EXPECT_EQ(store.size(), 2U);
    EXPECT_EQ(store.reserved_stop_slots(), 0U);
  }

  TEST(ProtocolV3OperationOutcomes, LookupDoesNotDependOnConnectionAuthority) {
    outcomes::Store store;
    const auto now = outcomes::Clock::time_point {};
    const auto client = identifier(1);
    const auto intent = identifier(2);
    const auto key_digest = digest(3);
    ASSERT_EQ(store.begin_start(client, intent, key_digest, identifier(4), now).match, outcomes::Match::inserted);
    ASSERT_TRUE(store.complete(outcomes::Operation::start, client, intent, key_digest, replay(9), now));
    EXPECT_EQ(store.lookup(outcomes::Operation::start, client, intent, key_digest, now).match, outcomes::Match::exact);
  }

  TEST(ProtocolV3OperationOutcomes, SessionEndTerminalizesActiveOutcomesAndReleasesReservation) {
    outcomes::Store store;
    const auto now = outcomes::Clock::time_point {};
    const auto client = identifier(1);
    const auto intent = identifier(2);
    const auto session = identifier(3);
    const auto key_digest = digest(4);
    ASSERT_EQ(store.begin_start(client, intent, key_digest, session, now).match, outcomes::Match::inserted);
    store.end_session(session, now + std::chrono::milliseconds {1});
    const auto result = store.lookup(outcomes::Operation::start, client, intent, key_digest, now + std::chrono::milliseconds {1});
    EXPECT_EQ(result.match, outcomes::Match::exact);
    EXPECT_EQ(result.state, outcomes::State::expired);
    EXPECT_EQ(store.reserved_stop_slots(), 0U);
  }

  TEST(ProtocolV3OperationOutcomes, StopReservationBindsOnlyItsOriginatingStartIntent) {
    outcomes::Store store;
    const auto now = outcomes::Clock::time_point {};
    const auto client = identifier(1);
    const auto first_intent = identifier(2);
    const auto second_intent = identifier(3);
    const auto first_digest = digest(4);
    const auto second_digest = digest(5);
    const auto first_session = identifier(6);
    const auto second_session = identifier(7);
    const outcomes::Identifier unbound {};

    ASSERT_EQ(
      store.begin_start(client, first_intent, first_digest, unbound, now).match,
      outcomes::Match::inserted
    );
    ASSERT_EQ(
      store.begin_start(client, second_intent, second_digest, unbound, now).match,
      outcomes::Match::inserted
    );
    ASSERT_EQ(store.reserved_stop_slots(), 2U);
    ASSERT_TRUE(store.bind_start_session(client, second_intent, second_digest, second_session));
    EXPECT_EQ(
      store.begin_stop(client, identifier(8), digest(8), second_session, now).match,
      outcomes::Match::inserted
    );
    EXPECT_EQ(store.reserved_stop_slots(), 1U);
    EXPECT_TRUE(store.bind_start_session(client, first_intent, first_digest, first_session));
  }
}  // namespace
