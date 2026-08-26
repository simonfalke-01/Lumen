/**
 * @file tests/unit/test_protocol_v3_response_cache.cpp
 * @brief Exact response-retirement and host-pressure tests for protocol v3.
 */

#include "src/protocol_v3/control_session.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <expected>
#include <gtest/gtest.h>
#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace {
  namespace control = lumen::protocol_v3::control_session;
  namespace quic = lumen::protocol_v3::quic_server;

  class FixedRandom final: public control::Random {
  public:
    bool fill(const std::span<std::uint8_t> output) noexcept override {
      std::ranges::fill(output, 0x5a);
      return true;
    }
  };

  class UnusedAuthorization final: public control::AuthorizationStore {
  public:
    std::optional<control::ClientRecord> paired_client(const control::Identifier &) override {
      return std::nullopt;
    }
    std::expected<control::ClientRecord, std::uint8_t> consume_invitation(
      const control::PairingClaim &
    ) override {
      return std::unexpected(std::uint8_t {1});
    }
  };

  class UnusedNonces final: public control::NonceRegistry {
  public:
    bool claim(
      const quic::RemoteSourcePrefix &,
      const control::Identifier &,
      const control::Bytes32 &,
      quic::MonotonicClock::time_point
    ) noexcept override {
      return true;
    }
  };

  class UnusedPairing final: public control::PairingAdmission {
  public:
    bool admit_hello(
      const quic::RemoteSourcePrefix &,
      const control::Identifier &,
      quic::MonotonicClock::time_point
    ) noexcept override {
      return true;
    }
    bool admit(
      const quic::RemoteSourcePrefix &,
      const control::Identifier &,
      quic::MonotonicClock::time_point
    ) noexcept override {
      return true;
    }
  };

  class CountingPingBackend final: public control::SessionBackend {
  public:
    std::expected<control::StartResult, std::uint8_t> start(
      const control::ClientRecord &,
      const control::cbor::Value::Map &,
      std::uint64_t,
      std::uint16_t
    ) override {
      return std::unexpected(std::uint8_t {11});
    }

    std::expected<control::ControlResult, std::uint8_t> control(
      const control::ClientRecord &,
      const control::AuthenticatedControl request,
      const control::cbor::Value::Map &fields,
      std::uint64_t,
      std::uint64_t,
      std::uint64_t
    ) override {
      ++control_calls;
      if (request != control::AuthenticatedControl::ping || fields.size() != 2) {
        return std::unexpected(std::uint8_t {1});
      }
      const auto *client_send = std::get_if<std::uint64_t>(&fields[0].second.storage);
      const auto *probe = std::get_if<std::uint64_t>(&fields[1].second.storage);
      if (!client_send || !probe) {
        return std::unexpected(std::uint8_t {1});
      }
      return control::ControlResult {
        request,
        {{1, *client_send}, {2, *probe}, {3, 1U}, {4, 2U}},
      };
    }

    std::optional<control::Identifier> owned_session(const control::ClientRecord &) override {
      return std::nullopt;
    }
    bool acknowledge_configuration(
      const control::ClientRecord &,
      control::ConfigurationAcknowledgement,
      const control::Identifier &,
      std::uint32_t,
      std::optional<std::uint32_t>
    ) override {
      return false;
    }
    bool start_media(const control::ClientRecord &, const control::Identifier &) override { return false; }
    void datagram(const control::ClientRecord &, const quic::DatagramRecord &) override {}
    void revoke_connection(std::uint64_t) noexcept override {}
    void disconnect(const std::optional<control::Identifier> &, std::uint64_t) noexcept override {}

    std::size_t control_calls {};
  };

  std::vector<std::uint8_t> encoded_ping(
    const std::uint64_t request_id,
    const std::uint64_t value
  ) {
    const auto payload = control::cbor::encode(control::cbor::Value {
      control::cbor::Value::Map {{1, value}, {2, value}},
    });
    EXPECT_TRUE(payload);
    std::vector<std::uint8_t> output {'U', 'L', 'C', '3', 3, 0, 0, 5};
    const auto append = [&output](const std::uint64_t integer, std::size_t count) {
      while (count-- != 0) {
        output.push_back(static_cast<std::uint8_t>(integer >> (count * 8U)));
      }
    };
    append(request_id, 8);
    append(payload.bytes.size(), 4);
    append(0, 4);
    output.insert(output.end(), payload.bytes.begin(), payload.bytes.end());
    return output;
  }

  struct ControlFixture {
    explicit ControlFixture(control::Config config = {}):
        identity {seed} {
      quic::ConnectionContext connection {
        .connection_id = 77,
        .local_udp_port = 48'021,
        .maximum_datagram_bytes = quic::maximum_semantic_datagram_bytes,
        .profile = quic::Profile::quality,
        .connected_at = quic::MonotonicClock::now(),
      };
      connection.leaf_spki_sha256.fill(0x33);
      session = std::make_unique<control::ControlSession>(
        connection,
        std::move(config),
        random,
        identity,
        authorization,
        nonces,
        pairing,
        authorities,
        backend
      );
      control::ClientRecord client {
        .permissions = control::browse_permission | control::start_permission,
        .generation = 1,
      };
      client.client_id.fill(0x51);
      client.public_key.fill(0x52);
      EXPECT_TRUE(session->install_authenticated_client_for_test(client));
    }

    std::shared_ptr<const std::vector<std::uint8_t>> ping(
      const std::uint64_t request_id,
      const std::uint64_t value
    ) {
      const auto encoded = encoded_ping(request_id, value);
      const auto parsed = quic::parse_control_frame(encoded);
      EXPECT_TRUE(parsed);
      if (!parsed) {
        return {};
      }
      const auto responses = session->control(*parsed);
      EXPECT_EQ(responses.size(), 1U);
      return responses.empty() ? nullptr : responses.front();
    }

    FixedRandom random;
    control::Bytes32 seed {[] {
      control::Bytes32 value {};
      value.fill(0x41);
      return value;
    }()};
    control::SeedHostIdentity identity;
    UnusedAuthorization authorization;
    UnusedNonces nonces;
    UnusedPairing pairing;
    control::ConnectionAuthorities authorities;
    CountingPingBackend backend;
    std::unique_ptr<control::ControlSession> session;
  };

  std::shared_ptr<const std::vector<std::uint8_t>> bytes(
    const std::size_t size,
    const std::uint8_t fill = 0x5a
  ) {
    return std::make_shared<const std::vector<std::uint8_t>>(size, fill);
  }

  TEST(ProtocolV3ResponseCache, TtlBoundaryIsExactAt119999120000And120001Milliseconds) {
    const std::array<std::uint8_t, 1> request {1};
    const auto started = quic::MonotonicClock::time_point {};
    for (const auto [elapsed, expected] : std::array {
           std::pair {std::chrono::milliseconds {119'999}, control::ResponseCacheCoordinator::Decision::replay},
           std::pair {std::chrono::milliseconds {120'000}, control::ResponseCacheCoordinator::Decision::retired},
           std::pair {std::chrono::milliseconds {120'001}, control::ResponseCacheCoordinator::Decision::retired},
         }) {
      control::ResponseCacheCoordinator cache;
      auto admission = cache.reserve(1, 1, request, 64, started);
      ASSERT_EQ(admission.decision, control::ResponseCacheCoordinator::Decision::reserved);
      ASSERT_TRUE(cache.commit(std::move(*admission.reservation), bytes(8), started));
      EXPECT_EQ(cache.reserve(1, 1, request, 64, started + elapsed).decision, expected);
    }
  }

  TEST(ProtocolV3ResponseCache, CountBoundaryRetains127And128ThenRetiresOldestAt129) {
    control::ResponseCacheCoordinator cache;
    const auto now = quic::MonotonicClock::time_point {};
    const auto commit = [&](const std::uint64_t request_id) {
      const std::array<std::uint8_t, 8> request {
        0, 0, 0, 0, 0, 0,
        static_cast<std::uint8_t>(request_id >> 8U),
        static_cast<std::uint8_t>(request_id),
      };
      auto admission = cache.reserve(2, request_id, request, 64, now);
      ASSERT_EQ(admission.decision, control::ResponseCacheCoordinator::Decision::reserved);
      ASSERT_TRUE(cache.commit(std::move(*admission.reservation), bytes(8), now));
    };
    const std::array<std::uint8_t, 8> first {0, 0, 0, 0, 0, 0, 0, 1};
    const std::array<std::uint8_t, 8> second {0, 0, 0, 0, 0, 0, 0, 3};

    for (std::uint64_t number = 1; number <= 127; ++number) {
      commit(number * 2 - 1);
    }
    EXPECT_EQ(cache.reserve(2, 1, first, 64, now).decision, control::ResponseCacheCoordinator::Decision::replay);
    commit(255);
    EXPECT_EQ(cache.reserve(2, 1, first, 64, now).decision, control::ResponseCacheCoordinator::Decision::replay);
    commit(257);
    EXPECT_EQ(cache.reserve(2, 1, first, 64, now).decision, control::ResponseCacheCoordinator::Decision::retired);
    EXPECT_EQ(cache.reserve(2, 3, second, 64, now).decision, control::ResponseCacheCoordinator::Decision::replay);
  }

  TEST(ProtocolV3ResponseCache, ConnectionByteBoundaryAdmitsBelowAndAtButRejectsAboveOneMiB) {
    const std::array<std::uint8_t, 1> request {1};
    const auto now = quic::MonotonicClock::time_point {};
    constexpr auto exact_response = control::ResponseCacheCoordinator::maximum_bytes_per_connection -
                                    control::ResponseCacheCoordinator::fixed_entry_charge - 1U;
    for (const auto [response_size, expected] : std::array {
           std::pair {exact_response - 1, control::ResponseCacheCoordinator::Decision::reserved},
           std::pair {exact_response, control::ResponseCacheCoordinator::Decision::reserved},
           std::pair {exact_response + 1, control::ResponseCacheCoordinator::Decision::resource_limit},
         }) {
      control::ResponseCacheCoordinator cache;
      auto admission = cache.reserve(3, 1, request, response_size, now);
      ASSERT_EQ(admission.decision, expected);
      if (admission.reservation) {
        EXPECT_TRUE(cache.commit(std::move(*admission.reservation), bytes(response_size), now));
      }
    }
  }

  TEST(ProtocolV3ResponseCache, HostByteBoundaryAdmitsBelowAndAtThenEvictsGlobalOldestAboveEightMiB) {
    const std::array<std::uint8_t, 1> request {1};
    const auto started = quic::MonotonicClock::time_point {};
    constexpr auto exact_response = control::ResponseCacheCoordinator::maximum_bytes_per_connection -
                                    control::ResponseCacheCoordinator::fixed_entry_charge - 1U;
    const auto fill = [&](control::ResponseCacheCoordinator &cache, const std::size_t connections, const std::size_t last_size) {
      for (std::size_t index = 0; index < connections; ++index) {
        const auto response_size = index + 1 == connections ? last_size : exact_response;
        auto admission = cache.reserve(
          index + 1,
          1,
          request,
          response_size,
          started + std::chrono::milliseconds {static_cast<std::int64_t>(index)}
        );
        ASSERT_EQ(admission.decision, control::ResponseCacheCoordinator::Decision::reserved);
        ASSERT_TRUE(cache.commit(
          std::move(*admission.reservation),
          bytes(response_size),
          started + std::chrono::milliseconds {static_cast<std::int64_t>(index)}
        ));
      }
    };

    control::ResponseCacheCoordinator below;
    fill(below, 8, exact_response - 1);
    EXPECT_EQ(below.reserve(1, 1, request, 64, started).decision, control::ResponseCacheCoordinator::Decision::replay);

    control::ResponseCacheCoordinator exact;
    fill(exact, 8, exact_response);
    EXPECT_EQ(exact.reserve(1, 1, request, 64, started).decision, control::ResponseCacheCoordinator::Decision::replay);

    auto above = exact.reserve(9, 1, request, 1, started + std::chrono::milliseconds {8});
    ASSERT_EQ(above.decision, control::ResponseCacheCoordinator::Decision::reserved);
    ASSERT_TRUE(exact.commit(std::move(*above.reservation), bytes(1), started + std::chrono::milliseconds {8}));
    EXPECT_EQ(exact.reserve(1, 1, request, 64, started).decision, control::ResponseCacheCoordinator::Decision::retired);
    EXPECT_EQ(exact.reserve(2, 1, request, 64, started).decision, control::ResponseCacheCoordinator::Decision::replay);
  }

  TEST(ProtocolV3ResponseCache, ControlSessionDuplicateIsByteIdenticalAndConflictMapsTo108) {
    ControlFixture fixture;
    const auto first = fixture.ping(1, 7);
    const auto duplicate = fixture.ping(1, 7);
    ASSERT_TRUE(first);
    ASSERT_TRUE(duplicate);
    EXPECT_EQ(first, duplicate);
    EXPECT_EQ(*first, *duplicate);
    EXPECT_EQ(fixture.backend.control_calls, 1U);

    try {
      static_cast<void>(fixture.ping(1, 8));
      FAIL() << "same request ID with different bytes must fail";
    } catch (const quic::ApplicationCloseError &error) {
      EXPECT_EQ(error.code(), quic::ApplicationCloseCode::request_id_conflict);
      EXPECT_EQ(static_cast<std::uint64_t>(error.code()), 0x108U);
    }
    EXPECT_EQ(fixture.backend.control_calls, 1U);
  }

  TEST(ProtocolV3ResponseCache, ControlSessionProcessesMoreThanOneThousandRequestsAndRetiresFloorTo108) {
    ControlFixture fixture;
    for (std::uint64_t number = 1; number <= 1'001; ++number) {
      const auto request_id = number * 2 - 1;
      ASSERT_TRUE(fixture.ping(request_id, number));
    }
    EXPECT_EQ(fixture.backend.control_calls, 1'001U);
    try {
      static_cast<void>(fixture.ping(1, 1));
      FAIL() << "retired request ID must not execute again";
    } catch (const quic::ApplicationCloseError &error) {
      EXPECT_EQ(error.code(), quic::ApplicationCloseCode::request_id_conflict);
      EXPECT_EQ(static_cast<std::uint64_t>(error.code()), 0x108U);
    }
    EXPECT_EQ(fixture.backend.control_calls, 1'001U);
  }

  TEST(ProtocolV3ResponseCache, ControlSessionReservesBeforeBackendSideEffect) {
    auto budget = std::make_shared<lumen::protocol_v3::resource_budget::ResourceBudgetCoordinator>();
    auto held = budget->reserve(
      lumen::protocol_v3::resource_budget::ResourceClass::cached_responses,
      lumen::protocol_v3::resource_budget::class_ceilings[
        static_cast<std::size_t>(lumen::protocol_v3::resource_budget::ResourceClass::cached_responses)
      ]
    );
    ASSERT_TRUE(held);
    control::Config config {
      .capabilities = control::Config {}.capabilities,
      .default_pairing_permissions = control::Config {}.default_pairing_permissions,
      .resource_budget = budget,
      .response_cache = std::make_shared<control::ResponseCacheCoordinator>(budget),
    };
    ControlFixture fixture {std::move(config)};
    try {
      static_cast<void>(fixture.ping(1, 1));
      FAIL() << "cache reservation must fail before backend control";
    } catch (const quic::ApplicationCloseError &error) {
      EXPECT_EQ(error.code(), quic::ApplicationCloseCode::resource_limit);
    }
    EXPECT_EQ(fixture.backend.control_calls, 0U);
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
