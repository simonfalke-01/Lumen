/**
 * @file tests/unit/test_lsp_core.cpp
 * @brief Concrete wire, bounded-state, input, path, pacing, and telemetry invariants for the portable LSP core.
 */

#include "src/protocol_lsp/core/core.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <limits>
#include <span>
#include <vector>

namespace {
  /** @brief Small exactly-once input edge used by ordered-window tests. */
  struct test_edge {
    std::uint16_t code = 0;  ///< Test physical control code.
    bool pressed = false;  ///< Test physical control state.

    /** @brief Compare complete test edge state. */
    [[nodiscard]] bool operator==(const test_edge &) const noexcept = default;
  };
}  // namespace

TEST(LspPacketCore, ClassifiesEveryLspRfc7983RangeWithoutReadingEmptyInput) {
  using lumen::lsp::packet_class;
  const std::array<std::pair<std::uint8_t, packet_class>, 10> cases {{
    {0, packet_class::stun},
    {3, packet_class::stun},
    {16, packet_class::zrtp},
    {20, packet_class::dtls},
    {63, packet_class::dtls},
    {64, packet_class::turn_channel},
    {79, packet_class::turn_channel},
    {128, packet_class::rtp_or_rtcp},
    {191, packet_class::rtp_or_rtcp},
    {255, packet_class::invalid},
  }};
  EXPECT_EQ(lumen::lsp::classify_packet({}), packet_class::invalid);
  for (const auto &[first, expected] : cases) {
    const std::array datagram {first};
    EXPECT_EQ(lumen::lsp::classify_packet(datagram), expected);
  }
}

TEST(LspPacketCore, PacketSlabAndQueueRejectCapacityOverflow) {
  lumen::lsp::packet_slab<4> slab;
  const std::array<std::uint8_t, 3> first {1, 2, 3};
  const std::array<std::uint8_t, 2> overflow {4, 5};
  ASSERT_TRUE(slab.assign(first));
  EXPECT_FALSE(slab.append(overflow));
  EXPECT_TRUE(std::ranges::equal(slab.bytes(), first));

  lumen::lsp::bounded_queue<int, 2> queue;
  EXPECT_TRUE(queue.try_push(4));
  EXPECT_TRUE(queue.try_push(5));
  EXPECT_FALSE(queue.try_push(6));
  int value = 0;
  ASSERT_TRUE(queue.try_pop(value));
  EXPECT_EQ(value, 4);
  ASSERT_TRUE(queue.try_pop(value));
  EXPECT_EQ(value, 5);
  EXPECT_FALSE(queue.try_pop(value));
}

TEST(LspControlCore, SerializesAndParsesTheFixedFortyEightByteHeaderExactly) {
  constexpr std::array<std::uint8_t, 3> payload {0xa1, 0x01, 0x02};
  const lumen::lsp::lspc_header header {
    .flags = static_cast<std::uint8_t>(lumen::lsp::lspc_flag::acknowledgement_required),
    .message_type = 0x1234,
    .connection_generation = 0x01020304,
    .payload_length = payload.size(),
    .message_id = 9,
    .request_id = 0x1122334455667788ULL,
    .acknowledgement_base = 5,
    .acknowledgement_bitmap = 0b0101,
  };
  std::array<std::uint8_t, lumen::lsp::lspc_header_size + payload.size()> wire {};
  const auto written = lumen::lsp::serialize_lspc(header, payload, wire);
  ASSERT_TRUE(written);
  EXPECT_EQ(written.bytes_written, wire.size());
  EXPECT_TRUE(std::ranges::equal(std::span<const std::uint8_t>(wire).first<4>(), std::array<std::uint8_t, 4> {'L', 'S', 'P', 'C'}));
  EXPECT_EQ(wire[4], 1);
  EXPECT_EQ(wire[6], 0x12);
  EXPECT_EQ(wire[7], 0x34);

  const auto parsed = lumen::lsp::parse_lspc(wire);
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed.header, header);
  EXPECT_TRUE(std::ranges::equal(parsed.payload, payload));
}

TEST(LspControlCore, RejectsTruncationTrailingBytesReservedFlagsAndMalformedAckOnly) {
  std::array<std::uint8_t, lumen::lsp::lspc_header_size> wire {};
  lumen::lsp::lspc_header header {.message_id = 1};
  ASSERT_TRUE(lumen::lsp::serialize_lspc(header, {}, wire));
  EXPECT_EQ(lumen::lsp::parse_lspc(std::span<const std::uint8_t>(wire).first(47)).error, lumen::lsp::lspc_error::header_too_short);

  std::vector<std::uint8_t> trailing(wire.begin(), wire.end());
  trailing.push_back(0);
  EXPECT_EQ(lumen::lsp::parse_lspc(trailing).error, lumen::lsp::lspc_error::payload_length_mismatch);

  wire[5] = 0x80;
  EXPECT_EQ(lumen::lsp::parse_lspc(wire).error, lumen::lsp::lspc_error::reserved_flags);

  header.flags = static_cast<std::uint8_t>(lumen::lsp::lspc_flag::acknowledgement_only);
  header.message_type = 1;
  EXPECT_EQ(lumen::lsp::serialize_lspc(header, {}, wire).error, lumen::lsp::lspc_error::invalid_acknowledgement_only);
}

TEST(LspControlCore, SelectiveAckWindowRetainsOnlyObservedIdentifiers) {
  lumen::lsp::selective_ack_window acknowledgements;
  EXPECT_EQ(acknowledgements.observe(5), lumen::lsp::receive_id_result::accepted);
  EXPECT_EQ(acknowledgements.base(), 5ULL);
  EXPECT_EQ(acknowledgements.bitmap(), 0ULL);
  EXPECT_EQ(acknowledgements.observe(3), lumen::lsp::receive_id_result::accepted);
  EXPECT_EQ(acknowledgements.bitmap(), 0b10ULL);
  EXPECT_EQ(acknowledgements.observe(4), lumen::lsp::receive_id_result::accepted);
  EXPECT_EQ(acknowledgements.bitmap(), 0b11ULL);
  EXPECT_EQ(acknowledgements.observe(3), lumen::lsp::receive_id_result::duplicate);
  EXPECT_EQ(acknowledgements.observe(70), lumen::lsp::receive_id_result::too_far_ahead);
}

TEST(LspControlCore, OutboundWindowAndResponseCacheRemainBoundedAndExact) {
  lumen::lsp::control_rto rto(lumen::lsp::control_path_profile::local);
  lumen::lsp::outbound_control_window<8, 2> outbound;
  constexpr std::array<std::uint8_t, 2> frame_one {1, 2};
  constexpr std::array<std::uint8_t, 2> frame_two {3, 4};
  EXPECT_EQ(outbound.reserve(1, frame_one, 100'000), lumen::lsp::outbound_store_result::stored);
  EXPECT_EQ(outbound.reserve(2, frame_two, 100'000), lumen::lsp::outbound_store_result::stored);
  EXPECT_EQ(outbound.reserve(3, frame_two, 100'000), lumen::lsp::outbound_store_result::window_full);
  EXPECT_EQ(outbound.mark_initial_submitted(1, 1'000, rto), lumen::lsp::outbound_submission_result::submitted);
  EXPECT_EQ(outbound.mark_initial_submitted(2, 2'000, rto), lumen::lsp::outbound_submission_result::submitted);
  EXPECT_EQ(outbound.acknowledge(2, 0b1, 3'000, rto).removed, std::size_t {2});
  EXPECT_EQ(outbound.size(), std::size_t {0});

  lumen::lsp::response_cache<4, 4, 2> cache;
  constexpr std::array<std::uint8_t, 2> request {7, 8};
  constexpr std::array<std::uint8_t, 1> response {9};
  lumen::lsp::response_cache_metadata metadata {
    .identity = {
      .message_type = 1,
      .schema_version = 1,
      .generation = 1,
      .semantic_id = {1},
      .request_digest = {1},
    },
    .retention_deadline_microseconds = 100'000,
  };
  EXPECT_EQ(cache.insert(11, metadata, request, response, 1'000), lumen::lsp::response_cache_result::stored);
  const auto hit = cache.lookup(11, metadata.identity, request, 2'000);
  EXPECT_EQ(hit.result, lumen::lsp::response_cache_result::hit);
  EXPECT_TRUE(std::ranges::equal(hit.response, response));
  constexpr std::array<std::uint8_t, 2> conflict {7, 9};
  EXPECT_EQ(
    cache.lookup(11, metadata.identity, conflict, 2'000).result,
    lumen::lsp::response_cache_result::conflicting_request
  );
}

TEST(LspRtpCore, WritesAndParsesAStandardFixedHeaderWithCsrcs) {
  const lumen::lsp::rtp_fixed_header header {
    .padding = false,
    .extension = true,
    .marker = true,
    .payload_type = 96,
    .csrc_count = 2,
    .sequence_number = 0x1234,
    .timestamp = 0x01020304,
    .ssrc = 0x11223344,
  };
  constexpr std::array<std::uint32_t, 2> csrcs {0x55667788, 0x99aabbcc};
  std::array<std::uint8_t, 20> packet {};
  const auto written = lumen::lsp::write_rtp_fixed_header(header, csrcs, packet);
  ASSERT_TRUE(written);
  EXPECT_EQ(packet[0], 0x92);
  EXPECT_EQ(packet[1], 0xe0);
  const auto parsed = lumen::lsp::parse_rtp_fixed_header(packet);
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed.header, header);
  EXPECT_EQ(parsed.bytes_consumed, packet.size());
  EXPECT_EQ(parsed.csrc_bytes.size(), std::size_t {8});
}

TEST(LspInputCore, CumulativePointerReplacementPreservesDistance) {
  lumen::lsp::pointer_accumulator pointer;
  ASSERT_TRUE(pointer.reset(3));
  EXPECT_EQ(pointer.add_relative(3, 1, 4, -2, 1, 0), lumen::lsp::pointer_update_result::accepted);
  EXPECT_EQ(pointer.add_relative(3, 2, 7, 5, 0, -1), lumen::lsp::pointer_update_result::accepted);
  EXPECT_EQ(pointer.state().relative_x, 11);
  EXPECT_EQ(pointer.state().relative_y, 3);
  EXPECT_EQ(pointer.state().vertical_scroll, 1);
  EXPECT_EQ(pointer.state().horizontal_scroll, -1);
  EXPECT_EQ(pointer.state().represented_reports, 2);
  pointer.mark_emitted();
  EXPECT_EQ(pointer.state().represented_reports, 0);
  EXPECT_EQ(pointer.state().relative_x, 11);
  EXPECT_EQ(pointer.add_relative(3, 2, 1, 1, 0, 0), lumen::lsp::pointer_update_result::invalid_ordinal);
}

TEST(LspInputCore, AppliesEdgesExactlyOnceBeforeDependentLatestState) {
  lumen::lsp::ordered_edge_window<test_edge> edges;
  EXPECT_EQ(edges.insert(2, {.code = 2, .pressed = false}), lumen::lsp::edge_insert_result::accepted);
  EXPECT_EQ(edges.insert(1, {.code = 1, .pressed = true}), lumen::lsp::edge_insert_result::accepted);
  std::array<std::uint16_t, 2> applied {};
  std::size_t count = 0;
  EXPECT_EQ(edges.drain([&](const test_edge &edge) {
    applied[count++] = edge.code;
    return true;
  }),
            std::size_t {2});
  EXPECT_EQ(applied, (std::array<std::uint16_t, 2> {1, 2}));
  EXPECT_EQ(edges.applied_through(), 2ULL);
  EXPECT_EQ(edges.insert(1, {.code = 1, .pressed = true}), lumen::lsp::edge_insert_result::duplicate);

  lumen::lsp::latest_state_table<std::uint32_t, std::uint32_t, 2> latest;
  EXPECT_EQ(latest.put(9, 100, 2, 4), lumen::lsp::latest_state_result::stored);
  EXPECT_EQ(latest.put(9, 200, 3, 5), lumen::lsp::latest_state_result::stored);
  EXPECT_EQ(latest.put(9, 300, 4, 4), lumen::lsp::latest_state_result::stale);
  lumen::lsp::latest_state_record<std::uint32_t, std::uint32_t> ready;
  EXPECT_FALSE(latest.take_ready(4, ready));
  ASSERT_TRUE(latest.take_ready(5, ready));
  EXPECT_EQ(ready.state, std::uint32_t {200});
  EXPECT_EQ(ready.state_sequence, 3ULL);
}

TEST(LspInputCore, BaselineCommitsOnlyAfterExactNonoverlappingCoverageAndDigestApproval) {
  lumen::lsp::baseline_assembler<8, 2> baseline;
  constexpr std::array<std::uint8_t, 32> digest {1};
  constexpr std::array<std::uint8_t, 4> tail {5, 6, 7, 8};
  constexpr std::array<std::uint8_t, 4> head {1, 2, 3, 4};
  EXPECT_EQ(baseline.add_part(7, 1, 2, 8, 4, digest, tail), lumen::lsp::baseline_part_result::accepted);
  EXPECT_FALSE(baseline.ready_for_digest());
  EXPECT_EQ(baseline.add_part(7, 0, 2, 8, 0, digest, head), lumen::lsp::baseline_part_result::accepted);
  ASSERT_TRUE(baseline.ready_for_digest());
  EXPECT_TRUE(std::ranges::equal(baseline.assembled_bytes(), std::array<std::uint8_t, 8> {1, 2, 3, 4, 5, 6, 7, 8}));
  EXPECT_FALSE(baseline.commit(false));
  EXPECT_TRUE(baseline.commit(true));
  EXPECT_TRUE(baseline.commit(false));

  lumen::lsp::input_state_sequence sequence;
  EXPECT_EQ(sequence.begin_generation(), 1ULL);
  EXPECT_EQ(sequence.next_state(), 0ULL);
  ASSERT_TRUE(sequence.commit_baseline());
  EXPECT_EQ(sequence.next_state(), 2ULL);
  EXPECT_TRUE(sequence.commit_baseline());
  EXPECT_EQ(sequence.next_state(), 3ULL);
}

TEST(LspTransportCore, DplpmtudUsesOneExactProbeAndRetainsConfirmedSizeOnLoss) {
  lumen::lsp::dplpmtud path({.base_payload = 1'200, .fast_probe_payload = 1'400, .ceiling_payload = 1'472});
  ASSERT_TRUE(path.valid());
  EXPECT_EQ(path.candidate_payload(), 1'400);
  EXPECT_EQ(path.start_probe(41, 100, 100), lumen::lsp::dplpmtud_result::accepted);
  EXPECT_EQ(path.start_probe(42, 100, 100), lumen::lsp::dplpmtud_result::probe_outstanding);
  EXPECT_EQ(path.acknowledge(41, 1'399), lumen::lsp::dplpmtud_result::unexpected_ack);
  EXPECT_EQ(path.acknowledge(41, 1'400), lumen::lsp::dplpmtud_result::accepted);
  EXPECT_EQ(path.current_payload(), 1'400);
  EXPECT_EQ(path.start_probe(42, 150, 0), lumen::lsp::dplpmtud_result::invalid_rtt);
  EXPECT_EQ(path.start_probe(42, 150, 100), lumen::lsp::dplpmtud_result::probe_too_soon);
  EXPECT_EQ(path.start_probe(42, 200, 100), lumen::lsp::dplpmtud_result::accepted);
  EXPECT_EQ(path.outstanding_probe().payload_size, 1'472);
  EXPECT_EQ(path.probe_timed_out(), lumen::lsp::dplpmtud_result::accepted);
  EXPECT_EQ(path.current_payload(), 1'400);
  EXPECT_GT(path.candidate_payload(), 1'400);
  EXPECT_LT(path.candidate_payload(), 1'472);
}

TEST(LspTransportCore, PacerEnforcesInputReserveQuantumAndEightDatagramLimit) {
  lumen::lsp::aggregate_pacer pacer({
    .pacing_bits_per_second = 1'000'000'000,
    .input_reserve_bits_per_second = 32'000'000,
    .path_datagram_bytes = 1'400,
    .quantum_microseconds = 100,
    .submission_horizon_microseconds = 200,
    .max_datagrams_per_batch = 8,
  });
  ASSERT_EQ(pacer.error(), lumen::lsp::pacer_error::none);
  pacer.reset(1'000);
  constexpr std::array<std::uint16_t, 9> packets {1'400, 1'400, 1'400, 1'400, 1'400, 1'400, 1'400, 1'400, 1'400};
  const auto startup = pacer.grant(packets, false, 1'000);
  EXPECT_EQ(startup.datagrams, std::size_t {1});
  const auto batch = pacer.grant(packets, false, 1'200);
  EXPECT_EQ(batch.datagrams, std::size_t {8});
  EXPECT_EQ(batch.bytes, 11'200ULL);

  lumen::lsp::aggregate_pacer invalid({
    .pacing_bits_per_second = 20'000'000,
    .input_reserve_bits_per_second = 32'000'000,
  });
  EXPECT_EQ(invalid.error(), lumen::lsp::pacer_error::invalid_input_reserve);
}

TEST(LspTransportCore, PacerReconfigureNeverGrantsFreshStartupCredit) {
  lumen::lsp::aggregate_pacer pacer({
    .pacing_bits_per_second = 8'000'000,
    .input_reserve_bits_per_second = 0,
    .path_datagram_bytes = 1'228,
    .quantum_microseconds = 100,
    .submission_horizon_microseconds = 200,
    .max_datagrams_per_batch = 8,
  });
  ASSERT_EQ(pacer.error(), lumen::lsp::pacer_error::none);
  pacer.reset(1'000);
  constexpr std::array<std::uint16_t, 1> packet {1'228};
  EXPECT_EQ(pacer.grant(packet, false, 1'000).datagrams, 1U);
  EXPECT_EQ(pacer.grant(packet, false, 1'000).datagrams, 0U);
  ASSERT_TRUE(pacer.reconfigure({
                                  .pacing_bits_per_second = 16'000'000,
                                  .input_reserve_bits_per_second = 0,
                                  .path_datagram_bytes = 1'428,
                                  .quantum_microseconds = 100,
                                  .submission_horizon_microseconds = 200,
                                  .max_datagrams_per_batch = 8,
                                },
                                1'000));
  EXPECT_EQ(pacer.grant(packet, false, 1'000).datagrams, 0U);
}

TEST(LspTransportCore, CompetitionRequiresCapacityAndCongestionExcludesReservedOverhead) {
  lumen::lsp::congestion_controller unavailable({
    .profile = lumen::lsp::congestion_profile::competition_lan,
    .initial_pacing_bits_per_second = 100'000'000,
    .minimum_pacing_bits_per_second = 10'000'000,
    .maximum_pacing_bits_per_second = 1'000'000'000,
    .competition_capacity_bits_per_second = 0,
  });
  EXPECT_EQ(unavailable.error(), lumen::lsp::congestion_error::competition_capacity_required);

  lumen::lsp::congestion_controller adaptive({
    .profile = lumen::lsp::congestion_profile::adaptive_low_latency,
    .initial_pacing_bits_per_second = 100'000'000,
    .minimum_pacing_bits_per_second = 10'000'000,
    .maximum_pacing_bits_per_second = 200'000'000,
    .reserved_overhead_bits_per_second = 20'000'000,
    .maximum_rtt_microseconds = 50'000,
    .queue_delay_budget_microseconds = 2'000,
  });
  ASSERT_EQ(adaptive.error(), lumen::lsp::congestion_error::none);
  adaptive.on_feedback({.delivered_bytes = 1'000, .lost_bytes = 100, .smoothed_rtt_microseconds = 1'000});
  const auto reduced = adaptive.snapshot();
  EXPECT_LT(reduced.pacing_bits_per_second, 100'000'000ULL);
  EXPECT_EQ(reduced.encoder_bits_per_second, reduced.pacing_bits_per_second - 20'000'000);
}

TEST(LspTelemetryCore, SnapshotsThreadOwnedCountersAndNearestRankPercentiles) {
  lumen::lsp::telemetry_accumulator telemetry;
  telemetry.record_received(100);
  telemetry.record_transmitted(80);
  telemetry.record_queue_drop();
  telemetry.observe_queue_depth(7);
  for (std::uint64_t sample = 1; sample <= 100; ++sample) {
    telemetry.record_pacing_error(sample);
  }
  const auto snapshot = telemetry.snapshot();
  EXPECT_EQ(snapshot.packets_received, 1ULL);
  EXPECT_EQ(snapshot.bytes_received, 100ULL);
  EXPECT_EQ(snapshot.packets_transmitted, 1ULL);
  EXPECT_EQ(snapshot.queue_drops, 1ULL);
  EXPECT_EQ(snapshot.peak_queue_depth, std::uint32_t {7});
  EXPECT_EQ(snapshot.pacing_error.retained_samples, std::uint32_t {100});
  EXPECT_EQ(snapshot.pacing_error.p50_microseconds, 50ULL);
  EXPECT_EQ(snapshot.pacing_error.p95_microseconds, 95ULL);
  EXPECT_EQ(snapshot.pacing_error.p99_microseconds, 99ULL);
  EXPECT_EQ(snapshot.pacing_error.maximum_microseconds, 100ULL);
}
