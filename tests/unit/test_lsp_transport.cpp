/**
 * @file tests/unit/test_lsp_transport.cpp
 * @brief Focused transport, repair, congestion, PMTU, and generation-fence tests for LSP.
 */

#include "src/protocol_lsp/transport/transport.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <vector>

namespace lsp_transport = lumen::lsp::transport;

TEST(LspTransportRtcp, ParsesCommonCompoundAndReducedSizePackets) {
  std::array<std::uint8_t, 12> pli_bytes {};
  const auto written = lsp_transport::write_picture_loss_indication(
    {.sender_ssrc = 0x01020304, .media_ssrc = 0x11223344},
    pli_bytes
  );
  ASSERT_TRUE(written);
  EXPECT_EQ(written.bytes_written, pli_bytes.size());

  const auto pli = lsp_transport::parse_rtcp_packet(pli_bytes);
  ASSERT_TRUE(pli);
  EXPECT_EQ(pli.count, lsp_transport::rtcp_picture_loss_indication_format);
  EXPECT_EQ(pli.packet_type, lsp_transport::rtcp_payload_feedback_type);
  EXPECT_EQ(pli.payload.size(), std::size_t {8});
  EXPECT_TRUE(lsp_transport::parse_rtcp_datagram(pli_bytes, lsp_transport::rtcp_datagram_form::reduced_size));
  EXPECT_EQ(
    lsp_transport::parse_rtcp_datagram(pli_bytes, lsp_transport::rtcp_datagram_form::compound).error,
    lsp_transport::rtcp_parse_error::invalid_compound_start
  );

  constexpr std::array<std::uint8_t, 8> receiver_report {
    0x80,
    lsp_transport::rtcp_receiver_report_type,
    0x00,
    0x01,
    0x55,
    0x66,
    0x77,
    0x88,
  };
  std::array<std::uint8_t, 20> compound {};
  std::copy(receiver_report.begin(), receiver_report.end(), compound.begin());
  std::copy(pli_bytes.begin(), pli_bytes.end(), compound.begin() + 8);
  const auto summary = lsp_transport::parse_rtcp_datagram(compound, lsp_transport::rtcp_datagram_form::compound);
  ASSERT_TRUE(summary);
  EXPECT_EQ(summary.packet_count, std::size_t {2});
  EXPECT_EQ(summary.bytes_consumed, compound.size());

  auto padded_first = compound;
  padded_first[0] |= 0x20U;
  padded_first[7] = 4;
  EXPECT_EQ(
    lsp_transport::parse_rtcp_datagram(padded_first, lsp_transport::rtcp_datagram_form::compound).error,
    lsp_transport::rtcp_parse_error::invalid_padding
  );
}

TEST(LspTransportRtcp, SerializesBoundedNackAndFirModels) {
  lsp_transport::generic_nack<2> nack {
    .sender_ssrc = 1,
    .media_ssrc = 2,
    .pairs = {{{.packet_id = 100, .lost_packet_bitmask = 0x0005}, {.packet_id = 120, .lost_packet_bitmask = 0x8000}}},
    .pair_count = 2,
  };
  std::array<std::uint8_t, 20> nack_bytes {};
  const auto nack_written = lsp_transport::write_generic_nack(nack, nack_bytes);
  ASSERT_TRUE(nack_written);
  EXPECT_EQ(nack_bytes[0], 0x81);
  EXPECT_EQ(nack_bytes[1], lsp_transport::rtcp_transport_feedback_type);
  EXPECT_EQ(nack_bytes[12], 0);
  EXPECT_EQ(nack_bytes[13], 100);
  EXPECT_EQ(nack_bytes[14], 0);
  EXPECT_EQ(nack_bytes[15], 5);

  lsp_transport::full_intra_request<1> fir {
    .sender_ssrc = 3,
    .entries = {{{.media_sender_ssrc = 4, .sequence_number = 9}}},
    .entry_count = 1,
  };
  std::array<std::uint8_t, 20> fir_bytes {};
  const auto fir_written = lsp_transport::write_full_intra_request(fir, fir_bytes);
  ASSERT_TRUE(fir_written);
  EXPECT_EQ(fir_bytes[0], 0x84);
  EXPECT_EQ(fir_bytes[1], lsp_transport::rtcp_payload_feedback_type);
  EXPECT_EQ(fir_bytes[16], 9);
  EXPECT_EQ(fir_bytes[17], 0);
  EXPECT_EQ(fir_bytes[18], 0);
  EXPECT_EQ(fir_bytes[19], 0);
}

TEST(LspTransportFeedback, UsesTwoMillisecondOr128PacketCadenceWithFiveHundredMicrosecondFloor) {
  lsp_transport::congestion_feedback_window<256> feedback;
  feedback.reset(1'000);
  for (std::uint32_t sequence = 1; sequence <= 127; ++sequence) {
    EXPECT_EQ(
      feedback.record({
        .media_ssrc = 7,
        .extended_sequence_number = sequence,
        .arrival_microseconds = 1'000 + sequence,
        .received_bytes = 1'400,
        .ecn = sequence == 127 ? lsp_transport::ecn_mark::congestion_experienced : lsp_transport::ecn_mark::ect0,
      }),
      lsp_transport::congestion_report_result::accepted
    );
  }
  EXPECT_FALSE(feedback.report_due(1'499));
  EXPECT_FALSE(feedback.report_due(1'500));
  ASSERT_EQ(
    feedback.record({
      .media_ssrc = 7,
      .extended_sequence_number = 128,
      .arrival_microseconds = 1'128,
      .received_bytes = 1'400,
      .ecn = lsp_transport::ecn_mark::ect0,
    }),
    lsp_transport::congestion_report_result::accepted
  );
  ASSERT_TRUE(feedback.report_due(1'500));
  const auto first = feedback.pending_report(1'500);
  EXPECT_EQ(first.size(), lsp_transport::congestion_feedback_packet_cadence);
  EXPECT_EQ(first.interval_begin_microseconds, 1'000ULL);
  EXPECT_EQ(feedback.commit_report(1'500), lsp_transport::congestion_feedback_packet_cadence);
  EXPECT_EQ(feedback.size(), std::size_t {0});

  ASSERT_EQ(
    feedback.record({
      .media_ssrc = 8,
      .extended_sequence_number = 1,
      .arrival_microseconds = 1'501,
      .received_bytes = 200,
    }),
    lsp_transport::congestion_report_result::accepted
  );
  EXPECT_FALSE(feedback.report_due(3'499));
  EXPECT_TRUE(feedback.report_due(3'500));
  EXPECT_EQ(feedback.commit_report(3'500), std::size_t {1});
}

TEST(LspTransportFeedback, CoalescesValidatedLspvCapacityAndDecodeStatus) {
  lsp_transport::lspv_coalescer coalescer;
  lsp_transport::lspv_status status {
    .session_generation = 1,
    .video_generation = 2,
    .recovery_epoch = 3,
    .largest_complete_frame_id = 12,
    .largest_decoded_frame_id = 11,
    .largest_metal_committed_frame_id = 10,
    .deadline_miss = false,
    .decoder_status = lsp_transport::lspv_decoder_status::ready,
    .decode_submissions_in_flight = 1,
    .maximum_decode_submissions = 3,
    .render_mailbox_occupancy = 1,
  };
  EXPECT_EQ(
    coalescer.update(status, lsp_transport::lspv_event::decode_completion),
    lsp_transport::lspv_update_result::accepted
  );
  lsp_transport::lspv_status emitted;
  lsp_transport::lspv_event event {};
  ASSERT_TRUE(coalescer.take(10'000, emitted, event));
  EXPECT_EQ(emitted.largest_decoded_frame_id, 11ULL);
  EXPECT_EQ(event, lsp_transport::lspv_event::decode_completion);

  status.largest_complete_frame_id = 13;
  status.largest_decoded_frame_id = 12;
  status.decode_submissions_in_flight = 2;
  ASSERT_EQ(
    coalescer.update(status, lsp_transport::lspv_event::capacity_transition),
    lsp_transport::lspv_update_result::accepted
  );
  EXPECT_FALSE(coalescer.take(10'499, emitted, event));
  ASSERT_TRUE(coalescer.take(10'500, emitted, event));
  EXPECT_EQ(event, lsp_transport::lspv_event::capacity_transition);

  status.maximum_decode_submissions = 5;
  EXPECT_EQ(lsp_transport::validate_lspv_status(status), lsp_transport::lspv_status_error::invalid_decode_capacity);
}

TEST(LspTransportRepair, AccumulatesFrameLocalPlaintextParityBeforeRepairSrtp) {
  std::array<std::uint8_t, 32> parity_storage {};
  lsp_transport::flexfec_group group(parity_storage);
  ASSERT_EQ(group.begin(10, 100, 200), lsp_transport::flexfec_result::accepted);
  constexpr std::array<std::uint8_t, 15> first {
    0x80,
    0xe0,
    0xff,
    0xff,
    0,
    0,
    0,
    100,
    0,
    0,
    0,
    100,
    1,
    2,
    3,
  };
  constexpr std::array<std::uint8_t, 17> second {
    0x80,
    0x60,
    0,
    0,
    0,
    0,
    0,
    101,
    0,
    0,
    0,
    100,
    4,
    5,
    6,
    7,
    8,
  };
  EXPECT_EQ(group.add_plaintext_source(10, 100, 65'535, first), lsp_transport::flexfec_result::accepted);
  EXPECT_EQ(group.add_plaintext_source(10, 100, 0, second), lsp_transport::flexfec_result::accepted);
  EXPECT_EQ(group.add_plaintext_source(11, 100, 1, first), lsp_transport::flexfec_result::wrong_frame);

  lsp_transport::flexfec_parity_view parity;
  ASSERT_EQ(group.seal_plaintext_repair(parity), lsp_transport::flexfec_result::accepted);
  EXPECT_EQ(parity.base_sequence_number, 65'535);
  EXPECT_EQ(parity.source_mask, 0b11ULL);
  EXPECT_EQ(parity.length_recovery, std::uint16_t {3 ^ 5});
  ASSERT_EQ(parity.parity.size(), std::size_t {5});
  EXPECT_EQ(parity.parity[0], static_cast<std::uint8_t>(1 ^ 4));
  EXPECT_EQ(parity.parity[3], 7);
  EXPECT_EQ(parity.parity[4], 8);
  EXPECT_EQ(group.add_plaintext_source(10, 100, 1, first), lsp_transport::flexfec_result::wrong_phase);
  EXPECT_EQ(group.mark_repair_plaintext_constructed(), lsp_transport::flexfec_result::accepted);
  EXPECT_EQ(group.phase(), lsp_transport::flexfec_phase::repair_ready_for_srtp);
  EXPECT_EQ(group.mark_repair_protected(), lsp_transport::flexfec_result::accepted);
}

TEST(LspTransportRepair, AdmitsRecoveredPlaintextOnlyThroughAuthenticatedRepairMarker) {
  const auto rejected = lsp_transport::recovered_packet_admission::authorize({
    .repair_authenticated_and_decrypted = false,
    .all_contributing_sources_authenticated_and_decrypted = true,
    .expected_source_ssrc = 10,
    .recovered_source_ssrc = 10,
    .expected_generation = 3,
    .recovered_generation = 3,
    .expected_payload_type = 96,
    .recovered_payload_type = 96,
    .recovered_packet_bytes = 1'200,
    .maximum_packet_bytes = 1'400,
    .now_microseconds = 100,
    .frame_deadline_microseconds = 200,
  });
  EXPECT_EQ(rejected.error, lsp_transport::recovered_packet_error::unauthenticated_input);
  EXPECT_FALSE(rejected.marker.has_value());

  const auto accepted = lsp_transport::recovered_packet_admission::authorize({
    .repair_authenticated_and_decrypted = true,
    .all_contributing_sources_authenticated_and_decrypted = true,
    .expected_source_ssrc = 10,
    .recovered_source_ssrc = 10,
    .expected_generation = 3,
    .recovered_generation = 3,
    .expected_payload_type = 96,
    .recovered_payload_type = 96,
    .recovered_packet_bytes = 1'200,
    .maximum_packet_bytes = 1'400,
    .now_microseconds = 100,
    .frame_deadline_microseconds = 200,
  });
  ASSERT_TRUE(accepted);
  EXPECT_EQ(accepted.marker->source_ssrc(), 10U);
  EXPECT_EQ(accepted.marker->generation(), 3U);
  EXPECT_EQ(accepted.marker->payload_type(), 96U);
}

TEST(LspTransportRtx, RetainsTwoFrameGenerationsAndRequiresStrictDeadlineEligibility) {
  EXPECT_TRUE(lsp_transport::rtx_deadline_eligible(100, 201, {.reverse_feedback_microseconds = 25, .retransmission_serialization_microseconds = 25, .forward_delivery_microseconds = 25, .decode_safety_reserve_microseconds = 25}));
  EXPECT_FALSE(lsp_transport::rtx_deadline_eligible(100, 200, {.reverse_feedback_microseconds = 25, .retransmission_serialization_microseconds = 25, .forward_delivery_microseconds = 25, .decode_safety_reserve_microseconds = 25}));

  static std::array<
    lsp_transport::rtx_retained_packet,
    lsp_transport::required_rtx_retention_slots>
    slots {};
  lsp_transport::rtx_retention retention(slots);
  std::vector<std::uint64_t> released;
  const auto release = [&released](const std::uint64_t token) {
    released.push_back(token);
  };
  const auto descriptor = [](const std::uint64_t frame_id) {
    return lsp_transport::rtx_frame_descriptor {
      .frame_id = frame_id,
      .frame_deadline_microseconds = 2'000,
      .now_microseconds = 1'000,
      .retention_origin_microseconds = 1'000,
      .measured_rtt_microseconds = 500,
      .source_ssrc = 5,
      .video_generation = 7,
    };
  };
  const auto first = retention.begin_frame(descriptor(10), release);
  ASSERT_TRUE(first);
  ASSERT_EQ(
    retention.retain(first.handle, {.reconstruction_token = 1, .source_sequence_number = 100, .source_packet_bytes = 1'200}),
    lsp_transport::rtx_retention_result::retained
  );
  ASSERT_EQ(retention.commit_frame(first.handle, 1'000), lsp_transport::rtx_frame_result::accepted);
  const auto second = retention.begin_frame(descriptor(11), release);
  ASSERT_TRUE(second);
  ASSERT_EQ(
    retention.retain(second.handle, {.reconstruction_token = 2, .source_sequence_number = 101, .source_packet_bytes = 1'200}),
    lsp_transport::rtx_retention_result::retained
  );
  ASSERT_EQ(retention.commit_frame(second.handle, 1'000), lsp_transport::rtx_frame_result::accepted);
  const auto third = retention.begin_frame(descriptor(12), release);
  ASSERT_TRUE(third);
  ASSERT_EQ(
    retention.retain(third.handle, {.reconstruction_token = 3, .source_sequence_number = 102, .source_packet_bytes = 1'200}),
    lsp_transport::rtx_retention_result::retained
  );
  ASSERT_EQ(retention.commit_frame(third.handle, 1'000), lsp_transport::rtx_frame_result::accepted);
  ASSERT_EQ(retention.retained_frame_count(), lsp_transport::maximum_rtx_frame_generations);
  ASSERT_EQ(released.size(), std::size_t {1});
  EXPECT_EQ(released.front(), 1ULL);

  const auto eligible = retention.find_eligible(
    7,
    5,
    102,
    1'100,
    {.reverse_feedback_microseconds = 20, .retransmission_serialization_microseconds = 20, .forward_delivery_microseconds = 20, .decode_safety_reserve_microseconds = 20}
  );
  ASSERT_TRUE(eligible.has_value());
  EXPECT_EQ(eligible->reconstruction_token, 3ULL);
  const auto pruned = retention.prune_expired_frames(1'500, release);
  EXPECT_EQ(pruned.frames_released, std::size_t {2});
  EXPECT_EQ(pruned.tokens_released, std::size_t {2});
  EXPECT_EQ(retention.retained_bytes(), std::size_t {0});
}

TEST(LspTransportRtx, EnforcesTheSixteenMibibyteConnectionBoundWithoutPacketCopies) {
  constexpr auto half_capacity = lsp_transport::maximum_rtx_retained_bytes / 2U;
  static std::array<
    lsp_transport::rtx_retained_packet,
    lsp_transport::required_rtx_retention_slots>
    slots {};
  lsp_transport::rtx_retention retention(slots);
  const auto frame = retention.begin_frame(
    {
      .frame_id = 10,
      .frame_deadline_microseconds = 10'000,
      .now_microseconds = 1'000,
      .retention_origin_microseconds = 1'000,
      .measured_rtt_microseconds = 5'000,
      .source_ssrc = 5,
      .video_generation = 7,
    },
    [](const std::uint64_t) {
    }
  );
  ASSERT_TRUE(frame);
  ASSERT_EQ(
    retention.retain(
      frame.handle,
      {.reconstruction_token = 1, .source_sequence_number = 1, .source_packet_bytes = half_capacity}
    ),
    lsp_transport::rtx_retention_result::retained
  );
  ASSERT_EQ(
    retention.retain(
      frame.handle,
      {.reconstruction_token = 2, .source_sequence_number = 2, .source_packet_bytes = half_capacity}
    ),
    lsp_transport::rtx_retention_result::retained
  );
  EXPECT_EQ(retention.retained_bytes(), lsp_transport::maximum_rtx_retained_bytes);
  EXPECT_EQ(
    retention.retain(
      frame.handle,
      {
        .reconstruction_token = 3,
        .source_sequence_number = 3,
        .source_packet_bytes = 1,
      }
    ),
    lsp_transport::rtx_retention_result::byte_capacity_exceeded
  );
  const auto aborted = retention.abort_frame(frame.handle, [](const std::uint64_t) {
  });
  EXPECT_EQ(aborted.tokens_released, std::size_t {2});
}

TEST(LspTransportRecovery, AllowsOneOutstandingIndependentFramePerEpoch) {
  lsp_transport::recovery_controller recovery;
  EXPECT_EQ(
    recovery.report_unrecoverable_damage(100, lsp_transport::recovery_cause::unrecoverable_reference_loss),
    lsp_transport::recovery_result::accepted
  );
  EXPECT_EQ(
    recovery.report_unrecoverable_damage(101, lsp_transport::recovery_cause::decoder_unrecoverable),
    lsp_transport::recovery_result::already_active
  );
  EXPECT_EQ(recovery.mark_independent_frame_sent(110, 1'000, 2'000), lsp_transport::recovery_result::accepted);
  EXPECT_EQ(
    recovery.mark_independent_frame_sent(111, 1'000, 2'000),
    lsp_transport::recovery_result::recovery_already_outstanding
  );
  const auto epoch = recovery.snapshot().epoch;
  EXPECT_EQ(recovery.confirm_recovery_decoded(epoch, 109), lsp_transport::recovery_result::wrong_recovery_frame);
  EXPECT_EQ(recovery.permit_retry(1'999, true), lsp_transport::recovery_result::deadline_not_expired);
  EXPECT_EQ(recovery.permit_retry(2'000, false), lsp_transport::recovery_result::failure_evidence_required);
  EXPECT_EQ(recovery.permit_retry(2'000, true), lsp_transport::recovery_result::accepted);
  EXPECT_EQ(recovery.mark_independent_frame_sent(111, 2'000, 3'000), lsp_transport::recovery_result::accepted);
  EXPECT_EQ(recovery.confirm_recovery_decoded(epoch, 111), lsp_transport::recovery_result::accepted);
  EXPECT_EQ(recovery.snapshot().phase, lsp_transport::recovery_phase::healthy);
}

TEST(LspTransportCongestion, RequiresAnExplicitCompetitionCeiling) {
  lsp_transport::congestion_controller invalid_competition({
    .profile = lsp_transport::controller_profile::competition_lan,
    .initial_pacing_bits_per_second = 100'000'000,
    .minimum_pacing_bits_per_second = 10'000'000,
    .maximum_pacing_bits_per_second = 1'000'000'000,
    .competition_capacity_bits_per_second = 0,
    .reserved_overhead_bits_per_second = 10'000'000,
    .rtt_inflation_budget_microseconds = 20'000,
    .queue_delay_budget_microseconds = 2'000,
  });
  EXPECT_EQ(invalid_competition.error(), lsp_transport::controller_error::competition_capacity_required);
}

namespace {
  lsp_transport::congestion_controller adaptive_controller() {
    return lsp_transport::congestion_controller({
      .profile = lsp_transport::controller_profile::adaptive_low_latency,
      .initial_pacing_bits_per_second = 20'000'000,
      .minimum_pacing_bits_per_second = 1'000'000,
      .maximum_pacing_bits_per_second = 30'000'000,
      .reserved_overhead_bits_per_second = 500'000,
      .rtt_inflation_budget_microseconds = 50'000,
      .queue_delay_budget_microseconds = 10'000,
    });
  }
}  // namespace

// Mobile data: long RTT and light random loss that FEC repairs. The old controller cut the rate on
// every lost packet and every report above 100 ms RTT, pinning streams at the 1 Mbps floor.
TEST(LspTransportCongestion, LongRttAndLightLossDoNotReduceTheRate) {
  auto controller = adaptive_controller();
  ASSERT_EQ(controller.error(), lsp_transport::controller_error::none);
  for (std::uint64_t report = 1; report <= 2'500; ++report) {
    const auto sent = controller.snapshot().pacing_bits_per_second / 8U / 500U;
    const auto lost = report % 100U == 0 ? std::uint64_t {1'200} : std::uint64_t {0};  // about 1%
    controller.apply_feedback({
      .delivered_bytes = sent - lost,
      .lost_bytes = lost,
      .smoothed_rtt_microseconds = 140'000,
      .rtt_variation_microseconds = 10'000,
      .report_microseconds = report * 2'000U,
    });
  }
  EXPECT_GE(controller.snapshot().pacing_bits_per_second, 20'000'000ULL);
}

TEST(LspTransportCongestion, SustainedHeavyLossCutsOncePerRoundTrip) {
  auto controller = adaptive_controller();
  std::uint64_t now = 0;
  const auto report = [&](const std::uint64_t lost_share_percent) {
    now += 2'000;
    const auto sent = controller.snapshot().pacing_bits_per_second / 8U / 500U;
    const auto lost = sent * lost_share_percent / 100U;
    controller.apply_feedback({
      .delivered_bytes = sent - lost,
      .lost_bytes = lost,
      .smoothed_rtt_microseconds = 40'000,
      .report_microseconds = now,
    });
  };
  for (int index = 0; index < 60; ++index) {
    report(0);
  }
  const auto clean_rate = controller.snapshot().pacing_bits_per_second;
  for (int index = 0; index < 60; ++index) {  // 120 ms of 30% loss: one window, one cut
    report(30);
  }
  const auto after_one_window = controller.snapshot().pacing_bits_per_second;
  EXPECT_LT(after_one_window, clean_rate);
  EXPECT_GE(after_one_window, clean_rate * 65U / 100U);
  for (int index = 0; index < 500; ++index) {
    report(30);
  }
  EXPECT_LT(controller.snapshot().pacing_bits_per_second, after_one_window);
}

TEST(LspTransportCongestion, RttRiseAboveThePathFloorCutsTheRate) {
  auto controller = adaptive_controller();
  std::uint64_t now = 0;
  const auto report = [&](const std::uint32_t rtt) {
    now += 2'000;
    controller.apply_feedback({
      .delivered_bytes = controller.snapshot().pacing_bits_per_second / 8U / 500U,
      .smoothed_rtt_microseconds = rtt,
      .report_microseconds = now,
    });
  };
  for (int index = 0; index < 100; ++index) {
    report(30'000);
  }
  const auto before = controller.snapshot().pacing_bits_per_second;
  for (int index = 0; index < 100; ++index) {
    report(110'000);
  }
  EXPECT_LT(controller.snapshot().pacing_bits_per_second, before);
}

TEST(LspTransportPathMtu, Probes1200Then1400ThenTheAddressFamilyCeiling) {
  lsp_transport::path_mtu_discovery path({
    .ip_version = lsp_transport::path_ip_version::ipv6,
    .sender_interface_limit = 1'472,
    .receiver_advertised_limit = 1'472,
    .operator_configured_limit = 1'472,
  });
  ASSERT_TRUE(path.valid());
  EXPECT_EQ(path.current_payload_bytes(), 1'200);
  EXPECT_EQ(path.ceiling_payload_bytes(), 1'452);
  EXPECT_EQ(path.candidate_payload_bytes(), 1'400);
  EXPECT_EQ(path.start_probe(1, 100, 0), lsp_transport::path_mtu_result::accepted);
  EXPECT_EQ(path.acknowledge_probe(1, 1'399), lsp_transport::path_mtu_result::unexpected_ack);
  EXPECT_EQ(path.acknowledge_probe(1, 1'400), lsp_transport::path_mtu_result::accepted);
  EXPECT_EQ(path.candidate_payload_bytes(), 1'452);
  EXPECT_EQ(path.start_probe(2, 150, 100), lsp_transport::path_mtu_result::probe_too_soon);
  EXPECT_EQ(path.start_probe(2, 200, 100), lsp_transport::path_mtu_result::accepted);
  EXPECT_EQ(path.acknowledge_probe(2, 1'452), lsp_transport::path_mtu_result::accepted);
  EXPECT_EQ(path.current_payload_bytes(), 1'452);
  EXPECT_EQ(path.candidate_payload_bytes(), 0);
  EXPECT_EQ(path.confirm_black_hole(1'200), lsp_transport::path_mtu_result::accepted);
  EXPECT_EQ(path.current_payload_bytes(), 1'200);
}

TEST(LspTransportPathMtu, RaiseTimerReopensCeilingAfterSmallerBinarySuccess) {
  lsp_transport::path_mtu_discovery path({
    .ip_version = lsp_transport::path_ip_version::ipv4,
    .sender_interface_limit = 1'472,
    .receiver_advertised_limit = 1'472,
    .operator_configured_limit = 1'472,
  });
  ASSERT_EQ(path.start_probe(1, 0, 0), lsp_transport::path_mtu_result::accepted);
  ASSERT_EQ(path.probe_timed_out(), lsp_transport::path_mtu_result::accepted);
  ASSERT_GT(path.candidate_payload_bytes(), 1'200);
  ASSERT_LT(path.candidate_payload_bytes(), 1'400);
  const auto binary_candidate = path.candidate_payload_bytes();
  ASSERT_EQ(path.start_probe(2, 100, 100), lsp_transport::path_mtu_result::accepted);
  ASSERT_EQ(path.acknowledge_probe(2, binary_candidate), lsp_transport::path_mtu_result::accepted);
  EXPECT_LT(path.candidate_payload_bytes(), 1'400);
  ASSERT_EQ(path.raise_timer_elapsed(), lsp_transport::path_mtu_result::accepted);
  EXPECT_EQ(path.candidate_payload_bytes(), 1'472);
}

TEST(LspTransportGenerationFence, TransfersAuthorityOnlyAfterFreshAuthenticationAndNeutralization) {
  lsp_transport::reconnect_generation_fence fence;
  EXPECT_EQ(fence.initialize(1, 10), lsp_transport::generation_fence_result::accepted);
  EXPECT_TRUE(fence.accepts_input_packet(1, 10, 1));
  EXPECT_EQ(fence.begin_fresh_association(2), lsp_transport::generation_fence_result::accepted);
  EXPECT_TRUE(fence.accepts_input_packet(1, 10, 1));
  EXPECT_FALSE(fence.accepts_connection_packet(2));
  EXPECT_EQ(fence.mark_candidate_authenticated(2), lsp_transport::generation_fence_result::accepted);
  EXPECT_EQ(fence.commit_attach(2, 11), lsp_transport::generation_fence_result::input_not_neutralized);
  EXPECT_EQ(fence.neutralize_old_input(2), lsp_transport::generation_fence_result::accepted);
  EXPECT_FALSE(fence.accepts_input_packet(1, 10, 1));
  EXPECT_EQ(fence.commit_attach(2, 11), lsp_transport::generation_fence_result::accepted);
  EXPECT_FALSE(fence.accepts_connection_packet(1));
  EXPECT_FALSE(fence.accepts_input_packet(2, 10, 2));
  EXPECT_FALSE(fence.accepts_input_packet(2, 11, 1));
  EXPECT_TRUE(fence.accepts_input_packet(2, 11, 2));
  EXPECT_EQ(fence.retire_old_association(1), lsp_transport::generation_fence_result::accepted);
}

TEST(LspTransportGenerationFence, FailedPostNeutralizationRekeyRequiresANewBaseline) {
  constexpr std::uint64_t required_baseline_id = 0x1122'3344'5566'7788ULL;
  lsp_transport::reconnect_generation_fence fence;
  ASSERT_EQ(fence.initialize(7, 23), lsp_transport::generation_fence_result::accepted);
  ASSERT_EQ(fence.begin_fresh_association(8), lsp_transport::generation_fence_result::accepted);
  ASSERT_EQ(fence.mark_candidate_authenticated(8), lsp_transport::generation_fence_result::accepted);
  ASSERT_EQ(fence.neutralize_old_input(8), lsp_transport::generation_fence_result::accepted);
  ASSERT_EQ(
    fence.reject_attach(8, required_baseline_id),
    lsp_transport::generation_fence_result::accepted
  );
  EXPECT_TRUE(fence.accepts_connection_packet(7));
  EXPECT_FALSE(fence.accepts_input_packet(7, 23, 7));
  EXPECT_TRUE(fence.snapshot().baseline_required);
  EXPECT_EQ(
    fence.acknowledge_old_neutral_baseline(7, 23, required_baseline_id - 1),
    lsp_transport::generation_fence_result::baseline_mismatch
  );
  EXPECT_EQ(
    fence.acknowledge_old_neutral_baseline(7, 23, required_baseline_id),
    lsp_transport::generation_fence_result::accepted
  );
  EXPECT_EQ(fence.snapshot().active_input_generation, 23U);
  EXPECT_EQ(fence.snapshot().input_authority_epoch, 8U);
  EXPECT_FALSE(fence.accepts_input_packet(7, 23, 7));
  EXPECT_TRUE(fence.accepts_input_packet(7, 23, 8));
  EXPECT_EQ(fence.begin_fresh_association(8), lsp_transport::generation_fence_result::invalid_generation);
  EXPECT_EQ(fence.begin_fresh_association(9), lsp_transport::generation_fence_result::accepted);
}
