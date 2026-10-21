/**
 * @file tests/unit/test_lsp_media.cpp
 * @brief Exact LSP/1 codec packetization and bounded media-pipeline invariants.
 */

#include "src/protocol_lsp/media/media.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <span>
#include <vector>

namespace {
  /** @brief Exact RFC 8285 one-byte extension block used for boundary-policy tests. */
  constexpr std::array<std::uint8_t, 8> test_extension {0xbe, 0xde, 0x00, 0x01, 0x10, 0, 0, 0};

  /**
   * @brief Build a deterministic video RTP packetization configuration.
   *
   * @param udp_payload_size Complete protected UDP payload size.
   * @return Test configuration with the same valid extension block for each boundary overlap.
   */
  lumen::lsp::media::video_packetization_config video_config(const std::size_t udp_payload_size = 1'200) {
    return {
      .stream = {
        .payload_type = 96,
        .first_sequence_number = 0x1234,
        .timestamp = 0x01020304,
        .ssrc = 0x11223344,
      },
      .path = {
        .family = lumen::lsp::media::ip_family::ipv4,
        .udp_payload_size = udp_payload_size,
      },
      .extensions = {
        .first_and_final = test_extension,
        .first = test_extension,
        .second_and_final = test_extension,
        .second = test_extension,
        .final = test_extension,
      },
    };
  }

  /**
   * @brief Return codec payload bytes after the RTP fixed header and optional extension block.
   *
   * @param packet Complete plaintext RTP packet.
   * @return Borrowed codec payload.
   */
  std::span<const std::uint8_t> codec_payload(const lumen::lsp::media::rtp_packet &packet) {
    const auto parsed = lumen::lsp::parse_rtp_fixed_header(packet.bytes);
    EXPECT_TRUE(parsed);
    auto offset = parsed.bytes_consumed;
    if (parsed.header.extension) {
      EXPECT_GE(packet.bytes.size(), offset + 4);
      const auto words = static_cast<std::size_t>((std::uint16_t {packet.bytes[offset + 2]} << 8U) | packet.bytes[offset + 3]);
      offset += 4 + words * 4;
    }
    EXPECT_LE(offset, packet.bytes.size());
    return std::span<const std::uint8_t>(packet.bytes).subspan(offset);
  }

  /**
   * @brief Retain copied test payload bytes.
   *
   * @param bytes Payload bytes.
   * @return Nonempty retained packet slice.
   */
  lumen::lsp::media::retained_packet_slice retained(const std::initializer_list<std::uint8_t> bytes) {
    const std::vector<std::uint8_t> storage(bytes);
    auto slice = lumen::lsp::media::retained_packet_slice::copy(storage);
    EXPECT_TRUE(slice.has_value());
    return std::move(*slice);
  }
}  // namespace

TEST(LspMediaCommon, EnforcesClockPathAndBoundaryExtensionContracts) {
  using namespace lumen::lsp::media;
  EXPECT_EQ(video_clock_rate, 90'000U);
  EXPECT_EQ(audio_clock_rate, 48'000U);
  EXPECT_FALSE(make_path_payload_limit(ip_family::ipv4, 1'199));
  EXPECT_TRUE(make_path_payload_limit(ip_family::ipv4, 1'200));
  EXPECT_TRUE(make_path_payload_limit(ip_family::ipv4, 8'972));
  EXPECT_FALSE(make_path_payload_limit(ip_family::ipv4, 8'973));
  EXPECT_TRUE(make_path_payload_limit(ip_family::ipv6, 8'952));
  EXPECT_FALSE(make_path_payload_limit(ip_family::ipv6, 8'953));
  EXPECT_EQ(make_path_payload_limit(ip_family::ipv4, 1'200).limit.plaintext_rtp_capacity(), 1'184U);

  for (std::size_t count = 1; count <= 7; ++count) {
    for (std::size_t index = 0; index < count; ++index) {
      EXPECT_EQ(carries_frame_boundary_extensions(index, count), index < 2 || index + 1 == count);
    }
  }
  EXPECT_EQ(packet_role(0, 1), frame_packet_role::first_and_final);
  EXPECT_EQ(packet_role(1, 2), frame_packet_role::second_and_final);
  EXPECT_EQ(packet_role(2, 4), frame_packet_role::middle);
  EXPECT_EQ(packet_role(3, 4), frame_packet_role::final);
}

TEST(LspMediaH264, EmitsSingleNalAndExactSameFrameStapA) {
  constexpr std::array<std::uint8_t, 3> single {0x65, 0xaa, 0xbb};
  const std::array<std::span<const std::uint8_t>, 1> one {single};
  const auto single_result = lumen::lsp::media::packetize_h264(one, video_config());
  ASSERT_TRUE(single_result);
  ASSERT_EQ(single_result.packets.size(), 1U);
  EXPECT_TRUE(std::ranges::equal(codec_payload(single_result.packets.front()), single));
  const auto single_header = lumen::lsp::parse_rtp_fixed_header(single_result.packets.front().bytes);
  ASSERT_TRUE(single_header);
  EXPECT_TRUE(single_header.header.marker);
  EXPECT_TRUE(single_header.header.extension);

  constexpr std::array<std::uint8_t, 2> first {0x41, 0x11};
  constexpr std::array<std::uint8_t, 3> second {0x65, 0x22, 0x33};
  const std::array<std::span<const std::uint8_t>, 2> nals {first, second};
  const auto aggregate = lumen::lsp::media::packetize_h264(nals, video_config());
  ASSERT_TRUE(aggregate);
  ASSERT_EQ(aggregate.packets.size(), 1U);
  constexpr std::array<std::uint8_t, 10> expected {0x78, 0, 2, 0x41, 0x11, 0, 3, 0x65, 0x22, 0x33};
  EXPECT_TRUE(std::ranges::equal(codec_payload(aggregate.packets.front()), expected));
}

TEST(LspMediaH264, FuaFillsExtensionFreeMiddleAndMarksOnlyFinalPacket) {
  std::vector<std::uint8_t> nal(3'501, 0x5a);
  nal.front() = 0x65;
  const std::array<std::span<const std::uint8_t>, 1> nals {nal};
  const auto result = lumen::lsp::media::packetize_h264(nals, video_config());
  ASSERT_TRUE(result);
  ASSERT_EQ(result.packets.size(), 4U);

  EXPECT_EQ(codec_payload(result.packets[0])[0], 0x7c);
  EXPECT_EQ(codec_payload(result.packets[0])[1], 0x85);
  EXPECT_EQ(codec_payload(result.packets[1])[1], 0x05);
  EXPECT_EQ(codec_payload(result.packets[2]).size(), 1'172U);
  EXPECT_EQ(codec_payload(result.packets[3])[1], 0x45);
  EXPECT_TRUE(lumen::lsp::parse_rtp_fixed_header(result.packets[0].bytes).header.extension);
  EXPECT_TRUE(lumen::lsp::parse_rtp_fixed_header(result.packets[1].bytes).header.extension);
  EXPECT_FALSE(lumen::lsp::parse_rtp_fixed_header(result.packets[2].bytes).header.extension);
  EXPECT_TRUE(lumen::lsp::parse_rtp_fixed_header(result.packets[3].bytes).header.extension);
  for (std::size_t index = 0; index < result.packets.size(); ++index) {
    EXPECT_EQ(lumen::lsp::parse_rtp_fixed_header(result.packets[index].bytes).header.marker, index + 1 == result.packets.size());
    EXPECT_LE(result.packets[index].bytes.size() + lumen::lsp::media::srtp_aead_tag_size, 1'200U);
  }
}

TEST(LspMediaH264, RejectsEmptyForbiddenAndPacketizationNalTypes) {
  const std::array<std::span<const std::uint8_t>, 1> empty {std::span<const std::uint8_t> {}};
  EXPECT_EQ(lumen::lsp::media::packetize_h264(empty, video_config()).error, lumen::lsp::media::packetization_error::empty_codec_unit);
  constexpr std::array<std::uint8_t, 1> forbidden {0x81};
  const std::array<std::span<const std::uint8_t>, 1> forbidden_input {forbidden};
  EXPECT_EQ(lumen::lsp::media::packetize_h264(forbidden_input, video_config()).error, lumen::lsp::media::packetization_error::malformed_codec_unit);
  constexpr std::array<std::uint8_t, 1> stap_source {0x78};
  const std::array<std::span<const std::uint8_t>, 1> stap_input {stap_source};
  EXPECT_EQ(lumen::lsp::media::packetize_h264(stap_input, video_config()).error, lumen::lsp::media::packetization_error::malformed_codec_unit);
}

TEST(LspMediaHevc, EmitsExactSingleLayerApAndFuHeaders) {
  constexpr std::array<std::uint8_t, 3> first {0x40, 0x01, 0xaa};
  constexpr std::array<std::uint8_t, 4> second {0x42, 0x01, 0xbb, 0xcc};
  const std::array<std::span<const std::uint8_t>, 2> nals {first, second};
  const auto aggregate = lumen::lsp::media::packetize_hevc(nals, video_config());
  ASSERT_TRUE(aggregate);
  ASSERT_EQ(aggregate.packets.size(), 1U);
  constexpr std::array<std::uint8_t, 13> expected {0x60, 0x01, 0, 3, 0x40, 0x01, 0xaa, 0, 4, 0x42, 0x01, 0xbb, 0xcc};
  EXPECT_TRUE(std::ranges::equal(codec_payload(aggregate.packets.front()), expected));

  std::vector<std::uint8_t> large(3'502, 0x5a);
  large[0] = 0x02;
  large[1] = 0x01;
  const std::array<std::span<const std::uint8_t>, 1> large_nal {large};
  const auto fragmented = lumen::lsp::media::packetize_hevc(large_nal, video_config());
  ASSERT_TRUE(fragmented);
  ASSERT_GE(fragmented.packets.size(), 3U);
  const auto first_payload = codec_payload(fragmented.packets.front());
  const auto final_payload = codec_payload(fragmented.packets.back());
  EXPECT_EQ(first_payload[0], 0x62);
  EXPECT_EQ(first_payload[1], 0x01);
  EXPECT_EQ(first_payload[2], 0x81);
  EXPECT_EQ(final_payload[2], 0x41);
  EXPECT_TRUE(lumen::lsp::parse_rtp_fixed_header(fragmented.packets.back().bytes).header.marker);
}

TEST(LspMediaHevc, RejectsTemporalIdZeroAndPayloadFormatNalTypes) {
  constexpr std::array<std::uint8_t, 2> temporal_zero {0x02, 0x00};
  const std::array<std::span<const std::uint8_t>, 1> temporal_input {temporal_zero};
  EXPECT_EQ(lumen::lsp::media::packetize_hevc(temporal_input, video_config()).error, lumen::lsp::media::packetization_error::malformed_codec_unit);
  constexpr std::array<std::uint8_t, 2> ap_source {0x60, 0x01};
  const std::array<std::span<const std::uint8_t>, 1> ap_input {ap_source};
  EXPECT_EQ(lumen::lsp::media::packetize_hevc(ap_input, video_config()).error, lumen::lsp::media::packetization_error::malformed_codec_unit);
}

TEST(LspMediaAv1, EmitsExactAggregationAndFragmentDescriptors) {
  constexpr std::array<std::uint8_t, 2> sequence_header {0x08, 0xaa};
  constexpr std::array<std::uint8_t, 3> frame_header {0x18, 0xbb, 0xcc};
  const std::array<std::span<const std::uint8_t>, 2> obus {sequence_header, frame_header};
  const auto aggregate = lumen::lsp::media::packetize_av1(obus, true, video_config());
  ASSERT_TRUE(aggregate);
  ASSERT_EQ(aggregate.packets.size(), 1U);
  constexpr std::array<std::uint8_t, 7> expected {0x28, 0x02, 0x08, 0xaa, 0x18, 0xbb, 0xcc};
  EXPECT_TRUE(std::ranges::equal(codec_payload(aggregate.packets.front()), expected));
  const auto parsed = lumen::lsp::media::parse_av1_aggregation_header(codec_payload(aggregate.packets.front()));
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed.header.element_count, 2);
  EXPECT_TRUE(parsed.header.starts_coded_video_sequence);

  std::vector<std::uint8_t> large(3'500, 0x5a);
  large.front() = 0x18;
  const std::array<std::span<const std::uint8_t>, 1> large_obu {large};
  const auto fragmented = lumen::lsp::media::packetize_av1(large_obu, true, video_config());
  ASSERT_TRUE(fragmented);
  ASSERT_GE(fragmented.packets.size(), 3U);
  EXPECT_EQ(codec_payload(fragmented.packets.front())[0], 0x58);
  EXPECT_EQ(codec_payload(fragmented.packets[1])[0], 0xd0);
  EXPECT_EQ(codec_payload(fragmented.packets.back())[0], 0x90);
  EXPECT_TRUE(lumen::lsp::parse_rtp_fixed_header(fragmented.packets.back().bytes).header.marker);
}

TEST(LspMediaAv1, RejectsMalformedDescriptorsAndUnnormalizedObus) {
  constexpr std::array<std::uint8_t, 1> reserved_header {0x01};
  EXPECT_EQ(lumen::lsp::media::parse_av1_aggregation_header(reserved_header).error, lumen::lsp::media::av1_header_error::reserved_bits);
  constexpr std::array<std::uint8_t, 1> continuation_new_sequence {0x98};
  EXPECT_EQ(lumen::lsp::media::parse_av1_aggregation_header(continuation_new_sequence).error, lumen::lsp::media::av1_header_error::invalid_sequence_start);
  constexpr std::array<std::uint8_t, 2> has_size_field {0x0a, 0x00};
  const std::array<std::span<const std::uint8_t>, 1> input {has_size_field};
  EXPECT_EQ(lumen::lsp::media::packetize_av1(input, false, video_config()).error, lumen::lsp::media::packetization_error::malformed_codec_unit);
  constexpr std::array<std::uint8_t, 1> temporal_delimiter {0x10};
  const std::array<std::span<const std::uint8_t>, 1> delimiter_input {temporal_delimiter};
  EXPECT_EQ(lumen::lsp::media::packetize_av1(delimiter_input, false, video_config()).error, lumen::lsp::media::packetization_error::empty_access_unit);
}

TEST(LspMediaOpus, UsesOnePacketNoFragmentationAndContinuousFortyEightKhzTimeline) {
  using namespace lumen::lsp::media;
  opus_sender_timeline timeline(48'000);
  const auto first_timing = timeline.prepare(static_cast<std::uint16_t>(opus_frame_samples::ms_5));
  ASSERT_TRUE(first_timing);
  EXPECT_EQ(first_timing->timestamp, 48'000U);
  EXPECT_TRUE(first_timing->marker);
  const auto second_timing = timeline.prepare(240);
  ASSERT_TRUE(second_timing);
  EXPECT_EQ(second_timing->timestamp, 48'240U);
  EXPECT_FALSE(second_timing->marker);
  timeline.discontinuity(96'000);
  ASSERT_TRUE(timeline.prepare(240)->marker);

  constexpr std::array<std::uint8_t, 4> opus {0xf8, 0xff, 0xfe, 0x01};
  const opus_packetization_config config {
    .stream = {.payload_type = 111, .first_sequence_number = 7, .timestamp = first_timing->timestamp, .ssrc = 9},
    .path = {.family = ip_family::ipv6, .udp_payload_size = 1'200},
    .marker = first_timing->marker,
  };
  const auto packetized = packetize_opus(opus, config);
  ASSERT_TRUE(packetized);
  ASSERT_EQ(packetized.packets.size(), 1U);
  EXPECT_TRUE(std::ranges::equal(codec_payload(packetized.packets.front()), opus));
  const auto header = lumen::lsp::parse_rtp_fixed_header(packetized.packets.front().bytes);
  ASSERT_TRUE(header);
  EXPECT_EQ(header.header.timestamp, 48'000U);
  EXPECT_TRUE(header.header.marker);

  std::vector<std::uint8_t> oversized(maximum_opus_packet_size + 1, 0);
  EXPECT_EQ(packetize_opus(oversized, config).error, packetization_error::codec_unit_too_large);
}

TEST(LspMediaOpus, HoldsExactlyOnePacketAndResetsOnDiscontinuityOrTimestampGap) {
  using namespace lumen::lsp::media;
  audio_preroll_state preroll;
  EXPECT_EQ(preroll.observe(1'000, 240), audio_preroll_action::hold);
  EXPECT_FALSE(preroll.playing());
  EXPECT_EQ(preroll.observe(1'240, 240), audio_preroll_action::start_playout);
  EXPECT_TRUE(preroll.playing());
  EXPECT_EQ(preroll.observe(1'480, 240), audio_preroll_action::continue_playout);
  EXPECT_EQ(preroll.observe(2'000, 240), audio_preroll_action::reset_and_hold);
  EXPECT_FALSE(preroll.playing());
  EXPECT_EQ(preroll.observe(2'240, 240), audio_preroll_action::start_playout);
  EXPECT_EQ(preroll.observe(3'000, 240, true), audio_preroll_action::reset_and_hold);
  EXPECT_EQ(preroll.observe(3'240, 241), audio_preroll_action::invalid_duration);
}

TEST(LspMediaAdmission, ComputesClampedDeadlineAndRequiresCompleteSerializationAndCredit) {
  using namespace lumen::lsp::media;
  const network_deadline_request deadline_request {
    .capture_time_us = 1'000,
    .maximum_capture_to_client_us = 5'000,
    .encode_reserve_us = 500,
    .decode_reserve_us = 300,
    .render_reserve_us = 200,
    .next_presentation_time_us = 4'800,
  };
  EXPECT_EQ(compute_network_deadline(deadline_request), 4'800U);

  frame_admission_request request {
    .size_mode = frame_size_mode::bounded_incremental,
    .source_bytes = 1'000,
    .selected_repair_bytes = 500,
    .pacing_rate_bits_per_second = 8'000'000,
    .now_us = 1'000,
    .network_deadline_us = 2'500,
    .decoder_credits = 2,
    .reference_path_valid = true,
  };
  const auto accepted = admit_frame(request);
  ASSERT_TRUE(accepted);
  EXPECT_EQ(accepted.estimated_serialization_us, 1'500U);
  EXPECT_EQ(accepted.estimated_completion_us, 2'500U);
  request.network_deadline_us = 2'499;
  EXPECT_EQ(admit_frame(request).status, frame_admission_status::misses_deadline);
  request.network_deadline_us = 2'500;
  request.decoder_credits = 0;
  EXPECT_EQ(admit_frame(request).status, frame_admission_status::decoder_saturated);
  request.decoder_credits = 2;
  request.reference_path_valid = false;
  EXPECT_EQ(admit_frame(request).status, frame_admission_status::invalid_reference_path);
}

TEST(LspMediaReassembly, ReordersTwoIncompleteFramesAndReturnsRetainedCompleteHandle) {
  using namespace lumen::lsp::media;
  video_frame_reassembler reassembler(64);
  const frame_key key {.ssrc = 7, .extended_timestamp = 90'000};
  EXPECT_EQ(reassembler.add({.key = key, .extended_sequence = 11, .deadline_us = 10'000, .payload = retained({2})}, 1).status, frame_reassembly_status::stored);
  EXPECT_EQ(reassembler.add({.key = key, .frame_id = 44, .extended_sequence = 10, .deadline_us = 10'000, .starts_frame = true, .payload = retained({1})}, 1).status, frame_reassembly_status::stored);
  const auto duplicate = reassembler.add({.key = key, .frame_id = 44, .extended_sequence = 10, .deadline_us = 10'000, .starts_frame = true, .payload = retained({1})}, 1);
  EXPECT_EQ(duplicate.status, frame_reassembly_status::duplicate);
  const auto completed = reassembler.add({.key = key, .frame_id = 44, .extended_sequence = 12, .deadline_us = 10'000, .ends_frame = true, .marker = true, .payload = retained({3})}, 1);
  ASSERT_EQ(completed.status, frame_reassembly_status::completed);
  ASSERT_TRUE(completed.frame);
  EXPECT_EQ(completed.frame.get()->frame_id(), 44U);
  EXPECT_EQ(completed.frame.get()->slices().size(), 3U);
  EXPECT_EQ(completed.frame.get()->coalesce(), (std::vector<std::uint8_t> {1, 2, 3}));
  EXPECT_EQ(reassembler.incomplete_frames(), 0U);
}

TEST(LspMediaReassembly, RetainsPacketStorageAndEvictsOnlyForAThirdIncompleteFrame) {
  using namespace lumen::lsp::media;
  auto storage = std::make_shared<const std::vector<std::uint8_t>>(std::initializer_list<std::uint8_t> {9, 8, 7});
  auto slice = retained_packet_slice::retain(storage, 1, 2);
  ASSERT_TRUE(slice);
  storage.reset();
  EXPECT_EQ(slice->bytes()[0], 8);
  EXPECT_EQ(slice->bytes()[1], 7);

  video_frame_reassembler reassembler(64);
  const frame_key first {.ssrc = 1, .extended_timestamp = 1};
  const frame_key second {.ssrc = 1, .extended_timestamp = 2};
  const frame_key third {.ssrc = 1, .extended_timestamp = 3};
  EXPECT_EQ(reassembler.add({.key = first, .extended_sequence = 1, .deadline_us = 100, .payload = retained({1})}, 1).status, frame_reassembly_status::stored);
  EXPECT_EQ(reassembler.add({.key = second, .extended_sequence = 2, .deadline_us = 100, .payload = retained({2})}, 1).status, frame_reassembly_status::stored);
  const auto eviction = reassembler.add({.key = third, .extended_sequence = 3, .deadline_us = 100, .payload = retained({3})}, 1);
  EXPECT_EQ(eviction.status, frame_reassembly_status::evicted_and_stored);
  ASSERT_TRUE(eviction.evicted);
  EXPECT_EQ(*eviction.evicted, first);
  EXPECT_EQ(reassembler.incomplete_frames(), 2U);
  EXPECT_EQ(reassembler.expire(100), 2U);
}

TEST(LspMediaReassembly, RejectsMalformedBoundariesMarkersConflictsAndOversizeFrames) {
  using namespace lumen::lsp::media;
  video_frame_reassembler reassembler(2);
  const frame_key key {.ssrc = 2, .extended_timestamp = 4};
  EXPECT_EQ(reassembler.add({.key = key, .extended_sequence = 1, .deadline_us = 100, .ends_frame = true, .marker = false, .payload = retained({1})}, 1).status, frame_reassembly_status::malformed);
  EXPECT_EQ(reassembler.add({.key = key, .extended_sequence = 1, .deadline_us = 100, .starts_frame = true, .payload = retained({1, 2, 3})}, 1).status, frame_reassembly_status::frame_too_large);

  EXPECT_EQ(reassembler.add({.key = key, .frame_id = 9, .extended_sequence = 1, .deadline_us = 100, .starts_frame = true, .payload = retained({1})}, 1).status, frame_reassembly_status::stored);
  EXPECT_EQ(reassembler.add({.key = key, .frame_id = 10, .extended_sequence = 2, .deadline_us = 100, .ends_frame = true, .marker = true, .payload = retained({2})}, 1).status, frame_reassembly_status::malformed);
  EXPECT_EQ(reassembler.add({.key = key, .extended_sequence = 3, .deadline_us = 1, .payload = retained({3})}, 1).status, frame_reassembly_status::expired);
}

TEST(LspMediaPooledReassembly, ReordersDuplicatesAndRecyclesCompletedStorageExplicitly) {
  using namespace lumen::lsp::media;
  pooled_video_frame_reassembler reassembler(64, 8);
  ASSERT_TRUE(reassembler.ready());
  const frame_key key {.ssrc = 7, .extended_timestamp = 90'000};
  const std::array<std::uint8_t, 1> first {1};
  const std::array<std::uint8_t, 1> middle {2};
  const std::array<std::uint8_t, 1> final {3};

  EXPECT_EQ(reassembler.add({.key = key, .extended_sequence = 11, .deadline_us = 10'000, .payload = middle}, 1).status, frame_reassembly_status::stored);
  EXPECT_EQ(reassembler.add({.key = key, .frame_id = 44, .extended_sequence = 10, .deadline_us = 10'000, .starts_frame = true, .payload = first}, 1).status, frame_reassembly_status::stored);
  EXPECT_EQ(reassembler.add({.key = key, .frame_id = 44, .extended_sequence = 10, .deadline_us = 10'000, .starts_frame = true, .payload = first}, 1).status, frame_reassembly_status::duplicate);
  const auto completed = reassembler.add({.key = key, .frame_id = 44, .extended_sequence = 12, .deadline_us = 10'000, .ends_frame = true, .marker = true, .payload = final}, 1);
  ASSERT_EQ(completed.status, frame_reassembly_status::completed);
  ASSERT_TRUE(completed.frame);
  EXPECT_EQ(completed.frame.frame_id, 44U);
  ASSERT_EQ(completed.frame.slices.size(), 3U);
  EXPECT_EQ(completed.frame.slices[0][0], 1U);
  EXPECT_EQ(completed.frame.slices[1][0], 2U);
  EXPECT_EQ(completed.frame.slices[2][0], 3U);
  EXPECT_EQ(completed.frame.total_size, 3U);
  EXPECT_EQ(reassembler.incomplete_frames(), 0U);
  EXPECT_TRUE(reassembler.release(completed.frame));
  EXPECT_FALSE(reassembler.release(completed.frame));
}

TEST(LspMediaPooledReassembly, PreservesCompletedViewsWhileBoundingLossEvictionAndExpiry) {
  using namespace lumen::lsp::media;
  pooled_video_frame_reassembler reassembler(8, 2);
  ASSERT_TRUE(reassembler.ready());
  const std::array<std::uint8_t, 1> one {1};
  const frame_key complete_key {.ssrc = 1, .extended_timestamp = 1};
  const auto completed = reassembler.add({
                                           .key = complete_key,
                                           .frame_id = 1,
                                           .extended_sequence = 1,
                                           .deadline_us = 100,
                                           .starts_frame = true,
                                           .ends_frame = true,
                                           .marker = true,
                                           .payload = one,
                                         },
                                         1);
  ASSERT_EQ(completed.status, frame_reassembly_status::completed);

  const frame_key second {.ssrc = 1, .extended_timestamp = 2};
  const frame_key third {.ssrc = 1, .extended_timestamp = 3};
  EXPECT_EQ(reassembler.add({.key = second, .extended_sequence = 2, .deadline_us = 100, .payload = one}, 1).status, frame_reassembly_status::stored);
  const auto eviction = reassembler.add({.key = third, .extended_sequence = 3, .deadline_us = 100, .payload = one}, 1);
  EXPECT_EQ(eviction.status, frame_reassembly_status::evicted_and_stored);
  ASSERT_TRUE(eviction.evicted);
  EXPECT_EQ(*eviction.evicted, second);
  EXPECT_EQ(completed.frame.slices[0][0], 1U);
  EXPECT_EQ(reassembler.expire(100), 1U);
  EXPECT_TRUE(reassembler.release(completed.frame));

  pooled_video_frame_reassembler fragment_limited(8, 1);
  ASSERT_TRUE(fragment_limited.ready());
  EXPECT_EQ(fragment_limited.add({.key = second, .extended_sequence = 1, .deadline_us = 100, .starts_frame = true, .payload = one}, 1).status, frame_reassembly_status::stored);
  EXPECT_EQ(fragment_limited.add({.key = second, .extended_sequence = 2, .deadline_us = 100, .ends_frame = true, .marker = true, .payload = one}, 1).status, frame_reassembly_status::frame_too_large);
}

TEST(LspMediaDecodePipeline, EnforcesTwoToFourCreditsAndLatestFrameMailboxDepthOne) {
  using namespace lumen::lsp::media;
  decoder_credit_state credits;
  EXPECT_FALSE(credits.configure(1));
  EXPECT_TRUE(credits.configure(4));
  for (int index = 0; index < 4; ++index) {
    EXPECT_TRUE(credits.try_acquire());
  }
  EXPECT_FALSE(credits.try_acquire());
  EXPECT_EQ(credits.available(), 0);
  EXPECT_FALSE(credits.configure(2));
  EXPECT_TRUE(credits.release());
  EXPECT_EQ(credits.available(), 1);

  auto first_frame = std::make_shared<const completed_frame>(
    frame_key {.ssrc = 1, .extended_timestamp = 1},
    1,
    100,
    std::vector<retained_packet_slice> {retained({1})},
    1
  );
  auto second_frame = std::make_shared<const completed_frame>(
    frame_key {.ssrc = 1, .extended_timestamp = 2},
    2,
    100,
    std::vector<retained_packet_slice> {retained({2})},
    1
  );
  render_mailbox mailbox;
  EXPECT_FALSE(mailbox.publish(retained_frame_handle(first_frame)));
  EXPECT_TRUE(mailbox.publish(retained_frame_handle(second_frame)));
  ASSERT_TRUE(mailbox.occupied());
  const auto latest = mailbox.take();
  ASSERT_TRUE(latest);
  EXPECT_EQ(latest.get()->frame_id(), 2U);
  EXPECT_FALSE(mailbox.occupied());
}
