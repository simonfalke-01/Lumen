/**
 * @file tests/unit/test_lsp_input_plane.cpp
 * @brief Focused LSP/1 input wire/state regression tests.
 */

#include "src/protocol_lsp/input_plane/input_plane.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <span>
#include <vector>

namespace {
  namespace input = lumen::lsp::input_plane;

  /** @brief Deterministic baseline verifier used to prove the injected digest boundary. */
  class exact_digest_verifier final: public input::baseline_digest_verifier {
  public:
    /**
     * @brief Accept only the configured complete bytes and digest.
     *
     * @param bytes Candidate complete baseline.
     * @param digest Candidate digest.
     * @return `true` only for both exact configured values.
     */
    [[nodiscard]] bool verify(
      const std::span<const std::uint8_t> bytes,
      const std::array<std::uint8_t, 32> &digest
    ) const noexcept override {
      return std::ranges::equal(bytes, expected_bytes) && digest == expected_digest;
    }

    std::span<const std::uint8_t> expected_bytes {};  ///< Expected deterministic baseline.
    std::array<std::uint8_t, 32> expected_digest {};  ///< Expected SHA-256 bytes.
  };

  /**
   * @brief Build and parse one exact cumulative pointer packet.
   *
   * @param state Pointer wire payload.
   * @param state_sequence Logical state sequence.
   * @param edge_watermark Required applied edge watermark.
   * @return Owned packet bytes.
   */
  std::array<std::uint8_t, input::common_header_size + input::pointer_payload_size> pointer_packet(
    const input::pointer_payload &state,
    const std::uint64_t state_sequence,
    const std::uint64_t edge_watermark
  ) {
    std::array<std::uint8_t, input::pointer_payload_size> payload {};
    EXPECT_EQ(input::serialize_pointer_payload(state, payload), input::wire_error::none);
    std::array<std::uint8_t, input::common_header_size + input::pointer_payload_size> packet {};
    EXPECT_EQ(
      input::serialize_packet(
        {
          .input_generation = 7,
          .kind = input::packet_kind::pointer_motion,
          .state_sequence = state_sequence,
          .sample_time_us = 100 + state_sequence,
          .object_id = 1,
          .edge_watermark = edge_watermark,
        },
        payload,
        packet
      ),
      input::wire_error::none
    );
    return packet;
  }

  /**
   * @brief Build one valid edge record for ordering tests.
   *
   * @param edge_id Edge identifier.
   * @param control_id Test HID usage.
   * @return Complete edge value.
   */
  input::edge_record edge(const std::uint64_t edge_id, const std::uint16_t control_id) {
    return {
      .edge_id = edge_id,
      .physical_time_us = 1'000 + edge_id,
      .kind = input::edge_kind::key_down,
      .device = input::device_type::keyboard,
      .control_id = control_id,
      .device_id = 1,
      .instance_generation = 4,
    };
  }

  /**
   * @brief Build one exact edge-batch packet from contiguous records.
   *
   * @tparam Count Record count in the LSP/1 range.
   * @param records Contiguous records.
   * @return Owned packet bytes.
   */
  template<std::size_t Count>
  std::array<std::uint8_t, input::common_header_size + Count * input::edge_record_size> edge_packet(
    const std::array<input::edge_record, Count> &records
  ) {
    static_assert(Count > 0 && Count <= input::maximum_edges_per_batch);
    std::array<std::uint8_t, Count * input::edge_record_size> payload {};
    for (std::size_t index = 0; index < Count; ++index) {
      EXPECT_EQ(
        input::serialize_edge_record(records[index], std::span(payload).subspan(index * input::edge_record_size, input::edge_record_size)),
        input::wire_error::none
      );
    }
    std::array<std::uint8_t, input::common_header_size + Count * input::edge_record_size> packet {};
    EXPECT_EQ(
      input::serialize_packet(
        {
          .input_generation = 7,
          .kind = input::packet_kind::edge_batch,
          .state_sequence = 2,
          .sample_time_us = records.back().physical_time_us,
          .object_id = records.back().edge_id,
          .edge_watermark = records.back().edge_id,
        },
        payload,
        packet
      ),
      input::wire_error::none
    );
    return packet;
  }

  /**
   * @brief Select a pointer rate while deliberately keeping video FPS outside the input API.
   *
   * @param video_fps Unrelated presentation cadence used by the regression matrix.
   * @return Selected pointer reports per second.
   */
  std::uint32_t selected_pointer_rate_for_video_fps(const std::uint32_t video_fps) {
    EXPECT_TRUE(video_fps == 60 || video_fps == 120 || video_fps == 240);
    input::rate_manager<> manager;
    EXPECT_TRUE(manager.reset(9, input::ip_family::ipv4));
    EXPECT_EQ(manager.arrive(input::device_type::pointer, 1, 3), input::device_generation_result::accepted);
    const input::rate_request request {
      .input_generation = 9,
      .key = {
        .input_class = input::rate_class::pointer_motion,
        .device = input::device_type::pointer,
        .device_id = 1,
        .instance_generation = 3,
      },
      .observed_capture_rate = 16'000,
      .minimum_rate = 1'000,
      .preferred_rate = 8'000,
      .maximum_rate = 16'000,
      .worst_case_payload_bytes = input::pointer_payload_size,
    };
    input::rate_selection selection;
    EXPECT_EQ(manager.authorize(request, 16'000, selection), input::rate_result::selected);
    return selection.reports_per_second;
  }
}  // namespace

TEST(LspInputWire, SerializesExactFortyByteHeaderAndFiftySixBytePointerPayload) {
  const input::pointer_payload pointer {
    .instance_generation = 4,
    .mode = input::pointer_flag::relative,
    .represented_reports = 2,
    .physical_ordinal = 9,
    .cumulative_x = -12,
    .cumulative_y = 25,
    .cumulative_vertical_scroll = -3,
    .cumulative_horizontal_scroll = 4,
  };
  const auto bytes = pointer_packet(pointer, 2, 8);
  EXPECT_EQ(bytes.size(), std::size_t {96});
  EXPECT_EQ(bytes[0], 0);
  EXPECT_EQ(bytes[3], 7);
  EXPECT_EQ(bytes[4], static_cast<std::uint8_t>(input::packet_kind::pointer_motion));
  EXPECT_EQ(bytes[6], 0);
  EXPECT_EQ(bytes[7], input::pointer_payload_size);

  const auto parsed = input::parse_packet(bytes, 7);
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed.header.state_sequence, 2ULL);
  EXPECT_EQ(parsed.header.edge_watermark, 8ULL);
  const auto parsed_pointer = input::parse_pointer_payload(parsed.payload);
  ASSERT_TRUE(parsed_pointer);
  EXPECT_EQ(parsed_pointer.value, pointer);
}

TEST(LspInputWire, RejectsBoundsStaleGenerationUnknownKindsReservedFlagsAndTrailingBytes) {
  input::pointer_payload pointer {
    .instance_generation = 4,
    .mode = input::pointer_flag::relative,
    .represented_reports = 1,
    .physical_ordinal = 1,
  };
  auto bytes = pointer_packet(pointer, 2, 0);
  EXPECT_EQ(input::parse_packet(std::span(bytes).first<39>()).error, input::wire_error::header_too_short);
  EXPECT_EQ(input::parse_packet(bytes, 8).error, input::wire_error::invalid_generation);
  bytes[4] = 99;
  EXPECT_EQ(input::parse_packet(bytes, 7).error, input::wire_error::unknown_kind);
  bytes[4] = static_cast<std::uint8_t>(input::packet_kind::pointer_motion);
  bytes[5] = 1;
  EXPECT_EQ(input::parse_packet(bytes, 7).error, input::wire_error::reserved_flags);
  bytes[5] = 0;
  bytes[7] = input::pointer_payload_size - 1;
  EXPECT_EQ(input::parse_packet(bytes, 7).error, input::wire_error::invalid_payload_length);

  pointer.mode = input::pointer_flag::relative;
  pointer.absolute_x = 1;
  std::array<std::uint8_t, input::pointer_payload_size> payload {};
  EXPECT_EQ(input::serialize_pointer_payload(pointer, payload), input::wire_error::invalid_pointer);
}

TEST(LspInputState, CumulativePointerSurvivesLossAndWaitsForItsEdgeWatermark) {
  input::pointer_receiver receiver;
  input::pointer_payload baseline {
    .instance_generation = 4,
    .mode = input::pointer_flag::relative,
    .represented_reports = 1,
    .physical_ordinal = 1,
  };
  ASSERT_TRUE(receiver.reset(7, 1, baseline));

  input::pointer_payload lost = baseline;
  lost.physical_ordinal = 2;
  lost.cumulative_x = 5;
  const auto lost_bytes = pointer_packet(lost, 2, 1);
  ASSERT_TRUE(input::parse_packet(lost_bytes, 7));

  input::pointer_payload newest = lost;
  newest.physical_ordinal = 3;
  newest.cumulative_x = 12;
  newest.cumulative_y = -4;
  const auto newest_bytes = pointer_packet(newest, 3, 2);
  EXPECT_EQ(receiver.admit(input::parse_packet(newest_bytes, 7), 1), input::pointer_receive_result::waiting_for_edges);

  unsigned applications = 0;
  EXPECT_EQ(
    receiver.apply_ready(1, [&](const input::pointer_application &) {
      ++applications;
      return true;
    }),
    input::pointer_receive_result::waiting_for_edges
  );
  EXPECT_EQ(
    receiver.apply_ready(2, [&](const input::pointer_application &application) {
      ++applications;
      EXPECT_EQ(application.relative_x, 12);
      EXPECT_EQ(application.relative_y, -4);
      return true;
    }),
    input::pointer_receive_result::applied
  );
  EXPECT_EQ(applications, 1U);
}

TEST(LspInputEdges, AppliesLossAndReorderExactlyOnceWithExplicitAckWindow) {
  input::edge_receiver receiver;
  ASSERT_TRUE(receiver.reset(7));
  receiver.activate_baseline();

  const auto second_packet = edge_packet(std::array {edge(2, 20)});
  EXPECT_EQ(receiver.admit(input::parse_packet(second_packet, 7)), input::edge_receive_result::accepted);
  EXPECT_EQ(receiver.drain([](const input::edge_record &) {
    return true;
  }),
            std::size_t {0});
  EXPECT_EQ(receiver.reception_bitmap(), 0b10ULL);

  const auto first_packet = edge_packet(std::array {edge(1, 10)});
  EXPECT_EQ(receiver.admit(input::parse_packet(first_packet, 7)), input::edge_receive_result::accepted);
  std::array<std::uint16_t, 2> applied {};
  std::size_t applied_count = 0;
  EXPECT_EQ(
    receiver.drain([&](const input::edge_record &record) {
      applied[applied_count++] = record.control_id;
      return true;
    }),
    std::size_t {2}
  );
  EXPECT_EQ(applied, (std::array<std::uint16_t, 2> {10, 20}));
  EXPECT_EQ(receiver.admit(input::parse_packet(first_packet, 7)), input::edge_receive_result::duplicate);
  EXPECT_EQ(receiver.drain([](const input::edge_record &) {
    return true;
  }),
            std::size_t {0});

  input::edge_sender sender;
  ASSERT_TRUE(sender.reset(7));
  std::uint64_t first_id = 0;
  auto outbound = edge(0, 30);
  outbound.edge_id = 0;
  EXPECT_EQ(sender.enqueue(outbound, first_id), input::edge_send_result::accepted);
  std::array<input::edge_record, 16> due {};
  ASSERT_EQ(sender.due_batch(1'000, 1'000, due), std::size_t {1});
  EXPECT_TRUE(sender.mark_sent(first_id, 1, 1'000));
  EXPECT_EQ(sender.due_batch(1'249, 1'000, due), std::size_t {0});
  EXPECT_EQ(sender.due_batch(1'500, 1'000, due), std::size_t {1});
  EXPECT_EQ(sender.acknowledge(0, 1), std::size_t {1});
  EXPECT_EQ(sender.size(), std::size_t {0});
}

TEST(LspInputBaseline, CommitsAtomicallyOnlyAfterAllPartsAndDigestVerification) {
  constexpr std::array<std::uint8_t, 8> complete {1, 2, 3, 4, 5, 6, 7, 8};
  std::array<std::uint8_t, 32> digest {};
  digest[0] = 42;
  const input::common_header header {
    .input_generation = 7,
    .kind = input::packet_kind::baseline_part,
    .payload_length = 52,
    .state_sequence = 1,
    .object_id = 99,
  };
  input::baseline_receiver receiver;
  const input::baseline_part tail {
    .part_index = 1,
    .part_count = 2,
    .total_length = complete.size(),
    .part_offset = 4,
    .part_length = 4,
    .digest = digest,
    .bytes = std::span(complete).subspan(4),
  };
  const input::baseline_part head {
    .part_index = 0,
    .part_count = 2,
    .total_length = complete.size(),
    .part_offset = 0,
    .part_length = 4,
    .digest = digest,
    .bytes = std::span(complete).first(4),
  };
  EXPECT_EQ(receiver.add(header, tail), input::baseline_result::accepted);
  EXPECT_TRUE(receiver.committed_bytes().empty());
  exact_digest_verifier verifier;
  verifier.expected_bytes = complete;
  verifier.expected_digest = digest;
  EXPECT_EQ(receiver.commit(verifier), input::baseline_result::incomplete);
  EXPECT_EQ(receiver.add(header, head), input::baseline_result::accepted);

  auto wrong_digest = digest;
  wrong_digest[0] = 0;
  exact_digest_verifier rejecting;
  rejecting.expected_bytes = complete;
  rejecting.expected_digest = wrong_digest;
  EXPECT_EQ(receiver.commit(rejecting), input::baseline_result::digest_mismatch);
  EXPECT_TRUE(receiver.committed_bytes().empty());
  EXPECT_EQ(receiver.commit(verifier), input::baseline_result::committed);
  EXPECT_TRUE(std::ranges::equal(receiver.committed_bytes(), complete));
}

TEST(LspInputSupersession, KeepsExactControllerAndSensorKeysAndHonorsWatermarks) {
  std::array<std::uint8_t, 25> controller_payload {};
  controller_payload[0] = static_cast<std::uint8_t>(input::device_type::controller);
  lumen::lsp::wire::write_be<std::uint16_t>(std::span(controller_payload).subspan(2, 2), 1);
  lumen::lsp::wire::write_be<std::uint32_t>(std::span(controller_payload).subspan(4, 4), 2);
  lumen::lsp::wire::write_be<std::uint32_t>(std::span(controller_payload).subspan(8, 4), 5);
  lumen::lsp::wire::write_be<std::uint16_t>(std::span(controller_payload).subspan(12, 2), controller_payload.size());
  lumen::lsp::wire::write_be<std::uint64_t>(std::span(controller_payload).subspan(16, 8), 9);
  controller_payload[24] = 77;

  std::array<std::uint8_t, input::common_header_size + controller_payload.size()> packet {};
  ASSERT_EQ(
    input::serialize_packet(
      {
        .input_generation = 7,
        .kind = input::packet_kind::device_state,
        .state_sequence = 2,
        .object_id = input::make_device_object_id(input::device_type::controller, 2),
        .edge_watermark = 3,
      },
      controller_payload,
      packet
    ),
    input::wire_error::none
  );
  input::latest_state_table<4, 64> latest;
  EXPECT_EQ(latest.put(input::parse_packet(packet, 7)), input::latest_state_result::stored);
  EXPECT_EQ(
    latest.drain_ready(2, [](const input::common_header &, const input::supersession_key &, std::span<const std::uint8_t>) {
      return true;
    }),
    std::size_t {0}
  );
  EXPECT_EQ(
    latest.drain_ready(3, [](const input::common_header &, const input::supersession_key &key, std::span<const std::uint8_t> bytes) {
      EXPECT_EQ(key.device, input::device_type::controller);
      EXPECT_EQ(key.device_id, 2U);
      EXPECT_EQ(key.instance_generation, 5U);
      EXPECT_EQ(bytes.back(), 77);
      return true;
    }),
    std::size_t {1}
  );
}

TEST(LspInputRates, UsesExactThirtyTwoMegabitBudgetAndNeverDependsOnVideoFps) {
  EXPECT_EQ(input::wire_bytes_per_report(input::ip_family::ipv4, input::pointer_payload_size), 152U);
  EXPECT_EQ(input::wire_bits_per_second(input::ip_family::ipv4, input::pointer_payload_size, 16'000), 19'456'000ULL);
  EXPECT_EQ(input::wire_bytes_per_report(input::ip_family::ipv6, input::pointer_payload_size), 172U);

  EXPECT_EQ(selected_pointer_rate_for_video_fps(60), 8'000U);
  EXPECT_EQ(selected_pointer_rate_for_video_fps(120), 8'000U);
  EXPECT_EQ(selected_pointer_rate_for_video_fps(240), 8'000U);

  input::rate_manager<> manager;
  ASSERT_TRUE(manager.reset(9, input::ip_family::ipv4));
  ASSERT_EQ(manager.arrive(input::device_type::pointer, 1, 3), input::device_generation_result::accepted);
  const input::rate_request request {
    .input_generation = 9,
    .key = {
      .input_class = input::rate_class::pointer_motion,
      .device = input::device_type::pointer,
      .device_id = 1,
      .instance_generation = 3,
    },
    .observed_capture_rate = 16'000,
    .minimum_rate = 1'000,
    .preferred_rate = 16'000,
    .maximum_rate = 16'000,
    .worst_case_payload_bytes = input::pointer_payload_size,
  };
  input::rate_selection selection;
  EXPECT_EQ(manager.begin_hotplug(request, selection), input::rate_result::selected);
  EXPECT_EQ(selection.reports_per_second, 1'000U);
  EXPECT_FALSE(selection.authenticated);
  EXPECT_EQ(manager.authorize(request, 16'000, selection), input::rate_result::selected);
  EXPECT_EQ(selection.reports_per_second, 16'000U);
  EXPECT_LE(manager.reserved_bits_per_second(), input::maximum_input_wire_bits_per_second);
  EXPECT_EQ(manager.remove(input::device_type::pointer, 1, 2), input::device_generation_result::stale_generation);
  EXPECT_EQ(manager.remove(input::device_type::pointer, 1, 3), input::device_generation_result::accepted);
  EXPECT_EQ(manager.reserved_bits_per_second(), 0ULL);
  EXPECT_EQ(manager.arrive(input::device_type::pointer, 1, 3), input::device_generation_result::duplicate);
  EXPECT_EQ(manager.arrive(input::device_type::pointer, 1, 4), input::device_generation_result::accepted);
}

TEST(LspInputAck, RoundTripsPointersAndRetiresOnlyExplicitlyAcknowledgedEdges) {
  input::lspi_ack ack {
    .input_generation = 7,
    .accepted_baseline_id = 99,
    .highest_accepted_state_sequence = 12,
    .highest_applied_state_sequence = 11,
    .contiguous_edge_id = 8,
    .edge_reception_bitmap = 0b10,
    .host_receive_time_us = 100,
    .host_apply_time_us = 105,
    .first_video_frame_id = 44,
    .pointers = {{{.pointer_id = 1, .instance_generation = 4, .physical_ordinal = 88}}},
    .pointer_count = 1,
  };
  std::array<std::uint8_t, input::lspi_fixed_size + input::lspi_pointer_record_size> bytes {};
  ASSERT_EQ(input::serialize_lspi_ack(ack, bytes), input::lspi_error::none);
  const auto parsed = input::parse_lspi_ack(bytes, 7);
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed.value, ack);
  EXPECT_TRUE(input::lspi_acknowledges_edge(ack, 8));
  EXPECT_FALSE(input::lspi_acknowledges_edge(ack, 9));
  EXPECT_TRUE(input::lspi_acknowledges_edge(ack, 10));

  input::lspi_ack_scheduler scheduler;
  scheduler.state_applied();
  EXPECT_TRUE(scheduler.due(100));
  scheduler.mark_sent(100);
  scheduler.edge_applied();
  EXPECT_FALSE(scheduler.due(224));
  EXPECT_TRUE(scheduler.due(225));
}

TEST(LspControllerOutput, SupersedesLatestStateRetriesCommandsAndTerminatesOnStaleAck) {
  input::controller_output_manager host;
  ASSERT_TRUE(host.reset(7));
  ASSERT_EQ(host.bind(2, 5), input::controller_output_result::accepted);
  EXPECT_EQ(
    host.put_latest({
      .input_generation = 7,
      .controller_id = 2,
      .instance_generation = 5,
      .sequence = 10,
      .low_frequency_rumble = 100,
      .led_red = 3,
    }),
    input::controller_output_result::accepted
  );
  EXPECT_EQ(
    host.put_latest({
      .input_generation = 7,
      .controller_id = 2,
      .instance_generation = 5,
      .sequence = 11,
      .low_frequency_rumble = 200,
      .led_green = 4,
    }),
    input::controller_output_result::accepted
  );
  input::controller_latest_state latest;
  ASSERT_TRUE(host.take_latest(2, latest));
  EXPECT_EQ(latest.sequence, 11ULL);
  EXPECT_EQ(latest.low_frequency_rumble, 200U);

  input::controller_command command {
    .input_generation = 7,
    .controller_id = 2,
    .instance_generation = 5,
    .kind = input::controller_command_kind::adaptive_trigger,
    .parameter_length = 2,
    .deadline_us = 20'000,
  };
  command.parameters[0] = 9;
  command.parameters[1] = 8;
  std::uint64_t sequence = 0;
  ASSERT_EQ(host.enqueue_command(command, 1'000, sequence), input::controller_output_result::accepted);
  std::array<input::controller_command, 4> due {};
  ASSERT_EQ(host.due_commands(1'000, 2'000, due), std::size_t {1});
  EXPECT_EQ(due[0].sequence, sequence);
  EXPECT_EQ(host.mark_command_sent(sequence, 1'000), input::controller_output_result::accepted);
  EXPECT_EQ(host.due_commands(1'999, 2'000, due), std::size_t {0});
  EXPECT_EQ(host.due_commands(2'000, 2'000, due), std::size_t {1});

  std::array<std::uint8_t, input::maximum_lspg_packet_size> wire {};
  ASSERT_EQ(input::serialize_controller_command(due[0], wire), input::lspg_error::none);
  const auto parsed = input::parse_lspg(std::span(wire).first(input::lspg_header_size + 4 + 2));
  ASSERT_TRUE(parsed);
  input::controller_command decoded;
  ASSERT_EQ(input::decode_controller_command(parsed, decoded), input::lspg_error::none);
  EXPECT_TRUE(decoded.same_wire_command(due[0]));

  const input::controller_command_ack stale_ack {
    .input_generation = 7,
    .controller_id = 2,
    .instance_generation = 5,
    .sequence = sequence,
    .status = input::controller_command_status::stale_generation,
  };
  EXPECT_EQ(host.acknowledge(stale_ack), input::controller_output_result::accepted);
  EXPECT_EQ(host.pending_commands(), std::size_t {0});

  input::controller_output_manager client;
  ASSERT_TRUE(client.reset(7));
  ASSERT_EQ(client.bind(2, 6), input::controller_output_result::accepted);
  input::controller_command_ack response;
  unsigned applied = 0;
  EXPECT_EQ(
    client.receive_command(
      due[0],
      2'000,
      [&](const input::controller_command &) {
        ++applied;
        return input::controller_command_status::success;
      },
      response
    ),
    input::controller_output_result::stale_generation
  );
  EXPECT_EQ(response.status, input::controller_command_status::stale_generation);
  EXPECT_EQ(applied, 0U);
}

TEST(LspTextInput, HonorsEdgeBarrierWithoutBlockingLaterRealtimeOrReadyText) {
  input::text_barrier_state<4, 64> text;
  ASSERT_TRUE(text.reset(7));
  constexpr std::array<std::uint8_t, 2> e_acute {0xc3, 0xa9};
  constexpr std::array<std::uint8_t, 1> x {'x'};
  EXPECT_EQ(text.submit_inline(1, 7, 5, e_acute), input::text_result::accepted);
  EXPECT_EQ(text.submit_inline(2, 7, 0, x), input::text_result::accepted);

  std::vector<std::uint64_t> delivered;
  EXPECT_EQ(
    text.drain_ready(0, [&](const input::text_delivery &value) {
      delivered.push_back(value.request_id);
      return true;
    }),
    std::size_t {1}
  );
  EXPECT_EQ(delivered, (std::vector<std::uint64_t> {2}));
  EXPECT_EQ(
    text.drain_ready(5, [&](const input::text_delivery &value) {
      delivered.push_back(value.request_id);
      return true;
    }),
    std::size_t {1}
  );
  EXPECT_EQ(delivered, (std::vector<std::uint64_t> {2, 1}));
  EXPECT_EQ(text.drain_ready(5, [](const input::text_delivery &) {
    return true;
  }),
            std::size_t {0});

  constexpr std::array<std::uint8_t, 3> surrogate {0xed, 0xa0, 0x80};
  EXPECT_EQ(text.submit_inline(3, 7, 0, surrogate), input::text_result::invalid_text);
}
