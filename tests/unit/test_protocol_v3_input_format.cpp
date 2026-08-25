/**
 * @file tests/unit/test_protocol_v3_input_format.cpp
 * @brief Protocol-v3 input format-version admission tests.
 */

#include "src/protocol_common/input_state.h"
#include "src/protocol_v3/control_session.h"
#include "src/protocol_v3/media_pipeline.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <limits>
#include <memory>
#include <vector>

namespace {
  namespace media = lumen::protocol_v3::media;
  namespace quic = lumen::protocol_v3::quic_server;

  template<class Integer>
  void append_be(std::vector<std::uint8_t> &bytes, Integer value) {
    for (std::size_t index = 0; index < sizeof(Integer); ++index) {
      bytes.push_back(static_cast<std::uint8_t>(value >> ((sizeof(Integer) - index - 1) * 8U)));
    }
  }

  template<class Integer>
  void write_be(std::vector<std::uint8_t> &bytes, const std::size_t offset, Integer value) {
    for (std::size_t index = 0; index < sizeof(Integer); ++index) {
      bytes[offset + sizeof(Integer) - index - 1] = static_cast<std::uint8_t>(value);
      value >>= 8U;
    }
  }

  std::uint32_t read_be32(const std::span<const std::uint8_t> bytes, const std::size_t offset) {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 8U) |
           bytes[offset + 3];
  }

  class transport_t final: public media::TransportSink {
  public:
    struct packet_event_t {
      std::uint64_t connection_id {};
      quic::Lane lane {quic::Lane::control};
      quic::MonotonicClock::time_point deadline {};
      bool replaceable {};
      std::vector<std::uint8_t> bytes;
    };

    struct video_event_t {
      std::uint64_t connection_id {};
      std::shared_ptr<const quic::LazyVideoFrame> frame;
    };

    bool update_policy(std::uint64_t, quic::Profile, std::uint64_t) noexcept override {
      return true;
    }

    quic::EnqueueResult enqueue(const std::uint64_t connection_id, quic::Packet packet) override {
      if (stopped) {
        return quic::EnqueueResult::shutting_down;
      }
      if (packets.size() >= maximum_packets) {
        return quic::EnqueueResult::would_block;
      }
      packets.emplace_back(*packet.bytes);
      packet_events.push_back({
        .connection_id = connection_id,
        .lane = packet.lane,
        .deadline = packet.deadline,
        .replaceable = packet.replaceable,
        .bytes = *packet.bytes,
      });
      return quic::EnqueueResult::queued;
    }

    quic::EnqueueResult enqueue_video_frame(
      const std::uint64_t connection_id,
      std::shared_ptr<const quic::LazyVideoFrame> frame
    ) override {
      video_events.push_back({connection_id, frame});
      video_frames.emplace_back(std::move(frame));
      return video_enqueue_result;
    }

    void stop() noexcept {
      stopped = true;
    }

    quic::EnqueueResult video_enqueue_result {quic::EnqueueResult::queued};
    std::size_t maximum_packets {std::numeric_limits<std::size_t>::max()};
    bool stopped {};
    std::vector<std::vector<std::uint8_t>> packets;
    std::vector<packet_event_t> packet_events;
    std::vector<std::shared_ptr<const quic::LazyVideoFrame>> video_frames;
    std::vector<video_event_t> video_events;
  };

  class input_t final: public media::InputSink {
  public:
    bool submit(const media::InputBatch &batch) override {
      ++submissions;
      last_state.assign(batch.state_block.begin(), batch.state_block.end());
      return true;
    }

    void reset() noexcept override {
      ++resets;
    }

    std::size_t submissions {};
    std::size_t resets {};
    std::vector<std::uint8_t> last_state;
  };

  class microphone_t final: public media::MicrophoneSink {
  public:
    bool submit(const media::MicrophonePacket &) override {
      return true;
    }

    void stop() noexcept override {
      ++stops;
    }

    std::size_t stops {};
  };

  class feedback_t final: public media::VideoFeedbackSink {
  public:
    void submit(const media::VideoFeedback &feedback) override {
      actions.push_back(feedback.action);
      deadline_misses.push_back(feedback.deadline_miss_microseconds);
    }

    std::vector<std::uint8_t> actions;
    std::vector<std::uint32_t> deadline_misses;
  };

  media::NegotiatedMediaConfig config() {
    media::NegotiatedMediaConfig value;
    value.session_id.fill(0xA5);
    return value;
  }

  std::vector<std::uint8_t> controller_state(
    const std::uint16_t state_format,
    const std::size_t controller_count,
    const std::size_t touch_count = 0
  ) {
    const auto controller_bytes = state_format == 3 ? std::size_t {56} : std::size_t {64};
    std::vector<std::uint8_t> state(
      lumen::protocol_common::input_state::header_bytes + controller_count * controller_bytes +
      touch_count * 32
    );
    write_be(state, 0, std::uint32_t {6});
    write_be(state, 80, controller_count == 16 ? std::uint32_t {0xffff} : (std::uint32_t {1} << controller_count) - 1);
    state[84] = static_cast<std::uint8_t>(controller_count);
    state[85] = static_cast<std::uint8_t>(touch_count);
    if (state_format == 3) {
      state[87] = 3;
    }
    for (std::size_t index = 0; index < controller_count; ++index) {
      const auto offset = lumen::protocol_common::input_state::header_bytes + index * controller_bytes;
      state[offset] = static_cast<std::uint8_t>(index);
      state[offset + 1] = static_cast<std::uint8_t>(1 + index % 5);
      write_be(state, offset + 2, static_cast<std::uint16_t>(1U << (index % 9)));
      write_be(state, offset + 4, std::uint64_t {1} << (index % 22));
      write_be(state, offset + 48, std::uint16_t {0xffff});
      write_be(state, offset + 52, std::uint32_t {1} << (index % 22));
    }
    const auto touch_base = lumen::protocol_common::input_state::header_bytes +
                            controller_count * controller_bytes;
    for (std::size_t index = 0; index < touch_count; ++index) {
      const auto offset = touch_base + index * 32;
      write_be(state, offset, static_cast<std::uint32_t>(index + 1));
      state[offset + 4] = 1;
    }
    return state;
  }

  std::vector<std::uint8_t> input_edges(const std::size_t count) {
    std::vector<std::uint8_t> edges(count * 32);
    for (std::size_t index = 0; index < count; ++index) {
      write_be(edges, index * 32, static_cast<std::uint64_t>(index + 1));
    }
    return edges;
  }

  std::vector<std::uint8_t> input_payload(
    const std::uint16_t state_format,
    const std::uint16_t edge_format = 2,
    std::vector<std::uint8_t> state = {},
    std::vector<std::uint8_t> edges = {}
  ) {
    if (state.empty()) {
      state.resize(lumen::protocol_common::input_state::header_bytes);
      write_be(state, 0, std::uint32_t {6});
      if (state_format == 3) {
        state[87] = 3;
      }
    }
    std::vector<std::uint8_t> payload;
    append_be(payload, std::uint64_t {100});
    append_be(payload, static_cast<std::uint64_t>(edges.size() / 32));
    append_be(payload, static_cast<std::uint16_t>(state.size()));
    append_be(payload, static_cast<std::uint16_t>(edges.size() / 32));
    append_be(payload, state_format);
    append_be(payload, edge_format);
    append_be(payload, std::uint64_t {0});
    payload.insert(payload.end(), state.begin(), state.end());
    payload.insert(payload.end(), edges.begin(), edges.end());
    return payload;
  }

  std::vector<std::uint8_t> video_feedback_payload(
    const std::uint8_t action,
    const std::uint32_t deadline_miss_microseconds
  ) {
    std::vector<std::uint8_t> payload;
    append_be(payload, std::uint64_t {100});
    append_be(payload, std::uint64_t {99});
    payload.push_back(action);
    payload.push_back(0);
    append_be(payload, std::uint16_t {0});
    append_be(payload, deadline_miss_microseconds);
    append_be(payload, std::uint64_t {0});
    return payload;
  }
}  // namespace

TEST(ProtocolV3InputFormat, AdvertisesCompactInputCapability) {
  EXPECT_EQ(lumen::protocol_v3::control_session::Config {}.capabilities, 0x37fU);
}

TEST(ProtocolV3InputFormat, AcceptsTwoAndThreeAndExplicitlyRejectsOne) {
  transport_t transport;
  input_t input;
  microphone_t microphone;
  feedback_t feedback;
  const auto negotiated = config();
  media::SessionPipeline pipeline(negotiated, transport, input, microphone, feedback);
  ASSERT_TRUE(pipeline.bind_connection(1));

  auto format_one = input_payload(1);
  EXPECT_EQ(
    pipeline.receive({1, 1, 0, negotiated.session_id, 1, 1, format_one}),
    media::ReceiveResult::malformed
  );
  EXPECT_EQ(input.submissions, 0U);

  auto format_two = input_payload(2);
  const auto expected_format_two_state = std::vector<std::uint8_t>(
    format_two.begin() + 32,
    format_two.end()
  );
  EXPECT_EQ(
    pipeline.receive({1, 1, 0, negotiated.session_id, 2, 1, format_two}),
    media::ReceiveResult::accepted
  );
  EXPECT_EQ(input.submissions, 1U);
  EXPECT_EQ(input.last_state, expected_format_two_state);

  auto format_three = input_payload(3);
  write_be(format_three, 32, std::uint32_t {2});
  EXPECT_EQ(
    pipeline.receive({1, 1, 0, negotiated.session_id, 3, 2, format_three}),
    media::ReceiveResult::accepted
  );
  EXPECT_EQ(input.submissions, 2U);
  ASSERT_GT(input.last_state.size(), 87U);
  EXPECT_EQ(input.last_state[87], 3U);
}

TEST(ProtocolV3InputFormat, RejectsStateMarkerAndEdgeFormatMismatch) {
  transport_t transport;
  input_t input;
  microphone_t microphone;
  feedback_t feedback;
  const auto negotiated = config();
  media::SessionPipeline pipeline(negotiated, transport, input, microphone, feedback);
  ASSERT_TRUE(pipeline.bind_connection(1));

  auto wrapper_three_marker_two = input_payload(3);
  wrapper_three_marker_two[32 + 87] = 0;
  EXPECT_EQ(
    pipeline.receive({1, 1, 0, negotiated.session_id, 1, 1, wrapper_three_marker_two}),
    media::ReceiveResult::malformed
  );

  auto wrapper_two_marker_three = input_payload(2);
  wrapper_two_marker_three[32 + 87] = 3;
  EXPECT_EQ(
    pipeline.receive({1, 1, 0, negotiated.session_id, 1, 1, wrapper_two_marker_three}),
    media::ReceiveResult::malformed
  );

  auto edge_format_three = input_payload(3, 3);
  EXPECT_EQ(
    pipeline.receive({1, 1, 0, negotiated.session_id, 1, 1, edge_format_three}),
    media::ReceiveResult::malformed
  );
  EXPECT_EQ(input.submissions, 0U);
}

TEST(ProtocolV3InputFormat, EnforcesExactFormatTwoAndThreePayloadBoundaries) {
  transport_t transport;
  input_t input;
  microphone_t microphone;
  feedback_t feedback;
  const auto negotiated = config();
  media::SessionPipeline pipeline(negotiated, transport, input, microphone, feedback);
  ASSERT_TRUE(pipeline.bind_connection(1));

  auto format_two_boundary = input_payload(2, 2, controller_state(2, 15));
  ASSERT_EQ(format_two_boundary.size(), 1'104U);
  EXPECT_EQ(
    pipeline.receive({1, 1, 0, negotiated.session_id, 1, 1, format_two_boundary}),
    media::ReceiveResult::accepted
  );
  EXPECT_EQ(input.submissions, 1U);
  EXPECT_EQ(input.last_state.size(), 1'072U);

  auto format_two_with_edge = input_payload(2, 2, controller_state(2, 15), input_edges(1));
  ASSERT_EQ(format_two_with_edge.size(), 1'136U);
  EXPECT_EQ(
    pipeline.receive({1, 1, 0, negotiated.session_id, 2, 2, format_two_with_edge}),
    media::ReceiveResult::malformed
  );

  auto format_three_with_two_edges = input_payload(3, 2, controller_state(3, 16), input_edges(2));
  write_be(format_three_with_two_edges, 32, std::uint32_t {2});
  ASSERT_EQ(format_three_with_two_edges.size(), 1'104U);
  EXPECT_EQ(
    pipeline.receive({1, 1, 0, negotiated.session_id, 2, 2, format_three_with_two_edges}),
    media::ReceiveResult::accepted
  );
  EXPECT_EQ(input.submissions, 2U);
  EXPECT_EQ(input.last_state.size(), 1'008U);

  auto oversized = input_payload(3, 2, controller_state(3, 16));
  oversized.resize(1'109U);
  EXPECT_EQ(
    pipeline.receive({1, 1, 0, negotiated.session_id, 3, 3, oversized}),
    media::ReceiveResult::malformed
  );
  EXPECT_EQ(input.submissions, 2U);
}

TEST(ProtocolV3HdrSelection, RequiresStaticMetadataForPqAndForbidsItForHlg) {
  transport_t transport;
  input_t input;
  microphone_t microphone;
  feedback_t feedback;

  auto pq = config();
  pq.codec_id = 2;
  pq.transfer = 2;
  pq.bit_depth = 10;
  pq.primaries = 9;
  pq.matrix_code = 9;
  EXPECT_THROW(
    media::SessionPipeline(pq, transport, input, microphone, feedback),
    std::invalid_argument
  );
  pq.static_hdr_metadata = media::StaticHDRMetadata {};
  EXPECT_NO_THROW(media::SessionPipeline(pq, transport, input, microphone, feedback));

  auto hlg = config();
  hlg.codec_id = 2;
  hlg.transfer = 3;
  hlg.bit_depth = 10;
  hlg.primaries = 9;
  hlg.matrix_code = 9;
  EXPECT_NO_THROW(media::SessionPipeline(hlg, transport, input, microphone, feedback));
  hlg.static_hdr_metadata = media::StaticHDRMetadata {};
  EXPECT_THROW(
    media::SessionPipeline(hlg, transport, input, microphone, feedback),
    std::invalid_argument
  );
}

TEST(ProtocolV3ControllerFeedback, SerializesEveryProductionCommandAndRejectsInvalidFields) {
  transport_t transport;
  input_t input;
  microphone_t microphone;
  feedback_t video_feedback;
  const auto negotiated = config();
  media::SessionPipeline pipeline(negotiated, transport, input, microphone, video_feedback);
  ASSERT_TRUE(pipeline.bind_connection(1));

  media::ControllerFeedback feedback {
    .input_generation = 7,
    .controller_generation = 3,
    .controller_id = 2,
    .command = 1,
    .low_frequency = 0x1234,
    .high_frequency = 0xabcd,
  };
  ASSERT_EQ(pipeline.submit_controller_feedback(feedback), media::PublishResult::accepted);
  ASSERT_EQ(transport.packets.size(), 1U);
  const auto &rumble = transport.packets.back();
  ASSERT_EQ(rumble.size(), quic::datagram_header_bytes + 40U);
  EXPECT_EQ(rumble[5], 1);
  EXPECT_EQ(rumble[6], 4);
  EXPECT_EQ(rumble[8], 0);
  EXPECT_EQ(rumble[9], quic::datagram_header_bytes);
  EXPECT_EQ(rumble[36], 0);
  EXPECT_EQ(rumble[43], 7);
  EXPECT_EQ(rumble[44], 0);
  EXPECT_EQ(rumble[47], 7);
  EXPECT_EQ(rumble[48], 0);
  EXPECT_EQ(rumble[51], 3);
  EXPECT_EQ(rumble[52], 2);
  EXPECT_EQ(rumble[53], 1);
  EXPECT_EQ(rumble[54], 0);
  EXPECT_EQ(rumble[55], 4);
  EXPECT_EQ(rumble[56], 0x12);
  EXPECT_EQ(rumble[57], 0x34);
  EXPECT_EQ(rumble[58], 0xab);
  EXPECT_EQ(rumble[59], 0xcd);
  EXPECT_TRUE(std::ranges::all_of(rumble.begin() + 60, rumble.end(), [](const auto byte) {
    return byte == 0;
  }));

  feedback.command = 3;
  feedback.motion_type = 2;
  feedback.report_rate_hz = 100;
  ASSERT_EQ(pipeline.submit_controller_feedback(feedback), media::PublishResult::accepted);
  EXPECT_EQ(transport.packets.back()[56], 2);
  EXPECT_EQ(transport.packets.back()[58], 0);
  EXPECT_EQ(transport.packets.back()[59], 100);

  feedback.command = 5;
  feedback.adaptive_flags = 0x0c;
  feedback.adaptive_left_type = 1;
  feedback.adaptive_right_type = 2;
  feedback.adaptive_left.fill(0x11);
  feedback.adaptive_right.fill(0x22);
  ASSERT_EQ(pipeline.submit_controller_feedback(feedback), media::PublishResult::accepted);
  EXPECT_EQ(transport.packets.back()[54], 0);
  EXPECT_EQ(transport.packets.back()[55], 24);
  EXPECT_TRUE(std::ranges::all_of(transport.packets.back().begin() + 60, transport.packets.back().begin() + 70, [](const auto byte) {
    return byte == 0x11;
  }));
  EXPECT_TRUE(std::ranges::all_of(transport.packets.back().begin() + 70, transport.packets.back().begin() + 80, [](const auto byte) {
    return byte == 0x22;
  }));

  feedback.controller_generation = 0;
  EXPECT_EQ(pipeline.submit_controller_feedback(feedback), media::PublishResult::invalid);
  feedback.controller_generation = 3;
  feedback.adaptive_flags = 0x01;
  EXPECT_EQ(pipeline.submit_controller_feedback(feedback), media::PublishResult::invalid);
  feedback.command = 3;
  feedback.motion_type = 3;
  EXPECT_EQ(pipeline.submit_controller_feedback(feedback), media::PublishResult::invalid);
}

TEST(ProtocolV3VideoFeedback, DeadlineMissFeedsBoundedProductionTelemetry) {
  transport_t transport;
  input_t input;
  microphone_t microphone;
  feedback_t feedback;
  const auto negotiated = config();
  media::SessionPipeline pipeline(negotiated, transport, input, microphone, feedback);
  ASSERT_TRUE(pipeline.bind_connection(1));

  auto missed = video_feedback_payload(1, 500);
  EXPECT_EQ(
    pipeline.receive({2, 3, 0, negotiated.session_id, 1, 100, missed}),
    media::ReceiveResult::accepted
  );
  auto on_time = video_feedback_payload(1, 0);
  EXPECT_EQ(
    pipeline.receive({2, 3, 0, negotiated.session_id, 2, 101, on_time}),
    media::ReceiveResult::accepted
  );
  auto decode_failure = video_feedback_payload(3, 700);
  EXPECT_EQ(
    pipeline.receive({2, 3, 0, negotiated.session_id, 3, 102, decode_failure}),
    media::ReceiveResult::accepted
  );

  const auto telemetry = pipeline.snapshot();
  EXPECT_EQ(telemetry.feedback_packets, 3U);
  EXPECT_EQ(telemetry.deadline_samples, 3U);
  EXPECT_EQ(telemetry.deadline_misses, 2U);
  EXPECT_EQ(telemetry.consecutive_deadline_misses, 1U);
  EXPECT_EQ(telemetry.latest_deadline_miss_microseconds, 700U);
  EXPECT_EQ(telemetry.peak_deadline_miss_microseconds, 700U);
  EXPECT_EQ(feedback.actions, (std::vector<std::uint8_t> {1, 1, 3}));
  EXPECT_EQ(feedback.deadline_misses, (std::vector<std::uint32_t> {500, 0, 700}));

  auto impossible_action = video_feedback_payload(4, 1);
  EXPECT_EQ(
    pipeline.receive({2, 3, 0, negotiated.session_id, 4, 103, impossible_action}),
    media::ReceiveResult::malformed
  );
  auto unbounded = video_feedback_payload(1, media::maximum_deadline_miss_microseconds + 1);
  EXPECT_EQ(
    pipeline.receive({2, 3, 0, negotiated.session_id, 4, 103, unbounded}),
    media::ReceiveResult::malformed
  );
  const auto after_rejection = pipeline.snapshot();
  EXPECT_EQ(after_rejection.feedback_packets, telemetry.feedback_packets);
  EXPECT_EQ(after_rejection.deadline_samples, telemetry.deadline_samples);
  EXPECT_EQ(after_rejection.deadline_misses, telemetry.deadline_misses);
  EXPECT_EQ(
    after_rejection.latest_deadline_miss_microseconds,
    telemetry.latest_deadline_miss_microseconds
  );
}

TEST(ProtocolV3AudioPublication, PreservesGenerationAndReportsBackpressureAndClosedState) {
  transport_t transport;
  input_t input;
  microphone_t microphone;
  feedback_t feedback;
  auto negotiated = config();
  negotiated.audio_generation = 0x12345678U;
  transport.maximum_packets = 1;
  media::SessionPipeline pipeline(negotiated, transport, input, microphone, feedback);
  ASSERT_TRUE(pipeline.bind_connection(7));

  const std::array<std::uint8_t, 4> opus {0x11, 0x22, 0x33, 0x44};
  const media::EncodedAudioPacket packet {
    .capture_time_microseconds = 90,
    .first_sample_position = 240,
    .opus = opus,
    .discontinuity = true,
  };
  ASSERT_EQ(pipeline.submit_audio(packet), media::PublishResult::accepted);
  ASSERT_EQ(transport.packets.size(), 1U);
  const auto &wire = transport.packets.back();
  const auto payload_offset = quic::datagram_header_bytes;
  ASSERT_EQ(wire.size(), payload_offset + 48U + opus.size());
  EXPECT_EQ(read_be32(wire, payload_offset + 16U), negotiated.audio_generation);
  EXPECT_EQ(wire[payload_offset + 25U], 0x02U);
  EXPECT_TRUE(std::ranges::equal(opus.begin(), opus.end(), wire.end() - opus.size(), wire.end()));

  EXPECT_EQ(pipeline.submit_audio(packet), media::PublishResult::backpressured);
  transport.stop();
  EXPECT_EQ(pipeline.submit_audio(packet), media::PublishResult::stopped);
  const auto before_stop = pipeline.snapshot();
  EXPECT_EQ(before_stop.audio_packets, 1U);
  EXPECT_EQ(before_stop.backpressure_drops, 2U);

  pipeline.stop();
  pipeline.stop();
  EXPECT_EQ(input.resets, 1U);
  EXPECT_EQ(microphone.stops, 1U);
  EXPECT_EQ(pipeline.submit_audio(packet), media::PublishResult::stopped);
}

TEST(ProtocolV3GenerationInstrumentation, KeepsRawAudioAndVideoEventsScopedPerSession) {
  struct evidence_t {
    transport_t::packet_event_t audio_event;
    transport_t::video_event_t video_event;
    std::vector<std::uint8_t> video_header;
    std::vector<std::uint8_t> video_payload;
    media::TelemetrySnapshot telemetry;
  };

  const auto publish = [](const std::uint8_t session_tag, const std::uint32_t audio_generation, const std::uint32_t video_generation) {
    transport_t transport;
    input_t input;
    microphone_t microphone;
    feedback_t feedback;
    auto negotiated = config();
    negotiated.session_id.fill(session_tag);
    negotiated.audio_generation = audio_generation;
    negotiated.video_generation = video_generation;
    media::SessionPipeline pipeline(negotiated, transport, input, microphone, feedback);
    EXPECT_TRUE(pipeline.bind_connection(session_tag));

    const std::array<std::uint8_t, 3> opus {session_tag, 0x22, 0x33};
    EXPECT_EQ(
      pipeline.submit_audio({
        .capture_time_microseconds = 10,
        .first_sample_position = 20,
        .opus = opus,
      }),
      media::PublishResult::accepted
    );

    auto storage = std::make_shared<const std::vector<std::uint8_t>>(
      std::initializer_list<std::uint8_t> {session_tag, 0x55, 0x66, 0x77}
    );
    EXPECT_EQ(
      pipeline.submit_video({
        .frame_id = session_tag,
        .capture_time_microseconds = 30,
        .encoder_complete_delta_microseconds = 5,
        .storage = storage,
        .bytes = *storage,
        .request_recovery = [] {
        },
        .key_frame = true,
      }),
      media::PublishResult::accepted
    );

    EXPECT_EQ(transport.packets.size(), 1U);
    EXPECT_EQ(transport.packet_events.size(), 1U);
    EXPECT_EQ(transport.video_frames.size(), 1U);
    EXPECT_EQ(transport.video_events.size(), 1U);
    if (transport.packets.size() != 1U || transport.packet_events.size() != 1U ||
        transport.video_frames.size() != 1U || transport.video_events.size() != 1U) {
      return evidence_t {};
    }
    std::array<std::uint8_t, quic::maximum_semantic_datagram_bytes> header {};
    quic::VideoFragmentView fragment;
    const auto materialized = transport.video_frames.front()->materialize(0, header, fragment);
    EXPECT_TRUE(materialized);
    if (!materialized) {
      return evidence_t {};
    }
    return evidence_t {
      .audio_event = transport.packet_events.front(),
      .video_event = transport.video_events.front(),
      .video_header = {header.begin(), header.begin() + static_cast<std::ptrdiff_t>(fragment.header_size)},
      .video_payload = {fragment.payload, fragment.payload + fragment.payload_size},
      .telemetry = pipeline.snapshot(),
    };
  };

  const auto first = publish(0x31, 101, 201);
  const auto second = publish(0x32, 102, 202);
  ASSERT_GE(first.audio_event.bytes.size(), quic::datagram_header_bytes + 20U);
  ASSERT_GE(second.audio_event.bytes.size(), quic::datagram_header_bytes + 20U);
  ASSERT_GE(first.video_header.size(), quic::datagram_header_bytes + 60U);
  ASSERT_GE(second.video_header.size(), quic::datagram_header_bytes + 60U);
  EXPECT_EQ(first.audio_event.connection_id, 0x31U);
  EXPECT_EQ(second.audio_event.connection_id, 0x32U);
  EXPECT_EQ(first.audio_event.lane, quic::Lane::audio);
  EXPECT_EQ(second.audio_event.lane, quic::Lane::audio);
  EXPECT_GT(first.audio_event.deadline, quic::MonotonicClock::time_point {});
  EXPECT_GT(second.audio_event.deadline, quic::MonotonicClock::time_point {});
  EXPECT_FALSE(first.audio_event.replaceable);
  EXPECT_FALSE(second.audio_event.replaceable);
  EXPECT_EQ(first.video_event.connection_id, 0x31U);
  EXPECT_EQ(second.video_event.connection_id, 0x32U);
  EXPECT_EQ(first.video_event.frame->object_id(), 0x31U);
  EXPECT_EQ(second.video_event.frame->object_id(), 0x32U);
  EXPECT_TRUE(std::ranges::all_of(first.audio_event.bytes.begin() + 12, first.audio_event.bytes.begin() + 28, [](const auto byte) {
    return byte == 0x31;
  }));
  EXPECT_TRUE(std::ranges::all_of(second.audio_event.bytes.begin() + 12, second.audio_event.bytes.begin() + 28, [](const auto byte) {
    return byte == 0x32;
  }));
  EXPECT_TRUE(std::ranges::all_of(first.video_header.begin() + 12, first.video_header.begin() + 28, [](const auto byte) {
    return byte == 0x31;
  }));
  EXPECT_TRUE(std::ranges::all_of(second.video_header.begin() + 12, second.video_header.begin() + 28, [](const auto byte) {
    return byte == 0x32;
  }));
  EXPECT_EQ(read_be32(first.audio_event.bytes, quic::datagram_header_bytes + 16U), 101U);
  EXPECT_EQ(read_be32(second.audio_event.bytes, quic::datagram_header_bytes + 16U), 102U);
  EXPECT_EQ(read_be32(first.video_header, quic::datagram_header_bytes + 56U), 201U);
  EXPECT_EQ(read_be32(second.video_header, quic::datagram_header_bytes + 56U), 202U);
  EXPECT_EQ(first.video_payload, (std::vector<std::uint8_t> {0x31, 0x55, 0x66, 0x77}));
  EXPECT_EQ(second.video_payload, (std::vector<std::uint8_t> {0x32, 0x55, 0x66, 0x77}));
  EXPECT_NE(first.audio_event.bytes, second.audio_event.bytes);
  EXPECT_NE(first.video_header, second.video_header);
  EXPECT_EQ(first.telemetry.audio_packets, 1U);
  EXPECT_EQ(first.telemetry.video_frames, 1U);
  EXPECT_EQ(second.telemetry.audio_packets, 1U);
  EXPECT_EQ(second.telemetry.video_frames, 1U);
}
