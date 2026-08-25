/**
 * @file tests/unit/test_protocol_v3_input_format.cpp
 * @brief Protocol-v3 input format-version admission tests.
 */

#include "src/protocol_v3/media_pipeline.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
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

  class transport_t final: public media::TransportSink {
  public:
    bool update_policy(std::uint64_t, quic::Profile, std::uint64_t) noexcept override { return true; }
    quic::EnqueueResult enqueue(std::uint64_t, quic::Packet packet) override {
      packets.emplace_back(*packet.bytes);
      return quic::EnqueueResult::queued;
    }
    quic::EnqueueResult enqueue_video_frame(
      std::uint64_t,
      std::shared_ptr<const quic::LazyVideoFrame>
    ) override {
      return quic::EnqueueResult::queued;
    }
    std::vector<std::vector<std::uint8_t>> packets;
  };

  class input_t final: public media::InputSink {
  public:
    bool submit(const media::InputBatch &) override {
      ++submissions;
      return true;
    }
    void reset() noexcept override {}
    std::size_t submissions {};
  };

  class microphone_t final: public media::MicrophoneSink {
  public:
    bool submit(const media::MicrophonePacket &) override { return true; }
    void stop() noexcept override {}
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

  std::vector<std::uint8_t> input_payload(const std::uint16_t format) {
    std::vector<std::uint8_t> payload;
    append_be(payload, std::uint64_t {100});
    append_be(payload, std::uint64_t {0});
    append_be(payload, std::uint16_t {112});
    append_be(payload, std::uint16_t {0});
    append_be(payload, format);
    append_be(payload, format);
    append_be(payload, std::uint64_t {0});
    append_be(payload, std::uint32_t {6});
    payload.resize(32 + 112);
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
}

TEST(ProtocolV3InputFormat, AcceptsTwoAndExplicitlyRejectsOne) {
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
  EXPECT_EQ(
    pipeline.receive({1, 1, 0, negotiated.session_id, 2, 1, format_two}),
    media::ReceiveResult::accepted
  );
  EXPECT_EQ(input.submissions, 1U);
}

TEST(ProtocolV3HdrSelection, RequiresStaticMetadataForPqAndForbidsItForHlg) {
  transport_t transport;
  input_t input;
  microphone_t microphone;
  feedback_t feedback;

  auto pq = config();
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
  EXPECT_TRUE(std::ranges::all_of(
    transport.packets.back().begin() + 60,
    transport.packets.back().begin() + 70,
    [](const auto byte) { return byte == 0x11; }
  ));
  EXPECT_TRUE(std::ranges::all_of(
    transport.packets.back().begin() + 70,
    transport.packets.back().begin() + 80,
    [](const auto byte) { return byte == 0x22; }
  ));

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
