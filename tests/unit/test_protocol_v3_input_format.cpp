/**
 * @file tests/unit/test_protocol_v3_input_format.cpp
 * @brief Protocol-v3 input format-version admission tests.
 */

#include "src/protocol_v3/media_pipeline.h"

#include <gtest/gtest.h>

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
    quic::EnqueueResult enqueue(std::uint64_t, quic::Packet) override { return quic::EnqueueResult::queued; }
    quic::EnqueueResult enqueue_video_frame(
      std::uint64_t,
      std::shared_ptr<const quic::LazyVideoFrame>
    ) override {
      return quic::EnqueueResult::queued;
    }
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
    void submit(const media::VideoFeedback &) override {}
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
