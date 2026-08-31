/**
 * @file tests/unit/test_lsp_video_control.cpp
 * @brief Exact deterministic-CBOR checks for the first LSP SDR video product slice.
 */

#include "src/protocol_common/cbor.h"
#include "src/protocol_lsp/runtime/control/wire.h"

#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <variant>
#include <vector>

namespace {
  namespace cbor = lumen::protocol_common::cbor;
  namespace lsp = lumen::lsp::runtime;

  /** @brief Construct a nonzero fixed protocol identifier. */
  template<std::size_t Size>
  std::array<std::uint8_t, Size> filled(const std::uint8_t value) {
    std::array<std::uint8_t, Size> output {};
    output.fill(value);
    return output;
  }

  /** @brief Return one exact selected H.264 SDR video tuple. */
  lsp::VideoSelectionPayload video_selection() {
    return {
      .video_generation = 3,
      .primary_ssrc = 4,
      .primary_payload_type = 97,
      .clock_rate = 90'000,
      .codec = lsp::VideoCodec::h264,
      .profile = lsp::VideoProfile::h264_high,
      .width = 1'920,
      .height = 1'080,
      .refresh_numerator = 240,
      .refresh_denominator = 1,
      .selected_bits_per_second = 100'000'000,
      .pixel_format = lsp::video_pixel_format_nv12,
      .color_primaries = lsp::video_color_rec709,
      .transfer_function = lsp::video_color_rec709,
      .matrix_coefficients = lsp::video_color_rec709,
      .full_range = false,
      .initial_udp_payload_size = 1'200,
      .decoder_surfaces = 3,
      .render_mailbox = 1,
      .delivery = lsp::video_delivery_complete_access_unit,
      .frame_marking_extension = 1,
      .absolute_capture_time_extension = 2,
      .frame_id_extension = 3,
      .input_watermark_extension = 4,
      .encoder_timing_extension = 5,
      .flexfec = false,
      .rtx = false,
      .maximum_frame_age_microseconds = 20'000,
    };
  }

  /** @brief Return one valid input/audio/microphone/video START response. */
  lsp::StartResponsePayload start_response() {
    lsp::AudioSelectionPayload audio {
      .audio_generation = 1,
      .audio_ssrc = 3,
      .audio_payload_type = 111,
      .clock_rate = 48'000,
      .channels = 2,
      .streams = 1,
      .coupled_streams = 1,
      .frame_samples = 240,
      .bitrate = 128'000,
      .inband_fec = false,
      .dtx = true,
      .initial_udp_payload_size = 1'200,
      .initial_preroll_packets = 1,
    };
    audio.mapping[0] = 0;
    audio.mapping[1] = 1;
    return {
      .session_id = filled<16>(1),
      .attach_token = filled<32>(2),
      .stream_generation = 1,
      .input_generation = 1,
      .input_ssrc = 1,
      .acknowledgement_ssrc = 2,
      .input_payload_type = 96,
      .pointer_rate = 1'000,
      .controller_rate = 250,
      .sensor_rate = 250,
      .reconciliation_rate = 100,
      .reserved_input_wire_bits_per_second = 12'000'000,
      .baseline_required = true,
      .audio = audio,
      .microphone = std::nullopt,
      .video = video_selection(),
    };
  }
}  // namespace

TEST(LspVideoControlWire, DecodesExactSixteenKeyStartAndRejectsRepairInFirstSlice) {
  const cbor::Value audio_offer {cbor::Value::Map {
    {1, 2U},
    {2, 240U},
    {3, 128'000U},
    {4, cbor::Value {false}},
    {5, cbor::Value {true}},
  }};
  auto video_offer = cbor::Value::Map {
    {1, 1U},
    {2, 1U},
    {3, 1'920U},
    {4, 1'080U},
    {5, 240U},
    {6, 1U},
    {7, 100'000'000U},
    {8, 120'000'000U},
    {9, 1U},
    {10, 1U},
    {11, cbor::Value {false}},
    {12, cbor::Value {false}},
  };
  const auto encode_start = [&](const cbor::Value::Map &offer) {
    return cbor::encode(cbor::Value {cbor::Value::Map {
                          {1, 1U},
                          {2, "1"},
                          {3, 1'000U},
                          {4, 250U},
                          {5, 250U},
                          {6, 100U},
                          {7, 32'000'000U},
                          {8, cbor::Value::Array {audio_offer}},
                          {9, 1'472U},
                          {10, cbor::Value {cbor::Null {}}},
                          {11, 0U},
                          {12, cbor::Value::Array {cbor::Value {offer}}},
                          {13, 64U},
                          {14, 3U},
                          {15, 1U},
                          {16, 20'000U},
                        }})
      .bytes;
  };

  const auto decoded = lsp::decode_start(encode_start(video_offer));
  ASSERT_TRUE(decoded);
  ASSERT_EQ(decoded->video_offers.size(), std::size_t {1});
  EXPECT_EQ(decoded->network_profile, lsp::VideoNetworkProfile::adaptive_low_latency);
  EXPECT_EQ(decoded->video_offers[0].codec, lsp::VideoCodec::h264);
  EXPECT_EQ(decoded->decoder_surfaces, 3U);
  EXPECT_EQ(decoded->maximum_capture_to_present_microseconds, 20'000U);

  video_offer[10].second = cbor::Value {true};
  EXPECT_FALSE(lsp::decode_start(encode_start(video_offer)));
}

TEST(LspVideoControlWire, EncodesExactTopLevelAndTwentyEightKeyVideoSelections) {
  const auto response = lsp::encode_start_response(start_response());
  ASSERT_TRUE(response);
  const auto decoded = cbor::decode(*response);
  ASSERT_TRUE(decoded);
  const auto *top = std::get_if<cbor::Value::Map>(&decoded.value->storage);
  ASSERT_NE(top, nullptr);
  ASSERT_EQ(top->size(), std::size_t {31});
  const auto *video = std::get_if<cbor::Value::Map>(&(*top)[30].second.storage);
  ASSERT_NE(video, nullptr);
  EXPECT_EQ(video->size(), std::size_t {28});
  EXPECT_EQ((*video)[27].first, 28U);
  EXPECT_EQ(*std::get_if<std::uint64_t>(&(*video)[27].second.storage), 20'000U);

  auto invalid = start_response();
  invalid.video.maximum_frame_age_microseconds = 0;
  EXPECT_FALSE(lsp::encode_start_response(invalid));

  auto attached = lsp::AttachResponsePayload {
    .session_id = start_response().session_id,
    .attach_token = filled<32>(3),
    .connection_generation = 2,
    .stream_generation = 1,
    .input_generation = 2,
    .input_ssrc = 5,
    .acknowledgement_ssrc = 6,
    .input_payload_type = 96,
    .pointer_rate = 1'000,
    .controller_rate = 250,
    .sensor_rate = 250,
    .reconciliation_rate = 100,
    .reserved_input_wire_bits_per_second = 12'000'000,
    .baseline_required = true,
    .audio = start_response().audio,
    .microphone = std::nullopt,
    .video = video_selection(),
  };
  attached.audio.audio_ssrc = 7;
  attached.video.primary_ssrc = 8;
  const auto attach_bytes = lsp::encode_attach_response(attached);
  ASSERT_TRUE(attach_bytes);
  const auto attach_value = cbor::decode(*attach_bytes);
  ASSERT_TRUE(attach_value);
  EXPECT_EQ(std::get<cbor::Value::Map>(attach_value.value->storage).size(), std::size_t {32});
}

TEST(LspVideoControlWire, FreezesVideoConfigParameterSetsAndFiveKeyAcknowledgement) {
  const lsp::VideoConfigPayload configuration {
    .session_id = filled<16>(1),
    .stream_generation = 1,
    .video = video_selection(),
    .parameter_sets = {{0x67, 0x64, 0x00, 0x1f}, {0x68, 0xee, 0x3c, 0x80}},
    .frame_id_origin = 10,
    .recovery_epoch = 1,
    .maximum_complete_access_unit_bytes = 16U * 1024U * 1024U,
  };
  const auto encoded = lsp::encode_video_config(configuration);
  ASSERT_TRUE(encoded);
  EXPECT_LE(encoded->size(), std::size_t {1'152});
  const auto decoded = cbor::decode(*encoded);
  ASSERT_TRUE(decoded);
  const auto &map = std::get<cbor::Value::Map>(decoded.value->storage);
  ASSERT_EQ(map.size(), std::size_t {8});
  EXPECT_EQ(std::get<cbor::Value::Map>(map[3].second.storage).size(), std::size_t {28});
  EXPECT_EQ(std::get<cbor::Value::Array>(map[4].second.storage).size(), std::size_t {2});

  const auto ack_bytes = cbor::encode(cbor::Value {cbor::Value::Map {
                                        {1, 1U},
                                        {2, 0U},
                                        {3, cbor::Value::Bytes(configuration.session_id.begin(), configuration.session_id.end())},
                                        {4, configuration.video.video_generation},
                                        {5, 3U},
                                      }})
                           .bytes;
  const auto ack = lsp::decode_video_config_ack(ack_bytes);
  ASSERT_TRUE(ack);
  EXPECT_EQ(ack->decoder_credit, 3U);
  EXPECT_EQ(ack->video_generation, configuration.video.video_generation);
}
