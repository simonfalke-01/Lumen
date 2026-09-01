/**
 * @file tests/unit/test_lsp_video_control.cpp
 * @brief Exact deterministic-CBOR and sender-boundary checks for LSP video schema revision three.
 */

#include "src/protocol_common/cbor.h"
#include "src/protocol_lsp/core/wire.h"
#include "src/protocol_lsp/runtime/control/wire.h"
#include "src/protocol_lsp/runtime/video_sender.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <variant>
#include <vector>

namespace {
  namespace cbor = lumen::protocol_common::cbor;
  namespace lsp = lumen::lsp::runtime;
  namespace lsp_transport = lumen::lsp::transport;

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
      .color_primaries = lsp::video_color_bt709,
      .transfer_function = lsp::video_color_bt709,
      .matrix_coefficients = lsp::video_color_bt709,
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
      .flexfec = lsp::FlexFecSelectionPayload {
        .repair_ssrc = 5,
        .repair_payload_type = 98,
        .window_microseconds = 20'000,
        .maximum_group_packets = 15,
      },
      .rtx = lsp::RtxSelectionPayload {
        .rtx_ssrc = 6,
        .rtx_payload_type = 99,
        .associated_payload_type = 97,
      },
      .maximum_frame_age_microseconds = 20'000,
      .maximum_complete_access_unit_bytes = 16U * 1024U * 1024U,
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

TEST(LspVideoControlWire, DecodesExactSixteenKeyStartWithEighteenKeyVideoOffers) {
  const cbor::Value audio_offer {cbor::Value::Map {
    {1, 2U},
    {2, 240U},
    {3, 128'000U},
    {4, cbor::Value {false}},
    {5, cbor::Value {true}},
  }};
  auto video_offer = cbor::Value::Map {
    {1, 3U},
    {2, 1U},
    {3, 1U},
    {4, 1'920U},
    {5, 1'080U},
    {6, 240U},
    {7, 1U},
    {8, 100'000'000U},
    {9, 120'000'000U},
    {10, 1U},
    {11, 1U},
    {12, 1U},
    {13, 1U},
    {14, cbor::Value {false}},
    {15, 1U},
    {16, cbor::Value {true}},
    {17, cbor::Value {true}},
    {18, 16U * 1'024U * 1'024U},
  };
  const auto encode_start = [&](const cbor::Value::Map &offer, const std::uint32_t capture_to_present) {
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
                          {16, capture_to_present},
                        }})
      .bytes;
  };

  const auto decoded = lsp::decode_start(encode_start(video_offer, 20'000));
  ASSERT_TRUE(decoded);
  ASSERT_EQ(decoded->video_offers.size(), std::size_t {1});
  EXPECT_EQ(decoded->network_profile, lsp::VideoNetworkProfile::adaptive_low_latency);
  EXPECT_EQ(decoded->video_offers[0].codec, lsp::VideoCodec::h264);
  EXPECT_TRUE(decoded->video_offers[0].flexfec);
  EXPECT_TRUE(decoded->video_offers[0].rtx);
  EXPECT_EQ(decoded->decoder_surfaces, 3U);
  EXPECT_EQ(decoded->maximum_capture_to_present_microseconds, 20'000U);
  EXPECT_TRUE(lsp::decode_start(encode_start(video_offer, lsp::video_maximum_frame_age_microseconds)));

  video_offer[0].second = cbor::Value {2U};
  EXPECT_FALSE(lsp::decode_start(encode_start(video_offer, 20'000)));
  video_offer[0].second = cbor::Value {3U};
  video_offer[2].second = cbor::Value {3U};
  EXPECT_FALSE(lsp::decode_start(encode_start(video_offer, 20'000)));
  video_offer[2].second = cbor::Value {1U};
  video_offer[7].second = cbor::Value {999U};
  EXPECT_FALSE(lsp::decode_start(encode_start(video_offer, 20'000)));
  video_offer[7].second = cbor::Value {100'000'000U};
  EXPECT_FALSE(lsp::decode_start(encode_start(video_offer, 1'000'001)));
}

TEST(LspVideoControlWire, EncodesExactTopLevelAndThirtyKeyVideoSelections) {
  const auto response = lsp::encode_start_response(start_response());
  ASSERT_TRUE(response);
  const auto decoded = cbor::decode(*response);
  ASSERT_TRUE(decoded);
  const auto *top = std::get_if<cbor::Value::Map>(&decoded.value->storage);
  ASSERT_NE(top, nullptr);
  ASSERT_EQ(top->size(), std::size_t {31});
  const auto *video = std::get_if<cbor::Value::Map>(&(*top)[30].second.storage);
  ASSERT_NE(video, nullptr);
  EXPECT_EQ(video->size(), std::size_t {30});
  EXPECT_EQ(std::get<std::uint64_t>((*video)[0].second.storage), 3U);
  EXPECT_EQ(std::get<cbor::Value::Map>((*video)[26].second.storage).size(), 4U);
  EXPECT_EQ(std::get<cbor::Value::Map>((*video)[27].second.storage).size(), 3U);
  EXPECT_EQ(std::get<std::uint64_t>((*video)[28].second.storage), 20'000U);
  EXPECT_EQ(std::get<std::uint64_t>((*video)[29].second.storage), 16U * 1'024U * 1'024U);

  auto invalid = start_response();
  invalid.video.maximum_frame_age_microseconds = 0;
  EXPECT_FALSE(lsp::encode_start_response(invalid));
  invalid = start_response();
  invalid.video.flexfec->maximum_group_packets = 14;
  EXPECT_FALSE(lsp::encode_start_response(invalid));
  invalid = start_response();
  invalid.video.rtx->associated_payload_type = 100;
  EXPECT_FALSE(lsp::encode_start_response(invalid));
  invalid = start_response();
  invalid.video.selected_bits_per_second = 999;
  EXPECT_FALSE(lsp::encode_start_response(invalid));
  invalid = start_response();
  invalid.video.maximum_frame_age_microseconds = lsp::video_maximum_frame_age_microseconds + 1U;
  EXPECT_FALSE(lsp::encode_start_response(invalid));
  invalid = start_response();
  invalid.video.flexfec->window_microseconds = lsp::video_maximum_frame_age_microseconds + 1U;
  invalid.video.maximum_frame_age_microseconds = lsp::video_maximum_frame_age_microseconds;
  EXPECT_FALSE(lsp::encode_start_response(invalid));
  auto maximum_age = start_response();
  maximum_age.video.maximum_frame_age_microseconds = lsp::video_maximum_frame_age_microseconds;
  maximum_age.video.flexfec->window_microseconds = lsp::video_maximum_frame_age_microseconds;
  EXPECT_TRUE(lsp::encode_start_response(maximum_age));

  auto without_repair = start_response();
  without_repair.video.flexfec.reset();
  without_repair.video.rtx.reset();
  const auto without_repair_bytes = lsp::encode_start_response(without_repair);
  ASSERT_TRUE(without_repair_bytes);
  const auto without_repair_value = cbor::decode(*without_repair_bytes);
  ASSERT_TRUE(without_repair_value);
  const auto &without_repair_top = std::get<cbor::Value::Map>(without_repair_value.value->storage);
  const auto &without_repair_video = std::get<cbor::Value::Map>(without_repair_top[30].second.storage);
  EXPECT_TRUE(std::holds_alternative<cbor::Null>(without_repair_video[26].second.storage));
  EXPECT_TRUE(std::holds_alternative<cbor::Null>(without_repair_video[27].second.storage));

  auto attached = lsp::AttachResponsePayload {
    .session_id = start_response().session_id,
    .attach_token = filled<32>(3),
    .connection_generation = 2,
    .stream_generation = 1,
    .input_generation = 2,
    .input_ssrc = 9,
    .acknowledgement_ssrc = 10,
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

TEST(LspVideoControlWire, DecodesExactFiveKeyAttachWithClientSelectedSuccessor) {
  const auto session_id = filled<16>(1);
  const auto attach_token = filled<32>(2);
  const auto intent_id = filled<16>(3);
  const auto successor = filled<32>(4);
  const auto encode_attach = [&](const std::array<std::uint8_t, 32> &candidate) {
    return cbor::encode(cbor::Value {cbor::Value::Map {
                          {1, 1U},
                          {2, cbor::Value::Bytes(session_id.begin(), session_id.end())},
                          {3, cbor::Value::Bytes(attach_token.begin(), attach_token.end())},
                          {4, cbor::Value::Bytes(intent_id.begin(), intent_id.end())},
                          {5, cbor::Value::Bytes(candidate.begin(), candidate.end())},
                        }})
      .bytes;
  };

  const auto decoded = lsp::decode_attach(encode_attach(successor));
  ASSERT_TRUE(decoded);
  EXPECT_EQ(decoded->session_id, session_id);
  EXPECT_EQ(decoded->attach_token, attach_token);
  EXPECT_EQ(decoded->intent_id, intent_id);
  EXPECT_EQ(decoded->successor_attach_token, successor);

  EXPECT_FALSE(lsp::decode_attach(encode_attach(attach_token)));
  EXPECT_FALSE(lsp::decode_attach(encode_attach({})));
  const auto four_keys = cbor::encode(cbor::Value {cbor::Value::Map {
                                        {1, 1U},
                                        {2, cbor::Value::Bytes(session_id.begin(), session_id.end())},
                                        {3, cbor::Value::Bytes(attach_token.begin(), attach_token.end())},
                                        {4, cbor::Value::Bytes(intent_id.begin(), intent_id.end())},
                                      }})
                           .bytes;
  EXPECT_FALSE(lsp::decode_attach(four_keys));
}

TEST(LspVideoControlWire, FreezesVideoConfigCodecMapHdrNullAndFiveKeyAcknowledgement) {
  const lsp::VideoConfigPayload configuration {
    .session_id = filled<16>(1),
    .stream_generation = 1,
    .video = video_selection(),
    .codec_configuration = {
      .kind = lsp::VideoCodec::h264,
      .units = {{0x67, 0x64, 0x00, 0x1f}, {0x68, 0xee, 0x3c, 0x80}},
    },
    .frame_id_origin = 10,
    .recovery_epoch = 1,
    .hdr_metadata = std::nullopt,
  };
  const auto encoded = lsp::encode_video_config(configuration);
  ASSERT_TRUE(encoded);
  EXPECT_LE(encoded->size(), std::size_t {1'152});
  const auto decoded = cbor::decode(*encoded);
  ASSERT_TRUE(decoded);
  const auto &map = std::get<cbor::Value::Map>(decoded.value->storage);
  ASSERT_EQ(map.size(), std::size_t {8});
  EXPECT_EQ(std::get<std::uint64_t>(map[0].second.storage), 3U);
  EXPECT_EQ(std::get<cbor::Value::Map>(map[3].second.storage).size(), std::size_t {30});
  const auto &codec_configuration = std::get<cbor::Value::Map>(map[4].second.storage);
  ASSERT_EQ(codec_configuration.size(), 2U);
  EXPECT_EQ(std::get<std::uint64_t>(codec_configuration[0].second.storage), 1U);
  EXPECT_EQ(std::get<cbor::Value::Array>(codec_configuration[1].second.storage).size(), std::size_t {2});
  EXPECT_TRUE(std::holds_alternative<cbor::Null>(map[7].second.storage));

  auto oversized_configuration = configuration;
  oversized_configuration.codec_configuration.units = {
    std::vector<std::uint8_t>(512, 0),
    std::vector<std::uint8_t>(512, 0),
  };
  oversized_configuration.codec_configuration.units[0][0] = 0x67;
  oversized_configuration.codec_configuration.units[1][0] = 0x68;
  EXPECT_FALSE(lsp::encode_video_config(oversized_configuration));

  const auto encode_ack = [&](const std::uint8_t schema_version) {
    return cbor::encode(cbor::Value {cbor::Value::Map {
                          {1, schema_version},
                          {2, 0U},
                          {3, cbor::Value::Bytes(configuration.session_id.begin(), configuration.session_id.end())},
                          {4, configuration.video.video_generation},
                          {5, 3U},
                        }})
      .bytes;
  };
  const auto ack_bytes = encode_ack(3);
  const auto ack = lsp::decode_video_config_ack(ack_bytes);
  ASSERT_TRUE(ack);
  EXPECT_EQ(ack->decoder_credit, 3U);
  EXPECT_EQ(ack->video_generation, configuration.video.video_generation);

  EXPECT_FALSE(lsp::decode_video_config_ack(encode_ack(2)));
}

TEST(LspVideoControlWire, ValidatesCodecProfilePixelAndH273ColorTuples) {
  auto response = start_response();
  response.video.profile = lsp::VideoProfile::h264_high_444_predictive;
  response.video.pixel_format = lsp::VideoPixelClass::yuv444_8;
  EXPECT_TRUE(lsp::encode_start_response(response));

  response.video.codec = lsp::VideoCodec::hevc;
  response.video.profile = lsp::VideoProfile::hevc_main10;
  response.video.pixel_format = lsp::VideoPixelClass::yuv420_10;
  response.video.color_primaries = lsp::video_color_primaries_bt2020;
  response.video.transfer_function = lsp::video_transfer_pq;
  response.video.matrix_coefficients = lsp::video_matrix_bt2020_ncl;
  EXPECT_TRUE(lsp::encode_start_response(response));

  response.video.codec = lsp::VideoCodec::av1;
  response.video.profile = lsp::VideoProfile::av1_high;
  response.video.pixel_format = lsp::VideoPixelClass::yuv444_10;
  response.video.transfer_function = lsp::video_transfer_hlg;
  EXPECT_TRUE(lsp::encode_start_response(response));

  response.video.profile = lsp::VideoProfile::av1_main;
  EXPECT_FALSE(lsp::encode_start_response(response));
  response.video.profile = lsp::VideoProfile::av1_high;
  response.video.full_range = true;
  EXPECT_FALSE(lsp::encode_start_response(response));
  response.video.full_range = false;
  response.video.codec = lsp::VideoCodec::h264;
  response.video.profile = lsp::VideoProfile::h264_high;
  response.video.pixel_format = lsp::VideoPixelClass::yuv420_10;
  EXPECT_FALSE(lsp::encode_start_response(response));
}

TEST(LspVideoControlWire, EncodesExactHdrMetadataAndCanonicalAv1CodecConfiguration) {
  auto selection = video_selection();
  selection.codec = lsp::VideoCodec::av1;
  selection.profile = lsp::VideoProfile::av1_main;
  selection.pixel_format = lsp::VideoPixelClass::yuv420_10;
  selection.color_primaries = lsp::video_color_primaries_bt2020;
  selection.transfer_function = lsp::video_transfer_pq;
  selection.matrix_coefficients = lsp::video_matrix_bt2020_ncl;
  const lsp::HdrMetadataPayload metadata {
    .red_primary_x = 35'400,
    .red_primary_y = 14'600,
    .green_primary_x = 8'500,
    .green_primary_y = 39'850,
    .blue_primary_x = 6'550,
    .blue_primary_y = 2'300,
    .white_point_x = 15'635,
    .white_point_y = 16'450,
    .maximum_display_luminance = 1'000,
    .minimum_display_luminance = 1,
    .maximum_content_light_level = 1'000,
    .maximum_frame_average_light_level = 400,
    .maximum_full_frame_luminance = 600,
  };
  lsp::VideoConfigPayload configuration {
    .session_id = filled<16>(1),
    .stream_generation = 1,
    .video = selection,
    .codec_configuration = {
      .kind = lsp::VideoCodec::av1,
      .units = {{0x0a, 0x01, 0x00}},
    },
    .frame_id_origin = 10,
    .recovery_epoch = 1,
    .hdr_metadata = metadata,
  };
  const auto encoded = lsp::encode_video_config(configuration);
  ASSERT_TRUE(encoded);
  const auto decoded = cbor::decode(*encoded);
  ASSERT_TRUE(decoded);
  const auto &map = std::get<cbor::Value::Map>(decoded.value->storage);
  EXPECT_EQ(std::get<cbor::Value::Map>(map[4].second.storage).size(), 2U);
  EXPECT_EQ(std::get<cbor::Value::Map>(map[7].second.storage).size(), 13U);

  configuration.hdr_metadata.reset();
  EXPECT_FALSE(lsp::encode_video_config(configuration));
  configuration.video.transfer_function = lsp::video_transfer_hlg;
  EXPECT_TRUE(lsp::encode_video_config(configuration));
  configuration.video.transfer_function = lsp::video_transfer_pq;
  configuration.hdr_metadata = metadata;
  configuration.hdr_metadata->white_point_x = 0;
  EXPECT_FALSE(lsp::encode_video_config(configuration));
  configuration.hdr_metadata = metadata;
  configuration.codec_configuration.units[0] = {0x0a, 0x81, 0x00, 0x00};
  EXPECT_FALSE(lsp::encode_video_config(configuration));
}

TEST(LspVideoRecoveryWire, SerializesFrameIdentityAndRecoveryEpochAsTwelveNetworkOrderBytes) {
  std::array<std::uint8_t, lsp::video_frame_identity_extension_size> extension {};
  ASSERT_TRUE(lsp::write_video_frame_identity_extension(extension, 0x0102030405060708ULL, 0x11121314U));
  EXPECT_EQ(
    extension,
    (std::array<std::uint8_t, 12> {
      0x01,
      0x02,
      0x03,
      0x04,
      0x05,
      0x06,
      0x07,
      0x08,
      0x11,
      0x12,
      0x13,
      0x14,
    })
  );
  EXPECT_FALSE(lsp::write_video_frame_identity_extension(extension, 0, 1));
  EXPECT_FALSE(lsp::write_video_frame_identity_extension(extension, 1, 0));
  std::array<std::uint8_t, 11> short_extension {};
  EXPECT_FALSE(lsp::write_video_frame_identity_extension(short_extension, 1, 1));
}

TEST(LspVideoRecoveryWire, UsesAuthenticatedDecoderErrorsForOneDeadlineGatedRecoveryAttempt) {
  lumen::lsp::transport::recovery_controller recovery {7};
  bool failure_latched = false;
  lumen::lsp::transport::lspv_status status {
    .session_generation = 1,
    .video_generation = 2,
    .recovery_epoch = 7,
    .largest_complete_frame_id = 50,
    .largest_decoded_frame_id = 49,
    .largest_metal_committed_frame_id = 49,
    .deadline_miss = true,
    .decoder_status = lumen::lsp::transport::lspv_decoder_status::ready,
    .maximum_decode_submissions = 3,
  };

  EXPECT_EQ(
    lsp::apply_authenticated_lspv_recovery(recovery, failure_latched, status, 50, 90),
    lsp::VideoRecoveryFeedbackAction::accepted
  );
  EXPECT_EQ(recovery.snapshot().phase, lumen::lsp::transport::recovery_phase::healthy);

  status.recovery_epoch = 6;
  EXPECT_EQ(
    lsp::apply_authenticated_lspv_recovery(recovery, failure_latched, status, 50, 92),
    lsp::VideoRecoveryFeedbackAction::ignored
  );
  status.recovery_epoch = 7;
  status.deadline_miss = false;
  status.decoder_status = lumen::lsp::transport::lspv_decoder_status::surface_exhausted;
  EXPECT_EQ(
    lsp::apply_authenticated_lspv_recovery(recovery, failure_latched, status, 50, 95),
    lsp::VideoRecoveryFeedbackAction::accepted
  );
  EXPECT_EQ(recovery.snapshot().epoch, 7U);

  status.decoder_status = lumen::lsp::transport::lspv_decoder_status::unrecoverable_error;
  EXPECT_EQ(
    lsp::apply_authenticated_lspv_recovery(recovery, failure_latched, status, 50, 100),
    lsp::VideoRecoveryFeedbackAction::request_independent_frame
  );
  ASSERT_EQ(recovery.snapshot().epoch, 8U);
  ASSERT_EQ(
    recovery.mark_independent_frame_sent(60, 100, 200),
    lumen::lsp::transport::recovery_result::accepted
  );

  status.recovery_epoch = 8;
  status.largest_complete_frame_id = 60;
  status.largest_decoded_frame_id = 59;
  status.largest_metal_committed_frame_id = 59;
  EXPECT_EQ(
    lsp::apply_authenticated_lspv_recovery(recovery, failure_latched, status, 60, 150),
    lsp::VideoRecoveryFeedbackAction::accepted
  );
  EXPECT_TRUE(failure_latched);
  EXPECT_EQ(recovery.snapshot().phase, lumen::lsp::transport::recovery_phase::recovery_frame_outstanding);
  EXPECT_EQ(
    lsp::apply_authenticated_lspv_recovery(recovery, failure_latched, status, 60, 200),
    lsp::VideoRecoveryFeedbackAction::request_independent_frame
  );
  EXPECT_FALSE(failure_latched);
  ASSERT_EQ(recovery.snapshot().phase, lumen::lsp::transport::recovery_phase::retry_permitted);
  ASSERT_EQ(
    recovery.mark_independent_frame_sent(61, 201, 300),
    lumen::lsp::transport::recovery_result::accepted
  );

  status.decoder_status = lumen::lsp::transport::lspv_decoder_status::ready;
  status.largest_complete_frame_id = 62;
  status.largest_decoded_frame_id = 62;
  status.largest_metal_committed_frame_id = 61;
  EXPECT_EQ(
    lsp::apply_authenticated_lspv_recovery(recovery, failure_latched, status, 62, 250),
    lsp::VideoRecoveryFeedbackAction::accepted
  );
  EXPECT_EQ(recovery.snapshot().phase, lumen::lsp::transport::recovery_phase::healthy);
}

TEST(LspVideoRecoveryWire, InvalidatesBlockedDependenciesAndRejectsStaleIndependentCompletion) {
  EXPECT_TRUE(lsp::video_recovery_drop_requires_dependency_invalidation(true, false, true));
  EXPECT_TRUE(lsp::video_recovery_drop_requires_dependency_invalidation(false, true, false));
  EXPECT_FALSE(lsp::video_recovery_drop_requires_dependency_invalidation(false, true, true));
  EXPECT_TRUE(lsp::video_independent_satisfies_dependency_fence(true, 0, 12, 20, 20, 20, 101, 100));
  EXPECT_TRUE(lsp::video_independent_satisfies_dependency_fence(false, 12, 12, 20, 20, 20, 101, 100));
  EXPECT_FALSE(lsp::video_independent_satisfies_dependency_fence(false, 11, 12, 19, 20, 20, 101, 100));
  EXPECT_FALSE(lsp::video_independent_satisfies_dependency_fence(true, 0, 12, 20, 19, 20, 101, 100));
  EXPECT_FALSE(lsp::video_independent_satisfies_dependency_fence(true, 0, 12, 20, 20, 20, 100, 100));
}

TEST(LspVideoRecoveryWire, QualifiesTerminalInvalidationAndCoalescesConcurrentQueuedRanges) {
  video::reference_invalidation_request_t active {
    .generation = 9,
    .first_frame = 100,
    .last_frame = 104,
  };
  const video::reference_invalidation_result_t exact {
    .generation = 9,
    .first_frame = 100,
    .last_frame = 104,
    .succeeded = true,
  };
  EXPECT_TRUE(video::reference_invalidation_result_matches(active, exact));
  auto stale_generation = exact;
  stale_generation.generation = 8;
  EXPECT_FALSE(video::reference_invalidation_result_matches(active, stale_generation));
  auto stale_range = exact;
  stale_range.last_frame = 105;
  EXPECT_FALSE(video::reference_invalidation_result_matches(active, stale_range));

  video::reference_invalidation_request_t queued {
    .first_frame = 110,
    .last_frame = 112,
  };
  ASSERT_TRUE(video::coalesce_reference_invalidation_range(queued, 106, 115));
  EXPECT_EQ(queued.generation, 0U);
  EXPECT_EQ(queued.first_frame, 106);
  EXPECT_EQ(queued.last_frame, 115);
}

TEST(LspVideoRecoveryWire, NewerConcurrentDependencyBreakWinsOverOlderIndependentRestore) {
  EXPECT_EQ(lsp::bind_video_invalidation_dependency_generation(40, 42, 41), 42U);
  EXPECT_EQ(lsp::bind_video_invalidation_dependency_generation(43, 42, 44), 44U);
  EXPECT_FALSE(lsp::video_independent_satisfies_dependency_fence(true, 0, 15, 15, 40, 41, 501, 500));
  EXPECT_FALSE(lsp::video_independent_satisfies_dependency_fence(false, 15, 15, 40, 40, 41, 501, 500));
}

TEST(LspVideoRecoveryWire, GenerationQualifiedReservationStopsDependentAtNextPacketBoundary) {
  EXPECT_FALSE(lsp::video_frame_is_partial_network_submission(0));
  EXPECT_TRUE(lsp::video_frame_is_partial_network_submission(1));
  EXPECT_TRUE(lsp::video_dependency_reservation_valid(false, 7, 7, true, false));
  EXPECT_FALSE(lsp::video_dependency_reservation_valid(false, 7, 8, true, false));
  EXPECT_FALSE(lsp::video_dependency_reservation_valid(false, 7, 7, false, false));
  EXPECT_FALSE(lsp::video_dependency_reservation_valid(false, 7, 7, true, true));
  EXPECT_TRUE(lsp::video_dependency_reservation_valid(true, 7, 8, false, true));
}

TEST(LspPathProbeWire, FreezesExactControlMapAndValidatesEveryLsppByte) {
  const lsp::PathProbePayload probe {
    .probe_id = 0x0102030405060708ULL,
    .udp_payload_size = 1'200,
  };
  const auto encoded = lsp::encode_path_probe(probe);
  ASSERT_TRUE(encoded);
  const auto value = cbor::decode(*encoded);
  ASSERT_TRUE(value);
  const auto &map = std::get<cbor::Value::Map>(value.value->storage);
  ASSERT_EQ(map.size(), 3U);
  EXPECT_EQ(lsp::decode_path_probe(*encoded), probe);
  auto trailing = *encoded;
  trailing.push_back(0);
  EXPECT_FALSE(lsp::decode_path_probe(trailing));
  const auto timeout = lsp::encode_control_error(lsp::ControlStatus::timeout);
  ASSERT_TRUE(timeout);
  EXPECT_EQ(lsp::decode_control_error(*timeout), lsp::ControlStatus::timeout);

  std::vector<std::uint8_t> lspp(1'180, 0);
  lspp[0] = 0x80;
  lspp[1] = 204;
  lumen::lsp::wire::write_be<std::uint16_t>(std::span<std::uint8_t> {lspp}.subspan<2, 2>(), 294);
  lumen::lsp::wire::write_be<std::uint32_t>(std::span<std::uint8_t> {lspp}.subspan<4, 4>(), 77);
  std::copy_n("LSPP", 4, lspp.begin() + 8);
  lspp[12] = 1;
  lumen::lsp::wire::write_be<std::uint16_t>(std::span<std::uint8_t> {lspp}.subspan<14, 2>(), 1'200);
  lumen::lsp::wire::write_be<std::uint64_t>(std::span<std::uint8_t> {lspp}.subspan<16, 8>(), probe.probe_id);
  EXPECT_EQ(lsp::parse_path_probe_datagram(lspp, 1'200, 77), probe);
  lspp[24] = 1;
  EXPECT_FALSE(lsp::parse_path_probe_datagram(lspp, 1'200, 77));
  lspp[24] = 0;
  EXPECT_FALSE(lsp::parse_path_probe_datagram(lspp, 1'199, 77));
  EXPECT_FALSE(lsp::parse_path_probe_datagram(lspp, 1'200, 78));
}

TEST(LspPathProbeWire, ClassifiesIntermediateReductionAgainstItsConfirmedGeneration) {
  EXPECT_EQ(
    lsp::classify_path_packet_size(1'400, 1'400),
    lsp::PathPacketSizeClass::confirmed_size
  );
  EXPECT_EQ(
    lsp::classify_path_packet_size(1'250, 1'400),
    lsp::PathPacketSizeClass::smaller
  );
  EXPECT_EQ(
    lsp::classify_path_packet_size(1'300, 1'300),
    lsp::PathPacketSizeClass::confirmed_size
  );
  EXPECT_EQ(
    lsp::classify_path_packet_size(1'250, 1'300),
    lsp::PathPacketSizeClass::smaller
  );
  EXPECT_EQ(
    lsp::classify_path_packet_size(1'400, 1'300),
    lsp::PathPacketSizeClass::invalid
  );
}

TEST(LspVideoRepairAdmission, ReservesExactPacketHeadroomAndBoundsFrameLocalGroups) {
  EXPECT_EQ(lsp::video_repair_packetization_reserve(false, false), 0U);
  EXPECT_EQ(lsp::video_repair_packetization_reserve(false, true), 2U);
  EXPECT_EQ(lsp::video_repair_packetization_reserve(true, false), 16U);
  EXPECT_EQ(lsp::video_repair_packetization_reserve(true, true), 16U);

  EXPECT_EQ(lsp::video_flexfec_group_packet_limit(1, false), 2U);
  EXPECT_EQ(lsp::video_flexfec_group_packet_limit(15, false), 15U);
  EXPECT_EQ(lsp::video_flexfec_group_packet_limit(64, false), 15U);
  EXPECT_EQ(lsp::video_flexfec_group_packet_limit(15, true), 8U);
  EXPECT_EQ(lsp::video_flexfec_group_packet_limit(5, true), 3U);
  EXPECT_EQ(lsp::video_flexfec_group_packet_limit(2, true), 2U);

  EXPECT_TRUE(lsp::video_rtx_frame_allowed(lsp::VideoNetworkProfile::adaptive_low_latency, false, false));
  EXPECT_FALSE(lsp::video_rtx_frame_allowed(lsp::VideoNetworkProfile::competition, false, false));
  EXPECT_TRUE(lsp::video_rtx_frame_allowed(lsp::VideoNetworkProfile::competition, false, true));
  EXPECT_TRUE(lsp::video_rtx_frame_allowed(lsp::VideoNetworkProfile::competition, true, false));

  EXPECT_TRUE(lsp::video_fir_command_is_duplicate(true, 10, 20, 7, 10, 20, 7));
  EXPECT_FALSE(lsp::video_fir_command_is_duplicate(false, 10, 20, 7, 10, 20, 7));
  EXPECT_FALSE(lsp::video_fir_command_is_duplicate(true, 10, 20, 7, 10, 20, 8));
  EXPECT_FALSE(lsp::video_fir_command_is_duplicate(true, 10, 20, 7, 11, 20, 7));
}

TEST(LspVideoRepairAdmission, CompetitionDeltaFramesCannotEvictIndependentRetention) {
  static std::array<
    lsp_transport::rtx_retained_packet,
    lsp_transport::required_rtx_retention_slots>
    slots {};
  lsp_transport::rtx_retention retention(slots);
  std::vector<std::uint64_t> released;
  const auto release = [&released](const std::uint64_t token) {
    released.push_back(token);
  };
  ASSERT_TRUE(lsp::video_rtx_frame_allowed(lsp::VideoNetworkProfile::competition, false, true));
  const auto independent = retention.begin_frame(
    {
      .frame_id = 100,
      .frame_deadline_microseconds = 10'000,
      .now_microseconds = 1'000,
      .retention_origin_microseconds = 1'000,
      .measured_rtt_microseconds = 5'000,
      .source_ssrc = 5,
      .video_generation = 7,
    },
    release
  );
  ASSERT_TRUE(independent);
  ASSERT_EQ(
    retention.retain(
      independent.handle,
      {.reconstruction_token = 1, .source_sequence_number = 42, .source_packet_bytes = 1'200}
    ),
    lsp_transport::rtx_retention_result::retained
  );
  ASSERT_EQ(
    retention.commit_frame(independent.handle, 1'000),
    lsp_transport::rtx_frame_result::accepted
  );

  const auto begin_if_allowed = [&](const std::uint64_t frame_id, const bool frame_independent) {
    std::optional<lsp_transport::rtx_frame_begin_result> result;
    if (lsp::video_rtx_frame_allowed(
          lsp::VideoNetworkProfile::competition,
          false,
          frame_independent
        )) {
      result = retention.begin_frame(
        {
          .frame_id = frame_id,
          .frame_deadline_microseconds = 10'000,
          .now_microseconds = 1'000,
          .retention_origin_microseconds = 1'000,
          .measured_rtt_microseconds = 5'000,
          .source_ssrc = 5,
          .video_generation = 7,
        },
        release
      );
    }
    return result;
  };
  EXPECT_FALSE(begin_if_allowed(101, false).has_value());
  EXPECT_FALSE(begin_if_allowed(102, false).has_value());
  EXPECT_EQ(retention.retained_frame_count(), 1U);
  const auto eligible = retention.find_eligible(7, 5, 42, 1'100, {});
  ASSERT_TRUE(eligible);
  EXPECT_EQ(eligible->frame_id, 100U);
  EXPECT_EQ(eligible->reconstruction_token, 1U);
  EXPECT_TRUE(released.empty());

  const auto cleared = retention.clear(release);
  EXPECT_EQ(cleared.frames_released, 1U);
  EXPECT_EQ(cleared.tokens_released, 1U);
  ASSERT_EQ(released.size(), 1U);
  EXPECT_EQ(released.front(), 1U);
}

TEST(LspCongestionFeedbackWire, ParsesVideoAndOddCountAudioBlocksThroughFinalTimestamp) {
  std::array<std::uint8_t, 36> packet {};
  packet[0] = static_cast<std::uint8_t>(0x80U | 11U);
  packet[1] = 205;
  lumen::lsp::wire::write_be<std::uint16_t>(std::span<std::uint8_t> {packet}.subspan<2, 2>(), 8);
  lumen::lsp::wire::write_be<std::uint32_t>(std::span<std::uint8_t> {packet}.subspan<4, 4>(), 10);

  lumen::lsp::wire::write_be<std::uint32_t>(std::span<std::uint8_t> {packet}.subspan<8, 4>(), 20);
  lumen::lsp::wire::write_be<std::uint16_t>(std::span<std::uint8_t> {packet}.subspan<12, 2>(), 100);
  lumen::lsp::wire::write_be<std::uint16_t>(std::span<std::uint8_t> {packet}.subspan<14, 2>(), 2);
  lumen::lsp::wire::write_be<std::uint16_t>(std::span<std::uint8_t> {packet}.subspan<16, 2>(), 0x8001);
  lumen::lsp::wire::write_be<std::uint16_t>(std::span<std::uint8_t> {packet}.subspan<18, 2>(), 0);

  lumen::lsp::wire::write_be<std::uint32_t>(std::span<std::uint8_t> {packet}.subspan<20, 4>(), 30);
  lumen::lsp::wire::write_be<std::uint16_t>(std::span<std::uint8_t> {packet}.subspan<24, 2>(), 200);
  lumen::lsp::wire::write_be<std::uint16_t>(std::span<std::uint8_t> {packet}.subspan<26, 2>(), 1);
  lumen::lsp::wire::write_be<std::uint16_t>(std::span<std::uint8_t> {packet}.subspan<28, 2>(), 0x8002);
  lumen::lsp::wire::write_be<std::uint32_t>(std::span<std::uint8_t> {packet}.subspan<32, 4>(), 0x12345678);

  const auto parsed = lsp::parse_congestion_feedback_packet(packet, 10);
  ASSERT_TRUE(parsed);
  ASSERT_EQ(parsed->block_count, 2U);
  EXPECT_EQ(parsed->blocks[0].media_ssrc, 20U);
  EXPECT_EQ(parsed->blocks[0].begin_sequence, 100U);
  EXPECT_EQ(parsed->blocks[0].report_count, 2U);
  EXPECT_EQ(parsed->blocks[0].metrics.size(), 4U);
  EXPECT_EQ(parsed->blocks[1].media_ssrc, 30U);
  EXPECT_EQ(parsed->blocks[1].begin_sequence, 200U);
  EXPECT_EQ(parsed->blocks[1].report_count, 1U);
  EXPECT_EQ(parsed->blocks[1].metrics.size(), 2U);
  EXPECT_EQ(parsed->report_timestamp, 0x12345678U);
  EXPECT_EQ(
    lsp::classify_congestion_feedback_content(*parsed, 20, 30),
    lsp::CongestionFeedbackContent::video
  );
  auto repair_feedback = *parsed;
  repair_feedback.blocks[2].media_ssrc = 40;
  repair_feedback.block_count = 3;
  EXPECT_EQ(
    lsp::classify_congestion_feedback_content(repair_feedback, 20, 30, 40, 50),
    lsp::CongestionFeedbackContent::video
  );
  repair_feedback.blocks[2].media_ssrc = 50;
  EXPECT_EQ(
    lsp::classify_congestion_feedback_content(repair_feedback, 20, 30, 40, 50),
    lsp::CongestionFeedbackContent::video
  );
  repair_feedback.blocks[2].media_ssrc = 20;
  EXPECT_EQ(
    lsp::classify_congestion_feedback_content(repair_feedback, 20, 30, 40, 50),
    lsp::CongestionFeedbackContent::invalid
  );

  packet[31] = 1;
  EXPECT_FALSE(lsp::parse_congestion_feedback_packet(packet, 10));

  std::array<std::uint8_t, 24> audio_only {};
  audio_only[0] = static_cast<std::uint8_t>(0x80U | 11U);
  audio_only[1] = 205;
  lumen::lsp::wire::write_be<std::uint16_t>(std::span<std::uint8_t> {audio_only}.subspan<2, 2>(), 5);
  lumen::lsp::wire::write_be<std::uint32_t>(std::span<std::uint8_t> {audio_only}.subspan<4, 4>(), 10);
  lumen::lsp::wire::write_be<std::uint32_t>(std::span<std::uint8_t> {audio_only}.subspan<8, 4>(), 30);
  lumen::lsp::wire::write_be<std::uint16_t>(std::span<std::uint8_t> {audio_only}.subspan<12, 2>(), 200);
  lumen::lsp::wire::write_be<std::uint16_t>(std::span<std::uint8_t> {audio_only}.subspan<14, 2>(), 1);
  lumen::lsp::wire::write_be<std::uint16_t>(std::span<std::uint8_t> {audio_only}.subspan<16, 2>(), 0x8002);
  lumen::lsp::wire::write_be<std::uint32_t>(std::span<std::uint8_t> {audio_only}.subspan<20, 4>(), 0x12345679);
  const auto parsed_audio_only = lsp::parse_congestion_feedback_packet(audio_only, 10);
  ASSERT_TRUE(parsed_audio_only);
  EXPECT_EQ(
    lsp::classify_congestion_feedback_content(*parsed_audio_only, 20, 30),
    lsp::CongestionFeedbackContent::audio_only
  );
  EXPECT_EQ(
    lsp::classify_congestion_feedback_content(*parsed_audio_only, 20, 31),
    lsp::CongestionFeedbackContent::invalid
  );
}
