/**
 * @file tests/unit/test_stream_policy.cpp
 * @brief Tests for immutable per-session stream optimization policies.
 */

// standard includes
#include <array>
#include <atomic>
#include <functional>
#include <limits>
#include <stdexcept>
#include <thread>

// lib includes
#include <gtest/gtest.h>

// local includes
#include "src/stream_policy.h"

namespace {
  using namespace std::chrono_literals;
  using namespace std::literals;

  /**
   * @brief Return an override snapshot with no explicitly configured settings.
   * @return Empty overrides.
   */
  stream_policy::AdvancedOverrides no_overrides() {
    return {};
  }

  /**
   * @brief Resolve one policy with deterministic test defaults.
   * @param requested Client-requested mode.
   * @param internal_default Internal fallback mode.
   * @param configured_fec Configured legacy FEC percentage.
   * @param overrides Explicit advanced overrides.
   * @return Resolved policy.
   */
  stream_policy::EffectiveStreamPolicy resolve(
    std::optional<stream_policy::StreamOptimizationMode> requested,
    stream_policy::StreamOptimizationMode internal_default = stream_policy::StreamOptimizationMode::legacy,
    int configured_fec = 20,
    const stream_policy::AdvancedOverrides &overrides = no_overrides()
  ) {
    return stream_policy::resolve_policy(
      requested,
      internal_default,
      nvenc::nvenc_config {},
      configured_fec,
      overrides
    );
  }

  /**
   * @brief Assert equality for every NVENC setting represented by the policy foundation.
   * @param actual Actual configuration.
   * @param expected Expected configuration.
   */
  void expect_nvenc_equal(const nvenc::nvenc_config &actual, const nvenc::nvenc_config &expected) {
    EXPECT_EQ(actual.quality_preset, expected.quality_preset);
    EXPECT_EQ(actual.tuning, expected.tuning);
    EXPECT_EQ(actual.fidelity, expected.fidelity);
    EXPECT_EQ(actual.two_pass, expected.two_pass);
    EXPECT_EQ(actual.vbv_percentage_increase, expected.vbv_percentage_increase);
    EXPECT_EQ(actual.weighted_prediction, expected.weighted_prediction);
    EXPECT_EQ(actual.adaptive_quantization, expected.adaptive_quantization);
    EXPECT_EQ(actual.enable_min_qp, expected.enable_min_qp);
    EXPECT_EQ(actual.min_qp_h264, expected.min_qp_h264);
    EXPECT_EQ(actual.min_qp_hevc, expected.min_qp_hevc);
    EXPECT_EQ(actual.min_qp_av1, expected.min_qp_av1);
    EXPECT_EQ(actual.h264_cavlc, expected.h264_cavlc);
    EXPECT_EQ(actual.insert_filler_data, expected.insert_filler_data);
    EXPECT_EQ(actual.split_frame_encoding, expected.split_frame_encoding);
  }
}  // namespace

TEST(StreamPolicyParserTest, AcceptsOnlyExactSupportedValues) {
  using stream_policy::ParsedOptimizationMode;
  using stream_policy::StreamOptimizationMode;

  EXPECT_EQ(
    stream_policy::parse_optimization_mode(std::nullopt).status,
    ParsedOptimizationMode::Status::absent
  );
  EXPECT_EQ(stream_policy::parse_optimization_mode("latency").mode, StreamOptimizationMode::latency);
  EXPECT_EQ(stream_policy::parse_optimization_mode("quality").mode, StreamOptimizationMode::quality);

  constexpr auto malformed_values = std::to_array<std::string_view>({
    "",
    "legacy",
    "Latency",
    "QUALITY",
    " latency",
    "quality ",
    "latency\0suffix"sv,
  });
  for (const auto malformed : malformed_values) {
    EXPECT_EQ(
      stream_policy::parse_optimization_mode(malformed).status,
      ParsedOptimizationMode::Status::invalid
    ) << malformed;
  }
}

TEST(StreamPolicyParserTest, ParsesCompleteRtspAnnouncePayloadStrictly) {
  using stream_policy::ParsedOptimizationMode;
  using stream_policy::StreamOptimizationMode;

  const auto latency = stream_policy::parse_rtsp_announce_optimization_mode(
    "v=0\r\na=x-nv-video[0].maxFPS:120\r\na=x-lumen-optimization-mode:latency\r\n"sv
  );
  EXPECT_EQ(latency.status, ParsedOptimizationMode::Status::valid);
  EXPECT_EQ(latency.mode, StreamOptimizationMode::latency);

  const auto quality = stream_policy::parse_rtsp_announce_optimization_mode(
    "v=0\na=x-lumen-optimization-mode:quality\na=x-nv-video[0].packetSize:1024\n"sv
  );
  EXPECT_EQ(quality.status, ParsedOptimizationMode::Status::valid);
  EXPECT_EQ(quality.mode, StreamOptimizationMode::quality);

  EXPECT_EQ(
    stream_policy::parse_rtsp_announce_optimization_mode("v=0\r\na=x-nv-video[0].maxFPS:120\r\n").status,
    ParsedOptimizationMode::Status::absent
  );

  constexpr auto malformed_payloads = std::to_array<std::string_view>({
    "a=x-lumen-optimization-mode\r\n",
    "a=x-lumen-optimization-mode:\r\n",
    "a=x-lumen-optimization-mode:latency \r\n",
    "a=x-lumen-optimization-mode:Latency\r\n",
    "a=x-lumen-optimization-mode:legacy\r\n",
    "a=x-lumen-optimization-mode:latency\r\na=x-lumen-optimization-mode:latency\r\n",
    "a=x-lumen-optimization-mode:latency\r\na=x-lumen-optimization-mode:quality\r\n",
  });
  for (const auto payload : malformed_payloads) {
    EXPECT_EQ(
      stream_policy::parse_rtsp_announce_optimization_mode(payload).status,
      ParsedOptimizationMode::Status::invalid
    ) << payload;
  }
}

TEST(StreamPolicyParserTest, ParsesFidelityIndependentlyAndRejectsAmbiguity) {
  using Status = stream_policy::ParsedFidelityRequest::Status;
  using stream_policy::StreamFidelityRequest;

  EXPECT_EQ(
    stream_policy::parse_rtsp_announce_fidelity_request("v=0\r\n").status,
    Status::absent
  );
  const auto required = stream_policy::parse_rtsp_announce_fidelity_request(
    "v=0\r\na=x-lumen-video-fidelity:codec-lossless-required\r\n"sv
  );
  EXPECT_EQ(required.status, Status::valid);
  EXPECT_EQ(required.request, StreamFidelityRequest::codec_lossless_required);
  const auto allowed = stream_policy::parse_rtsp_announce_fidelity_request(
    "a=x-lumen-video-fidelity:visually-lossless-allowed\n"sv
  );
  EXPECT_EQ(allowed.status, Status::valid);
  EXPECT_EQ(allowed.request, StreamFidelityRequest::visually_lossless_allowed);

  constexpr auto malformed = std::to_array<std::string_view>({
    "a=x-lumen-video-fidelity\r\n",
    "a=x-lumen-video-fidelity:\r\n",
    "a=x-lumen-video-fidelity:lossless\r\n",
    "a=x-lumen-video-fidelity:codec-lossless-required \r\n",
    "a=x-lumen-video-fidelity:codec-lossless-required\r\na=x-lumen-video-fidelity:codec-lossless-required\r\n",
    "a=x-lumen-video-fidelity:codec-lossless-required\r\na=x-lumen-video-fidelity:visually-lossless-allowed\r\n",
  });
  for (const auto payload : malformed) {
    EXPECT_EQ(stream_policy::parse_rtsp_announce_fidelity_request(payload).status, Status::invalid)
      << payload;
  }
}

TEST(StreamPolicyParserTest, ClassifiesDedicatedUmbraLegacyMarkerStrictly) {
  using stream_policy::ClientProtocol;
  using Status = stream_policy::ParsedClientProtocol::Status;

  EXPECT_EQ(
    stream_policy::parse_rtsp_announce_client_protocol("v=0\r\na=x-nv-video[0].maxFPS:120\r\n").protocol,
    ClientProtocol::vanilla
  );
  EXPECT_EQ(
    stream_policy::parse_rtsp_announce_client_protocol(
      "v=0\r\na=x-lumen-optimization-mode:latency\r\n"
    )
      .protocol,
    ClientProtocol::third_party_extension
  );
  const auto umbra = stream_policy::parse_rtsp_announce_client_protocol(
    "v=0\r\na=x-lumen-optimization-mode:quality\r\na=x-umbra-client-protocol:legacy-v1\r\n"
  );
  EXPECT_EQ(umbra.status, Status::valid);
  EXPECT_EQ(umbra.protocol, ClientProtocol::umbra_legacy);

  constexpr auto malformed = std::to_array<std::string_view>({
    "a=x-umbra-client-protocol\r\n",
    "a=x-umbra-client-protocol:\r\n",
    "a=x-umbra-client-protocol:legacy-v1 \r\n",
    "a=x-umbra-client-protocol:Legacy-v1\r\n",
    "a=x-umbra-client-protocol:legacy-v2\r\n",
    "a=x-umbra-client-protocol-extra:legacy-v1\r\n",
    "a=x-umbra-client-protocol:legacy-v1\r\na=x-umbra-client-protocol:legacy-v1\r\n",
  });
  for (const auto payload : malformed) {
    EXPECT_EQ(stream_policy::parse_rtsp_announce_client_protocol(payload).status, Status::invalid)
      << payload;
  }
}

TEST(StreamPolicyProfileTest, FixedLatencyProfileMatchesImplementedControls) {
  const auto &latency = stream_policy::fixed_profiles().latency;
  EXPECT_EQ(latency.nvenc.quality_preset, 1);
  EXPECT_EQ(latency.nvenc.tuning, nvenc::nvenc_tuning::ultra_low_latency);
  EXPECT_EQ(latency.nvenc.two_pass, nvenc::nvenc_two_pass::disabled);
  EXPECT_EQ(latency.nvenc.vbv_percentage_increase, 0);
  EXPECT_FALSE(latency.nvenc.weighted_prediction);
  EXPECT_FALSE(latency.nvenc.adaptive_quantization);
  EXPECT_EQ(latency.static_profile_fec.minimum_percentage, 0);
  EXPECT_EQ(latency.static_profile_fec.maximum_percentage, 10);
  EXPECT_EQ(latency.static_profile_fec.ordinary_percentage, 0);
  EXPECT_EQ(latency.static_profile_fec.recovery_percentage, 10);
  EXPECT_EQ(latency.packet_pacing, stream_policy::PacketPacingMode::immediate);
}

TEST(StreamPolicyProfileTest, FixedQualityProfileMatchesImplementedControls) {
  const auto &quality = stream_policy::fixed_profiles().quality;
  EXPECT_EQ(quality.nvenc.quality_preset, 5);
  EXPECT_EQ(quality.nvenc.tuning, nvenc::nvenc_tuning::high_quality);
  EXPECT_EQ(quality.nvenc.two_pass, nvenc::nvenc_two_pass::quarter_resolution);
  EXPECT_EQ(quality.nvenc.vbv_percentage_increase, 100);
  EXPECT_TRUE(quality.nvenc.weighted_prediction);
  EXPECT_TRUE(quality.nvenc.adaptive_quantization);
  EXPECT_EQ(quality.static_profile_fec.minimum_percentage, 10);
  EXPECT_EQ(quality.static_profile_fec.maximum_percentage, 20);
  EXPECT_EQ(quality.static_profile_fec.ordinary_percentage, 10);
  EXPECT_EQ(quality.static_profile_fec.recovery_percentage, 20);
  EXPECT_EQ(quality.packet_pacing, stream_policy::PacketPacingMode::stable);
}

TEST(StreamPolicyResolutionTest, MissingClientModeRetainsLegacyBehavior) {
  auto configured_nvenc = nvenc::nvenc_config {};
  configured_nvenc.quality_preset = 7;
  configured_nvenc.tuning = nvenc::nvenc_tuning::high_quality;
  configured_nvenc.two_pass = nvenc::nvenc_two_pass::full_resolution;
  configured_nvenc.vbv_percentage_increase = 37;
  configured_nvenc.weighted_prediction = true;
  configured_nvenc.adaptive_quantization = true;

  const auto policy = stream_policy::resolve_policy(
    std::nullopt,
    stream_policy::StreamOptimizationMode::legacy,
    configured_nvenc,
    37,
    no_overrides()
  );

  EXPECT_EQ(policy.mode, stream_policy::StreamOptimizationMode::legacy);
  EXPECT_FALSE(policy.client_negotiated_mode);
  expect_nvenc_equal(policy.nvenc, configured_nvenc);
  const auto ordinary = stream_policy::select_frame_fec(policy, false, 100, 5);
  EXPECT_EQ(ordinary.percentage, 37);
  EXPECT_EQ(ordinary.minimum_fec_packets, 5U);
  EXPECT_EQ(policy.packet_pacing, stream_policy::PacketPacingMode::legacy);
}

TEST(StreamPolicyResolutionTest, ZeroLatencyFecRequiresExplicitRtspNegotiation) {
  const auto internal = resolve(
    std::nullopt,
    stream_policy::StreamOptimizationMode::latency
  );
  EXPECT_FALSE(internal.client_negotiated_mode);
  EXPECT_EQ(stream_policy::select_frame_fec(internal, false, 100, 2).percentage, 2);

  const auto negotiated = resolve(stream_policy::StreamOptimizationMode::latency);
  EXPECT_TRUE(negotiated.client_negotiated_mode);
  const auto ordinary = stream_policy::select_frame_fec(negotiated, false, 100, 2);
  EXPECT_EQ(ordinary.percentage, 0);
  EXPECT_EQ(ordinary.minimum_fec_packets, 0U);
  EXPECT_EQ(stream_policy::select_frame_fec(negotiated, true, 100, 2).percentage, 10);
}

TEST(StreamPolicyResolutionTest, ExplicitAdvancedSettingsHaveDeterministicPrecedence) {
  auto configured_nvenc = nvenc::nvenc_config {};
  configured_nvenc.quality_preset = 7;
  configured_nvenc.two_pass = nvenc::nvenc_two_pass::full_resolution;
  configured_nvenc.adaptive_quantization = true;
  configured_nvenc.vbv_percentage_increase = 250;

  const auto overrides = stream_policy::capture_advanced_overrides(
    configured_nvenc,
    7,
    stream_policy::AdvancedOverridePresence {true, true, true, true, true}
  );
  const auto policy = stream_policy::resolve_policy(
    stream_policy::StreamOptimizationMode::latency,
    stream_policy::StreamOptimizationMode::legacy,
    configured_nvenc,
    20,
    overrides
  );

  EXPECT_EQ(policy.nvenc.quality_preset, 7);
  EXPECT_EQ(policy.nvenc.two_pass, nvenc::nvenc_two_pass::full_resolution);
  EXPECT_TRUE(policy.nvenc.adaptive_quantization);
  EXPECT_EQ(policy.nvenc.vbv_percentage_increase, 250);
  EXPECT_EQ(stream_policy::select_frame_fec(policy, false, 100, 0).percentage, 7);
  EXPECT_EQ(stream_policy::select_frame_fec(policy, true, 100, 0).percentage, 7);
  EXPECT_EQ(stream_policy::maximum_fec_percentage(policy), 10);
}

TEST(StreamPolicyResolutionTest, RequiredLosslessOverridesOnlyInQualityAndDisablesExtraPasses) {
  auto configured = nvenc::nvenc_config {};
  configured.two_pass = nvenc::nvenc_two_pass::full_resolution;
  configured.adaptive_quantization = true;
  configured.enable_min_qp = true;
  configured.insert_filler_data = true;
  const auto overrides = stream_policy::capture_advanced_overrides(
    configured,
    20,
    stream_policy::AdvancedOverridePresence {false, true, true, false, false}
  );
  const auto quality = stream_policy::resolve_policy(
    stream_policy::StreamOptimizationMode::quality,
    stream_policy::StreamOptimizationMode::legacy,
    configured,
    20,
    overrides,
    stream_policy::StreamFidelityRequest::codec_lossless_required
  );

  EXPECT_EQ(quality.fidelity_request, stream_policy::StreamFidelityRequest::codec_lossless_required);
  EXPECT_EQ(quality.nvenc.fidelity, nvenc::nvenc_fidelity::codec_lossless_required);
  EXPECT_EQ(quality.nvenc.tuning, nvenc::nvenc_tuning::lossless);
  EXPECT_EQ(quality.nvenc.two_pass, nvenc::nvenc_two_pass::disabled);
  EXPECT_EQ(quality.nvenc.vbv_percentage_increase, 0);
  EXPECT_FALSE(quality.nvenc.weighted_prediction);
  EXPECT_FALSE(quality.nvenc.adaptive_quantization);
  EXPECT_FALSE(quality.nvenc.enable_min_qp);
  EXPECT_FALSE(quality.nvenc.insert_filler_data);
  EXPECT_EQ(quality.selected_fidelity, stream_policy::SelectedFidelityClass::rejected);

  const auto ordinary_quality = resolve(stream_policy::StreamOptimizationMode::quality);
  EXPECT_EQ(ordinary_quality.nvenc.fidelity, nvenc::nvenc_fidelity::rate_controlled);
  EXPECT_EQ(
    ordinary_quality.selected_fidelity,
    stream_policy::SelectedFidelityClass::visually_lossless_rate_controlled
  );
  const auto latency = resolve(stream_policy::StreamOptimizationMode::latency);
  EXPECT_EQ(latency.nvenc.fidelity, nvenc::nvenc_fidelity::rate_controlled);
  EXPECT_EQ(latency.nvenc.tuning, nvenc::nvenc_tuning::ultra_low_latency);
  EXPECT_EQ(latency.nvenc.two_pass, nvenc::nvenc_two_pass::disabled);
  EXPECT_EQ(latency.selected_fidelity, stream_policy::SelectedFidelityClass::latency_rate_controlled);
  EXPECT_TRUE(stream_policy::permits_encoder_backend(latency, false));
  EXPECT_TRUE(stream_policy::permits_encoder_backend(quality, true));
  EXPECT_FALSE(stream_policy::permits_encoder_backend(quality, false));
}

TEST(StreamPolicyFidelityTest, RequiredLosslessSelectsExactPixelFormatClass) {
  using stream_policy::FidelityProof;
  using stream_policy::SelectedFidelityClass;
  using stream_policy::StreamFidelityRequest;
  using stream_policy::StreamOptimizationMode;

  const auto yuv444_10 = stream_policy::select_fidelity(
    StreamOptimizationMode::quality,
    StreamFidelityRequest::codec_lossless_required,
    FidelityProof {1, 10, true, true, true, true, true}
  );
  EXPECT_EQ(yuv444_10.selected, SelectedFidelityClass::codec_lossless_yuv444_10bit);
  EXPECT_EQ(yuv444_10.rejection, stream_policy::FidelityRejectionReason::none);

  const auto yuv420_8 = stream_policy::select_fidelity(
    StreamOptimizationMode::quality,
    StreamFidelityRequest::codec_lossless_required,
    FidelityProof {2, 8, false, true, true, true, true}
  );
  EXPECT_EQ(yuv420_8.selected, SelectedFidelityClass::codec_lossless_yuv420_8bit);

  const auto visually = stream_policy::select_fidelity(
    StreamOptimizationMode::quality,
    StreamFidelityRequest::visually_lossless_allowed,
    FidelityProof {1, 10, true, false, false, false, false}
  );
  EXPECT_EQ(visually.selected, SelectedFidelityClass::visually_lossless_rate_controlled);
  EXPECT_EQ(visually.rejection, stream_policy::FidelityRejectionReason::none);
}

TEST(StreamPolicyFidelityTest, RequiredLosslessRejectsEveryMissingProofWithoutFallback) {
  using stream_policy::FidelityProof;
  using stream_policy::FidelityRejectionReason;
  using stream_policy::SelectedFidelityClass;
  using stream_policy::StreamFidelityRequest;
  using stream_policy::StreamOptimizationMode;

  const auto expect_rejection = [](const StreamOptimizationMode mode, const FidelityProof &proof, const FidelityRejectionReason reason) {
    const auto selected = stream_policy::select_fidelity(
      mode,
      StreamFidelityRequest::codec_lossless_required,
      proof
    );
    EXPECT_EQ(selected.selected, SelectedFidelityClass::rejected);
    EXPECT_EQ(selected.rejection, reason);
  };

  expect_rejection(StreamOptimizationMode::latency, {1, 10, true, true, true, true, true}, FidelityRejectionReason::quality_mode_required);
  expect_rejection(StreamOptimizationMode::quality, {1, 10, true, false, true, true, true}, FidelityRejectionReason::decoder_tuple_unproven);
  expect_rejection(StreamOptimizationMode::quality, {1, 10, true, true, false, true, true}, FidelityRejectionReason::encoder_lossless_unavailable);
  expect_rejection(StreamOptimizationMode::quality, {1, 10, true, true, true, false, true}, FidelityRejectionReason::bit_depth_unavailable);
  expect_rejection(StreamOptimizationMode::quality, {1, 10, true, true, true, true, false}, FidelityRejectionReason::chroma_unavailable);
  expect_rejection(StreamOptimizationMode::quality, {0, 8, false, true, true, true, true}, FidelityRejectionReason::h264_high444_required);
}

TEST(StreamPolicyFidelityTest, ProbeCapabilityCacheIsPositiveOnlyAndResettable) {
  stream_policy::reset_nvenc_lossless_capabilities();
  EXPECT_FALSE(stream_policy::nvenc_lossless_capability(0));
  EXPECT_FALSE(stream_policy::nvenc_lossless_capability(1));
  EXPECT_FALSE(stream_policy::nvenc_lossless_capability(2));
  EXPECT_FALSE(stream_policy::nvenc_lossless_capability(-1));
  EXPECT_FALSE(stream_policy::nvenc_lossless_capability(3));

  stream_policy::record_nvenc_lossless_capability(1, true);
  stream_policy::record_nvenc_lossless_capability(1, false);
  stream_policy::record_nvenc_lossless_capability(-1, true);
  stream_policy::record_nvenc_lossless_capability(3, true);
  EXPECT_FALSE(stream_policy::nvenc_lossless_capability(1));
  stream_policy::publish_nvenc_lossless_capabilities(true);
  EXPECT_TRUE(stream_policy::nvenc_lossless_capability(1));
  EXPECT_FALSE(stream_policy::nvenc_lossless_capability(0));
  EXPECT_FALSE(stream_policy::nvenc_lossless_capability(2));

  stream_policy::reset_nvenc_lossless_capabilities();
  EXPECT_FALSE(stream_policy::nvenc_lossless_capability(1));
  stream_policy::record_nvenc_lossless_capability(1, true);
  stream_policy::publish_nvenc_lossless_capabilities(false);
  EXPECT_FALSE(stream_policy::nvenc_lossless_capability(1));
}

TEST(StreamPolicyFidelityTest, NvencLosslessGoldenIsQpZeroSinglePassWithoutLookahead) {
  constexpr auto contract = nvenc::required_lossless_contract();
  static_assert(contract.qp_inter_p == 0);
  static_assert(contract.qp_inter_b == 0);
  static_assert(contract.qp_intra == 0);
  static_assert(!contract.multipass);
  static_assert(!contract.adaptive_quantization);
  static_assert(!contract.lookahead);

  struct TestQp {
    unsigned qpInterP;
    unsigned qpInterB;
    unsigned qpIntra;
  };

  struct TestRateControl {
    unsigned version;
    unsigned rateControlMode;
    TestQp constQP;
    unsigned averageBitRate;
    unsigned maxBitRate;
    unsigned vbvBufferSize;
    unsigned vbvInitialDelay;
    unsigned enableMinQP;
    unsigned enableMaxQP;
    unsigned enableInitialRCQP;
    unsigned enableAQ;
    unsigned enableTemporalAQ;
    unsigned enableLookahead;
    unsigned zeroReorderDelay;
    unsigned lookaheadDepth;
    unsigned multiPass;
  };

  TestRateControl actual {
    99,
    99,
    {99, 99, 99},
    99,
    99,
    99,
    99,
    1,
    1,
    1,
    1,
    1,
    1,
    0,
    99,
    99,
  };
  nvenc::apply_lossless_rate_control(actual, 13U, 7U, 0U);
  EXPECT_EQ(actual.version, 13U);
  EXPECT_EQ(actual.rateControlMode, 7U);
  EXPECT_EQ(actual.constQP.qpInterP, 0U);
  EXPECT_EQ(actual.constQP.qpInterB, 0U);
  EXPECT_EQ(actual.constQP.qpIntra, 0U);
  EXPECT_EQ(actual.zeroReorderDelay, 1U);
  EXPECT_EQ(actual.multiPass, 0U);
  EXPECT_EQ(actual.averageBitRate, 0U);
  EXPECT_EQ(actual.maxBitRate, 0U);
  EXPECT_EQ(actual.vbvBufferSize, 0U);
  EXPECT_EQ(actual.vbvInitialDelay, 0U);
  EXPECT_EQ(actual.enableMinQP, 0U);
  EXPECT_EQ(actual.enableMaxQP, 0U);
  EXPECT_EQ(actual.enableInitialRCQP, 0U);
  EXPECT_EQ(actual.enableAQ, 0U);
  EXPECT_EQ(actual.enableTemporalAQ, 0U);
  EXPECT_EQ(actual.enableLookahead, 0U);
  EXPECT_EQ(actual.lookaheadDepth, 0U);
}

TEST(StreamPolicyFecTest, HonorsNegotiatedMinimumWithinEachFixedProfileBound) {
  const auto latency = resolve(
    std::nullopt,
    stream_policy::StreamOptimizationMode::latency
  );
  const auto latency_selection = stream_policy::select_frame_fec(latency, false, 100, 50);
  EXPECT_EQ(latency_selection.percentage, 10);
  EXPECT_EQ(latency_selection.minimum_fec_packets, 10U);

  const auto quality = resolve(stream_policy::StreamOptimizationMode::quality);
  const auto quality_selection = stream_policy::select_frame_fec(quality, false, 100, 99);
  EXPECT_EQ(quality_selection.percentage, 20);
  EXPECT_EQ(quality_selection.minimum_fec_packets, 20U);

  const auto small_block = stream_policy::select_frame_fec(quality, false, 3, 99);
  EXPECT_EQ(small_block.percentage, 10);
  EXPECT_EQ(small_block.minimum_fec_packets, 1U);

  const auto nine_data_shards = stream_policy::select_frame_fec(quality, false, 9, 2);
  EXPECT_EQ(nine_data_shards.percentage, 20);
  EXPECT_EQ(nine_data_shards.minimum_fec_packets, 2U);
  EXPECT_EQ(
    stream_policy::pack_video_fec_info(1, 9, nine_data_shards.percentage),
    (1U << 12U) | (9U << 22U) | (20U << 4U)
  );

  constexpr auto maximum_shards = std::numeric_limits<std::size_t>::max();
  constexpr auto expected_bounded_minimum =
    (maximum_shards / 100U) * 20U + ((maximum_shards % 100U) * 20U + 99U) / 100U;
  const auto maximum_boundary = stream_policy::select_frame_fec(
    quality,
    false,
    maximum_shards,
    maximum_shards
  );
  EXPECT_EQ(maximum_boundary.percentage, 20);
  EXPECT_EQ(maximum_boundary.minimum_fec_packets, expected_bounded_minimum);
}

TEST(StreamPolicyFecTest, PacksZeroAndMinimumRaisedPercentagesIntoProductionHeader) {
  const auto explicit_latency = resolve(stream_policy::StreamOptimizationMode::latency);
  const auto zero = stream_policy::select_frame_fec(explicit_latency, false, 100, 2);
  ASSERT_EQ(zero.percentage, 0);
  EXPECT_EQ(stream_policy::pack_video_fec_info(3, 100, zero.percentage), (3U << 12U) | (100U << 22U));

  const auto quality = resolve(stream_policy::StreamOptimizationMode::quality);
  const auto minimum_raised = stream_policy::select_frame_fec(quality, false, 100, 20);
  ASSERT_EQ(minimum_raised.percentage, 20);
  EXPECT_EQ(
    stream_policy::pack_video_fec_info(3, 100, minimum_raised.percentage),
    (3U << 12U) | (100U << 22U) | (20U << 4U)
  );
}

TEST(StreamPolicyFecTest, ReservesBitrateUsingProductionWorstCasePercentage) {
  const auto latency = resolve(stream_policy::StreamOptimizationMode::latency);
  const auto quality = resolve(stream_policy::StreamOptimizationMode::quality);
  const auto legacy = resolve(std::nullopt, stream_policy::StreamOptimizationMode::legacy, 20);
  const auto malformed_legacy = resolve(std::nullopt, stream_policy::StreamOptimizationMode::legacy, 100);

  EXPECT_EQ(stream_policy::reserve_bitrate_for_fec(100000, latency), 90000);
  EXPECT_EQ(stream_policy::reserve_bitrate_for_fec(100000, quality), 80000);
  EXPECT_EQ(stream_policy::reserve_bitrate_for_fec(100000, legacy), 80000);
  EXPECT_EQ(stream_policy::reserve_bitrate_for_fec(100000, malformed_legacy), 100000);

  constexpr auto maximum = std::numeric_limits<std::int64_t>::max();
  constexpr auto minimum = std::numeric_limits<std::int64_t>::min();
  const auto expected_maximum = (maximum / 100) * 90 + (maximum % 100) * 90 / 100;
  const auto expected_minimum = (minimum / 100) * 90 + (minimum % 100) * 90 / 100;
  EXPECT_EQ(stream_policy::reserve_bitrate_for_fec(maximum, latency), expected_maximum);
  EXPECT_EQ(stream_policy::reserve_bitrate_for_fec(minimum, latency), expected_minimum);
}

TEST(StreamPolicyPacingTest, UsesPerSessionWireAndPathBudgetsWithinSafeBounds) {
  const auto latency = resolve(stream_policy::StreamOptimizationMode::latency);
  const auto quality = resolve(stream_policy::StreamOptimizationMode::quality);

  EXPECT_EQ(stream_policy::video_pacing_bitrate_bps(80'000, quality, 0), 100'000'000U);
  EXPECT_EQ(stream_policy::video_pacing_bitrate_bps(80'000, quality, 90'000'000), 90'000'000U);
  EXPECT_EQ(stream_policy::video_pacing_bitrate_bps(90'000, latency, 0), 100'000'000U);
  EXPECT_EQ(stream_policy::video_pacing_bitrate_bps(0, quality, 0), 64'000U);
  EXPECT_EQ(
    stream_policy::video_pacing_bitrate_bps(std::numeric_limits<std::int64_t>::max(), quality, 0),
    1'000'000'000U
  );
}

TEST(StreamPolicyPacingTest, InterleavedSessionsNeverSharePacingOrDuplicateTimestampState) {
  const auto epoch = std::chrono::steady_clock::time_point {100s};
  auto latency = stream_policy::initialize_pacing(epoch);
  auto quality = stream_policy::initialize_pacing(epoch + 1ms);
  auto legacy = stream_policy::initialize_pacing(epoch + 2ms);

  const auto latency_start = stream_policy::begin_paced_frame(latency, epoch + 3ms);
  stream_policy::complete_paced_frame(latency, latency_start, 400us);

  const auto quality_start = stream_policy::begin_paced_frame(quality, epoch + 2ms);
  stream_policy::complete_paced_frame(quality, quality_start, 2ms);

  const auto legacy_start = stream_policy::begin_paced_frame(legacy, epoch + 10ms);
  stream_policy::complete_paced_frame(legacy, legacy_start, 1ms);

  EXPECT_EQ(stream_policy::duplicate_frame_timestamp(latency), epoch + 3400us);
  EXPECT_EQ(stream_policy::duplicate_frame_timestamp(quality), epoch + 4ms);
  EXPECT_EQ(stream_policy::duplicate_frame_timestamp(legacy), epoch + 11ms);
  EXPECT_EQ(stream_policy::begin_paced_frame(latency, epoch + 3500us), epoch + 3500us);
  EXPECT_EQ(stream_policy::begin_paced_frame(quality, epoch + 3500us), epoch + 4ms);
}

TEST(StreamPolicyBindingTest, ActualNvencBindingSeamRestoresOnNestedAndExceptionalExit) {
  const auto latency = resolve(stream_policy::StreamOptimizationMode::latency);
  const auto quality = resolve(stream_policy::StreamOptimizationMode::quality);
  auto configured = nvenc::nvenc_config {};
  configured.quality_preset = 6;

  EXPECT_EQ(stream_policy::current_thread_nvenc_config(configured).quality_preset, 6);
  {
    const stream_policy::ScopedPolicyBinding latency_binding {latency};
    EXPECT_EQ(stream_policy::current_thread_nvenc_config(configured).quality_preset, 1);
    {
      const stream_policy::ScopedPolicyBinding quality_binding {quality};
      EXPECT_EQ(stream_policy::current_thread_nvenc_config(configured).quality_preset, 5);
    }
    EXPECT_EQ(stream_policy::current_thread_nvenc_config(configured).quality_preset, 1);
  }
  EXPECT_EQ(stream_policy::current_thread_nvenc_config(configured).quality_preset, 6);

  EXPECT_THROW(
    {
      const stream_policy::ScopedPolicyBinding binding {quality};
      throw std::runtime_error {"scope exit"};
    },
    std::runtime_error
  );
  EXPECT_EQ(stream_policy::current_thread_nvenc_config(configured).quality_preset, 6);
}

TEST(StreamPolicyBindingTest, ConcurrentSessionsCannotObserveEachOthersNvencBinding) {
  const auto latency = resolve(stream_policy::StreamOptimizationMode::latency);
  const auto quality = resolve(stream_policy::StreamOptimizationMode::quality);
  std::atomic_int ready {};
  std::atomic_bool release {};
  std::atomic_bool correct {true};

  auto run = [&](const stream_policy::EffectiveStreamPolicy &policy, const int expected) {
    const stream_policy::ScopedPolicyBinding binding {policy};
    ready.fetch_add(1, std::memory_order_release);
    while (!release.load(std::memory_order_acquire)) {
      std::this_thread::yield();
    }
    if (stream_policy::current_thread_nvenc_config(nvenc::nvenc_config {}).quality_preset != expected) {
      correct.store(false, std::memory_order_release);
    }
  };

  std::thread latency_thread {run, std::cref(latency), 1};
  std::thread quality_thread {run, std::cref(quality), 5};
  while (ready.load(std::memory_order_acquire) != 2) {
    std::this_thread::yield();
  }
  EXPECT_EQ(stream_policy::current_thread_policy(), nullptr);
  release.store(true, std::memory_order_release);
  latency_thread.join();
  quality_thread.join();
  EXPECT_TRUE(correct.load(std::memory_order_acquire));
}
