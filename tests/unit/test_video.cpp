/**
 * @file tests/unit/test_video.cpp
 * @brief Test src/video.*.
 */
// test includes
#include "../tests_common.h"

// standard includes
#include <algorithm>
#include <array>
#include <limits>
#include <optional>
#include <tuple>
#include <utility>
#include <vector>

// ffmpeg includes
extern "C" {
#include <libavutil/frame.h>
#include <libavutil/pixfmt.h>
}

// local includes
#include <src/config.h>
#include <src/stream_policy.h>
#include <src/video.h>
#include <src/video_colorspace.h>

using namespace std::literals;

namespace {
  video::encoder_probe_device_identity_t device_identity(std::uint64_t adapter_luid = 2) {
    return {
      adapter_luid,
      0x10DE,
      0x2882,
      0,
      1,
      0x0000000100000002,
      "\\\\.\\DISPLAY1",
    };
  }

  video::encoder_probe_identity_t probe_identity() {
    return {
      "NVIDIA GeForce RTX 4060",
      "{configured-display-id}",
      "\\\\.\\DISPLAY1",
      "ddx",
      "nvenc",
      3,
      2,
      false,
      true,
      device_identity(),
    };
  }
}  // namespace

TEST(VideoColorspaceTest, MapsProtocolV3H273TransfersExactly) {
  video::config_t config {};
  config.protocolV3Colorimetry = true;
  config.dynamicRange = 1;
  config.colorMatrix = 9;

  config.colorTransfer = 16;
  EXPECT_EQ(video::colorspace_from_client_config(config, true).colorspace, video::colorspace_e::bt2020);

  config.colorTransfer = 18;
  EXPECT_EQ(video::colorspace_from_client_config(config, true).colorspace, video::colorspace_e::bt2020hlg);

  config.colorTransfer = 1;
  EXPECT_EQ(video::colorspace_from_client_config(config, false).colorspace, video::colorspace_e::bt2020sdr);
}

TEST(VideoCaptureRecoveryTest, RequiredDirectSourceLossTerminatesInsteadOfReinitializing) {
  video::config_t ordinary {};
  EXPECT_EQ(
    video::capture_reinitialization_action(ordinary),
    video::capture_reinitialization_e::retry
  );
  EXPECT_EQ(video::display_initialization_attempts(ordinary), 2);

  auto direct_required = ordinary;
  direct_required.virtual_display_direct_required = true;
  EXPECT_EQ(
    video::capture_reinitialization_action(direct_required),
    video::capture_reinitialization_e::terminate
  );
  EXPECT_EQ(video::display_initialization_attempts(direct_required), 1);
}

TEST(VideoCodecInitializationTest, ExtractsOnlyH264ParameterSets) {
  const std::vector<std::uint8_t> access_unit {
    0, 0, 0, 1, 0x09, 0xf0,
    0, 0, 1, 0x67, 0x64, 0x00, 0x1f,
    0, 0, 1, 0x68, 0xee, 0x3c,
    0, 0, 1, 0x65, 0x88, 0x84,
  };
  EXPECT_EQ(
    video::extract_codec_initialization(access_unit, 0),
    (std::vector<std::uint8_t> {
      0, 0, 1, 0x67, 0x64, 0x00, 0x1f,
      0, 0, 1, 0x68, 0xee, 0x3c,
    })
  );
}

TEST(VideoCodecInitializationTest, ExtractsAllHEVCParameterSets) {
  const std::vector<std::uint8_t> access_unit {
    0, 0, 1, 0x40, 0x01, 0xaa,
    0, 0, 1, 0x42, 0x01, 0xbb,
    0, 0, 1, 0x44, 0x01, 0xcc,
    0, 0, 1, 0x26, 0x01, 0xdd,
  };
  EXPECT_EQ(
    video::extract_codec_initialization(access_unit, 1),
    (std::vector<std::uint8_t> {
      0, 0, 1, 0x40, 0x01, 0xaa,
      0, 0, 1, 0x42, 0x01, 0xbb,
      0, 0, 1, 0x44, 0x01, 0xcc,
    })
  );
}

TEST(VideoCodecInitializationTest, ExtractsTheAV1SequenceHeaderOBU) {
  const std::vector<std::uint8_t> access_unit {
    0x12, 0x01, 0,
    0x0a, 0x03, 0x20, 0x11, 0x22,
    0x32, 0x02, 0x33, 0x44,
  };
  EXPECT_EQ(
    video::extract_codec_initialization(access_unit, 2),
    (std::vector<std::uint8_t> {0x0a, 0x03, 0x20, 0x11, 0x22})
  );
}

TEST(VideoCodecInitializationTest, RejectsIncompleteOrMalformedInitialization) {
  const std::array<std::uint8_t, 5> incomplete_h264 {0, 0, 1, 0x67, 1};
  const std::array<std::uint8_t, 3> malformed_av1 {0x0a, 0x80, 0x80};
  EXPECT_TRUE(video::extract_codec_initialization(incomplete_h264, 0).empty());
  EXPECT_TRUE(video::extract_codec_initialization(malformed_av1, 2).empty());
  EXPECT_TRUE(video::extract_codec_initialization(std::span<const std::uint8_t> {}, 3).empty());
}

TEST(VideoCodecInitializationCacheTest, RepeatedExactTupleSkipsSecondPrewarm) {
  video::codec_initialization_cache_t cache;
  const video::codec_initialization_cache_key_t key {
    probe_identity(),
    "nvenc",
    "hevc_nvenc",
    "exact-quality-hevc-10bit-444-hdr-lossless",
  };
  const std::vector<std::uint8_t> expected {0, 0, 1, 0x40, 0, 0, 1, 0x42, 0, 0, 1, 0x44};
  int prewarm_encoder_constructions = 0;
  const auto initialization = [&]() -> std::optional<std::vector<std::uint8_t>> {
    if (auto cached = cache.lookup(key)) {
      return cached;
    }
    ++prewarm_encoder_constructions;
    if (!cache.commit(key, expected)) {
      return std::nullopt;
    }
    return expected;
  };

  EXPECT_EQ(initialization(), expected);
  EXPECT_EQ(initialization(), expected);
  EXPECT_EQ(prewarm_encoder_constructions, 1);
}

TEST(VideoCodecInitializationCacheTest, FailsClosedAndBindsEveryIdentityDimension) {
  video::codec_initialization_cache_t cache;
  const video::codec_initialization_cache_key_t key {
    probe_identity(),
    "nvenc",
    "hevc_nvenc",
    "exact-quality-hevc-10bit-444-hdr-lossless",
  };
  const std::vector<std::uint8_t> initialization {0, 0, 1, 0x40};

  EXPECT_FALSE(cache.commit(key, {}));
  EXPECT_FALSE(cache.lookup(key));
  ASSERT_TRUE(cache.commit(key, initialization));
  ASSERT_EQ(cache.lookup(key), initialization);

  const auto expect_miss = [&](auto mutate) {
    auto changed = key;
    mutate(changed);
    EXPECT_FALSE(cache.lookup(changed));
  };
  expect_miss([](auto &changed) {
    changed.probe_identity.device_identity->adapter_luid++;
  });
  expect_miss([](auto &changed) {
    changed.probe_identity.device_identity->driver_version++;
  });
  expect_miss([](auto &changed) {
    changed.probe_identity.device_identity->output_name = "\\\\.\\DISPLAY2";
  });
  expect_miss([](auto &changed) {
    changed.encoder_name = "software";
  });
  expect_miss([](auto &changed) {
    changed.codec_name = "av1_nvenc";
  });
  expect_miss([](auto &changed) {
    changed.configuration_fingerprint += ":latency";
  });
}

TEST(EncoderProbeCacheTest, ReusesOnlyMatchingCurrentIdentity) {
  const auto current = probe_identity();
  const std::optional<video::encoder_probe_identity_t> cached {current};

  EXPECT_TRUE(video::can_reuse_encoder_probe(true, false, false, current, cached));
  EXPECT_FALSE(video::can_reuse_encoder_probe(false, false, false, current, cached));
  EXPECT_FALSE(video::can_reuse_encoder_probe(true, true, false, current, cached));
  EXPECT_FALSE(video::can_reuse_encoder_probe(true, false, true, current, cached));
  EXPECT_FALSE(video::can_reuse_encoder_probe(true, false, false, current, std::nullopt));
}

TEST(EncoderProbeCacheTest, InvalidatesOnCaptureTargetOrPolicyChanges) {
  const auto cached_identity = probe_identity();
  const std::optional<video::encoder_probe_identity_t> cached {cached_identity};

  auto expect_invalid = [&](auto mutate) {
    auto current = cached_identity;
    mutate(current);
    EXPECT_FALSE(video::can_reuse_encoder_probe(true, false, false, current, cached));
  };

  expect_invalid([](auto &identity) {
    identity.adapter_name = "Microsoft Basic Render Driver";
  });
  expect_invalid([](auto &identity) {
    identity.raw_output_name = "{different-display-id}";
  });
  expect_invalid([](auto &identity) {
    identity.resolved_output_name = "\\\\.\\DISPLAY2";
  });
  expect_invalid([](auto &identity) {
    identity.capture = "wgc";
  });
  expect_invalid([](auto &identity) {
    identity.encoder = "software";
  });
  expect_invalid([](auto &identity) {
    identity.hevc_mode = 0;
  });
  expect_invalid([](auto &identity) {
    identity.av1_mode = 0;
  });
  expect_invalid([](auto &identity) {
    identity.force_video_header_replace = true;
  });
  expect_invalid([](auto &identity) {
    identity.device_identity = device_identity(1);
  });
  expect_invalid([](auto &identity) {
    identity.device_identity->driver_version += 1;
  });
  expect_invalid([](auto &identity) {
    identity.device_identity->output_name = "\\\\.\\DISPLAY2";
  });
}

TEST(EncoderProbeCacheTest, HybridGpuBindingUsesActuallyOpenedAdapter) {
  auto opened_on_discrete_gpu = probe_identity();
  opened_on_discrete_gpu.adapter_name.clear();
  opened_on_discrete_gpu.raw_output_name.clear();
  opened_on_discrete_gpu.resolved_output_name.clear();

  video::encoder_probe_cache_t cache;
  ASSERT_TRUE(cache.commit(opened_on_discrete_gpu));
  EXPECT_TRUE(cache.can_reuse(true, false, false, opened_on_discrete_gpu));

  auto independently_enumerated_integrated_gpu = opened_on_discrete_gpu;
  independently_enumerated_integrated_gpu.device_identity = device_identity(1);
  EXPECT_FALSE(cache.can_reuse(true, false, false, independently_enumerated_integrated_gpu));
}

TEST(EncoderProbeCacheTest, InactiveConfiguredDisplayIsNeverCacheable) {
  auto unresolved = probe_identity();
  unresolved.raw_output_name = "{inactive-display-id}";
  unresolved.resolved_output_name.clear();

  video::encoder_probe_cache_t cache;
  EXPECT_FALSE(video::encoder_probe_identity_is_cacheable(unresolved));
  EXPECT_FALSE(cache.commit(unresolved));
  EXPECT_FALSE(cache.can_reuse(true, false, false, unresolved));
}

TEST(EncoderProbeCacheTest, AutomaticSelectionReusesExactOpenedBinding) {
  auto automatic = probe_identity();
  automatic.adapter_name.clear();
  automatic.raw_output_name.clear();
  automatic.resolved_output_name.clear();

  video::encoder_probe_cache_t cache;
  ASSERT_TRUE(cache.commit(automatic));
  EXPECT_TRUE(cache.can_reuse(true, false, false, automatic));
}

TEST(EncoderProbeCacheTest, AutomaticIntentSurvivesConcreteStreamOpenAndInvalidatesEarlierNewTarget) {
  auto integrated = device_identity(1);
  integrated.output_name = "\\\\.\\DISPLAY1";
  auto discrete = device_identity(2);
  discrete.output_name = "\\\\.\\DISPLAY2";

  const video::encoder_probe_selection_intent_t automatic_intent {
    "",
    "",
    "",
    true,
    true,
  };

  video::encoder_probe_device_selection_t boot_selection;
  boot_selection.observe({integrated, true, true, false, false});
  boot_selection.observe({discrete, true, true, true, true});
  ASSERT_TRUE(boot_selection.selected());
  ASSERT_EQ(*boot_selection.selected(), discrete);

  const video::encoder_probe_opened_device_baseline_t boot_probe_baseline {
    *boot_selection.selected(),
    automatic_intent,
  };

  // The real capture path opens the concrete output by name. Recording that exact
  // binding must not turn the original automatic selection policy into an explicit one.
  const video::encoder_probe_opened_device_baseline_t real_stream_baseline {
    discrete,
    boot_probe_baseline.selection_intent,
  };
  ASSERT_TRUE(video::encoder_probe_selection_requires_replay(real_stream_baseline.selection_intent));

  auto cached = probe_identity();
  cached.adapter_name.clear();
  cached.raw_output_name.clear();
  cached.resolved_output_name.clear();
  cached.device_identity = real_stream_baseline.identity;
  video::encoder_probe_cache_t cache;
  ASSERT_TRUE(cache.commit(cached));

  video::encoder_probe_device_selection_t launch_selection;
  launch_selection.observe({integrated, true, true, true, true});
  launch_selection.observe({discrete, true, true, true, true});
  ASSERT_TRUE(launch_selection.selected());
  ASSERT_EQ(*launch_selection.selected(), integrated);

  auto current = cached;
  current.device_identity = *launch_selection.selected();
  EXPECT_FALSE(cache.can_reuse(true, false, false, current));
}

TEST(EncoderProbeCacheTest, ExplicitSelectionIgnoresUnmatchedEarlierOutput) {
  auto integrated = device_identity(1);
  auto discrete = device_identity(2);
  discrete.output_name = "\\\\.\\DISPLAY2";

  video::encoder_probe_device_selection_t selection;
  selection.observe({integrated, true, false, true, true});
  selection.observe({discrete, true, true, true, true});

  ASSERT_TRUE(selection.selected());
  EXPECT_EQ(*selection.selected(), discrete);

  const video::encoder_probe_selection_intent_t explicit_intent {
    "NVIDIA GeForce RTX 4060",
    "{configured-display-id}",
    "\\\\.\\DISPLAY2",
    false,
    false,
  };
  EXPECT_FALSE(video::encoder_probe_selection_requires_replay(explicit_intent));
}

TEST(EncoderProbeCacheTest, BootCommitAndLaunchGenerationLifecycle) {
  const auto identity = probe_identity();
  video::encoder_probe_cache_t cache;

  EXPECT_FALSE(cache.can_reuse(false, false, true, identity));
  ASSERT_TRUE(cache.commit(identity));
  EXPECT_TRUE(cache.can_reuse(true, false, false, identity));
  EXPECT_FALSE(cache.can_reuse(true, false, true, identity));

  cache.clear();
  EXPECT_FALSE(cache.can_reuse(true, false, false, identity));
}

TEST(EncoderProbeCacheTest, LosslessPublicationRequiresCompletedMatchingIdentityCommit) {
  EXPECT_TRUE(video::can_publish_nvenc_lossless_capabilities(true, false, true, true));
  EXPECT_FALSE(video::can_publish_nvenc_lossless_capabilities(false, false, true, true));
  EXPECT_FALSE(video::can_publish_nvenc_lossless_capabilities(true, true, true, true));
  EXPECT_FALSE(video::can_publish_nvenc_lossless_capabilities(true, false, false, true));
  EXPECT_FALSE(video::can_publish_nvenc_lossless_capabilities(true, false, true, false));

  stream_policy::reset_nvenc_lossless_capabilities();
  stream_policy::record_nvenc_lossless_capability(1, true);
  stream_policy::publish_nvenc_lossless_capabilities(
    video::can_publish_nvenc_lossless_capabilities(true, true, true, true)
  );
  EXPECT_FALSE(stream_policy::nvenc_lossless_capability(1));
  const auto topology_rejected = stream_policy::select_fidelity(
    stream_policy::StreamOptimizationMode::quality,
    stream_policy::StreamFidelityRequest::codec_lossless_required,
    {1, 10, true, true, stream_policy::nvenc_lossless_capability(1), true, true}
  );
  EXPECT_EQ(topology_rejected.selected, stream_policy::SelectedFidelityClass::rejected);
  EXPECT_EQ(
    topology_rejected.rejection,
    stream_policy::FidelityRejectionReason::encoder_lossless_unavailable
  );

  stream_policy::record_nvenc_lossless_capability(1, true);
  stream_policy::publish_nvenc_lossless_capabilities(
    video::can_publish_nvenc_lossless_capabilities(true, false, true, false)
  );
  EXPECT_FALSE(stream_policy::nvenc_lossless_capability(1));
}

TEST(EncoderProbeCacheTest, StableRequestAcceptsBindingDiscoveredDuringBootProbe) {
  auto before_probe = probe_identity();
  before_probe.device_identity.reset();
  const auto after_probe = probe_identity();

  EXPECT_TRUE(video::same_encoder_probe_request(before_probe, after_probe));
  EXPECT_FALSE(video::encoder_probe_identity_is_cacheable(before_probe));
  EXPECT_TRUE(video::encoder_probe_identity_is_cacheable(after_probe));
}

TEST(EncoderProbeCacheTest, RequiredDeviceObservationFailsClosedWhenUnavailable) {
  auto unavailable = probe_identity();
  unavailable.device_identity.reset();

  video::encoder_probe_cache_t cache;
  EXPECT_FALSE(cache.commit(unavailable));

  unavailable.device_identity_required = false;
  EXPECT_TRUE(cache.commit(unavailable));
}

TEST(DisplayReadyEventTest, ResetRaiseStopLifecycle) {
  safe::signal_t display_ready;

  EXPECT_FALSE(display_ready.view(1ms));
  display_ready.raise(true);
  ASSERT_TRUE(display_ready.view(1ms));

  display_ready.reset();
  EXPECT_FALSE(display_ready.view(1ms));
  display_ready.raise(true);
  ASSERT_TRUE(display_ready.view(1ms));

  display_ready.stop();
  EXPECT_FALSE(display_ready.view(1ms));
}

struct EncoderTest: PlatformTestSuite, testing::WithParamInterface<video::encoder_t *> {
  void SetUp() override {
    BaseTest::SetUp();
    auto &encoder = *GetParam();
    if (!video::validate_encoder(encoder, false)) {
      // Encoder failed validation,
      // if it's software - fail, otherwise skip
      if (encoder.name == "software") {
        FAIL() << "Software encoder not available";
      } else {
        GTEST_SKIP() << "Encoder not available";
      }
    }
  }
};

INSTANTIATE_TEST_SUITE_P(
  EncoderVariants,
  EncoderTest,
  testing::Values(
#if !defined(__APPLE__)
    &video::nvenc,
#endif
#ifdef _WIN32
    &video::amdvce,
    &video::quicksync,
#endif
#if defined(__linux__) || defined(__FreeBSD__)
    &video::vaapi,
#endif
#ifdef __APPLE__
    &video::videotoolbox,
#endif
    &video::software
  ),
  [](const auto &info) {
    return std::string(info.param->name);
  }
);

TEST_P(EncoderTest, ValidateEncoder) {
  // todo:: test something besides fixture setup
}

/**
 * @brief Parameterized coverage for effective H.264 profile selection.
 */
struct H264ProfileTest: testing::TestWithParam<std::tuple<std::string_view, video::amf::coder_e, int, int>> {};

TEST_P(H264ProfileTest, SelectProfile) {
  const auto &[encoder_name, coder, chroma_sampling_type, expected_profile] = GetParam();
  video::config_t config {};
  config.chromaSamplingType = chroma_sampling_type;

  EXPECT_EQ(expected_profile, video::select_h264_profile(encoder_name, config, std::to_underlying(coder)));
}

INSTANTIATE_TEST_SUITE_P(
  H264ProfileTests,
  H264ProfileTest,
  testing::Values(
    std::make_tuple("h264_amf"sv, video::amf::coder_e::auto_, 0, AV_PROFILE_H264_HIGH),
    std::make_tuple("h264_amf"sv, video::amf::coder_e::cabac, 0, AV_PROFILE_H264_HIGH),
    std::make_tuple("h264_amf"sv, video::amf::coder_e::cavlc, 0, AV_PROFILE_H264_CONSTRAINED_BASELINE),
    std::make_tuple("h264_amf"sv, video::amf::coder_e::cavlc, 1, AV_PROFILE_H264_HIGH_444_PREDICTIVE),
    std::make_tuple("h264_nvenc"sv, video::amf::coder_e::cavlc, 0, AV_PROFILE_H264_HIGH)
  )
);

#ifdef _WIN32
TEST(AmfH264OptionsTest, CoderUsesConfiguredValue) {
  const auto coder_option = std::ranges::find(video::amdvce.h264.common_options, "coder"sv, &video::encoder_t::option_t::name);

  ASSERT_NE(video::amdvce.h264.common_options.end(), coder_option);
  ASSERT_TRUE(std::holds_alternative<int *>(coder_option->value));
  EXPECT_EQ(&config::video.amd.amd_coder, std::get<int *>(coder_option->value));
}

/**
 * @brief Verify that the AMF maximum access-unit size is mapped only to supported codecs.
 */
struct AmfMaxAuSizeOptionsTest: testing::TestWithParam<std::tuple<const video::encoder_t::codec_t *, bool>> {};

TEST_P(AmfMaxAuSizeOptionsTest, UsesConfiguredValueForSupportedCodecsOnly) {
  const auto &[codec, supported] = GetParam();
  const auto option = std::ranges::find(codec->common_options, "max_au_size"sv, &video::encoder_t::option_t::name);

  if (!supported) {
    EXPECT_EQ(codec->common_options.end(), option);
    return;
  }

  ASSERT_NE(codec->common_options.end(), option);
  ASSERT_TRUE(std::holds_alternative<std::optional<int> *>(option->value));
  EXPECT_EQ(&config::video.amd.amd_max_au_size, std::get<std::optional<int> *>(option->value));
}

INSTANTIATE_TEST_SUITE_P(
  AmfCodecOptions,
  AmfMaxAuSizeOptionsTest,
  testing::Values(
    std::make_tuple(&video::amdvce.h264, true),
    std::make_tuple(&video::amdvce.hevc, true),
    std::make_tuple(&video::amdvce.av1, false)
  )
);
#endif

using AmfMaxAuSizeConfigParam = std::tuple<std::string_view, std::optional<int>>;

/**
 * @brief Verify parsing and validation of the AMF maximum access-unit size.
 */
struct AmfMaxAuSizeConfigTest: BaseTest, testing::WithParamInterface<AmfMaxAuSizeConfigParam> {
  void SetUp() override {
    BaseTest::SetUp();
    config::video.amd.amd_max_au_size.reset();
    config::stream.file_apps = SUNSHINE_SOURCE_DIR "/tests/unit/test_video.cpp";
  }

  void TearDown() override {
    config::video = original_video;
    config::audio = original_audio;
    config::stream = original_stream;
    config::nvhttp = original_nvhttp;
    config::input = original_input;
    config::sunshine = original_sunshine;
    config::modified_config_settings = original_modified_config_settings;
    BaseTest::TearDown();
  }

  config::video_t original_video {config::video};  ///< Video configuration restored after each test.
  config::audio_t original_audio {config::audio};  ///< Audio configuration restored after each test.
  config::stream_t original_stream {config::stream};  ///< Stream configuration restored after each test.
  config::nvhttp_t original_nvhttp {config::nvhttp};  ///< HTTP configuration restored after each test.
  config::input_t original_input {config::input};  ///< Input configuration restored after each test.
  config::sunshine_t original_sunshine {config::sunshine};  ///< Core configuration restored after each test.
  decltype(config::modified_config_settings) original_modified_config_settings {config::modified_config_settings};  ///< Modified settings restored after each test.
};

TEST_P(AmfMaxAuSizeConfigTest, AcceptsOnlyFfmpegSupportedRange) {
  const auto &[setting, expected] = GetParam();
  config::apply_config_for_test(setting);

  EXPECT_EQ(expected, config::video.amd.amd_max_au_size);
}

INSTANTIATE_TEST_SUITE_P(
  AmfMaxAuSizeValues,
  AmfMaxAuSizeConfigTest,
  testing::Values(
    AmfMaxAuSizeConfigParam {""sv, std::nullopt},
    AmfMaxAuSizeConfigParam {"amd_max_au_size = -2\n"sv, std::nullopt},
    AmfMaxAuSizeConfigParam {"amd_max_au_size = -1\n"sv, -1},
    AmfMaxAuSizeConfigParam {"amd_max_au_size = 0\n"sv, 0},
    AmfMaxAuSizeConfigParam {"amd_max_au_size = 800000\n"sv, 800000},
    AmfMaxAuSizeConfigParam {"amd_max_au_size = 2147483647\n"sv, std::numeric_limits<int>::max()}
  )
);

struct FramerateX100Test: BaseTest, testing::WithParamInterface<std::tuple<std::int32_t, AVRational>> {};

TEST_P(FramerateX100Test, Run) {
  const auto &[x100, expected] = GetParam();
  auto res = video::framerateX100_to_rational(x100);
  ASSERT_EQ(0, av_cmp_q(res, expected)) << "expected "
                                        << expected.num << "/" << expected.den
                                        << ", got "
                                        << res.num << "/" << res.den;
}

INSTANTIATE_TEST_SUITE_P(
  FramerateX100Tests,
  FramerateX100Test,
  testing::Values(
    std::make_tuple(2397, AVRational {24000, 1001}),
    std::make_tuple(2398, AVRational {24000, 1001}),
    std::make_tuple(2500, AVRational {25, 1}),
    std::make_tuple(2997, AVRational {30000, 1001}),
    std::make_tuple(3000, AVRational {30, 1}),
    std::make_tuple(5994, AVRational {60000, 1001}),
    std::make_tuple(6000, AVRational {60, 1}),
    std::make_tuple(11988, AVRational {120000, 1001}),
    std::make_tuple(23976, AVRational {240000, 1001}),  // future NTSC 240hz?
    std::make_tuple(9498, AVRational {4749, 50})  // from my LG 27GN950
  )
);

/**
 * @brief Verify software conversion of packed BGR0 and NV12 frames with varied strides.
 */
TEST(SoftwareEncoderConversion, Bgr0AndNv12) {
  constexpr int width = 320;
  constexpr int height = 240;

  AVFrame *frame = av_frame_alloc();
  ASSERT_NE(frame, nullptr);
  frame->width = width;
  frame->height = height;
  frame->format = AV_PIX_FMT_YUV420P;

  video::avcodec_software_encode_device_t device;
  ASSERT_EQ(device.init(width, height, frame, AV_PIX_FMT_YUV420P, false), 0);
  ASSERT_EQ(device.set_frame(frame, nullptr), 0);

  std::vector<uint8_t> bgr0_buffer(static_cast<size_t>(width) * height * 4);
  platf::img_t bgr0_img {};
  bgr0_img.data = bgr0_buffer.data();
  bgr0_img.width = width;
  bgr0_img.height = height;
  bgr0_img.row_pitch = width * 4;
  bgr0_img.pixel_pitch = 4;
  EXPECT_EQ(device.convert(bgr0_img), 0);

  std::vector<uint8_t> nv12_buffer(static_cast<size_t>(width) * height * 3 / 2);
  platf::img_t nv12_img {};
  nv12_img.data = nv12_buffer.data();
  nv12_img.width = width;
  nv12_img.height = height;
  nv12_img.row_pitch = width;
  nv12_img.pixel_pitch = 1;
  EXPECT_EQ(device.convert(nv12_img), 0);

  constexpr int padded_stride = width + 32;
  std::vector<uint8_t> padded_nv12_buffer(static_cast<size_t>(padded_stride) * height * 3 / 2);
  platf::img_t padded_nv12_img {};
  padded_nv12_img.data = padded_nv12_buffer.data();
  padded_nv12_img.width = width;
  padded_nv12_img.height = height;
  padded_nv12_img.row_pitch = padded_stride;
  padded_nv12_img.pixel_pitch = 1;
  EXPECT_EQ(device.convert(padded_nv12_img), 0);

  platf::img_t fallback_bgr0_img {};
  fallback_bgr0_img.data = bgr0_buffer.data();
  fallback_bgr0_img.width = width;
  fallback_bgr0_img.height = height;
  fallback_bgr0_img.row_pitch = width * 4;
  EXPECT_EQ(device.convert(fallback_bgr0_img), 0);

  platf::img_t fallback_nv12_img {};
  fallback_nv12_img.data = nv12_buffer.data();
  fallback_nv12_img.width = width;
  fallback_nv12_img.height = height;
  fallback_nv12_img.row_pitch = width;
  EXPECT_EQ(device.convert(fallback_nv12_img), 0);
}

struct FramerateToRationalTest: testing::TestWithParam<std::tuple<int, int, AVRational>> {};

TEST_P(FramerateToRationalTest, Run) {
  const auto &[framerate, framerateX100, expected] = GetParam();
  video::config_t config {};
  config.framerate = framerate;
  config.framerateX100 = framerateX100;
  auto res = video::framerate_to_rational(config);
  ASSERT_EQ(0, av_cmp_q(res, expected)) << "expected "
                                        << expected.num << "/" << expected.den
                                        << ", got "
                                        << res.num << "/" << res.den;
}

INSTANTIATE_TEST_SUITE_P(
  FramerateToRationalTests,
  FramerateToRationalTest,
  testing::Values(
    std::make_tuple(60, 0, AVRational {60, 1}),  // no X100 value, fall back to integer framerate
    std::make_tuple(60, 5994, AVRational {60000, 1001}),
    std::make_tuple(120, 11988, AVRational {120000, 1001}),
    std::make_tuple(24, 2398, AVRational {24000, 1001})
  )
);

struct CaptureFrameIntervalTest: testing::TestWithParam<std::tuple<int, int, std::chrono::nanoseconds>> {};

TEST_P(CaptureFrameIntervalTest, Run) {
  const auto &[framerate, framerateX100, expected] = GetParam();
  video::config_t config {};
  config.framerate = framerate;
  config.framerateX100 = framerateX100;
  ASSERT_EQ(expected, video::capture_frame_interval(config));
}

INSTANTIATE_TEST_SUITE_P(
  CaptureFrameIntervalTests,
  CaptureFrameIntervalTest,
  testing::Values(
    std::make_tuple(60, 0, std::chrono::nanoseconds {16666666}),
    std::make_tuple(60, 5994, std::chrono::nanoseconds {16683333}),  // 1e9 * 1001 / 60000
    std::make_tuple(120, 11988, std::chrono::nanoseconds {8341666})  // 1e9 * 1001 / 120000
  )
);
