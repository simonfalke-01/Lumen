/**
 * @file tests/unit/test_nvenc_hdr_metadata.cpp
 * @brief SDK 13 production-structure tests for NVENC HDR10 static metadata.
 */
// local includes
#include "src/nvenc/nvenc_hdr_metadata.h"

#ifdef _WIN32
  #define NVENC_NAMESPACE nvenc_sdk13_test
  #define NVENC_SDK_VERSION 1300
  #include "src/nvenc/nvenc_sdk.h"
  #undef NVENC_SDK_VERSION
  #undef NVENC_NAMESPACE
#endif

// lib includes
#include <gtest/gtest.h>

namespace {
  constexpr nvenc::hdr_static_metadata_t hdr10_metadata() {
    return {
      {{{35'400, 14'600}, {8'500, 39'850}, {6'550, 2'300}}},
      {15'635, 16'450},
      1'000,
      50,
      1'000,
      400,
    };
  }
}  // namespace

TEST(NvencHdrStaticMetadataTest, RejectsMalformedMasteringAndContentLightBlocks) {
  const auto valid = hdr10_metadata();
  EXPECT_TRUE(nvenc::valid_hdr_static_metadata(valid));
  auto independently_rounded = valid;
  independently_rounded.display_primaries[0].y = 14'601;
  EXPECT_TRUE(nvenc::valid_hdr_static_metadata(independently_rounded));

  const auto expect_invalid = [&](auto mutate) {
    auto malformed = valid;
    mutate(malformed);
    EXPECT_FALSE(nvenc::valid_hdr_static_metadata(malformed));
  };
  expect_invalid([](auto &metadata) {
    metadata.display_primaries[0].x = 0;
  });
  expect_invalid([](auto &metadata) {
    metadata.display_primaries[1] = metadata.display_primaries[0];
  });
  expect_invalid([](auto &metadata) {
    metadata.white_point = {50'001, 1};
  });
  expect_invalid([](auto &metadata) {
    metadata.maximum_mastering_luminance = 0;
  });
  expect_invalid([](auto &metadata) {
    metadata.maximum_mastering_luminance = 1;
    metadata.minimum_mastering_luminance = 10'001;
  });
  expect_invalid([](auto &metadata) {
    metadata.maximum_content_light_level = 0;
    metadata.maximum_frame_average_light_level = 1;
  });
  expect_invalid([](auto &metadata) {
    metadata.maximum_frame_average_light_level = 1'001;
  });
}

TEST(NvencHdrStaticMetadataPolicyTest, PqRequiresHevcOrAv1AndValidStaticMetadata) {
  const std::optional<nvenc::hdr_static_metadata_t> metadata {hdr10_metadata()};
  const auto hevc = nvenc::evaluate_hdr_metadata_policy(1, nvenc::hdr_transfer_e::hdr10_pq, metadata);
  const auto av1 = nvenc::evaluate_hdr_metadata_policy(2, nvenc::hdr_transfer_e::hdr10_pq, metadata);
  EXPECT_TRUE(hevc.accepted);
  EXPECT_TRUE(hevc.attach_static_metadata);
  EXPECT_TRUE(av1.accepted);
  EXPECT_TRUE(av1.attach_static_metadata);
  EXPECT_FALSE(nvenc::evaluate_hdr_metadata_policy(0, nvenc::hdr_transfer_e::hdr10_pq, metadata).accepted);
  EXPECT_FALSE(nvenc::evaluate_hdr_metadata_policy(1, nvenc::hdr_transfer_e::hdr10_pq, std::nullopt).accepted);

  auto malformed = *metadata;
  malformed.maximum_mastering_luminance = 0;
  EXPECT_FALSE(nvenc::evaluate_hdr_metadata_policy(2, nvenc::hdr_transfer_e::hdr10_pq, malformed).accepted);
}

TEST(NvencHdrStaticMetadataPolicyTest, HlgAllowsHevcAndAv1OnlyWithoutHdr10StaticMetadata) {
  const auto hevc = nvenc::evaluate_hdr_metadata_policy(1, nvenc::hdr_transfer_e::hlg, std::nullopt);
  const auto av1 = nvenc::evaluate_hdr_metadata_policy(2, nvenc::hdr_transfer_e::hlg, std::nullopt);
  EXPECT_TRUE(hevc.accepted);
  EXPECT_FALSE(hevc.attach_static_metadata);
  EXPECT_TRUE(av1.accepted);
  EXPECT_FALSE(av1.attach_static_metadata);
  EXPECT_FALSE(nvenc::evaluate_hdr_metadata_policy(0, nvenc::hdr_transfer_e::hlg, std::nullopt).accepted);
  EXPECT_FALSE(nvenc::evaluate_hdr_metadata_policy(1, nvenc::hdr_transfer_e::hlg, hdr10_metadata()).accepted);
}

TEST(NvencHdrStaticMetadataPolicyTest, SdrRejectsHdr10StaticMetadataWithoutChangingCodecSupport) {
  for (int video_format = 0; video_format <= 2; ++video_format) {
    const auto sdr = nvenc::evaluate_hdr_metadata_policy(video_format, nvenc::hdr_transfer_e::sdr, std::nullopt);
    EXPECT_TRUE(sdr.accepted);
    EXPECT_FALSE(sdr.attach_static_metadata);
    EXPECT_FALSE(nvenc::evaluate_hdr_metadata_policy(
      video_format,
      nvenc::hdr_transfer_e::sdr,
      hdr10_metadata()
    ).accepted);
  }
  EXPECT_FALSE(nvenc::evaluate_hdr_metadata_policy(3, nvenc::hdr_transfer_e::sdr, std::nullopt).accepted);
}

#ifdef _WIN32
TEST(NvencHdrStaticMetadataTest, SerializesOfficialSdk13MasteringAndContentLightStructures) {
  nvenc_sdk13_test::MASTERING_DISPLAY_INFO mastering {};
  nvenc_sdk13_test::CONTENT_LIGHT_LEVEL content_light {};
  ASSERT_TRUE(nvenc::serialize_hdr_static_metadata(
    nvenc::hdr_codec_e::hevc,
    hdr10_metadata(),
    mastering,
    content_light
  ));

  EXPECT_EQ(mastering.r.x, 35'400);
  EXPECT_EQ(mastering.r.y, 14'600);
  EXPECT_EQ(mastering.g.x, 8'500);
  EXPECT_EQ(mastering.g.y, 39'850);
  EXPECT_EQ(mastering.b.x, 6'550);
  EXPECT_EQ(mastering.b.y, 2'300);
  EXPECT_EQ(mastering.whitePoint.x, 15'635);
  EXPECT_EQ(mastering.whitePoint.y, 16'450);
  EXPECT_EQ(mastering.maxLuma, 10'000'000U);
  EXPECT_EQ(mastering.minLuma, 50U);
  EXPECT_EQ(content_light.maxContentLightLevel, 1'000U);
  EXPECT_EQ(content_light.maxPicAverageLightLevel, 400U);

  ASSERT_TRUE(nvenc::serialize_hdr_static_metadata(
    nvenc::hdr_codec_e::av1,
    hdr10_metadata(),
    mastering,
    content_light
  ));
  EXPECT_EQ(mastering.r.x, 46'399);
  EXPECT_EQ(mastering.r.y, 19'137);
  EXPECT_EQ(mastering.g.x, 11'141);
  EXPECT_EQ(mastering.g.y, 52'232);
  EXPECT_EQ(mastering.b.x, 8'585);
  EXPECT_EQ(mastering.b.y, 3'015);
  EXPECT_EQ(mastering.whitePoint.x, 20'493);
  EXPECT_EQ(mastering.whitePoint.y, 21'561);
  EXPECT_EQ(mastering.maxLuma, 256'000U);
  EXPECT_EQ(mastering.minLuma, 82U);
}

TEST(NvencHdrStaticMetadataTest, EnablesAndAttachesOfficialHevcAndAv1Fields) {
  nvenc_sdk13_test::NV_ENC_CONFIG hevc_config {};
  nvenc::enable_hdr_static_metadata_output(nvenc::hdr_codec_e::hevc, hevc_config);
  EXPECT_EQ(hevc_config.encodeCodecConfig.hevcConfig.outputMasteringDisplay, 1U);
  EXPECT_EQ(hevc_config.encodeCodecConfig.hevcConfig.outputMaxCll, 1U);

  nvenc_sdk13_test::NV_ENC_CONFIG av1_config {};
  nvenc::enable_hdr_static_metadata_output(nvenc::hdr_codec_e::av1, av1_config);
  EXPECT_EQ(av1_config.encodeCodecConfig.av1Config.outputMasteringDisplay, 1U);
  EXPECT_EQ(av1_config.encodeCodecConfig.av1Config.outputMaxCll, 1U);

  nvenc_sdk13_test::MASTERING_DISPLAY_INFO mastering {};
  nvenc_sdk13_test::CONTENT_LIGHT_LEVEL content_light {};
  nvenc_sdk13_test::NV_ENC_PIC_PARAMS hevc_picture {};
  ASSERT_TRUE(nvenc::attach_hdr_static_metadata(
    nvenc::hdr_codec_e::hevc,
    hdr10_metadata(),
    mastering,
    content_light,
    hevc_picture
  ));
  EXPECT_EQ(hevc_picture.codecPicParams.hevcPicParams.pMasteringDisplay, &mastering);
  EXPECT_EQ(hevc_picture.codecPicParams.hevcPicParams.pMaxCll, &content_light);

  nvenc_sdk13_test::NV_ENC_PIC_PARAMS av1_picture {};
  ASSERT_TRUE(nvenc::attach_hdr_static_metadata(
    nvenc::hdr_codec_e::av1,
    hdr10_metadata(),
    mastering,
    content_light,
    av1_picture
  ));
  EXPECT_EQ(av1_picture.codecPicParams.av1PicParams.pMasteringDisplay, &mastering);
  EXPECT_EQ(av1_picture.codecPicParams.av1PicParams.pMaxCll, &content_light);
}

#endif
