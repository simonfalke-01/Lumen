/**
 * @file src/nvenc/nvenc_hdr_metadata.h
 * @brief Validated HDR10 static metadata carried into SDK 13 NVENC structures.
 */
#pragma once

// standard includes
#include <array>
#include <cstdint>
#include <optional>

namespace nvenc {
  /** @brief Chromaticity coordinate normalized to 50,000. */
  struct hdr_chromaticity_t {
    std::uint16_t x {};
    std::uint16_t y {};

    bool operator==(const hdr_chromaticity_t &) const = default;
  };

  /** @brief Exact HDR10 mastering-display and content-light static metadata. */
  struct hdr_static_metadata_t {
    std::array<hdr_chromaticity_t, 3> display_primaries {};  ///< RGB order.
    hdr_chromaticity_t white_point {};
    std::uint16_t maximum_mastering_luminance {};  ///< Nits.
    std::uint16_t minimum_mastering_luminance {};  ///< 0.0001-nit units.
    std::uint16_t maximum_content_light_level {};  ///< MaxCLL in nits, or zero when unknown.
    std::uint16_t maximum_frame_average_light_level {};  ///< MaxFALL in nits, or zero when unknown.

    bool operator==(const hdr_static_metadata_t &) const = default;
  };

  /** @brief SDK 13 codec locations that support HDR10 static metadata. */
  enum class hdr_codec_e {
    hevc,
    av1,
  };

  /** @brief Transfer families relevant to NVENC static-metadata policy. */
  enum class hdr_transfer_e {
    sdr,
    hdr10_pq,
    hlg,
  };

  /** @brief Fail-closed decision made before opening an NVENC session. */
  struct hdr_metadata_policy_t {
    bool accepted {};  ///< Whether the codec/transfer/metadata tuple is valid.
    bool attach_static_metadata {};  ///< Whether SDK 13 mastering/CLL fields must be enabled.
  };

  /** Return whether one chromaticity coordinate is finite in normalized CIE space. */
  [[nodiscard]] constexpr bool valid_hdr_chromaticity(const hdr_chromaticity_t &point) noexcept {
    constexpr std::uint32_t normalized_one = 50'000U;
    return point.x != 0 && point.y != 0 && point.x <= normalized_one && point.y <= normalized_one;
  }

  /** Return whether a complete static block can be serialized without inventing values. */
  [[nodiscard]] constexpr bool valid_hdr_static_metadata(const hdr_static_metadata_t &metadata) noexcept {
    if (!valid_hdr_chromaticity(metadata.white_point) ||
        metadata.maximum_mastering_luminance == 0 ||
        static_cast<std::uint32_t>(metadata.minimum_mastering_luminance) >
          static_cast<std::uint32_t>(metadata.maximum_mastering_luminance) * 10'000U) {
      return false;
    }
    for (const auto &primary : metadata.display_primaries) {
      if (!valid_hdr_chromaticity(primary)) {
        return false;
      }
    }
    if (metadata.display_primaries[0] == metadata.display_primaries[1] ||
        metadata.display_primaries[0] == metadata.display_primaries[2] ||
        metadata.display_primaries[1] == metadata.display_primaries[2]) {
      return false;
    }
    return metadata.maximum_content_light_level == 0 ?
             metadata.maximum_frame_average_light_level == 0 :
             metadata.maximum_frame_average_light_level <= metadata.maximum_content_light_level;
  }

  /**
   * @brief Decide exact PQ, HLG, and SDR metadata behavior for one codec tuple.
   * @param video_format 0 H.264, 1 HEVC, or 2 AV1.
   * @param transfer SDR, HDR10 PQ, or HLG.
   * @param metadata Optional HDR10 mastering-display and content-light block.
   */
  [[nodiscard]] constexpr hdr_metadata_policy_t evaluate_hdr_metadata_policy(
    const int video_format,
    const hdr_transfer_e transfer,
    const std::optional<hdr_static_metadata_t> &metadata
  ) noexcept {
    if (video_format < 0 || video_format > 2) {
      return {};
    }
    if (transfer == hdr_transfer_e::sdr) {
      return {!metadata.has_value(), false};
    }
    if (video_format == 0) {
      return {};
    }
    if (transfer == hdr_transfer_e::hlg) {
      return {!metadata.has_value(), false};
    }
    return {metadata && valid_hdr_static_metadata(*metadata), true};
  }

  /**
   * @brief Serialize a validated block into the official SDK 13 payload structures.
   * @tparam Mastering SDK `MASTERING_DISPLAY_INFO` layout.
   * @tparam ContentLight SDK `CONTENT_LIGHT_LEVEL` layout.
   */
  template<typename Mastering, typename ContentLight>
  [[nodiscard]] constexpr bool serialize_hdr_static_metadata(
    const hdr_codec_e codec,
    const hdr_static_metadata_t &metadata,
    Mastering &mastering,
    ContentLight &content_light
  ) noexcept {
    mastering = {};
    content_light = {};
    if (!valid_hdr_static_metadata(metadata)) {
      return false;
    }

    const auto scale = [](const std::uint32_t value, const std::uint32_t numerator, const std::uint32_t denominator) {
      return static_cast<std::uint32_t>(
        (static_cast<std::uint64_t>(value) * numerator + denominator / 2U) / denominator
      );
    };
    const auto chromaticity = [&](const hdr_chromaticity_t &point) {
      if (codec == hdr_codec_e::hevc) {
        return std::array<std::uint16_t, 2> {point.x, point.y};
      }
      return std::array<std::uint16_t, 2> {
        static_cast<std::uint16_t>(scale(point.x, 1U << 16U, 50'000U)),
        static_cast<std::uint16_t>(scale(point.y, 1U << 16U, 50'000U)),
      };
    };
    const auto r = chromaticity(metadata.display_primaries[0]);
    const auto g = chromaticity(metadata.display_primaries[1]);
    const auto b = chromaticity(metadata.display_primaries[2]);
    const auto white = chromaticity(metadata.white_point);
    mastering.r = {r[0], r[1]};
    mastering.g = {g[0], g[1]};
    mastering.b = {b[0], b[1]};
    mastering.whitePoint = {white[0], white[1]};
    mastering.maxLuma = codec == hdr_codec_e::hevc ?
                           static_cast<std::uint32_t>(metadata.maximum_mastering_luminance) * 10'000U :
                           static_cast<std::uint32_t>(metadata.maximum_mastering_luminance) * (1U << 8U);
    mastering.minLuma = codec == hdr_codec_e::hevc ?
                           metadata.minimum_mastering_luminance :
                           scale(metadata.minimum_mastering_luminance, 1U << 14U, 10'000U);
    content_light.maxContentLightLevel = metadata.maximum_content_light_level;
    content_light.maxPicAverageLightLevel = metadata.maximum_frame_average_light_level;
    return true;
  }

  /** Enable the official SDK 13 output flags for the selected codec configuration. */
  template<typename EncoderConfig>
  constexpr void enable_hdr_static_metadata_output(
    const hdr_codec_e codec,
    EncoderConfig &config
  ) noexcept {
    if (codec == hdr_codec_e::hevc) {
      config.encodeCodecConfig.hevcConfig.outputMasteringDisplay = 1;
      config.encodeCodecConfig.hevcConfig.outputMaxCll = 1;
    } else {
      config.encodeCodecConfig.av1Config.outputMasteringDisplay = 1;
      config.encodeCodecConfig.av1Config.outputMaxCll = 1;
    }
  }

  /** Attach official SDK 13 per-picture pointers after validated serialization. */
  template<typename PictureParams, typename Mastering, typename ContentLight>
  [[nodiscard]] constexpr bool attach_hdr_static_metadata(
    const hdr_codec_e codec,
    const hdr_static_metadata_t &metadata,
    Mastering &mastering,
    ContentLight &content_light,
    PictureParams &picture
  ) noexcept {
    if (!serialize_hdr_static_metadata(codec, metadata, mastering, content_light)) {
      return false;
    }
    if (codec == hdr_codec_e::hevc) {
      picture.codecPicParams.hevcPicParams.pMasteringDisplay = &mastering;
      picture.codecPicParams.hevcPicParams.pMaxCll = &content_light;
    } else {
      picture.codecPicParams.av1PicParams.pMasteringDisplay = &mastering;
      picture.codecPicParams.av1PicParams.pMaxCll = &content_light;
    }
    return true;
  }
}  // namespace nvenc
