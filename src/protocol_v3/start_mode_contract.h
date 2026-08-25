/**
 * @file src/protocol_v3/start_mode_contract.h
 * @brief Canonical pure protocol-v3 START mode-admission contract.
 */
#pragma once

#include <cstdint>
#include <limits>
#include <numeric>
#include <string_view>

namespace lumen::protocol_v3::start_mode {
  inline constexpr std::uint32_t minimum_width = 320;  ///< Smallest client-visible even width.
  inline constexpr std::uint32_t maximum_width = 7680;  ///< Largest client-visible even width.
  inline constexpr std::uint32_t minimum_height = 200;  ///< Smallest client-visible even height.
  inline constexpr std::uint32_t maximum_height = 4320;  ///< Largest client-visible even height.
  inline constexpr std::uint32_t minimum_refresh_hz = 10;  ///< Smallest exact refresh rate.
  inline constexpr std::uint32_t maximum_refresh_hz = 480;  ///< Largest exact refresh rate.
  inline constexpr std::uint32_t h264_maximum_dimension = 4096;  ///< NVENC H.264 per-axis limit.

  /** @brief Stable rejection class shared by control, runtime, and resource admission. */
  enum class AdmissionError {
    none,  ///< The complete tuple is admitted.
    dimensions,  ///< Dimensions are odd or outside the protocol bounds.
    refresh_component,  ///< A refresh component is zero or not representable as uint32.
    refresh_unreduced,  ///< The exact rational is not in canonical reduced form.
    refresh_range,  ///< The exact rational is below 10 Hz or above 480 Hz.
    codec,  ///< The codec identifier is outside H.264, HEVC, and AV1.
    color_mode,  ///< Chroma, bit depth, or SDR/HDR pairing is VDD-incompatible.
    h264_limit,  ///< H.264 exceeds its dimensions or requests HDR/10-bit.
    fidelity,  ///< Fidelity is invalid or codec-lossless lacks 4:4:4 host proof.
  };

  /**
   * @brief Return the language-neutral vector name for one admission result.
   * @param error Admission result.
   * @return Stable lowercase vector name.
   */
  [[nodiscard]] constexpr std::string_view name(const AdmissionError error) noexcept {
    switch (error) {
      case AdmissionError::none:
        return "none";
      case AdmissionError::dimensions:
        return "dimensions";
      case AdmissionError::refresh_component:
        return "refresh_component";
      case AdmissionError::refresh_unreduced:
        return "refresh_unreduced";
      case AdmissionError::refresh_range:
        return "refresh_range";
      case AdmissionError::codec:
        return "codec";
      case AdmissionError::color_mode:
        return "color_mode";
      case AdmissionError::h264_limit:
        return "h264_limit";
      case AdmissionError::fidelity:
        return "fidelity";
    }
    return "unknown";
  }

  /** @brief Language-neutral selected START tuple used by pure admission. */
  struct Mode {
    std::uint64_t width {};  ///< Active width in pixels.
    std::uint64_t height {};  ///< Active height in pixels.
    std::uint64_t refresh_numerator {};  ///< Exact refresh numerator.
    std::uint64_t refresh_denominator {};  ///< Exact refresh denominator.
    std::uint64_t codec {};  ///< 1 H.264, 2 HEVC, or 3 AV1.
    std::uint64_t bit_depth {};  ///< 8 or 10 bits per component.
    std::uint64_t chroma {};  ///< 1 4:2:0 or 2 4:4:4.
    std::uint64_t dynamic_range {};  ///< 1 SDR, 2 PQ, or 3 HLG.
    std::uint64_t codec_flags {};  ///< Bit one is exact host codec-lossless proof.
    std::uint64_t fidelity {};  ///< 1 lossy, 2 visually lossless, or 3 codec lossless.
  };

  /**
   * @brief Validate the exact structural dimensions and refresh rational.
   *
   * Comparisons multiply only a uint32 denominator by the small 10/480 bounds,
   * so the function never truncates through integer division or overflows.
   *
   * @param mode Candidate mode whose codec/color fields may be unset.
   * @return Stable structural admission result.
   */
  [[nodiscard]] constexpr AdmissionError admit_shape(const Mode &mode) noexcept {
    if (mode.width < minimum_width || mode.width > maximum_width ||
        mode.height < minimum_height || mode.height > maximum_height ||
        (mode.width & 1U) != 0 || (mode.height & 1U) != 0) {
      return AdmissionError::dimensions;
    }
    if (mode.refresh_numerator == 0 || mode.refresh_denominator == 0 ||
        mode.refresh_numerator > std::numeric_limits<std::uint32_t>::max() ||
        mode.refresh_denominator > std::numeric_limits<std::uint32_t>::max()) {
      return AdmissionError::refresh_component;
    }
    if (std::gcd(mode.refresh_numerator, mode.refresh_denominator) != 1) {
      return AdmissionError::refresh_unreduced;
    }
    if (mode.refresh_numerator < minimum_refresh_hz * mode.refresh_denominator ||
        mode.refresh_numerator > maximum_refresh_hz * mode.refresh_denominator) {
      return AdmissionError::refresh_range;
    }
    return AdmissionError::none;
  }

  /**
   * @brief Validate the complete canonical protocol/VDD/encoder tuple.
   * @param mode Candidate selected START tuple.
   * @return Stable tuple admission result.
   */
  [[nodiscard]] constexpr AdmissionError admit(const Mode &mode) noexcept {
    if (const auto shape = admit_shape(mode); shape != AdmissionError::none) {
      return shape;
    }
    if (mode.codec < 1 || mode.codec > 3) {
      return AdmissionError::codec;
    }
    const auto valid_color_mode =
      mode.chroma >= 1 && mode.chroma <= 2 &&
      ((mode.dynamic_range == 1 && mode.bit_depth == 8) ||
       ((mode.dynamic_range == 2 || mode.dynamic_range == 3) && mode.bit_depth == 10));
    if (!valid_color_mode) {
      return AdmissionError::color_mode;
    }
    if (mode.codec == 1 &&
        (mode.width > h264_maximum_dimension || mode.height > h264_maximum_dimension ||
         mode.dynamic_range != 1 || mode.bit_depth != 8)) {
      return AdmissionError::h264_limit;
    }
    if (mode.fidelity < 1 || mode.fidelity > 3 ||
        (mode.fidelity == 3 && (mode.chroma != 2 || (mode.codec_flags & 0x02U) == 0))) {
      return AdmissionError::fidelity;
    }
    return AdmissionError::none;
  }
}  // namespace lumen::protocol_v3::start_mode
