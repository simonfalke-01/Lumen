/**
 * @file src/platform/windows/virtual_display_driver/LumenModeValidationPolicy.h
 * @brief Portable overflow-safe validation for the fixed virtual-display mode ABI.
 */
#ifndef LUMEN_PLATFORM_WINDOWS_MODE_VALIDATION_POLICY_H
#define LUMEN_PLATFORM_WINDOWS_MODE_VALIDATION_POLICY_H

#include "../../../protocol_common/start_mode_limits.h"
#include "LumenVirtualDisplayProtocol.h"

#include <cstdint>
#include <numeric>

namespace lumen::vdd::mode {
  /**
   * @brief Validate an even, reduced display shape within the shared VDD bounds.
   *
   * @param width Active width in pixels.
   * @param height Active height in pixels.
   * @param refresh_numerator Exact refresh numerator.
   * @param refresh_denominator Exact refresh denominator.
   * @return True when every structural mode field is valid.
   */
  [[nodiscard]] constexpr bool valid_shape(
    const std::uint32_t width,
    const std::uint32_t height,
    const std::uint32_t refresh_numerator,
    const std::uint32_t refresh_denominator
  ) noexcept {
    return width >= LUMEN_START_MODE_MIN_WIDTH && width <= LUMEN_START_MODE_MAX_WIDTH &&
           height >= LUMEN_START_MODE_MIN_HEIGHT && height <= LUMEN_START_MODE_MAX_HEIGHT &&
           (width & 1U) == 0 && (height & 1U) == 0 &&
           refresh_numerator != 0 && refresh_denominator != 0 &&
           std::gcd(refresh_numerator, refresh_denominator) == 1 &&
           static_cast<std::uint64_t>(refresh_numerator) >=
             static_cast<std::uint64_t>(LUMEN_START_MODE_MIN_REFRESH_HZ) * refresh_denominator &&
           static_cast<std::uint64_t>(refresh_numerator) <=
             static_cast<std::uint64_t>(LUMEN_START_MODE_MAX_REFRESH_HZ) * refresh_denominator;
  }

  /** Return whether one mode is structurally valid without overflow-prone pixel-rate products. */
  [[nodiscard]] constexpr bool valid(const LUMEN_VDD_MODE &mode) noexcept {
    const bool valid_color_mode =
      (mode.dynamic_range == LUMEN_VDD_DYNAMIC_RANGE_SDR && mode.bits_per_channel == 8) ||
      (mode.dynamic_range == LUMEN_VDD_DYNAMIC_RANGE_HDR10 && mode.bits_per_channel == 10);
    if (!valid_shape(mode.width, mode.height, mode.refresh_numerator, mode.refresh_denominator) || !valid_color_mode ||
        (mode.delivery_policy != LUMEN_VDD_POLICY_LATENCY && mode.delivery_policy != LUMEN_VDD_POLICY_QUALITY) ||
        mode.minimum_fidelity != LUMEN_VDD_FIDELITY_LOSSLESS) {
      return false;
    }
    const auto pixels = static_cast<std::uint64_t>(mode.width) * mode.height;
    return pixels <= static_cast<std::uint64_t>(LUMEN_VDD_MAX_WIDTH) * LUMEN_VDD_MAX_HEIGHT;
  }
}  // namespace lumen::vdd::mode

#endif  // LUMEN_PLATFORM_WINDOWS_MODE_VALIDATION_POLICY_H
