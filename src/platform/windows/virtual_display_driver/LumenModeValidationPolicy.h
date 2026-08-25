/**
 * @file src/platform/windows/virtual_display_driver/LumenModeValidationPolicy.h
 * @brief Portable overflow-safe validation for the fixed virtual-display mode ABI.
 */
#ifndef LUMEN_PLATFORM_WINDOWS_MODE_VALIDATION_POLICY_H
#define LUMEN_PLATFORM_WINDOWS_MODE_VALIDATION_POLICY_H

#include "LumenVirtualDisplayProtocol.h"

#include <cstdint>
#include <numeric>

namespace lumen::vdd::mode {
  /** Return whether one mode is structurally valid without overflow-prone pixel-rate products. */
  [[nodiscard]] constexpr bool valid(const LUMEN_VDD_MODE &mode) noexcept {
    const bool valid_color_mode =
      (mode.dynamic_range == LUMEN_VDD_DYNAMIC_RANGE_SDR && mode.bits_per_channel == 8) ||
      (mode.dynamic_range == LUMEN_VDD_DYNAMIC_RANGE_HDR10 && mode.bits_per_channel == 10);
    if (mode.width < 256 || mode.width > LUMEN_VDD_MAX_WIDTH ||
        mode.height < 200 || mode.height > LUMEN_VDD_MAX_HEIGHT ||
        (mode.width & 1U) != 0 || (mode.height & 1U) != 0 ||
        mode.refresh_numerator == 0 || mode.refresh_denominator == 0 ||
        mode.refresh_numerator > LUMEN_VDD_MAX_RATIONAL_COMPONENT ||
        mode.refresh_denominator > LUMEN_VDD_MAX_RATIONAL_COMPONENT ||
        std::gcd(mode.refresh_numerator, mode.refresh_denominator) != 1 || !valid_color_mode ||
        (mode.delivery_policy != LUMEN_VDD_POLICY_LATENCY && mode.delivery_policy != LUMEN_VDD_POLICY_QUALITY) ||
        mode.minimum_fidelity != LUMEN_VDD_FIDELITY_LOSSLESS) {
      return false;
    }
    const auto refresh = static_cast<std::uint64_t>(mode.refresh_numerator);
    const auto denominator = static_cast<std::uint64_t>(mode.refresh_denominator);
    const auto pixels = static_cast<std::uint64_t>(mode.width) * mode.height;
    return refresh >= 10ULL * denominator && refresh <= 480ULL * denominator &&
           pixels <= static_cast<std::uint64_t>(LUMEN_VDD_MAX_WIDTH) * LUMEN_VDD_MAX_HEIGHT;
  }
}  // namespace lumen::vdd::mode

#endif  // LUMEN_PLATFORM_WINDOWS_MODE_VALIDATION_POLICY_H
