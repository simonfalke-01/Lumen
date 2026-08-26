/**
 * @file src/platform/windows/virtual_display_driver/LumenModeValidationPolicy.h
 * @brief Portable overflow-safe validation for the fixed virtual-display mode ABI.
 */
#ifndef LUMEN_PLATFORM_WINDOWS_MODE_VALIDATION_POLICY_H
#define LUMEN_PLATFORM_WINDOWS_MODE_VALIDATION_POLICY_H

#include "../../../protocol_v3/start_mode_contract.h"
#include "LumenVirtualDisplayProtocol.h"

#include <cstdint>
#include <numeric>

namespace lumen::vdd::mode {
  /** Return whether one mode is structurally valid without overflow-prone pixel-rate products. */
  [[nodiscard]] constexpr bool valid(const LUMEN_VDD_MODE &mode) noexcept {
    const bool valid_color_mode =
      (mode.dynamic_range == LUMEN_VDD_DYNAMIC_RANGE_SDR && mode.bits_per_channel == 8) ||
      (mode.dynamic_range == LUMEN_VDD_DYNAMIC_RANGE_HDR10 && mode.bits_per_channel == 10);
    const auto shape = lumen::protocol_v3::start_mode::admit_shape({
      mode.width,
      mode.height,
      mode.refresh_numerator,
      mode.refresh_denominator,
    });
    if (shape != lumen::protocol_v3::start_mode::AdmissionError::none || !valid_color_mode ||
        (mode.delivery_policy != LUMEN_VDD_POLICY_LATENCY && mode.delivery_policy != LUMEN_VDD_POLICY_QUALITY) ||
        mode.minimum_fidelity != LUMEN_VDD_FIDELITY_LOSSLESS) {
      return false;
    }
    const auto pixels = static_cast<std::uint64_t>(mode.width) * mode.height;
    return pixels <= static_cast<std::uint64_t>(LUMEN_VDD_MAX_WIDTH) * LUMEN_VDD_MAX_HEIGHT;
  }
}  // namespace lumen::vdd::mode

#endif  // LUMEN_PLATFORM_WINDOWS_MODE_VALIDATION_POLICY_H
