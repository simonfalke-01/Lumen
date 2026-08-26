/**
 * @file src/platform/windows/virtual_display_driver/LumenModeTimingPolicy.h
 * @brief Portable exact-rational signal timing for one immutable VDD mode.
 */
#ifndef LUMEN_PLATFORM_WINDOWS_MODE_TIMING_POLICY_H
#define LUMEN_PLATFORM_WINDOWS_MODE_TIMING_POLICY_H

#include "LumenHdrModePolicy.h"

#include <cstdint>

namespace lumen::vdd::timing {
  /** @brief Platform-neutral signal facts mapped to DisplayConfig by the driver. */
  struct signal_t {
    std::uint32_t active_width {};  ///< Active horizontal pixels.
    std::uint32_t active_height {};  ///< Active vertical pixels.
    std::uint32_t total_width {};  ///< Total horizontal pixels.
    std::uint32_t total_height {};  ///< Total vertical pixels.
    std::uint32_t refresh_numerator {};  ///< Exact vertical refresh numerator.
    std::uint32_t refresh_denominator {};  ///< Exact vertical refresh denominator.
    std::uint32_t horizontal_numerator {};  ///< Rounded scan lines per second.
    std::uint32_t horizontal_denominator {1};  ///< Horizontal frequency denominator.
    std::uint64_t pixel_rate {};  ///< Rounded active pixel rate.
    std::uint32_t video_standard {255};  ///< CTA standard code, or 255 for dynamic modes.
    std::uint32_t vertical_sync_divider {};  ///< IddCx monitor/target divider convention.
  };

  /**
   * @brief Derive deterministic signal facts while retaining the exact requested refresh rational.
   * @param mode Immutable generation mode.
   * @param monitor_mode True for monitor modes, false for target modes.
   * @return Exact portable signal description.
   */
  [[nodiscard]] constexpr signal_t make(
    const LUMEN_VDD_MODE &mode,
    const bool monitor_mode
  ) noexcept {
    if (mode.dynamic_range == LUMEN_VDD_DYNAMIC_RANGE_HDR10 &&
        lumen::vdd::hdr::modes_equal(mode, lumen::vdd::hdr::baseline_mode)) {
      return {
        mode.width,
        mode.height,
        2200,
        1125,
        60,
        1,
        67500,
        1,
        148500000,
        16,
        monitor_mode ? 0U : 1U,
      };
    }
    const auto horizontal =
      (static_cast<std::uint64_t>(mode.refresh_numerator) * mode.height + mode.refresh_denominator / 2U) /
      mode.refresh_denominator;
    const auto pixel_rate =
      (static_cast<std::uint64_t>(mode.width) * mode.height * mode.refresh_numerator + mode.refresh_denominator / 2U) /
      mode.refresh_denominator;
    return {
      mode.width,
      mode.height,
      mode.width,
      mode.height,
      mode.refresh_numerator,
      mode.refresh_denominator,
      static_cast<std::uint32_t>(horizontal),
      1,
      pixel_rate,
      255,
      monitor_mode ? 0U : 1U,
    };
  }
}  // namespace lumen::vdd::timing

#endif  // LUMEN_PLATFORM_WINDOWS_MODE_TIMING_POLICY_H
