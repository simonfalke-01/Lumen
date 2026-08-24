/**
 * @file src/platform/windows/virtual_display_driver/LumenEdidModePolicy.h
 * @brief Portable EDID timing-descriptor policy helpers.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace lumen::vdd::edid {
  /**
   * @brief Count base-block detailed timing descriptors by nonzero pixel clock.
   * @param bytes Exact 128-byte EDID base block.
   * @return Number of timing descriptors in the four descriptor slots.
   */
  constexpr std::size_t detailed_timing_count(const std::array<std::uint8_t, 128> &bytes) noexcept {
    std::size_t count = 0;
    for (std::size_t offset = 54; offset <= 108; offset += 18) {
      if (bytes[offset] != 0 || bytes[offset + 1] != 0) {
        ++count;
      }
    }
    return count;
  }
}  // namespace lumen::vdd::edid
