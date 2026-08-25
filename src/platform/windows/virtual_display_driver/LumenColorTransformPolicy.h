/**
 * @file src/platform/windows/virtual_display_driver/LumenColorTransformPolicy.h
 * @brief Portable validation for immutable ABI v5 gamma and color transforms.
 */
#ifndef LUMEN_PLATFORM_WINDOWS_COLOR_TRANSFORM_POLICY_H
#define LUMEN_PLATFORM_WINDOWS_COLOR_TRANSFORM_POLICY_H

#include "LumenVirtualDisplayProtocol.h"

#include <cmath>
#include <cstdint>
#include <limits>

namespace lumen::vdd::color {
  /** Return whether a runtime output structure covers the negotiated and required known prefix. */
  [[nodiscard]] constexpr bool valid_compatible_prefix(
    const std::uint32_t reported_size,
    const std::uint32_t negotiated_size,
    const std::uint32_t compile_size,
    const std::uint32_t required_end
  ) noexcept {
    return negotiated_size != std::numeric_limits<std::uint32_t>::max() &&
           compile_size >= negotiated_size && compile_size >= required_end &&
           reported_size >= negotiated_size && reported_size >= required_end;
  }

  /** Return whether a normalized ABI BOOL is exactly false or true. */
  [[nodiscard]] constexpr bool valid_bool(const std::uint32_t value) noexcept {
    return value == 0 || value == 1;
  }

  /** Return whether a transform type has its one exact ABI payload size. */
  [[nodiscard]] constexpr bool valid_payload_header(
    const std::uint32_t type,
    const std::uint32_t payload_size
  ) noexcept {
    switch (type) {
      case LUMEN_VDD_GAMMA_RAMP_TYPE_DEFAULT:
        return payload_size == 0;
      case LUMEN_VDD_GAMMA_RAMP_TYPE_RGB256X3X16:
        return payload_size == sizeof(LUMEN_VDD_GAMMA_RAMP_RGB256X3X16);
      case LUMEN_VDD_GAMMA_RAMP_TYPE_3X4_COLORSPACE_TRANSFORM:
        return payload_size == sizeof(LUMEN_VDD_GAMMA_RAMP_3X4_COLORSPACE_TRANSFORM);
      default:
        return false;
    }
  }

  /** Return whether every enabled flag and floating-point value has an exact valid representation. */
  [[nodiscard]] inline bool valid_transform(
    const LUMEN_VDD_GAMMA_RAMP_3X4_COLORSPACE_TRANSFORM &transform
  ) noexcept {
    if (!valid_bool(transform.matrix_enabled) || !valid_bool(transform.lut_enabled)) {
      return false;
    }
    if (transform.matrix_enabled != 0) {
      if (!std::isfinite(transform.scalar_multiplier)) {
        return false;
      }
      for (const auto &row : transform.color_matrix_3x4) {
        for (const auto value : row) {
          if (!std::isfinite(value)) {
            return false;
          }
        }
      }
    }
    if (transform.lut_enabled != 0) {
      for (const auto &entry : transform.lookup_table_1d) {
        if (!std::isfinite(entry.red) || !std::isfinite(entry.green) || !std::isfinite(entry.blue)) {
          return false;
        }
      }
    }
    return true;
  }

  /** Clear ignored disabled sections without interpreting unspecified OS bytes. */
  inline void clear_disabled_sections(
    LUMEN_VDD_GAMMA_RAMP_3X4_COLORSPACE_TRANSFORM &transform
  ) noexcept {
    if (transform.matrix_enabled == 0) {
      for (auto &row : transform.color_matrix_3x4) {
        for (auto &value : row) {
          value = 0.0F;
        }
      }
      transform.scalar_multiplier = 0.0F;
    }
    if (transform.lut_enabled == 0) {
      for (auto &entry : transform.lookup_table_1d) {
        entry = {};
      }
    }
  }

  /** Return DEFAULT when a 3x4 payload has no enabled matrix or LUT work. */
  [[nodiscard]] constexpr std::uint32_t effective_type(
    const std::uint32_t type,
    const LUMEN_VDD_GAMMA_RAMP_3X4_COLORSPACE_TRANSFORM &transform
  ) noexcept {
    return type == LUMEN_VDD_GAMMA_RAMP_TYPE_3X4_COLORSPACE_TRANSFORM &&
               transform.matrix_enabled == 0 && transform.lut_enabled == 0 ?
             LUMEN_VDD_GAMMA_RAMP_TYPE_DEFAULT :
             type;
  }
}  // namespace lumen::vdd::color

#endif  // LUMEN_PLATFORM_WINDOWS_COLOR_TRANSFORM_POLICY_H
