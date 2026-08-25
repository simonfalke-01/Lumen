/**
 * @file src/protocol_common/input_state.h
 * @brief Strict protocol-v3 state-format-2/3 structural validation.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace lumen::protocol_common::input_state {
  /** @brief Supported protocol-v3 input state wire formats. */
  enum class Format : std::uint16_t {
    two = 2,
    three = 3,
  };

  /**
   * @brief State-format validation error.
   */
  enum class Error {
    too_short,
    wrong_size,
    invalid_flags,
    pointer_mode_mismatch,
    invalid_controller,
    invalid_touch,
    invalid_pen,
    reserved_not_zero,
    format_mismatch,
  };

  /** @brief Exact common state header size for formats two and three. */
  inline constexpr std::size_t header_bytes = 112;

  /**
   * @brief Infer the state format from the exact byte-87 marker.
   *
   * Format two retains the original zero reserved byte. Format three uses the
   * explicit value three while bytes 88...111 remain reserved zero.
   *
   * @param bytes Complete or partial state block.
   * @return Declared format, or no value for a short/unknown marker.
   */
  std::optional<Format> format(std::span<const std::uint8_t> bytes) noexcept;

  /**
   * @brief Return the exact controller-record stride for one supported format.
   *
   * @param format Supported state format.
   * @return 64 bytes for format two or 56 bytes for format three.
   */
  std::size_t controller_record_bytes(Format format) noexcept;

  /**
   * @brief Strictly validate one complete state block using its marker.
   *
   * @param bytes Complete state block.
   * @param expected_absolute Optional negotiated pointer mode.
   * @return Success or exact structural error.
   */
  std::optional<Error> validate(
    std::span<const std::uint8_t> bytes,
    std::optional<bool> expected_absolute = std::nullopt
  ) noexcept;

  /**
   * @brief Strictly validate one complete state block against a wire format.
   *
   * @param bytes Complete state block.
   * @param expected_format Format declared by the enclosing input payload.
   * @param expected_absolute Optional negotiated pointer mode.
   * @return Success or exact structural/format mismatch error.
   */
  std::optional<Error> validate(
    std::span<const std::uint8_t> bytes,
    Format expected_format,
    std::optional<bool> expected_absolute = std::nullopt
  ) noexcept;
}  // namespace lumen::protocol_common::input_state
