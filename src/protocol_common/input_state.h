/**
 * @file src/protocol_common/input_state.h
 * @brief Strict protocol-v3 state-format-2 structural validation.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <span>

namespace lumen::protocol_common::input_state {
  /**
   * @brief State-format-2 validation error.
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
  };

  /**
   * @brief Strictly validate one complete state-format-2 block.
   *
   * @param bytes Complete state block.
   * @param expected_absolute Optional negotiated pointer mode.
   * @return Success or exact structural error.
   */
  std::optional<Error> validate(
    std::span<const std::uint8_t> bytes,
    std::optional<bool> expected_absolute = std::nullopt
  ) noexcept;
}  // namespace lumen::protocol_common::input_state
