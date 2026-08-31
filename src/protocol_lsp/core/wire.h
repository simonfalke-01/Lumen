/**
 * @file src/protocol_lsp/core/wire.h
 * @brief Dependency-free network-byte-order helpers for portable LSP wire code.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

namespace lumen::lsp::wire {
  /**
   * @brief Read an unsigned integer in network byte order.
   *
   * The caller must first prove that `sizeof(Integer)` bytes are available.
   *
   * @tparam Integer Unsigned integer type.
   * @param bytes Input bytes beginning at the encoded integer.
   * @return Decoded integer.
   */
  template<class Integer>
    requires(std::is_integral_v<Integer> && std::is_unsigned_v<Integer>)
  [[nodiscard]] constexpr Integer read_be(const std::span<const std::uint8_t> bytes) noexcept {
    Integer value = 0;
    for (std::size_t index = 0; index < sizeof(Integer); ++index) {
      value = static_cast<Integer>((value << 8U) | bytes[index]);
    }
    return value;
  }

  /**
   * @brief Write an unsigned integer in network byte order.
   *
   * The caller must first prove that `sizeof(Integer)` bytes are available.
   *
   * @tparam Integer Unsigned integer type.
   * @param bytes Output bytes beginning at the encoded integer.
   * @param value Integer to encode.
   */
  template<class Integer>
    requires(std::is_integral_v<Integer> && std::is_unsigned_v<Integer>)
  constexpr void write_be(const std::span<std::uint8_t> bytes, Integer value) noexcept {
    for (std::size_t index = 0; index < sizeof(Integer); ++index) {
      bytes[sizeof(Integer) - index - 1U] = static_cast<std::uint8_t>(value);
      value = static_cast<Integer>(value >> 8U);
    }
  }
}  // namespace lumen::lsp::wire
