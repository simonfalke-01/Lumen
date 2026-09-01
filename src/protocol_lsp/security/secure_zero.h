/**
 * @file src/protocol_lsp/security/secure_zero.h
 * @brief Shared non-optimizable byte clearing for LSP secret owners.
 */

#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace lumen::lsp {
  /**
   * @brief Clear mutable bytes with compiler barriers and volatile stores.
   *
   * @param bytes Secret bytes to clear.
   */
  inline void secure_zero(const std::span<std::uint8_t> bytes) noexcept {
    std::atomic_signal_fence(std::memory_order_seq_cst);
    volatile std::uint8_t *cursor = bytes.data();
    for (std::size_t index = 0; index < bytes.size(); ++index) {
      cursor[index] = 0;
    }
    std::atomic_signal_fence(std::memory_order_seq_cst);
  }

  /**
   * @brief Clear mutable character bytes such as a transient ASCII PIN.
   *
   * @param bytes Secret characters to clear.
   */
  inline void secure_zero(const std::span<char> bytes) noexcept {
    secure_zero({reinterpret_cast<std::uint8_t *>(bytes.data()), bytes.size()});
  }

  /**
   * @brief Clear the active bytes in one dynamic secret buffer.
   *
   * @param bytes Secret buffer to clear and logically empty.
   */
  inline void secure_zero(std::vector<std::uint8_t> &bytes) noexcept {
    secure_zero(std::span<std::uint8_t> {bytes});
    bytes.clear();
  }

  /**
   * @brief Clear one fixed byte array.
   *
   * @tparam Size Array size.
   * @param bytes Secret bytes to clear.
   */
  template<std::size_t Size>
  inline void secure_zero(std::array<std::uint8_t, Size> &bytes) noexcept {
    secure_zero(std::span<std::uint8_t> {bytes});
  }

  /**
   * @brief Clear one fixed character array.
   *
   * @tparam Size Array size.
   * @param bytes Secret characters to clear.
   */
  template<std::size_t Size>
  inline void secure_zero(std::array<char, Size> &bytes) noexcept {
    secure_zero(std::span<char> {bytes});
  }
}  // namespace lumen::lsp
