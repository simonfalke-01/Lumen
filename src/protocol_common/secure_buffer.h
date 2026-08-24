/**
 * @file src/protocol_common/secure_buffer.h
 * @brief Move-only zeroizing secret-byte containers for protocol code.
 */

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <openssl/crypto.h>
#include <span>

namespace lumen::protocol_common {
  /**
   * @brief Move-only fixed-size secret storage cleansed at destruction.
   *
   * @tparam Size Secret size in bytes.
   */
  template<std::size_t Size>
  class SecureArray {
  public:
    SecureArray() = default;

    /**
     * @brief Copy bytes into newly owned secret storage.
     *
     * @param source Exact-size source bytes.
     */
    explicit SecureArray(const std::span<const std::uint8_t, Size> source) {
      std::copy(source.begin(), source.end(), bytes_.begin());
    }

    SecureArray(const SecureArray &) = delete;
    SecureArray &operator=(const SecureArray &) = delete;

    /**
     * @brief Transfer ownership and cleanse the moved-from storage.
     *
     * @param other Source secret.
     */
    SecureArray(SecureArray &&other) noexcept:
        bytes_ {other.bytes_} {
      other.cleanse();
    }

    /**
     * @brief Replace this secret and cleanse both prior/moved-from storage.
     *
     * @param other Source secret.
     * @return This object.
     */
    SecureArray &operator=(SecureArray &&other) noexcept {
      if (this != &other) {
        cleanse();
        bytes_ = other.bytes_;
        other.cleanse();
      }
      return *this;
    }

    ~SecureArray() {
      cleanse();
    }

    /**
     * @brief Access the secret for a bounded cryptographic operation.
     *
     * @return Mutable exact-size span.
     */
    std::span<std::uint8_t, Size> bytes() noexcept {
      return bytes_;
    }

    /**
     * @brief Access the secret for a bounded cryptographic operation.
     *
     * @return Constant exact-size span.
     */
    std::span<const std::uint8_t, Size> bytes() const noexcept {
      return bytes_;
    }

  private:
    void cleanse() noexcept {
      OPENSSL_cleanse(bytes_.data(), bytes_.size());
    }

    std::array<std::uint8_t, Size> bytes_ {};
  };

}  // namespace lumen::protocol_common
