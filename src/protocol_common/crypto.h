/**
 * @file src/protocol_common/crypto.h
 * @brief OpenSSL-backed protocol cryptographic primitives.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace lumen::protocol_common::crypto {
  inline constexpr std::size_t sha256_bytes = 32;  ///< SHA-256 digest length.
  inline constexpr std::size_t ed25519_public_key_bytes = 32;  ///< Ed25519 raw public-key length.
  inline constexpr std::size_t ed25519_private_seed_bytes = 32;  ///< Ed25519 raw private seed length.
  inline constexpr std::size_t ed25519_signature_bytes = 64;  ///< Ed25519 signature length.

  using Digest = std::array<std::uint8_t, sha256_bytes>;  ///< SHA-256 digest.
  using PublicKey = std::array<std::uint8_t, ed25519_public_key_bytes>;  ///< Ed25519 public key.
  using Signature = std::array<std::uint8_t, ed25519_signature_bytes>;  ///< Ed25519 signature.

  /**
   * @brief Compute SHA-256 through OpenSSL EVP.
   *
   * @param input Bytes to hash.
   * @return Digest or nullopt on OpenSSL failure.
   */
  std::optional<Digest> sha256(std::span<const std::uint8_t> input) noexcept;

  /**
   * @brief Derive an Ed25519 public key from a raw private seed.
   *
   * @param private_seed Raw 32-byte Ed25519 seed.
   * @return Raw public key or nullopt on failure.
   */
  std::optional<PublicKey> ed25519_public_key(std::span<const std::uint8_t> private_seed) noexcept;

  /**
   * @brief Sign a complete message using Ed25519.
   *
   * @param private_seed Raw 32-byte Ed25519 seed.
   * @param message Message bytes.
   * @return Signature or nullopt on failure.
   */
  std::optional<Signature> ed25519_sign(
    std::span<const std::uint8_t> private_seed,
    std::span<const std::uint8_t> message
  ) noexcept;

  /**
   * @brief Verify an Ed25519 signature.
   *
   * @param public_key Raw 32-byte public key.
   * @param message Message bytes.
   * @param signature Raw 64-byte signature.
   * @return True only for a valid signature.
   */
  bool ed25519_verify(
    std::span<const std::uint8_t> public_key,
    std::span<const std::uint8_t> message,
    std::span<const std::uint8_t> signature
  ) noexcept;

}  // namespace lumen::protocol_common::crypto
