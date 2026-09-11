/**
 * @file src/protocol_lsp/runtime/identity.h
 * @brief Fresh LSP-only host identity generation and atomic persistence.
 */

#pragma once

#include "../types.h"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <span>
#include <vector>

namespace lumen::lsp::runtime {
  /** @brief Raw Ed25519 private-key size used by the application identity. */
  inline constexpr std::size_t ed25519_private_key_size = 32;

  /**
   * @brief Complete fresh LSP host identity, independent of legacy credentials.
   */
  struct HostIdentity {
    HostIdentity() noexcept = default;
    HostIdentity(const HostIdentity &) = delete;
    HostIdentity &operator=(const HostIdentity &) = delete;
    HostIdentity(HostIdentity &&other) noexcept;
    HostIdentity &operator=(HostIdentity &&other) noexcept;
    ~HostIdentity();

    Identifier128 host_id {};  ///< Stable random LSP host identifier.
    PublicKey256 application_public_key {};  ///< Ed25519 application identity public key.
    std::array<std::uint8_t, ed25519_private_key_size> application_private_key {};  ///< Ed25519 application identity private key.
    Secret256 cookie_secret {};  ///< DTLS 1.3 stateless-cookie secret.
    std::vector<std::uint8_t> certificate_der;  ///< Self-signed wolfSSL DTLS certificate in canonical DER.
    std::vector<std::uint8_t> private_key_der;  ///< Matching wolfSSL DTLS private key in canonical DER.

    /**
     * @brief Validate fixed fields and bounded DER storage.
     *
     * @return True only for a complete nonzero identity.
     */
    [[nodiscard]] bool valid() const noexcept;
  };

  /**
   * @brief Typed identity generation, parsing, or persistence failure.
   */
  enum class IdentityError : std::uint8_t {
    provider_unavailable,  ///< wolfSSL key/certificate generation is not compiled in.
    random_failed,  ///< The wolfCrypt random generator failed.
    key_generation_failed,  ///< Ed25519 key generation or export failed.
    certificate_generation_failed,  ///< The self-signed DTLS certificate could not be created.
    invalid_identity,  ///< An in-memory identity is incomplete or oversized.
    malformed_storage,  ///< Persisted bytes fail the exact versioned format.
    io_failed,  ///< A filesystem read, write, flush, permission, or rename failed.
  };

  /**
   * @brief Serialize one identity using the private version-1 binary container.
   *
   * @param identity Valid LSP-only identity.
   * @return Exact bytes or a typed error.
   */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, IdentityError> encode_identity(
    const HostIdentity &identity
  );

  /**
   * @brief Parse one exact version-1 identity container.
   *
   * @param bytes Complete file bytes.
   * @return Validated identity or a typed error.
   */
  [[nodiscard]] std::expected<HostIdentity, IdentityError> decode_identity(
    std::span<const std::uint8_t> bytes
  );

  /**
   * @brief Generate a fresh host ID, application key, DTLS key/certificate, and cookie secret.
   *
   * @return Fresh identity or an exact provider/crypto failure.
   */
  [[nodiscard]] std::expected<HostIdentity, IdentityError> generate_identity() noexcept;

  /** @brief Generate fresh DTLS credentials while retaining the stable application identity. */
  [[nodiscard]] std::expected<HostIdentity, IdentityError> generate_rotated_identity(
    const HostIdentity &current
  ) noexcept;

  /** @brief Atomically replace one persisted identity with a validated complete candidate. */
  [[nodiscard]] std::expected<void, IdentityError> persist_identity_atomic(
    const std::filesystem::path &path,
    const HostIdentity &identity
  ) noexcept;

  /**
   * @brief Load the existing LSP identity or generate and atomically persist it.
   *
   * This function never reads or reuses the legacy GameStream certificate,
   * private key, pairing registry, or client identities.
   *
   * @param path Exact `credentials/lsp_identity_v1.bin` destination.
   * @return Loaded or newly committed identity.
   */
  [[nodiscard]] std::expected<HostIdentity, IdentityError> load_or_create_identity(
    const std::filesystem::path &path
  ) noexcept;
}  // namespace lumen::lsp::runtime
