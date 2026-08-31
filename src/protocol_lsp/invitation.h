/**
 * @file src/protocol_lsp/invitation.h
 * @brief Exact LSP/1 pairing invitation URI model and codec.
 */

#pragma once

#include "types.h"

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

namespace lumen::lsp {
  inline constexpr std::string_view invitation_uri_prefix = "umbra://pair/lsp1#";  ///< Exact LSP/1 invitation URI prefix.

  /**
   * @brief Deterministic ten-field LSP pairing invitation.
   */
  struct PairingInvitation {
    std::uint8_t version {wire_version};  ///< Wire version; exactly one in this codec.
    Identifier128 host_id {};  ///< Stable host identifier.
    PublicKey256 host_identity_key {};  ///< Host Ed25519 public key.
    Digest256 dtls_spki_sha256 {};  ///< SHA-256 digest of the DTLS leaf certificate SPKI.
    std::uint16_t port {};  ///< Nonzero LSP UDP port.
    std::string host;  ///< Hostname or IP literal.
    Identifier128 invitation_id {};  ///< Random single-use invitation identifier.
    Secret256 invitation_secret {};  ///< Random single-use invitation secret.
    std::uint64_t expires_at_utc_seconds {};  ///< Expiration in whole UTC seconds.
    PermissionSet offered_permissions {};  ///< Valid offered permission mask.

    /**
     * @brief Validate every invitation field required by LSP/1.
     *
     * @return True only for an exact, encodable LSP/1 invitation.
     */
    [[nodiscard]] bool valid() const noexcept;

    /**
     * @brief Test expiration against a caller-supplied UTC clock.
     *
     * @param now_utc_seconds Current whole UTC seconds.
     * @return True when the invitation is expired at the supplied time.
     */
    [[nodiscard]] bool expired(std::uint64_t now_utc_seconds) const noexcept;

    bool operator==(const PairingInvitation &) const = default;
  };

  /**
   * @brief Pairing invitation codec failure.
   */
  enum class InvitationError : std::uint8_t {
    invalid_model,  ///< An in-memory field violates LSP/1 constraints.
    invalid_uri,  ///< URI prefix, length, or fragment placement is invalid.
    invalid_base64url,  ///< Fragment is not canonical unpadded base64url.
    invalid_cbor,  ///< Fragment is not strict deterministic CBOR.
    invalid_shape,  ///< CBOR is not the exact ten-key invitation map.
    version_mismatch,  ///< Invitation wire version is not one.
    invalid_field,  ///< A typed invitation field has an invalid value or size.
    unknown_permissions,  ///< Offered mask contains a bit unknown to LSP/1.
  };

  /**
   * @brief Encode an invitation as its exact fragment-only LSP/1 URI.
   *
   * @param invitation Valid invitation model.
   * @return URI or a typed validation/encoding error.
   */
  [[nodiscard]] std::expected<std::string, InvitationError> encode_invitation_uri(
    const PairingInvitation &invitation
  );

  /**
   * @brief Parse an exact LSP/1 invitation URI.
   *
   * Unknown keys, alternate types, padding, noncanonical base64url tails, and
   * non-deterministic CBOR are rejected.
   *
   * @param uri Complete invitation URI.
   * @return Validated invitation or a typed error.
   */
  [[nodiscard]] std::expected<PairingInvitation, InvitationError> decode_invitation_uri(std::string_view uri);
}  // namespace lumen::lsp
