/**
 * @file src/protocol_lsp/security/wolfssl_spake2.h
 * @brief Internal wolfSSL 5.9.2 RFC 9382 SPAKE2-P256 provider.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

namespace lumen::lsp {
  inline constexpr std::size_t spake2_point_size = 65;  ///< Uncompressed SEC1 P-256 point size.
  inline constexpr std::size_t spake2_confirmation_size = 32;  ///< Full HMAC-SHA-256 confirmation size.
  inline constexpr std::size_t spake2_shared_key_size = 16;  ///< RFC 9382 SHA-256 `Ke` size.
  inline constexpr std::size_t spake2_scalar_size = 32;  ///< Fixed-width P-256 scalar size.
  inline constexpr std::size_t spake2_pin_size = 6;  ///< Exact ASCII decimal PIN size.
  inline constexpr std::size_t spake2_minimum_salt_size = 16;  ///< Minimum application salt size.
  inline constexpr std::size_t spake2_maximum_salt_size = 64;  ///< Bounded application salt size.
  inline constexpr std::size_t spake2_maximum_identity_size = 255;  ///< Bounded identity size.
  inline constexpr std::size_t spake2_maximum_aad_size = 8'176;  ///< RFC 9382 AAD maximum in bytes.

  using Spake2Point = std::array<std::uint8_t, spake2_point_size>;  ///< Exact uncompressed SPAKE2 wire point.
  using Spake2Confirmation =
    std::array<std::uint8_t, spake2_confirmation_size>;  ///< Exact full-length confirmation MAC.
  using Spake2SharedKey = std::array<std::uint8_t, spake2_shared_key_size>;  ///< Confirmed RFC 9382 `Ke`.
  using Spake2Scalar = std::array<std::uint8_t, spake2_scalar_size>;  ///< Fixed-width big-endian P-256 scalar.

  /**
   * @brief Fail-closed SPAKE2 provider status.
   */
  enum class Spake2Status : std::uint8_t {
    success,  ///< Operation completed successfully.
    invalid_argument,  ///< A required pointer, identity, AAD, or output was invalid.
    invalid_pin,  ///< PIN was not exactly six ASCII decimal digits.
    invalid_salt,  ///< Scrypt salt was outside the supported bounded range.
    invalid_scalar,  ///< Scalar was zero or not less than the P-256 subgroup order.
    invalid_point,  ///< Peer or fixed point failed exact SEC1/group validation.
    invalid_state,  ///< Method was called outside its one-shot protocol state.
    unavailable,  ///< The pinned wolfSSL build lacks a required reviewed primitive.
    crypto_failure,  ///< A wolfCrypt primitive failed locally.
    confirmation_failed,  ///< Full peer confirmation MAC did not match in constant time.
  };

  /**
   * @brief Immutable common inputs copied by a client-A or host-B session.
   *
   * The caller supplies a pairing-specific salt that is already known when
   * the client creates `pA`. Final challenge data and the DTLS exporter belong
   * in the later AAD parameter so they can be fixed after BEGIN.
   */
  struct Spake2Inputs {
    std::string_view pin;  ///< Exactly six ASCII decimal digits; never retained after `create` returns.
    std::span<const std::uint8_t> salt;  ///< Pairing-specific scrypt salt, 16 through 64 bytes.
    std::span<const std::uint8_t> identity_a;  ///< Client-A identity encoded into TT.
    std::span<const std::uint8_t> identity_b;  ///< Host-B identity encoded into TT.
  };

#ifdef LSP_SPAKE2_TESTING
  /**
   * @brief Deterministic RFC 9382 vector-only inputs.
   *
   * Production code must use `Spake2Inputs`; this surface exists only in a
   * separately compiled focused test target.
   */
  struct Spake2TestInputs {
    Spake2Scalar w;  ///< Direct RFC vector password scalar.
    Spake2Scalar ephemeral_scalar;  ///< Direct RFC vector x or y scalar.
    std::span<const std::uint8_t> identity_a;  ///< Vector identity A.
    std::span<const std::uint8_t> identity_b;  ///< Vector identity B.
  };

  /**
   * @brief Derive the frozen PIN-to-w test vector through the production path.
   *
   * @param pin Exactly six ASCII digits.
   * @param salt Exact scrypt salt bytes.
   * @param scalar Reduced fixed-width w output.
   * @return Exact production derivation status.
   */
  [[nodiscard]] Spake2Status derive_spake2_password_scalar_for_test(
    std::string_view pin,
    std::span<const std::uint8_t> salt,
    Spake2Scalar &scalar
  ) noexcept;
#endif

  /**
   * @brief One-shot RFC 9382 party-A session used by the LSP client.
   *
   * Instances are synchronous, non-reentrant, and owned by one pairing state
   * machine. Secret state is cleared on every terminal result and destruction.
   */
  class WolfsslSpake2ClientSession final {
  public:
    /**
     * @brief Derive w with scrypt and create an unstarted client-A session.
     *
     * @param inputs PIN, salt, and transcript identities.
     * @param status Exact construction status.
     * @return Opaque session, or null on failure.
     */
    [[nodiscard]] static std::unique_ptr<WolfsslSpake2ClientSession> create(
      const Spake2Inputs &inputs,
      Spake2Status &status
    ) noexcept;

#ifdef LSP_SPAKE2_TESTING
    /**
     * @brief Create a deterministic RFC-vector client-A session.
     *
     * @param inputs Direct w/x scalars and identities.
     * @param status Exact construction status.
     * @return Opaque deterministic session, or null on failure.
     */
    [[nodiscard]] static std::unique_ptr<WolfsslSpake2ClientSession> create_for_test(
      const Spake2TestInputs &inputs,
      Spake2Status &status
    ) noexcept;
#endif

    WolfsslSpake2ClientSession(const WolfsslSpake2ClientSession &) = delete;
    WolfsslSpake2ClientSession &operator=(const WolfsslSpake2ClientSession &) = delete;
    WolfsslSpake2ClientSession(WolfsslSpake2ClientSession &&) = delete;
    WolfsslSpake2ClientSession &operator=(WolfsslSpake2ClientSession &&) = delete;

    /**
     * @brief Clear every retained scalar, key, transcript, and confirmation.
     */
    ~WolfsslSpake2ClientSession();

    /**
     * @brief Generate the one-use scalar x and client point pA.
     *
     * @param point_a Exact 65-byte uncompressed output.
     * @return Exact operation status.
     */
    Spake2Status start(Spake2Point &point_a) noexcept;

    /**
     * @brief Validate pB and derive client confirmation cA.
     *
     * @param point_b Exact 65-byte uncompressed host point.
     * @param aad Final challenge/DTLS-exporter binding used only by the confirmation-key HKDF.
     * @param confirmation_a Full HMAC-SHA-256 client confirmation.
     * @return Exact operation status.
     */
    Spake2Status receive_host_point(
      const Spake2Point &point_b,
      std::span<const std::uint8_t> aad,
      Spake2Confirmation &confirmation_a
    ) noexcept;

    /**
     * @brief Verify cB in constant time and release confirmed Ke.
     *
     * @param confirmation_b Exact full-length host confirmation.
     * @param shared_key Confirmed 16-byte RFC 9382 Ke output.
     * @return Success only after exact confirmation equality.
     */
    Spake2Status verify_host_confirmation(
      const Spake2Confirmation &confirmation_b,
      Spake2SharedKey &shared_key
    ) noexcept;

  private:
    class Impl;

    /**
     * @brief Adopt an initialized implementation.
     *
     * @param implementation Secret implementation owner.
     */
    explicit WolfsslSpake2ClientSession(std::unique_ptr<Impl> implementation) noexcept;

    std::unique_ptr<Impl> impl_;  ///< Secret client-A implementation.
  };

  /**
   * @brief One-shot RFC 9382 party-B session used by the LSP host.
   *
   * The host withholds cB and Ke until the client's full confirmation verifies.
   */
  class WolfsslSpake2HostSession final {
  public:
    /**
     * @brief Derive w with scrypt and create an unstarted host-B session.
     *
     * @param inputs PIN, salt, and transcript identities.
     * @param status Exact construction status.
     * @return Opaque session, or null on failure.
     */
    [[nodiscard]] static std::unique_ptr<WolfsslSpake2HostSession> create(
      const Spake2Inputs &inputs,
      Spake2Status &status
    ) noexcept;

#ifdef LSP_SPAKE2_TESTING
    /**
     * @brief Create a deterministic RFC-vector host-B session.
     *
     * @param inputs Direct w/y scalars and identities.
     * @param status Exact construction status.
     * @return Opaque deterministic session, or null on failure.
     */
    [[nodiscard]] static std::unique_ptr<WolfsslSpake2HostSession> create_for_test(
      const Spake2TestInputs &inputs,
      Spake2Status &status
    ) noexcept;
#endif

    WolfsslSpake2HostSession(const WolfsslSpake2HostSession &) = delete;
    WolfsslSpake2HostSession &operator=(const WolfsslSpake2HostSession &) = delete;
    WolfsslSpake2HostSession(WolfsslSpake2HostSession &&) = delete;
    WolfsslSpake2HostSession &operator=(WolfsslSpake2HostSession &&) = delete;

    /**
     * @brief Clear every retained scalar, key, transcript, and confirmation.
     */
    ~WolfsslSpake2HostSession();

    /**
     * @brief Validate pA, generate one-use y/pB, and derive confirmation keys.
     *
     * @param point_a Exact 65-byte uncompressed client point.
     * @param aad Final challenge/DTLS-exporter binding used only by the confirmation-key HKDF.
     * @param point_b Exact 65-byte uncompressed host output.
     * @return Exact operation status.
     */
    Spake2Status receive_client_point(
      const Spake2Point &point_a,
      std::span<const std::uint8_t> aad,
      Spake2Point &point_b
    ) noexcept;

    /**
     * @brief Verify cA, then release cB and confirmed Ke.
     *
     * @param confirmation_a Exact full-length client confirmation.
     * @param confirmation_b Full HMAC-SHA-256 host confirmation output.
     * @param shared_key Confirmed 16-byte RFC 9382 Ke output.
     * @return Success only after exact confirmation equality.
     */
    Spake2Status verify_client_confirmation(
      const Spake2Confirmation &confirmation_a,
      Spake2Confirmation &confirmation_b,
      Spake2SharedKey &shared_key
    ) noexcept;

  private:
    class Impl;

    /**
     * @brief Adopt an initialized implementation.
     *
     * @param implementation Secret implementation owner.
     */
    explicit WolfsslSpake2HostSession(std::unique_ptr<Impl> implementation) noexcept;

    std::unique_ptr<Impl> impl_;  ///< Secret host-B implementation.
  };
}  // namespace lumen::lsp
