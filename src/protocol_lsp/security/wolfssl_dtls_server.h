/**
 * @file src/protocol_lsp/security/wolfssl_dtls_server.h
 * @brief wolfSSL 5.9.2 DTLS 1.3 server provider for LSP.
 */

#pragma once

#include "../security_provider.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace lumen::lsp {
  inline constexpr std::size_t dtls_srtp_exporter_size = 56;  ///< RFC 5764 exporter size for AES-128-GCM.
  inline constexpr std::size_t srtp_aes_128_key_size = 16;  ///< AES-128 SRTP master-key size.
  inline constexpr std::size_t srtp_aead_salt_size = 12;  ///< RFC 7714 AEAD SRTP master-salt size.

  /**
   * @brief Directional RFC 5764 keying material exported by one DTLS association.
   *
   * The exporter order is client key, server key, client salt, then server
   * salt. Ownership is transferred only for the duration of the association
   * ready callback; the DTLS provider clears its temporary copy immediately.
   */
  struct DtlsSrtpKeyMaterial {
    std::array<std::uint8_t, srtp_aes_128_key_size> client_write_key {};  ///< Client-to-server SRTP master key.
    std::array<std::uint8_t, srtp_aes_128_key_size> server_write_key {};  ///< Server-to-client SRTP master key.
    std::array<std::uint8_t, srtp_aead_salt_size> client_write_salt {};  ///< Client-to-server SRTP master salt.
    std::array<std::uint8_t, srtp_aead_salt_size> server_write_salt {};  ///< Server-to-client SRTP master salt.
  };

  /**
   * @brief Authenticated security result for a completed LSP DTLS association.
   */
  struct DtlsAssociationSecurity {
    Digest256 server_spki_sha256 {};  ///< SHA-256 of the server certificate's complete DER SubjectPublicKeyInfo.
    DtlsSrtpKeyMaterial srtp {};  ///< Directional SRTP master keys and salts.
  };

  /**
   * @brief Result of a concrete wolfSSL provider lifecycle operation.
   */
  enum class WolfsslDtlsOperationResult : std::uint8_t {
    accepted,  ///< The operation completed or is waiting for peer progress.
    not_found,  ///< No live association matched the supplied peer.
    not_established,  ///< The association exists but authentication is incomplete.
    rejected,  ///< Policy, callback, or remote authentication rejected the operation.
    fatal,  ///< A local wolfSSL or transport failure requires association teardown.
  };

  /**
   * @brief Provider initialization state retained for fail-closed diagnostics.
   */
  enum class WolfsslDtlsInitializationStatus : std::uint8_t {
    ready,  ///< Every LSP security invariant was configured successfully.
    invalid_configuration,  ///< A required credential, secret, callback, or resource bound was invalid.
    certificate_parse_failed,  ///< The server certificate was not strict DER X.509 or its SPKI could not be extracted.
    certificate_rejected,  ///< The product identity callback rejected the certificate/SPKI pair.
    wolfssl_initialization_failed,  ///< wolfSSL could not create or configure the exact DTLS 1.3 context.
  };

  /**
   * @brief Non-owning callbacks used by the concrete wolfSSL DTLS server.
   *
   * Callbacks execute synchronously on the socket-owner thread and must not
   * re-enter this provider. A byte span is valid only for the callback.
   */
  struct WolfsslDtlsServerCallbacks {
    /**
     * @brief Emit one complete DTLS-only UDP datagram.
     *
     * @param context Opaque callback context.
     * @param peer Destination five-tuple.
     * @param datagram Complete DTLS UDP payload.
     * @return True only when the socket owner accepted the complete datagram.
     */
    using SendDatagram = bool (*)(
      void *context,
      const PeerEndpoint &peer,
      std::span<const std::uint8_t> datagram
    ) noexcept;

    /**
     * @brief Deliver one authenticated DTLS application record.
     *
     * @param context Opaque callback context.
     * @param peer Authenticated association five-tuple.
     * @param plaintext Complete plaintext application record.
     * @return True only when the bounded LSP control owner accepted the record.
     */
    using ApplicationData = bool (*)(
      void *context,
      const PeerEndpoint &peer,
      std::span<const std::uint8_t> plaintext
    ) noexcept;

    /**
     * @brief Admit a completed association and install its SRTP key material.
     *
     * @param context Opaque callback context.
     * @param peer Authenticated association five-tuple.
     * @param security Exact negotiated security result.
     * @return True only when product state and directional SRTP contexts accepted the association.
     */
    using AssociationReady = bool (*)(
      void *context,
      const PeerEndpoint &peer,
      const DtlsAssociationSecurity &security
    ) noexcept;

    /**
     * @brief Validate the configured server certificate and its SPKI digest.
     *
     * @param context Opaque callback context.
     * @param certificate_der Complete DER leaf certificate.
     * @param spki_sha256 SHA-256 of the certificate's complete DER SubjectPublicKeyInfo.
     * @return True only when the LSP identity store accepts this certificate/SPKI pair.
     */
    using ServerCertificate = bool (*)(
      void *context,
      std::span<const std::uint8_t> certificate_der,
      const Digest256 &spki_sha256
    ) noexcept;

    /**
     * @brief Observe teardown of a previously stateful association.
     *
     * @param context Opaque callback context.
     * @param peer Association five-tuple.
     */
    using AssociationClosed = void (*)(void *context, const PeerEndpoint &peer) noexcept;

    void *context {};  ///< Opaque value passed unchanged to every callback.
    SendDatagram send_datagram {};  ///< Required complete-datagram output callback.
    ApplicationData application_data {};  ///< Required authenticated-control callback.
    AssociationReady association_ready {};  ///< Required exporter and admission callback.
    ServerCertificate server_certificate {};  ///< Required local certificate/SPKI validation callback.
    AssociationClosed association_closed {};  ///< Optional association teardown notification.
  };

  /**
   * @brief Immutable construction input for the wolfSSL DTLS 1.3 server.
   *
   * wolfSSL is intentionally pinned to 5.9.2 until a dependency review
   * changes the product pin. Credentials must be DER so SPKI pinning and key
   * loading use one canonical byte representation.
   */
  struct WolfsslDtlsServerConfig {
    std::span<const std::uint8_t> certificate_der;  ///< Complete DER server leaf certificate.
    std::span<const std::uint8_t> private_key_der;  ///< Complete DER private key matching the certificate.
    std::span<const std::uint8_t> cookie_secret;  ///< Exactly 32 nonzero bytes shared by stateless HRR attempts.
    std::size_t maximum_associations {64};  ///< Durable post-cookie association bound.
    WolfsslDtlsServerCallbacks callbacks;  ///< Required product and socket callbacks.
  };

  /**
   * @brief Concrete fail-closed wolfSSL 5.9.2 DTLS 1.3 LSP server provider.
   *
   * Unknown peers are processed with wolfSSL's address-bound stateless
   * HelloRetryRequest cookie path. A durable association is retained only
   * after `wolfSSL_is_stateful()` reports successful cookie validation.
   */
  class WolfsslDtlsServerProvider final: public DtlsServerProvider {
  public:
    /**
     * @brief Copy credentials, validate the leaf SPKI, and configure wolfSSL.
     *
     * @param config Immutable provider configuration; input spans need not outlive the call.
     */
    explicit WolfsslDtlsServerProvider(const WolfsslDtlsServerConfig &config) noexcept;

    WolfsslDtlsServerProvider(const WolfsslDtlsServerProvider &) = delete;
    WolfsslDtlsServerProvider &operator=(const WolfsslDtlsServerProvider &) = delete;
    WolfsslDtlsServerProvider(WolfsslDtlsServerProvider &&) = delete;
    WolfsslDtlsServerProvider &operator=(WolfsslDtlsServerProvider &&) = delete;

    /**
     * @brief Clear credentials and destroy every retained wolfSSL association.
     */
    ~WolfsslDtlsServerProvider() override;

    /**
     * @copydoc DtlsServerProvider::ready
     */
    [[nodiscard]] bool ready(const DtlsRequirements &requirements) const noexcept override;

    /**
     * @copydoc DtlsServerProvider::receive_dtls
     */
    ProviderDatagramResult receive_dtls(
      const PeerEndpoint &peer,
      std::span<const std::uint8_t> datagram
    ) noexcept override;

    /**
     * @brief Protect and emit one LSP control application record.
     *
     * @param peer Established association five-tuple.
     * @param plaintext One bounded LSPC record.
     * @return Exact write disposition.
     */
    WolfsslDtlsOperationResult send_application_data(
      const PeerEndpoint &peer,
      std::span<const std::uint8_t> plaintext
    ) noexcept;

    /**
     * @brief Process one expired wolfSSL DTLS retransmission timer.
     *
     * The socket owner calls this only after the duration returned by
     * `timeout_seconds()` has expired for the same association.
     *
     * @param peer Association five-tuple.
     * @return Exact timeout disposition.
     */
    WolfsslDtlsOperationResult handle_timeout(const PeerEndpoint &peer) noexcept;

    /**
     * @brief Return wolfSSL's current retransmission timeout.
     *
     * @param peer Association five-tuple.
     * @return Positive whole seconds, or zero when no association exists.
     */
    [[nodiscard]] std::uint32_t timeout_seconds(const PeerEndpoint &peer) const noexcept;

    /**
     * @brief Destroy one association and clear its wolfSSL traffic secrets.
     *
     * @param peer Association five-tuple.
     * @return True when an association was removed.
     */
    bool close_association(const PeerEndpoint &peer) noexcept;

    /**
     * @brief Return the provider initialization result.
     *
     * @return Stable fail-closed construction status.
     */
    [[nodiscard]] WolfsslDtlsInitializationStatus initialization_status() const noexcept;

    /**
     * @brief Return the configured server SPKI digest.
     *
     * @return Digest derived from the exact DER certificate, or zero before successful initialization.
     */
    [[nodiscard]] Digest256 server_spki_sha256() const noexcept;

    /**
     * @brief Return the number of durable post-cookie associations.
     *
     * @return Current retained association count.
     */
    [[nodiscard]] std::size_t association_count() const noexcept;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;  ///< Opaque wolfSSL implementation and secret owner.
    WolfsslDtlsInitializationStatus status_ {WolfsslDtlsInitializationStatus::invalid_configuration};  ///< Construction status.
  };
}  // namespace lumen::lsp
