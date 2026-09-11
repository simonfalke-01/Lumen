/**
 * @file src/protocol_lsp/security_provider.h
 * @brief Explicit fail-closed DTLS and SRTP provider boundaries for LSP.
 */

#pragma once

#include "packet_classifier.h"
#include "types.h"

#include <cstdint>
#include <span>
#include <string_view>

namespace lumen::lsp {
  /**
   * @brief Immutable DTLS requirements a production provider must enforce.
   */
  struct DtlsRequirements {
    std::string_view alpn_protocol {alpn};  ///< Exact ALPN selected for every LSP association.
    std::string_view cipher_suite {"TLS_AES_128_GCM_SHA256"};  ///< Required DTLS 1.3 cipher suite.
    std::string_view key_agreement {"X25519"};  ///< Required key-agreement group.
    bool require_dtls_1_3 {true};  ///< Whether DTLS versions before 1.3 must be rejected.
    bool require_stateless_cookie {true};  ///< Whether return routability must precede durable allocation.
    bool allow_early_data {false};  ///< Whether early application data is accepted.
    bool allow_resumption {false};  ///< Whether session resumption is accepted in LSP/1.
  };

  /**
   * @brief Immutable SRTP requirements a production provider must enforce.
   */
  struct SrtpRequirements {
    std::string_view protection_profile {"SRTP_AEAD_AES_128_GCM"};  ///< Required DTLS-SRTP protection profile.
    std::string_view exporter_label {"EXTRACTOR-dtls_srtp"};  ///< RFC 5764 exporter label.
    bool require_replay_protection {true};  ///< Whether RTP and RTCP replay windows are mandatory.
    bool require_encrypted_extensions {true};  ///< Whether private RTP header extensions use RFC 6904 processing.
    bool allow_mki {false};  ///< Whether a master key identifier is accepted.
  };

  /**
   * @brief Result of handing an authenticated or unauthenticated datagram to a provider.
   */
  enum class ProviderDatagramResult : std::uint8_t {
    accepted,  ///< Provider consumed the complete datagram.
    dropped,  ///< Provider silently rejected an invalid, unauthenticated, replayed, or stale datagram.
    fatal,  ///< Provider detected a local association failure requiring teardown.
  };

  /** @brief IP-layer ECN codepoint observed on one authenticated receive datagram. */
  enum class IpEcn : std::uint8_t {
    not_ect = 0,  ///< Datagram was explicitly Not-ECT.
    ect_1 = 1,  ///< Datagram carried ECT(1).
    ect_0 = 2,  ///< Datagram carried ECT(0).
    congestion_experienced = 3,  ///< Datagram carried ECN-CE.
    unavailable = 0xff,  ///< Platform ancillary receive metadata was unavailable.
  };

  /**
   * @brief DTLS 1.3 server provider injected by product integration.
   *
   * This interface does not implement or emulate DTLS. The service remains
   * inactive until a provider confirms that it enforces every requirement.
   */
  class DtlsServerProvider {
  public:
    virtual ~DtlsServerProvider() = default;

    /**
     * @brief Confirm that the provider is configured for the exact LSP policy.
     *
     * @param requirements Required DTLS policy.
     * @return True only when all requirements are active.
     */
    [[nodiscard]] virtual bool ready(const DtlsRequirements &requirements) const noexcept = 0;

    /**
     * @brief Process one complete DTLS-only UDP datagram.
     *
     * @param peer Source endpoint.
     * @param datagram Complete UDP payload containing only DTLS records for one association.
     * @return Provider disposition.
     */
    virtual ProviderDatagramResult receive_dtls(
      const PeerEndpoint &peer,
      std::span<const std::uint8_t> datagram
    ) noexcept = 0;
  };

  /**
   * @brief SRTP/SRTCP provider injected by product integration.
   *
   * This interface does not implement or emulate media cryptography. Unknown
   * SSRC, payload-type, authentication, and replay failures must be returned as
   * silent drops by the provider.
   */
  class SrtpProvider {
  public:
    virtual ~SrtpProvider() = default;

    /**
     * @brief Confirm that the provider is configured for the exact LSP policy.
     *
     * @param requirements Required SRTP policy.
     * @return True only when all requirements are active.
     */
    [[nodiscard]] virtual bool ready(const SrtpRequirements &requirements) const noexcept = 0;

    /**
     * @brief Authenticate and process one complete protected media packet.
     *
     * @param peer Source endpoint bound to the authenticated association.
     * @param packet_class RFC 5761 packet class.
     * @param datagram Mutable socket-owned SRTP or SRTCP packet unprotected in place.
     * @param received_at_microseconds Socket receive timestamp in the host monotonic domain.
     * @param ecn Authenticated datagram's IP-layer ECN observation.
     * @return Provider disposition.
     */
    virtual ProviderDatagramResult receive_secure_packet(
      const PeerEndpoint &peer,
      SecurePacketClass packet_class,
      std::span<std::uint8_t> datagram,
      std::uint64_t received_at_microseconds,
      IpEcn ecn
    ) noexcept = 0;
  };
}  // namespace lumen::lsp
