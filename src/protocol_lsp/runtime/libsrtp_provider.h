/**
 * @file src/protocol_lsp/runtime/libsrtp_provider.h
 * @brief Concrete libSRTP 2.8.0 association provider for the LSP runtime.
 */

#pragma once

#include "../security/wolfssl_dtls_server.h"
#include "../security_provider.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace lumen::lsp::runtime {
  /**
   * @brief Non-owning authenticated SRTP/SRTCP delivery callbacks.
   */
  struct LibsrtpCallbacks {
    /**
     * @brief Consume one authenticated and decrypted RTP or RTCP packet.
     *
     * @param context Opaque callback context.
     * @param peer Exact authenticated association five-tuple.
     * @param packet_class RTP or RTCP classification.
     * @param plaintext Complete in-place-decrypted packet.
     * @return True only when the bounded lane owner accepted the packet.
     */
    using PlaintextPacket = bool (*)(
      void *context,
      const PeerEndpoint &peer,
      SecurePacketClass packet_class,
      std::span<const std::uint8_t> plaintext
    ) noexcept;

    /**
     * @brief Submit one complete protected RTP or RTCP datagram.
     *
     * @param context Opaque callback context.
     * @param peer Exact destination association.
     * @param protected_packet Complete protected packet.
     * @return True only when the socket accepted the complete datagram.
     */
    using SendDatagram = bool (*)(
      void *context,
      const PeerEndpoint &peer,
      std::span<const std::uint8_t> protected_packet
    ) noexcept;

    void *context {};  ///< Opaque callback value.
    PlaintextPacket plaintext_packet {};  ///< Required authenticated receive callback.
    SendDatagram send_datagram {};  ///< Required exact protected send callback.
  };

  /**
   * @brief Concrete libSRTP AEAD AES-128-GCM provider scoped by DTLS association.
   */
  class LibsrtpServerProvider final: public SrtpProvider {
  public:
    /**
     * @brief Initialize process-wide libSRTP and retain callbacks.
     *
     * @param callbacks Required runtime callbacks.
     * @param maximum_associations Bound from one through 64.
     */
    explicit LibsrtpServerProvider(
      LibsrtpCallbacks callbacks,
      std::size_t maximum_associations = 64
    ) noexcept;

    LibsrtpServerProvider(const LibsrtpServerProvider &) = delete;
    LibsrtpServerProvider &operator=(const LibsrtpServerProvider &) = delete;

    /** @brief Destroy every SRTP/SRTCP association context. */
    ~LibsrtpServerProvider() override;

    /** @copydoc SrtpProvider::ready */
    [[nodiscard]] bool ready(const SrtpRequirements &requirements) const noexcept override;

    /** @copydoc SrtpProvider::receive_secure_packet */
    ProviderDatagramResult receive_secure_packet(
      const PeerEndpoint &peer,
      SecurePacketClass packet_class,
      std::span<const std::uint8_t> datagram
    ) noexcept override;

    /**
     * @brief Install directional contexts from one authenticated DTLS-SRTP exporter.
     *
     * @param peer Exact association five-tuple.
     * @param key_material RFC 5764 client/server key and salt fields.
     * @return True only after both replay-protected contexts are active.
     */
    bool install_association(
      const PeerEndpoint &peer,
      const DtlsSrtpKeyMaterial &key_material
    ) noexcept;

    /**
     * @brief Remove and clear one association's SRTP/SRTCP contexts.
     *
     * @param peer Exact association five-tuple.
     * @return True when an association was removed.
     */
    bool remove_association(const PeerEndpoint &peer) noexcept;

    /**
     * @brief Protect and atomically submit one RTP or RTCP packet.
     *
     * @param peer Exact established association.
     * @param packet_class RTP or RTCP classification.
     * @param plaintext Complete unprotected packet.
     * @return True only when protection and exact datagram submission succeed.
     */
    bool protect_and_send(
      const PeerEndpoint &peer,
      SecurePacketClass packet_class,
      std::span<const std::uint8_t> plaintext
    ) noexcept;

    /**
     * @brief Return the number of installed association context pairs.
     *
     * @return Current association count.
     */
    [[nodiscard]] std::size_t association_count() const noexcept;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;  ///< Hidden libSRTP context owner.
  };
}  // namespace lumen::lsp::runtime
