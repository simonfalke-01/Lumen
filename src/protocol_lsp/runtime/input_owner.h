/**
 * @file src/protocol_lsp/runtime/input_owner.h
 * @brief Bounded ordered LSP input receive and platform-apply owner.
 */

#pragma once

#include "../types.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <span>

namespace lumen::lsp::runtime {
  /** @brief Authenticated input-only session mapping installed by START_RESPONSE. */
  struct InputSessionMapping {
    PeerEndpoint peer;  ///< Exact authoritative DTLS/SRTP five-tuple.
    Identifier128 client_id {};  ///< Authenticated client identity.
    std::uint32_t connection_generation {};  ///< Connection authority generation.
    std::uint32_t session_generation {};  ///< Stream-session generation.
    std::uint32_t input_generation {};  ///< Input authority generation.
    std::uint32_t input_ssrc {};  ///< Negotiated client input RTP SSRC.
    std::uint32_t acknowledgement_ssrc {};  ///< Host SRTCP LSPI sender SSRC.
    std::uint8_t input_payload_type {};  ///< Negotiated dynamic LSP input payload type.

    /** @brief Return whether every authority/mapping field is valid. */
    [[nodiscard]] bool valid() const noexcept;

    bool operator==(const InputSessionMapping &) const = default;
  };

  /** @brief Non-owning crypto and protected-ACK callbacks used by the input owner. */
  struct InputOwnerCallbacks {
    /** @brief Verify SHA-256 for one completed multipart baseline. */
    using VerifyDigest = bool (*)(
      void *context,
      std::span<const std::uint8_t> bytes,
      const Digest256 &expected
    ) noexcept;

    /** @brief Protect and send one complete plaintext RTCP APP packet. */
    using SendAcknowledgement = bool (*)(
      void *context,
      const PeerEndpoint &peer,
      std::span<const std::uint8_t> rtcp_packet
    ) noexcept;

    /** @brief Commit baseline authority before any normal input is applied. */
    using BaselineCommitted = bool (*)(
      void *context,
      const PeerEndpoint &peer,
      std::uint32_t session_generation,
      std::uint32_t input_generation
    ) noexcept;

    void *context {};  ///< Opaque callback context.
    VerifyDigest verify_digest {};  ///< Required baseline verifier.
    SendAcknowledgement send_acknowledgement {};  ///< Required SRTCP sender.
    BaselineCommitted baseline_committed {};  ///< Required SessionAuthority commit callback.
  };

  /**
   * @brief Dedicated bounded ordered owner for authenticated input RTP.
   */
  class InputOwner {
  public:
    /** @brief Start the dedicated platform-apply worker. */
    explicit InputOwner(InputOwnerCallbacks callbacks) noexcept;
    InputOwner(const InputOwner &) = delete;
    InputOwner &operator=(const InputOwner &) = delete;
    /** @brief Neutralize held input, stop, and join the worker. */
    ~InputOwner();

    /**
     * @brief Install a fresh START-selected mapping and require a neutral baseline.
     *
     * @param mapping Exact authenticated mapping.
     * @return True after old input is neutralized and the new generation is installed.
     */
    bool configure(const InputSessionMapping &mapping) noexcept;

    /**
     * @brief Validate SSRC/PT and enqueue one authenticated plaintext RTP packet.
     *
     * @param peer Exact receive five-tuple.
     * @param packet Complete decrypted RTP packet.
     * @return True when accepted into the bounded ordered owner; unknown mappings are silent drops.
     */
    bool receive(const PeerEndpoint &peer, std::span<const std::uint8_t> packet) noexcept;

    /** @brief Process one authenticated negotiated SRTCP LSPG acknowledgement. */
    bool receive_rtcp(const PeerEndpoint &peer, std::span<const std::uint8_t> packet) noexcept;

    /** @brief Neutralize and remove the active mapping synchronously. */
    void neutralize() noexcept;

    /** @brief Return the active mapping, or no value when input authority is absent. */
    [[nodiscard]] std::optional<InputSessionMapping> mapping() const noexcept;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;  ///< Hidden queue, state machine, and worker.
  };
}  // namespace lumen::lsp::runtime
