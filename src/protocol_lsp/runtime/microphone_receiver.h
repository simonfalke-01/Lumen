/**
 * @file src/protocol_lsp/runtime/microphone_receiver.h
 * @brief Authenticated LSP reverse-microphone RTP receive and platform-injection owner.
 */

#pragma once

#include "../../client_microphone.h"
#include "../types.h"

#include <cstdint>
#include <memory>
#include <span>

namespace lumen::lsp::runtime {
  /** @brief Exact acknowledged reverse-microphone RTP mapping. */
  struct MicrophoneReceiverConfig {
    PeerEndpoint peer {};  ///< Authenticated client association.
    std::uint32_t generation {};  ///< Nonzero microphone configuration generation.
    std::uint32_t ssrc {};  ///< Negotiated client microphone SSRC.
    std::uint8_t payload_type {};  ///< Negotiated dynamic Opus payload type.
    std::uint32_t clock_rate {48'000};  ///< Required Opus RTP clock.
    std::uint8_t channels {1};  ///< Required mono channel count.
    std::uint16_t frame_samples {960};  ///< Required 20 ms frame size.
    bool inband_fec {};  ///< Whether following packets may repair one missing frame.
    bool dtx {};  ///< Whether the sender may emit Opus DTX packets.

    /** @brief Return whether every fixed LSP microphone invariant is valid. */
    [[nodiscard]] bool valid() const noexcept;
  };

  /** @brief LSP microphone packet, RTCP, and parser counters. */
  struct MicrophoneReceiverSnapshot {
    std::uint64_t accepted_rtp_packets {};  ///< Opus RTP packets admitted to the bounded receiver.
    std::uint64_t rejected_rtp_packets {};  ///< Stale, malformed, or out-of-window RTP packets.
    std::uint64_t sender_reports {};  ///< Valid reverse sender reports for the microphone SSRC.
    client_microphone::statistics_t playout {};  ///< Bounded jitter/FEC/PLC/sink counters.
    bool active {};  ///< Whether writer, decoder, and platform sink are active.
  };

  /** @brief Generation-qualified LSP microphone writer and clocked receiver owner. */
  class LspMicrophoneReceiver {
  public:
    /**
     * @brief Create and begin a real generation-qualified microphone receiver.
     *
     * @param config Exact acknowledged microphone mapping.
     * @param sink Probed platform virtual microphone sink.
     * @return Active owner, or null when writer, decoder, or sink initialization fails.
     */
    [[nodiscard]] static std::unique_ptr<LspMicrophoneReceiver> create(
      MicrophoneReceiverConfig config,
      std::unique_ptr<client_microphone::sink_t> sink
    ) noexcept;

    LspMicrophoneReceiver(const LspMicrophoneReceiver &) = delete;
    LspMicrophoneReceiver &operator=(const LspMicrophoneReceiver &) = delete;

    /** @brief Stop, join, release the exact writer, and destroy platform state. */
    ~LspMicrophoneReceiver();

    /**
     * @brief Submit one authenticated and decrypted RFC 7587 RTP packet.
     *
     * @param peer Exact received association.
     * @param packet Plaintext RTP packet.
     * @return True for an accepted or safely dropped media packet.
     */
    bool receive_rtp(const PeerEndpoint &peer, std::span<const std::uint8_t> packet) noexcept;

    /**
     * @brief Parse reverse RTCP sender reports independently from RTP media.
     *
     * @param peer Exact received association.
     * @param packet Plaintext RTCP datagram.
     * @return True for a valid report datagram or an unrelated valid RTCP packet.
     */
    bool receive_rtcp(const PeerEndpoint &peer, std::span<const std::uint8_t> packet) noexcept;

    /** @brief End playout immediately while retaining joinable receiver ownership. */
    void stop() noexcept;

    /** @brief Permanently join playout and release the generation-qualified writer. */
    void shutdown() noexcept;

    /** @brief Return current parser and playout observations. */
    [[nodiscard]] MicrophoneReceiverSnapshot snapshot() const noexcept;

    /** @brief Return the exact configured association. */
    [[nodiscard]] const PeerEndpoint &peer() const noexcept;

    /** @brief Return the exact active microphone generation. */
    [[nodiscard]] std::uint32_t generation() const noexcept;

  private:
    class Impl;
    explicit LspMicrophoneReceiver(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;  ///< Hidden sequence, decoder, sink, and writer ownership.
  };
}  // namespace lumen::lsp::runtime
