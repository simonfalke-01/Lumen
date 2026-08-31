/**
 * @file src/protocol_lsp/runtime/microphone_receiver.cpp
 * @brief Authenticated LSP reverse-microphone receiver implementation.
 */

#include "microphone_receiver.h"

#include "../core/rtp.h"
#include "../core/wire.h"
#include "../transport/rtcp.h"

#include <algorithm>
#include <limits>
#include <new>
#include <utility>
#include <vector>

namespace lumen::lsp::runtime {
  bool MicrophoneReceiverConfig::valid() const noexcept {
    return peer.valid() && generation != 0 && ssrc != 0 && payload_type >= 96 && payload_type <= 127 &&
           clock_rate == client_microphone::SAMPLE_RATE && channels == client_microphone::CHANNEL_COUNT &&
           frame_samples == client_microphone::SAMPLES_PER_FRAME;
  }

  /** @brief Hidden generation-qualified writer, sequence, decoder, and sink state. */
  class LspMicrophoneReceiver::Impl {
  public:
    /**
     * @brief Retain an already started receiver and its exact writer ownership.
     *
     * @param config Exact acknowledged mapping.
     * @param owner Claimed LSP writer identity.
     * @param sink Owned platform sink.
     * @param receiver Started clocked receiver borrowing `sink`.
     */
    Impl(
      MicrophoneReceiverConfig config,
      const client_microphone::writer_owner_t owner,
      std::unique_ptr<client_microphone::sink_t> sink,
      std::unique_ptr<client_microphone::clocked_receiver_t> receiver
    ) noexcept:
        config_(std::move(config)),
        owner_(owner),
        sink_(std::move(sink)),
        receiver_(std::move(receiver)),
        active_(true) {
    }

    /** @brief Stop and release all exact generation ownership. */
    ~Impl() {
      shutdown();
    }

    /**
     * @brief Expand a 16-bit RTP sequence around the greatest accepted sequence.
     *
     * @param sequence Wire RTP sequence.
     * @return Monotonic sequence suitable for the bounded receiver.
     */
    std::uint64_t expand_sequence(const std::uint16_t sequence) noexcept {
      if (!sequence_initialized_) {
        sequence_initialized_ = true;
        highest_sequence_ = sequence;
        return highest_sequence_;
      }
      const auto cycle = highest_sequence_ & ~std::uint64_t {0xffffU};
      auto candidate = cycle | sequence;
      if (candidate + 0x8000U < highest_sequence_) {
        candidate += 0x1'0000U;
      } else if (candidate > highest_sequence_ + 0x8000U && candidate >= 0x1'0000U) {
        candidate -= 0x1'0000U;
      }
      highest_sequence_ = std::max(highest_sequence_, candidate);
      return candidate;
    }

    /** @brief Submit one exact authenticated RTP packet to clocked playout. */
    bool receive_rtp(const PeerEndpoint &peer, const std::span<const std::uint8_t> packet) noexcept {
      if (!active_ || peer != config_.peer) {
        ++rejected_rtp_packets_;
        return true;
      }
      const auto rtp = parse_rtp_fixed_header(packet);
      if (!rtp || rtp.header.padding || rtp.header.extension || rtp.header.csrc_count != 0 ||
          rtp.header.ssrc != config_.ssrc || rtp.header.payload_type != config_.payload_type ||
          rtp.bytes_consumed >= packet.size()) {
        ++rejected_rtp_packets_;
        return true;
      }
      const auto payload = packet.subspan(rtp.bytes_consumed);
      if (payload.empty() || payload.size() > client_microphone::MAX_OPUS_PAYLOAD_SIZE) {
        ++rejected_rtp_packets_;
        return true;
      }
      client_microphone::packet_t microphone_packet {
        .generation = config_.generation,
        .sequence = expand_sequence(rtp.header.sequence_number),
        .timestamp = rtp.header.timestamp,
        .kind = client_microphone::packet_kind_e::opus,
        .fixed_payload_size = static_cast<std::uint16_t>(payload.size()),
      };
      std::ranges::copy(payload, microphone_packet.fixed_payload.begin());
      if (receiver_->submit(std::move(microphone_packet)) != client_microphone::submit_result_e::accepted) {
        ++rejected_rtp_packets_;
        return true;
      }
      ++accepted_rtp_packets_;
      return true;
    }

    /** @brief Validate RTCP and count sender reports belonging to the microphone SSRC. */
    bool receive_rtcp(const PeerEndpoint &peer, std::span<const std::uint8_t> packet) noexcept {
      if (!active_ || peer != config_.peer) {
        return true;
      }
      const auto datagram = transport::parse_rtcp_datagram(packet, transport::rtcp_datagram_form::compound);
      if (!datagram) {
        return true;
      }
      std::size_t offset = 0;
      while (offset < packet.size()) {
        const auto parsed = transport::parse_rtcp_packet(packet.subspan(offset));
        if (!parsed) {
          return true;
        }
        if (parsed.packet_type == transport::rtcp_sender_report_type && parsed.payload.size() >= 24 &&
            wire::read_be<std::uint32_t>(parsed.payload.first<4>()) == config_.ssrc) {
          ++sender_reports_;
        }
        offset += parsed.packet.size();
      }
      return true;
    }

    /** @brief Stop active playout without joining its reusable worker. */
    void stop() noexcept {
      if (active_ && receiver_) {
        receiver_->stop();
      }
      active_ = false;
    }

    /** @brief Join the receiver worker and release the exact writer once. */
    void shutdown() noexcept {
      stop();
      if (receiver_) {
        receiver_->shutdown();
        receiver_.reset();
      }
      if (owner_.id != 0) {
        client_microphone::release_writer(owner_);
        owner_.id = 0;
      }
      sink_.reset();
    }

    /** @brief Return current receive and playout counters. */
    [[nodiscard]] MicrophoneReceiverSnapshot snapshot() const noexcept {
      return {
        .accepted_rtp_packets = accepted_rtp_packets_,
        .rejected_rtp_packets = rejected_rtp_packets_,
        .sender_reports = sender_reports_,
        .playout = receiver_ ? receiver_->statistics() : client_microphone::statistics_t {},
        .active = active_ && receiver_ && receiver_->active(),
      };
    }

    MicrophoneReceiverConfig config_;  ///< Immutable authenticated mapping.
    client_microphone::writer_owner_t owner_;  ///< Exact claimed LSP writer.
    std::unique_ptr<client_microphone::sink_t> sink_;  ///< Owned platform injection backend.
    std::unique_ptr<client_microphone::clocked_receiver_t> receiver_;  ///< Bounded decoder/playout owner.
    std::uint64_t highest_sequence_ {};  ///< Greatest expanded RTP sequence observed.
    std::uint64_t accepted_rtp_packets_ {};  ///< Accepted Opus RTP packets.
    std::uint64_t rejected_rtp_packets_ {};  ///< Safely dropped RTP packets.
    std::uint64_t sender_reports_ {};  ///< Valid reverse SR packets.
    bool sequence_initialized_ {};  ///< Whether `highest_sequence_` has an origin.
    bool active_ {};  ///< Whether writer and receiver remain active.
  };

  std::unique_ptr<LspMicrophoneReceiver> LspMicrophoneReceiver::create(
    MicrophoneReceiverConfig config,
    std::unique_ptr<client_microphone::sink_t> sink
  ) noexcept {
    if (!config.valid() || !sink) {
      return nullptr;
    }
    const auto owner = client_microphone::writer_owner_t::lsp(config.generation);
    if (!client_microphone::claim_writer(owner)) {
      return nullptr;
    }
    try {
      auto receiver = std::make_unique<client_microphone::clocked_receiver_t>(
        std::make_unique<client_microphone::opus_decoder_t>(),
        *sink,
        config.inband_fec
      );
      if (!receiver->reset(config.generation)) {
        receiver->shutdown();
        client_microphone::release_writer(owner);
        return nullptr;
      }
      auto impl = std::make_unique<Impl>(std::move(config), owner, std::move(sink), std::move(receiver));
      return std::unique_ptr<LspMicrophoneReceiver> {new (std::nothrow) LspMicrophoneReceiver(std::move(impl))};
    } catch (...) {
      client_microphone::release_writer(owner);
      return nullptr;
    }
  }

  LspMicrophoneReceiver::LspMicrophoneReceiver(std::unique_ptr<Impl> impl) noexcept:
      impl_(std::move(impl)) {
  }

  LspMicrophoneReceiver::~LspMicrophoneReceiver() = default;

  bool LspMicrophoneReceiver::receive_rtp(const PeerEndpoint &peer, const std::span<const std::uint8_t> packet) noexcept {
    return impl_ && impl_->receive_rtp(peer, packet);
  }

  bool LspMicrophoneReceiver::receive_rtcp(const PeerEndpoint &peer, const std::span<const std::uint8_t> packet) noexcept {
    return impl_ && impl_->receive_rtcp(peer, packet);
  }

  void LspMicrophoneReceiver::stop() noexcept {
    if (impl_) {
      impl_->stop();
    }
  }

  void LspMicrophoneReceiver::shutdown() noexcept {
    if (impl_) {
      impl_->shutdown();
    }
  }

  MicrophoneReceiverSnapshot LspMicrophoneReceiver::snapshot() const noexcept {
    return impl_ ? impl_->snapshot() : MicrophoneReceiverSnapshot {};
  }

  const PeerEndpoint &LspMicrophoneReceiver::peer() const noexcept {
    static const PeerEndpoint empty;
    return impl_ ? impl_->config_.peer : empty;
  }

  std::uint32_t LspMicrophoneReceiver::generation() const noexcept {
    return impl_ ? impl_->config_.generation : 0;
  }
}  // namespace lumen::lsp::runtime
