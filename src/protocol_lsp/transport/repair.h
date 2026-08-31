/**
 * @file src/protocol_lsp/transport/repair.h
 * @brief Allocation-free LSP FlexFEC, RTX, and recovery-epoch state.
 */

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>

namespace lumen::lsp::transport {
  /** @brief Maximum LSP RTX source-packet retention per connection. */
  inline constexpr std::size_t maximum_rtx_retained_bytes = 16U * 1024U * 1024U;

  /** @brief Maximum number of distinct frame generations retained for RTX. */
  inline constexpr std::size_t maximum_rtx_frame_generations = 2;

  /** @brief Maximum source packets represented by one small frame-local FlexFEC group. */
  inline constexpr std::size_t maximum_flexfec_group_packets = 64;

  /** @brief Lifecycle state of one FEC-before-SRTP source/repair group. */
  enum class flexfec_phase : std::uint8_t {
    idle,  ///< No frame-local group is active.
    accumulating_plaintext,  ///< Plaintext source RTP packets may update parity before SRTP protection.
    repair_plaintext_ready,  ///< Incremental parity is sealed for repair-packet construction.
    repair_ready_for_srtp,  ///< Plaintext repair RTP packet was constructed and may be SRTP-protected.
    complete,  ///< Source and repair protection ordering completed.
  };

  /** @brief Typed FlexFEC group transition result. */
  enum class flexfec_result : std::uint8_t {
    accepted,  ///< Transition completed successfully.
    invalid_identifier,  ///< Frame ID or SSRC zero is forbidden, or SSRCs collide.
    invalid_storage,  ///< Parity storage is empty or cannot hold a source packet.
    wrong_phase,  ///< Operation violates the FEC-before-SRTP lifecycle.
    wrong_frame,  ///< Source belongs to a different encoded frame.
    wrong_ssrc,  ///< Source SSRC does not match the protected primary stream.
    group_full,  ///< Small source group already contains 64 packets.
    sequence_out_of_range,  ///< Sequence is outside the 64-packet group mask.
    duplicate_source,  ///< Source sequence already contributed to parity.
    empty_group,  ///< A group with no protected source cannot be sealed.
  };

  /** @brief Borrowed incremental plaintext parity ready for RFC 8627 packet construction. */
  struct flexfec_parity_view {
    std::uint64_t frame_id = 0;  ///< Encoded frame protected by this group.
    std::uint32_t primary_ssrc = 0;  ///< Protected primary video SSRC.
    std::uint32_t repair_ssrc = 0;  ///< Negotiated FlexFEC repair SSRC.
    std::uint16_t base_sequence_number = 0;  ///< First source sequence in the 64-bit mask space.
    std::uint16_t length_recovery = 0;  ///< XOR of complete plaintext source RTP packet lengths.
    std::uint64_t source_mask = 0;  ///< Source sequence offsets included in parity.
    std::span<const std::uint8_t> parity {};  ///< Incremental zero-padded plaintext packet XOR.
  };

  /**
   * @brief Caller-storage-backed frame-local FlexFEC parity accumulator.
   *
   * Accepted source packets are incorporated while plaintext and may then immediately be protected
   * in place under the primary SRTP context. The sealed repair plaintext is constructed from the
   * returned parity and only then protected under the repair SRTP context. No duplicate plaintext
   * packet copy is retained by this state object.
   */
  class flexfec_group {
  public:
    /**
     * @brief Construct an idle group over caller-owned parity storage.
     *
     * @param parity_storage Maximum-size packet XOR storage retained for the group lifetime.
     */
    constexpr explicit flexfec_group(const std::span<std::uint8_t> parity_storage) noexcept:
        parity_storage_(parity_storage) {
    }

    /**
     * @brief Begin one enabled frame-local repair group.
     *
     * A clean path with zero active parity simply does not call `begin()`.
     *
     * @param frame_id Nonzero encoded frame ID.
     * @param primary_ssrc Nonzero primary video SSRC.
     * @param repair_ssrc Nonzero distinct FlexFEC SSRC.
     * @return Typed transition result.
     */
    constexpr flexfec_result begin(
      const std::uint64_t frame_id,
      const std::uint32_t primary_ssrc,
      const std::uint32_t repair_ssrc
    ) noexcept {
      if (frame_id == 0 || primary_ssrc == 0 || repair_ssrc == 0 || primary_ssrc == repair_ssrc) {
        return flexfec_result::invalid_identifier;
      }
      if (parity_storage_.empty()) {
        return flexfec_result::invalid_storage;
      }
      if (phase_ != flexfec_phase::idle && phase_ != flexfec_phase::complete) {
        return flexfec_result::wrong_phase;
      }
      std::fill(parity_storage_.begin(), parity_storage_.end(), 0);
      frame_id_ = frame_id;
      primary_ssrc_ = primary_ssrc;
      repair_ssrc_ = repair_ssrc;
      base_sequence_number_ = 0;
      length_recovery_ = 0;
      parity_size_ = 0;
      source_mask_ = 0;
      source_count_ = 0;
      phase_ = flexfec_phase::accumulating_plaintext;
      return flexfec_result::accepted;
    }

    /**
     * @brief Add one final plaintext source RTP packet before in-place SRTP protection.
     *
     * On success the caller may immediately protect the source packet. The parity accumulator keeps
     * only its XOR contribution and never retains the source pointer.
     *
     * @param frame_id Encoded frame containing the source.
     * @param primary_ssrc Source RTP SSRC.
     * @param sequence_number Source RTP sequence number.
     * @param plaintext_packet Complete final plaintext RTP packet.
     * @return Typed transition result.
     */
    constexpr flexfec_result add_plaintext_source(
      const std::uint64_t frame_id,
      const std::uint32_t primary_ssrc,
      const std::uint16_t sequence_number,
      const std::span<const std::uint8_t> plaintext_packet
    ) noexcept {
      if (phase_ != flexfec_phase::accumulating_plaintext) {
        return flexfec_result::wrong_phase;
      }
      if (frame_id != frame_id_) {
        return flexfec_result::wrong_frame;
      }
      if (primary_ssrc != primary_ssrc_) {
        return flexfec_result::wrong_ssrc;
      }
      if (plaintext_packet.empty() || plaintext_packet.size() > parity_storage_.size() ||
          plaintext_packet.size() > std::numeric_limits<std::uint16_t>::max()) {
        return flexfec_result::invalid_storage;
      }
      if (source_count_ == maximum_flexfec_group_packets) {
        return flexfec_result::group_full;
      }
      if (source_count_ == 0) {
        base_sequence_number_ = sequence_number;
      }
      const auto offset = static_cast<std::uint16_t>(sequence_number - base_sequence_number_);
      if (offset >= maximum_flexfec_group_packets) {
        return flexfec_result::sequence_out_of_range;
      }
      const auto bit = std::uint64_t {1} << offset;
      if ((source_mask_ & bit) != 0) {
        return flexfec_result::duplicate_source;
      }
      for (std::size_t index = 0; index < plaintext_packet.size(); ++index) {
        parity_storage_[index] ^= plaintext_packet[index];
      }
      source_mask_ |= bit;
      ++source_count_;
      parity_size_ = std::max(parity_size_, plaintext_packet.size());
      length_recovery_ ^= static_cast<std::uint16_t>(plaintext_packet.size());
      return flexfec_result::accepted;
    }

    /**
     * @brief Seal incremental parity for plaintext FlexFEC packet construction.
     *
     * @param parity Receives a borrowed view of the group parity.
     * @return Typed transition result.
     */
    constexpr flexfec_result seal_plaintext_repair(flexfec_parity_view &parity) noexcept {
      if (phase_ != flexfec_phase::accumulating_plaintext) {
        return flexfec_result::wrong_phase;
      }
      if (source_count_ == 0) {
        return flexfec_result::empty_group;
      }
      phase_ = flexfec_phase::repair_plaintext_ready;
      parity = {
        .frame_id = frame_id_,
        .primary_ssrc = primary_ssrc_,
        .repair_ssrc = repair_ssrc_,
        .base_sequence_number = base_sequence_number_,
        .length_recovery = length_recovery_,
        .source_mask = source_mask_,
        .parity = parity_storage_.first(parity_size_),
      };
      return flexfec_result::accepted;
    }

    /**
     * @brief Mark the plaintext FlexFEC RTP packet constructed and ready for repair-SRTP protection.
     *
     * @return Typed transition result.
     */
    constexpr flexfec_result mark_repair_plaintext_constructed() noexcept {
      if (phase_ != flexfec_phase::repair_plaintext_ready) {
        return flexfec_result::wrong_phase;
      }
      phase_ = flexfec_phase::repair_ready_for_srtp;
      return flexfec_result::accepted;
    }

    /**
     * @brief Mark repair-SRTP protection complete.
     *
     * @return Typed transition result.
     */
    constexpr flexfec_result mark_repair_protected() noexcept {
      if (phase_ != flexfec_phase::repair_ready_for_srtp) {
        return flexfec_result::wrong_phase;
      }
      phase_ = flexfec_phase::complete;
      return flexfec_result::accepted;
    }

    /**
     * @brief Return the current FEC-before-SRTP lifecycle phase.
     *
     * @return Current group phase.
     */
    [[nodiscard]] constexpr flexfec_phase phase() const noexcept {
      return phase_;
    }

  private:
    std::span<std::uint8_t> parity_storage_ {};  ///< Caller-owned incremental plaintext XOR storage.
    std::uint64_t frame_id_ = 0;  ///< Active encoded frame ID.
    std::uint64_t source_mask_ = 0;  ///< Included source-sequence offsets.
    std::uint32_t primary_ssrc_ = 0;  ///< Protected primary video SSRC.
    std::uint32_t repair_ssrc_ = 0;  ///< FlexFEC repair SSRC.
    std::size_t parity_size_ = 0;  ///< Largest included plaintext packet size.
    std::uint16_t base_sequence_number_ = 0;  ///< First sequence in the mask space.
    std::uint16_t length_recovery_ = 0;  ///< XOR of included source lengths.
    std::size_t source_count_ = 0;  ///< Number of distinct included sources.
    flexfec_phase phase_ = flexfec_phase::idle;  ///< FEC-before-SRTP lifecycle phase.
  };

  /** @brief Validation request for one plaintext packet recovered from authenticated FlexFEC inputs. */
  struct recovered_packet_candidate {
    bool repair_authenticated_and_decrypted = false;  ///< Repair packet passed SRTCP/SRTP authentication and decryption.
    bool all_contributing_sources_authenticated_and_decrypted = false;  ///< Every contributing source passed SRTP authentication.
    std::uint32_t expected_source_ssrc = 0;  ///< Negotiated primary source SSRC.
    std::uint32_t recovered_source_ssrc = 0;  ///< SSRC reconstructed into the source packet.
    std::uint32_t expected_generation = 0;  ///< Active video configuration generation.
    std::uint32_t recovered_generation = 0;  ///< Generation associated with the recovered packet.
    std::uint8_t expected_payload_type = 0;  ///< Negotiated primary payload type.
    std::uint8_t recovered_payload_type = 0;  ///< Reconstructed RTP payload type.
    std::size_t recovered_packet_bytes = 0;  ///< Complete recovered plaintext RTP packet size.
    std::size_t maximum_packet_bytes = 0;  ///< Current authenticated path-size maximum.
    std::uint64_t now_microseconds = 0;  ///< Current monotonic time.
    std::uint64_t frame_deadline_microseconds = 0;  ///< Protected frame network/decode deadline.
  };

  /** @brief Typed recovered-packet admission failure. */
  enum class recovered_packet_error : std::uint8_t {
    none,  ///< Candidate is authorized for normal RTP and replay processing.
    unauthenticated_input,  ///< Repair or a contributing source was not authenticated and decrypted.
    invalid_ssrc,  ///< Recovered SSRC is zero, unknown, or mismatched.
    invalid_generation,  ///< Recovered packet belongs to a stale or invalid generation.
    invalid_payload_type,  ///< Recovered payload type differs from negotiation.
    invalid_size,  ///< Recovered packet is empty or exceeds the path maximum.
    expired,  ///< Protected frame deadline has passed.
  };

  class recovered_packet_admission;

  /**
   * @brief Unforgeable semantic marker for a packet authenticated by validated FlexFEC repair.
   *
   * The marker does not replace source replay admission. It authorizes the recovered plaintext to
   * enter the same RTP parser, generation checks, and source sequence/replay state as an original.
   */
  class authenticated_recovered_packet {
  public:
    /**
     * @brief Return the recovered source SSRC.
     *
     * @return Validated primary SSRC.
     */
    [[nodiscard]] constexpr std::uint32_t source_ssrc() const noexcept {
      return source_ssrc_;
    }

    /**
     * @brief Return the recovered generation.
     *
     * @return Validated video generation.
     */
    [[nodiscard]] constexpr std::uint32_t generation() const noexcept {
      return generation_;
    }

    /**
     * @brief Return the recovered RTP payload type.
     *
     * @return Validated payload type.
     */
    [[nodiscard]] constexpr std::uint8_t payload_type() const noexcept {
      return payload_type_;
    }

  private:
    friend class recovered_packet_admission;

    /**
     * @brief Construct a marker after complete repair admission validation.
     *
     * @param source_ssrc Validated primary SSRC.
     * @param generation Validated video generation.
     * @param payload_type Validated RTP payload type.
     */
    constexpr authenticated_recovered_packet(
      const std::uint32_t source_ssrc,
      const std::uint32_t generation,
      const std::uint8_t payload_type
    ) noexcept:
        source_ssrc_(source_ssrc),
        generation_(generation),
        payload_type_(payload_type) {
    }

    std::uint32_t source_ssrc_ = 0;  ///< Validated primary SSRC.
    std::uint32_t generation_ = 0;  ///< Validated video generation.
    std::uint8_t payload_type_ = 0;  ///< Validated primary payload type.
  };

  /** @brief Result of authorizing a recovered plaintext source packet. */
  struct recovered_packet_admission_result {
    std::optional<authenticated_recovered_packet> marker {};  ///< Marker present only on complete validation.
    recovered_packet_error error = recovered_packet_error::none;  ///< Admission status.

    /**
     * @brief Return whether authorization succeeded.
     *
     * @return `true` only when the authenticated-by-repair marker is present.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return marker.has_value() && error == recovered_packet_error::none;
    }
  };

  /** @brief Stateless validator that creates authenticated-by-repair admission markers. */
  class recovered_packet_admission {
  public:
    /**
     * @brief Validate all authentication, registry, generation, size, and deadline gates.
     *
     * @param candidate Candidate reconstructed source metadata.
     * @return Marker and typed status.
     */
    [[nodiscard]] static constexpr recovered_packet_admission_result authorize(
      const recovered_packet_candidate &candidate
    ) noexcept {
      if (!candidate.repair_authenticated_and_decrypted ||
          !candidate.all_contributing_sources_authenticated_and_decrypted) {
        return {.error = recovered_packet_error::unauthenticated_input};
      }
      if (candidate.expected_source_ssrc == 0 ||
          candidate.recovered_source_ssrc != candidate.expected_source_ssrc) {
        return {.error = recovered_packet_error::invalid_ssrc};
      }
      if (candidate.expected_generation == 0 ||
          candidate.recovered_generation != candidate.expected_generation) {
        return {.error = recovered_packet_error::invalid_generation};
      }
      if (candidate.recovered_payload_type != candidate.expected_payload_type) {
        return {.error = recovered_packet_error::invalid_payload_type};
      }
      if (candidate.expected_payload_type > 0x7fU) {
        return {.error = recovered_packet_error::invalid_payload_type};
      }
      if (candidate.recovered_packet_bytes == 0 ||
          candidate.maximum_packet_bytes == 0 ||
          candidate.recovered_packet_bytes > candidate.maximum_packet_bytes) {
        return {.error = recovered_packet_error::invalid_size};
      }
      if (candidate.now_microseconds >= candidate.frame_deadline_microseconds) {
        return {.error = recovered_packet_error::expired};
      }
      return {
        .marker = authenticated_recovered_packet {
          candidate.recovered_source_ssrc,
          candidate.recovered_generation,
          candidate.recovered_payload_type,
        },
      };
    }
  };

  /** @brief Complete deadline estimate used by both receiver and sender RTX gates. */
  struct rtx_deadline_estimate {
    std::uint64_t reverse_feedback_microseconds = 0;  ///< Estimated NACK delivery time.
    std::uint64_t retransmission_serialization_microseconds = 0;  ///< RTX pacing and serialization time.
    std::uint64_t forward_delivery_microseconds = 0;  ///< Estimated forward path time.
    std::uint64_t decode_safety_reserve_microseconds = 0;  ///< Decoder admission safety reserve.
  };

  /**
   * @brief Test strict RFC 4588 retransmission deadline eligibility without overflow.
   *
   * @param now_microseconds Current monotonic time.
   * @param frame_deadline_microseconds Protected frame deadline.
   * @param estimate Complete reverse/send/forward/decode estimate.
   * @return `true` only when predicted arrival is strictly before the deadline.
   */
  [[nodiscard]] constexpr bool rtx_deadline_eligible(
    const std::uint64_t now_microseconds,
    const std::uint64_t frame_deadline_microseconds,
    const rtx_deadline_estimate &estimate
  ) noexcept {
    if (now_microseconds >= frame_deadline_microseconds) {
      return false;
    }
    auto remaining = frame_deadline_microseconds - now_microseconds;
    const auto consume = [&remaining](const std::uint64_t duration) constexpr noexcept {
      if (duration >= remaining) {
        return false;
      }
      remaining -= duration;
      return true;
    };
    return consume(estimate.reverse_feedback_microseconds) &&
           consume(estimate.retransmission_serialization_microseconds) &&
           consume(estimate.forward_delivery_microseconds) &&
           consume(estimate.decode_safety_reserve_microseconds);
  }

  /** @brief Opaque reference to one immutable final source-packet slab. */
  struct rtx_packet_reference {
    std::uint64_t token = 0;  ///< Nonzero integration-owned slab retention token.
    std::uint64_t frame_id = 0;  ///< Encoded frame generation retained by the slab.
    std::uint64_t frame_deadline_microseconds = 0;  ///< Absolute repair deadline.
    std::uint32_t source_ssrc = 0;  ///< Primary source SSRC.
    std::uint32_t video_generation = 0;  ///< Video configuration generation.
    std::uint16_t source_sequence_number = 0;  ///< Original primary RTP sequence number.
    std::size_t protected_packet_bytes = 0;  ///< Immutable final protected source-slab bytes.
  };

  /** @brief One caller-storage-backed RTX retention entry. */
  struct rtx_retained_packet {
    rtx_packet_reference packet {};  ///< Opaque immutable source slab reference.
    std::uint64_t expires_microseconds = 0;  ///< Earlier of frame repair deadline or one RTT.
    std::uint64_t insertion_order = 0;  ///< Monotonic local insertion order.
    bool occupied = false;  ///< Whether this slot retains one integration-owned slab.
  };

  /** @brief Result of retaining one immutable source slab for possible RTX. */
  enum class rtx_retention_result : std::uint8_t {
    retained,  ///< Reference was retained without copying packet bytes.
    invalid_packet,  ///< Token, frame, SSRC, generation, size, or deadline is invalid.
    invalid_rtt,  ///< Positive measured RTT is required.
    duplicate_packet,  ///< Same generation, SSRC, and source sequence is already retained.
    byte_capacity_exceeded,  ///< Current frame alone cannot fit the 16 MiB connection limit.
    slot_capacity_exceeded,  ///< Caller-provided metadata slots cannot retain the packet.
  };

  /** @brief Successful eligible RTX lookup result. */
  struct eligible_rtx_packet {
    std::uint64_t token = 0;  ///< Integration-owned immutable source-slab token.
    std::uint64_t frame_id = 0;  ///< Retained encoded frame generation.
    std::size_t protected_packet_bytes = 0;  ///< Source packet bytes before RTX construction.
  };

  /**
   * @brief Caller-storage-backed RFC 4588 immutable source-retention state.
   *
   * Packet bytes remain in integration-owned final slabs. This state stores only opaque retention
   * tokens and bounded metadata, retaining at most two frame generations and 16 MiB. Release
   * callbacks let the packet-pool owner retire evicted tokens without heap allocation here.
   */
  class rtx_retention {
  public:
    /**
     * @brief Construct retention state over fixed caller-provided metadata slots.
     *
     * @param slots Metadata storage allocated during connection setup.
     */
    constexpr explicit rtx_retention(const std::span<rtx_retained_packet> slots) noexcept:
        slots_(slots) {
    }

    /**
     * @brief Retain an immutable final source slab until deadline or one RTT.
     *
     * @tparam Release Callable accepting an evicted nonzero token.
     * @param packet Source slab reference and media metadata.
     * @param now_microseconds Current monotonic time.
     * @param measured_rtt_microseconds Positive measured RTT.
     * @param release Called once for each token evicted before insertion.
     * @return Typed retention result.
     */
    template<class Release>
    constexpr rtx_retention_result retain(
      const rtx_packet_reference &packet,
      const std::uint64_t now_microseconds,
      const std::uint64_t measured_rtt_microseconds,
      Release &&release
    ) noexcept(noexcept(release(std::uint64_t {}))) {
      prune(now_microseconds, release);
      if (packet.token == 0 || packet.frame_id == 0 || packet.source_ssrc == 0 ||
          packet.video_generation == 0 || packet.protected_packet_bytes == 0 ||
          packet.protected_packet_bytes > maximum_rtx_retained_bytes ||
          packet.frame_deadline_microseconds <= now_microseconds) {
        return rtx_retention_result::invalid_packet;
      }
      if (measured_rtt_microseconds == 0) {
        return rtx_retention_result::invalid_rtt;
      }
      for (const auto &slot : slots_) {
        if (slot.occupied && slot.packet.video_generation == packet.video_generation &&
            slot.packet.source_ssrc == packet.source_ssrc &&
            slot.packet.source_sequence_number == packet.source_sequence_number) {
          return rtx_retention_result::duplicate_packet;
        }
      }

      while (!frame_is_retained(packet.frame_id) && retained_frame_count() >= maximum_rtx_frame_generations) {
        evict_oldest_frame(release, 0);
      }
      while (retained_bytes_ > maximum_rtx_retained_bytes - packet.protected_packet_bytes) {
        if (!evict_oldest_frame(release, packet.frame_id)) {
          return rtx_retention_result::byte_capacity_exceeded;
        }
      }

      auto *slot = first_free_slot();
      while (slot == nullptr) {
        if (!evict_oldest_frame(release, packet.frame_id)) {
          return rtx_retention_result::slot_capacity_exceeded;
        }
        slot = first_free_slot();
      }
      const auto rtt_expiry = now_microseconds > std::numeric_limits<std::uint64_t>::max() - measured_rtt_microseconds ?
                                std::numeric_limits<std::uint64_t>::max() :
                                now_microseconds + measured_rtt_microseconds;
      ++insertion_order_;
      if (insertion_order_ == 0) {
        insertion_order_ = 1;
      }
      *slot = {
        .packet = packet,
        .expires_microseconds = std::min(packet.frame_deadline_microseconds, rtt_expiry),
        .insertion_order = insertion_order_,
        .occupied = true,
      };
      retained_bytes_ += packet.protected_packet_bytes;
      ++retained_packets_;
      return rtx_retention_result::retained;
    }

    /**
     * @brief Release every source slab whose frame deadline or one-RTT retention expired.
     *
     * @tparam Release Callable accepting one nonzero token.
     * @param now_microseconds Current monotonic time.
     * @param release Called once per expired source-slab token.
     * @return Number of expired packet references.
     */
    template<class Release>
    constexpr std::size_t prune(
      const std::uint64_t now_microseconds,
      Release &&release
    ) noexcept(noexcept(release(std::uint64_t {}))) {
      std::size_t released = 0;
      for (auto &slot : slots_) {
        if (slot.occupied && now_microseconds >= slot.expires_microseconds) {
          release_slot(slot, release);
          ++released;
        }
      }
      return released;
    }

    /**
     * @brief Find a retained source packet only when an actual RTX remains deadline eligible.
     *
     * @param video_generation Active video generation.
     * @param source_ssrc Primary source SSRC.
     * @param source_sequence_number NACKed primary sequence number.
     * @param now_microseconds Current monotonic time.
     * @param estimate Complete retransmission timing estimate.
     * @return Opaque eligible source reference, or no value.
     */
    [[nodiscard]] constexpr std::optional<eligible_rtx_packet> find_eligible(
      const std::uint32_t video_generation,
      const std::uint32_t source_ssrc,
      const std::uint16_t source_sequence_number,
      const std::uint64_t now_microseconds,
      const rtx_deadline_estimate &estimate
    ) const noexcept {
      for (const auto &slot : slots_) {
        if (slot.occupied && slot.packet.video_generation == video_generation &&
            slot.packet.source_ssrc == source_ssrc &&
            slot.packet.source_sequence_number == source_sequence_number &&
            now_microseconds < slot.expires_microseconds &&
            rtx_deadline_eligible(now_microseconds, slot.packet.frame_deadline_microseconds, estimate)) {
          return eligible_rtx_packet {
            .token = slot.packet.token,
            .frame_id = slot.packet.frame_id,
            .protected_packet_bytes = slot.packet.protected_packet_bytes,
          };
        }
      }
      return std::nullopt;
    }

    /**
     * @brief Return retained immutable source bytes.
     *
     * @return Aggregate protected packet bytes, at most 16 MiB.
     */
    [[nodiscard]] constexpr std::size_t retained_bytes() const noexcept {
      return retained_bytes_;
    }

    /**
     * @brief Return retained packet-reference count.
     *
     * @return Occupied caller-storage slots.
     */
    [[nodiscard]] constexpr std::size_t retained_packets() const noexcept {
      return retained_packets_;
    }

    /**
     * @brief Return number of distinct retained frame generations.
     *
     * @return Zero through two frame generations.
     */
    [[nodiscard]] constexpr std::size_t retained_frame_count() const noexcept {
      std::uint64_t first_frame = 0;
      std::size_t count = 0;
      for (const auto &slot : slots_) {
        if (!slot.occupied) {
          continue;
        }
        if (count == 0) {
          first_frame = slot.packet.frame_id;
          count = 1;
        } else if (slot.packet.frame_id != first_frame) {
          return 2;
        }
      }
      return count;
    }

  private:
    /**
     * @brief Return whether one frame currently has retained packets.
     *
     * @param frame_id Candidate frame ID.
     * @return `true` when at least one occupied slot matches.
     */
    [[nodiscard]] constexpr bool frame_is_retained(const std::uint64_t frame_id) const noexcept {
      return std::any_of(slots_.begin(), slots_.end(), [frame_id](const rtx_retained_packet &slot) {
        return slot.occupied && slot.packet.frame_id == frame_id;
      });
    }

    /**
     * @brief Return the first unoccupied caller storage slot.
     *
     * @return Slot pointer, or null when storage is full.
     */
    [[nodiscard]] constexpr rtx_retained_packet *first_free_slot() noexcept {
      const auto found = std::find_if(slots_.begin(), slots_.end(), [](const rtx_retained_packet &slot) {
        return !slot.occupied;
      });
      return found == slots_.end() ? nullptr : &*found;
    }

    /**
     * @brief Release one occupied metadata slot and update aggregate bounds.
     *
     * @tparam Release Callable accepting one token.
     * @param slot Occupied slot to release.
     * @param release Integration packet-pool callback.
     */
    template<class Release>
    constexpr void release_slot(
      rtx_retained_packet &slot,
      Release &release
    ) noexcept(noexcept(release(std::uint64_t {}))) {
      release(slot.packet.token);
      retained_bytes_ -= slot.packet.protected_packet_bytes;
      --retained_packets_;
      slot = {};
    }

    /**
     * @brief Evict the oldest complete frame other than an optional protected frame.
     *
     * @tparam Release Callable accepting one token.
     * @param release Integration packet-pool callback.
     * @param protected_frame Frame that must not be evicted, or zero.
     * @return `true` when one frame was evicted.
     */
    template<class Release>
    constexpr bool evict_oldest_frame(
      Release &release,
      const std::uint64_t protected_frame
    ) noexcept(noexcept(release(std::uint64_t {}))) {
      std::uint64_t oldest_frame = 0;
      std::uint64_t oldest_order = std::numeric_limits<std::uint64_t>::max();
      for (const auto &slot : slots_) {
        if (slot.occupied && slot.packet.frame_id != protected_frame && slot.insertion_order < oldest_order) {
          oldest_order = slot.insertion_order;
          oldest_frame = slot.packet.frame_id;
        }
      }
      if (oldest_frame == 0) {
        return false;
      }
      for (auto &slot : slots_) {
        if (slot.occupied && slot.packet.frame_id == oldest_frame) {
          release_slot(slot, release);
        }
      }
      return true;
    }

    std::span<rtx_retained_packet> slots_ {};  ///< Caller-owned fixed metadata storage.
    std::size_t retained_bytes_ = 0;  ///< Aggregate immutable source-slab bytes.
    std::size_t retained_packets_ = 0;  ///< Occupied metadata slot count.
    std::uint64_t insertion_order_ = 0;  ///< Local monotonic retention order.
  };

  /** @brief Cause that legitimately opens a frame-recovery epoch. */
  enum class recovery_cause : std::uint8_t {
    unrecoverable_reference_loss,  ///< FEC, RTX, and reference invalidation cannot repair a lost reference.
    decoder_unrecoverable,  ///< Decoder explicitly reported unrecoverable state.
    unexpected_partial_frame,  ///< Mid-frame submission failed after admission.
  };

  /** @brief Sender recovery-epoch lifecycle. */
  enum class recovery_phase : std::uint8_t {
    healthy,  ///< No recovery epoch is active.
    repairing_references,  ///< Epoch is active before an independent frame is required.
    recovery_frame_outstanding,  ///< Exactly one independent recovery frame awaits decode confirmation.
    retry_permitted,  ///< Prior recovery deadline expired with explicit decode-failure evidence.
  };

  /** @brief Typed recovery state transition result. */
  enum class recovery_result : std::uint8_t {
    accepted,  ///< Transition completed successfully.
    already_active,  ///< Repeated damage belongs to the existing epoch.
    no_active_epoch,  ///< Operation requires an active recovery epoch.
    invalid_frame,  ///< Independent recovery frame ID or deadline is invalid.
    recovery_already_outstanding,  ///< One independent recovery frame already awaits confirmation.
    stale_epoch,  ///< Feedback names a different recovery epoch.
    wrong_recovery_frame,  ///< Decode feedback does not name the outstanding recovery frame.
    deadline_not_expired,  ///< Retry requested before the outstanding recovery deadline.
    failure_evidence_required,  ///< A retry cannot be opened without evidence the prior recovery did not decode.
    epoch_exhausted,  ///< Recovery epoch cannot advance without re-establishing the session.
  };

  /** @brief Snapshot of bounded sender recovery state. */
  struct recovery_snapshot {
    std::uint32_t epoch = 0;  ///< Current monotonically increasing recovery epoch, or zero.
    recovery_phase phase = recovery_phase::healthy;  ///< Current recovery lifecycle phase.
    recovery_cause cause = recovery_cause::unrecoverable_reference_loss;  ///< Cause that opened the epoch.
    std::uint64_t damaged_frame_id = 0;  ///< First damaged frame in the epoch.
    std::uint64_t outstanding_recovery_frame_id = 0;  ///< Independent frame awaiting decode confirmation.
    std::uint64_t recovery_deadline_microseconds = 0;  ///< Outstanding recovery deadline.
  };

  /** @brief One-epoch, one-outstanding-frame LSP video recovery controller. */
  class recovery_controller {
  public:
    /**
     * @brief Open a new recovery epoch or coalesce repeated damage into the active epoch.
     *
     * @param damaged_frame_id Nonzero damaged source frame.
     * @param cause Legitimate repair or decoder cause.
     * @return Typed transition result.
     */
    constexpr recovery_result report_unrecoverable_damage(
      const std::uint64_t damaged_frame_id,
      const recovery_cause cause
    ) noexcept {
      if (damaged_frame_id == 0) {
        return recovery_result::invalid_frame;
      }
      if (phase_ != recovery_phase::healthy) {
        return recovery_result::already_active;
      }
      if (epoch_ == std::numeric_limits<std::uint32_t>::max()) {
        return recovery_result::epoch_exhausted;
      }
      ++epoch_;
      phase_ = recovery_phase::repairing_references;
      cause_ = cause;
      damaged_frame_id_ = damaged_frame_id;
      outstanding_recovery_frame_id_ = 0;
      recovery_deadline_microseconds_ = 0;
      return recovery_result::accepted;
    }

    /**
     * @brief Register the single independent recovery frame for the active epoch.
     *
     * Repeated PLI/FIR feedback cannot schedule another frame while one is outstanding.
     *
     * @param frame_id Nonzero independent recovery frame ID.
     * @param now_microseconds Current monotonic time.
     * @param deadline_microseconds Strict future recovery deadline.
     * @return Typed transition result.
     */
    constexpr recovery_result mark_independent_frame_sent(
      const std::uint64_t frame_id,
      const std::uint64_t now_microseconds,
      const std::uint64_t deadline_microseconds
    ) noexcept {
      if (phase_ == recovery_phase::healthy) {
        return recovery_result::no_active_epoch;
      }
      if (phase_ == recovery_phase::recovery_frame_outstanding) {
        return recovery_result::recovery_already_outstanding;
      }
      if (frame_id == 0 || deadline_microseconds <= now_microseconds) {
        return recovery_result::invalid_frame;
      }
      outstanding_recovery_frame_id_ = frame_id;
      recovery_deadline_microseconds_ = deadline_microseconds;
      phase_ = recovery_phase::recovery_frame_outstanding;
      return recovery_result::accepted;
    }

    /**
     * @brief Permit exactly one new recovery attempt after deadline and explicit failure evidence.
     *
     * @param now_microseconds Current monotonic time.
     * @param failed_to_decode Whether protected receiver status proves decode failure.
     * @return Typed transition result.
     */
    constexpr recovery_result permit_retry(
      const std::uint64_t now_microseconds,
      const bool failed_to_decode
    ) noexcept {
      if (phase_ != recovery_phase::recovery_frame_outstanding) {
        return recovery_result::no_active_epoch;
      }
      if (now_microseconds < recovery_deadline_microseconds_) {
        return recovery_result::deadline_not_expired;
      }
      if (!failed_to_decode) {
        return recovery_result::failure_evidence_required;
      }
      outstanding_recovery_frame_id_ = 0;
      recovery_deadline_microseconds_ = 0;
      phase_ = recovery_phase::retry_permitted;
      return recovery_result::accepted;
    }

    /**
     * @brief Leave recovery only after the outstanding independent frame decodes successfully.
     *
     * @param epoch Recovery epoch named by protected `LSPV` status.
     * @param decoded_frame_id Successfully decoded independent frame ID.
     * @return Typed transition result.
     */
    constexpr recovery_result confirm_recovery_decoded(
      const std::uint32_t epoch,
      const std::uint64_t decoded_frame_id
    ) noexcept {
      if (phase_ != recovery_phase::recovery_frame_outstanding) {
        return recovery_result::no_active_epoch;
      }
      if (epoch != epoch_) {
        return recovery_result::stale_epoch;
      }
      if (decoded_frame_id != outstanding_recovery_frame_id_) {
        return recovery_result::wrong_recovery_frame;
      }
      phase_ = recovery_phase::healthy;
      damaged_frame_id_ = 0;
      outstanding_recovery_frame_id_ = 0;
      recovery_deadline_microseconds_ = 0;
      return recovery_result::accepted;
    }

    /**
     * @brief Return immutable recovery state.
     *
     * @return Current recovery snapshot.
     */
    [[nodiscard]] constexpr recovery_snapshot snapshot() const noexcept {
      return {
        .epoch = epoch_,
        .phase = phase_,
        .cause = cause_,
        .damaged_frame_id = damaged_frame_id_,
        .outstanding_recovery_frame_id = outstanding_recovery_frame_id_,
        .recovery_deadline_microseconds = recovery_deadline_microseconds_,
      };
    }

  private:
    std::uint32_t epoch_ = 0;  ///< Monotonic recovery epoch, never wrapping to zero.
    recovery_phase phase_ = recovery_phase::healthy;  ///< Active recovery lifecycle phase.
    recovery_cause cause_ = recovery_cause::unrecoverable_reference_loss;  ///< Epoch-opening cause.
    std::uint64_t damaged_frame_id_ = 0;  ///< First damaged frame in the epoch.
    std::uint64_t outstanding_recovery_frame_id_ = 0;  ///< Single independent recovery frame.
    std::uint64_t recovery_deadline_microseconds_ = 0;  ///< Deadline for decode confirmation.
  };
}  // namespace lumen::lsp::transport
