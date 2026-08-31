/**
 * @file src/lsp/transport/repair.h
 * @brief Allocation-free LSP FlexFEC, RTX, and recovery-epoch state.
 */

#pragma once

#include <algorithm>
#include <array>
#include <bit>
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

  /**
   * @brief Return whether a payload type is in LSP's negotiated dynamic RTP range.
   *
   * @param payload_type Candidate seven-bit RTP payload type.
   * @return `true` only for payload types 96 through 127 inclusive.
   */
  [[nodiscard]] constexpr bool valid_lsp_dynamic_payload_type(const std::uint8_t payload_type) noexcept {
    return payload_type >= 96U && payload_type <= 127U;
  }

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
    invalid_source_packet,  ///< Source is not the named complete RTP version-2 packet.
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
    std::uint16_t length_recovery = 0;  ///< XOR of source lengths after the fixed RTP header.
    std::uint32_t timestamp_recovery = 0;  ///< XOR of source RTP timestamps.
    std::uint64_t source_mask = 0;  ///< Source sequence offsets included in parity.
    std::span<const std::uint8_t> parity {};  ///< Zero-padded XOR of bytes after the fixed RTP header.
    std::uint8_t first_header_recovery = 0;  ///< XOR of source RTP P, X, and CC bits.
    std::uint8_t second_header_recovery = 0;  ///< XOR of source RTP M and payload-type bits.
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
     * @param parity_storage Maximum source tail XOR storage retained for the group lifetime.
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
      timestamp_recovery_ = 0;
      parity_size_ = 0;
      source_mask_ = 0;
      source_count_ = 0;
      first_header_recovery_ = 0;
      second_header_recovery_ = 0;
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
      constexpr auto fixed_header_size = std::size_t {12};
      if (plaintext_packet.size() < fixed_header_size ||
          plaintext_packet.size() - fixed_header_size > parity_storage_.size() ||
          plaintext_packet.size() - fixed_header_size > std::numeric_limits<std::uint16_t>::max()) {
        return flexfec_result::invalid_storage;
      }
      const auto packet_sequence = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(plaintext_packet[2]) << 8U) |
        plaintext_packet[3]
      );
      const auto packet_ssrc = (static_cast<std::uint32_t>(plaintext_packet[8]) << 24U) |
                               (static_cast<std::uint32_t>(plaintext_packet[9]) << 16U) |
                               (static_cast<std::uint32_t>(plaintext_packet[10]) << 8U) |
                               plaintext_packet[11];
      if ((plaintext_packet[0] >> 6U) != 2U || packet_sequence != sequence_number || packet_ssrc != primary_ssrc) {
        return flexfec_result::invalid_source_packet;
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
      const auto source_tail = plaintext_packet.subspan(fixed_header_size);
      for (std::size_t index = 0; index < source_tail.size(); ++index) {
        parity_storage_[index] ^= source_tail[index];
      }
      first_header_recovery_ ^= static_cast<std::uint8_t>(plaintext_packet[0] & 0x3fU);
      second_header_recovery_ ^= plaintext_packet[1];
      timestamp_recovery_ ^= (static_cast<std::uint32_t>(plaintext_packet[4]) << 24U) |
                             (static_cast<std::uint32_t>(plaintext_packet[5]) << 16U) |
                             (static_cast<std::uint32_t>(plaintext_packet[6]) << 8U) |
                             plaintext_packet[7];
      source_mask_ |= bit;
      ++source_count_;
      parity_size_ = std::max(parity_size_, source_tail.size());
      length_recovery_ ^= static_cast<std::uint16_t>(source_tail.size());
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
        .timestamp_recovery = timestamp_recovery_,
        .source_mask = source_mask_,
        .parity = parity_storage_.first(parity_size_),
        .first_header_recovery = first_header_recovery_,
        .second_header_recovery = second_header_recovery_,
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
    std::span<std::uint8_t> parity_storage_ {};  ///< Caller-owned incremental source-tail XOR storage.
    std::uint64_t frame_id_ = 0;  ///< Active encoded frame ID.
    std::uint64_t source_mask_ = 0;  ///< Included source-sequence offsets.
    std::uint32_t primary_ssrc_ = 0;  ///< Protected primary video SSRC.
    std::uint32_t repair_ssrc_ = 0;  ///< FlexFEC repair SSRC.
    std::size_t parity_size_ = 0;  ///< Largest included source-tail size.
    std::uint16_t base_sequence_number_ = 0;  ///< First sequence in the mask space.
    std::uint16_t length_recovery_ = 0;  ///< XOR of included source lengths.
    std::uint32_t timestamp_recovery_ = 0;  ///< XOR of included source timestamps.
    std::size_t source_count_ = 0;  ///< Number of distinct included sources.
    std::uint8_t first_header_recovery_ = 0;  ///< XOR of source P, X, and CC bits.
    std::uint8_t second_header_recovery_ = 0;  ///< XOR of source M and payload-type bits.
    flexfec_phase phase_ = flexfec_phase::idle;  ///< FEC-before-SRTP lifecycle phase.
  };

  /** @brief Fixed RTP header plus one protected-source CSRC in an LSP FlexFEC repair packet. */
  inline constexpr std::size_t flexfec_repair_rtp_header_size = 16;

  /** @brief Smallest RFC 8627 flexible-mask FEC header. */
  inline constexpr std::size_t flexfec_minimum_header_size = 12;

  /** @brief Largest RFC 8627 flexible-mask FEC header. */
  inline constexpr std::size_t flexfec_maximum_header_size = 24;

  /** @brief RTP metadata assigned independently to one outgoing repair stream packet. */
  struct flexfec_repair_rtp_header {
    std::uint8_t payload_type = 0;  ///< Negotiated dynamic FlexFEC payload type.
    std::uint16_t sequence_number = 0;  ///< Monotonic repair-stream RTP sequence number.
    std::uint32_t timestamp = 0;  ///< Repair transmission-time RTP timestamp.
  };

  /** @brief Typed RFC 8627 flexible-mask wire or reconstruction failure. */
  enum class flexfec_wire_error : std::uint8_t {
    none,  ///< Operation completed successfully.
    invalid_identifier,  ///< A required SSRC is zero or source and repair SSRCs collide.
    invalid_payload_type,  ///< Repair payload type is outside LSP's dynamic range 96 through 127.
    invalid_source_mask,  ///< Mask is empty, omits its base, or exceeds the LSP 64-packet group.
    malformed_packet,  ///< RTP, FEC header, padding, extension, or recovered packet is malformed.
    unsupported_variant,  ///< Packet does not use the RFC 8627 R=0, F=0 flexible-mask variant.
    destination_too_small,  ///< Caller storage cannot contain the complete output packet.
    source_set_mismatch,  ///< Decoder sources do not exactly cover every non-missing protected packet.
  };

  /** @brief Result of constructing one plaintext RFC 8627 repair RTP packet. */
  struct flexfec_write_result {
    std::size_t bytes_written = 0;  ///< Complete plaintext repair RTP bytes on success.
    flexfec_wire_error error = flexfec_wire_error::none;  ///< Typed construction status.

    /**
     * @brief Return whether packet construction succeeded.
     *
     * @return `true` only when a complete repair packet was written.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == flexfec_wire_error::none;
    }
  };

  /** @brief Borrowed RFC 8627 single-source flexible-mask repair packet. */
  struct flexfec_repair_view {
    std::uint32_t primary_ssrc = 0;  ///< Protected source SSRC from the repair RTP CSRC list.
    std::uint32_t repair_ssrc = 0;  ///< Repair RTP synchronization source.
    std::uint32_t repair_timestamp = 0;  ///< Repair RTP transmission timestamp.
    std::uint32_t timestamp_recovery = 0;  ///< XOR of protected source RTP timestamps.
    std::uint64_t source_mask = 0;  ///< LSB-first local representation of offsets zero through 63.
    std::uint16_t repair_sequence_number = 0;  ///< Repair-stream RTP sequence number.
    std::uint16_t base_sequence_number = 0;  ///< Lowest protected source sequence number.
    std::uint16_t length_recovery = 0;  ///< XOR of protected source lengths after byte 12.
    std::span<const std::uint8_t> repair_payload {};  ///< Tail parity following the variable FEC header.
    std::uint8_t repair_payload_type = 0;  ///< Negotiated repair RTP payload type observed on wire.
    std::uint8_t first_header_recovery = 0;  ///< Recovered P, X, and CC parity bits.
    std::uint8_t second_header_recovery = 0;  ///< Recovered M and payload-type parity bits.
  };

  /** @brief Result of parsing one decrypted RFC 8627 repair RTP packet. */
  struct flexfec_parse_result {
    flexfec_repair_view repair {};  ///< Borrowed parsed repair fields and parity payload.
    std::size_t fec_header_bytes = 0;  ///< Variable FEC header length, 12, 16, or 24 bytes.
    flexfec_wire_error error = flexfec_wire_error::none;  ///< Typed parse status.

    /**
     * @brief Return whether parsing succeeded.
     *
     * @return `true` only for a complete supported repair packet.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == flexfec_wire_error::none;
    }
  };

  /** @brief Result of reconstructing one plaintext source RTP packet. */
  struct flexfec_decode_result {
    std::size_t bytes_written = 0;  ///< Complete recovered source RTP bytes on success.
    flexfec_wire_error error = flexfec_wire_error::none;  ///< Typed reconstruction status.

    /**
     * @brief Return whether reconstruction succeeded.
     *
     * @return `true` only when one complete source packet was recovered.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == flexfec_wire_error::none;
    }
  };

  namespace repair_detail {
    /**
     * @brief Read one network-order 16-bit integer.
     *
     * @param bytes Input containing at least two bytes.
     * @return Host-order value.
     */
    [[nodiscard]] constexpr std::uint16_t read_u16(const std::span<const std::uint8_t> bytes) noexcept {
      return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[0]) << 8U) | bytes[1]);
    }

    /**
     * @brief Read one network-order 32-bit integer.
     *
     * @param bytes Input containing at least four bytes.
     * @return Host-order value.
     */
    [[nodiscard]] constexpr std::uint32_t read_u32(const std::span<const std::uint8_t> bytes) noexcept {
      return (static_cast<std::uint32_t>(bytes[0]) << 24U) |
             (static_cast<std::uint32_t>(bytes[1]) << 16U) |
             (static_cast<std::uint32_t>(bytes[2]) << 8U) |
             bytes[3];
    }

    /**
     * @brief Read one network-order 64-bit integer.
     *
     * @param bytes Input containing at least eight bytes.
     * @return Host-order value.
     */
    [[nodiscard]] constexpr std::uint64_t read_u64(const std::span<const std::uint8_t> bytes) noexcept {
      return (static_cast<std::uint64_t>(read_u32(bytes.first(4))) << 32U) |
             read_u32(bytes.subspan(4, 4));
    }

    /**
     * @brief Write one network-order 16-bit integer.
     *
     * @param bytes Output containing at least two bytes.
     * @param value Host-order value.
     */
    constexpr void write_u16(const std::span<std::uint8_t> bytes, const std::uint16_t value) noexcept {
      bytes[0] = static_cast<std::uint8_t>(value >> 8U);
      bytes[1] = static_cast<std::uint8_t>(value);
    }

    /**
     * @brief Write one network-order 32-bit integer.
     *
     * @param bytes Output containing at least four bytes.
     * @param value Host-order value.
     */
    constexpr void write_u32(const std::span<std::uint8_t> bytes, const std::uint32_t value) noexcept {
      bytes[0] = static_cast<std::uint8_t>(value >> 24U);
      bytes[1] = static_cast<std::uint8_t>(value >> 16U);
      bytes[2] = static_cast<std::uint8_t>(value >> 8U);
      bytes[3] = static_cast<std::uint8_t>(value);
    }

    /**
     * @brief Write one network-order 64-bit integer.
     *
     * @param bytes Output containing at least eight bytes.
     * @param value Host-order value.
     */
    constexpr void write_u64(const std::span<std::uint8_t> bytes, const std::uint64_t value) noexcept {
      write_u32(bytes.first(4), static_cast<std::uint32_t>(value >> 32U));
      write_u32(bytes.subspan(4, 4), static_cast<std::uint32_t>(value));
    }

    /**
     * @brief Return the smallest RFC 8627 mask header that represents a local 64-bit mask.
     *
     * @param source_mask LSB-first source-offset mask.
     * @return FEC header bytes, or zero for an invalid mask.
     */
    [[nodiscard]] constexpr std::size_t flexfec_header_size(const std::uint64_t source_mask) noexcept {
      if (source_mask == 0 || (source_mask & 1U) == 0) {
        return 0;
      }
      const auto used_bits = static_cast<std::size_t>(std::bit_width(source_mask));
      if (used_bits <= 15U) {
        return 12;
      }
      if (used_bits <= 46U) {
        return 16;
      }
      return 24;
    }

    /**
     * @brief Encode an LSB-first local mask into RFC 8627 MSB-first mask fields.
     *
     * @param source_mask Local source mask.
     * @param fec_header Complete variable-size FEC header.
     */
    constexpr void write_source_mask(
      const std::uint64_t source_mask,
      const std::span<std::uint8_t> fec_header
    ) noexcept {
      std::uint16_t first = fec_header.size() > 12U ? 0x8000U : 0U;
      for (std::size_t offset = 0; offset < 15U; ++offset) {
        if ((source_mask & (std::uint64_t {1} << offset)) != 0) {
          first |= static_cast<std::uint16_t>(std::uint16_t {1} << (14U - offset));
        }
      }
      write_u16(fec_header.subspan(10, 2), first);
      if (fec_header.size() == 12U) {
        return;
      }
      std::uint32_t second = fec_header.size() > 16U ? 0x8000'0000U : 0U;
      for (std::size_t offset = 15; offset < 46U; ++offset) {
        if ((source_mask & (std::uint64_t {1} << offset)) != 0) {
          second |= std::uint32_t {1} << (45U - offset);
        }
      }
      write_u32(fec_header.subspan(12, 4), second);
      if (fec_header.size() == 16U) {
        return;
      }
      std::uint64_t third = 0;
      for (std::size_t offset = 46; offset < maximum_flexfec_group_packets; ++offset) {
        if ((source_mask & (std::uint64_t {1} << offset)) != 0) {
          third |= std::uint64_t {1} << (109U - offset);
        }
      }
      write_u64(fec_header.subspan(16, 8), third);
    }

    /**
     * @brief Decode one supported RFC 8627 mask and reject nonzero offsets above 63.
     *
     * @param fec_payload FEC header and repair payload bytes.
     * @param source_mask Receives the LSB-first local source mask.
     * @return Parsed FEC header size, or zero on malformed input.
     */
    [[nodiscard]] constexpr std::size_t read_source_mask(
      const std::span<const std::uint8_t> fec_payload,
      std::uint64_t &source_mask
    ) noexcept {
      if (fec_payload.size() < 12U) {
        return 0;
      }
      source_mask = 0;
      const auto first = read_u16(fec_payload.subspan(10, 2));
      for (std::size_t offset = 0; offset < 15U; ++offset) {
        if ((first & (std::uint16_t {1} << (14U - offset))) != 0) {
          source_mask |= std::uint64_t {1} << offset;
        }
      }
      if ((first & 0x8000U) == 0) {
        return 12;
      }
      if (fec_payload.size() < 16U) {
        return 0;
      }
      const auto second = read_u32(fec_payload.subspan(12, 4));
      for (std::size_t offset = 15; offset < 46U; ++offset) {
        if ((second & (std::uint32_t {1} << (45U - offset))) != 0) {
          source_mask |= std::uint64_t {1} << offset;
        }
      }
      if ((second & 0x8000'0000U) == 0) {
        return 16;
      }
      if (fec_payload.size() < 24U) {
        return 0;
      }
      const auto third = read_u64(fec_payload.subspan(16, 8));
      for (std::size_t offset = 46; offset < maximum_flexfec_group_packets; ++offset) {
        if ((third & (std::uint64_t {1} << (109U - offset))) != 0) {
          source_mask |= std::uint64_t {1} << offset;
        }
      }
      constexpr auto unsupported_mask = (std::uint64_t {1} << 46U) - 1U;
      if ((third & unsupported_mask) != 0) {
        return 0;
      }
      return 24;
    }

    /**
     * @brief Validate optional fields in a reconstructed variable RTP header.
     *
     * @param packet Complete recovered RTP packet.
     * @return `true` when CSRC, extension, and padding bounds are valid.
     */
    [[nodiscard]] constexpr bool valid_recovered_rtp(const std::span<const std::uint8_t> packet) noexcept {
      if (packet.size() < 12U || (packet[0] >> 6U) != 2U) {
        return false;
      }
      const auto csrc_bytes = std::size_t {packet[0] & 0x0fU} * 4U;
      auto header_bytes = 12U + csrc_bytes;
      if (packet.size() < header_bytes) {
        return false;
      }
      if ((packet[0] & 0x10U) != 0) {
        if (packet.size() < header_bytes + 4U) {
          return false;
        }
        const auto extension_words = read_u16(packet.subspan(header_bytes + 2U, 2));
        const auto extension_bytes = std::size_t {extension_words} * 4U;
        if (extension_bytes > packet.size() - header_bytes - 4U) {
          return false;
        }
        header_bytes += 4U + extension_bytes;
      }
      if ((packet[0] & 0x20U) != 0) {
        const auto padding = packet.back();
        if (padding == 0 || padding > packet.size() - header_bytes) {
          return false;
        }
      }
      return true;
    }
  }  // namespace repair_detail

  /**
   * @brief Construct one plaintext RFC 8627 single-source flexible-mask repair RTP packet.
   *
   * The RTP CSRC list contains exactly the protected source SSRC. The FEC header uses the 15-,
   * 46-, or 110-bit form selected by the highest protected offset, while LSP rejects offsets above
   * 63. The returned packet must be protected under the negotiated repair SRTP context.
   *
   * @param parity Sealed incremental RFC 8627 recovery fields and tail parity.
   * @param repair_header Repair-stream RTP fields.
   * @param destination Caller-owned plaintext packet storage.
   * @return Complete packet byte count and typed status.
   */
  [[nodiscard]] constexpr flexfec_write_result write_flexfec_repair(
    const flexfec_parity_view &parity,
    const flexfec_repair_rtp_header &repair_header,
    const std::span<std::uint8_t> destination
  ) noexcept {
    if (parity.primary_ssrc == 0 || parity.repair_ssrc == 0 || parity.primary_ssrc == parity.repair_ssrc) {
      return {.error = flexfec_wire_error::invalid_identifier};
    }
    if (!valid_lsp_dynamic_payload_type(repair_header.payload_type)) {
      return {.error = flexfec_wire_error::invalid_payload_type};
    }
    const auto fec_header_bytes = repair_detail::flexfec_header_size(parity.source_mask);
    if (fec_header_bytes == 0) {
      return {.error = flexfec_wire_error::invalid_source_mask};
    }
    const auto required = flexfec_repair_rtp_header_size + fec_header_bytes + parity.parity.size();
    if (destination.size() < required) {
      return {.error = flexfec_wire_error::destination_too_small};
    }
    const auto packet = destination.first(required);
    packet[0] = 0x81U;
    packet[1] = repair_header.payload_type;
    repair_detail::write_u16(packet.subspan(2, 2), repair_header.sequence_number);
    repair_detail::write_u32(packet.subspan(4, 4), repair_header.timestamp);
    repair_detail::write_u32(packet.subspan(8, 4), parity.repair_ssrc);
    repair_detail::write_u32(packet.subspan(12, 4), parity.primary_ssrc);

    const auto fec_header = packet.subspan(flexfec_repair_rtp_header_size, fec_header_bytes);
    std::fill(fec_header.begin(), fec_header.end(), 0);
    fec_header[0] = static_cast<std::uint8_t>(parity.first_header_recovery & 0x3fU);
    fec_header[1] = parity.second_header_recovery;
    repair_detail::write_u16(fec_header.subspan(2, 2), parity.length_recovery);
    repair_detail::write_u32(fec_header.subspan(4, 4), parity.timestamp_recovery);
    repair_detail::write_u16(fec_header.subspan(8, 2), parity.base_sequence_number);
    repair_detail::write_source_mask(parity.source_mask, fec_header);
    std::copy(parity.parity.begin(), parity.parity.end(), packet.begin() + static_cast<std::ptrdiff_t>(flexfec_repair_rtp_header_size + fec_header_bytes));
    return {.bytes_written = required};
  }

  /**
   * @brief Parse one authenticated and decrypted RFC 8627 single-source repair RTP packet.
   *
   * Repair RTP padding and header extensions are bounded and skipped. LSP accepts only one CSRC,
   * the R=0/F=0 flexible-mask variant, and source offsets zero through 63.
   *
   * @param packet Complete decrypted repair RTP packet.
   * @return Borrowed repair view and typed status.
   */
  [[nodiscard]] constexpr flexfec_parse_result parse_flexfec_repair(
    const std::span<const std::uint8_t> packet
  ) noexcept {
    if (packet.size() < flexfec_repair_rtp_header_size + flexfec_minimum_header_size ||
        (packet[0] >> 6U) != 2U) {
      return {.error = flexfec_wire_error::malformed_packet};
    }
    const auto csrc_count = static_cast<std::uint8_t>(packet[0] & 0x0fU);
    const auto repair_ssrc = repair_detail::read_u32(packet.subspan(8, 4));
    const auto primary_ssrc = repair_detail::read_u32(packet.subspan(12, 4));
    if (csrc_count != 1U) {
      return {.error = flexfec_wire_error::malformed_packet};
    }
    if (repair_ssrc == 0 || primary_ssrc == 0 || repair_ssrc == primary_ssrc) {
      return {.error = flexfec_wire_error::invalid_identifier};
    }
    auto payload_offset = flexfec_repair_rtp_header_size;
    if ((packet[0] & 0x10U) != 0) {
      if (packet.size() < payload_offset + 4U) {
        return {.error = flexfec_wire_error::malformed_packet};
      }
      const auto extension_words = repair_detail::read_u16(packet.subspan(payload_offset + 2U, 2));
      const auto extension_bytes = std::size_t {extension_words} * 4U;
      if (extension_bytes > packet.size() - payload_offset - 4U) {
        return {.error = flexfec_wire_error::malformed_packet};
      }
      payload_offset += 4U + extension_bytes;
    }
    auto payload_end = packet.size();
    if ((packet[0] & 0x20U) != 0) {
      const auto padding = packet.back();
      if (padding == 0 || padding > payload_end - payload_offset) {
        return {.error = flexfec_wire_error::malformed_packet};
      }
      payload_end -= padding;
    }
    if (payload_end < payload_offset + flexfec_minimum_header_size) {
      return {.error = flexfec_wire_error::malformed_packet};
    }
    const auto fec_payload = packet.subspan(payload_offset, payload_end - payload_offset);
    if ((fec_payload[0] & 0xc0U) != 0) {
      return {.error = flexfec_wire_error::unsupported_variant};
    }
    std::uint64_t source_mask = 0;
    const auto fec_header_bytes = repair_detail::read_source_mask(fec_payload, source_mask);
    if (fec_header_bytes == 0) {
      return {.error = flexfec_wire_error::malformed_packet};
    }
    if (source_mask == 0 || (source_mask & 1U) == 0) {
      return {.error = flexfec_wire_error::invalid_source_mask};
    }
    return {
      .repair = {
        .primary_ssrc = primary_ssrc,
        .repair_ssrc = repair_ssrc,
        .repair_timestamp = repair_detail::read_u32(packet.subspan(4, 4)),
        .timestamp_recovery = repair_detail::read_u32(fec_payload.subspan(4, 4)),
        .source_mask = source_mask,
        .repair_sequence_number = repair_detail::read_u16(packet.subspan(2, 2)),
        .base_sequence_number = repair_detail::read_u16(fec_payload.subspan(8, 2)),
        .length_recovery = repair_detail::read_u16(fec_payload.subspan(2, 2)),
        .repair_payload = fec_payload.subspan(fec_header_bytes),
        .repair_payload_type = static_cast<std::uint8_t>(packet[1] & 0x7fU),
        .first_header_recovery = static_cast<std::uint8_t>(fec_payload[0] & 0x3fU),
        .second_header_recovery = fec_payload[1],
      },
      .fec_header_bytes = fec_header_bytes,
    };
  }

  /**
   * @brief Recover exactly one missing plaintext source RTP packet from authenticated inputs.
   *
   * `received_sources` must contain every protected source except `missing_sequence_number`, once
   * each. The function reconstructs the RFC 8627 fixed header recovery fields and tail parity into
   * caller storage. Authentication, negotiated-field admission, and the shared replay window remain
   * mandatory after this mechanical decoder succeeds.
   *
   * @param repair Parsed authenticated and decrypted repair packet.
   * @param missing_sequence_number Protected sequence number to reconstruct.
   * @param received_sources Authenticated and decrypted source packets in arbitrary order.
   * @param destination Caller-owned recovered plaintext packet storage.
   * @return Complete recovered source size and typed status.
   */
  [[nodiscard]] constexpr flexfec_decode_result recover_flexfec_source(
    const flexfec_repair_view &repair,
    const std::uint16_t missing_sequence_number,
    const std::span<const std::span<const std::uint8_t>> received_sources,
    const std::span<std::uint8_t> destination
  ) noexcept {
    if (repair.primary_ssrc == 0 || repair.repair_ssrc == 0 || repair.primary_ssrc == repair.repair_ssrc) {
      return {.error = flexfec_wire_error::invalid_identifier};
    }
    const auto missing_offset = static_cast<std::uint16_t>(missing_sequence_number - repair.base_sequence_number);
    if (missing_offset >= maximum_flexfec_group_packets ||
        (repair.source_mask & (std::uint64_t {1} << missing_offset)) == 0 ||
        (repair.source_mask & 1U) == 0) {
      return {.error = flexfec_wire_error::invalid_source_mask};
    }
    const auto expected_sources = static_cast<std::size_t>(std::popcount(repair.source_mask)) - 1U;
    if (received_sources.size() != expected_sources) {
      return {.error = flexfec_wire_error::source_set_mismatch};
    }

    auto first_recovery = repair.first_header_recovery;
    auto second_recovery = repair.second_header_recovery;
    auto length_recovery = repair.length_recovery;
    auto timestamp_recovery = repair.timestamp_recovery;
    std::uint64_t received_mask = 0;
    for (const auto source : received_sources) {
      if (source.size() < 12U || source.size() - 12U > std::numeric_limits<std::uint16_t>::max() ||
          source.size() - 12U > repair.repair_payload.size() || (source[0] >> 6U) != 2U ||
          repair_detail::read_u32(source.subspan(8, 4)) != repair.primary_ssrc ||
          !repair_detail::valid_recovered_rtp(source)) {
        return {.error = flexfec_wire_error::source_set_mismatch};
      }
      const auto sequence_number = repair_detail::read_u16(source.subspan(2, 2));
      const auto offset = static_cast<std::uint16_t>(sequence_number - repair.base_sequence_number);
      if (offset >= maximum_flexfec_group_packets || offset == missing_offset) {
        return {.error = flexfec_wire_error::source_set_mismatch};
      }
      const auto bit = std::uint64_t {1} << offset;
      if ((repair.source_mask & bit) == 0 || (received_mask & bit) != 0) {
        return {.error = flexfec_wire_error::source_set_mismatch};
      }
      received_mask |= bit;
      first_recovery ^= static_cast<std::uint8_t>(source[0] & 0x3fU);
      second_recovery ^= source[1];
      length_recovery ^= static_cast<std::uint16_t>(source.size() - 12U);
      timestamp_recovery ^= repair_detail::read_u32(source.subspan(4, 4));
    }
    const auto expected_mask = repair.source_mask & ~(std::uint64_t {1} << missing_offset);
    if (received_mask != expected_mask) {
      return {.error = flexfec_wire_error::source_set_mismatch};
    }

    const auto recovered_tail_bytes = static_cast<std::size_t>(length_recovery);
    const auto recovered_packet_bytes = 12U + recovered_tail_bytes;
    if (repair.repair_payload.size() < recovered_tail_bytes) {
      return {.error = flexfec_wire_error::malformed_packet};
    }
    if (destination.size() < recovered_packet_bytes) {
      return {.error = flexfec_wire_error::destination_too_small};
    }
    const auto recovered = destination.first(recovered_packet_bytes);
    recovered[0] = static_cast<std::uint8_t>(0x80U | (first_recovery & 0x3fU));
    recovered[1] = second_recovery;
    repair_detail::write_u16(recovered.subspan(2, 2), missing_sequence_number);
    repair_detail::write_u32(recovered.subspan(4, 4), timestamp_recovery);
    repair_detail::write_u32(recovered.subspan(8, 4), repair.primary_ssrc);
    std::copy(
      repair.repair_payload.begin(),
      repair.repair_payload.begin() + static_cast<std::ptrdiff_t>(recovered_tail_bytes),
      recovered.begin() + 12
    );
    for (const auto source : received_sources) {
      const auto source_tail = source.subspan(12);
      const auto bytes_to_xor = std::min(source_tail.size(), recovered_tail_bytes);
      for (std::size_t index = 0; index < bytes_to_xor; ++index) {
        recovered[12U + index] ^= source_tail[index];
      }
    }
    if (!repair_detail::valid_recovered_rtp(recovered)) {
      std::fill(recovered.begin(), recovered.end(), 0);
      return {.error = flexfec_wire_error::malformed_packet};
    }
    return {.bytes_written = recovered_packet_bytes};
  }

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
    invalid_payload_type,  ///< Expected or recovered type is outside 96 through 127, or they differ.
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
      if (!valid_lsp_dynamic_payload_type(candidate.expected_payload_type) ||
          !valid_lsp_dynamic_payload_type(candidate.recovered_payload_type) ||
          candidate.recovered_payload_type != candidate.expected_payload_type) {
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

  /** @brief Shared source-sequence replay admission result for original and FEC-recovered packets. */
  enum class source_replay_result : std::uint8_t {
    accepted_new_highest,  ///< Packet advanced the authenticated source sequence watermark.
    accepted_reordered,  ///< Packet was unseen and inside the retained reorder window.
    duplicate,  ///< Sequence was already admitted from either original or recovered input.
    too_old,  ///< Sequence fell outside the fixed 128-packet replay window.
    not_configured,  ///< No source SSRC and generation have been installed.
    wrong_source,  ///< Packet SSRC differs from the configured primary source.
    wrong_generation,  ///< Packet belongs to another video generation.
  };

  /**
   * @brief Fixed 128-packet replay window shared by original and FEC-recovered source RTP.
   *
   * The same instance must gate both authenticated source packets and plaintext packets admitted
   * through `authenticated_recovered_packet`. This makes the first accepted representation win:
   * a recovered packet suppresses its later original, and an original suppresses duplicate repair.
   * The 128-packet bound matches libSRTP 2.8's default RTP replay database window.
   */
  class source_replay_window {
  public:
    /**
     * @brief Reset replay state for one authenticated source and video generation.
     *
     * @param source_ssrc Nonzero negotiated primary source SSRC.
     * @param video_generation Nonzero active video generation.
     * @return `true` when the new scope was installed.
     */
    constexpr bool reset(const std::uint32_t source_ssrc, const std::uint32_t video_generation) noexcept {
      source_ssrc_ = source_ssrc;
      video_generation_ = video_generation;
      highest_sequence_ = 0;
      admitted_mask_ = {};
      initialized_ = false;
      configured_ = source_ssrc != 0 && video_generation != 0;
      return configured_;
    }

    /**
     * @brief Admit one authenticated original or admitted-by-repair source sequence.
     *
     * @param source_ssrc Packet source SSRC.
     * @param video_generation Packet video generation.
     * @param sequence_number Source RTP sequence number.
     * @return Typed replay result.
     */
    constexpr source_replay_result admit(
      const std::uint32_t source_ssrc,
      const std::uint32_t video_generation,
      const std::uint16_t sequence_number
    ) noexcept {
      if (!configured_) {
        return source_replay_result::not_configured;
      }
      if (source_ssrc != source_ssrc_) {
        return source_replay_result::wrong_source;
      }
      if (video_generation != video_generation_) {
        return source_replay_result::wrong_generation;
      }
      if (!initialized_) {
        highest_sequence_ = sequence_number;
        admitted_mask_[0] = 1;
        initialized_ = true;
        return source_replay_result::accepted_new_highest;
      }

      const auto forward = static_cast<std::uint16_t>(sequence_number - highest_sequence_);
      if (forward != 0 && forward < 0x8000U) {
        if (forward >= 128U) {
          admitted_mask_ = {1, 0};
        } else if (forward >= 64U) {
          admitted_mask_[1] = admitted_mask_[0] << (forward - 64U);
          admitted_mask_[0] = 1;
        } else {
          admitted_mask_[1] = (admitted_mask_[1] << forward) |
                              (admitted_mask_[0] >> (64U - forward));
          admitted_mask_[0] = (admitted_mask_[0] << forward) | 1U;
        }
        highest_sequence_ = sequence_number;
        return source_replay_result::accepted_new_highest;
      }
      const auto backward = static_cast<std::uint16_t>(highest_sequence_ - sequence_number);
      if (backward >= 128U) {
        return source_replay_result::too_old;
      }
      const auto word = backward / 64U;
      const auto bit = std::uint64_t {1} << (backward % 64U);
      if ((admitted_mask_[word] & bit) != 0) {
        return source_replay_result::duplicate;
      }
      admitted_mask_[word] |= bit;
      return source_replay_result::accepted_reordered;
    }

    /**
     * @brief Return the most recent admitted source sequence.
     *
     * @return Highest sequence, or no value before first admission.
     */
    [[nodiscard]] constexpr std::optional<std::uint16_t> highest_sequence() const noexcept {
      if (!initialized_) {
        return std::nullopt;
      }
      return highest_sequence_;
    }

  private:
    std::array<std::uint64_t, 2> admitted_mask_ {};  ///< Bit zero is the highest; older bits trail it.
    std::uint32_t source_ssrc_ = 0;  ///< Configured primary source SSRC.
    std::uint32_t video_generation_ = 0;  ///< Configured video generation.
    std::uint16_t highest_sequence_ = 0;  ///< Most recent forward sequence watermark.
    bool configured_ = false;  ///< Whether nonzero identifiers installed a replay scope.
    bool initialized_ = false;  ///< Whether at least one sequence was admitted.
  };

  /** @brief One bounded unresolved video source sequence gap. */
  struct video_gap {
    std::uint64_t frame_id = 0;  ///< Affected encoded frame identifier.
    std::uint64_t frame_deadline_microseconds = 0;  ///< Absolute repair deadline.
    std::uint64_t detected_microseconds = 0;  ///< First monotonic gap observation.
    std::uint16_t sequence_number = 0;  ///< Missing primary RTP sequence number.
    std::uint8_t later_packet_count = 0;  ///< Distinct admitted later packets, saturated at two.
    bool nack_sent = false;  ///< Whether a Generic NACK was successfully submitted.
    bool occupied = false;  ///< Whether this fixed slot contains an unresolved gap.
  };

  /** @brief Gap insertion or source-observation result. */
  enum class video_gap_result : std::uint8_t {
    accepted,  ///< New gap or forward source observation was accepted.
    already_tracked,  ///< Identical missing-sequence metadata is already retained.
    resolved,  ///< An arriving original or recovered source removed the retained gap.
    old_or_duplicate_source,  ///< Source did not advance the later-packet watermark.
    invalid_identifier,  ///< Source SSRC or generation is zero or mismatched.
    invalid_gap,  ///< Frame ID, deadline, or timing metadata is invalid.
    conflicting_gap,  ///< The sequence is retained with different frame metadata.
    capacity_exceeded,  ///< Fixed unresolved-gap storage is full.
  };

  /** @brief One immediate Generic NACK candidate emitted by the gap tracker. */
  struct video_gap_nack_candidate {
    std::uint64_t frame_id = 0;  ///< Affected encoded frame.
    std::uint64_t frame_deadline_microseconds = 0;  ///< Deadline used for RTX eligibility.
    std::uint16_t sequence_number = 0;  ///< Missing primary RTP sequence.
  };

  /** @brief Bounded result of collecting deadline-eligible NACK candidates. */
  struct video_gap_nack_batch {
    std::size_t count = 0;  ///< Candidates written to caller storage.
    std::size_t required = 0;  ///< Total due candidates, including truncated output.

    /**
     * @brief Return whether caller storage contained every due candidate.
     *
     * @return `true` when `count` equals `required`.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return count == required;
    }
  };

  /** @brief Complete deadline estimate used by both receiver and sender RTX gates. */
  struct rtx_deadline_estimate;

  /**
   * @brief Test strict RFC 4588 retransmission deadline eligibility without overflow.
   *
   * @param now_microseconds Current monotonic time.
   * @param frame_deadline_microseconds Protected frame deadline.
   * @param estimate Complete reverse/send/forward/decode estimate.
   * @return `true` only when predicted arrival is strictly before the deadline.
   */
  [[nodiscard]] constexpr bool rtx_deadline_eligible(
    std::uint64_t now_microseconds,
    std::uint64_t frame_deadline_microseconds,
    const rtx_deadline_estimate &estimate
  ) noexcept;

  /**
   * @brief Fixed-capacity video gap state with two-packet and reorder-delay confirmation.
   *
   * Gap detection remains integration-owned because repeated frame metadata determines the exact
   * affected frame. This tracker owns bounded confirmation, deadline eligibility, one-shot NACK
   * submission state, FEC/original resolution, and expiry without allocation.
   *
   * @tparam Capacity Maximum simultaneous unresolved source sequences.
   */
  template<std::size_t Capacity = 256>
  class video_gap_tracker {
  public:
    static_assert(Capacity != 0, "video gap tracker requires at least one slot");

    /**
     * @brief Reset tracking for one source and generation.
     *
     * @param source_ssrc Nonzero negotiated primary source SSRC.
     * @param video_generation Nonzero active video generation.
     * @param reorder_delay_microseconds Path-adaptive gap confirmation delay.
     * @return `true` when the new scope was installed.
     */
    constexpr bool reset(
      const std::uint32_t source_ssrc,
      const std::uint32_t video_generation,
      const std::uint64_t reorder_delay_microseconds
    ) noexcept {
      gaps_ = {};
      source_ssrc_ = source_ssrc;
      video_generation_ = video_generation;
      reorder_delay_microseconds_ = reorder_delay_microseconds;
      latest_sequence_ = 0;
      recent_sequences_ = {};
      size_ = 0;
      recent_sequence_count_ = 0;
      latest_initialized_ = false;
      configured_ = source_ssrc != 0 && video_generation != 0;
      return configured_;
    }

    /**
     * @brief Retain one missing source sequence with exact frame metadata.
     *
     * @param source_ssrc Primary source SSRC.
     * @param video_generation Active video generation.
     * @param sequence_number Missing primary RTP sequence.
     * @param frame_id Nonzero affected frame identifier.
     * @param frame_deadline_microseconds Strict future repair deadline.
     * @param now_microseconds Current monotonic time.
     * @return Typed insertion result.
     */
    constexpr video_gap_result record_gap(
      const std::uint32_t source_ssrc,
      const std::uint32_t video_generation,
      const std::uint16_t sequence_number,
      const std::uint64_t frame_id,
      const std::uint64_t frame_deadline_microseconds,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (!valid_scope(source_ssrc, video_generation)) {
        return video_gap_result::invalid_identifier;
      }
      if (frame_id == 0 || frame_deadline_microseconds <= now_microseconds) {
        return video_gap_result::invalid_gap;
      }
      if (auto *existing = find(sequence_number); existing != nullptr) {
        if (existing->frame_id != frame_id || existing->frame_deadline_microseconds != frame_deadline_microseconds) {
          return video_gap_result::conflicting_gap;
        }
        return video_gap_result::already_tracked;
      }
      if (size_ == Capacity) {
        return video_gap_result::capacity_exceeded;
      }
      auto *slot = &gaps_[size_];
      *slot = {
        .frame_id = frame_id,
        .frame_deadline_microseconds = frame_deadline_microseconds,
        .detected_microseconds = now_microseconds,
        .sequence_number = sequence_number,
        .occupied = true,
      };
      for (std::size_t index = 0; index < recent_sequence_count_; ++index) {
        const auto later = static_cast<std::uint16_t>(recent_sequences_[index] - sequence_number);
        if (later != 0 && later < 0x8000U && slot->later_packet_count < 2U) {
          ++slot->later_packet_count;
        }
      }
      ++size_;
      return video_gap_result::accepted;
    }

    /**
     * @brief Observe one admitted primary sequence and resolve it if previously missing.
     *
     * Original and FEC-recovered packets both call this after shared replay admission. Every
     * unresolved gap counts distinct admitted packets with later sequence numbers up to the
     * two-packet RFC 4585 confirmation threshold.
     *
     * @param source_ssrc Primary source SSRC.
     * @param video_generation Active video generation.
     * @param sequence_number Admitted primary sequence.
     * @return Typed observation result.
     */
    constexpr video_gap_result observe_source(
      const std::uint32_t source_ssrc,
      const std::uint32_t video_generation,
      const std::uint16_t sequence_number
    ) noexcept {
      if (!valid_scope(source_ssrc, video_generation)) {
        return video_gap_result::invalid_identifier;
      }
      for (auto &gap : std::span<video_gap> {gaps_}.first(size_)) {
        if (!gap.occupied || gap.sequence_number == sequence_number) {
          continue;
        }
        const auto later = static_cast<std::uint16_t>(sequence_number - gap.sequence_number);
        if (later != 0 && later < 0x8000U && gap.later_packet_count < 2U) {
          ++gap.later_packet_count;
        }
      }
      if (recent_sequence_count_ < recent_sequences_.size()) {
        recent_sequences_[recent_sequence_count_++] = sequence_number;
      } else {
        recent_sequences_[0] = recent_sequences_[1];
        recent_sequences_[1] = sequence_number;
      }
      const auto erased = erase(sequence_number);
      if (!latest_initialized_) {
        latest_sequence_ = sequence_number;
        latest_initialized_ = true;
        return erased ? video_gap_result::resolved : video_gap_result::accepted;
      }
      const auto forward = static_cast<std::uint16_t>(sequence_number - latest_sequence_);
      if (forward != 0 && forward < 0x8000U) {
        latest_sequence_ = sequence_number;
        return erased ? video_gap_result::resolved : video_gap_result::accepted;
      }
      return erased ? video_gap_result::resolved : video_gap_result::old_or_duplicate_source;
    }

    /**
     * @brief Collect every confirmed, unsent, deadline-eligible gap without mutating state.
     *
     * @param now_microseconds Current monotonic time.
     * @param estimate Complete RTX timing estimate.
     * @param destination Fixed caller storage for immediate Generic NACK construction.
     * @return Written and required candidate counts.
     */
    [[nodiscard]] constexpr video_gap_nack_batch pending_nacks(
      const std::uint64_t now_microseconds,
      const rtx_deadline_estimate &estimate,
      const std::span<video_gap_nack_candidate> destination
    ) const noexcept {
      video_gap_nack_batch batch;
      for (const auto &gap : std::span<const video_gap> {gaps_}.first(size_)) {
        if (!gap.occupied || gap.nack_sent || !confirmed(gap, now_microseconds) ||
            !rtx_deadline_eligible(now_microseconds, gap.frame_deadline_microseconds, estimate)) {
          continue;
        }
        if (batch.count < destination.size()) {
          destination[batch.count] = {
            .frame_id = gap.frame_id,
            .frame_deadline_microseconds = gap.frame_deadline_microseconds,
            .sequence_number = gap.sequence_number,
          };
          ++batch.count;
        }
        ++batch.required;
      }
      return batch;
    }

    /**
     * @brief Mark named candidates after successful protected Generic NACK submission.
     *
     * @param sequence_numbers Successfully submitted missing sequences.
     * @return Number of newly marked gaps.
     */
    constexpr std::size_t mark_nacks_sent(const std::span<const std::uint16_t> sequence_numbers) noexcept {
      std::size_t marked = 0;
      for (const auto sequence_number : sequence_numbers) {
        if (auto *gap = find(sequence_number); gap != nullptr && !gap->nack_sent) {
          gap->nack_sent = true;
          ++marked;
        }
      }
      return marked;
    }

    /**
     * @brief Resolve one gap after original arrival or deterministic authenticated FEC recovery.
     *
     * @param sequence_number Resolved primary sequence.
     * @return `true` when a retained gap was removed.
     */
    constexpr bool erase(const std::uint16_t sequence_number) noexcept {
      if (auto *gap = find(sequence_number); gap != nullptr) {
        --size_;
        *gap = gaps_[size_];
        gaps_[size_] = {};
        return true;
      }
      return false;
    }

    /**
     * @brief Remove every gap whose frame deadline has expired.
     *
     * @param now_microseconds Current monotonic time.
     * @return Number of expired gaps removed.
     */
    constexpr std::size_t erase_expired(const std::uint64_t now_microseconds) noexcept {
      std::size_t erased = 0;
      std::size_t index = 0;
      while (index < size_) {
        if (now_microseconds >= gaps_[index].frame_deadline_microseconds) {
          --size_;
          gaps_[index] = gaps_[size_];
          gaps_[size_] = {};
          ++erased;
        } else {
          ++index;
        }
      }
      return erased;
    }

    /**
     * @brief Return unresolved gap count.
     *
     * @return Occupied fixed slots.
     */
    [[nodiscard]] constexpr std::size_t size() const noexcept {
      return size_;
    }

  private:
    /**
     * @brief Return whether packet identifiers match the configured scope.
     *
     * @param source_ssrc Candidate primary source SSRC.
     * @param video_generation Candidate video generation.
     * @return `true` only when both identifiers match a configured scope.
     */
    [[nodiscard]] constexpr bool valid_scope(
      const std::uint32_t source_ssrc,
      const std::uint32_t video_generation
    ) const noexcept {
      return configured_ && source_ssrc == source_ssrc_ && video_generation == video_generation_;
    }

    /**
     * @brief Find one occupied gap by source sequence.
     *
     * @param sequence_number Missing source sequence.
     * @return Mutable gap pointer, or null when not retained.
     */
    [[nodiscard]] constexpr video_gap *find(const std::uint16_t sequence_number) noexcept {
      const auto active = std::span<video_gap> {gaps_}.first(size_);
      const auto found = std::find_if(active.begin(), active.end(), [sequence_number](const video_gap &gap) {
        return gap.occupied && gap.sequence_number == sequence_number;
      });
      return found == active.end() ? nullptr : &*found;
    }

    /**
     * @brief Return whether time or two later source packets confirm one gap.
     *
     * @param gap Retained unresolved gap.
     * @param now_microseconds Current monotonic time.
     * @return `true` when immediate Generic NACK confirmation is satisfied.
     */
    [[nodiscard]] constexpr bool confirmed(
      const video_gap &gap,
      const std::uint64_t now_microseconds
    ) const noexcept {
      const auto two_later_packets = gap.later_packet_count >= 2U;
      const auto reorder_elapsed = now_microseconds >= gap.detected_microseconds &&
                                   now_microseconds - gap.detected_microseconds >= reorder_delay_microseconds_;
      return two_later_packets || reorder_elapsed;
    }

    std::array<video_gap, Capacity> gaps_ {};  ///< Fixed unresolved-gap storage.
    std::array<std::uint16_t, 2> recent_sequences_ {};  ///< Two most recent admitted source sequences.
    std::uint64_t reorder_delay_microseconds_ = 0;  ///< Time-based confirmation delay.
    std::uint32_t source_ssrc_ = 0;  ///< Configured primary source SSRC.
    std::uint32_t video_generation_ = 0;  ///< Configured video generation.
    std::size_t size_ = 0;  ///< Occupied gap slots.
    std::size_t recent_sequence_count_ = 0;  ///< Populated recent-sequence entries.
    std::uint16_t latest_sequence_ = 0;  ///< Highest forward admitted sequence.
    bool configured_ = false;  ///< Whether valid nonzero identifiers were installed.
    bool latest_initialized_ = false;  ///< Whether a source watermark exists.
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

  /** @brief Opaque reference to integration-owned source state sufficient to construct RFC 4588 RTX. */
  struct rtx_packet_reference {
    std::uint64_t reconstruction_token = 0;  ///< Nonzero retained reconstruction-state token.
    std::uint64_t frame_id = 0;  ///< Encoded frame represented by the reconstruction state.
    std::uint64_t frame_deadline_microseconds = 0;  ///< Absolute repair deadline.
    std::uint32_t source_ssrc = 0;  ///< Primary source SSRC.
    std::uint32_t video_generation = 0;  ///< Video configuration generation.
    std::uint16_t source_sequence_number = 0;  ///< Original primary RTP sequence number.
    std::size_t source_packet_bytes = 0;  ///< Complete original source RTP bytes represented by the token.
  };

  /** @brief One caller-storage-backed RTX reconstruction retention entry. */
  struct rtx_retained_packet {
    rtx_packet_reference packet {};  ///< Opaque reconstruction reference and source metadata.
    std::uint64_t expires_microseconds = 0;  ///< Earlier of frame repair deadline or one RTT.
    std::uint64_t insertion_order = 0;  ///< Monotonic local insertion order.
    bool occupied = false;  ///< Whether this slot retains one integration-owned token.
  };

  /** @brief Result of retaining one source reconstruction token for possible RTX. */
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
    std::uint64_t reconstruction_token = 0;  ///< Integration-owned retained reconstruction-state token.
    std::uint64_t frame_id = 0;  ///< Retained encoded frame generation.
    std::uint32_t source_ssrc = 0;  ///< Original primary source SSRC.
    std::uint32_t video_generation = 0;  ///< Active video generation retained with the token.
    std::uint16_t source_sequence_number = 0;  ///< RFC 4588 original sequence number.
    std::size_t source_packet_bytes = 0;  ///< Complete original source packet bytes.
  };

  /**
   * @brief Caller-storage-backed RFC 4588 immutable source-retention state.
   *
   * Packet reconstruction state remains integration owned. This class stores only opaque retained
   * tokens and bounded metadata, retaining at most two frame generations and 16 MiB. A token must
   * reproduce the original RTP payload and required negotiated extensions after its source slab is
   * SRTP-protected in place; it must never name ciphertext as if it were an RFC 4588 payload.
   * Release callbacks retire evicted or explicitly erased tokens without heap allocation here.
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
     * @brief Retain source reconstruction state until deadline or one RTT.
     *
     * @tparam Release Callable accepting an evicted nonzero token.
     * @param packet Reconstruction token and media metadata.
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
      if (packet.reconstruction_token == 0 || packet.frame_id == 0 || packet.source_ssrc == 0 ||
          packet.video_generation == 0 || packet.source_packet_bytes == 0 ||
          packet.source_packet_bytes > maximum_rtx_retained_bytes ||
          packet.frame_deadline_microseconds <= now_microseconds) {
        return rtx_retention_result::invalid_packet;
      }
      if (measured_rtt_microseconds == 0) {
        return rtx_retention_result::invalid_rtt;
      }
      for (const auto &slot : slots_) {
        if (slot.occupied &&
            (slot.packet.reconstruction_token == packet.reconstruction_token ||
             (slot.packet.video_generation == packet.video_generation &&
              slot.packet.source_ssrc == packet.source_ssrc &&
              slot.packet.source_sequence_number == packet.source_sequence_number))) {
          return rtx_retention_result::duplicate_packet;
        }
      }

      while (!frame_is_retained(packet.frame_id) && retained_frame_count() >= maximum_rtx_frame_generations) {
        evict_oldest_frame(release, 0);
      }
      while (retained_bytes_ > maximum_rtx_retained_bytes - packet.source_packet_bytes) {
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
      retained_bytes_ += packet.source_packet_bytes;
      ++retained_packets_;
      return rtx_retention_result::retained;
    }

    /**
     * @brief Release every reconstruction token whose frame deadline or one-RTT retention expired.
     *
     * @tparam Release Callable accepting one nonzero token.
     * @param now_microseconds Current monotonic time.
     * @param release Called once per expired reconstruction token.
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
            .reconstruction_token = slot.packet.reconstruction_token,
            .frame_id = slot.packet.frame_id,
            .source_ssrc = slot.packet.source_ssrc,
            .video_generation = slot.packet.video_generation,
            .source_sequence_number = slot.packet.source_sequence_number,
            .source_packet_bytes = slot.packet.source_packet_bytes,
          };
        }
      }
      return std::nullopt;
    }

    /**
     * @brief Erase one retained source packet after repair, cancellation, or generation teardown.
     *
     * @tparam Release Callable accepting one nonzero reconstruction token.
     * @param video_generation Video generation naming the packet.
     * @param source_ssrc Primary source SSRC naming the packet.
     * @param source_sequence_number Original source sequence number.
     * @param release Called exactly once when a retained packet matches.
     * @return `true` when one packet was erased.
     */
    template<class Release>
    constexpr bool erase(
      const std::uint32_t video_generation,
      const std::uint32_t source_ssrc,
      const std::uint16_t source_sequence_number,
      Release &&release
    ) noexcept(noexcept(release(std::uint64_t {}))) {
      for (auto &slot : slots_) {
        if (slot.occupied && slot.packet.video_generation == video_generation &&
            slot.packet.source_ssrc == source_ssrc &&
            slot.packet.source_sequence_number == source_sequence_number) {
          release_slot(slot, release);
          return true;
        }
      }
      return false;
    }

    /**
     * @brief Erase one retained packet by its unique integration reconstruction token.
     *
     * @tparam Release Callable accepting the erased nonzero token.
     * @param reconstruction_token Integration-owned token to remove.
     * @param release Called exactly once when the token is retained.
     * @return `true` when one packet was erased.
     */
    template<class Release>
    constexpr bool erase_token(
      const std::uint64_t reconstruction_token,
      Release &&release
    ) noexcept(noexcept(release(std::uint64_t {}))) {
      if (reconstruction_token == 0) {
        return false;
      }
      for (auto &slot : slots_) {
        if (slot.occupied && slot.packet.reconstruction_token == reconstruction_token) {
          release_slot(slot, release);
          return true;
        }
      }
      return false;
    }

    /**
     * @brief Erase every retained reconstruction token for one encoded frame.
     *
     * @tparam Release Callable accepting each erased nonzero token.
     * @param frame_id Encoded frame whose retained source state is no longer useful.
     * @param release Called exactly once for every matching packet.
     * @return Number of packets erased.
     */
    template<class Release>
    constexpr std::size_t erase_frame(
      const std::uint64_t frame_id,
      Release &&release
    ) noexcept(noexcept(release(std::uint64_t {}))) {
      std::size_t erased = 0;
      for (auto &slot : slots_) {
        if (slot.occupied && slot.packet.frame_id == frame_id) {
          release_slot(slot, release);
          ++erased;
        }
      }
      return erased;
    }

    /**
     * @brief Release every retained reconstruction token during stream teardown.
     *
     * @tparam Release Callable accepting each erased nonzero token.
     * @param release Called exactly once for every retained packet.
     * @return Number of packets erased.
     */
    template<class Release>
    constexpr std::size_t clear(Release &&release) noexcept(noexcept(release(std::uint64_t {}))) {
      std::size_t erased = 0;
      for (auto &slot : slots_) {
        if (slot.occupied) {
          release_slot(slot, release);
          ++erased;
        }
      }
      return erased;
    }

    /**
     * @brief Return retained immutable source bytes.
     *
     * @return Aggregate represented source packet bytes, at most 16 MiB.
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
      release(slot.packet.reconstruction_token);
      retained_bytes_ -= slot.packet.source_packet_bytes;
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
    std::size_t retained_bytes_ = 0;  ///< Aggregate source bytes represented by retained tokens.
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
     * @brief Construct healthy recovery state from the configured epoch origin.
     *
     * A video generation supplies its nonzero `VIDEO_CONFIG` recovery epoch here so the first
     * subsequently opened recovery epoch advances from that authenticated origin. Zero retains
     * the default pre-configuration origin for value initialization and compile-time use.
     *
     * @param initial_epoch Initial recovery epoch for the video generation, or zero before
     * configuration.
     */
    constexpr explicit recovery_controller(const std::uint32_t initial_epoch = 0) noexcept:
        epoch_ {initial_epoch} {
    }

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
     * @param decoded_frame_watermark Largest successfully decoded frame ID.
     * @return Typed transition result.
     */
    constexpr recovery_result confirm_recovery_decoded_through(
      const std::uint32_t epoch,
      const std::uint64_t decoded_frame_watermark
    ) noexcept {
      if (phase_ != recovery_phase::recovery_frame_outstanding) {
        return recovery_result::no_active_epoch;
      }
      if (epoch != epoch_) {
        return recovery_result::stale_epoch;
      }
      if (decoded_frame_watermark < outstanding_recovery_frame_id_) {
        return recovery_result::wrong_recovery_frame;
      }
      phase_ = recovery_phase::healthy;
      damaged_frame_id_ = 0;
      outstanding_recovery_frame_id_ = 0;
      recovery_deadline_microseconds_ = 0;
      return recovery_result::accepted;
    }

    /**
     * @brief Compatibility spelling for watermark-based recovery confirmation.
     *
     * @param epoch Recovery epoch named by protected `LSPV` status.
     * @param decoded_frame_watermark Largest successfully decoded frame ID.
     * @return Typed transition result.
     */
    constexpr recovery_result confirm_recovery_decoded(
      const std::uint32_t epoch,
      const std::uint64_t decoded_frame_watermark
    ) noexcept {
      return confirm_recovery_decoded_through(epoch, decoded_frame_watermark);
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
