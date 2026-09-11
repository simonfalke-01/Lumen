/**
 * @file src/lsp/core/control.h
 * @brief LSPC version-1 framing, selective acknowledgement, and bounded reliability primitives.
 */

#pragma once

#include "packet.h"
#include "wire.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>

namespace lumen::lsp {
  /** @brief Encoded size of every LSPC version-1 fixed header. */
  inline constexpr std::size_t lspc_header_size = 48;

  /** @brief Wire version implemented by this core. */
  inline constexpr std::uint8_t lspc_wire_version = 1;

  /** @brief LSPC version-1 control flags. */
  enum class lspc_flag : std::uint8_t {
    acknowledgement_required = 1U << 0U,  ///< Receiver must acknowledge this logical frame.
    response = 1U << 1U,  ///< Frame is a response to `request_id`.
    error_response = 1U << 2U,  ///< Response carries a typed error.
    acknowledgement_only = 1U << 3U,  ///< Frame carries no type, request, or payload.
    final_chunk = 1U << 4U,  ///< Frame is the final chunk of a bounded object.
  };

  /**
   * @brief Return whether a raw flag field contains a specified LSPC flag.
   *
   * @param flags Raw LSPC flag bits.
   * @param flag Flag to test.
   * @return `true` when the flag is set.
   */
  [[nodiscard]] constexpr bool has_flag(const std::uint8_t flags, const lspc_flag flag) noexcept {
    return (flags & static_cast<std::uint8_t>(flag)) != 0;
  }

  /** @brief Parsed or serializable LSPC version-1 fixed header. */
  struct lspc_header {
    std::uint8_t flags = 0;  ///< LSPC flag bits.
    std::uint16_t message_type = 0;  ///< Semantic control-message type.
    std::uint32_t connection_generation = 0;  ///< Authenticated connection generation.
    std::uint32_t payload_length = 0;  ///< Exact deterministic-CBOR payload length.
    std::uint64_t message_id = 0;  ///< Nonzero logical-frame identifier.
    std::uint64_t request_id = 0;  ///< Nonzero request identifier for requests and responses, or zero for events.
    std::uint64_t acknowledgement_base = 0;  ///< Largest received peer message identifier.
    std::uint64_t acknowledgement_bitmap = 0;  ///< Receipt bits for the 64 identifiers preceding the base.

    /** @brief Compare all fixed-header fields. */
    [[nodiscard]] bool operator==(const lspc_header &) const noexcept = default;
  };

  /** @brief Typed LSPC framing failure. */
  enum class lspc_error : std::uint8_t {
    none,  ///< Operation completed successfully.
    header_too_short,  ///< Input does not contain the 48-byte fixed header.
    destination_too_small,  ///< Serialization destination cannot hold the complete frame.
    bad_magic,  ///< Header does not begin with ASCII `LSPC`.
    unsupported_version,  ///< Header carries a wire version other than one.
    reserved_flags,  ///< Header sets a reserved flag bit.
    payload_too_large,  ///< Payload cannot be represented by the 32-bit wire length.
    payload_length_mismatch,  ///< Encoded payload length does not exactly match the datagram.
    invalid_message_id,  ///< Logical message identifier is zero.
    invalid_acknowledgement,  ///< ACK base and bitmap describe an identifier below one.
    invalid_acknowledgement_only,  ///< ACK-only frame carries a forbidden semantic field or flag.
    invalid_response,  ///< Response flags or request identifier are inconsistent.
  };

  /** @brief Non-owning result of parsing one complete LSPC frame. */
  struct lspc_parse_result {
    lspc_header header {};  ///< Parsed fixed header when `error` is `none`.
    std::span<const std::uint8_t> payload {};  ///< Payload view backed by the caller's input buffer.
    lspc_error error = lspc_error::none;  ///< Parse status.

    /**
     * @brief Return whether parsing succeeded.
     *
     * @return `true` only for a fully valid frame.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == lspc_error::none;
    }
  };

  /** @brief Result of serializing one complete LSPC frame. */
  struct lspc_serialize_result {
    std::size_t bytes_written = 0;  ///< Complete encoded frame length on success.
    lspc_error error = lspc_error::none;  ///< Serialization status.

    /**
     * @brief Return whether serialization succeeded.
     *
     * @return `true` only when the complete frame was written.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == lspc_error::none;
    }
  };

  /**
   * @brief Validate semantic invariants shared by LSPC parsing and serialization.
   *
   * @param header Header fields to validate.
   * @return `lspc_error::none` when the header is internally consistent.
   */
  [[nodiscard]] constexpr lspc_error validate_lspc_header(const lspc_header &header) noexcept {
    constexpr auto allowed_flags = std::uint8_t {0x1f};
    if ((header.flags & static_cast<std::uint8_t>(~allowed_flags)) != 0) {
      return lspc_error::reserved_flags;
    }
    if (header.message_id == 0) {
      return lspc_error::invalid_message_id;
    }
    if (header.acknowledgement_base == 0) {
      if (header.acknowledgement_bitmap != 0) {
        return lspc_error::invalid_acknowledgement;
      }
    } else if (header.acknowledgement_base <= 64U) {
      const auto valid_preceding_ids = static_cast<unsigned>(header.acknowledgement_base - 1U);
      const auto valid_mask = valid_preceding_ids == 64U ?
                                std::numeric_limits<std::uint64_t>::max() :
                                ((std::uint64_t {1} << valid_preceding_ids) - 1U);
      if ((header.acknowledgement_bitmap & ~valid_mask) != 0) {
        return lspc_error::invalid_acknowledgement;
      }
    }

    const auto ack_only = has_flag(header.flags, lspc_flag::acknowledgement_only);
    if (ack_only) {
      const auto forbidden = static_cast<std::uint8_t>(
        static_cast<std::uint8_t>(lspc_flag::acknowledgement_required) |
        static_cast<std::uint8_t>(lspc_flag::response) |
        static_cast<std::uint8_t>(lspc_flag::error_response) |
        static_cast<std::uint8_t>(lspc_flag::final_chunk)
      );
      if ((header.flags & forbidden) != 0 || header.message_type != 0 || header.request_id != 0 || header.payload_length != 0) {
        return lspc_error::invalid_acknowledgement_only;
      }
    }

    const auto response = has_flag(header.flags, lspc_flag::response);
    const auto error_response = has_flag(header.flags, lspc_flag::error_response);
    if (error_response && !response) {
      return lspc_error::invalid_response;
    }
    if (response && header.request_id == 0) {
      return lspc_error::invalid_response;
    }
    return lspc_error::none;
  }

  /**
   * @brief Parse one complete LSPC version-1 frame without allocation.
   *
   * @param frame Complete DTLS application-record payload.
   * @return Parsed fixed header, borrowed payload, and typed status.
   */
  [[nodiscard]] constexpr lspc_parse_result parse_lspc(const std::span<const std::uint8_t> frame) noexcept {
    if (frame.size() < lspc_header_size) {
      return {.error = lspc_error::header_too_short};
    }
    if (frame[0] != 'L' || frame[1] != 'S' || frame[2] != 'P' || frame[3] != 'C') {
      return {.error = lspc_error::bad_magic};
    }
    if (frame[4] != lspc_wire_version) {
      return {.error = lspc_error::unsupported_version};
    }

    lspc_header header {
      .flags = frame[5],
      .message_type = wire::read_be<std::uint16_t>(frame.subspan(6, 2)),
      .connection_generation = wire::read_be<std::uint32_t>(frame.subspan(8, 4)),
      .payload_length = wire::read_be<std::uint32_t>(frame.subspan(12, 4)),
      .message_id = wire::read_be<std::uint64_t>(frame.subspan(16, 8)),
      .request_id = wire::read_be<std::uint64_t>(frame.subspan(24, 8)),
      .acknowledgement_base = wire::read_be<std::uint64_t>(frame.subspan(32, 8)),
      .acknowledgement_bitmap = wire::read_be<std::uint64_t>(frame.subspan(40, 8)),
    };
    if (header.payload_length != frame.size() - lspc_header_size) {
      return {.error = lspc_error::payload_length_mismatch};
    }
    if (const auto error = validate_lspc_header(header); error != lspc_error::none) {
      return {.error = error};
    }
    return {
      .header = header,
      .payload = frame.subspan(lspc_header_size),
      .error = lspc_error::none,
    };
  }

  /**
   * @brief Serialize one complete LSPC version-1 frame without allocation.
   *
   * @param header Fixed-header values; `payload_length` must equal `payload.size()`.
   * @param payload Deterministic-CBOR payload bytes.
   * @param destination Destination packet storage.
   * @return Encoded length and typed status.
   */
  [[nodiscard]] constexpr lspc_serialize_result serialize_lspc(
    const lspc_header &header,
    const std::span<const std::uint8_t> payload,
    const std::span<std::uint8_t> destination
  ) noexcept {
    if (payload.size() > std::numeric_limits<std::uint32_t>::max()) {
      return {.error = lspc_error::payload_too_large};
    }
    if (header.payload_length != payload.size()) {
      return {.error = lspc_error::payload_length_mismatch};
    }
    if (const auto error = validate_lspc_header(header); error != lspc_error::none) {
      return {.error = error};
    }
    if (destination.size() < lspc_header_size + payload.size()) {
      return {.error = lspc_error::destination_too_small};
    }

    destination[0] = 'L';
    destination[1] = 'S';
    destination[2] = 'P';
    destination[3] = 'C';
    destination[4] = lspc_wire_version;
    destination[5] = header.flags;
    wire::write_be<std::uint16_t>(destination.subspan(6, 2), header.message_type);
    wire::write_be<std::uint32_t>(destination.subspan(8, 4), header.connection_generation);
    wire::write_be<std::uint32_t>(destination.subspan(12, 4), header.payload_length);
    wire::write_be<std::uint64_t>(destination.subspan(16, 8), header.message_id);
    wire::write_be<std::uint64_t>(destination.subspan(24, 8), header.request_id);
    wire::write_be<std::uint64_t>(destination.subspan(32, 8), header.acknowledgement_base);
    wire::write_be<std::uint64_t>(destination.subspan(40, 8), header.acknowledgement_bitmap);
    for (std::size_t index = 0; index < payload.size(); ++index) {
      destination[lspc_header_size + index] = payload[index];
    }
    return {.bytes_written = lspc_header_size + payload.size()};
  }

  /** @brief Result of admitting one received logical message identifier. */
  enum class receive_id_result : std::uint8_t {
    accepted,  ///< Identifier was new and is now acknowledged.
    duplicate,  ///< Identifier was already acknowledged.
    zero,  ///< Identifier zero is forbidden.
    too_far_ahead,  ///< Identifier jumps more than 64 beyond the largest authenticated identifier.
    too_old,  ///< Identifier precedes the retained 64-message reorder window.
  };

  /** @brief Fixed 64-message LSPC receive and selective-ACK window. */
  class selective_ack_window {
  public:
    /**
     * @brief Admit one authenticated message identifier.
     *
     * @param message_id Nonzero message identifier.
     * @return Admission result.
     */
    constexpr receive_id_result observe(const std::uint64_t message_id) noexcept {
      if (message_id == 0) {
        return receive_id_result::zero;
      }
      if (largest_ == 0) {
        if (message_id > 64U) {
          return receive_id_result::too_far_ahead;
        }
        largest_ = message_id;
        received_before_ = 0;
        return receive_id_result::accepted;
      }
      if (message_id == largest_) {
        return receive_id_result::duplicate;
      }
      if (message_id > largest_) {
        const auto distance = message_id - largest_;
        if (distance > 64U) {
          return receive_id_result::too_far_ahead;
        }
        received_before_ = distance == 64U ? 0 : (received_before_ << distance);
        received_before_ |= std::uint64_t {1} << (distance - 1U);
        largest_ = message_id;
        return receive_id_result::accepted;
      }
      const auto distance = largest_ - message_id;
      if (distance > 64U) {
        return receive_id_result::too_old;
      }
      const auto mask = std::uint64_t {1} << (distance - 1U);
      if ((received_before_ & mask) != 0) {
        return receive_id_result::duplicate;
      }
      received_before_ |= mask;
      return receive_id_result::accepted;
    }

    /**
     * @brief Return the largest authenticated identifier.
     *
     * @return ACK base, or zero before a message is accepted.
     */
    [[nodiscard]] constexpr std::uint64_t base() const noexcept {
      return largest_;
    }

    /**
     * @brief Return receipt bits for the 64 identifiers preceding `base()`.
     *
     * @return Selective ACK bitmap.
     */
    [[nodiscard]] constexpr std::uint64_t bitmap() const noexcept {
      return received_before_;
    }

    /** @brief Reset the receive generation to its initial empty state. */
    constexpr void reset() noexcept {
      largest_ = 0;
      received_before_ = 0;
    }

  private:
    std::uint64_t largest_ = 0;  ///< Largest authenticated message identifier.
    std::uint64_t received_before_ = 0;  ///< Receipt bits preceding `largest_`.
  };

  /** @brief Explicit initial retransmission profile for the authenticated control path. */
  enum class control_path_profile : std::uint8_t {
    local,  ///< Directly connected or local path with a 20 ms initial RTO.
    nonlocal,  ///< Nonlocal path with a 100 ms initial RTO.
  };

  /** @brief Smoothed RTT and bounded LSPC retransmission-timeout estimator. */
  class control_rto {
  public:
    /**
     * @brief Construct an estimator with the path-appropriate initial timeout.
     *
     * @param profile Explicit local or nonlocal initial timeout profile.
     */
    constexpr explicit control_rto(const control_path_profile profile) noexcept:
        profile_(profile),
        rto_microseconds_(profile == control_path_profile::local ? 20'000U : 100'000U) {
    }

    /**
     * @brief Incorporate one non-retransmitted RTT sample.
     *
     * @param sample_microseconds Positive RTT sample in microseconds.
     */
    constexpr void update(const std::uint64_t sample_microseconds) noexcept {
      if (sample_microseconds == 0) {
        return;
      }
      if (!sampled_) {
        smoothed_microseconds_ = sample_microseconds;
        variation_microseconds_ = sample_microseconds / 2U;
        sampled_ = true;
      } else {
        const auto difference = smoothed_microseconds_ > sample_microseconds ?
                                  smoothed_microseconds_ - sample_microseconds :
                                  sample_microseconds - smoothed_microseconds_;
        variation_microseconds_ = (3U * variation_microseconds_ + difference) / 4U;
        smoothed_microseconds_ = (7U * smoothed_microseconds_ + sample_microseconds) / 8U;
      }
      const auto calculated = smoothed_microseconds_ + smoothed_microseconds_ / 2U + 4U * variation_microseconds_;
      rto_microseconds_ = calculated < 5'000U ? 5'000U : (calculated > 250'000U ? 250'000U : calculated);
    }

    /**
     * @brief Return the current base retransmission timeout.
     *
     * @return Timeout in microseconds, clamped to 5 through 250 ms after samples exist.
     */
    [[nodiscard]] constexpr std::uint64_t timeout_microseconds() const noexcept {
      return rto_microseconds_;
    }

    /** @brief Return the explicit initial path profile. */
    [[nodiscard]] constexpr control_path_profile profile() const noexcept {
      return profile_;
    }

    /** @brief Return whether an authenticated non-retransmitted ACK initialized the estimator. */
    [[nodiscard]] constexpr bool sampled() const noexcept {
      return sampled_;
    }

    /** @brief Return the current smoothed RTT in microseconds, or zero before initialization. */
    [[nodiscard]] constexpr std::uint64_t smoothed_microseconds() const noexcept {
      return smoothed_microseconds_;
    }

    /** @brief Return the current smoothed RTT variation in microseconds, or zero before initialization. */
    [[nodiscard]] constexpr std::uint64_t variation_microseconds() const noexcept {
      return variation_microseconds_;
    }

    /**
     * @brief Return an exponentially backed-off timeout for a transmission attempt.
     *
     * @param attempt One-based transmission attempt number.
     * @return Timeout in microseconds, capped at 250 ms.
     */
    [[nodiscard]] constexpr std::uint64_t timeout_for_attempt(const std::uint8_t attempt) const noexcept {
      auto timeout = rto_microseconds_;
      for (std::uint8_t index = 1; index < attempt && timeout < 250'000U; ++index) {
        timeout = timeout > 125'000U ? 250'000U : timeout * 2U;
      }
      return timeout;
    }

  private:
    control_path_profile profile_ = control_path_profile::nonlocal;  ///< Explicit initial path classification.
    std::uint64_t smoothed_microseconds_ = 0;  ///< Smoothed RTT.
    std::uint64_t variation_microseconds_ = 0;  ///< Smoothed RTT variation.
    std::uint64_t rto_microseconds_ = 0;  ///< Current base RTO.
    bool sampled_ = false;  ///< Whether an RTT sample has initialized the estimator.
  };

  /** @brief Failure while adding a retained outbound LSPC frame. */
  enum class outbound_store_result : std::uint8_t {
    stored,  ///< Frame was reserved before its first socket submission.
    invalid_id,  ///< Message identifier is zero.
    duplicate_id,  ///< Identifier is already retained.
    frame_too_large,  ///< Byte-identical frame exceeds configured storage.
    window_full,  ///< All 64 or fewer configured slots are occupied.
    invalid_deadline,  ///< Absolute deadline is zero.
  };

  /** @brief Result of binding a reserved frame to its actual first socket submission. */
  enum class outbound_submission_result : std::uint8_t {
    submitted,  ///< Actual first-send time and retry deadline were recorded.
    not_found,  ///< Message identifier names no reserved live frame.
    already_submitted,  ///< The retained frame already has a first submission.
    invalid_time,  ///< Socket-submission time is zero or at/after the operation deadline.
  };

  /**
   * @brief One byte-identical retained LSPC frame and its retry metadata.
   *
   * @tparam MaxFrameBytes Maximum encoded frame size.
   */
  template<std::size_t MaxFrameBytes>
  struct outbound_control_frame {
    std::uint64_t message_id = 0;  ///< Retained logical-frame identifier.
    packet_slab<MaxFrameBytes> frame {};  ///< Byte-identical encoded frame.
    std::uint64_t first_sent_microseconds = 0;  ///< Authenticated first socket-submission time.
    std::uint64_t last_sent_microseconds = 0;  ///< Most recent socket-submission time.
    std::uint64_t deadline_microseconds = 0;  ///< Absolute operation deadline.
    std::uint64_t next_retry_microseconds = 0;  ///< Absolute next retry time.
    std::uint8_t transmissions = 0;  ///< Completed transmission count.
    bool karn_eligible = false;  ///< Whether an ACK may yield an unambiguous first-send RTT sample.
    bool occupied = false;  ///< Whether this slot contains a live frame.
  };

  /** @brief Typed authenticated selective-ACK processing status. */
  enum class outbound_ack_status : std::uint8_t {
    accepted,  ///< At least one retained frame was retired.
    no_match,  ///< ACK fields named no live retained frame.
  };

  /** @brief Result of retiring frames and optionally applying one Karn-safe RTT sample. */
  struct outbound_ack_result {
    outbound_ack_status status = outbound_ack_status::no_match;  ///< ACK processing status.
    std::size_t removed = 0;  ///< Number of newly retired frames.
    std::uint64_t rtt_sample_microseconds = 0;  ///< Applied RTT sample, or zero when Karn suppressed sampling.
    bool rto_updated = false;  ///< Whether the supplied estimator consumed the sample.
  };

  /**
   * @brief Fixed outbound LSPC reliability window.
   *
   * @tparam MaxFrameBytes Maximum retained encoded-frame size.
   * @tparam Capacity Maximum outstanding messages; must not exceed 64.
   */
  template<std::size_t MaxFrameBytes, std::size_t Capacity = 64>
  class outbound_control_window {
  public:
    static_assert(Capacity > 0 && Capacity <= 64, "LSPC outbound capacity must be 1 through 64");

    /**
     * @brief Reserve a byte-identical frame before its first socket submission.
     *
     * @param message_id Nonzero logical-frame identifier.
     * @param frame Complete encoded frame.
     * @param deadline_microseconds Absolute operation deadline.
     * @return Storage result.
     */
    constexpr outbound_store_result reserve(
      const std::uint64_t message_id,
      const std::span<const std::uint8_t> frame,
      const std::uint64_t deadline_microseconds
    ) noexcept {
      if (message_id == 0) {
        return outbound_store_result::invalid_id;
      }
      if (deadline_microseconds == 0) {
        return outbound_store_result::invalid_deadline;
      }
      if (frame.size() > MaxFrameBytes) {
        return outbound_store_result::frame_too_large;
      }
      outbound_control_frame<MaxFrameBytes> *free_slot = nullptr;
      for (auto &slot : slots_) {
        if (slot.occupied && slot.message_id == message_id) {
          return outbound_store_result::duplicate_id;
        }
        if (!slot.occupied && free_slot == nullptr) {
          free_slot = &slot;
        }
      }
      if (free_slot == nullptr) {
        return outbound_store_result::window_full;
      }
      free_slot->message_id = message_id;
      free_slot->frame.assign(frame);
      free_slot->first_sent_microseconds = 0;
      free_slot->last_sent_microseconds = 0;
      free_slot->deadline_microseconds = deadline_microseconds;
      free_slot->next_retry_microseconds = 0;
      free_slot->transmissions = 0;
      free_slot->karn_eligible = false;
      free_slot->occupied = true;
      ++size_;
      return outbound_store_result::stored;
    }

    /**
     * @brief Record the actual first socket submission of one reserved frame.
     *
     * Karn eligibility begins only here, never when queue space is reserved.
     *
     * @param message_id Reserved message identifier.
     * @param submitted_at_microseconds Actual monotonic socket-submission time.
     * @param rto Retry-time estimator used to schedule the first retry.
     * @return Typed submission result.
     */
    constexpr outbound_submission_result mark_initial_submitted(
      const std::uint64_t message_id,
      const std::uint64_t submitted_at_microseconds,
      const control_rto &rto
    ) noexcept {
      for (auto &slot : slots_) {
        if (!slot.occupied || slot.message_id != message_id) {
          continue;
        }
        if (slot.transmissions != 0) {
          return outbound_submission_result::already_submitted;
        }
        if (submitted_at_microseconds == 0 || submitted_at_microseconds >= slot.deadline_microseconds) {
          return outbound_submission_result::invalid_time;
        }
        slot.first_sent_microseconds = submitted_at_microseconds;
        slot.last_sent_microseconds = submitted_at_microseconds;
        slot.transmissions = 1;
        slot.karn_eligible = true;
        const auto initial_delay = rto.timeout_for_attempt(1);
        slot.next_retry_microseconds = submitted_at_microseconds > std::numeric_limits<std::uint64_t>::max() - initial_delay ?
                                         std::numeric_limits<std::uint64_t>::max() :
                                         submitted_at_microseconds + initial_delay;
        return outbound_submission_result::submitted;
      }
      return outbound_submission_result::not_found;
    }

    /**
     * @brief Remove every retained frame explicitly covered by a peer ACK field.
     *
     * Karn's algorithm permits one RTT sample only from a frame that was never retransmitted. When one
     * ACK retires several eligible frames, the most recently first-sent frame supplies the single sample.
     *
     * @param acknowledgement_base ACK base, explicitly acknowledged when nonzero.
     * @param acknowledgement_bitmap Receipt bits for the preceding 64 identifiers.
     * @param authenticated_ack_time_microseconds Local monotonic receive time after ACK authentication.
     * @param rto Estimator updated by at most one unambiguous sample.
     * @return Removal count and RTT update result.
     */
    constexpr outbound_ack_result acknowledge(
      const std::uint64_t acknowledgement_base,
      const std::uint64_t acknowledgement_bitmap,
      const std::uint64_t authenticated_ack_time_microseconds,
      control_rto &rto
    ) noexcept {
      outbound_control_frame<MaxFrameBytes> *sample_source = nullptr;
      for (auto &slot : slots_) {
        if (!slot.occupied || slot.transmissions == 0) {
          continue;
        }
        auto acknowledged = acknowledgement_base != 0 && slot.message_id == acknowledgement_base;
        if (!acknowledged && acknowledgement_base > slot.message_id) {
          const auto distance = acknowledgement_base - slot.message_id;
          acknowledged = distance <= 64U && (acknowledgement_bitmap & (std::uint64_t {1} << (distance - 1U))) != 0;
        }
        if (acknowledged) {
          if (authenticated_ack_time_microseconds != 0 && slot.karn_eligible &&
              authenticated_ack_time_microseconds > slot.first_sent_microseconds &&
              (sample_source == nullptr || slot.first_sent_microseconds > sample_source->first_sent_microseconds)) {
            sample_source = &slot;
          }
        }
      }
      outbound_ack_result result;
      if (sample_source != nullptr) {
        result.rtt_sample_microseconds = authenticated_ack_time_microseconds - sample_source->first_sent_microseconds;
        rto.update(result.rtt_sample_microseconds);
        result.rto_updated = true;
      }
      for (auto &slot : slots_) {
        if (!slot.occupied || slot.transmissions == 0) {
          continue;
        }
        auto acknowledged = acknowledgement_base != 0 && slot.message_id == acknowledgement_base;
        if (!acknowledged && acknowledgement_base > slot.message_id) {
          const auto distance = acknowledgement_base - slot.message_id;
          acknowledged = distance <= 64U && (acknowledgement_bitmap & (std::uint64_t {1} << (distance - 1U))) != 0;
        }
        if (acknowledged) {
          slot = {};
          --size_;
          ++result.removed;
        }
      }
      result.status = result.removed == 0 ? outbound_ack_status::no_match : outbound_ack_status::accepted;
      return result;
    }

    /**
     * @brief Return the earliest retryable frame due at a timestamp.
     *
     * Expired or five-times-transmitted frames are not returned and should cause the owning
     * operation to fail explicitly through `has_failed()`.
     *
     * @param now_microseconds Current monotonic time.
     * @return Mutable retained frame, or `nullptr` when none is due.
     */
    [[nodiscard]] constexpr outbound_control_frame<MaxFrameBytes> *due(const std::uint64_t now_microseconds) noexcept {
      outbound_control_frame<MaxFrameBytes> *selected = nullptr;
      for (auto &slot : slots_) {
        if (!slot.occupied || slot.transmissions == 0 || slot.transmissions >= 5U ||
            now_microseconds >= slot.deadline_microseconds || now_microseconds < slot.next_retry_microseconds) {
          continue;
        }
        if (selected == nullptr || slot.next_retry_microseconds < selected->next_retry_microseconds) {
          selected = &slot;
        }
      }
      return selected;
    }

    /**
     * @brief Record transmission of a retained byte-identical retry.
     *
     * @param retained Slot returned by `due()`.
     * @param now_microseconds Retry transmission time.
     * @param rto Retry-time estimator.
     */
    constexpr void mark_retransmitted(
      outbound_control_frame<MaxFrameBytes> &retained,
      const std::uint64_t now_microseconds,
      const control_rto &rto
    ) noexcept {
      if (!retained.occupied || retained.transmissions == 0 || retained.transmissions >= 5U) {
        return;
      }
      ++retained.transmissions;
      retained.last_sent_microseconds = now_microseconds;
      retained.karn_eligible = false;
      const auto delay = rto.timeout_for_attempt(retained.transmissions);
      retained.next_retry_microseconds = now_microseconds > std::numeric_limits<std::uint64_t>::max() - delay ?
                                           std::numeric_limits<std::uint64_t>::max() :
                                           now_microseconds + delay;
    }

    /**
     * @brief Return whether any retained operation exhausted attempts or its deadline.
     *
     * @param now_microseconds Current monotonic time.
     * @return `true` when a live operation must fail.
     */
    [[nodiscard]] constexpr bool has_failed(const std::uint64_t now_microseconds) const noexcept {
      for (const auto &slot : slots_) {
        if (slot.occupied && (slot.transmissions >= 5U || now_microseconds >= slot.deadline_microseconds)) {
          return true;
        }
      }
      return false;
    }

    /**
     * @brief Return the number of unacknowledged frames.
     *
     * @return Live retained-frame count.
     */
    [[nodiscard]] constexpr std::size_t size() const noexcept {
      return size_;
    }

  private:
    std::array<outbound_control_frame<MaxFrameBytes>, Capacity> slots_ {};  ///< Fixed retained-frame slots.
    std::size_t size_ = 0;  ///< Number of occupied slots.
  };

  /** @brief Result of response-cache lookup or insertion. */
  enum class response_cache_result : std::uint8_t {
    miss,  ///< Request identifier is not cached.
    hit,  ///< Byte-identical request has a cached response.
    stored,  ///< New request and response were cached.
    conflicting_request,  ///< Reused request identifier carries different request bytes.
    invalid_request_id,  ///< Request identifier zero is forbidden.
    invalid_semantic_identity,  ///< Semantic message type, schema, or generation is zero.
    invalid_retention_deadline,  ///< Retention deadline is not later than the current time.
    object_too_large,  ///< Request or response exceeds its configured fixed storage.
    capacity_exhausted,  ///< Every slot contains an unexpired response and caller must apply backpressure.
  };

  /** @brief Exact semantic operation identity retained beside an idempotent response. */
  struct response_semantic_identity {
    std::uint16_t message_type = 0;  ///< Nonzero request message type.
    std::uint16_t schema_version = 0;  ///< Nonzero deterministic request schema version.
    std::uint32_t generation = 0;  ///< Nonzero configuration, transaction, or authority generation.
    std::array<std::uint8_t, 16> semantic_id {};  ///< Canonical 128-bit transaction/configuration identity.
    std::array<std::uint8_t, 32> request_digest {};  ///< SHA-256 of the complete canonical semantic request.

    /** @brief Compare every semantic identity field. */
    [[nodiscard]] bool operator==(const response_semantic_identity &) const noexcept = default;
  };

  /** @brief Retention metadata supplied for one terminal-response cache insertion. */
  struct response_cache_metadata {
    response_semantic_identity identity {};  ///< Exact semantic operation identity.
    std::uint64_t retention_deadline_microseconds = 0;  ///< Absolute monotonic retention deadline.
  };

  /**
   * @brief Borrowed cached-response lookup result.
   *
   * The response view remains valid until the next mutable cache operation.
   */
  struct cached_response_view {
    response_cache_result result = response_cache_result::miss;  ///< Lookup status.
    std::span<const std::uint8_t> response {};  ///< Cached response on a hit.
    response_cache_metadata metadata {};  ///< Retained semantic and deadline metadata on a hit.
  };

  /**
   * @brief Bounded terminal idempotent request/response cache with exact byte comparison.
   *
   * @tparam MaxRequestBytes Maximum retained request bytes.
   * @tparam MaxResponseBytes Maximum retained response bytes.
   * @tparam Capacity Maximum entries; must not exceed 64.
   */
  template<std::size_t MaxRequestBytes, std::size_t MaxResponseBytes, std::size_t Capacity = 64>
  class response_cache {
  public:
    static_assert(Capacity > 0 && Capacity <= 64, "LSPC response-cache capacity must be 1 through 64");

    /**
     * @brief Look up an idempotent response by request identifier and exact request bytes.
     *
     * @param request_id Nonzero request identifier.
     * @param identity Exact semantic identity of the request.
     * @param request Complete deterministic semantic request bytes.
     * @param now_microseconds Current monotonic time used to expire old entries.
     * @return Hit, miss, conflict, or invalid-input result.
     */
    [[nodiscard]] constexpr cached_response_view lookup(
      const std::uint64_t request_id,
      const response_semantic_identity &identity,
      const std::span<const std::uint8_t> request,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (request_id == 0) {
        return {.result = response_cache_result::invalid_request_id};
      }
      if (!valid(identity)) {
        return {.result = response_cache_result::invalid_semantic_identity};
      }
      for (auto &entry : entries_) {
        if (entry.occupied && entry.metadata.retention_deadline_microseconds <= now_microseconds) {
          release(entry);
        }
        if (!entry.occupied || entry.request_id != request_id) {
          continue;
        }
        if (entry.metadata.identity != identity || !equal(entry.request.bytes(), request)) {
          return {.result = response_cache_result::conflicting_request};
        }
        return {
          .result = response_cache_result::hit,
          .response = entry.response.bytes(),
          .metadata = entry.metadata,
        };
      }
      return {.result = response_cache_result::miss};
    }

    /**
     * @brief Insert an idempotent response without evicting any unexpired entry.
     *
     * An existing byte-identical request is left untouched and reported as a hit. Reuse of an
     * identifier with different bytes is always a conflict and never replaces the prior entry.
     *
     * @param request_id Nonzero request identifier.
     * @param metadata Exact 128-bit identity, request digest, and retention deadline.
     * @param request Complete deterministic semantic request bytes.
     * @param response Complete byte-identical response bytes.
     * @param now_microseconds Current monotonic time.
     * @return Cache result.
     */
    constexpr response_cache_result insert(
      const std::uint64_t request_id,
      const response_cache_metadata &metadata,
      const std::span<const std::uint8_t> request,
      const std::span<const std::uint8_t> response,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (request_id == 0) {
        return response_cache_result::invalid_request_id;
      }
      if (!valid(metadata.identity)) {
        return response_cache_result::invalid_semantic_identity;
      }
      if (metadata.retention_deadline_microseconds <= now_microseconds) {
        return response_cache_result::invalid_retention_deadline;
      }
      if (request.size() > MaxRequestBytes || response.size() > MaxResponseBytes) {
        return response_cache_result::object_too_large;
      }
      const auto prior = lookup(request_id, metadata.identity, request, now_microseconds);
      if (prior.result == response_cache_result::hit || prior.result == response_cache_result::conflicting_request) {
        return prior.result;
      }

      entry_type *free_entry = nullptr;
      for (auto &entry : entries_) {
        if (!entry.occupied) {
          free_entry = &entry;
          break;
        }
      }
      if (free_entry == nullptr) {
        return response_cache_result::capacity_exhausted;
      }
      free_entry->request_id = request_id;
      free_entry->metadata = metadata;
      free_entry->request.assign(request);
      free_entry->response.assign(response);
      free_entry->occupied = true;
      ++size_;
      return response_cache_result::stored;
    }

    /**
     * @brief Release every entry whose retention deadline has elapsed.
     *
     * @param now_microseconds Current monotonic time.
     * @return Number of released entries.
     */
    constexpr std::size_t expire(const std::uint64_t now_microseconds) noexcept {
      std::size_t expired = 0;
      for (auto &entry : entries_) {
        if (entry.occupied && entry.metadata.retention_deadline_microseconds <= now_microseconds) {
          release(entry);
          ++expired;
        }
      }
      return expired;
    }

    /**
     * @brief Return the number of cached responses.
     *
     * @return Occupied entry count.
     */
    [[nodiscard]] constexpr std::size_t size() const noexcept {
      return size_;
    }

    /** @brief Discard every cached request and response. */
    constexpr void clear() noexcept {
      for (auto &entry : entries_) {
        release(entry);
      }
    }

  private:
    /** @brief One fixed request/response cache entry. */
    struct entry_type {
      std::uint64_t request_id = 0;  ///< Request identifier.
      response_cache_metadata metadata {};  ///< Semantic identity, digest, and retention deadline.
      packet_slab<MaxRequestBytes> request {};  ///< Exact request bytes.
      packet_slab<MaxResponseBytes> response {};  ///< Exact response bytes.
      bool occupied = false;  ///< Whether the entry is live.
    };

    /**
     * @brief Compare two byte strings exactly.
     *
     * @param left First byte string.
     * @param right Second byte string.
     * @return `true` when lengths and all bytes match.
     */
    [[nodiscard]] static constexpr bool equal(
      const std::span<const std::uint8_t> left,
      const std::span<const std::uint8_t> right
    ) noexcept {
      if (left.size() != right.size()) {
        return false;
      }
      for (std::size_t index = 0; index < left.size(); ++index) {
        if (left[index] != right[index]) {
          return false;
        }
      }
      return true;
    }

    /** @brief Return whether a semantic identity is usable as a cache discriminator. */
    [[nodiscard]] static constexpr bool valid(const response_semantic_identity &identity) noexcept {
      return identity.message_type != 0 && identity.schema_version != 0 && identity.generation != 0 &&
             std::any_of(identity.semantic_id.begin(), identity.semantic_id.end(), [](const auto byte) {
               return byte != 0;
             }) &&
             std::any_of(identity.request_digest.begin(), identity.request_digest.end(), [](const auto byte) {
               return byte != 0;
             });
    }

    /** @brief Release one entry and update the occupied count exactly once. */
    constexpr void release(entry_type &entry) noexcept {
      if (!entry.occupied) {
        return;
      }
      entry = {};
      --size_;
    }

    std::array<entry_type, Capacity> entries_ {};  ///< Fixed cache entries.
    std::size_t size_ = 0;  ///< Occupied entry count.
  };
}  // namespace lumen::lsp
