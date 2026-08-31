/**
 * @file src/protocol_lsp/media/av1.h
 * @brief AOM AV1 RTP payload-format version 1.0 packetization and receive reconstruction for LSP/1.
 */

#pragma once

#include "common.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <vector>

namespace lumen::lsp::media {
  /** @brief Parsed one-byte AV1 RTP aggregation header. */
  struct av1_aggregation_header {
    bool continuation_from_previous = false;  ///< `Z`: first element continues an OBU from the prior packet.
    bool continues_in_next = false;  ///< `Y`: final element continues in the next packet.
    std::uint8_t element_count = 0;  ///< `W`: zero means every element has a length, otherwise `1...3` elements.
    bool starts_coded_video_sequence = false;  ///< `N`: packet begins a new coded video sequence.

    /** @brief Compare every AV1 aggregation-header field. */
    [[nodiscard]] bool operator==(const av1_aggregation_header &) const noexcept = default;
  };

  /** @brief Typed AV1 aggregation-header parse failure. */
  enum class av1_header_error : std::uint8_t {
    none,  ///< Header is valid.
    header_too_short,  ///< No aggregation-header byte is available.
    reserved_bits,  ///< One or more reserved low bits are nonzero.
    invalid_sequence_start,  ///< `N` is set while `Z` says the first OBU began in an earlier packet.
  };

  /** @brief AV1 aggregation-header parse result. */
  struct av1_header_result {
    av1_aggregation_header header {};  ///< Parsed header fields.
    av1_header_error error = av1_header_error::none;  ///< Parse status.

    /**
     * @brief Return whether parsing succeeded.
     *
     * @return `true` only for a valid aggregation header.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == av1_header_error::none;
    }
  };

  /**
   * @brief Parse the one-byte AV1 RTP aggregation header.
   *
   * @param payload Complete or prefix AV1 RTP payload.
   * @return Parsed descriptor and typed status.
   */
  [[nodiscard]] constexpr av1_header_result parse_av1_aggregation_header(
    const std::span<const std::uint8_t> payload
  ) noexcept {
    if (payload.empty()) {
      return {.error = av1_header_error::header_too_short};
    }
    if ((payload[0] & 0x07U) != 0) {
      return {.error = av1_header_error::reserved_bits};
    }
    const av1_aggregation_header header {
      .continuation_from_previous = (payload[0] & 0x80U) != 0,
      .continues_in_next = (payload[0] & 0x40U) != 0,
      .element_count = static_cast<std::uint8_t>((payload[0] >> 4U) & 0x03U),
      .starts_coded_video_sequence = (payload[0] & 0x08U) != 0,
    };
    if (header.continuation_from_previous && header.starts_coded_video_sequence) {
      return {.error = av1_header_error::invalid_sequence_start};
    }
    return {.header = header};
  }

  /** @brief Typed AV1 RTP payload reconstruction failure. */
  enum class av1_depacketization_error : std::uint8_t {
    none,  ///< The packet was accepted.
    payload_too_short,  ///< The payload does not contain an aggregation header and OBU element.
    reserved_header_bits,  ///< The aggregation header contains nonzero reserved bits.
    invalid_sequence_start,  ///< `N` and `Z` are both set.
    invalid_element_count,  ///< The declared `W` layout contains no element or the wrong element count.
    malformed_length,  ///< An OBU or element LEB128 length is unterminated or exceeds `UINT32_MAX`.
    empty_obu_element,  ///< An OBU element has zero bytes.
    truncated_obu_element,  ///< An explicit OBU-element length exceeds the remaining payload.
    invalid_obu_header,  ///< An OBU has invalid reserved, extension, or type bits.
    invalid_obu_size,  ///< An internal `obu_size` does not exactly cover the OBU payload.
    inconsistent_layer_ids,  ///< Extended OBUs in one packet disagree on temporal/spatial IDs.
    unexpected_continuation,  ///< `Z` is set when no preceding OBU fragment is pending.
    missing_continuation,  ///< A pending OBU fragment is not continued by the next packet.
    sequence_discontinuity,  ///< RTP sequence order changed inside the temporal unit.
    invalid_new_sequence_boundary,  ///< `N` is set after the first packet of the temporal unit.
    marker_on_incomplete_obu,  ///< RTP marker is set while `Y` leaves an OBU incomplete.
    output_too_small,  ///< Caller-owned output storage cannot contain the canonical access unit.
    packet_after_temporal_unit,  ///< A packet was supplied after the marked temporal-unit boundary.
    failed_state,  ///< An earlier packet invalidated this depacketizer and reset is required.
  };

  /** @brief Result of consuming one AV1 RTP payload. */
  struct av1_depacketization_result {
    std::size_t bytes_written = 0;  ///< Finalized canonical low-overhead OBU bytes currently available.
    bool temporal_unit_complete = false;  ///< Marker or a later timestamp completed the temporal unit.
    bool starts_coded_video_sequence = false;  ///< The first packet carried `N`.
    bool packet_consumed = false;  ///< Input packet was consumed rather than deferred at a timestamp boundary.
    av1_depacketization_error error = av1_depacketization_error::none;  ///< Typed receive status.

    /**
     * @brief Return whether the packet was accepted.
     *
     * @return `true` only when the depacketizer remains usable.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == av1_depacketization_error::none;
    }
  };

  namespace detail {
    /** @brief Parsed bounded LEB128 value used by AV1 aggregation lengths. */
    struct av1_leb128_result {
      std::uint32_t value = 0;  ///< Decoded non-negative value, capped to AV1's 32-bit size domain.
      std::size_t bytes_consumed = 0;  ///< Encoded byte count on success.
      av1_depacketization_error error = av1_depacketization_error::none;  ///< Typed parse status.

      /** @brief Return whether the LEB128 value was parsed successfully. */
      [[nodiscard]] constexpr explicit operator bool() const noexcept {
        return error == av1_depacketization_error::none;
      }
    };

    /**
     * @brief Parse one AV1 LEB128 value without allocation.
     *
     * AV1 permits non-minimal encodings of up to eight bytes. Values above `UINT32_MAX` are
     * rejected before conversion to a platform `size_t`.
     *
     * @param bytes Bytes beginning with the encoded value.
     * @return Decoded value, consumed byte count, and typed status.
     */
    [[nodiscard]] constexpr av1_leb128_result parse_av1_leb128(
      const std::span<const std::uint8_t> bytes
    ) noexcept {
      std::uint64_t value = 0;
      for (std::size_t index = 0; index < 8; ++index) {
        if (index >= bytes.size()) {
          return {.error = av1_depacketization_error::malformed_length};
        }
        const auto byte = bytes[index];
        value |= std::uint64_t {byte & 0x7fU} << (index * 7U);
        if ((byte & 0x80U) != 0) {
          continue;
        }
        if (value > std::numeric_limits<std::uint32_t>::max()) {
          return {.error = av1_depacketization_error::malformed_length};
        }
        return {
          .value = static_cast<std::uint32_t>(value),
          .bytes_consumed = index + 1,
        };
      }
      return {.error = av1_depacketization_error::malformed_length};
    }

    /**
     * @brief Visit every packet-local AV1 OBU element without allocating descriptors.
     *
     * @tparam Visitor Callable accepting `(element, is_first, is_last)` and returning an
     * `av1_depacketization_error`.
     * @param payload Complete AV1 RTP payload including its aggregation header.
     * @param header Parsed aggregation header.
     * @param visitor Synchronous borrowed-element visitor.
     * @return `none` or the first wire/visitor failure.
     */
    template<typename Visitor>
    [[nodiscard]] constexpr av1_depacketization_error visit_av1_elements(
      const std::span<const std::uint8_t> payload,
      const av1_aggregation_header &header,
      Visitor &&visitor
    ) noexcept {
      if (payload.size() <= 1) {
        return av1_depacketization_error::payload_too_short;
      }

      std::size_t offset = 1;
      std::size_t element_index = 0;
      if (header.element_count == 0) {
        while (offset < payload.size()) {
          const auto length = parse_av1_leb128(payload.subspan(offset));
          if (!length) {
            return length.error;
          }
          offset += length.bytes_consumed;
          if (length.value == 0) {
            return av1_depacketization_error::empty_obu_element;
          }
          if (length.value > payload.size() - offset) {
            return av1_depacketization_error::truncated_obu_element;
          }
          const auto element = payload.subspan(offset, length.value);
          offset += length.value;
          const auto status = visitor(element, element_index == 0, offset == payload.size());
          if (status != av1_depacketization_error::none) {
            return status;
          }
          ++element_index;
        }
        return element_index == 0 ? av1_depacketization_error::invalid_element_count :
                                    av1_depacketization_error::none;
      }

      for (std::size_t index = 0; index < header.element_count; ++index) {
        const auto is_last = index + 1 == header.element_count;
        std::size_t element_size = 0;
        if (is_last) {
          element_size = payload.size() - offset;
        } else {
          const auto length = parse_av1_leb128(payload.subspan(offset));
          if (!length) {
            return length.error;
          }
          offset += length.bytes_consumed;
          element_size = length.value;
        }
        if (element_size == 0) {
          return av1_depacketization_error::empty_obu_element;
        }
        if (element_size > payload.size() - offset) {
          return av1_depacketization_error::truncated_obu_element;
        }
        const auto status = visitor(payload.subspan(offset, element_size), index == 0, is_last);
        if (status != av1_depacketization_error::none) {
          return status;
        }
        offset += element_size;
      }
      return offset == payload.size() ? av1_depacketization_error::none :
                                        av1_depacketization_error::invalid_element_count;
    }

    /** @brief Sender-side disposition for one normalized AV1 OBU element. */
    enum class av1_source_obu_status : std::uint8_t {
      valid,  ///< OBU is carried in RTP.
      ignored,  ///< Temporal delimiter or tile list is omitted from RTP.
      malformed,  ///< Header, extension, size-field, or type is invalid for LSP packetization.
    };

    /**
     * @brief Classify one normalized source OBU for AV1 RTP packetization.
     *
     * OBU elements supplied to the sender exclude an external Annex-B length and must clear
     * `obu_has_size_field`. Temporal delimiter and tile-list OBUs are valid input but omitted as
     * required by the AOM RTP payload format.
     *
     * @param obu Complete normalized OBU element.
     * @return Carry, omit, or malformed disposition.
     */
    [[nodiscard]] constexpr av1_source_obu_status classify_av1_source_obu(
      const std::span<const std::uint8_t> obu
    ) noexcept {
      if (obu.empty() || (obu[0] & 0x80U) != 0 || (obu[0] & 0x03U) != 0) {
        return av1_source_obu_status::malformed;
      }
      const auto type = static_cast<std::uint8_t>((obu[0] >> 3U) & 0x0fU);
      if (type == 0U || (type >= 9U && type <= 14U)) {
        return av1_source_obu_status::malformed;
      }
      const auto has_extension = (obu[0] & 0x04U) != 0;
      if (has_extension && (obu.size() < 2 || (obu[1] & 0x07U) != 0)) {
        return av1_source_obu_status::malformed;
      }
      return type == 2U || type == 8U ? av1_source_obu_status::ignored :
                                        av1_source_obu_status::valid;
    }

    /**
     * @brief Return whether complete OBUs may share one AV1 aggregation packet.
     *
     * When multiple contained OBUs have extension headers, the AOM payload format requires their
     * temporal and spatial IDs to match.
     *
     * @param obus Same-temporal-unit OBU elements.
     * @param first First OBU index included.
     * @param count Number of candidate elements.
     * @return `true` when all extended elements have identical layer identifiers.
     */
    [[nodiscard]] inline bool av1_elements_may_aggregate(
      const std::span<const std::span<const std::uint8_t>> obus,
      const std::size_t first,
      const std::size_t count
    ) noexcept {
      std::optional<std::uint8_t> layer_ids;
      for (std::size_t index = first; index < first + count; ++index) {
        if ((obus[index][0] & 0x04U) == 0) {
          continue;
        }
        const auto current = static_cast<std::uint8_t>(obus[index][1] & 0xf8U);
        if (layer_ids && *layer_ids != current) {
          return false;
        }
        layer_ids = current;
      }
      return true;
    }

    /**
     * @brief Calculate an AV1 packet size for complete aggregated OBU elements.
     *
     * @param obus Same-temporal-unit OBU elements.
     * @param first First OBU index included.
     * @param count Number of complete elements included.
     * @return Aggregation header, length fields, and element bytes.
     */
    [[nodiscard]] inline std::size_t av1_complete_packet_size(
      const std::span<const std::span<const std::uint8_t>> obus,
      const std::size_t first,
      const std::size_t count
    ) noexcept {
      std::size_t size = 1;
      const auto explicit_all_lengths = count > 3;
      for (std::size_t relative = 0; relative < count; ++relative) {
        const auto element_size = obus[first + relative].size();
        if (explicit_all_lengths || relative + 1 < count) {
          size += leb128_size(element_size);
        }
        size += element_size;
      }
      return size;
    }

    /**
     * @brief Build an AV1 RTP payload containing complete OBU elements.
     *
     * @param obus Same-temporal-unit OBU elements.
     * @param first First OBU index included.
     * @param count Number of complete elements included.
     * @param starts_sequence Whether this is the first packet of a new coded video sequence.
     * @return Complete AV1 RTP payload.
     */
    [[nodiscard]] inline std::vector<std::uint8_t> make_av1_complete_payload(
      const std::span<const std::span<const std::uint8_t>> obus,
      const std::size_t first,
      const std::size_t count,
      const bool starts_sequence
    ) {
      const auto w = count <= 3 ? static_cast<std::uint8_t>(count) : std::uint8_t {0};
      std::vector<std::uint8_t> payload;
      payload.reserve(av1_complete_packet_size(obus, first, count));
      payload.push_back(static_cast<std::uint8_t>((static_cast<unsigned int>(w) << 4U) | (starts_sequence ? 0x08U : 0U)));
      for (std::size_t relative = 0; relative < count; ++relative) {
        const auto obu = obus[first + relative];
        if (w == 0 || relative + 1 < count) {
          const auto encoded_size = encode_leb128(obu.size());
          payload.insert(payload.end(), encoded_size.begin(), encoded_size.end());
        }
        payload.insert(payload.end(), obu.begin(), obu.end());
      }
      return payload;
    }

    /**
     * @brief Build one AV1 fragmented-OBU RTP payload.
     *
     * @param obu Complete source OBU element.
     * @param offset Source byte offset.
     * @param count Source bytes carried in this fragment.
     * @param continuation Whether the OBU started in a previous packet.
     * @param continues Whether the OBU continues in the next packet.
     * @param starts_sequence Whether this packet begins a new coded video sequence.
     * @return Complete AV1 RTP payload.
     */
    [[nodiscard]] inline std::vector<std::uint8_t> make_av1_fragment_payload(
      const std::span<const std::uint8_t> obu,
      const std::size_t offset,
      const std::size_t count,
      const bool continuation,
      const bool continues,
      const bool starts_sequence
    ) {
      std::vector<std::uint8_t> payload;
      payload.reserve(1 + count);
      payload.push_back(static_cast<std::uint8_t>((continuation ? 0x80U : 0U) | (continues ? 0x40U : 0U) | 0x10U | (starts_sequence ? 0x08U : 0U)));
      payload.insert(
        payload.end(),
        obu.begin() + static_cast<std::ptrdiff_t>(offset),
        obu.begin() + static_cast<std::ptrdiff_t>(offset + count)
      );
      return payload;
    }
  }  // namespace detail

  /**
   * @brief Allocation-free AV1 RTP temporal-unit depacketizer backed by caller-owned storage.
   *
   * The depacketizer validates `Z`, `Y`, `W`, `N`, and packet sequence continuity, reconstructs
   * fragmented OBU elements, removes temporal-delimiter and tile-list OBUs, and writes canonical
   * AV1 low-overhead OBU bytes. Each emitted OBU has `obu_has_size_field` set and a minimal LEB128
   * payload size, which is the representation accepted by VideoToolbox. A failure invalidates the
   * current temporal unit so partially reconstructed bytes can never be presented to a decoder.
   */
  class av1_depacketizer {
  public:
    /**
     * @brief Construct a depacketizer over fixed caller-owned output storage.
     *
     * @param storage Storage retained by the caller for the lifetime of this object.
     */
    explicit constexpr av1_depacketizer(const std::span<std::uint8_t> storage) noexcept:
        storage_(storage) {
    }

    /**
     * @brief Reset packet order, fragment state, and output for a new temporal unit.
     */
    constexpr void reset() noexcept {
      committed_size_ = 0;
      fragment_payload_size_ = 0;
      fragment_header_size_ = 0;
      fragment_header_length_ = 0;
      fragment_declared_payload_size_ = 0;
      expected_sequence_number_ = 0;
      rtp_timestamp_ = 0;
      packet_count_ = 0;
      fragment_active_ = false;
      fragment_ignored_ = false;
      fragment_has_size_field_ = false;
      fragment_prefix_complete_ = false;
      fragment_layer_id_present_ = false;
      fragment_start_layer_constraint_present_ = false;
      sequence_initialized_ = false;
      timestamp_initialized_ = false;
      temporal_unit_complete_ = false;
      starts_coded_video_sequence_ = false;
      packet_layer_id_present_ = false;
      failed_ = false;
    }

    /**
     * @brief Consume one decrypted AV1 RTP payload in RTP sequence order.
     *
     * Packet payload bytes are borrowed only for this call. Finalized access-unit bytes and any
     * non-ignored fragment are copied into caller storage. Temporal delimiter and tile-list OBUs
     * are consumed and omitted without consuming caller storage.
     *
     * If a new RTP timestamp arrives after a packet without marker, the current temporal unit is
     * completed and the new packet is deliberately not consumed. The caller reads `bytes()`, calls
     * `reset()`, and retries the same packet when `packet_consumed` is false.
     *
     * @param sequence_number RTP sequence number for discontinuity and reorder detection.
     * @param rtp_timestamp RTP timestamp identifying the temporal unit.
     * @param marker RTP marker bit for an explicit temporal-unit boundary.
     * @param payload AV1 RTP payload beginning with the aggregation header.
     * @return Current finalized byte count, boundary flags, and typed status.
     */
    [[nodiscard]] av1_depacketization_result push_packet(
      const std::uint16_t sequence_number,
      const std::uint32_t rtp_timestamp,
      const bool marker,
      const std::span<const std::uint8_t> payload
    ) noexcept {
      if (failed_) {
        return result(av1_depacketization_error::failed_state, false);
      }
      if (temporal_unit_complete_) {
        return fail(av1_depacketization_error::packet_after_temporal_unit);
      }
      if (sequence_initialized_ && sequence_number != expected_sequence_number_) {
        return fail(av1_depacketization_error::sequence_discontinuity);
      }
      if (timestamp_initialized_ && rtp_timestamp != rtp_timestamp_) {
        if (fragment_active_) {
          return fail(av1_depacketization_error::missing_continuation);
        }
        temporal_unit_complete_ = true;
        return result(av1_depacketization_error::none, false);
      }

      const auto parsed_header = parse_av1_aggregation_header(payload);
      if (!parsed_header) {
        switch (parsed_header.error) {
          case av1_header_error::header_too_short:
            return fail(av1_depacketization_error::payload_too_short);
          case av1_header_error::reserved_bits:
            return fail(av1_depacketization_error::reserved_header_bits);
          case av1_header_error::invalid_sequence_start:
            return fail(av1_depacketization_error::invalid_sequence_start);
          case av1_header_error::none:
            break;
        }
      }
      const auto &header = parsed_header.header;
      if (payload.size() <= 1) {
        return fail(av1_depacketization_error::payload_too_short);
      }
      if (header.continuation_from_previous && !fragment_active_) {
        return fail(av1_depacketization_error::unexpected_continuation);
      }
      if (!header.continuation_from_previous && fragment_active_) {
        return fail(av1_depacketization_error::missing_continuation);
      }
      if (header.starts_coded_video_sequence && packet_count_ != 0) {
        return fail(av1_depacketization_error::invalid_new_sequence_boundary);
      }
      if (marker && header.continues_in_next) {
        return fail(av1_depacketization_error::marker_on_incomplete_obu);
      }

      sequence_initialized_ = true;
      expected_sequence_number_ = static_cast<std::uint16_t>(sequence_number + 1U);
      timestamp_initialized_ = true;
      rtp_timestamp_ = rtp_timestamp;
      packet_layer_id_present_ = false;
      if (header.starts_coded_video_sequence) {
        starts_coded_video_sequence_ = true;
      }
      const auto status = detail::visit_av1_elements(
        payload,
        header,
        [this, &header](
          const std::span<const std::uint8_t> element,
          const bool is_first,
          const bool is_last
        ) noexcept {
          const auto continuation = is_first && header.continuation_from_previous;
          const auto continues = is_last && header.continues_in_next;
          return consume_element(element, continuation, continues);
        }
      );
      if (status != av1_depacketization_error::none) {
        return fail(status);
      }
      ++packet_count_;
      if (marker) {
        if (fragment_active_) {
          return fail(av1_depacketization_error::marker_on_incomplete_obu);
        }
        temporal_unit_complete_ = true;
      }
      return result(av1_depacketization_error::none, true);
    }

    /**
     * @brief Return finalized canonical low-overhead OBU bytes.
     *
     * In-progress fragment bytes are intentionally hidden. A failed temporal unit exposes no
     * bytes, even if earlier packet-local writes succeeded.
     *
     * @return Borrowed finalized bytes, or an empty span after failure.
     */
    [[nodiscard]] constexpr std::span<const std::uint8_t> bytes() const noexcept {
      return failed_ ? std::span<const std::uint8_t> {} :
                       std::span<const std::uint8_t> {storage_.data(), committed_size_};
    }

    /** @brief Return whether marker or a later timestamp completed this temporal unit. */
    [[nodiscard]] constexpr bool complete() const noexcept {
      return temporal_unit_complete_ && !failed_;
    }

    /** @brief Return whether an OBU fragment must continue in the next packet. */
    [[nodiscard]] constexpr bool fragment_pending() const noexcept {
      return fragment_active_ && !failed_;
    }

  private:
    /** @brief Validated OBU header information used by reconstruction. */
    struct obu_header_info {
      std::size_t header_size = 0;  ///< One-byte base header plus optional extension byte.
      std::size_t payload_offset = 0;  ///< Payload offset after header and optional internal size.
      std::size_t payload_size = 0;  ///< Exact decoded OBU payload byte count.
      bool ignored = false;  ///< Temporal delimiter or tile list must not reach the decoder.
      bool has_extension = false;  ///< OBU carries temporal and spatial identifiers.
      std::uint8_t layer_id = 0;  ///< Extension temporal/spatial bits masked with `0xf8`.
      av1_depacketization_error error = av1_depacketization_error::none;  ///< Typed status.
    };

    /**
     * @brief Validate a complete OBU from a retained prefix and total byte count.
     *
     * The prefix must retain the base header, optional extension byte, and up to eight internal
     * LEB128 bytes. Payload bytes need not be retained for ignored fragmented OBUs.
     *
     * @param prefix Complete OBU or its retained header/size prefix.
     * @param total_size Complete OBU-element byte count across every fragment.
     * @return Header layout, canonical payload range, layer, ignore policy, and typed status.
     */
    [[nodiscard]] static constexpr obu_header_info inspect_obu(
      const std::span<const std::uint8_t> prefix,
      const std::size_t total_size
    ) noexcept {
      if (prefix.empty() || total_size == 0) {
        return {.error = av1_depacketization_error::empty_obu_element};
      }
      const auto header = prefix[0];
      if ((header & 0x81U) != 0) {
        return {.error = av1_depacketization_error::invalid_obu_header};
      }
      const auto type = static_cast<std::uint8_t>((header >> 3U) & 0x0fU);
      const auto ignored = type == 2U || type == 8U;
      if (!ignored && type != 1U && (type < 3U || type > 7U) && type != 15U) {
        return {.error = av1_depacketization_error::invalid_obu_header};
      }
      const auto has_extension = (header & 0x04U) != 0;
      const auto header_size = has_extension ? std::size_t {2} : std::size_t {1};
      if (total_size < header_size || prefix.size() < header_size ||
          (has_extension && (prefix[1] & 0x07U) != 0)) {
        return {.error = av1_depacketization_error::invalid_obu_header};
      }
      auto payload_offset = header_size;
      auto payload_size = total_size - header_size;
      if ((header & 0x02U) != 0) {
        const auto size = detail::parse_av1_leb128(prefix.subspan(header_size));
        if (!size) {
          return {.error = size.error};
        }
        payload_offset += size.bytes_consumed;
        if (payload_offset > total_size ||
            static_cast<std::size_t>(size.value) != total_size - payload_offset) {
          return {.error = av1_depacketization_error::invalid_obu_size};
        }
        payload_size = size.value;
      }
      return {
        .header_size = header_size,
        .payload_offset = payload_offset,
        .payload_size = payload_size,
        .ignored = ignored,
        .has_extension = has_extension,
        .layer_id = has_extension ? static_cast<std::uint8_t>(prefix[1] & 0xf8U) :
                                    std::uint8_t {0},
      };
    }

    /**
     * @brief Enforce the AOM packet-local temporal/spatial layer invariant.
     *
     * @param layer_id Extension byte masked with `0xf8`.
     * @return `none` for the first or matching ID, otherwise `inconsistent_layer_ids`.
     */
    [[nodiscard]] constexpr av1_depacketization_error observe_packet_layer(
      const std::uint8_t layer_id
    ) noexcept {
      if (!packet_layer_id_present_) {
        packet_layer_id_ = layer_id;
        packet_layer_id_present_ = true;
        return av1_depacketization_error::none;
      }
      return packet_layer_id_ == layer_id ? av1_depacketization_error::none :
                                            av1_depacketization_error::inconsistent_layer_ids;
    }

    /**
     * @brief Consume one already length-delimited packet-local OBU element.
     *
     * @param element Borrowed complete element or fragment bytes.
     * @param continuation Element continues the pending fragment.
     * @param continues Element remains incomplete after this packet.
     * @return Typed reconstruction status.
     */
    [[nodiscard]] av1_depacketization_error consume_element(
      const std::span<const std::uint8_t> element,
      const bool continuation,
      const bool continues
    ) noexcept {
      if (continuation) {
        const auto status = append_fragment(element);
        if (status != av1_depacketization_error::none || continues) {
          return status;
        }
        return finish_fragment();
      }
      if (fragment_active_) {
        return av1_depacketization_error::missing_continuation;
      }
      if (continues) {
        return begin_fragment(element);
      }
      return append_complete_obu(element);
    }

    /**
     * @brief Start one fragmented OBU.
     *
     * @param element First fragment bytes.
     * @return Typed reconstruction status.
     */
    [[nodiscard]] av1_depacketization_error begin_fragment(
      const std::span<const std::uint8_t> element
    ) noexcept {
      if (element.empty()) {
        return av1_depacketization_error::empty_obu_element;
      }
      const auto header = element[0];
      if ((header & 0x81U) != 0) {
        return av1_depacketization_error::invalid_obu_header;
      }
      const auto type = static_cast<std::uint8_t>((header >> 3U) & 0x0fU);
      fragment_ignored_ = type == 2U || type == 8U;
      if (!fragment_ignored_ && type != 1U && (type < 3U || type > 7U) && type != 15U) {
        return av1_depacketization_error::invalid_obu_header;
      }
      fragment_header_length_ = (header & 0x04U) != 0 ? 2U : 1U;
      fragment_has_size_field_ = (header & 0x02U) != 0;
      fragment_header_size_ = 0;
      fragment_payload_size_ = 0;
      fragment_prefix_complete_ = false;
      fragment_layer_id_present_ = false;
      fragment_start_layer_constraint_present_ = fragment_header_length_ == 2 &&
                                                 packet_layer_id_present_;
      fragment_start_layer_constraint_ = packet_layer_id_;
      fragment_active_ = true;
      return stage_fragment_bytes(element);
    }

    /**
     * @brief Append continuation bytes to the active fragment.
     *
     * @param element Continuation bytes from the first packet element.
     * @return Typed reconstruction status.
     */
    [[nodiscard]] av1_depacketization_error append_fragment(
      const std::span<const std::uint8_t> element
    ) noexcept {
      if (!fragment_active_) {
        return av1_depacketization_error::unexpected_continuation;
      }
      if (element.empty()) {
        return av1_depacketization_error::empty_obu_element;
      }
      if (fragment_layer_id_present_) {
        if (const auto status = observe_packet_layer(fragment_layer_id_);
            status != av1_depacketization_error::none) {
          return status;
        }
      }
      return stage_fragment_bytes(element);
    }

    /**
     * @brief Retain bounded OBU prefix bytes and stage only payload into canonical output storage.
     *
     * @param bytes Next contiguous bytes of the fragmented OBU element.
     * @return Typed prefix, layer, size, or capacity status.
     */
    [[nodiscard]] av1_depacketization_error stage_fragment_bytes(
      const std::span<const std::uint8_t> bytes
    ) noexcept {
      std::size_t offset = 0;
      while (offset < bytes.size() && !fragment_prefix_complete_) {
        if (fragment_header_size_ >= fragment_header_.size()) {
          return av1_depacketization_error::malformed_length;
        }
        fragment_header_[fragment_header_size_++] = bytes[offset++];
        if (fragment_header_size_ < fragment_header_length_) {
          continue;
        }
        if (fragment_header_length_ == 2 && !fragment_layer_id_present_) {
          if ((fragment_header_[1] & 0x07U) != 0) {
            return av1_depacketization_error::invalid_obu_header;
          }
          fragment_layer_id_ = static_cast<std::uint8_t>(fragment_header_[1] & 0xf8U);
          fragment_layer_id_present_ = true;
          if (fragment_start_layer_constraint_present_ &&
              fragment_layer_id_ != fragment_start_layer_constraint_) {
            return av1_depacketization_error::inconsistent_layer_ids;
          }
          if (const auto status = observe_packet_layer(fragment_layer_id_);
              status != av1_depacketization_error::none) {
            return status;
          }
        }
        if (!fragment_has_size_field_) {
          fragment_prefix_complete_ = true;
          break;
        }
        const auto size_bytes = fragment_header_size_ - fragment_header_length_;
        if (size_bytes == 0) {
          continue;
        }
        if ((fragment_header_[fragment_header_size_ - 1] & 0x80U) != 0) {
          if (size_bytes == 8) {
            return av1_depacketization_error::malformed_length;
          }
          continue;
        }
        const auto parsed = detail::parse_av1_leb128(
          std::span<const std::uint8_t> {fragment_header_.data(), fragment_header_size_}.subspan(
            fragment_header_length_
          )
        );
        if (!parsed) {
          return parsed.error;
        }
        fragment_declared_payload_size_ = parsed.value;
        fragment_prefix_complete_ = true;
      }

      const auto payload = bytes.subspan(offset);
      if (payload.size() > std::numeric_limits<std::size_t>::max() - fragment_payload_size_) {
        return av1_depacketization_error::malformed_length;
      }
      if (!fragment_ignored_) {
        if (payload.size() > storage_.size() - committed_size_ - fragment_payload_size_) {
          return av1_depacketization_error::output_too_small;
        }
        std::memmove(
          storage_.data() + committed_size_ + fragment_payload_size_,
          payload.data(),
          payload.size()
        );
      }
      fragment_payload_size_ += payload.size();
      return av1_depacketization_error::none;
    }

    /**
     * @brief Finalize the active fragment into one canonical low-overhead OBU.
     *
     * @return Typed reconstruction status.
     */
    [[nodiscard]] av1_depacketization_error finish_fragment() noexcept {
      if (!fragment_prefix_complete_) {
        return av1_depacketization_error::invalid_obu_header;
      }
      if (fragment_has_size_field_ &&
          static_cast<std::size_t>(fragment_declared_payload_size_) != fragment_payload_size_) {
        return av1_depacketization_error::invalid_obu_size;
      }
      if (fragment_ignored_) {
        clear_fragment();
        return av1_depacketization_error::none;
      }
      const auto length_size = detail::leb128_size(fragment_payload_size_);
      const auto canonical_size = fragment_header_length_ + length_size + fragment_payload_size_;
      if (canonical_size > storage_.size() - committed_size_) {
        return av1_depacketization_error::output_too_small;
      }
      auto *const start = storage_.data() + committed_size_;
      std::memmove(
        start + fragment_header_length_ + length_size,
        start,
        fragment_payload_size_
      );
      start[0] = static_cast<std::uint8_t>(fragment_header_[0] | 0x02U);
      if (fragment_header_length_ == 2) {
        start[1] = fragment_header_[1];
      }
      write_leb128(
        fragment_payload_size_,
        std::span<std::uint8_t> {start + fragment_header_length_, length_size}
      );
      committed_size_ += canonical_size;
      clear_fragment();
      return av1_depacketization_error::none;
    }

    /**
     * @brief Append one complete OBU in canonical low-overhead form.
     *
     * @param element Complete normalized RTP OBU element.
     * @return Typed reconstruction status.
     */
    [[nodiscard]] av1_depacketization_error append_complete_obu(
      const std::span<const std::uint8_t> element
    ) noexcept {
      const auto info = inspect_obu(element, element.size());
      if (info.error != av1_depacketization_error::none) {
        return info.error;
      }
      if (info.has_extension) {
        if (const auto status = observe_packet_layer(info.layer_id);
            status != av1_depacketization_error::none) {
          return status;
        }
      }
      if (info.ignored) {
        return av1_depacketization_error::none;
      }
      const auto length_size = detail::leb128_size(info.payload_size);
      const auto required = info.header_size + length_size + info.payload_size;
      if (required > storage_.size() - committed_size_) {
        return av1_depacketization_error::output_too_small;
      }
      auto *const destination = storage_.data() + committed_size_;
      const auto base_header = static_cast<std::uint8_t>(element[0] | 0x02U);
      const auto extension_header = info.header_size == 2 ? element[1] : std::uint8_t {0};
      std::memmove(
        destination + info.header_size + length_size,
        element.data() + info.payload_offset,
        info.payload_size
      );
      destination[0] = base_header;
      if (info.header_size == 2) {
        destination[1] = extension_header;
      }
      write_leb128(
        info.payload_size,
        std::span<std::uint8_t> {destination + info.header_size, length_size}
      );
      committed_size_ += required;
      return av1_depacketization_error::none;
    }

    /**
     * @brief Write a minimal LEB128 value into exact caller storage.
     *
     * @param value Value to encode.
     * @param destination Exact-sized destination returned by `leb128_size`.
     */
    static constexpr void write_leb128(
      std::size_t value,
      const std::span<std::uint8_t> destination
    ) noexcept {
      std::size_t index = 0;
      do {
        auto byte = static_cast<std::uint8_t>(value & 0x7fU);
        value >>= 7U;
        if (value != 0) {
          byte = static_cast<std::uint8_t>(byte | 0x80U);
        }
        destination[index++] = byte;
      } while (value != 0);
    }

    /** @brief Clear active-fragment metadata without changing finalized bytes. */
    constexpr void clear_fragment() noexcept {
      fragment_payload_size_ = 0;
      fragment_header_size_ = 0;
      fragment_header_length_ = 0;
      fragment_declared_payload_size_ = 0;
      fragment_active_ = false;
      fragment_ignored_ = false;
      fragment_has_size_field_ = false;
      fragment_prefix_complete_ = false;
      fragment_layer_id_present_ = false;
      fragment_start_layer_constraint_present_ = false;
    }

    /**
     * @brief Build the current public result.
     *
     * @param error Typed status.
     * @return Result hiding all bytes after failure.
     */
    [[nodiscard]] constexpr av1_depacketization_result result(
      const av1_depacketization_error error,
      const bool packet_consumed
    ) const noexcept {
      return {
        .bytes_written = error == av1_depacketization_error::none ? committed_size_ : 0,
        .temporal_unit_complete = error == av1_depacketization_error::none && temporal_unit_complete_,
        .starts_coded_video_sequence = starts_coded_video_sequence_,
        .packet_consumed = packet_consumed,
        .error = error,
      };
    }

    /**
     * @brief Invalidate the temporal unit and return one failure.
     *
     * @param error Failure that invalidated reconstruction.
     * @return Public failure result.
     */
    [[nodiscard]] constexpr av1_depacketization_result fail(
      const av1_depacketization_error error
    ) noexcept {
      failed_ = true;
      temporal_unit_complete_ = false;
      return result(error, false);
    }

    std::span<std::uint8_t> storage_ {};  ///< Caller-owned canonical access-unit storage.
    std::array<std::uint8_t, 10> fragment_header_ {};  ///< Base, extension, and eight size bytes.
    std::size_t committed_size_ = 0;  ///< Finalized canonical OBU byte count.
    std::size_t fragment_payload_size_ = 0;  ///< Payload-only bytes staged after finalized data.
    std::size_t fragment_header_size_ = 0;  ///< Available header-prefix bytes.
    std::size_t fragment_header_length_ = 0;  ///< Required base plus extension header bytes.
    std::uint32_t fragment_declared_payload_size_ = 0;  ///< Parsed internal `obu_size`.
    std::uint16_t expected_sequence_number_ = 0;  ///< Next accepted RTP sequence number.
    std::uint32_t rtp_timestamp_ = 0;  ///< Timestamp of the temporal unit in caller storage.
    std::size_t packet_count_ = 0;  ///< Accepted packet count in this temporal unit.
    std::uint8_t fragment_layer_id_ = 0;  ///< Active extended OBU temporal/spatial identifier.
    std::uint8_t fragment_start_layer_constraint_ = 0;  ///< Layer required by fragment-start packet.
    std::uint8_t packet_layer_id_ = 0;  ///< Required temporal/spatial identifier in this packet.
    bool fragment_active_ = false;  ///< Whether `Z` is required on the next packet.
    bool fragment_ignored_ = false;  ///< Active fragment is a TD or tile-list OBU.
    bool fragment_has_size_field_ = false;  ///< Active OBU supplied an internal size.
    bool fragment_prefix_complete_ = false;  ///< Header and optional internal size are retained.
    bool fragment_layer_id_present_ = false;  ///< Active fragment extension byte is available.
    bool fragment_start_layer_constraint_present_ = false;  ///< Start packet established a layer.
    bool sequence_initialized_ = false;  ///< Whether packet-order tracking has begun.
    bool timestamp_initialized_ = false;  ///< Whether the temporal-unit timestamp is known.
    bool temporal_unit_complete_ = false;  ///< Marker or later RTP timestamp closed the unit.
    bool starts_coded_video_sequence_ = false;  ///< First packet carried `N`.
    bool packet_layer_id_present_ = false;  ///< Current packet established an extension layer ID.
    bool failed_ = false;  ///< A packet invalidated the current temporal unit.
  };

  /**
   * @brief Packetize one AV1 temporal unit using AOM RTP payload format version 1.0.
   *
   * Complete normalized OBU elements are aggregated without crossing the supplied temporal-unit
   * boundary. Large elements use `Z`/`Y` fragmentation descriptors. `N` is emitted only on the
   * first packet of an explicitly identified coded-video-sequence start, and RTP marker is set on
   * the final packet of the temporal unit.
   * Temporal-delimiter and tile-list OBUs are filtered before packet construction. If filtering
   * removes every supplied OBU, the result is `empty_access_unit` and no RTP packet is emitted.
   *
   * @param obus Normalized OBU elements from one temporal unit, with OBU size fields removed.
   * @param starts_coded_video_sequence Whether this temporal unit begins a coded video sequence.
   * @param config RTP, path-payload, and frame-boundary extension configuration.
   * @return Complete RTP packets and typed status.
   */
  [[nodiscard]] inline packetization_result packetize_av1(
    const std::span<const std::span<const std::uint8_t>> obus,
    const bool starts_coded_video_sequence,
    const video_packetization_config &config
  ) {
    packetization_result failure;
    failure.next_sequence_number = config.stream.first_sequence_number;
    if (obus.empty()) {
      failure.error = packetization_error::empty_access_unit;
      return failure;
    }
    std::vector<std::span<const std::uint8_t>> filtered_obus;
    filtered_obus.reserve(obus.size());
    for (const auto obu : obus) {
      if (obu.empty()) {
        failure.error = packetization_error::empty_codec_unit;
        return failure;
      }
      switch (detail::classify_av1_source_obu(obu)) {
        case detail::av1_source_obu_status::valid:
          filtered_obus.push_back(obu);
          break;
        case detail::av1_source_obu_status::ignored:
          break;
        case detail::av1_source_obu_status::malformed:
          failure.error = packetization_error::malformed_codec_unit;
          return failure;
      }
    }
    if (filtered_obus.empty()) {
      failure.error = packetization_error::empty_access_unit;
      return failure;
    }
    if (const auto status = detail::validate_video_config(config); status != packetization_error::none) {
      failure.error = status;
      return failure;
    }

    const auto boundary_capacity = detail::boundary_codec_capacity(config);
    const auto middle_capacity = detail::middle_codec_capacity(config);
    if (boundary_capacity < 2 || middle_capacity < 2) {
      failure.error = packetization_error::path_payload_too_small;
      return failure;
    }

    std::vector<std::vector<std::uint8_t>> payloads;
    std::size_t obu_index = 0;
    std::size_t fragment_offset = 0;
    const std::span<const std::span<const std::uint8_t>> carried_obus {filtered_obus};
    while (obu_index < carried_obus.size()) {
      const auto obu = carried_obus[obu_index];
      if (fragment_offset != 0 && obu_index + 1 == carried_obus.size() && obu.size() - fragment_offset <= boundary_capacity - 1) {
        const auto remaining = obu.size() - fragment_offset;
        payloads.push_back(detail::make_av1_fragment_payload(obu, fragment_offset, remaining, true, false, false));
        ++obu_index;
        break;
      }

      if (fragment_offset == 0) {
        std::size_t final_count = 0;
        for (std::size_t count = 1; count <= carried_obus.size() - obu_index; ++count) {
          if (!detail::av1_elements_may_aggregate(carried_obus, obu_index, count) ||
              detail::av1_complete_packet_size(carried_obus, obu_index, count) > boundary_capacity) {
            break;
          }
          final_count = count;
        }
        if (final_count == carried_obus.size() - obu_index) {
          payloads.push_back(detail::make_av1_complete_payload(carried_obus, obu_index, final_count, starts_coded_video_sequence && payloads.empty()));
          obu_index = carried_obus.size();
          break;
        }
      }

      const auto capacity = payloads.size() < 2 ? boundary_capacity : middle_capacity;
      if (fragment_offset != 0 || obu.size() + 1 > capacity || (obu_index + 1 == carried_obus.size() && obu.size() + 1 > boundary_capacity)) {
        const auto remaining = obu.size() - fragment_offset;
        const auto data_capacity = capacity - 1;
        auto count = std::min(remaining, data_capacity);
        if (obu_index + 1 == carried_obus.size() && count == remaining && remaining > boundary_capacity - 1) {
          --count;
        }
        if (count == 0) {
          failure.error = packetization_error::path_payload_too_small;
          return failure;
        }
        const auto end = count == remaining;
        payloads.push_back(detail::make_av1_fragment_payload(obu, fragment_offset, count, fragment_offset != 0, !end, starts_coded_video_sequence && payloads.empty() && fragment_offset == 0));
        fragment_offset += count;
        if (end) {
          ++obu_index;
          fragment_offset = 0;
        }
        continue;
      }

      std::size_t aggregate_count = 0;
      for (std::size_t count = 1; count <= carried_obus.size() - obu_index; ++count) {
        if (!detail::av1_elements_may_aggregate(carried_obus, obu_index, count)) {
          break;
        }
        const auto size = detail::av1_complete_packet_size(carried_obus, obu_index, count);
        if (size > capacity) {
          break;
        }
        if (obu_index + count == carried_obus.size() && size > boundary_capacity) {
          break;
        }
        aggregate_count = count;
      }
      if (aggregate_count == 0) {
        fragment_offset = 0;
        continue;
      }
      payloads.push_back(detail::make_av1_complete_payload(carried_obus, obu_index, aggregate_count, starts_coded_video_sequence && payloads.empty()));
      obu_index += aggregate_count;
    }
    return detail::assemble_video_packets(std::move(payloads), config);
  }
}  // namespace lumen::lsp::media
