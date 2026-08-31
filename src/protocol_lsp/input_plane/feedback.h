/**
 * @file src/protocol_lsp/input_plane/feedback.h
 * @brief Frozen LSPI acknowledgements and LSPG controller-output wire/state models.
 */

#pragma once

#include "state.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <span>
#include <utility>

namespace lumen::lsp::input_plane {
  /** @brief Four-byte SRTCP APP name for input acknowledgements. */
  inline constexpr std::array<std::uint8_t, 4> lspi_name {'L', 'S', 'P', 'I'};

  /** @brief Four-byte SRTCP APP name for controller output. */
  inline constexpr std::array<std::uint8_t, 4> lspg_name {'L', 'S', 'P', 'G'};

  /** @brief Fixed LSPI ACK bytes before zero through four pointer records. */
  inline constexpr std::size_t lspi_fixed_size = 72;

  /** @brief Fixed bytes in one active-pointer LSPI ACK record. */
  inline constexpr std::size_t lspi_pointer_record_size = 16;

  /** @brief Maximum pointers acknowledged in one LSP/1 LSPI APP payload. */
  inline constexpr std::size_t maximum_acknowledged_pointers = 4;

  /** @brief LSPI ACK flags. */
  enum class lspi_flag : std::uint8_t {
    baseline_requested = 1U << 0U,  ///< Host requests a fresh baseline at the expected next edge.
  };

  /** @brief One active pointer's greatest applied physical sample. */
  struct lspi_pointer_ack {
    std::uint32_t pointer_id = 0;  ///< Pointer object ID in the range 1 through 4.
    std::uint32_t instance_generation = 0;  ///< Exact active pointer instance generation.
    std::uint64_t physical_ordinal = 0;  ///< Greatest applied physical sample ordinal.

    /** @brief Compare all pointer ACK fields. */
    [[nodiscard]] bool operator==(const lspi_pointer_ack &) const noexcept = default;
  };

  /** @brief Protected LSPI acknowledgement state. */
  struct lspi_ack {
    std::uint32_t input_generation = 0;  ///< Exact input authority generation.
    std::uint8_t flags = 0;  ///< Frozen LSPI flags.
    std::uint64_t accepted_baseline_id = 0;  ///< Committed baseline ID, or zero before commit.
    std::uint64_t highest_accepted_state_sequence = 0;  ///< Greatest retained replaceable state.
    std::uint64_t highest_applied_state_sequence = 0;  ///< Greatest platform-applied replaceable state.
    std::uint64_t contiguous_edge_id = 0;  ///< Greatest contiguously applied edge.
    std::uint64_t edge_reception_bitmap = 0;  ///< Receipt of the next 64 edge IDs.
    std::uint64_t host_receive_time_us = 0;  ///< Host monotonic receive time.
    std::uint64_t host_apply_time_us = 0;  ///< Host monotonic apply completion time.
    std::uint64_t first_video_frame_id = 0;  ///< First captured frame carrying this watermark.
    std::array<lspi_pointer_ack, maximum_acknowledged_pointers> pointers {};  ///< Active pointer samples.
    std::uint8_t pointer_count = 0;  ///< Live leading records in `pointers`.

    /** @brief Compare all LSPI ACK fields and pointer records. */
    [[nodiscard]] bool operator==(const lspi_ack &) const noexcept = default;
  };

  /** @brief LSPI wire codec result. */
  enum class lspi_error : std::uint8_t {
    none,  ///< Codec succeeded.
    too_short,  ///< Payload is shorter than fixed LSPI fields.
    output_too_small,  ///< Destination cannot hold the exact pointer count.
    invalid_generation,  ///< Input or pointer generation is zero/stale.
    reserved_flags,  ///< Unknown flag or nonzero reserved byte was received.
    invalid_length,  ///< Pointer count and exact byte length disagree.
    invalid_sequence,  ///< Applied state exceeds accepted state.
    invalid_pointer,  ///< Pointer identifier, ordinal, or uniqueness is invalid.
  };

  /** @brief Parsed LSPI ACK result. */
  struct parsed_lspi_ack {
    lspi_error error = lspi_error::none;  ///< Parse result.
    lspi_ack value {};  ///< Parsed ACK when successful.

    /** @brief Test whether parsing succeeded. */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == lspi_error::none;
    }
  };

  /**
   * @brief Validate one complete LSPI ACK model.
   *
   * @param value Candidate ACK.
   * @param expected_generation Expected authority generation, or zero for generic vectors.
   * @return Validation result.
   */
  [[nodiscard]] constexpr lspi_error validate_lspi_ack(
    const lspi_ack &value,
    const std::uint32_t expected_generation = 0
  ) noexcept {
    if (value.input_generation == 0 || (expected_generation != 0 && value.input_generation != expected_generation)) {
      return lspi_error::invalid_generation;
    }
    if ((value.flags & ~static_cast<std::uint8_t>(lspi_flag::baseline_requested)) != 0) {
      return lspi_error::reserved_flags;
    }
    if (value.pointer_count > maximum_acknowledged_pointers ||
        value.highest_applied_state_sequence > value.highest_accepted_state_sequence) {
      return value.pointer_count > maximum_acknowledged_pointers ? lspi_error::invalid_length : lspi_error::invalid_sequence;
    }
    for (std::size_t index = 0; index < value.pointer_count; ++index) {
      const auto &pointer = value.pointers[index];
      if (pointer.pointer_id == 0 || pointer.pointer_id > maximum_acknowledged_pointers ||
          pointer.instance_generation == 0 || pointer.physical_ordinal == 0) {
        return lspi_error::invalid_pointer;
      }
      for (std::size_t prior = 0; prior < index; ++prior) {
        if (value.pointers[prior].pointer_id == pointer.pointer_id) {
          return lspi_error::invalid_pointer;
        }
      }
    }
    return lspi_error::none;
  }

  /**
   * @brief Serialize one frozen LSPI ACK APP payload.
   *
   * @param value ACK state.
   * @param output Destination bytes.
   * @return Codec result.
   */
  [[nodiscard]] constexpr lspi_error serialize_lspi_ack(
    const lspi_ack &value,
    const std::span<std::uint8_t> output
  ) noexcept {
    const auto validation = validate_lspi_ack(value);
    if (validation != lspi_error::none) {
      return validation;
    }
    const auto size = lspi_fixed_size + std::size_t {value.pointer_count} * lspi_pointer_record_size;
    if (output.size() < size) {
      return lspi_error::output_too_small;
    }
    wire::write_be<std::uint32_t>(output.first<4>(), value.input_generation);
    output[4] = value.pointer_count;
    output[5] = value.flags;
    output[6] = 0;
    output[7] = 0;
    wire::write_be<std::uint64_t>(output.subspan(8, 8), value.accepted_baseline_id);
    wire::write_be<std::uint64_t>(output.subspan(16, 8), value.highest_accepted_state_sequence);
    wire::write_be<std::uint64_t>(output.subspan(24, 8), value.highest_applied_state_sequence);
    wire::write_be<std::uint64_t>(output.subspan(32, 8), value.contiguous_edge_id);
    wire::write_be<std::uint64_t>(output.subspan(40, 8), value.edge_reception_bitmap);
    wire::write_be<std::uint64_t>(output.subspan(48, 8), value.host_receive_time_us);
    wire::write_be<std::uint64_t>(output.subspan(56, 8), value.host_apply_time_us);
    wire::write_be<std::uint64_t>(output.subspan(64, 8), value.first_video_frame_id);
    for (std::size_t index = 0; index < value.pointer_count; ++index) {
      const auto offset = lspi_fixed_size + index * lspi_pointer_record_size;
      wire::write_be<std::uint32_t>(output.subspan(offset, 4), value.pointers[index].pointer_id);
      wire::write_be<std::uint32_t>(output.subspan(offset + 4, 4), value.pointers[index].instance_generation);
      wire::write_be<std::uint64_t>(output.subspan(offset + 8, 8), value.pointers[index].physical_ordinal);
    }
    return lspi_error::none;
  }

  /**
   * @brief Parse one exact frozen LSPI ACK APP payload.
   *
   * @param bytes Complete bytes following the SRTCP APP name.
   * @param expected_generation Expected authority generation, or zero for generic vectors.
   * @return Parsed ACK or validation error.
   */
  [[nodiscard]] constexpr parsed_lspi_ack parse_lspi_ack(
    const std::span<const std::uint8_t> bytes,
    const std::uint32_t expected_generation = 0
  ) noexcept {
    if (bytes.size() < lspi_fixed_size) {
      return {.error = lspi_error::too_short};
    }
    lspi_ack value {
      .input_generation = wire::read_be<std::uint32_t>(bytes.first<4>()),
      .flags = bytes[5],
      .accepted_baseline_id = wire::read_be<std::uint64_t>(bytes.subspan(8, 8)),
      .highest_accepted_state_sequence = wire::read_be<std::uint64_t>(bytes.subspan(16, 8)),
      .highest_applied_state_sequence = wire::read_be<std::uint64_t>(bytes.subspan(24, 8)),
      .contiguous_edge_id = wire::read_be<std::uint64_t>(bytes.subspan(32, 8)),
      .edge_reception_bitmap = wire::read_be<std::uint64_t>(bytes.subspan(40, 8)),
      .host_receive_time_us = wire::read_be<std::uint64_t>(bytes.subspan(48, 8)),
      .host_apply_time_us = wire::read_be<std::uint64_t>(bytes.subspan(56, 8)),
      .first_video_frame_id = wire::read_be<std::uint64_t>(bytes.subspan(64, 8)),
      .pointer_count = bytes[4],
    };
    if (bytes[6] != 0 || bytes[7] != 0) {
      return {.error = lspi_error::reserved_flags};
    }
    if (value.pointer_count > maximum_acknowledged_pointers ||
        bytes.size() != lspi_fixed_size + std::size_t {value.pointer_count} * lspi_pointer_record_size) {
      return {.error = lspi_error::invalid_length};
    }
    for (std::size_t index = 0; index < value.pointer_count; ++index) {
      const auto offset = lspi_fixed_size + index * lspi_pointer_record_size;
      value.pointers[index] = {
        .pointer_id = wire::read_be<std::uint32_t>(bytes.subspan(offset, 4)),
        .instance_generation = wire::read_be<std::uint32_t>(bytes.subspan(offset + 4, 4)),
        .physical_ordinal = wire::read_be<std::uint64_t>(bytes.subspan(offset + 8, 8)),
      };
    }
    const auto validation = validate_lspi_ack(value, expected_generation);
    return validation == lspi_error::none ? parsed_lspi_ack {.value = value} : parsed_lspi_ack {.error = validation};
  }

  /**
   * @brief Test whether an LSPI ACK explicitly acknowledges one retained edge ID.
   *
   * @param ack Parsed ACK.
   * @param edge_id Nonzero retained edge ID.
   * @return `true` for a contiguous applied ID or a set forward-reception bit.
   */
  [[nodiscard]] constexpr bool lspi_acknowledges_edge(const lspi_ack &ack, const std::uint64_t edge_id) noexcept {
    if (edge_id == 0) {
      return false;
    }
    if (edge_id <= ack.contiguous_edge_id) {
      return true;
    }
    const auto distance = edge_id - ack.contiguous_edge_id;
    return distance <= 64 && (ack.edge_reception_bitmap & (std::uint64_t {1} << (distance - 1U))) != 0;
  }

  /** @brief Bounded LSPI ACK cadence controller. */
  class lspi_ack_scheduler {
  public:
    /** @brief Record baseline commit, which requests the earliest legal immediate ACK. */
    constexpr void baseline_committed() noexcept {
      urgent_ = true;
      pending_records_ = std::max<std::uint8_t>(pending_records_, 1);
    }

    /** @brief Record one applied edge, which requests the earliest legal immediate ACK. */
    constexpr void edge_applied() noexcept {
      urgent_ = true;
      if (pending_records_ != std::numeric_limits<std::uint8_t>::max()) {
        ++pending_records_;
      }
    }

    /** @brief Record one applied replaceable state for the 1-ms/eight-record cadence. */
    constexpr void state_applied() noexcept {
      if (pending_records_ != std::numeric_limits<std::uint8_t>::max()) {
        ++pending_records_;
      }
    }

    /**
     * @brief Determine whether an ACK should be emitted now.
     *
     * The hard minimum is 125 microseconds. Otherwise urgent ACKs leave at the
     * earliest legal instant and ordinary ACKs leave at eight records or 1 ms.
     *
     * @param now_us Current host monotonic time.
     * @return `true` when an ACK should be serialized.
     */
    [[nodiscard]] constexpr bool due(const std::uint64_t now_us) const noexcept {
      if (pending_records_ == 0) {
        return false;
      }
      if (last_sent_us_ == 0) {
        return true;
      }
      const auto elapsed = now_us - last_sent_us_;
      return elapsed >= 125 && (urgent_ || pending_records_ >= 8 || elapsed >= 1'000);
    }

    /**
     * @brief Mark one LSPI ACK submitted and reset pending cadence counters.
     *
     * @param now_us Nonzero monotonic submission time.
     */
    constexpr void mark_sent(const std::uint64_t now_us) noexcept {
      last_sent_us_ = now_us;
      pending_records_ = 0;
      urgent_ = false;
    }

  private:
    std::uint64_t last_sent_us_ = 0;  ///< Most recent ACK submission time.
    std::uint8_t pending_records_ = 0;  ///< Saturating applied record count.
    bool urgent_ = false;  ///< Whether baseline/edge application requests immediate ACK.
  };

  /** @brief Frozen LSPG APP subtypes. */
  enum class lspg_subtype : std::uint8_t {
    latest_state = 1,  ///< Replaceable rumble amplitudes and LED color.
    command = 2,  ///< Acknowledged generation-scoped controller command.
    acknowledgement = 3,  ///< Terminal command acknowledgement.
  };

  /** @brief Acknowledged LSPG controller command kinds. */
  enum class controller_command_kind : std::uint8_t {
    adaptive_trigger = 1,  ///< Bounded negotiated adaptive-trigger program.
    haptic_waveform = 2,  ///< Bounded negotiated haptic primitive and parameters.
    motion_sensor = 3,  ///< Enable or disable controller motion sensors.
    player_slot = 4,  ///< Change player-slot assignment.
  };

  /** @brief Terminal LSPG command acknowledgement status. */
  enum class controller_command_status : std::uint8_t {
    success = 0,  ///< Command applied once.
    unsupported = 1,  ///< Negotiated device lacks the named primitive.
    stale_generation = 2,  ///< Device was removed or rebound; command was not applied.
    failed = 3,  ///< Platform rejected the command.
    expired = 4,  ///< Command deadline passed before application.
  };

  /** @brief Replaceable LSPG latest controller output state. */
  struct controller_latest_state {
    std::uint32_t input_generation = 0;  ///< Input authority generation.
    std::uint32_t controller_id = 0;  ///< Controller slot/device ID.
    std::uint32_t instance_generation = 0;  ///< Exact controller instance generation.
    std::uint64_t sequence = 0;  ///< Nonzero direction-wide output sequence.
    std::uint16_t low_frequency_rumble = 0;  ///< Low-frequency amplitude.
    std::uint16_t high_frequency_rumble = 0;  ///< High-frequency amplitude.
    std::uint8_t led_red = 0;  ///< Latest LED red channel.
    std::uint8_t led_green = 0;  ///< Latest LED green channel.
    std::uint8_t led_blue = 0;  ///< Latest LED blue channel.

    /** @brief Compare every latest-state field. */
    [[nodiscard]] bool operator==(const controller_latest_state &) const noexcept = default;
  };

  /** @brief Maximum bounded parameter bytes in one 256-byte LSPG command packet. */
  inline constexpr std::size_t maximum_controller_command_parameters = 224;

  /** @brief One acknowledged, retained LSPG controller command. */
  struct controller_command {
    std::uint32_t input_generation = 0;  ///< Input authority generation.
    std::uint32_t controller_id = 0;  ///< Controller device ID.
    std::uint32_t instance_generation = 0;  ///< Exact controller instance generation.
    std::uint64_t sequence = 0;  ///< Nonzero direction-wide command sequence.
    controller_command_kind kind = controller_command_kind::adaptive_trigger;  ///< Command primitive.
    std::array<std::uint8_t, maximum_controller_command_parameters> parameters {};  ///< Bounded parameters.
    std::uint16_t parameter_length = 0;  ///< Live leading parameter bytes.
    std::uint64_t deadline_us = 0;  ///< Absolute bounded retry/application deadline.

    /** @brief Compare all wire-significant command fields except local deadline. */
    [[nodiscard]] bool same_wire_command(const controller_command &other) const noexcept {
      return input_generation == other.input_generation && controller_id == other.controller_id &&
             instance_generation == other.instance_generation && sequence == other.sequence && kind == other.kind &&
             parameter_length == other.parameter_length &&
             std::equal(parameters.begin(), parameters.begin() + parameter_length, other.parameters.begin());
    }
  };

  /** @brief One terminal LSPG controller command ACK. */
  struct controller_command_ack {
    std::uint32_t input_generation = 0;  ///< Input authority generation.
    std::uint32_t controller_id = 0;  ///< Controller device ID.
    std::uint32_t instance_generation = 0;  ///< Exact controller instance generation.
    std::uint64_t sequence = 0;  ///< Acknowledged command sequence.
    controller_command_status status = controller_command_status::success;  ///< Terminal result.

    /** @brief Compare every command ACK field. */
    [[nodiscard]] bool operator==(const controller_command_ack &) const noexcept = default;
  };

  /** @brief Frozen LSPG common-envelope size before subtype payload. */
  inline constexpr std::size_t lspg_header_size = 28;

  /** @brief Maximum complete bytes following the SRTCP APP name. */
  inline constexpr std::size_t maximum_lspg_packet_size = 256;

  /** @brief LSPG wire codec result. */
  enum class lspg_error : std::uint8_t {
    none,  ///< Codec succeeded.
    too_short,  ///< Fewer than 28 envelope bytes were supplied.
    output_too_small,  ///< Destination cannot hold the complete packet.
    invalid_magic,  ///< Packet does not start with `LSPG`.
    unsupported_version,  ///< Wire version is not one.
    unknown_subtype,  ///< Subtype is not assigned by LSP/1.
    invalid_length,  ///< Payload length is inconsistent or packet exceeds 256 bytes.
    stale_generation,  ///< Input/controller generation is zero or does not match.
    invalid_sequence,  ///< Direction-wide sequence is zero.
    invalid_payload,  ///< State, command, or ACK payload is malformed.
  };

  /** @brief Zero-copy parsed LSPG envelope. */
  struct parsed_lspg {
    lspg_error error = lspg_error::none;  ///< Parse result.
    lspg_subtype subtype = lspg_subtype::latest_state;  ///< Parsed subtype.
    std::uint32_t input_generation = 0;  ///< Parsed input generation.
    std::uint32_t controller_id = 0;  ///< Parsed controller ID.
    std::uint32_t instance_generation = 0;  ///< Parsed controller generation.
    std::uint64_t sequence = 0;  ///< Parsed output sequence.
    std::span<const std::uint8_t> payload {};  ///< Validated subtype bytes.

    /** @brief Test whether parsing succeeded. */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == lspg_error::none;
    }
  };

  /**
   * @brief Test whether a controller command kind is assigned by LSP/1.
   *
   * @param kind Candidate kind.
   * @return `true` for the four acknowledged command primitives.
   */
  [[nodiscard]] constexpr bool valid_controller_command_kind(const controller_command_kind kind) noexcept {
    return kind >= controller_command_kind::adaptive_trigger && kind <= controller_command_kind::player_slot;
  }

  /**
   * @brief Test whether a terminal controller command status is assigned.
   *
   * @param status Candidate status.
   * @return `true` for a frozen status.
   */
  [[nodiscard]] constexpr bool valid_controller_command_status(const controller_command_status status) noexcept {
    return status >= controller_command_status::success && status <= controller_command_status::expired;
  }

  /**
   * @brief Parse and validate one frozen LSPG APP payload.
   *
   * @param bytes Complete bytes beginning with `LSPG`.
   * @return Zero-copy parsed envelope.
   */
  [[nodiscard]] constexpr parsed_lspg parse_lspg(const std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.size() < lspg_header_size) {
      return {.error = lspg_error::too_short};
    }
    if (!std::equal(lspg_name.begin(), lspg_name.end(), bytes.begin())) {
      return {.error = lspg_error::invalid_magic};
    }
    if (bytes[4] != 1) {
      return {.error = lspg_error::unsupported_version};
    }
    const auto subtype = static_cast<lspg_subtype>(bytes[5]);
    if (subtype < lspg_subtype::latest_state || subtype > lspg_subtype::acknowledgement) {
      return {.error = lspg_error::unknown_subtype};
    }
    const auto payload_length = wire::read_be<std::uint16_t>(bytes.subspan(6, 2));
    if (bytes.size() > maximum_lspg_packet_size || bytes.size() != lspg_header_size + payload_length) {
      return {.error = lspg_error::invalid_length};
    }
    parsed_lspg value {
      .subtype = subtype,
      .input_generation = wire::read_be<std::uint32_t>(bytes.subspan(8, 4)),
      .controller_id = wire::read_be<std::uint32_t>(bytes.subspan(12, 4)),
      .instance_generation = wire::read_be<std::uint32_t>(bytes.subspan(16, 4)),
      .sequence = wire::read_be<std::uint64_t>(bytes.subspan(20, 8)),
      .payload = bytes.subspan(lspg_header_size),
    };
    if (value.input_generation == 0 || value.controller_id == 0 || value.instance_generation == 0) {
      return {.error = lspg_error::stale_generation};
    }
    if (value.sequence == 0) {
      return {.error = lspg_error::invalid_sequence};
    }
    switch (value.subtype) {
      case lspg_subtype::latest_state:
        if (value.payload.size() != 8 || value.payload[7] != 0) {
          return {.error = lspg_error::invalid_payload};
        }
        break;
      case lspg_subtype::command:
        {
          if (value.payload.size() < 4 || !valid_controller_command_kind(static_cast<controller_command_kind>(value.payload[0])) ||
              value.payload[1] != 0 || wire::read_be<std::uint16_t>(value.payload.subspan(2, 2)) != value.payload.size() - 4) {
            return {.error = lspg_error::invalid_payload};
          }
          break;
        }
      case lspg_subtype::acknowledgement:
        if (value.payload.size() != 4 || !valid_controller_command_status(static_cast<controller_command_status>(value.payload[0])) ||
            value.payload[1] != 0 || value.payload[2] != 0 || value.payload[3] != 0) {
          return {.error = lspg_error::invalid_payload};
        }
        break;
    }
    return value;
  }

  /**
   * @brief Write a checked LSPG envelope and subtype payload.
   *
   * @param subtype Frozen LSPG subtype.
   * @param input_generation Nonzero authority generation.
   * @param controller_id Nonzero controller ID.
   * @param instance_generation Nonzero controller instance generation.
   * @param sequence Nonzero direction-wide output sequence.
   * @param payload Checked subtype bytes.
   * @param output Destination buffer.
   * @return Codec result.
   */
  [[nodiscard]] constexpr lspg_error serialize_lspg(
    const lspg_subtype subtype,
    const std::uint32_t input_generation,
    const std::uint32_t controller_id,
    const std::uint32_t instance_generation,
    const std::uint64_t sequence,
    const std::span<const std::uint8_t> payload,
    const std::span<std::uint8_t> output
  ) noexcept {
    if (input_generation == 0 || controller_id == 0 || instance_generation == 0) {
      return lspg_error::stale_generation;
    }
    if (sequence == 0) {
      return lspg_error::invalid_sequence;
    }
    if (subtype < lspg_subtype::latest_state || subtype > lspg_subtype::acknowledgement ||
        payload.size() > std::numeric_limits<std::uint16_t>::max() ||
        lspg_header_size + payload.size() > maximum_lspg_packet_size) {
      return subtype < lspg_subtype::latest_state || subtype > lspg_subtype::acknowledgement ? lspg_error::unknown_subtype :
                                                                                               lspg_error::invalid_length;
    }
    if (output.size() < lspg_header_size + payload.size()) {
      return lspg_error::output_too_small;
    }
    std::copy(lspg_name.begin(), lspg_name.end(), output.begin());
    output[4] = 1;
    output[5] = static_cast<std::uint8_t>(subtype);
    wire::write_be<std::uint16_t>(output.subspan(6, 2), static_cast<std::uint16_t>(payload.size()));
    wire::write_be<std::uint32_t>(output.subspan(8, 4), input_generation);
    wire::write_be<std::uint32_t>(output.subspan(12, 4), controller_id);
    wire::write_be<std::uint32_t>(output.subspan(16, 4), instance_generation);
    wire::write_be<std::uint64_t>(output.subspan(20, 8), sequence);
    std::copy(payload.begin(), payload.end(), output.begin() + lspg_header_size);
    const auto parsed = parse_lspg(output.first(lspg_header_size + payload.size()));
    return parsed ? lspg_error::none : parsed.error;
  }

  /**
   * @brief Serialize replaceable rumble/LED state into one LSPG packet.
   *
   * @param value Latest controller state.
   * @param output Destination buffer.
   * @return Codec result.
   */
  [[nodiscard]] constexpr lspg_error serialize_controller_latest(
    const controller_latest_state &value,
    const std::span<std::uint8_t> output
  ) noexcept {
    std::array<std::uint8_t, 8> payload {};
    wire::write_be<std::uint16_t>(std::span(payload).first<2>(), value.low_frequency_rumble);
    wire::write_be<std::uint16_t>(std::span(payload).subspan(2, 2), value.high_frequency_rumble);
    payload[4] = value.led_red;
    payload[5] = value.led_green;
    payload[6] = value.led_blue;
    return serialize_lspg(
      lspg_subtype::latest_state,
      value.input_generation,
      value.controller_id,
      value.instance_generation,
      value.sequence,
      payload,
      output
    );
  }

  /**
   * @brief Decode replaceable rumble/LED state from a validated LSPG envelope.
   *
   * @param parsed Parsed envelope.
   * @param output Latest-state destination.
   * @return Codec result.
   */
  [[nodiscard]] constexpr lspg_error decode_controller_latest(
    const parsed_lspg &parsed,
    controller_latest_state &output
  ) noexcept {
    if (!parsed || parsed.subtype != lspg_subtype::latest_state || parsed.payload.size() != 8) {
      return lspg_error::invalid_payload;
    }
    output = {
      .input_generation = parsed.input_generation,
      .controller_id = parsed.controller_id,
      .instance_generation = parsed.instance_generation,
      .sequence = parsed.sequence,
      .low_frequency_rumble = wire::read_be<std::uint16_t>(parsed.payload.first<2>()),
      .high_frequency_rumble = wire::read_be<std::uint16_t>(parsed.payload.subspan(2, 2)),
      .led_red = parsed.payload[4],
      .led_green = parsed.payload[5],
      .led_blue = parsed.payload[6],
    };
    return lspg_error::none;
  }

  /**
   * @brief Serialize one acknowledged controller command into an LSPG packet.
   *
   * @param value Command value.
   * @param output Destination buffer.
   * @return Codec result.
   */
  [[nodiscard]] constexpr lspg_error serialize_controller_command(
    const controller_command &value,
    const std::span<std::uint8_t> output
  ) noexcept {
    if (!valid_controller_command_kind(value.kind) || value.parameter_length > maximum_controller_command_parameters) {
      return lspg_error::invalid_payload;
    }
    std::array<std::uint8_t, 4 + maximum_controller_command_parameters> payload {};
    payload[0] = static_cast<std::uint8_t>(value.kind);
    wire::write_be<std::uint16_t>(std::span(payload).subspan(2, 2), value.parameter_length);
    std::copy_n(value.parameters.begin(), value.parameter_length, payload.begin() + 4);
    return serialize_lspg(
      lspg_subtype::command,
      value.input_generation,
      value.controller_id,
      value.instance_generation,
      value.sequence,
      std::span<const std::uint8_t>(payload).first(4 + value.parameter_length),
      output
    );
  }

  /**
   * @brief Decode one acknowledged command from a validated LSPG envelope.
   *
   * @param parsed Parsed envelope.
   * @param output Command destination.
   * @return Codec result.
   */
  [[nodiscard]] constexpr lspg_error decode_controller_command(
    const parsed_lspg &parsed,
    controller_command &output
  ) noexcept {
    if (!parsed || parsed.subtype != lspg_subtype::command || parsed.payload.size() < 4) {
      return lspg_error::invalid_payload;
    }
    const auto length = wire::read_be<std::uint16_t>(parsed.payload.subspan(2, 2));
    output = {
      .input_generation = parsed.input_generation,
      .controller_id = parsed.controller_id,
      .instance_generation = parsed.instance_generation,
      .sequence = parsed.sequence,
      .kind = static_cast<controller_command_kind>(parsed.payload[0]),
      .parameter_length = length,
    };
    std::copy_n(parsed.payload.begin() + 4, length, output.parameters.begin());
    return lspg_error::none;
  }

  /**
   * @brief Serialize one terminal controller command ACK into an LSPG packet.
   *
   * @param value Command ACK.
   * @param output Destination buffer.
   * @return Codec result.
   */
  [[nodiscard]] constexpr lspg_error serialize_controller_ack(
    const controller_command_ack &value,
    const std::span<std::uint8_t> output
  ) noexcept {
    if (!valid_controller_command_status(value.status)) {
      return lspg_error::invalid_payload;
    }
    const std::array<std::uint8_t, 4> payload {static_cast<std::uint8_t>(value.status), 0, 0, 0};
    return serialize_lspg(
      lspg_subtype::acknowledgement,
      value.input_generation,
      value.controller_id,
      value.instance_generation,
      value.sequence,
      payload,
      output
    );
  }

  /**
   * @brief Decode a terminal controller command ACK from a validated LSPG envelope.
   *
   * @param parsed Parsed envelope.
   * @param output ACK destination.
   * @return Codec result.
   */
  [[nodiscard]] constexpr lspg_error decode_controller_ack(
    const parsed_lspg &parsed,
    controller_command_ack &output
  ) noexcept {
    if (!parsed || parsed.subtype != lspg_subtype::acknowledgement || parsed.payload.size() != 4) {
      return lspg_error::invalid_payload;
    }
    output = {
      .input_generation = parsed.input_generation,
      .controller_id = parsed.controller_id,
      .instance_generation = parsed.instance_generation,
      .sequence = parsed.sequence,
      .status = static_cast<controller_command_status>(parsed.payload[0]),
    };
    return lspg_error::none;
  }

  /** @brief Controller output state-machine result. */
  enum class controller_output_result : std::uint8_t {
    accepted,  ///< State, command, generation, or ACK was accepted.
    duplicate,  ///< Byte-identical command/ACK or older latest state repeated.
    stale_generation,  ///< Input/controller generation does not match the live instance.
    stale_sequence,  ///< Replaceable state sequence is not newer.
    invalid,  ///< Identifier, command, deadline, or payload is invalid.
    full,  ///< Fixed command/controller table has no free slot.
    not_found,  ///< ACK or send update named no retained command.
    expired,  ///< Retained command reached its deadline and was retired.
  };

  /** @brief Fixed latest-state and acknowledged-command controller output manager. */
  class controller_output_manager {
  public:
    /** @brief Maximum active controller instances. */
    static constexpr std::size_t maximum_controllers = 16;

    /** @brief Maximum outstanding acknowledged controller commands. */
    static constexpr std::size_t maximum_commands = 64;

    /**
     * @brief Begin one input generation and clear all controller output state.
     *
     * @param input_generation Nonzero input authority generation.
     * @return `true` when the generation is valid.
     */
    constexpr bool reset(const std::uint32_t input_generation) noexcept {
      if (input_generation == 0) {
        return false;
      }
      for (auto &controller : controllers_) {
        controller.occupied = false;
      }
      for (auto &command : commands_) {
        command.occupied = false;
      }
      input_generation_ = input_generation;
      next_sequence_ = 1;
      return true;
    }

    /**
     * @brief Bind or rebind one controller ID to a nonzero instance generation.
     *
     * @param controller_id Controller ID in the range 1 through 16.
     * @param instance_generation Nonzero generation greater than a retired generation.
     * @return Binding result.
     */
    constexpr controller_output_result bind(
      const std::uint32_t controller_id,
      const std::uint32_t instance_generation
    ) noexcept {
      if (controller_id == 0 || controller_id > maximum_controllers || instance_generation == 0) {
        return controller_output_result::invalid;
      }
      controller_slot *free_slot = nullptr;
      for (auto &controller : controllers_) {
        if (controller.occupied && controller.controller_id == controller_id) {
          if (controller.active) {
            return controller.instance_generation == instance_generation ? controller_output_result::duplicate :
                                                                           controller_output_result::stale_generation;
          }
          if (instance_generation <= controller.instance_generation) {
            return controller_output_result::stale_generation;
          }
          controller.instance_generation = instance_generation;
          controller.active = true;
          controller.latest_dirty = false;
          controller.last_applied_command = 0;
          return controller_output_result::accepted;
        }
        if (!controller.occupied && free_slot == nullptr) {
          free_slot = &controller;
        }
      }
      if (free_slot == nullptr) {
        return controller_output_result::full;
      }
      *free_slot = {
        .controller_id = controller_id,
        .instance_generation = instance_generation,
        .active = true,
        .occupied = true,
      };
      return controller_output_result::accepted;
    }

    /**
     * @brief Retire one exact controller generation after lifecycle release edges.
     *
     * @param controller_id Controller ID.
     * @param instance_generation Exact active generation.
     * @return Retirement result.
     */
    constexpr controller_output_result remove(
      const std::uint32_t controller_id,
      const std::uint32_t instance_generation
    ) noexcept {
      auto *controller = find_controller(controller_id);
      if (controller == nullptr || !controller->active || controller->instance_generation != instance_generation) {
        return controller_output_result::stale_generation;
      }
      controller->active = false;
      controller->latest_dirty = false;
      return controller_output_result::accepted;
    }

    /**
     * @brief Store newest replaceable rumble/LED state for one live controller.
     *
     * @param value Latest state with nonzero direction-wide sequence.
     * @return Supersession result.
     */
    constexpr controller_output_result put_latest(const controller_latest_state &value) noexcept {
      auto *controller = find_controller(value.controller_id);
      if (value.input_generation != input_generation_ || controller == nullptr || !controller->active ||
          controller->instance_generation != value.instance_generation) {
        return controller_output_result::stale_generation;
      }
      if (value.sequence == 0) {
        return controller_output_result::invalid;
      }
      if (value.sequence <= controller->latest.sequence) {
        return controller_output_result::stale_sequence;
      }
      controller->latest = value;
      controller->latest_dirty = true;
      next_sequence_ = std::max(next_sequence_, value.sequence == std::numeric_limits<std::uint64_t>::max() ? value.sequence : value.sequence + 1U);
      return controller_output_result::accepted;
    }

    /**
     * @brief Take one newest replaceable state and clear its dirty bit.
     *
     * @param controller_id Controller ID.
     * @param output Latest-state destination.
     * @return `true` when new state was available.
     */
    constexpr bool take_latest(const std::uint32_t controller_id, controller_latest_state &output) noexcept {
      auto *controller = find_controller(controller_id);
      if (controller == nullptr || !controller->latest_dirty) {
        return false;
      }
      output = controller->latest;
      controller->latest_dirty = false;
      return true;
    }

    /**
     * @brief Assign and retain one acknowledged controller command for bounded retry.
     *
     * @param value Command with zero sequence and a future nonzero deadline.
     * @param now_us Current host monotonic time.
     * @param assigned_sequence Assigned direction-wide sequence destination.
     * @return Retention result.
     */
    constexpr controller_output_result enqueue_command(
      controller_command value,
      const std::uint64_t now_us,
      std::uint64_t &assigned_sequence
    ) noexcept {
      const auto *controller = find_controller(value.controller_id);
      if (value.input_generation != input_generation_ || controller == nullptr || !controller->active ||
          value.instance_generation != controller->instance_generation) {
        return controller_output_result::stale_generation;
      }
      if (value.sequence != 0 || !valid_controller_command_kind(value.kind) ||
          value.parameter_length > maximum_controller_command_parameters || value.deadline_us <= now_us || next_sequence_ == 0 ||
          next_sequence_ == std::numeric_limits<std::uint64_t>::max()) {
        return controller_output_result::invalid;
      }
      command_slot *destination = nullptr;
      for (auto &candidate : commands_) {
        if (!candidate.occupied) {
          destination = &candidate;
          break;
        }
      }
      if (destination == nullptr) {
        return controller_output_result::full;
      }
      assigned_sequence = next_sequence_++;
      value.sequence = assigned_sequence;
      *destination = {
        .value = value,
        .occupied = true,
      };
      return controller_output_result::accepted;
    }

    /**
     * @brief Copy due command retries into caller-owned output.
     *
     * @param now_us Current host monotonic time.
     * @param srtt_us Smoothed RTT used by the 250-us-to-5-ms clamp.
     * @param output Destination command records.
     * @return Number of due commands copied.
     */
    constexpr std::size_t due_commands(
      const std::uint64_t now_us,
      const std::uint64_t srtt_us,
      const std::span<controller_command> output
    ) noexcept {
      const auto retry = edge_sender::retry_interval_us(srtt_us, 5'000);
      std::size_t count = 0;
      for (auto &command : commands_) {
        if (!command.occupied) {
          continue;
        }
        if (now_us >= command.value.deadline_us) {
          command.occupied = false;
          continue;
        }
        if (count == output.size()) {
          break;
        }
        if (command.last_sent_us == 0 || now_us - command.last_sent_us >= retry) {
          output[count++] = command.value;
        }
      }
      return count;
    }

    /**
     * @brief Mark one retained command submitted without changing its wire sequence.
     *
     * @param sequence Retained command sequence.
     * @param sent_at_us Monotonic submission time.
     * @return Update result.
     */
    constexpr controller_output_result mark_command_sent(
      const std::uint64_t sequence,
      const std::uint64_t sent_at_us
    ) noexcept {
      for (auto &command : commands_) {
        if (command.occupied && command.value.sequence == sequence) {
          command.last_sent_us = sent_at_us;
          return controller_output_result::accepted;
        }
      }
      return controller_output_result::not_found;
    }

    /**
     * @brief Retire a retained command after a generation-scoped terminal ACK.
     *
     * A stale-generation status is terminal and prevents retry against a rebound device.
     *
     * @param ack Parsed terminal ACK.
     * @return ACK result.
     */
    constexpr controller_output_result acknowledge(const controller_command_ack &ack) noexcept {
      if (ack.input_generation != input_generation_ || ack.sequence == 0 || !valid_controller_command_status(ack.status)) {
        return controller_output_result::stale_generation;
      }
      for (auto &command : commands_) {
        if (!command.occupied || command.value.sequence != ack.sequence) {
          continue;
        }
        if (command.value.controller_id != ack.controller_id ||
            command.value.instance_generation != ack.instance_generation) {
          return controller_output_result::stale_generation;
        }
        command.occupied = false;
        return controller_output_result::accepted;
      }
      return controller_output_result::duplicate;
    }

    /**
     * @brief Apply one received acknowledged command exactly once and produce its ACK.
     *
     * @tparam Apply Callable returning a terminal `controller_command_status`.
     * @param command Received command.
     * @param now_us Current client monotonic time.
     * @param apply Platform output callback.
     * @param acknowledgement ACK destination.
     * @return Receive/application result.
     */
    template<class Apply>
    constexpr controller_output_result receive_command(
      const controller_command &command,
      const std::uint64_t now_us,
      Apply &&apply,
      controller_command_ack &acknowledgement
    ) noexcept(noexcept(std::invoke(apply, std::declval<const controller_command &>()))) {
      acknowledgement = {
        .input_generation = command.input_generation,
        .controller_id = command.controller_id,
        .instance_generation = command.instance_generation,
        .sequence = command.sequence,
      };
      auto *controller = find_controller(command.controller_id);
      if (command.input_generation != input_generation_ || controller == nullptr || !controller->active ||
          command.instance_generation != controller->instance_generation) {
        acknowledgement.status = controller_command_status::stale_generation;
        return controller_output_result::stale_generation;
      }
      if (command.sequence == 0 || !valid_controller_command_kind(command.kind) ||
          command.parameter_length > maximum_controller_command_parameters) {
        acknowledgement.status = controller_command_status::failed;
        return controller_output_result::invalid;
      }
      if (command.deadline_us != 0 && now_us >= command.deadline_us) {
        acknowledgement.status = controller_command_status::expired;
        return controller_output_result::expired;
      }
      if (command.sequence <= controller->last_applied_command) {
        acknowledgement.status = controller->last_command_status;
        return controller_output_result::duplicate;
      }
      acknowledgement.status = std::invoke(apply, std::as_const(command));
      if (!valid_controller_command_status(acknowledgement.status)) {
        acknowledgement.status = controller_command_status::failed;
      }
      controller->last_applied_command = command.sequence;
      controller->last_command_status = acknowledgement.status;
      return controller_output_result::accepted;
    }

    /** @brief Return the number of retained acknowledged commands. */
    [[nodiscard]] constexpr std::size_t pending_commands() const noexcept {
      std::size_t count = 0;
      for (const auto &command : commands_) {
        count += command.occupied ? 1U : 0U;
      }
      return count;
    }

  private:
    /** @brief One active or retired controller generation and latest output state. */
    struct controller_slot {
      controller_latest_state latest {};  ///< Newest replaceable rumble/LED state.
      std::uint32_t controller_id = 0;  ///< Controller identifier.
      std::uint32_t instance_generation = 0;  ///< Greatest bound generation.
      std::uint64_t last_applied_command = 0;  ///< Greatest exactly-once applied command sequence.
      controller_command_status last_command_status = controller_command_status::success;  ///< Duplicate ACK status.
      bool latest_dirty = false;  ///< Whether newest state awaits packet creation.
      bool active = false;  ///< Whether output may apply to this instance.
      bool occupied = false;  ///< Whether generation history exists.
    };

    /** @brief One retained acknowledged command and retry timestamp. */
    struct command_slot {
      controller_command value {};  ///< Immutable command wire state plus deadline.
      std::uint64_t last_sent_us = 0;  ///< Most recent transmission time.
      bool occupied = false;  ///< Whether terminal ACK/deadline is pending.
    };

    /** @brief Find a mutable controller slot by stable controller ID. */
    [[nodiscard]] constexpr controller_slot *find_controller(const std::uint32_t controller_id) noexcept {
      for (auto &controller : controllers_) {
        if (controller.occupied && controller.controller_id == controller_id) {
          return &controller;
        }
      }
      return nullptr;
    }

    /** @brief Find an immutable controller slot by stable controller ID. */
    [[nodiscard]] constexpr const controller_slot *find_controller(const std::uint32_t controller_id) const noexcept {
      for (const auto &controller : controllers_) {
        if (controller.occupied && controller.controller_id == controller_id) {
          return &controller;
        }
      }
      return nullptr;
    }

    std::array<controller_slot, maximum_controllers> controllers_ {};  ///< Fixed controller table.
    std::array<command_slot, maximum_commands> commands_ {};  ///< Fixed acknowledged-command table.
    std::uint32_t input_generation_ = 0;  ///< Active input authority generation.
    std::uint64_t next_sequence_ = 1;  ///< Next direction-wide nonzero output sequence.
  };
}  // namespace lumen::lsp::input_plane
