/**
 * @file src/protocol_lsp/input_plane/wire.h
 * @brief Frozen dependency-free LSP/1 input wire formats and checked codecs.
 */

#pragma once

#include "../core/wire.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>

namespace lumen::lsp::input_plane {
  /** @brief Fixed LSP/1 input common-header size in bytes. */
  inline constexpr std::size_t common_header_size = 40;

  /** @brief Fixed LSP/1 cumulative pointer payload size in bytes. */
  inline constexpr std::size_t pointer_payload_size = 56;

  /** @brief Fixed LSP/1 physical-edge record size in bytes. */
  inline constexpr std::size_t edge_record_size = 32;

  /** @brief Maximum number of contiguous edge records carried by one packet. */
  inline constexpr std::size_t maximum_edges_per_batch = 16;

  /** @brief Fixed metadata size preceding bytes in one baseline part. */
  inline constexpr std::size_t baseline_part_header_size = 48;

  /** @brief Maximum complete deterministic input-baseline size. */
  inline constexpr std::size_t maximum_baseline_bytes = 32U * 1024U;

  /** @brief Maximum number of parts in one deterministic input baseline. */
  inline constexpr std::size_t maximum_baseline_parts = 32;

  /** @brief Maximum LSP/1 core-state payload size. */
  inline constexpr std::size_t maximum_core_state_bytes = 128;

  /** @brief LSP/1 input packet kinds. */
  enum class packet_kind : std::uint8_t {
    pointer_motion = 1,  ///< Cumulative relative or latest absolute pointer state.
    core_state = 2,  ///< Replaceable keyboard and mouse reconciliation state.
    device_state = 3,  ///< Replaceable controller, touch, or pen state.
    sensor_state = 4,  ///< Replaceable controller gyro or accelerometer state.
    edge_batch = 5,  ///< Ordered non-replaceable physical transitions.
    baseline_part = 6,  ///< One retained part of the authority baseline.
  };

  /** @brief LSP/1 device classes used by object identifiers and supersession keys. */
  enum class device_type : std::uint8_t {
    keyboard = 1,  ///< Keyboard HID state and edges.
    pointer = 2,  ///< Relative or absolute pointer device.
    controller = 3,  ///< Game controller device.
    touch = 4,  ///< Direct-touch device.
    pen = 5,  ///< Pen or stylus device.
  };

  /** @brief Independently replaceable controller sensor streams. */
  enum class sensor_type : std::uint8_t {
    gyroscope = 1,  ///< Three-axis angular velocity.
    accelerometer = 2,  ///< Three-axis acceleration.
  };

  /** @brief Exact physical transition registry for 32-byte edge records. */
  enum class edge_kind : std::uint8_t {
    key_down = 1,  ///< Physical keyboard key became pressed.
    key_up = 2,  ///< Physical keyboard key became released.
    pointer_button_down = 3,  ///< Pointer button became pressed.
    pointer_button_up = 4,  ///< Pointer button became released.
    controller_arrival = 5,  ///< Controller instance became authoritative.
    controller_removal = 6,  ///< Controller instance was retired.
    controller_button_down = 7,  ///< Controller digital button became pressed.
    controller_button_up = 8,  ///< Controller digital button became released.
    touch_begin = 9,  ///< Touch contact began.
    touch_end = 10,  ///< Touch contact ended.
    touch_cancel = 11,  ///< Touch contact was cancelled.
    pen_begin = 12,  ///< Pen contact began.
    pen_end = 13,  ///< Pen contact ended.
    pen_cancel = 14,  ///< Pen contact was cancelled.
  };

  /** @brief Exactly one pointer mode bit is set in each pointer-motion payload. */
  enum class pointer_flag : std::uint16_t {
    relative = 1U << 0U,  ///< Cumulative relative motion is authoritative.
    absolute = 1U << 1U,  ///< Latest absolute position is authoritative.
  };

  /** @brief Checked LSP/1 input wire error. */
  enum class wire_error : std::uint8_t {
    none,  ///< Parsing or serialization succeeded.
    header_too_short,  ///< Fewer than 40 common-header bytes were supplied.
    output_too_small,  ///< Destination cannot hold the complete encoded value.
    invalid_generation,  ///< Input or device generation is zero or stale.
    unknown_kind,  ///< Packet or record kind is not assigned by LSP/1.
    reserved_flags,  ///< A reserved flag or byte is nonzero.
    invalid_payload_length,  ///< Declared and supplied payload lengths differ or overflow.
    invalid_state_sequence,  ///< State sequence violates baseline/replaceable rules.
    invalid_object_id,  ///< Object identifier is inconsistent with the packet kind or payload.
    invalid_pointer,  ///< Pointer payload mode, count, ordinal, or coordinates are invalid.
    invalid_device,  ///< Device record prefix or length is invalid.
    invalid_edge_batch,  ///< Edge count, identifiers, contiguity, or object ID is invalid.
    invalid_baseline_part,  ///< Baseline identifier, range, part metadata, or digest is invalid.
    packet_too_large,  ///< Complete packet cannot be represented by the 16-bit payload length.
  };

  /** @brief Common 40-byte header carried by every LSP/1 input RTP payload. */
  struct common_header {
    std::uint32_t input_generation = 0;  ///< Nonzero negotiated input-authority generation.
    packet_kind kind = packet_kind::pointer_motion;  ///< Exact input packet kind.
    std::uint8_t flags = 0;  ///< Reserved in LSP/1 and therefore zero.
    std::uint16_t payload_length = 0;  ///< Bytes following this header.
    std::uint64_t state_sequence = 0;  ///< Logical replaceable-state sequence.
    std::uint64_t sample_time_us = 0;  ///< Client monotonic time of the newest sample.
    std::uint64_t object_id = 0;  ///< Kind-specific object identifier.
    std::uint64_t edge_watermark = 0;  ///< Greatest edge observed before sampling state.

    /** @brief Compare every common-header field. */
    [[nodiscard]] bool operator==(const common_header &) const noexcept = default;
  };

  /** @brief Parsed input packet containing a zero-copy payload view. */
  struct parsed_packet {
    wire_error error = wire_error::none;  ///< Parse result.
    common_header header {};  ///< Decoded common header when successful.
    std::span<const std::uint8_t> payload {};  ///< Kind payload when successful.

    /** @brief Test whether parsing succeeded. */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == wire_error::none;
    }
  };

  /** @brief Exact cumulative/latest pointer state encoded in 56 bytes. */
  struct pointer_payload {
    std::uint32_t instance_generation = 0;  ///< Nonzero pointer instance generation.
    pointer_flag mode = pointer_flag::relative;  ///< Exactly one relative/absolute mode.
    std::uint16_t represented_reports = 0;  ///< Physical reports combined by this packet.
    std::uint64_t physical_ordinal = 0;  ///< Newest represented physical-sample ordinal.
    std::int64_t cumulative_x = 0;  ///< Cumulative relative horizontal motion.
    std::int64_t cumulative_y = 0;  ///< Cumulative relative vertical motion.
    std::int64_t cumulative_vertical_scroll = 0;  ///< Cumulative vertical scrolling.
    std::int64_t cumulative_horizontal_scroll = 0;  ///< Cumulative horizontal scrolling.
    std::uint32_t absolute_x = 0;  ///< Latest absolute horizontal coordinate in Q0.32.
    std::uint32_t absolute_y = 0;  ///< Latest absolute vertical coordinate in Q0.32.

    /** @brief Compare every pointer payload field. */
    [[nodiscard]] bool operator==(const pointer_payload &) const noexcept = default;
  };

  /** @brief Result of parsing an exact 56-byte pointer payload. */
  struct parsed_pointer {
    wire_error error = wire_error::none;  ///< Parse result.
    pointer_payload value {};  ///< Parsed pointer state when successful.

    /** @brief Test whether parsing succeeded. */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == wire_error::none;
    }
  };

  /** @brief Fresh fixed-layout 32-byte LSP/1 physical transition record. */
  struct edge_record {
    std::uint64_t edge_id = 0;  ///< Nonzero globally ordered input-generation edge identifier.
    std::uint64_t physical_time_us = 0;  ///< Original client monotonic physical sample time.
    edge_kind kind = edge_kind::key_down;  ///< Exact physical transition kind.
    device_type device = device_type::keyboard;  ///< Device class owning the transition.
    std::uint16_t control_id = 0;  ///< HID usage, button, contact, or pen control identifier.
    std::uint32_t device_id = 0;  ///< Nonzero device ID within its class.
    std::uint32_t instance_generation = 0;  ///< Nonzero device instance generation.
    std::int32_t value = 0;  ///< Kind-specific bounded scalar, slot, or lifecycle value.

    /** @brief Compare all wire-significant edge fields. */
    [[nodiscard]] bool operator==(const edge_record &) const noexcept = default;
  };

  /** @brief Result of parsing one exact physical edge. */
  struct parsed_edge {
    wire_error error = wire_error::none;  ///< Parse result.
    edge_record value {};  ///< Parsed record when successful.

    /** @brief Test whether parsing succeeded. */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == wire_error::none;
    }
  };

  /** @brief Zero-copy view over one validated contiguous edge batch. */
  struct parsed_edge_batch {
    wire_error error = wire_error::none;  ///< Parse result.
    std::span<const std::uint8_t> bytes {};  ///< Validated record bytes.
    std::uint8_t count = 0;  ///< Number of exact 32-byte records.
    std::uint64_t first_edge_id = 0;  ///< First contiguous edge identifier.
    std::uint64_t newest_edge_id = 0;  ///< Last contiguous edge identifier.

    /** @brief Test whether parsing succeeded. */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == wire_error::none;
    }

    /**
     * @brief Parse one record from this previously validated batch.
     *
     * @param index Zero-based record index smaller than `count`.
     * @return Parsed edge, or an edge-batch error for an invalid index.
     */
    [[nodiscard]] constexpr parsed_edge edge(const std::size_t index) const noexcept;
  };

  /** @brief Fixed device-state prefix preceding kind-specific state bytes. */
  struct device_record_prefix {
    device_type device = device_type::controller;  ///< Encoded device class.
    std::uint16_t represented_reports = 0;  ///< Physical reports represented by this sample.
    std::uint32_t device_id = 0;  ///< Nonzero device identifier.
    std::uint32_t instance_generation = 0;  ///< Nonzero instance generation.
    std::uint16_t record_length = 0;  ///< Exact bytes in the complete device payload.
    std::uint64_t physical_ordinal = 0;  ///< Newest represented physical-sample ordinal.
  };

  /** @brief Result of parsing the fixed 24-byte device record prefix. */
  struct parsed_device_prefix {
    wire_error error = wire_error::none;  ///< Parse result.
    device_record_prefix value {};  ///< Parsed prefix when successful.

    /** @brief Test whether parsing succeeded. */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == wire_error::none;
    }
  };

  /** @brief Frozen metadata carried before each baseline byte range. */
  struct baseline_part {
    std::uint8_t part_index = 0;  ///< Zero-based part index.
    std::uint8_t part_count = 0;  ///< Complete part count in the range 1 through 32.
    std::uint32_t total_length = 0;  ///< Complete baseline length up to 32 KiB.
    std::uint32_t part_offset = 0;  ///< Exact byte offset of this part.
    std::uint32_t part_length = 0;  ///< Exact bytes following the metadata.
    std::array<std::uint8_t, 32> digest {};  ///< SHA-256 of the complete deterministic baseline.
    std::span<const std::uint8_t> bytes {};  ///< Zero-copy part bytes.
  };

  /** @brief Result of parsing one baseline-part payload. */
  struct parsed_baseline_part {
    wire_error error = wire_error::none;  ///< Parse result.
    baseline_part value {};  ///< Parsed metadata and bytes when successful.

    /** @brief Test whether parsing succeeded. */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == wire_error::none;
    }
  };

  /**
   * @brief Test whether a numeric packet kind is assigned by LSP/1.
   *
   * @param kind Candidate kind.
   * @return `true` for packet kinds 1 through 6.
   */
  [[nodiscard]] constexpr bool valid_packet_kind(const packet_kind kind) noexcept {
    return kind >= packet_kind::pointer_motion && kind <= packet_kind::baseline_part;
  }

  /**
   * @brief Test whether a device type is assigned by LSP/1.
   *
   * @param type Candidate device class.
   * @return `true` for a frozen LSP/1 device class.
   */
  [[nodiscard]] constexpr bool valid_device_type(const device_type type) noexcept {
    return type >= device_type::keyboard && type <= device_type::pen;
  }

  /**
   * @brief Test whether a controller sensor type is assigned by LSP/1.
   *
   * @param type Candidate sensor stream.
   * @return `true` for gyro or accelerometer.
   */
  [[nodiscard]] constexpr bool valid_sensor_type(const sensor_type type) noexcept {
    return type == sensor_type::gyroscope || type == sensor_type::accelerometer;
  }

  /**
   * @brief Test whether a physical edge kind is assigned by LSP/1.
   *
   * @param kind Candidate edge kind.
   * @return `true` for the frozen edge registry.
   */
  [[nodiscard]] constexpr bool valid_edge_kind(const edge_kind kind) noexcept {
    return kind >= edge_kind::key_down && kind <= edge_kind::pen_cancel;
  }

  /**
   * @brief Test whether an edge kind belongs to its declared device class.
   *
   * @param kind Physical transition kind.
   * @param device Declared owning device class.
   * @return `true` when the frozen edge registry permits the pairing.
   */
  [[nodiscard]] constexpr bool edge_kind_matches_device(const edge_kind kind, const device_type device) noexcept {
    switch (kind) {
      case edge_kind::key_down:
      case edge_kind::key_up:
        return device == device_type::keyboard;
      case edge_kind::pointer_button_down:
      case edge_kind::pointer_button_up:
        return device == device_type::pointer;
      case edge_kind::controller_arrival:
      case edge_kind::controller_removal:
      case edge_kind::controller_button_down:
      case edge_kind::controller_button_up:
        return device == device_type::controller;
      case edge_kind::touch_begin:
      case edge_kind::touch_end:
      case edge_kind::touch_cancel:
        return device == device_type::touch;
      case edge_kind::pen_begin:
      case edge_kind::pen_end:
      case edge_kind::pen_cancel:
        return device == device_type::pen;
    }
    return false;
  }

  /**
   * @brief Encode a device class and identifier into a kind-specific object ID.
   *
   * Bits 63 through 56 carry the type, bits 55 through 32 are zero, and bits
   * 31 through 0 carry the nonzero device identifier.
   *
   * @param type Device class.
   * @param device_id Nonzero device identifier.
   * @return Encoded ID, or zero when either input is invalid.
   */
  [[nodiscard]] constexpr std::uint64_t make_device_object_id(
    const device_type type,
    const std::uint32_t device_id
  ) noexcept {
    if (!valid_device_type(type) || device_id == 0) {
      return 0;
    }
    return (static_cast<std::uint64_t>(type) << 56U) | device_id;
  }

  /**
   * @brief Encode one controller sensor supersession object.
   *
   * Bits 63 through 56 carry `controller`, bits 55 through 48 carry the sensor,
   * bits 47 through 32 are zero, and bits 31 through 0 carry the controller ID.
   *
   * @param controller_id Nonzero controller identifier.
   * @param sensor Sensor stream.
   * @return Encoded ID, or zero when either input is invalid.
   */
  [[nodiscard]] constexpr std::uint64_t make_sensor_object_id(
    const std::uint32_t controller_id,
    const sensor_type sensor
  ) noexcept {
    if (controller_id == 0 || !valid_sensor_type(sensor)) {
      return 0;
    }
    return (static_cast<std::uint64_t>(device_type::controller) << 56U) |
           (static_cast<std::uint64_t>(sensor) << 48U) | controller_id;
  }

  /**
   * @brief Decode a normal device object identifier.
   *
   * @param object_id Encoded object identifier.
   * @param type Decoded device class destination.
   * @param device_id Decoded nonzero device identifier destination.
   * @return `true` when reserved bits and fields are valid.
   */
  [[nodiscard]] constexpr bool decode_device_object_id(
    const std::uint64_t object_id,
    device_type &type,
    std::uint32_t &device_id
  ) noexcept {
    type = static_cast<device_type>(object_id >> 56U);
    device_id = static_cast<std::uint32_t>(object_id);
    return valid_device_type(type) && device_id != 0 && (object_id & 0x00FFFFFF00000000ULL) == 0;
  }

  /**
   * @brief Decode a controller sensor object identifier.
   *
   * @param object_id Encoded sensor object identifier.
   * @param controller_id Decoded controller identifier destination.
   * @param sensor Decoded sensor stream destination.
   * @return `true` when type, sensor, and reserved bits are valid.
   */
  [[nodiscard]] constexpr bool decode_sensor_object_id(
    const std::uint64_t object_id,
    std::uint32_t &controller_id,
    sensor_type &sensor
  ) noexcept {
    const auto type = static_cast<device_type>(object_id >> 56U);
    sensor = static_cast<sensor_type>((object_id >> 48U) & 0xffU);
    controller_id = static_cast<std::uint32_t>(object_id);
    return type == device_type::controller && valid_sensor_type(sensor) && controller_id != 0 &&
           (object_id & 0x0000FFFF00000000ULL) == 0;
  }

  /**
   * @brief Parse the fixed device-state prefix.
   *
   * @param payload Complete controller/device or sensor payload.
   * @param sensor_record Whether byte one names a sensor rather than being reserved.
   * @return Checked prefix result.
   */
  [[nodiscard]] constexpr parsed_device_prefix parse_device_prefix(
    const std::span<const std::uint8_t> payload,
    const bool sensor_record = false
  ) noexcept {
    if (payload.size() < 24U) {
      return {.error = wire_error::invalid_device};
    }
    const auto type = static_cast<device_type>(payload[0]);
    if (!valid_device_type(type) || (sensor_record && type != device_type::controller) ||
        (!sensor_record && payload[1] != 0) ||
        (sensor_record && !valid_sensor_type(static_cast<sensor_type>(payload[1]))) || payload[14] != 0 || payload[15] != 0) {
      return {.error = sensor_record ? wire_error::reserved_flags : wire_error::invalid_device};
    }
    device_record_prefix value {
      .device = type,
      .represented_reports = wire::read_be<std::uint16_t>(payload.subspan(2, 2)),
      .device_id = wire::read_be<std::uint32_t>(payload.subspan(4, 4)),
      .instance_generation = wire::read_be<std::uint32_t>(payload.subspan(8, 4)),
      .record_length = wire::read_be<std::uint16_t>(payload.subspan(12, 2)),
      .physical_ordinal = wire::read_be<std::uint64_t>(payload.subspan(16, 8)),
    };
    if (value.represented_reports == 0 || value.device_id == 0 || value.instance_generation == 0 ||
        value.physical_ordinal == 0 || value.record_length != payload.size()) {
      return {.error = wire_error::invalid_device};
    }
    return {.value = value};
  }

  /**
   * @brief Parse and validate the exact 56-byte cumulative pointer payload.
   *
   * @param payload Candidate payload bytes.
   * @return Parsed pointer or a precise validation error.
   */
  [[nodiscard]] constexpr parsed_pointer parse_pointer_payload(const std::span<const std::uint8_t> payload) noexcept {
    if (payload.size() != pointer_payload_size) {
      return {.error = wire_error::invalid_pointer};
    }
    const auto raw_mode = wire::read_be<std::uint16_t>(payload.subspan(4, 2));
    if (raw_mode != static_cast<std::uint16_t>(pointer_flag::relative) &&
        raw_mode != static_cast<std::uint16_t>(pointer_flag::absolute)) {
      return {.error = wire_error::invalid_pointer};
    }
    pointer_payload value {
      .instance_generation = wire::read_be<std::uint32_t>(payload.first<4>()),
      .mode = static_cast<pointer_flag>(raw_mode),
      .represented_reports = wire::read_be<std::uint16_t>(payload.subspan(6, 2)),
      .physical_ordinal = wire::read_be<std::uint64_t>(payload.subspan(8, 8)),
      .cumulative_x = std::bit_cast<std::int64_t>(wire::read_be<std::uint64_t>(payload.subspan(16, 8))),
      .cumulative_y = std::bit_cast<std::int64_t>(wire::read_be<std::uint64_t>(payload.subspan(24, 8))),
      .cumulative_vertical_scroll = std::bit_cast<std::int64_t>(wire::read_be<std::uint64_t>(payload.subspan(32, 8))),
      .cumulative_horizontal_scroll = std::bit_cast<std::int64_t>(wire::read_be<std::uint64_t>(payload.subspan(40, 8))),
      .absolute_x = wire::read_be<std::uint32_t>(payload.subspan(48, 4)),
      .absolute_y = wire::read_be<std::uint32_t>(payload.subspan(52, 4)),
    };
    if (value.instance_generation == 0 || value.represented_reports == 0 || value.physical_ordinal == 0 ||
        (value.mode == pointer_flag::relative && (value.absolute_x != 0 || value.absolute_y != 0))) {
      return {.error = wire_error::invalid_pointer};
    }
    return {.value = value};
  }

  /**
   * @brief Serialize one checked cumulative pointer payload.
   *
   * @param value Pointer state.
   * @param output Exact 56-byte destination or a larger span.
   * @return Serialization result.
   */
  [[nodiscard]] constexpr wire_error serialize_pointer_payload(
    const pointer_payload &value,
    const std::span<std::uint8_t> output
  ) noexcept {
    if (output.size() < pointer_payload_size) {
      return wire_error::output_too_small;
    }
    if (value.instance_generation == 0 || value.represented_reports == 0 || value.physical_ordinal == 0 ||
        (value.mode != pointer_flag::relative && value.mode != pointer_flag::absolute) ||
        (value.mode == pointer_flag::relative && (value.absolute_x != 0 || value.absolute_y != 0))) {
      return wire_error::invalid_pointer;
    }
    wire::write_be<std::uint32_t>(output.first<4>(), value.instance_generation);
    wire::write_be<std::uint16_t>(output.subspan(4, 2), static_cast<std::uint16_t>(value.mode));
    wire::write_be<std::uint16_t>(output.subspan(6, 2), value.represented_reports);
    wire::write_be<std::uint64_t>(output.subspan(8, 8), value.physical_ordinal);
    wire::write_be<std::uint64_t>(output.subspan(16, 8), std::bit_cast<std::uint64_t>(value.cumulative_x));
    wire::write_be<std::uint64_t>(output.subspan(24, 8), std::bit_cast<std::uint64_t>(value.cumulative_y));
    wire::write_be<std::uint64_t>(output.subspan(32, 8), std::bit_cast<std::uint64_t>(value.cumulative_vertical_scroll));
    wire::write_be<std::uint64_t>(output.subspan(40, 8), std::bit_cast<std::uint64_t>(value.cumulative_horizontal_scroll));
    wire::write_be<std::uint32_t>(output.subspan(48, 4), value.absolute_x);
    wire::write_be<std::uint32_t>(output.subspan(52, 4), value.absolute_y);
    return wire_error::none;
  }

  /**
   * @brief Parse one exact 32-byte physical edge record.
   *
   * @param bytes Candidate record bytes.
   * @return Parsed edge or validation error.
   */
  [[nodiscard]] constexpr parsed_edge parse_edge_record(const std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.size() != edge_record_size) {
      return {.error = wire_error::invalid_edge_batch};
    }
    edge_record value {
      .edge_id = wire::read_be<std::uint64_t>(bytes.first<8>()),
      .physical_time_us = wire::read_be<std::uint64_t>(bytes.subspan(8, 8)),
      .kind = static_cast<edge_kind>(bytes[16]),
      .device = static_cast<device_type>(bytes[17]),
      .control_id = wire::read_be<std::uint16_t>(bytes.subspan(18, 2)),
      .device_id = wire::read_be<std::uint32_t>(bytes.subspan(20, 4)),
      .instance_generation = wire::read_be<std::uint32_t>(bytes.subspan(24, 4)),
      .value = std::bit_cast<std::int32_t>(wire::read_be<std::uint32_t>(bytes.subspan(28, 4))),
    };
    if (value.edge_id == 0 || value.physical_time_us == 0 || !valid_edge_kind(value.kind) ||
        !valid_device_type(value.device) || !edge_kind_matches_device(value.kind, value.device) || value.device_id == 0 ||
        value.instance_generation == 0) {
      return {.error = wire_error::invalid_edge_batch};
    }
    return {.value = value};
  }

  /**
   * @brief Serialize one exact physical edge record.
   *
   * @param value Edge value.
   * @param output Exact 32-byte destination or larger span.
   * @return Serialization result.
   */
  [[nodiscard]] constexpr wire_error serialize_edge_record(
    const edge_record &value,
    const std::span<std::uint8_t> output
  ) noexcept {
    if (output.size() < edge_record_size) {
      return wire_error::output_too_small;
    }
    if (value.edge_id == 0 || value.physical_time_us == 0 || !valid_edge_kind(value.kind) ||
        !valid_device_type(value.device) || !edge_kind_matches_device(value.kind, value.device) || value.device_id == 0 ||
        value.instance_generation == 0) {
      return wire_error::invalid_edge_batch;
    }
    wire::write_be<std::uint64_t>(output.first<8>(), value.edge_id);
    wire::write_be<std::uint64_t>(output.subspan(8, 8), value.physical_time_us);
    output[16] = static_cast<std::uint8_t>(value.kind);
    output[17] = static_cast<std::uint8_t>(value.device);
    wire::write_be<std::uint16_t>(output.subspan(18, 2), value.control_id);
    wire::write_be<std::uint32_t>(output.subspan(20, 4), value.device_id);
    wire::write_be<std::uint32_t>(output.subspan(24, 4), value.instance_generation);
    wire::write_be<std::uint32_t>(output.subspan(28, 4), std::bit_cast<std::uint32_t>(value.value));
    return wire_error::none;
  }

  constexpr parsed_edge parsed_edge_batch::edge(const std::size_t index) const noexcept {
    if (error != wire_error::none || index >= count) {
      return {.error = wire_error::invalid_edge_batch};
    }
    return parse_edge_record(bytes.subspan(index * edge_record_size, edge_record_size));
  }

  /**
   * @brief Validate one 1-through-16 record contiguous edge batch.
   *
   * @param bytes Complete edge payload.
   * @param newest_object_id Common-header object ID that must name the newest edge.
   * @return Validated zero-copy batch.
   */
  [[nodiscard]] constexpr parsed_edge_batch parse_edge_batch(
    const std::span<const std::uint8_t> bytes,
    const std::uint64_t newest_object_id
  ) noexcept {
    if (bytes.empty() || bytes.size() % edge_record_size != 0 || bytes.size() > maximum_edges_per_batch * edge_record_size) {
      return {.error = wire_error::invalid_edge_batch};
    }
    const auto count = static_cast<std::uint8_t>(bytes.size() / edge_record_size);
    const auto first = parse_edge_record(bytes.first<edge_record_size>());
    if (!first) {
      return {.error = wire_error::invalid_edge_batch};
    }
    auto previous_id = first.value.edge_id;
    for (std::size_t index = 1; index < count; ++index) {
      const auto current = parse_edge_record(bytes.subspan(index * edge_record_size, edge_record_size));
      if (!current || previous_id == std::numeric_limits<std::uint64_t>::max() || current.value.edge_id != previous_id + 1U) {
        return {.error = wire_error::invalid_edge_batch};
      }
      previous_id = current.value.edge_id;
    }
    if (newest_object_id != previous_id) {
      return {.error = wire_error::invalid_object_id};
    }
    return {
      .bytes = bytes,
      .count = count,
      .first_edge_id = first.value.edge_id,
      .newest_edge_id = previous_id,
    };
  }

  /**
   * @brief Parse frozen baseline-part metadata and its exact byte range.
   *
   * @param payload Complete baseline part payload.
   * @param baseline_id Common-header object identifier.
   * @return Parsed baseline part or validation error.
   */
  [[nodiscard]] constexpr parsed_baseline_part parse_baseline_part(
    const std::span<const std::uint8_t> payload,
    const std::uint64_t baseline_id
  ) noexcept {
    if (baseline_id == 0 || payload.size() < baseline_part_header_size || payload[2] != 0 || payload[3] != 0) {
      return {.error = wire_error::invalid_baseline_part};
    }
    baseline_part value {
      .part_index = payload[0],
      .part_count = payload[1],
      .total_length = wire::read_be<std::uint32_t>(payload.subspan(4, 4)),
      .part_offset = wire::read_be<std::uint32_t>(payload.subspan(8, 4)),
      .part_length = wire::read_be<std::uint32_t>(payload.subspan(12, 4)),
      .bytes = payload.subspan(baseline_part_header_size),
    };
    std::copy_n(payload.begin() + 16, value.digest.size(), value.digest.begin());
    if (value.part_count == 0 || value.part_count > maximum_baseline_parts || value.part_index >= value.part_count ||
        value.total_length == 0 || value.total_length > maximum_baseline_bytes || value.part_length == 0 ||
        value.part_length != value.bytes.size() || value.part_offset > value.total_length ||
        value.part_length > value.total_length - value.part_offset) {
      return {.error = wire_error::invalid_baseline_part};
    }
    return {.value = value};
  }

  /**
   * @brief Serialize frozen baseline-part metadata and bytes.
   *
   * @param value Baseline part metadata and byte view.
   * @param output Destination buffer.
   * @return Serialization result.
   */
  [[nodiscard]] constexpr wire_error serialize_baseline_part(
    const baseline_part &value,
    const std::span<std::uint8_t> output
  ) noexcept {
    if (value.part_count == 0 || value.part_count > maximum_baseline_parts || value.part_index >= value.part_count ||
        value.total_length == 0 || value.total_length > maximum_baseline_bytes || value.bytes.empty() ||
        value.part_length != value.bytes.size() || value.part_offset > value.total_length ||
        value.part_length > value.total_length - value.part_offset) {
      return wire_error::invalid_baseline_part;
    }
    if (output.size() < baseline_part_header_size + value.bytes.size()) {
      return wire_error::output_too_small;
    }
    output[0] = value.part_index;
    output[1] = value.part_count;
    output[2] = 0;
    output[3] = 0;
    wire::write_be<std::uint32_t>(output.subspan(4, 4), value.total_length);
    wire::write_be<std::uint32_t>(output.subspan(8, 4), value.part_offset);
    wire::write_be<std::uint32_t>(output.subspan(12, 4), value.part_length);
    std::copy(value.digest.begin(), value.digest.end(), output.begin() + 16);
    std::copy(value.bytes.begin(), value.bytes.end(), output.begin() + baseline_part_header_size);
    return wire_error::none;
  }

  /**
   * @brief Validate one common header against its exact kind payload.
   *
   * @param header Decoded common header.
   * @param payload Complete kind payload.
   * @param expected_generation Expected nonzero authority generation, or zero to accept any live generation.
   * @return Validation result.
   */
  [[nodiscard]] constexpr wire_error validate_packet(
    const common_header &header,
    const std::span<const std::uint8_t> payload,
    const std::uint32_t expected_generation = 0
  ) noexcept {
    if (header.input_generation == 0 || (expected_generation != 0 && header.input_generation != expected_generation)) {
      return wire_error::invalid_generation;
    }
    if (!valid_packet_kind(header.kind)) {
      return wire_error::unknown_kind;
    }
    if (header.flags != 0) {
      return wire_error::reserved_flags;
    }
    if (header.payload_length != payload.size()) {
      return wire_error::invalid_payload_length;
    }
    if (header.state_sequence == 0 ||
        (header.kind == packet_kind::baseline_part && header.state_sequence != 1) ||
        (header.kind != packet_kind::baseline_part && header.kind != packet_kind::edge_batch && header.state_sequence < 2)) {
      return wire_error::invalid_state_sequence;
    }

    switch (header.kind) {
      case packet_kind::pointer_motion:
        if (header.object_id == 0 || header.object_id > 4) {
          return wire_error::invalid_object_id;
        }
        return parse_pointer_payload(payload).error;
      case packet_kind::core_state:
        if (header.object_id != 0) {
          return wire_error::invalid_object_id;
        }
        return payload.empty() || payload.size() > maximum_core_state_bytes ? wire_error::invalid_payload_length : wire_error::none;
      case packet_kind::device_state:
        {
          device_type type {};
          std::uint32_t device_id = 0;
          const auto prefix = parse_device_prefix(payload);
          if (!prefix) {
            return prefix.error;
          }
          if (!decode_device_object_id(header.object_id, type, device_id) || type != prefix.value.device || device_id != prefix.value.device_id) {
            return wire_error::invalid_object_id;
          }
          return wire_error::none;
        }
      case packet_kind::sensor_state:
        {
          std::uint32_t controller_id = 0;
          sensor_type sensor {};
          const auto prefix = parse_device_prefix(payload, true);
          if (!prefix) {
            return prefix.error;
          }
          if (!decode_sensor_object_id(header.object_id, controller_id, sensor) ||
              controller_id != prefix.value.device_id || sensor != static_cast<sensor_type>(payload[1])) {
            return wire_error::invalid_object_id;
          }
          return wire_error::none;
        }
      case packet_kind::edge_batch:
        return parse_edge_batch(payload, header.object_id).error;
      case packet_kind::baseline_part:
        return parse_baseline_part(payload, header.object_id).error;
    }
    return wire_error::unknown_kind;
  }

  /**
   * @brief Parse one complete 40-byte-header LSP/1 input payload.
   *
   * @param packet Complete decrypted RTP payload bytes.
   * @param expected_generation Expected input generation, or zero during generic vector parsing.
   * @return Parsed packet and zero-copy kind payload.
   */
  [[nodiscard]] constexpr parsed_packet parse_packet(
    const std::span<const std::uint8_t> packet,
    const std::uint32_t expected_generation = 0
  ) noexcept {
    if (packet.size() < common_header_size) {
      return {.error = wire_error::header_too_short};
    }
    common_header header {
      .input_generation = wire::read_be<std::uint32_t>(packet.first<4>()),
      .kind = static_cast<packet_kind>(packet[4]),
      .flags = packet[5],
      .payload_length = wire::read_be<std::uint16_t>(packet.subspan(6, 2)),
      .state_sequence = wire::read_be<std::uint64_t>(packet.subspan(8, 8)),
      .sample_time_us = wire::read_be<std::uint64_t>(packet.subspan(16, 8)),
      .object_id = wire::read_be<std::uint64_t>(packet.subspan(24, 8)),
      .edge_watermark = wire::read_be<std::uint64_t>(packet.subspan(32, 8)),
    };
    const auto payload = packet.subspan(common_header_size);
    const auto error = validate_packet(header, payload, expected_generation);
    return error == wire_error::none ? parsed_packet {.header = header, .payload = payload} : parsed_packet {.error = error};
  }

  /**
   * @brief Serialize one complete checked LSP/1 input payload.
   *
   * @param header Common header; payload length is derived and must either be zero or exact.
   * @param payload Kind payload.
   * @param output Destination buffer.
   * @return Serialization result.
   */
  [[nodiscard]] constexpr wire_error serialize_packet(
    common_header header,
    const std::span<const std::uint8_t> payload,
    const std::span<std::uint8_t> output
  ) noexcept {
    if (payload.size() > std::numeric_limits<std::uint16_t>::max()) {
      return wire_error::packet_too_large;
    }
    if (header.payload_length != 0 && header.payload_length != payload.size()) {
      return wire_error::invalid_payload_length;
    }
    header.payload_length = static_cast<std::uint16_t>(payload.size());
    const auto error = validate_packet(header, payload);
    if (error != wire_error::none) {
      return error;
    }
    if (output.size() < common_header_size + payload.size()) {
      return wire_error::output_too_small;
    }
    wire::write_be<std::uint32_t>(output.first<4>(), header.input_generation);
    output[4] = static_cast<std::uint8_t>(header.kind);
    output[5] = header.flags;
    wire::write_be<std::uint16_t>(output.subspan(6, 2), header.payload_length);
    wire::write_be<std::uint64_t>(output.subspan(8, 8), header.state_sequence);
    wire::write_be<std::uint64_t>(output.subspan(16, 8), header.sample_time_us);
    wire::write_be<std::uint64_t>(output.subspan(24, 8), header.object_id);
    wire::write_be<std::uint64_t>(output.subspan(32, 8), header.edge_watermark);
    std::copy(payload.begin(), payload.end(), output.begin() + common_header_size);
    return wire_error::none;
  }
}  // namespace lumen::lsp::input_plane
