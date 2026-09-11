/**
 * @file src/lsp/input_plane/wire.h
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

  /** @brief Exact frozen keyboard, buttons, and text-barrier core-state size. */
  inline constexpr std::size_t core_state_payload_size = 64;

  /** @brief Exact frozen controller device-state payload size. */
  inline constexpr std::size_t controller_state_payload_size = 88;

  /** @brief Exact frozen controller sensor-state payload size. */
  inline constexpr std::size_t controller_sensor_payload_size = 36;

  /** @brief Fixed bytes preceding touch contacts in one touch device-state payload. */
  inline constexpr std::size_t touch_state_header_size = 28;

  /** @brief Exact frozen touch-contact record size. */
  inline constexpr std::size_t touch_contact_size = 32;

  /** @brief Maximum touch contacts carried by one device-state payload. */
  inline constexpr std::size_t maximum_touch_contacts = 16;

  /** @brief Exact frozen pen device-state payload size. */
  inline constexpr std::size_t pen_state_payload_size = 56;

  /** @brief Exact deterministic complete-baseline header size. */
  inline constexpr std::size_t input_baseline_header_size = 32;

  /** @brief Exact deterministic complete-baseline record header size. */
  inline constexpr std::size_t input_baseline_record_header_size = 32;

  /** @brief Maximum independently sequenced records in one complete baseline. */
  inline constexpr std::size_t maximum_input_baseline_records = 128;

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

  /** @brief Device lifecycle retained by deterministic complete baselines. */
  enum class device_presence : std::uint8_t {
    active = 1,  ///< Device instance is authoritative.
    removed = 2,  ///< Device generation is a retained removal tombstone.
  };

  /** @brief Frozen controller battery state. */
  enum class controller_battery_state : std::uint8_t {
    unknown = 0,  ///< Platform exposes no battery state.
    discharging = 1,  ///< Battery is discharging.
    charging = 2,  ///< Battery is charging.
    full = 3,  ///< Battery reports full charge.
  };

  /** @brief Frozen controller digital-button bit positions in `controller_state_payload::buttons`. */
  enum class controller_button_bit : std::uint8_t {
    south = 0,  ///< South face button.
    east = 1,  ///< East face button.
    west = 2,  ///< West face button.
    north = 3,  ///< North face button.
    left_shoulder = 4,  ///< Left shoulder button.
    right_shoulder = 5,  ///< Right shoulder button.
    left_stick = 6,  ///< Left stick click.
    right_stick = 7,  ///< Right stick click.
    menu = 8,  ///< Menu/start button.
    view = 9,  ///< View/select button.
    guide = 10,  ///< Guide/home button.
    dpad_up = 11,  ///< Digital directional-pad up.
    dpad_down = 12,  ///< Digital directional-pad down.
    dpad_left = 13,  ///< Digital directional-pad left.
    dpad_right = 14,  ///< Digital directional-pad right.
    paddle_one = 15,  ///< First rear paddle.
    paddle_two = 16,  ///< Second rear paddle.
    paddle_three = 17,  ///< Third rear paddle.
    paddle_four = 18,  ///< Fourth rear paddle.
    touchpad_click = 19,  ///< Touchpad click.
  };

  /** @brief Frozen controller signed-axis array indices; values are normalized Q1.15. */
  enum class controller_axis_index : std::uint8_t {
    left_x = 0,  ///< Left-stick horizontal Q1.15.
    left_y = 1,  ///< Left-stick vertical Q1.15, positive up.
    right_x = 2,  ///< Right-stick horizontal Q1.15.
    right_y = 3,  ///< Right-stick vertical Q1.15, positive up.
    dpad_x = 4,  ///< Analog directional-pad horizontal Q1.15.
    dpad_y = 5,  ///< Analog directional-pad vertical Q1.15, positive up.
    auxiliary_x = 6,  ///< Platform auxiliary horizontal Q1.15.
    auxiliary_y = 7,  ///< Platform auxiliary vertical Q1.15, positive up.
  };

  /** @brief Frozen controller unsigned-trigger array indices; values are normalized Q0.16. */
  enum class controller_trigger_index : std::uint8_t {
    left = 0,  ///< Left trigger Q0.16.
    right = 1,  ///< Right trigger Q0.16.
    auxiliary_left = 2,  ///< Platform auxiliary left trigger Q0.16.
    auxiliary_right = 3,  ///< Platform auxiliary right trigger Q0.16.
  };

  /** @brief Frozen controller sensor fixed-point units. */
  enum class controller_sensor_unit : std::uint8_t {
    radians_per_second_q16_16 = 1,  ///< Gyroscope X/Y/Z signed radians per second in Q16.16.
    meters_per_second_squared_q16_16 = 2,  ///< Accelerometer X/Y/Z signed metres per second squared in Q16.16.
  };

  /**
   * @brief Return the frozen SI fixed-point unit for one controller sensor stream.
   *
   * @param sensor Gyroscope or accelerometer.
   * @return Signed Q16.16 unit used by all three right-handed axes.
   */
  [[nodiscard]] constexpr controller_sensor_unit sensor_unit(const sensor_type sensor) noexcept {
    return sensor == sensor_type::gyroscope ? controller_sensor_unit::radians_per_second_q16_16 :
                                              controller_sensor_unit::meters_per_second_squared_q16_16;
  }

  /**
   * @brief Return one controller button mask.
   *
   * @param button Frozen named button bit.
   * @return Exact 64-bit bitmap mask.
   */
  [[nodiscard]] constexpr std::uint64_t controller_button_mask(const controller_button_bit button) noexcept {
    return std::uint64_t {1} << static_cast<std::uint8_t>(button);
  }

  /** @brief Mask of every assigned controller digital-button bit. */
  inline constexpr std::uint64_t assigned_controller_button_mask =
    (std::uint64_t {1} << (static_cast<std::uint8_t>(controller_button_bit::touchpad_click) + 1U)) - 1U;

  /** @brief Deterministically ordered record kinds in a complete input baseline. */
  enum class baseline_record_kind : std::uint8_t {
    core = 1,  ///< Keyboard bitmap, pointer buttons, neutral flag, and text barrier.
    device_lifecycle = 2,  ///< Device arrival or removal generation.
    pointer = 3,  ///< Cumulative/latest relative or absolute pointer state.
    controller = 4,  ///< Controller buttons, axes, triggers, battery, and touchpad state.
    controller_sensor = 5,  ///< Gyroscope or accelerometer vector.
    touch = 6,  ///< Bounded active direct-touch contacts.
    pen = 7,  ///< Latest absolute pen state.
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
    invalid_core_state,  ///< Core-state schema, flags, bitmap, buttons, or ordinal are invalid.
    invalid_controller_state,  ///< Controller buttons, axes, triggers, battery, or touch state is invalid.
    invalid_sensor_state,  ///< Controller sensor vector or exact length is invalid.
    invalid_touch_state,  ///< Touch contact count, identity, coordinates, or ordinal is invalid.
    invalid_pen_state,  ///< Pen flags, buttons, coordinates, pressure, or exact length is invalid.
    invalid_device,  ///< Device record prefix or length is invalid.
    invalid_edge_batch,  ///< Edge count, identifiers, contiguity, or object ID is invalid.
    invalid_baseline_part,  ///< Baseline identifier, range, part metadata, or digest is invalid.
    invalid_baseline_body,  ///< Complete baseline header, record ordering, or body is invalid.
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

  /** @brief Frozen 64-byte keyboard, pointer-button, neutral, and text-barrier core state. */
  struct core_state_payload {
    bool neutral = false;  ///< Whether every held key and pointer button is released.
    std::uint32_t keyboard_instance_generation = 0;  ///< Nonzero keyboard reconciliation generation.
    std::uint64_t physical_ordinal = 0;  ///< Newest keyboard or pointer-button physical sample.
    std::uint64_t text_barrier_edge_id = 0;  ///< Greatest edge that must precede queued text/IME state.
    std::uint32_t pointer_buttons = 0;  ///< Current pointer-button bitmap.
    std::array<std::uint8_t, 32> key_bitmap {};  ///< HID usage IDs 0 through 255.

    /** @brief Compare every frozen core-state field. */
    [[nodiscard]] bool operator==(const core_state_payload &) const noexcept = default;
  };

  /** @brief Parsed frozen core state. */
  struct parsed_core_state {
    wire_error error = wire_error::none;  ///< Parse result.
    core_state_payload value {};  ///< Parsed core state on success.

    /** @brief Test whether parsing succeeded. */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == wire_error::none;
    }
  };

  /** @brief Fixed device-state prefix preceding kind-specific state bytes. */
  struct device_record_prefix {
    device_type device = device_type::controller;  ///< Encoded device class.
    std::uint16_t represented_reports = 0;  ///< Physical reports represented by this sample.
    std::uint32_t device_id = 0;  ///< Nonzero device identifier.
    std::uint32_t instance_generation = 0;  ///< Nonzero instance generation.
    std::uint16_t record_length = 0;  ///< Exact bytes in the complete device payload.
    std::uint64_t physical_ordinal = 0;  ///< Newest represented physical-sample ordinal.

    /** @brief Compare every device-prefix field. */
    [[nodiscard]] bool operator==(const device_record_prefix &) const noexcept = default;
  };

  /** @brief One newest controller touchpad contact. */
  struct controller_touchpad_contact {
    std::uint8_t contact_id = 0;  ///< Nonzero platform contact identifier when active.
    bool active = false;  ///< Whether this contact is held.
    std::uint32_t x = 0;  ///< Absolute Q0.32 horizontal coordinate.
    std::uint32_t y = 0;  ///< Absolute Q0.32 vertical coordinate.
    std::uint16_t pressure = 0;  ///< Unsigned normalized pressure.

    /** @brief Compare every controller touchpad field. */
    [[nodiscard]] bool operator==(const controller_touchpad_contact &) const noexcept = default;
  };

  /** @brief Frozen controller buttons, analog state, battery, and touchpad state. */
  struct controller_state_payload {
    device_record_prefix prefix {};  ///< Exact controller device-state prefix.
    controller_battery_state battery_state = controller_battery_state::unknown;  ///< Battery status.
    std::uint8_t battery_percent = 255;  ///< Charge percent 0 through 100, or 255 when unknown.
    std::uint64_t buttons = 0;  ///< Current digital-button bitmap.
    std::array<std::int16_t, 8> axes {};  ///< Q1.15 axes indexed by `controller_axis_index`.
    std::array<std::uint16_t, 4> triggers {};  ///< Q0.16 triggers indexed by `controller_trigger_index`.
    std::array<controller_touchpad_contact, 2> touchpad {};  ///< Up to two latest controller contacts.

    /** @brief Compare every owned controller-state field. */
    [[nodiscard]] bool operator==(const controller_state_payload &) const noexcept = default;
  };

  /** @brief Parsed frozen controller state. */
  struct parsed_controller_state {
    wire_error error = wire_error::none;  ///< Parse result.
    controller_state_payload value {};  ///< Parsed controller state on success.

    /** @brief Test whether parsing succeeded. */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == wire_error::none;
    }
  };

  /** @brief Frozen one-stream controller sensor vector. */
  struct controller_sensor_payload {
    device_record_prefix prefix {};  ///< Exact sensor-state prefix.
    sensor_type sensor = sensor_type::gyroscope;  ///< Gyroscope or accelerometer stream.
    std::array<std::int32_t, 3> vector {};  ///< Right-handed X/Y/Z in the sensor-specific signed Q16.16 SI unit.

    /** @brief Compare every sensor-state field. */
    [[nodiscard]] bool operator==(const controller_sensor_payload &) const noexcept = default;
  };

  /** @brief Parsed frozen controller sensor state. */
  struct parsed_controller_sensor {
    wire_error error = wire_error::none;  ///< Parse result.
    controller_sensor_payload value {};  ///< Parsed sensor state on success.

    /** @brief Test whether parsing succeeded. */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == wire_error::none;
    }
  };

  /** @brief Frozen direct-touch contact state. */
  struct touch_contact_payload {
    std::uint16_t contact_id = 0;  ///< Nonzero device-local contact identifier.
    bool active = false;  ///< Whether the contact is held.
    std::uint32_t x = 0;  ///< Absolute normalized Q0.32 horizontal coordinate.
    std::uint32_t y = 0;  ///< Absolute normalized Q0.32 vertical coordinate.
    std::uint16_t pressure = 0;  ///< Normalized Q0.16 pressure.
    std::uint16_t major = 0;  ///< Normalized Q0.16 surface-width major axis.
    std::uint16_t minor = 0;  ///< Normalized Q0.16 surface-height minor axis.
    std::int16_t orientation = 0;  ///< Clockwise radians from +X in signed Q3.12.
    std::uint64_t physical_ordinal = 0;  ///< Latest physical sample for this contact.

    /** @brief Compare every touch-contact field. */
    [[nodiscard]] bool operator==(const touch_contact_payload &) const noexcept = default;
  };

  /** @brief Parsed frozen touch-contact record. */
  struct parsed_touch_contact {
    wire_error error = wire_error::none;  ///< Parse result.
    touch_contact_payload value {};  ///< Parsed contact state on success.

    /** @brief Test whether parsing succeeded. */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == wire_error::none;
    }
  };

  /** @brief Borrowed bounded direct-touch device state. */
  struct touch_state_view {
    device_record_prefix prefix {};  ///< Exact touch device-state prefix.
    std::span<const touch_contact_payload> contacts {};  ///< Active contacts in ascending identifier order.
  };

  /** @brief Parsed zero-copy touch device state. */
  struct parsed_touch_state {
    wire_error error = wire_error::none;  ///< Parse result.
    device_record_prefix prefix {};  ///< Parsed touch prefix on success.
    std::span<const std::uint8_t> contact_bytes {};  ///< Validated exact 32-byte contact records.
    std::uint8_t contact_count = 0;  ///< Number of records in `contact_bytes`.

    /** @brief Test whether parsing succeeded. */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == wire_error::none;
    }

    /**
     * @brief Return one validated contact by index.
     *
     * @param index Zero-based contact index.
     * @return Parsed contact or an invalid-touch result.
     */
    [[nodiscard]] constexpr parsed_touch_contact contact(std::size_t index) const noexcept;
  };

  /** @brief Frozen latest absolute pen state. */
  struct pen_state_payload {
    device_record_prefix prefix {};  ///< Exact pen device-state prefix.
    bool in_range = false;  ///< Pen is in digitizer range.
    bool contact = false;  ///< Pen tip is touching.
    bool eraser = false;  ///< Eraser tool is selected.
    std::uint16_t buttons = 0;  ///< Current barrel/button bitmap.
    std::uint32_t x = 0;  ///< Absolute Q0.32 horizontal coordinate.
    std::uint32_t y = 0;  ///< Absolute Q0.32 vertical coordinate.
    std::uint16_t pressure = 0;  ///< Normalized tip pressure in Q0.16.
    std::int16_t tangential_pressure = 0;  ///< Signed normalized barrel pressure in Q1.15.
    std::int16_t tilt_x = 0;  ///< X tilt radians in signed Q3.12.
    std::int16_t tilt_y = 0;  ///< Y tilt radians in signed Q3.12.
    std::int16_t rotation = 0;  ///< Clockwise barrel rotation radians in signed Q3.12.
    std::uint16_t distance = 0;  ///< Normalized hover distance in Q0.16.
    std::uint16_t contact_id = 0;  ///< Nonzero contact ID while in range.

    /** @brief Compare every pen-state field. */
    [[nodiscard]] bool operator==(const pen_state_payload &) const noexcept = default;
  };

  /** @brief Parsed frozen pen state. */
  struct parsed_pen_state {
    wire_error error = wire_error::none;  ///< Parse result.
    pen_state_payload value {};  ///< Parsed pen state on success.

    /** @brief Test whether parsing succeeded. */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == wire_error::none;
    }
  };

  /** @brief Frozen device arrival/removal record payload. */
  struct device_lifecycle_payload {
    device_type device = device_type::keyboard;  ///< Device class.
    device_presence presence = device_presence::active;  ///< Arrival or removal state.

    /** @brief Compare every lifecycle payload field. */
    [[nodiscard]] bool operator==(const device_lifecycle_payload &) const noexcept = default;
  };

  /** @brief Exact per-key metadata preceding each complete-baseline record body. */
  struct input_baseline_record_header {
    baseline_record_kind kind = baseline_record_kind::core;  ///< Deterministic record class.
    std::uint8_t subtype = 0;  ///< Sensor or device class where defined, otherwise zero.
    std::uint32_t payload_length = 0;  ///< Exact following body bytes.
    std::uint32_t device_id = 0;  ///< Device ID, zero only for core state.
    std::uint32_t instance_generation = 0;  ///< Nonzero state/lifecycle generation.
    std::uint64_t state_sequence = 0;  ///< Nonzero latest logical sequence for this exact key.
    std::uint64_t physical_ordinal = 0;  ///< Nonzero latest physical sample for this exact key.

    /** @brief Compare every record-header field. */
    [[nodiscard]] bool operator==(const input_baseline_record_header &) const noexcept = default;
  };

  /** @brief Caller-owned record body used to serialize a complete deterministic baseline. */
  struct input_baseline_record_view {
    input_baseline_record_header header {};  ///< Exact record metadata.
    std::span<const std::uint8_t> payload {};  ///< Frozen kind body.
  };

  /** @brief Caller-owned complete deterministic baseline description. */
  struct input_baseline_view {
    bool neutral = false;  ///< Whether all held/contact/analog state is neutral.
    std::uint64_t edge_watermark = 0;  ///< Greatest edge atomically represented by every record.
    std::uint64_t text_barrier_edge_id = 0;  ///< Greatest edge required before retained text/IME work.
    std::span<const input_baseline_record_view> records {};  ///< Strictly sorted unique record keys.
  };

  /** @brief Parsed zero-copy complete deterministic baseline. */
  struct parsed_input_baseline {
    wire_error error = wire_error::none;  ///< Parse result.
    bool neutral = false;  ///< Whether neutral-state validation succeeded.
    std::uint16_t record_count = 0;  ///< Number of exact records.
    std::uint64_t edge_watermark = 0;  ///< Atomically represented edge watermark.
    std::uint64_t text_barrier_edge_id = 0;  ///< Text/IME ordering barrier.
    std::span<const std::uint8_t> record_bytes {};  ///< Validated record stream.

    /** @brief Test whether parsing succeeded. */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == wire_error::none;
    }

    /**
     * @brief Return one validated baseline record by index.
     *
     * @param index Zero-based record index.
     * @return Record view, or an invalid default view when out of range.
     */
    [[nodiscard]] constexpr input_baseline_record_view record(std::size_t index) const noexcept;
  };

  /** @brief Result of serializing one complete deterministic baseline body. */
  struct input_baseline_serialize_result {
    std::size_t bytes_written = 0;  ///< Exact complete body length on success.
    wire_error error = wire_error::none;  ///< Serialization status.

    /** @brief Test whether serialization succeeded. */
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
   * @brief Serialize the exact common 24-byte device or sensor prefix.
   *
   * @param value Prefix fields.
   * @param subtype Zero for device state or one frozen sensor type for sensor state.
   * @param output Exact prefix destination or larger span.
   * @return Serialization result.
   */
  [[nodiscard]] constexpr wire_error serialize_device_prefix(
    const device_record_prefix &value,
    const std::uint8_t subtype,
    const std::span<std::uint8_t> output
  ) noexcept {
    const auto sensor_record = subtype != 0;
    if (output.size() < 24U) {
      return wire_error::output_too_small;
    }
    if (!valid_device_type(value.device) || value.represented_reports == 0 || value.device_id == 0 ||
        value.instance_generation == 0 || value.record_length < 24U || value.physical_ordinal == 0 ||
        (sensor_record && (value.device != device_type::controller || !valid_sensor_type(static_cast<sensor_type>(subtype))))) {
      return wire_error::invalid_device;
    }
    output[0] = static_cast<std::uint8_t>(value.device);
    output[1] = subtype;
    wire::write_be<std::uint16_t>(output.subspan(2, 2), value.represented_reports);
    wire::write_be<std::uint32_t>(output.subspan(4, 4), value.device_id);
    wire::write_be<std::uint32_t>(output.subspan(8, 4), value.instance_generation);
    wire::write_be<std::uint16_t>(output.subspan(12, 2), value.record_length);
    wire::write_be<std::uint16_t>(output.subspan(14, 2), 0);
    wire::write_be<std::uint64_t>(output.subspan(16, 8), value.physical_ordinal);
    return wire_error::none;
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
   * @brief Parse an exact pointer payload and require absolute mode.
   *
   * @param payload Candidate 56-byte pointer payload.
   * @return Parsed absolute pointer or an exact pointer error.
   */
  [[nodiscard]] constexpr parsed_pointer parse_absolute_pointer_payload(
    const std::span<const std::uint8_t> payload
  ) noexcept {
    const auto parsed = parse_pointer_payload(payload);
    return parsed && parsed.value.mode == pointer_flag::absolute ? parsed : parsed_pointer {.error = wire_error::invalid_pointer};
  }

  /**
   * @brief Parse the exact frozen 64-byte keyboard, button, neutral, and text-barrier body.
   *
   * @param payload Candidate core-state bytes.
   * @return Parsed core state or a precise error.
   */
  [[nodiscard]] constexpr parsed_core_state parse_core_state_payload(
    const std::span<const std::uint8_t> payload
  ) noexcept {
    if (payload.size() != core_state_payload_size || wire::read_be<std::uint16_t>(payload.first<2>()) != 1U ||
        (wire::read_be<std::uint16_t>(payload.subspan(2, 2)) & ~std::uint16_t {1}) != 0 ||
        wire::read_be<std::uint32_t>(payload.subspan(28, 4)) != 0) {
      return {.error = wire_error::invalid_core_state};
    }
    core_state_payload value {
      .neutral = (wire::read_be<std::uint16_t>(payload.subspan(2, 2)) & 1U) != 0,
      .keyboard_instance_generation = wire::read_be<std::uint32_t>(payload.subspan(4, 4)),
      .physical_ordinal = wire::read_be<std::uint64_t>(payload.subspan(8, 8)),
      .text_barrier_edge_id = wire::read_be<std::uint64_t>(payload.subspan(16, 8)),
      .pointer_buttons = wire::read_be<std::uint32_t>(payload.subspan(24, 4)),
    };
    std::copy_n(payload.begin() + 32, value.key_bitmap.size(), value.key_bitmap.begin());
    if (value.keyboard_instance_generation == 0 || value.physical_ordinal == 0 ||
        (value.neutral && (value.pointer_buttons != 0 ||
                           std::any_of(value.key_bitmap.begin(), value.key_bitmap.end(), [](const auto byte) {
                             return byte != 0;
                           })))) {
      return {.error = wire_error::invalid_core_state};
    }
    return {.value = value};
  }

  /**
   * @brief Serialize the exact frozen core-state body.
   *
   * @param value Core state.
   * @param output Exact 64-byte destination or larger span.
   * @return Serialization result.
   */
  [[nodiscard]] constexpr wire_error serialize_core_state_payload(
    const core_state_payload &value,
    const std::span<std::uint8_t> output
  ) noexcept {
    if (output.size() < core_state_payload_size) {
      return wire_error::output_too_small;
    }
    if (value.keyboard_instance_generation == 0 || value.physical_ordinal == 0 ||
        (value.neutral && (value.pointer_buttons != 0 ||
                           std::any_of(value.key_bitmap.begin(), value.key_bitmap.end(), [](const auto byte) {
                             return byte != 0;
                           })))) {
      return wire_error::invalid_core_state;
    }
    wire::write_be<std::uint16_t>(output.first<2>(), 1);
    wire::write_be<std::uint16_t>(output.subspan(2, 2), value.neutral ? 1 : 0);
    wire::write_be<std::uint32_t>(output.subspan(4, 4), value.keyboard_instance_generation);
    wire::write_be<std::uint64_t>(output.subspan(8, 8), value.physical_ordinal);
    wire::write_be<std::uint64_t>(output.subspan(16, 8), value.text_barrier_edge_id);
    wire::write_be<std::uint32_t>(output.subspan(24, 4), value.pointer_buttons);
    wire::write_be<std::uint32_t>(output.subspan(28, 4), 0);
    std::copy(value.key_bitmap.begin(), value.key_bitmap.end(), output.begin() + 32);
    return wire_error::none;
  }

  /**
   * @brief Parse the exact frozen controller device-state body.
   *
   * @param payload Candidate 88-byte controller payload.
   * @return Parsed controller state or a precise error.
   */
  [[nodiscard]] constexpr parsed_controller_state parse_controller_state_payload(
    const std::span<const std::uint8_t> payload
  ) noexcept {
    if (payload.size() != controller_state_payload_size) {
      return {.error = wire_error::invalid_controller_state};
    }
    const auto prefix = parse_device_prefix(payload);
    const auto raw_battery = payload[24];
    const auto battery_percent = payload[25];
    const auto touch_count = payload[26];
    if (!prefix || prefix.value.device != device_type::controller ||
        prefix.value.record_length != controller_state_payload_size || raw_battery > 3U ||
        !((raw_battery == 0 && battery_percent == 255U) || (raw_battery != 0 && battery_percent <= 100U)) ||
        touch_count > 2U || payload[27] != 0) {
      return {.error = wire_error::invalid_controller_state};
    }
    controller_state_payload value {
      .prefix = prefix.value,
      .battery_state = static_cast<controller_battery_state>(raw_battery),
      .battery_percent = battery_percent,
      .buttons = wire::read_be<std::uint64_t>(payload.subspan(28, 8)),
    };
    if ((value.buttons & ~assigned_controller_button_mask) != 0) {
      return {.error = wire_error::invalid_controller_state};
    }
    for (std::size_t index = 0; index < value.axes.size(); ++index) {
      value.axes[index] = std::bit_cast<std::int16_t>(wire::read_be<std::uint16_t>(payload.subspan(36 + index * 2U, 2)));
    }
    for (std::size_t index = 0; index < value.triggers.size(); ++index) {
      value.triggers[index] = wire::read_be<std::uint16_t>(payload.subspan(52 + index * 2U, 2));
    }
    std::uint8_t active_contacts = 0;
    std::uint8_t previous_contact_id = 0;
    for (std::size_t index = 0; index < value.touchpad.size(); ++index) {
      const auto offset = 60 + index * 14U;
      const auto active = payload[offset + 1] == 1U;
      const auto expected_active = index < touch_count;
      if (payload[offset + 1] > 1U || active != expected_active || payload[offset + 12] != 0 ||
          payload[offset + 13] != 0) {
        return {.error = wire_error::invalid_controller_state};
      }
      value.touchpad[index] = {
        .contact_id = payload[offset],
        .active = active,
        .x = wire::read_be<std::uint32_t>(payload.subspan(offset + 2, 4)),
        .y = wire::read_be<std::uint32_t>(payload.subspan(offset + 6, 4)),
        .pressure = wire::read_be<std::uint16_t>(payload.subspan(offset + 10, 2)),
      };
      if (active) {
        if (value.touchpad[index].contact_id == 0 || value.touchpad[index].contact_id <= previous_contact_id) {
          return {.error = wire_error::invalid_controller_state};
        }
        previous_contact_id = value.touchpad[index].contact_id;
        ++active_contacts;
      } else if (value.touchpad[index].contact_id != 0 || value.touchpad[index].x != 0 ||
                 value.touchpad[index].y != 0 || value.touchpad[index].pressure != 0) {
        return {.error = wire_error::invalid_controller_state};
      }
    }
    return active_contacts == touch_count ? parsed_controller_state {.value = value} :
                                            parsed_controller_state {.error = wire_error::invalid_controller_state};
  }

  /**
   * @brief Serialize the exact frozen controller device-state body.
   *
   * @param value Controller state.
   * @param output Exact 88-byte destination or larger span.
   * @return Serialization result.
   */
  [[nodiscard]] constexpr wire_error serialize_controller_state_payload(
    const controller_state_payload &value,
    const std::span<std::uint8_t> output
  ) noexcept {
    if (output.size() < controller_state_payload_size) {
      return wire_error::output_too_small;
    }
    const auto raw_battery = static_cast<std::uint8_t>(value.battery_state);
    if (value.prefix.device != device_type::controller || value.prefix.record_length != controller_state_payload_size ||
        raw_battery > 3U ||
        !((raw_battery == 0 && value.battery_percent == 255U) ||
          (raw_battery != 0 && value.battery_percent <= 100U)) ||
        (value.buttons & ~assigned_controller_button_mask) != 0) {
      return wire_error::invalid_controller_state;
    }
    std::uint8_t active_contacts = 0;
    std::uint8_t previous_contact_id = 0;
    bool saw_inactive = false;
    for (std::size_t index = 0; index < value.touchpad.size(); ++index) {
      const auto &contact = value.touchpad[index];
      if (contact.active) {
        if (saw_inactive || contact.contact_id == 0 || contact.contact_id <= previous_contact_id) {
          return wire_error::invalid_controller_state;
        }
        previous_contact_id = contact.contact_id;
        ++active_contacts;
      } else if (contact.contact_id != 0 || contact.x != 0 || contact.y != 0 || contact.pressure != 0) {
        return wire_error::invalid_controller_state;
      } else {
        saw_inactive = true;
      }
    }
    if (const auto error = serialize_device_prefix(value.prefix, 0, output); error != wire_error::none) {
      return error;
    }
    output[24] = raw_battery;
    output[25] = value.battery_percent;
    output[26] = active_contacts;
    output[27] = 0;
    wire::write_be<std::uint64_t>(output.subspan(28, 8), value.buttons);
    for (std::size_t index = 0; index < value.axes.size(); ++index) {
      wire::write_be<std::uint16_t>(output.subspan(36 + index * 2U, 2), std::bit_cast<std::uint16_t>(value.axes[index]));
    }
    for (std::size_t index = 0; index < value.triggers.size(); ++index) {
      wire::write_be<std::uint16_t>(output.subspan(52 + index * 2U, 2), value.triggers[index]);
    }
    for (std::size_t index = 0; index < value.touchpad.size(); ++index) {
      const auto offset = 60 + index * 14U;
      const auto &contact = value.touchpad[index];
      output[offset] = contact.contact_id;
      output[offset + 1] = contact.active ? 1 : 0;
      wire::write_be<std::uint32_t>(output.subspan(offset + 2, 4), contact.x);
      wire::write_be<std::uint32_t>(output.subspan(offset + 6, 4), contact.y);
      wire::write_be<std::uint16_t>(output.subspan(offset + 10, 2), contact.pressure);
      output[offset + 12] = 0;
      output[offset + 13] = 0;
    }
    return wire_error::none;
  }

  /**
   * @brief Parse one exact controller gyroscope or accelerometer payload.
   *
   * @param payload Candidate 36-byte sensor payload.
   * @return Parsed controller sensor or a precise error.
   */
  [[nodiscard]] constexpr parsed_controller_sensor parse_controller_sensor_payload(
    const std::span<const std::uint8_t> payload
  ) noexcept {
    if (payload.size() != controller_sensor_payload_size) {
      return {.error = wire_error::invalid_sensor_state};
    }
    const auto prefix = parse_device_prefix(payload, true);
    if (!prefix || prefix.value.record_length != controller_sensor_payload_size) {
      return {.error = wire_error::invalid_sensor_state};
    }
    controller_sensor_payload value {
      .prefix = prefix.value,
      .sensor = static_cast<sensor_type>(payload[1]),
    };
    for (std::size_t index = 0; index < value.vector.size(); ++index) {
      value.vector[index] = std::bit_cast<std::int32_t>(wire::read_be<std::uint32_t>(payload.subspan(24 + index * 4U, 4)));
    }
    return {.value = value};
  }

  /**
   * @brief Serialize one exact controller sensor payload.
   *
   * @param value Sensor state.
   * @param output Exact 36-byte destination or larger span.
   * @return Serialization result.
   */
  [[nodiscard]] constexpr wire_error serialize_controller_sensor_payload(
    const controller_sensor_payload &value,
    const std::span<std::uint8_t> output
  ) noexcept {
    if (output.size() < controller_sensor_payload_size) {
      return wire_error::output_too_small;
    }
    if (value.prefix.record_length != controller_sensor_payload_size || !valid_sensor_type(value.sensor)) {
      return wire_error::invalid_sensor_state;
    }
    if (const auto error = serialize_device_prefix(value.prefix, static_cast<std::uint8_t>(value.sensor), output);
        error != wire_error::none) {
      return error;
    }
    for (std::size_t index = 0; index < value.vector.size(); ++index) {
      wire::write_be<std::uint32_t>(output.subspan(24 + index * 4U, 4), std::bit_cast<std::uint32_t>(value.vector[index]));
    }
    return wire_error::none;
  }

  /**
   * @brief Parse one exact 32-byte direct-touch contact record.
   *
   * @param bytes Candidate contact bytes.
   * @return Parsed contact or a precise error.
   */
  [[nodiscard]] constexpr parsed_touch_contact parse_touch_contact_payload(
    const std::span<const std::uint8_t> bytes
  ) noexcept {
    if (bytes.size() != touch_contact_size || (wire::read_be<std::uint16_t>(bytes.subspan(2, 2)) & ~std::uint16_t {1}) != 0 ||
        wire::read_be<std::uint32_t>(bytes.subspan(28, 4)) != 0) {
      return {.error = wire_error::invalid_touch_state};
    }
    touch_contact_payload value {
      .contact_id = wire::read_be<std::uint16_t>(bytes.first<2>()),
      .active = (wire::read_be<std::uint16_t>(bytes.subspan(2, 2)) & 1U) != 0,
      .x = wire::read_be<std::uint32_t>(bytes.subspan(4, 4)),
      .y = wire::read_be<std::uint32_t>(bytes.subspan(8, 4)),
      .pressure = wire::read_be<std::uint16_t>(bytes.subspan(12, 2)),
      .major = wire::read_be<std::uint16_t>(bytes.subspan(14, 2)),
      .minor = wire::read_be<std::uint16_t>(bytes.subspan(16, 2)),
      .orientation = std::bit_cast<std::int16_t>(wire::read_be<std::uint16_t>(bytes.subspan(18, 2))),
      .physical_ordinal = wire::read_be<std::uint64_t>(bytes.subspan(20, 8)),
    };
    if (value.contact_id == 0 || !value.active || value.physical_ordinal == 0) {
      return {.error = wire_error::invalid_touch_state};
    }
    return {.value = value};
  }

  /**
   * @brief Serialize one exact direct-touch contact record.
   *
   * @param value Active contact state.
   * @param output Exact 32-byte destination or larger span.
   * @return Serialization result.
   */
  [[nodiscard]] constexpr wire_error serialize_touch_contact_payload(
    const touch_contact_payload &value,
    const std::span<std::uint8_t> output
  ) noexcept {
    if (output.size() < touch_contact_size) {
      return wire_error::output_too_small;
    }
    if (value.contact_id == 0 || !value.active || value.physical_ordinal == 0) {
      return wire_error::invalid_touch_state;
    }
    wire::write_be<std::uint16_t>(output.first<2>(), value.contact_id);
    wire::write_be<std::uint16_t>(output.subspan(2, 2), 1);
    wire::write_be<std::uint32_t>(output.subspan(4, 4), value.x);
    wire::write_be<std::uint32_t>(output.subspan(8, 4), value.y);
    wire::write_be<std::uint16_t>(output.subspan(12, 2), value.pressure);
    wire::write_be<std::uint16_t>(output.subspan(14, 2), value.major);
    wire::write_be<std::uint16_t>(output.subspan(16, 2), value.minor);
    wire::write_be<std::uint16_t>(output.subspan(18, 2), std::bit_cast<std::uint16_t>(value.orientation));
    wire::write_be<std::uint64_t>(output.subspan(20, 8), value.physical_ordinal);
    wire::write_be<std::uint32_t>(output.subspan(28, 4), 0);
    return wire_error::none;
  }

  constexpr parsed_touch_contact parsed_touch_state::contact(const std::size_t index) const noexcept {
    return error == wire_error::none && index < contact_count ?
             parse_touch_contact_payload(contact_bytes.subspan(index * touch_contact_size, touch_contact_size)) :
             parsed_touch_contact {.error = wire_error::invalid_touch_state};
  }

  /**
   * @brief Parse one bounded direct-touch device state with sorted active contacts.
   *
   * @param payload Candidate touch device-state payload.
   * @return Parsed zero-copy touch state or a precise error.
   */
  [[nodiscard]] constexpr parsed_touch_state parse_touch_state_payload(
    const std::span<const std::uint8_t> payload
  ) noexcept {
    if (payload.size() < touch_state_header_size || payload[25] != 0 || payload[26] != 0 || payload[27] != 0) {
      return {.error = wire_error::invalid_touch_state};
    }
    const auto prefix = parse_device_prefix(payload);
    const auto count = payload[24];
    if (!prefix || prefix.value.device != device_type::touch || count > maximum_touch_contacts ||
        prefix.value.record_length != payload.size() || payload.size() != touch_state_header_size + count * touch_contact_size) {
      return {.error = wire_error::invalid_touch_state};
    }
    std::uint16_t previous_id = 0;
    const auto contacts = payload.subspan(touch_state_header_size);
    for (std::size_t index = 0; index < count; ++index) {
      const auto contact = parse_touch_contact_payload(contacts.subspan(index * touch_contact_size, touch_contact_size));
      if (!contact || contact.value.contact_id <= previous_id || contact.value.physical_ordinal > prefix.value.physical_ordinal) {
        return {.error = wire_error::invalid_touch_state};
      }
      previous_id = contact.value.contact_id;
    }
    return {
      .prefix = prefix.value,
      .contact_bytes = contacts,
      .contact_count = count,
    };
  }

  /**
   * @brief Serialize one bounded sorted direct-touch device state.
   *
   * @param value Touch prefix and active contacts.
   * @param output Destination storage.
   * @return Serialization result.
   */
  [[nodiscard]] constexpr wire_error serialize_touch_state_payload(
    const touch_state_view &value,
    const std::span<std::uint8_t> output
  ) noexcept {
    if (value.contacts.size() > maximum_touch_contacts ||
        value.prefix.record_length != touch_state_header_size + value.contacts.size() * touch_contact_size) {
      return wire_error::invalid_touch_state;
    }
    if (output.size() < value.prefix.record_length) {
      return wire_error::output_too_small;
    }
    if (value.prefix.device != device_type::touch) {
      return wire_error::invalid_touch_state;
    }
    if (const auto error = serialize_device_prefix(value.prefix, 0, output); error != wire_error::none) {
      return error;
    }
    output[24] = static_cast<std::uint8_t>(value.contacts.size());
    output[25] = 0;
    output[26] = 0;
    output[27] = 0;
    std::uint16_t previous_id = 0;
    for (std::size_t index = 0; index < value.contacts.size(); ++index) {
      const auto &contact = value.contacts[index];
      if (contact.contact_id <= previous_id || contact.physical_ordinal > value.prefix.physical_ordinal) {
        return wire_error::invalid_touch_state;
      }
      const auto error = serialize_touch_contact_payload(
        contact,
        output.subspan(touch_state_header_size + index * touch_contact_size, touch_contact_size)
      );
      if (error != wire_error::none) {
        return error;
      }
      previous_id = contact.contact_id;
    }
    return wire_error::none;
  }

  /**
   * @brief Parse one exact latest absolute pen device state.
   *
   * @param payload Candidate 56-byte pen payload.
   * @return Parsed pen state or a precise error.
   */
  [[nodiscard]] constexpr parsed_pen_state parse_pen_state_payload(
    const std::span<const std::uint8_t> payload
  ) noexcept {
    if (payload.size() != pen_state_payload_size || (payload[24] & ~std::uint8_t {7}) != 0 || payload[25] != 0 ||
        wire::read_be<std::uint16_t>(payload.subspan(50, 2)) != 0 || wire::read_be<std::uint32_t>(payload.subspan(52, 4)) != 0) {
      return {.error = wire_error::invalid_pen_state};
    }
    const auto prefix = parse_device_prefix(payload);
    if (!prefix || prefix.value.device != device_type::pen || prefix.value.record_length != pen_state_payload_size) {
      return {.error = wire_error::invalid_pen_state};
    }
    pen_state_payload value {
      .prefix = prefix.value,
      .in_range = (payload[24] & 1U) != 0,
      .contact = (payload[24] & 2U) != 0,
      .eraser = (payload[24] & 4U) != 0,
      .buttons = wire::read_be<std::uint16_t>(payload.subspan(26, 2)),
      .x = wire::read_be<std::uint32_t>(payload.subspan(28, 4)),
      .y = wire::read_be<std::uint32_t>(payload.subspan(32, 4)),
      .pressure = wire::read_be<std::uint16_t>(payload.subspan(36, 2)),
      .tangential_pressure = std::bit_cast<std::int16_t>(wire::read_be<std::uint16_t>(payload.subspan(38, 2))),
      .tilt_x = std::bit_cast<std::int16_t>(wire::read_be<std::uint16_t>(payload.subspan(40, 2))),
      .tilt_y = std::bit_cast<std::int16_t>(wire::read_be<std::uint16_t>(payload.subspan(42, 2))),
      .rotation = std::bit_cast<std::int16_t>(wire::read_be<std::uint16_t>(payload.subspan(44, 2))),
      .distance = wire::read_be<std::uint16_t>(payload.subspan(46, 2)),
      .contact_id = wire::read_be<std::uint16_t>(payload.subspan(48, 2)),
    };
    if ((value.contact && !value.in_range) || (value.in_range && value.contact_id == 0) ||
        (!value.in_range && (value.contact_id != 0 || value.contact || value.eraser || value.buttons != 0 ||
                             value.pressure != 0 || value.tangential_pressure != 0 || value.distance != 0))) {
      return {.error = wire_error::invalid_pen_state};
    }
    return {.value = value};
  }

  /**
   * @brief Serialize one exact latest absolute pen state.
   *
   * @param value Pen state.
   * @param output Exact 56-byte destination or larger span.
   * @return Serialization result.
   */
  [[nodiscard]] constexpr wire_error serialize_pen_state_payload(
    const pen_state_payload &value,
    const std::span<std::uint8_t> output
  ) noexcept {
    if (output.size() < pen_state_payload_size) {
      return wire_error::output_too_small;
    }
    if (value.prefix.device != device_type::pen || value.prefix.record_length != pen_state_payload_size ||
        (value.contact && !value.in_range) || (value.in_range && value.contact_id == 0) ||
        (!value.in_range && (value.contact_id != 0 || value.contact || value.eraser || value.buttons != 0 ||
                             value.pressure != 0 || value.tangential_pressure != 0 || value.distance != 0))) {
      return wire_error::invalid_pen_state;
    }
    if (const auto error = serialize_device_prefix(value.prefix, 0, output); error != wire_error::none) {
      return error;
    }
    output[24] = static_cast<std::uint8_t>((value.in_range ? 1U : 0U) | (value.contact ? 2U : 0U) | (value.eraser ? 4U : 0U));
    output[25] = 0;
    wire::write_be<std::uint16_t>(output.subspan(26, 2), value.buttons);
    wire::write_be<std::uint32_t>(output.subspan(28, 4), value.x);
    wire::write_be<std::uint32_t>(output.subspan(32, 4), value.y);
    wire::write_be<std::uint16_t>(output.subspan(36, 2), value.pressure);
    wire::write_be<std::uint16_t>(output.subspan(38, 2), std::bit_cast<std::uint16_t>(value.tangential_pressure));
    wire::write_be<std::uint16_t>(output.subspan(40, 2), std::bit_cast<std::uint16_t>(value.tilt_x));
    wire::write_be<std::uint16_t>(output.subspan(42, 2), std::bit_cast<std::uint16_t>(value.tilt_y));
    wire::write_be<std::uint16_t>(output.subspan(44, 2), std::bit_cast<std::uint16_t>(value.rotation));
    wire::write_be<std::uint16_t>(output.subspan(46, 2), value.distance);
    wire::write_be<std::uint16_t>(output.subspan(48, 2), value.contact_id);
    wire::write_be<std::uint16_t>(output.subspan(50, 2), 0);
    wire::write_be<std::uint32_t>(output.subspan(52, 4), 0);
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

  /** @brief Return whether a complete-baseline record kind is assigned by LSP/1. */
  [[nodiscard]] constexpr bool valid_baseline_record_kind(const baseline_record_kind kind) noexcept {
    return kind >= baseline_record_kind::core && kind <= baseline_record_kind::pen;
  }

  /**
   * @brief Parse one exact four-byte device lifecycle body.
   *
   * @param payload Candidate lifecycle bytes.
   * @param value Parsed destination.
   * @return Parsing status.
   */
  [[nodiscard]] constexpr wire_error parse_device_lifecycle_payload(
    const std::span<const std::uint8_t> payload,
    device_lifecycle_payload &value
  ) noexcept {
    if (payload.size() != 4U || payload[2] != 0 || payload[3] != 0) {
      return wire_error::invalid_baseline_body;
    }
    value = {
      .device = static_cast<device_type>(payload[0]),
      .presence = static_cast<device_presence>(payload[1]),
    };
    return valid_device_type(value.device) && value.device != device_type::keyboard &&
               (value.presence == device_presence::active || value.presence == device_presence::removed) ?
             wire_error::none :
             wire_error::invalid_baseline_body;
  }

  /**
   * @brief Serialize one exact four-byte device lifecycle body.
   *
   * @param value Arrival or removal state.
   * @param output Exact four-byte destination or larger span.
   * @return Serialization result.
   */
  [[nodiscard]] constexpr wire_error serialize_device_lifecycle_payload(
    const device_lifecycle_payload &value,
    const std::span<std::uint8_t> output
  ) noexcept {
    if (output.size() < 4U) {
      return wire_error::output_too_small;
    }
    if (!valid_device_type(value.device) || value.device == device_type::keyboard ||
        (value.presence != device_presence::active && value.presence != device_presence::removed)) {
      return wire_error::invalid_baseline_body;
    }
    output[0] = static_cast<std::uint8_t>(value.device);
    output[1] = static_cast<std::uint8_t>(value.presence);
    output[2] = 0;
    output[3] = 0;
    return wire_error::none;
  }

  /**
   * @brief Return whether one validated record body represents neutral input state.
   *
   * @param header Record metadata.
   * @param payload Frozen record body.
   * @return `true` when no held button, contact, analog deflection, or sensor value remains.
   */
  [[nodiscard]] constexpr bool baseline_record_is_neutral(
    const input_baseline_record_header &header,
    const std::span<const std::uint8_t> payload
  ) noexcept {
    switch (header.kind) {
      case baseline_record_kind::core:
        {
          const auto value = parse_core_state_payload(payload);
          return value && value.value.neutral;
        }
      case baseline_record_kind::device_lifecycle:
      case baseline_record_kind::pointer:
        return true;
      case baseline_record_kind::controller:
        {
          const auto value = parse_controller_state_payload(payload);
          return value && value.value.buttons == 0 &&
                 std::all_of(value.value.axes.begin(), value.value.axes.end(), [](const auto axis) {
                   return axis == 0;
                 }) &&
                 std::all_of(value.value.triggers.begin(), value.value.triggers.end(), [](const auto trigger) {
                   return trigger == 0;
                 }) &&
                 std::all_of(value.value.touchpad.begin(), value.value.touchpad.end(), [](const auto &contact) {
                   return !contact.active;
                 });
        }
      case baseline_record_kind::controller_sensor:
        {
          const auto value = parse_controller_sensor_payload(payload);
          return value && std::all_of(value.value.vector.begin(), value.value.vector.end(), [](const auto axis) {
                   return axis == 0;
                 });
        }
      case baseline_record_kind::touch:
        {
          const auto value = parse_touch_state_payload(payload);
          return value && value.contact_count == 0;
        }
      case baseline_record_kind::pen:
        {
          const auto value = parse_pen_state_payload(payload);
          return value && !value.value.in_range && !value.value.contact && !value.value.eraser &&
                 value.value.buttons == 0 && value.value.x == 0 && value.value.y == 0 &&
                 value.value.pressure == 0 && value.value.tangential_pressure == 0 && value.value.tilt_x == 0 &&
                 value.value.tilt_y == 0 && value.value.rotation == 0 && value.value.distance == 0 &&
                 value.value.contact_id == 0;
        }
    }
    return false;
  }

  /**
   * @brief Validate one complete-baseline record body against its exact per-key metadata.
   *
   * @param header Record metadata.
   * @param payload Exact record body.
   * @param neutral Whether neutral-state constraints apply.
   * @return Validation result.
   */
  [[nodiscard]] constexpr wire_error validate_input_baseline_record(
    const input_baseline_record_header &header,
    const std::span<const std::uint8_t> payload,
    const bool neutral
  ) noexcept {
    if (!valid_baseline_record_kind(header.kind) || header.payload_length != payload.size() ||
        header.instance_generation == 0 || header.state_sequence == 0 || header.physical_ordinal == 0) {
      return wire_error::invalid_baseline_body;
    }
    wire_error error = wire_error::invalid_baseline_body;
    switch (header.kind) {
      case baseline_record_kind::core:
        {
          const auto value = parse_core_state_payload(payload);
          error = value && header.subtype == 0 && header.device_id == 0 &&
                      header.instance_generation == value.value.keyboard_instance_generation &&
                      header.physical_ordinal == value.value.physical_ordinal ?
                    wire_error::none :
                    wire_error::invalid_baseline_body;
          break;
        }
      case baseline_record_kind::device_lifecycle:
        {
          device_lifecycle_payload value;
          error = parse_device_lifecycle_payload(payload, value);
          if (error == wire_error::none &&
              (header.device_id == 0 || header.subtype != static_cast<std::uint8_t>(value.device))) {
            error = wire_error::invalid_baseline_body;
          }
          break;
        }
      case baseline_record_kind::pointer:
        {
          const auto value = parse_pointer_payload(payload);
          error = value && header.subtype == 0 && header.device_id >= 1U && header.device_id <= 4U &&
                      header.instance_generation == value.value.instance_generation &&
                      header.physical_ordinal == value.value.physical_ordinal ?
                    wire_error::none :
                    wire_error::invalid_baseline_body;
          break;
        }
      case baseline_record_kind::controller:
        {
          const auto value = parse_controller_state_payload(payload);
          error = value && header.subtype == 0 && header.device_id == value.value.prefix.device_id &&
                      header.instance_generation == value.value.prefix.instance_generation &&
                      header.physical_ordinal == value.value.prefix.physical_ordinal ?
                    wire_error::none :
                    wire_error::invalid_baseline_body;
          break;
        }
      case baseline_record_kind::controller_sensor:
        {
          const auto value = parse_controller_sensor_payload(payload);
          error = value && header.subtype == static_cast<std::uint8_t>(value.value.sensor) &&
                      header.device_id == value.value.prefix.device_id &&
                      header.instance_generation == value.value.prefix.instance_generation &&
                      header.physical_ordinal == value.value.prefix.physical_ordinal ?
                    wire_error::none :
                    wire_error::invalid_baseline_body;
          break;
        }
      case baseline_record_kind::touch:
        {
          const auto value = parse_touch_state_payload(payload);
          error = value && header.subtype == 0 && header.device_id == value.prefix.device_id &&
                      header.instance_generation == value.prefix.instance_generation &&
                      header.physical_ordinal == value.prefix.physical_ordinal ?
                    wire_error::none :
                    wire_error::invalid_baseline_body;
          break;
        }
      case baseline_record_kind::pen:
        {
          const auto value = parse_pen_state_payload(payload);
          error = value && header.subtype == 0 && header.device_id == value.value.prefix.device_id &&
                      header.instance_generation == value.value.prefix.instance_generation &&
                      header.physical_ordinal == value.value.prefix.physical_ordinal ?
                    wire_error::none :
                    wire_error::invalid_baseline_body;
          break;
        }
    }
    return error == wire_error::none && (!neutral || baseline_record_is_neutral(header, payload)) ?
             wire_error::none :
             wire_error::invalid_baseline_body;
  }

  /** @brief Return whether the left deterministic record key precedes the right key. */
  [[nodiscard]] constexpr bool baseline_record_key_less(
    const input_baseline_record_header &left,
    const input_baseline_record_header &right
  ) noexcept {
    if (left.kind != right.kind) {
      return static_cast<std::uint8_t>(left.kind) < static_cast<std::uint8_t>(right.kind);
    }
    if (left.subtype != right.subtype) {
      return left.subtype < right.subtype;
    }
    return left.device_id < right.device_id;
  }

  /**
   * @brief Parse one exact 32-byte complete-baseline record header.
   *
   * @param bytes Candidate header bytes.
   * @return Parsed metadata, or a default invalid header when reserved fields are nonzero.
   */
  [[nodiscard]] constexpr input_baseline_record_header parse_input_baseline_record_header(
    const std::span<const std::uint8_t> bytes
  ) noexcept {
    if (bytes.size() < input_baseline_record_header_size || wire::read_be<std::uint16_t>(bytes.subspan(2, 2)) != 0) {
      return {};
    }
    return {
      .kind = static_cast<baseline_record_kind>(bytes[0]),
      .subtype = bytes[1],
      .payload_length = wire::read_be<std::uint32_t>(bytes.subspan(4, 4)),
      .device_id = wire::read_be<std::uint32_t>(bytes.subspan(8, 4)),
      .instance_generation = wire::read_be<std::uint32_t>(bytes.subspan(12, 4)),
      .state_sequence = wire::read_be<std::uint64_t>(bytes.subspan(16, 8)),
      .physical_ordinal = wire::read_be<std::uint64_t>(bytes.subspan(24, 8)),
    };
  }

  /**
   * @brief Serialize one exact complete-baseline record header.
   *
   * @param header Valid nonzero record metadata.
   * @param output Exact 32-byte destination or larger span.
   * @return Typed serialization error.
   */
  [[nodiscard]] constexpr wire_error serialize_input_baseline_record_header(
    const input_baseline_record_header &header,
    const std::span<std::uint8_t> output
  ) noexcept {
    if (output.size() < input_baseline_record_header_size) {
      return wire_error::output_too_small;
    }
    if (!valid_baseline_record_kind(header.kind) || header.payload_length == 0 ||
        header.instance_generation == 0 || header.state_sequence == 0 || header.physical_ordinal == 0) {
      return wire_error::invalid_baseline_body;
    }
    output[0] = static_cast<std::uint8_t>(header.kind);
    output[1] = header.subtype;
    wire::write_be<std::uint16_t>(output.subspan(2, 2), 0);
    wire::write_be<std::uint32_t>(output.subspan(4, 4), header.payload_length);
    wire::write_be<std::uint32_t>(output.subspan(8, 4), header.device_id);
    wire::write_be<std::uint32_t>(output.subspan(12, 4), header.instance_generation);
    wire::write_be<std::uint64_t>(output.subspan(16, 8), header.state_sequence);
    wire::write_be<std::uint64_t>(output.subspan(24, 8), header.physical_ordinal);
    return wire_error::none;
  }

  constexpr input_baseline_record_view parsed_input_baseline::record(const std::size_t index) const noexcept {
    if (error != wire_error::none || index >= record_count) {
      return {};
    }
    auto remaining = record_bytes;
    for (std::size_t current = 0; current <= index; ++current) {
      if (remaining.size() < input_baseline_record_header_size) {
        return {};
      }
      const auto header = parse_input_baseline_record_header(remaining.first<input_baseline_record_header_size>());
      if (!valid_baseline_record_kind(header.kind) ||
          header.payload_length > remaining.size() - input_baseline_record_header_size) {
        return {};
      }
      const auto payload = remaining.subspan(input_baseline_record_header_size, header.payload_length);
      if (current == index) {
        return {.header = header, .payload = payload};
      }
      remaining = remaining.subspan(input_baseline_record_header_size + header.payload_length);
    }
    return {};
  }

  /**
   * @brief Parse and validate one complete deterministic input-baseline body.
   *
   * @param bytes Complete assembled and digest-authenticated baseline bytes.
   * @return Parsed zero-copy baseline or a precise error.
   */
  [[nodiscard]] constexpr parsed_input_baseline parse_input_baseline(
    const std::span<const std::uint8_t> bytes
  ) noexcept {
    if (bytes.size() < input_baseline_header_size || bytes.size() > maximum_baseline_bytes ||
        bytes[0] != 'L' || bytes[1] != 'S' || bytes[2] != 'P' || bytes[3] != 'B' || bytes[4] != 1U ||
        (bytes[5] & ~std::uint8_t {1}) != 0 || wire::read_be<std::uint32_t>(bytes.subspan(8, 4)) != bytes.size() ||
        wire::read_be<std::uint32_t>(bytes.subspan(12, 4)) != 0) {
      return {.error = wire_error::invalid_baseline_body};
    }
    const auto count = wire::read_be<std::uint16_t>(bytes.subspan(6, 2));
    const auto edge_watermark = wire::read_be<std::uint64_t>(bytes.subspan(16, 8));
    const auto text_barrier = wire::read_be<std::uint64_t>(bytes.subspan(24, 8));
    const auto neutral = (bytes[5] & 1U) != 0;
    if (count == 0 || count > maximum_input_baseline_records || text_barrier > edge_watermark) {
      return {.error = wire_error::invalid_baseline_body};
    }
    auto remaining = bytes.subspan(input_baseline_header_size);
    input_baseline_record_header previous;

    struct lifecycle_entry {
      device_type device = device_type::keyboard;  ///< Lifecycle device class.
      device_presence presence = device_presence::active;  ///< Active or removed state.
      std::uint32_t device_id = 0;  ///< Device identifier.
      std::uint32_t instance_generation = 0;  ///< Exact lifecycle generation.
    };

    std::array<lifecycle_entry, maximum_input_baseline_records> lifecycles {};
    std::size_t lifecycle_count = 0;
    bool have_previous = false;
    bool saw_core = false;
    for (std::size_t index = 0; index < count; ++index) {
      if (remaining.size() < input_baseline_record_header_size) {
        return {.error = wire_error::invalid_baseline_body};
      }
      const auto header = parse_input_baseline_record_header(remaining.first<input_baseline_record_header_size>());
      if (!valid_baseline_record_kind(header.kind) || header.payload_length > remaining.size() - input_baseline_record_header_size) {
        return {.error = wire_error::invalid_baseline_body};
      }
      const auto payload = remaining.subspan(input_baseline_record_header_size, header.payload_length);
      if ((have_previous && !baseline_record_key_less(previous, header)) ||
          validate_input_baseline_record(header, payload, neutral) != wire_error::none) {
        return {.error = wire_error::invalid_baseline_body};
      }
      if (header.kind == baseline_record_kind::core) {
        const auto core = parse_core_state_payload(payload);
        if (saw_core || !core || core.value.text_barrier_edge_id != text_barrier) {
          return {.error = wire_error::invalid_baseline_body};
        }
        saw_core = true;
      } else if (header.kind == baseline_record_kind::device_lifecycle) {
        device_lifecycle_payload lifecycle;
        if (parse_device_lifecycle_payload(payload, lifecycle) != wire_error::none) {
          return {.error = wire_error::invalid_baseline_body};
        }
        lifecycles[lifecycle_count++] = {
          .device = lifecycle.device,
          .presence = lifecycle.presence,
          .device_id = header.device_id,
          .instance_generation = header.instance_generation,
        };
      } else {
        device_type expected_device = device_type::keyboard;
        switch (header.kind) {
          case baseline_record_kind::pointer:
            expected_device = device_type::pointer;
            break;
          case baseline_record_kind::controller:
          case baseline_record_kind::controller_sensor:
            expected_device = device_type::controller;
            break;
          case baseline_record_kind::touch:
            expected_device = device_type::touch;
            break;
          case baseline_record_kind::pen:
            expected_device = device_type::pen;
            break;
          case baseline_record_kind::core:
          case baseline_record_kind::device_lifecycle:
            break;
        }
        const auto active_lifecycle = std::find_if(
          lifecycles.begin(),
          lifecycles.begin() + lifecycle_count,
          [&](const auto &lifecycle) {
            return lifecycle.device == expected_device && lifecycle.presence == device_presence::active &&
                   lifecycle.device_id == header.device_id &&
                   lifecycle.instance_generation == header.instance_generation;
          }
        );
        if (active_lifecycle == lifecycles.begin() + lifecycle_count) {
          return {.error = wire_error::invalid_baseline_body};
        }
      }
      previous = header;
      have_previous = true;
      remaining = remaining.subspan(input_baseline_record_header_size + header.payload_length);
    }
    if (!remaining.empty() || !saw_core) {
      return {.error = wire_error::invalid_baseline_body};
    }
    for (std::size_t lifecycle_index = 0; lifecycle_index < lifecycle_count; ++lifecycle_index) {
      const auto &lifecycle = lifecycles[lifecycle_index];
      bool matching_state = false;
      auto records = bytes.subspan(input_baseline_header_size);
      for (std::size_t record_index = 0; record_index < count; ++record_index) {
        const auto header = parse_input_baseline_record_header(records.first<input_baseline_record_header_size>());
        const auto payload = records.subspan(input_baseline_record_header_size, header.payload_length);
        device_type state_device = device_type::keyboard;
        bool is_device_state = true;
        switch (header.kind) {
          case baseline_record_kind::pointer:
            state_device = device_type::pointer;
            break;
          case baseline_record_kind::controller:
            state_device = device_type::controller;
            break;
          case baseline_record_kind::touch:
            state_device = device_type::touch;
            break;
          case baseline_record_kind::pen:
            state_device = device_type::pen;
            break;
          case baseline_record_kind::core:
          case baseline_record_kind::device_lifecycle:
          case baseline_record_kind::controller_sensor:
            is_device_state = false;
            break;
        }
        matching_state = matching_state ||
                         (is_device_state && state_device == lifecycle.device &&
                          header.device_id == lifecycle.device_id &&
                          header.instance_generation == lifecycle.instance_generation && !payload.empty());
        records = records.subspan(input_baseline_record_header_size + header.payload_length);
      }
      if ((lifecycle.presence == device_presence::active) != matching_state) {
        return {.error = wire_error::invalid_baseline_body};
      }
    }
    return {
      .neutral = neutral,
      .record_count = count,
      .edge_watermark = edge_watermark,
      .text_barrier_edge_id = text_barrier,
      .record_bytes = bytes.subspan(input_baseline_header_size),
    };
  }

  /**
   * @brief Serialize one complete deterministic input-baseline body into caller storage.
   *
   * @param value Complete sorted baseline description.
   * @param output Caller-owned destination up to 32 KiB.
   * @return Exact encoded length and status.
   */
  [[nodiscard]] constexpr input_baseline_serialize_result serialize_input_baseline(
    const input_baseline_view &value,
    const std::span<std::uint8_t> output
  ) noexcept {
    if (value.records.empty() || value.records.size() > maximum_input_baseline_records ||
        value.text_barrier_edge_id > value.edge_watermark) {
      return {.error = wire_error::invalid_baseline_body};
    }
    std::size_t total = input_baseline_header_size;
    input_baseline_record_header previous;
    bool have_previous = false;
    bool saw_core = false;
    for (const auto &record : value.records) {
      if (record.payload.size() > std::numeric_limits<std::uint32_t>::max() ||
          record.header.payload_length != record.payload.size() ||
          (have_previous && !baseline_record_key_less(previous, record.header)) ||
          validate_input_baseline_record(record.header, record.payload, value.neutral) != wire_error::none ||
          total > maximum_baseline_bytes - input_baseline_record_header_size ||
          record.payload.size() > maximum_baseline_bytes - total - input_baseline_record_header_size) {
        return {.error = wire_error::invalid_baseline_body};
      }
      if (record.header.kind == baseline_record_kind::core) {
        const auto core = parse_core_state_payload(record.payload);
        if (saw_core || !core || core.value.text_barrier_edge_id != value.text_barrier_edge_id) {
          return {.error = wire_error::invalid_baseline_body};
        }
        saw_core = true;
      }
      total += input_baseline_record_header_size + record.payload.size();
      previous = record.header;
      have_previous = true;
    }
    if (!saw_core || output.size() < total) {
      return {.error = saw_core ? wire_error::output_too_small : wire_error::invalid_baseline_body};
    }
    output[0] = 'L';
    output[1] = 'S';
    output[2] = 'P';
    output[3] = 'B';
    output[4] = 1;
    output[5] = value.neutral ? 1 : 0;
    wire::write_be<std::uint16_t>(output.subspan(6, 2), static_cast<std::uint16_t>(value.records.size()));
    wire::write_be<std::uint32_t>(output.subspan(8, 4), static_cast<std::uint32_t>(total));
    wire::write_be<std::uint32_t>(output.subspan(12, 4), 0);
    wire::write_be<std::uint64_t>(output.subspan(16, 8), value.edge_watermark);
    wire::write_be<std::uint64_t>(output.subspan(24, 8), value.text_barrier_edge_id);
    std::size_t offset = input_baseline_header_size;
    for (const auto &record : value.records) {
      if (serialize_input_baseline_record_header(
            record.header,
            output.subspan(offset, input_baseline_record_header_size)
          ) != wire_error::none) {
        return {.error = wire_error::invalid_baseline_body};
      }
      offset += input_baseline_record_header_size;
      std::copy(record.payload.begin(), record.payload.end(), output.subspan(offset, record.payload.size()).begin());
      offset += record.payload.size();
    }
    return parse_input_baseline(output.first(total)) ? input_baseline_serialize_result {.bytes_written = total} :
                                                       input_baseline_serialize_result {.error = wire_error::invalid_baseline_body};
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
        {
          const auto core = parse_core_state_payload(payload);
          return !core || core.value.text_barrier_edge_id > header.edge_watermark ? wire_error::invalid_core_state : wire_error::none;
        }
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
          switch (type) {
            case device_type::controller:
              return parse_controller_state_payload(payload).error;
            case device_type::touch:
              return parse_touch_state_payload(payload).error;
            case device_type::pen:
              return parse_pen_state_payload(payload).error;
            case device_type::keyboard:
            case device_type::pointer:
              return wire_error::invalid_device;
          }
          return wire_error::invalid_device;
        }
      case packet_kind::sensor_state:
        {
          std::uint32_t controller_id = 0;
          sensor_type sensor {};
          const auto sensor_payload = parse_controller_sensor_payload(payload);
          if (!sensor_payload) {
            return sensor_payload.error;
          }
          const auto &prefix = sensor_payload.value.prefix;
          if (!decode_sensor_object_id(header.object_id, controller_id, sensor) ||
              controller_id != prefix.device_id || sensor != sensor_payload.value.sensor) {
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
