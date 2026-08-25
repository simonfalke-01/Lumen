/**
 * @file src/protocol_common/input_state.cpp
 * @brief Strict protocol-v3 state-format-2/3 structural validation.
 */

#include "input_state.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <type_traits>

namespace lumen::protocol_common::input_state {
  namespace {
    template<typename Integer>
    Integer read_be(const std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
      static_assert(std::is_unsigned_v<Integer>);
      Integer value = 0;
      for (std::size_t index = 0; index < sizeof(Integer); ++index) {
        value = static_cast<Integer>((value << 8) | bytes[offset + index]);
      }
      return value;
    }

    bool zero_range(const std::span<const std::uint8_t> bytes, const std::size_t first, const std::size_t last) noexcept {
      return std::all_of(bytes.begin() + static_cast<std::ptrdiff_t>(first), bytes.begin() + static_cast<std::ptrdiff_t>(last), [](const auto byte) {
        return byte == 0;
      });
    }
  }  // namespace

  std::optional<Format> format(const std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.size() < header_bytes) {
      return std::nullopt;
    }
    if (bytes[87] == 0) {
      return Format::two;
    }
    if (bytes[87] == static_cast<std::uint8_t>(Format::three)) {
      return Format::three;
    }
    return std::nullopt;
  }

  std::size_t controller_record_bytes(const Format format) noexcept {
    return format == Format::three ? std::size_t {56} : std::size_t {64};
  }

  std::optional<Error> validate(
    const std::span<const std::uint8_t> bytes,
    const std::optional<bool> expected_absolute
  ) noexcept {
    if (bytes.size() < header_bytes) {
      return Error::too_short;
    }
    const auto declared_format = format(bytes);
    if (!declared_format) {
      return Error::format_mismatch;
    }
    return validate(bytes, *declared_format, expected_absolute);
  }

  std::optional<Error> validate(
    const std::span<const std::uint8_t> bytes,
    const Format expected_format,
    const std::optional<bool> expected_absolute
  ) noexcept {
    if (bytes.size() < header_bytes) {
      return Error::too_short;
    }
    if (format(bytes) != expected_format) {
      return Error::format_mismatch;
    }
    const auto state_flags = read_be<std::uint32_t>(bytes, 0);
    const bool absolute = (state_flags & 1) != 0;
    const bool relative = (state_flags & 2) != 0;
    if ((state_flags & ~std::uint32_t {7}) != 0 || absolute == relative || (read_be<std::uint32_t>(bytes, 4) & ~std::uint32_t {0x1f}) != 0) {
      return Error::invalid_flags;
    }
    if (expected_absolute && absolute != *expected_absolute) {
      return Error::pointer_mode_mismatch;
    }
    if ((relative && (read_be<std::uint32_t>(bytes, 40) != 0 || read_be<std::uint32_t>(bytes, 44) != 0)) ||
        (absolute && (read_be<std::uint64_t>(bytes, 8) != 0 || read_be<std::uint64_t>(bytes, 16) != 0))) {
      return Error::pointer_mode_mismatch;
    }
    const auto reserved_start = expected_format == Format::three ? std::size_t {88} : std::size_t {87};
    if (!zero_range(bytes, reserved_start, header_bytes)) {
      return Error::reserved_not_zero;
    }

    const auto controller_count = bytes[84];
    const auto touch_count = bytes[85];
    const auto pen_count = bytes[86];
    const auto controller_bytes = controller_record_bytes(expected_format);
    const auto expected_size = header_bytes + controller_bytes * controller_count +
                               std::size_t {32} * touch_count + std::size_t {40} * pen_count;
    if (controller_count > 16 || touch_count > 16 || pen_count > 4 || expected_size != bytes.size()) {
      return Error::wrong_size;
    }
    std::uint32_t controller_mask = 0;
    std::uint8_t previous_controller = 0;
    for (std::size_t index = 0; index < controller_count; ++index) {
      const auto offset = header_bytes + index * controller_bytes;
      const auto id = bytes[offset];
      const auto type = bytes[offset + 1];
      const auto flags = read_be<std::uint16_t>(bytes, offset + 2);
      const auto buttons = read_be<std::uint64_t>(bytes, offset + 4);
      const auto battery = read_be<std::uint16_t>(bytes, offset + 48);
      const auto battery_state = bytes[offset + 50];
      const auto supported_buttons = read_be<std::uint32_t>(bytes, offset + 52);
      if (id > 15 || (index != 0 && id <= previous_controller) || type < 1 || type > 5 ||
          (flags & ~std::uint16_t {0x01ff}) != 0 || (buttons & ~std::uint64_t {0x003fffff}) != 0 ||
          (battery != 0xffff && battery > 10'000) || battery_state > 5 || bytes[offset + 51] != 0 ||
          (supported_buttons & ~std::uint32_t {0x003fffff}) != 0) {
        return Error::invalid_controller;
      }
      if (expected_format == Format::two && !zero_range(bytes, offset + 56, offset + 64)) {
        return Error::reserved_not_zero;
      }
      previous_controller = id;
      controller_mask |= std::uint32_t {1} << id;
    }
    if (controller_mask != read_be<std::uint32_t>(bytes, 80)) {
      return Error::invalid_controller;
    }

    const auto touch_start = header_bytes + controller_bytes * controller_count;
    std::array<std::uint32_t, 16> touch_ids {};
    for (std::size_t index = 0; index < touch_count; ++index) {
      const auto offset = touch_start + index * 32;
      const auto pointer_id = read_be<std::uint32_t>(bytes, offset);
      const auto rotation = std::bit_cast<std::int16_t>(read_be<std::uint16_t>(bytes, offset + 20));
      if (bytes[offset + 4] < 1 || bytes[offset + 4] > 3 || (bytes[offset + 5] & ~std::uint8_t {1}) != 0 || rotation < -18'000 || rotation > 18'000) {
        return Error::invalid_touch;
      }
      if (std::find(touch_ids.begin(), touch_ids.begin() + static_cast<std::ptrdiff_t>(index), pointer_id) != touch_ids.begin() + static_cast<std::ptrdiff_t>(index)) {
        return Error::invalid_touch;
      }
      touch_ids[index] = pointer_id;
      if (!zero_range(bytes, offset + 22, offset + 24) || !zero_range(bytes, offset + 28, offset + 32)) {
        return Error::reserved_not_zero;
      }
    }

    const auto pen_start = touch_start + std::size_t {32} * touch_count;
    std::array<std::uint32_t, 4> pen_ids {};
    for (std::size_t index = 0; index < pen_count; ++index) {
      const auto offset = pen_start + index * 40;
      const auto pointer_id = read_be<std::uint32_t>(bytes, offset);
      const auto tilt_x = std::bit_cast<std::int16_t>(read_be<std::uint16_t>(bytes, offset + 20));
      const auto tilt_y = std::bit_cast<std::int16_t>(read_be<std::uint16_t>(bytes, offset + 22));
      const auto rotation = std::bit_cast<std::int16_t>(read_be<std::uint16_t>(bytes, offset + 24));
      if (bytes[offset + 4] < 1 || bytes[offset + 4] > 2 || (bytes[offset + 5] & ~std::uint8_t {7}) != 0 ||
          (read_be<std::uint16_t>(bytes, offset + 6) & ~std::uint16_t {1}) != 0 || tilt_x < -9'000 || tilt_x > 9'000 ||
          tilt_y < -9'000 || tilt_y > 9'000 || rotation < -18'000 || rotation > 18'000) {
        return Error::invalid_pen;
      }
      if (std::find(pen_ids.begin(), pen_ids.begin() + static_cast<std::ptrdiff_t>(index), pointer_id) != pen_ids.begin() + static_cast<std::ptrdiff_t>(index)) {
        return Error::invalid_pen;
      }
      pen_ids[index] = pointer_id;
      if (!zero_range(bytes, offset + 26, offset + 28) || !zero_range(bytes, offset + 32, offset + 40)) {
        return Error::reserved_not_zero;
      }
    }
    return std::nullopt;
  }
}  // namespace lumen::protocol_common::input_state
