/**
 * @file tests/unit/test_protocol_common_input_state.cpp
 * @brief Protocol-v3 input state-format-2/3 validation tests.
 */

#include "src/protocol_common/input_state.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

namespace {
  template<class Integer>
  void write_be(std::vector<std::uint8_t> &bytes, const std::size_t offset, Integer value) {
    for (std::size_t index = 0; index < sizeof(Integer); ++index) {
      bytes[offset + sizeof(Integer) - index - 1] = static_cast<std::uint8_t>(value);
      value >>= 8U;
    }
  }

  std::vector<std::uint8_t> advanced_controller_state() {
    std::vector<std::uint8_t> state(112 + 64 + 32);
    write_be(state, 0, std::uint32_t {6});
    write_be(state, 80, std::uint32_t {1});
    state[84] = 1;
    state[85] = 1;
    const auto controller = std::size_t {112};
    state[controller] = 0;
    state[controller + 1] = 2;
    write_be(state, controller + 2, std::uint16_t {0x0179});
    write_be(state, controller + 4, std::uint64_t {0x104000});
    write_be(state, controller + 48, std::uint16_t {7'500});
    state[controller + 50] = 3;
    write_be(state, controller + 52, std::uint32_t {0x104000});
    const auto touch = controller + 64;
    write_be(state, touch, std::uint32_t {0x01000001});
    state[touch + 4] = 3;
    state[touch + 5] = 1;
    write_be(state, touch + 6, std::uint16_t {0x8000});
    return state;
  }

  std::vector<std::uint8_t> compact_controller_state(
    const std::uint8_t controller_count = 16,
    const std::uint8_t touch_count = 2
  ) {
    constexpr auto controller_bytes = std::size_t {56};
    std::vector<std::uint8_t> state(
      lumen::protocol_common::input_state::header_bytes + controller_bytes * controller_count +
      std::size_t {32} * touch_count
    );
    write_be(state, 0, std::uint32_t {6});
    write_be(state, 80, controller_count == 16 ? std::uint32_t {0xffff} : (std::uint32_t {1} << controller_count) - 1);
    state[84] = controller_count;
    state[85] = touch_count;
    state[87] = 3;
    for (std::size_t index = 0; index < controller_count; ++index) {
      const auto controller = lumen::protocol_common::input_state::header_bytes + index * controller_bytes;
      state[controller] = static_cast<std::uint8_t>(index);
      state[controller + 1] = static_cast<std::uint8_t>(1 + index % 5);
      write_be(state, controller + 2, static_cast<std::uint16_t>(1U << (index % 9)));
      write_be(state, controller + 4, std::uint64_t {1} << (index % 22));
      write_be(state, controller + 48, std::uint16_t {0xffff});
      write_be(state, controller + 52, std::uint32_t {1} << (index % 22));
    }
    const auto touch_base = lumen::protocol_common::input_state::header_bytes +
                            controller_bytes * controller_count;
    for (std::size_t index = 0; index < touch_count; ++index) {
      const auto touch = touch_base + index * 32;
      write_be(state, touch, static_cast<std::uint32_t>(index + 1));
      state[touch + 4] = 1;
    }
    return state;
  }
}  // namespace

TEST(ProtocolCommonInputState, AcceptsAdvancedControllerFormatTwoRecord) {
  const auto state = advanced_controller_state();
  const auto original = state;
  EXPECT_FALSE(lumen::protocol_common::input_state::validate(state));
  EXPECT_FALSE(lumen::protocol_common::input_state::validate(state, lumen::protocol_common::input_state::Format::two));
  EXPECT_EQ(state, original);
}

TEST(ProtocolCommonInputState, AcceptsSixteenHeterogeneousCompactControllersAndTwoTouches) {
  const auto state = compact_controller_state();
  EXPECT_EQ(state.size(), 1'072U);
  EXPECT_EQ(
    lumen::protocol_common::input_state::controller_record_bytes(
      lumen::protocol_common::input_state::Format::three
    ),
    56U
  );
  EXPECT_EQ(
    lumen::protocol_common::input_state::format(state),
    lumen::protocol_common::input_state::Format::three
  );
  EXPECT_FALSE(lumen::protocol_common::input_state::validate(state));
  EXPECT_FALSE(lumen::protocol_common::input_state::validate(state, lumen::protocol_common::input_state::Format::three));
}

TEST(ProtocolCommonInputState, RejectsMarkerAndEnclosingFormatMismatch) {
  auto state = compact_controller_state(1, 0);
  EXPECT_EQ(
    lumen::protocol_common::input_state::validate(
      state,
      lumen::protocol_common::input_state::Format::two
    ),
    lumen::protocol_common::input_state::Error::format_mismatch
  );
  state[87] = 0;
  EXPECT_EQ(
    lumen::protocol_common::input_state::validate(
      state,
      lumen::protocol_common::input_state::Format::three
    ),
    lumen::protocol_common::input_state::Error::format_mismatch
  );
  state[87] = 4;
  EXPECT_EQ(
    lumen::protocol_common::input_state::validate(state),
    lumen::protocol_common::input_state::Error::format_mismatch
  );
}

TEST(ProtocolCommonInputState, RejectsReservedCapabilitiesBatteryAndButtonFields) {
  auto state = advanced_controller_state();
  const auto controller = std::size_t {112};
  write_be(state, controller + 2, std::uint16_t {0x0200});
  EXPECT_EQ(
    lumen::protocol_common::input_state::validate(state),
    lumen::protocol_common::input_state::Error::invalid_controller
  );
  state = advanced_controller_state();
  state[controller + 50] = 6;
  EXPECT_EQ(
    lumen::protocol_common::input_state::validate(state),
    lumen::protocol_common::input_state::Error::invalid_controller
  );
  state = advanced_controller_state();
  write_be(state, controller + 52, std::uint32_t {0x00400000});
  EXPECT_EQ(
    lumen::protocol_common::input_state::validate(state),
    lumen::protocol_common::input_state::Error::invalid_controller
  );
}
