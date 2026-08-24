/**
 * @file tests/unit/test_protocol_common_input_state.cpp
 * @brief Protocol-v3 input state-format-2 validation tests.
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
}  // namespace

TEST(ProtocolCommonInputState, AcceptsAdvancedControllerFormatTwoRecord) {
  EXPECT_FALSE(lumen::protocol_common::input_state::validate(advanced_controller_state()));
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
