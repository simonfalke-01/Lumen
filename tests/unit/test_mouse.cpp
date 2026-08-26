/**
 * @file tests/unit/test_mouse.cpp
 * @brief Test src/input.*.
 */
#include "../tests_common.h"

#include <cstdint>
#include <limits>
#include <src/input.h>

TEST(InputBatchingTest, CheckedAddInt16AcceptsRepresentableSums) {
  std::int16_t result = 0;

  EXPECT_TRUE(input::detail::checked_add_int16(120, 40, result));
  EXPECT_EQ(result, 160);

  EXPECT_TRUE(input::detail::checked_add_int16(-120, -40, result));
  EXPECT_EQ(result, -160);

  EXPECT_TRUE(input::detail::checked_add_int16(std::numeric_limits<std::int16_t>::max(), 0, result));
  EXPECT_EQ(result, std::numeric_limits<std::int16_t>::max());

  EXPECT_TRUE(input::detail::checked_add_int16(std::numeric_limits<std::int16_t>::min(), 0, result));
  EXPECT_EQ(result, std::numeric_limits<std::int16_t>::min());
}

TEST(InputBatchingTest, CheckedAddInt16RejectsOverflow) {
  constexpr std::int16_t sentinel = 42;
  std::int16_t result = sentinel;

  EXPECT_FALSE(input::detail::checked_add_int16(std::numeric_limits<std::int16_t>::max(), 1, result));
  EXPECT_EQ(result, sentinel);

  EXPECT_FALSE(input::detail::checked_add_int16(std::numeric_limits<std::int16_t>::min(), -1, result));
  EXPECT_EQ(result, sentinel);
}

TEST(InputBatchingTest, RelativeMouseBatchesRepresentableSums) {
  std::int16_t dest_x = 100;
  std::int16_t dest_y = -100;

  EXPECT_TRUE(input::detail::batch_relative_mouse_for_test(dest_x, dest_y, 20, -20));
  EXPECT_EQ(dest_x, 120);
  EXPECT_EQ(dest_y, -120);
}

TEST(InputBatchingTest, RelativeMouseRejectsOverflowWithoutMutation) {
  std::int16_t dest_x = std::numeric_limits<std::int16_t>::max();
  std::int16_t dest_y = std::numeric_limits<std::int16_t>::min();

  EXPECT_FALSE(input::detail::batch_relative_mouse_for_test(dest_x, dest_y, 1, -1));
  EXPECT_EQ(dest_x, std::numeric_limits<std::int16_t>::max());
  EXPECT_EQ(dest_y, std::numeric_limits<std::int16_t>::min());
}

TEST(InputBatchingTest, RelativeMouseRejectsVerticalOverflowWithoutPartialMutation) {
  std::int16_t dest_x = 100;
  std::int16_t dest_y = std::numeric_limits<std::int16_t>::min();

  EXPECT_FALSE(input::detail::batch_relative_mouse_for_test(dest_x, dest_y, 20, -1));
  EXPECT_EQ(dest_x, 100);
  EXPECT_EQ(dest_y, std::numeric_limits<std::int16_t>::min());
}

TEST(InputBatchingTest, VerticalScrollBatchesRepresentableSums) {
  std::int16_t dest_primary = 120;
  std::int16_t dest_secondary = 120;

  EXPECT_TRUE(input::detail::batch_vertical_scroll_for_test(dest_primary, dest_secondary, -40));
  EXPECT_EQ(dest_primary, 80);
  EXPECT_EQ(dest_secondary, 80);
}

TEST(InputBatchingTest, VerticalScrollRejectsOverflowWithoutMutation) {
  std::int16_t dest_primary = std::numeric_limits<std::int16_t>::max();
  std::int16_t dest_secondary = std::numeric_limits<std::int16_t>::max();

  EXPECT_FALSE(input::detail::batch_vertical_scroll_for_test(dest_primary, dest_secondary, 1));
  EXPECT_EQ(dest_primary, std::numeric_limits<std::int16_t>::max());
  EXPECT_EQ(dest_secondary, std::numeric_limits<std::int16_t>::max());
}

TEST(InputBatchingTest, HorizontalScrollBatchesRepresentableSums) {
  std::int16_t dest = -80;

  EXPECT_TRUE(input::detail::batch_horizontal_scroll_for_test(dest, -40));
  EXPECT_EQ(dest, -120);
}

TEST(InputBatchingTest, HorizontalScrollRejectsOverflowWithoutMutation) {
  std::int16_t dest = std::numeric_limits<std::int16_t>::min();

  EXPECT_FALSE(input::detail::batch_horizontal_scroll_for_test(dest, -1));
  EXPECT_EQ(dest, std::numeric_limits<std::int16_t>::min());
}

TEST(DelayedLeftStateTest, AbsoluteClickSchedulesAndConsumesOneReleaseTimer) {
  input::detail::delayed_left_state_t state;
  state.on_absolute_move();

  const auto down = state.on_left_down();
  EXPECT_FALSE(down.cancel_timer);
  EXPECT_FALSE(down.emit_left_release);

  const auto up = state.on_left_up();
  EXPECT_TRUE(up.schedule_timer);
  EXPECT_GT(up.generation, 0U);

  const auto timer = state.on_timer(up.generation, false);
  EXPECT_TRUE(timer.consume_timer);
  EXPECT_TRUE(timer.emit_left_release);
  EXPECT_FALSE(state.on_timer(up.generation, false).consume_timer);
}

TEST(DelayedLeftStateTest, NewLeftDownFlushesPendingReleaseBeforePress) {
  input::detail::delayed_left_state_t state;
  state.on_absolute_move();
  const auto pending = state.on_left_up();
  ASSERT_TRUE(pending.schedule_timer);

  const auto down = state.on_left_down();
  EXPECT_TRUE(down.cancel_timer);
  EXPECT_TRUE(down.emit_left_release);
  EXPECT_FALSE(state.on_timer(pending.generation, false).consume_timer);
}

TEST(DelayedLeftStateTest, RightDownIsSynthesizedWhileLeftReleaseRemainsPending) {
  input::detail::delayed_left_state_t state;
  const auto pending = state.on_left_up();
  ASSERT_TRUE(pending.schedule_timer);

  EXPECT_TRUE(state.on_right_down().synthesize_right_click);
  const auto timer = state.on_timer(pending.generation, false);
  EXPECT_TRUE(timer.consume_timer);
  EXPECT_TRUE(timer.emit_left_release);
  EXPECT_FALSE(state.on_right_down().synthesize_right_click);
}

TEST(DelayedLeftStateTest, RelativeMoveCancelsAndFlushesPendingRelease) {
  input::detail::delayed_left_state_t state;
  const auto pending = state.on_left_up();
  ASSERT_TRUE(pending.schedule_timer);

  const auto relative = state.on_relative_move();
  EXPECT_TRUE(relative.cancel_timer);
  EXPECT_TRUE(relative.emit_left_release);
  EXPECT_FALSE(state.on_timer(pending.generation, false).consume_timer);
  EXPECT_FALSE(state.on_left_up().schedule_timer);
  EXPECT_FALSE(state.on_relative_move().cancel_timer);

  state.on_absolute_move();
  EXPECT_TRUE(state.on_left_up().schedule_timer);
}

TEST(DelayedLeftStateTest, ResetInvalidatesAlreadyDequeuedTimerGeneration) {
  input::detail::delayed_left_state_t state;
  const auto dequeued = state.on_left_up();
  ASSERT_TRUE(dequeued.schedule_timer);

  const auto reset = state.on_reset();
  EXPECT_TRUE(reset.cancel_timer);
  EXPECT_TRUE(reset.emit_left_release);
  const auto stale = state.on_timer(dequeued.generation, false);
  EXPECT_FALSE(stale.consume_timer);
  EXPECT_FALSE(stale.emit_left_release);

  const auto next = state.on_left_up();
  EXPECT_TRUE(next.schedule_timer);
  EXPECT_GT(next.generation, dequeued.generation);
  const auto newer_press = state.on_timer(next.generation, true);
  EXPECT_TRUE(newer_press.consume_timer);
  EXPECT_FALSE(newer_press.emit_left_release);
  EXPECT_FALSE(state.on_reset().cancel_timer);
}

struct MouseHIDTest: PlatformTestSuite, testing::WithParamInterface<util::point_t> {
  void SetUp() override {
    BaseTest::SetUp();
#ifdef _WIN32
    // TODO: Windows tests are failing, `get_mouse_loc` seems broken and `platf::abs_mouse` too
    //       the alternative `platf::abs_mouse` method seem to work better during tests,
    //       but I'm not sure about real work
    GTEST_SKIP() << "TODO Windows";
#elif defined(__linux__) || defined(__FreeBSD__)
    // TODO: Inputtino waiting https://github.com/games-on-whales/inputtino/issues/6 is resolved.
    GTEST_SKIP() << "TODO Inputtino";
#endif
  }

  void TearDown() override {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    BaseTest::TearDown();
  }
};

INSTANTIATE_TEST_SUITE_P(
  MouseInputs,
  MouseHIDTest,
  testing::Values(
    util::point_t {40, 40},
    util::point_t {70, 150}
  )
);

// todo: add tests for hitting screen edges

TEST_P(MouseHIDTest, MoveInputTest) {
  util::point_t mouse_delta = GetParam();

  BOOST_LOG(tests) << "MoveInputTest:: got param: " << mouse_delta;
  platf::input_t input = platf::input();
  BOOST_LOG(tests) << "MoveInputTest:: init input";

  BOOST_LOG(tests) << "MoveInputTest:: get current mouse loc";
  auto old_loc = platf::get_mouse_loc(input);
  BOOST_LOG(tests) << "MoveInputTest:: got current mouse loc: " << old_loc;

  BOOST_LOG(tests) << "MoveInputTest:: move: " << mouse_delta;
  platf::move_mouse(input, mouse_delta.x, mouse_delta.y);
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  BOOST_LOG(tests) << "MoveInputTest:: moved: " << mouse_delta;

  BOOST_LOG(tests) << "MoveInputTest:: get updated mouse loc";
  auto new_loc = platf::get_mouse_loc(input);
  BOOST_LOG(tests) << "MoveInputTest:: got updated mouse loc: " << new_loc;

  bool has_input_moved = old_loc.x != new_loc.x && old_loc.y != new_loc.y;

  if (!has_input_moved) {
    BOOST_LOG(tests) << "MoveInputTest:: haven't moved";
  } else {
    BOOST_LOG(tests) << "MoveInputTest:: moved";
  }

  EXPECT_TRUE(has_input_moved);

  // Verify we moved as much as we requested
#ifdef __APPLE__
  // CoreGraphics reports the live cursor in logical points after asynchronous
  // event delivery. Sub-point quantization and concurrent physical cursor
  // updates can make that observation differ slightly from the exact delta
  // carried by the injected event, so retain a tight two-point tolerance.
  constexpr double cursor_observation_tolerance = 2.0;
  EXPECT_NEAR(new_loc.x - old_loc.x, mouse_delta.x, cursor_observation_tolerance);
  EXPECT_NEAR(new_loc.y - old_loc.y, mouse_delta.y, cursor_observation_tolerance);
#else
  EXPECT_EQ(new_loc.x - old_loc.x, mouse_delta.x);
  EXPECT_EQ(new_loc.y - old_loc.y, mouse_delta.y);
#endif
}

TEST_P(MouseHIDTest, AbsMoveInputTest) {
  util::point_t mouse_pos = GetParam();
  BOOST_LOG(tests) << "AbsMoveInputTest:: got param: " << mouse_pos;

  platf::input_t input = platf::input();
  BOOST_LOG(tests) << "AbsMoveInputTest:: init input";

  BOOST_LOG(tests) << "AbsMoveInputTest:: get current mouse loc";
  auto old_loc = platf::get_mouse_loc(input);
  BOOST_LOG(tests) << "AbsMoveInputTest:: got current mouse loc: " << old_loc;

#ifdef _WIN32
  platf::touch_port_t abs_port {
    0,
    0,
    65535,
    65535
  };
#elif defined(__linux__) || defined(__FreeBSD__)
  platf::touch_port_t abs_port {
    0,
    0,
    19200,
    12000
  };
#else
  platf::touch_port_t abs_port {};
#endif
  BOOST_LOG(tests) << "AbsMoveInputTest:: move: " << mouse_pos;
  platf::abs_mouse(input, abs_port, mouse_pos.x, mouse_pos.y);
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  BOOST_LOG(tests) << "AbsMoveInputTest:: moved: " << mouse_pos;

  BOOST_LOG(tests) << "AbsMoveInputTest:: get updated mouse loc";
  auto new_loc = platf::get_mouse_loc(input);
  BOOST_LOG(tests) << "AbsMoveInputTest:: got updated mouse loc: " << new_loc;

  bool has_input_moved = old_loc.x != new_loc.x || old_loc.y != new_loc.y;

  if (!has_input_moved) {
    BOOST_LOG(tests) << "AbsMoveInputTest:: haven't moved";
  } else {
    BOOST_LOG(tests) << "AbsMoveInputTest:: moved";
  }

  EXPECT_TRUE(has_input_moved);

  // Verify we moved to the absolute coordinate
  EXPECT_EQ(new_loc.x, mouse_pos.x);
  EXPECT_EQ(new_loc.y, mouse_pos.y);
}
