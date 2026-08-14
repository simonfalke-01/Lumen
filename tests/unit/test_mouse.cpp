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
  EXPECT_EQ(new_loc.x - old_loc.x, mouse_delta.x);
  EXPECT_EQ(new_loc.y - old_loc.y, mouse_delta.y);
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
