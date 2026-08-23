/**
 * @file tests/unit/platform/windows/test_virtual_hid_report_queue.cpp
 * @brief Test the portable readiness-driven Virtual HID report queue.
 */

#include <gtest/gtest.h>

// local includes
#include <src/platform/windows/virtual_hid_driver/ReportQueue.h>

// standard includes
#include <cstdint>
#include <cstring>
#include <limits>

extern "C" int LumenVhidReportQueueCCompatibilitySmoke(void);

namespace {
  /** Create one relative-mouse report for a queue test. */
  LUMEN_VHID_RELATIVE_MOUSE_REPORT Mouse(
    std::uint8_t buttons,
    std::int16_t x,
    std::int16_t y,
    std::int16_t vertical_wheel = 0,
    std::int16_t horizontal_wheel = 0
  ) {
    return {LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE, buttons, x, y, vertical_wheel, horizontal_wheel};
  }

  /** Pop and decode one relative-mouse report. */
  LUMEN_VHID_RELATIVE_MOUSE_REPORT PopMouse(LUMEN_VHID_REPORT_QUEUE &queue) {
    LUMEN_VHID_QUEUED_REPORT queued {};
    LUMEN_VHID_RELATIVE_MOUSE_REPORT report {};

    EXPECT_TRUE(LumenVhidReportQueuePop(&queue, &queued));
    EXPECT_EQ(queued.size, sizeof(report));
    std::memcpy(&report, queued.bytes, sizeof(report));
    return report;
  }

  /** Pop and decode one absolute-mouse report. */
  LUMEN_VHID_ABSOLUTE_MOUSE_REPORT PopAbsoluteMouse(LUMEN_VHID_REPORT_QUEUE &queue) {
    LUMEN_VHID_QUEUED_REPORT queued {};
    LUMEN_VHID_ABSOLUTE_MOUSE_REPORT report {};

    EXPECT_TRUE(LumenVhidReportQueuePop(&queue, &queued));
    EXPECT_EQ(queued.size, sizeof(report));
    std::memcpy(&report, queued.bytes, sizeof(report));
    return report;
  }
}  // namespace

TEST(VirtualHidReportQueueTest, RunsStrictCCompatibilitySmoke) {
  EXPECT_EQ(LumenVhidReportQueueCCompatibilitySmoke(), 0);
}

TEST(VirtualHidReportQueueTest, RejectsInvalidOperationsWithoutMutation) {
  LUMEN_VHID_REPORT_QUEUE queue {};
  LUMEN_VHID_QUEUED_REPORT output {};
  const auto mouse = Mouse(0u, 1, 2);

  LumenVhidReportQueueClear(nullptr);
  EXPECT_FALSE(LumenVhidReportQueueAppend(nullptr, &mouse, sizeof(mouse)));
  EXPECT_FALSE(LumenVhidReportQueueAppend(&queue, nullptr, sizeof(mouse)));
  EXPECT_FALSE(LumenVhidReportQueueAppend(&queue, &mouse, 0u));
  EXPECT_FALSE(LumenVhidReportQueuePop(nullptr, &output));
  EXPECT_FALSE(LumenVhidReportQueuePop(&queue, nullptr));
  EXPECT_FALSE(LumenVhidReportQueuePop(&queue, &output));
  EXPECT_FALSE(LumenVhidReportQueuePushFront(nullptr, &output));
  EXPECT_EQ(queue.count, 0u);
}

TEST(VirtualHidReportQueueTest, CoalescesAdjacentRelativeMotionWithIdenticalButtons) {
  LUMEN_VHID_REPORT_QUEUE queue {};
  const auto first = Mouse(1u, 10, -20, 3, -4);
  const auto second = Mouse(1u, -5, 7, 8, 9);

  ASSERT_TRUE(LumenVhidReportQueuePush(&queue, LUMEN_VHID_REPORT_KIND_RELATIVE_MOUSE, &first, sizeof(first)));
  ASSERT_TRUE(LumenVhidReportQueuePush(&queue, LUMEN_VHID_REPORT_KIND_RELATIVE_MOUSE, &second, sizeof(second)));
  ASSERT_EQ(queue.count, 1u);
  const auto combined = PopMouse(queue);
  EXPECT_EQ(combined.buttons, 1u);
  EXPECT_EQ(combined.x, 5);
  EXPECT_EQ(combined.y, -13);
  EXPECT_EQ(combined.vertical_wheel, 11);
  EXPECT_EQ(combined.horizontal_wheel, 5);
}

TEST(VirtualHidReportQueueTest, PreservesButtonAndReportIdTransitions) {
  LUMEN_VHID_REPORT_QUEUE queue {};
  const auto released = Mouse(0u, 0, 0);
  const auto pressed = Mouse(1u, 0, 0);
  LUMEN_VHID_KEYBOARD_REPORT keyboard {};
  keyboard.report_id = LUMEN_VHID_REPORT_ID_KEYBOARD;

  ASSERT_TRUE(LumenVhidReportQueuePush(&queue, LUMEN_VHID_REPORT_KIND_RELATIVE_MOUSE, &released, sizeof(released)));
  ASSERT_TRUE(LumenVhidReportQueuePush(&queue, LUMEN_VHID_REPORT_KIND_RELATIVE_MOUSE, &pressed, sizeof(pressed)));
  ASSERT_TRUE(LumenVhidReportQueuePush(&queue, LUMEN_VHID_REPORT_KIND_KEYBOARD, &keyboard, sizeof(keyboard)));
  ASSERT_TRUE(LumenVhidReportQueuePush(&queue, LUMEN_VHID_REPORT_KIND_RELATIVE_MOUSE, &released, sizeof(released)));
  ASSERT_EQ(queue.count, 4u);
  EXPECT_EQ(PopMouse(queue).buttons, 0u);
  EXPECT_EQ(PopMouse(queue).buttons, 1u);
  LUMEN_VHID_QUEUED_REPORT queued {};
  ASSERT_TRUE(LumenVhidReportQueuePop(&queue, &queued));
  EXPECT_EQ(queued.bytes[0], LUMEN_VHID_REPORT_ID_KEYBOARD);
  EXPECT_EQ(PopMouse(queue).buttons, 0u);
}

TEST(VirtualHidReportQueueTest, SegmentsRelativeOverflowWithoutLosingDeltas) {
  LUMEN_VHID_REPORT_QUEUE queue {};
  const auto first = Mouse(
    2u,
    std::numeric_limits<std::int16_t>::max(),
    std::numeric_limits<std::int16_t>::min(),
    std::numeric_limits<std::int16_t>::max(),
    std::numeric_limits<std::int16_t>::min()
  );
  const auto second = Mouse(2u, 100, -100, 1, -1);

  ASSERT_TRUE(LumenVhidReportQueuePush(&queue, LUMEN_VHID_REPORT_KIND_RELATIVE_MOUSE, &first, sizeof(first)));
  ASSERT_TRUE(LumenVhidReportQueuePush(&queue, LUMEN_VHID_REPORT_KIND_RELATIVE_MOUSE, &second, sizeof(second)));
  ASSERT_EQ(queue.count, 2u);
  const auto segment = PopMouse(queue);
  const auto remainder = PopMouse(queue);
  EXPECT_EQ(static_cast<std::int32_t>(segment.x) + remainder.x, 32867);
  EXPECT_EQ(static_cast<std::int32_t>(segment.y) + remainder.y, -32868);
  EXPECT_EQ(static_cast<std::int32_t>(segment.vertical_wheel) + remainder.vertical_wheel, 32768);
  EXPECT_EQ(static_cast<std::int32_t>(segment.horizontal_wheel) + remainder.horizontal_wheel, -32769);
}

TEST(VirtualHidReportQueueTest, CoalescesAbsolutePositionAndSegmentsRelativeWheels) {
  LUMEN_VHID_REPORT_QUEUE queue {};
  const LUMEN_VHID_ABSOLUTE_MOUSE_REPORT first {
    LUMEN_VHID_REPORT_ID_MOUSE_ABSOLUTE,
    4u,
    100u,
    200u,
    std::numeric_limits<std::int16_t>::max(),
    std::numeric_limits<std::int16_t>::min(),
  };
  const LUMEN_VHID_ABSOLUTE_MOUSE_REPORT second {
    LUMEN_VHID_REPORT_ID_MOUSE_ABSOLUTE,
    4u,
    50000u,
    60000u,
    20,
    -30,
  };

  ASSERT_TRUE(LumenVhidReportQueuePush(&queue, LUMEN_VHID_REPORT_KIND_ABSOLUTE_MOUSE, &first, sizeof(first)));
  ASSERT_TRUE(LumenVhidReportQueuePush(&queue, LUMEN_VHID_REPORT_KIND_ABSOLUTE_MOUSE, &second, sizeof(second)));
  ASSERT_EQ(queue.count, 2u);
  const auto segment = PopAbsoluteMouse(queue);
  const auto remainder = PopAbsoluteMouse(queue);
  EXPECT_EQ(segment.x, second.x);
  EXPECT_EQ(segment.y, second.y);
  EXPECT_EQ(remainder.x, second.x);
  EXPECT_EQ(remainder.y, second.y);
  EXPECT_EQ(static_cast<std::int32_t>(segment.vertical_wheel) + remainder.vertical_wheel, 32787);
  EXPECT_EQ(static_cast<std::int32_t>(segment.horizontal_wheel) + remainder.horizontal_wheel, -32798);

  const LUMEN_VHID_ABSOLUTE_MOUSE_REPORT released {
    LUMEN_VHID_REPORT_ID_MOUSE_ABSOLUTE,
    0u,
    1u,
    2u,
    0,
    0,
  };
  ASSERT_TRUE(LumenVhidReportQueuePush(&queue, LUMEN_VHID_REPORT_KIND_ABSOLUTE_MOUSE, &second, sizeof(second)));
  ASSERT_TRUE(LumenVhidReportQueuePush(&queue, LUMEN_VHID_REPORT_KIND_ABSOLUTE_MOUSE, &released, sizeof(released)));
  ASSERT_EQ(queue.count, 2u);
  EXPECT_EQ(PopAbsoluteMouse(queue).buttons, 4u);
  EXPECT_EQ(PopAbsoluteMouse(queue).buttons, 0u);
}

TEST(VirtualHidReportQueueTest, RejectsOverflowAndReservesFailedSubmissionRecovery) {
  LUMEN_VHID_REPORT_QUEUE queue {};
  LUMEN_VHID_QUEUED_REPORT recovered {};

  for (std::size_t index = 0; index < LUMEN_VHID_REPORT_QUEUE_CAPACITY; ++index) {
    const auto report = Mouse(static_cast<std::uint8_t>(index & 1u), static_cast<std::int16_t>(index), 0);
    ASSERT_TRUE(LumenVhidReportQueuePush(&queue, LUMEN_VHID_REPORT_KIND_RELATIVE_MOUSE, &report, sizeof(report)));
  }
  const auto overflow = Mouse(4u, 1, 1);
  EXPECT_FALSE(LumenVhidReportQueuePush(&queue, LUMEN_VHID_REPORT_KIND_RELATIVE_MOUSE, &overflow, sizeof(overflow)));
  ASSERT_EQ(queue.count, LUMEN_VHID_REPORT_QUEUE_CAPACITY);

  recovered.size = sizeof(overflow);
  std::memcpy(recovered.bytes, &overflow, sizeof(overflow));
  ASSERT_TRUE(LumenVhidReportQueuePushFront(&queue, &recovered));
  EXPECT_EQ(queue.count, LUMEN_VHID_REPORT_QUEUE_STORAGE_CAPACITY);
  EXPECT_FALSE(LumenVhidReportQueuePushFront(&queue, &recovered));
  ASSERT_TRUE(LumenVhidReportQueuePop(&queue, &recovered));
  EXPECT_EQ(recovered.bytes[0], LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE);
  EXPECT_EQ(queue.count, LUMEN_VHID_REPORT_QUEUE_CAPACITY);
}
