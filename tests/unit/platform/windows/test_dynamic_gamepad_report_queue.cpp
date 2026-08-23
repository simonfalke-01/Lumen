/**
 * @file tests/unit/platform/windows/test_dynamic_gamepad_report_queue.cpp
 * @brief Test bounded driver-side dynamic-gamepad report queues.
 */

// standard includes
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

// local includes
#include <src/platform/windows/virtual_hid_driver/DynamicReportQueue.h>

// third-party includes
#include <gtest/gtest.h>

namespace {
  /**
   * @brief Make one unique single-byte report.
   *
   * @param value Report byte.
   * @return Complete queued-report payload.
   */
  std::array<std::uint8_t, 1> report_byte(std::uint8_t value) {
    return {value};
  }
}  // namespace

TEST(DynamicGamepadReportQueueTest, InputQueueRejectsInvalidReports) {
  LUMEN_VHID_GAMEPAD_INPUT_QUEUE queue {};
  const std::array<std::uint8_t, LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE + 1U> oversized {};
  const auto valid = report_byte(1);

  EXPECT_FALSE(LumenVhidGamepadInputQueuePush(nullptr, valid.data(), valid.size()));
  EXPECT_FALSE(LumenVhidGamepadInputQueuePush(&queue, nullptr, valid.size()));
  EXPECT_FALSE(LumenVhidGamepadInputQueuePush(&queue, valid.data(), 0));
  EXPECT_FALSE(LumenVhidGamepadInputQueuePush(&queue, oversized.data(), oversized.size()));
  EXPECT_EQ(queue.count, 0U);
}

TEST(DynamicGamepadReportQueueTest, InputQueueRejectsReportsBeyondCapacity) {
  LUMEN_VHID_GAMEPAD_INPUT_QUEUE queue {};

  for (std::size_t index = 0; index < LUMEN_VHID_GAMEPAD_INPUT_QUEUE_CAPACITY; ++index) {
    const auto report = report_byte(static_cast<std::uint8_t>(index));
    ASSERT_TRUE(LumenVhidGamepadInputQueuePush(&queue, report.data(), report.size()));
  }
  const auto overflow = report_byte(0xFF);

  EXPECT_FALSE(LumenVhidGamepadInputQueuePush(&queue, overflow.data(), overflow.size()));
  EXPECT_EQ(queue.count, LUMEN_VHID_GAMEPAD_INPUT_QUEUE_CAPACITY);
}

TEST(DynamicGamepadReportQueueTest, InputQueuePreservesFifoAcrossRingWrap) {
  LUMEN_VHID_GAMEPAD_INPUT_QUEUE queue {};
  LUMEN_VHID_GAMEPAD_QUEUED_REPORT popped {};

  for (std::size_t index = 0; index < LUMEN_VHID_GAMEPAD_INPUT_QUEUE_CAPACITY; ++index) {
    const auto report = report_byte(static_cast<std::uint8_t>(index));
    ASSERT_TRUE(LumenVhidGamepadInputQueuePush(&queue, report.data(), report.size()));
  }
  for (std::size_t index = 0; index < 8U; ++index) {
    ASSERT_TRUE(LumenVhidGamepadInputQueuePop(&queue, &popped));
    ASSERT_EQ(popped.size, 1U);
    EXPECT_EQ(popped.bytes[0], index);
  }
  for (std::size_t index = 0; index < 8U; ++index) {
    const auto report = report_byte(static_cast<std::uint8_t>(0x80U + index));
    ASSERT_TRUE(LumenVhidGamepadInputQueuePush(&queue, report.data(), report.size()));
  }

  for (std::size_t index = 8U; index < LUMEN_VHID_GAMEPAD_INPUT_QUEUE_CAPACITY; ++index) {
    ASSERT_TRUE(LumenVhidGamepadInputQueuePop(&queue, &popped));
    EXPECT_EQ(popped.bytes[0], index);
  }
  for (std::size_t index = 0; index < 8U; ++index) {
    ASSERT_TRUE(LumenVhidGamepadInputQueuePop(&queue, &popped));
    EXPECT_EQ(popped.bytes[0], 0x80U + index);
  }
  EXPECT_EQ(queue.count, 0U);
}

TEST(DynamicGamepadReportQueueTest, InputQueueRecoverySlotRestoresFailedFrontReport) {
  LUMEN_VHID_GAMEPAD_INPUT_QUEUE queue {};
  LUMEN_VHID_GAMEPAD_QUEUED_REPORT failed {};
  const auto first = report_byte(0x40);

  ASSERT_TRUE(LumenVhidGamepadInputQueuePush(&queue, first.data(), first.size()));
  ASSERT_TRUE(LumenVhidGamepadInputQueuePop(&queue, &failed));
  for (std::size_t index = 0; index < LUMEN_VHID_GAMEPAD_INPUT_QUEUE_CAPACITY; ++index) {
    const auto report = report_byte(static_cast<std::uint8_t>(index));
    ASSERT_TRUE(LumenVhidGamepadInputQueuePush(&queue, report.data(), report.size()));
  }

  ASSERT_TRUE(LumenVhidGamepadInputQueuePushFront(&queue, &failed));
  EXPECT_EQ(queue.count, LUMEN_VHID_GAMEPAD_INPUT_QUEUE_STORAGE_CAPACITY);
  const auto overflow = report_byte(0xFF);
  EXPECT_FALSE(LumenVhidGamepadInputQueuePush(&queue, overflow.data(), overflow.size()));

  LUMEN_VHID_GAMEPAD_QUEUED_REPORT recovered {};
  ASSERT_TRUE(LumenVhidGamepadInputQueuePop(&queue, &recovered));
  EXPECT_EQ(recovered.size, 1U);
  EXPECT_EQ(recovered.bytes[0], 0x40);
}

TEST(DynamicGamepadReportQueueTest, OutputQueueDropsOldestAndKeepsLatestWhenFull) {
  LUMEN_VHID_GAMEPAD_OUTPUT_QUEUE queue {};

  for (std::size_t index = 0; index < LUMEN_VHID_GAMEPAD_OUTPUT_QUEUE_CAPACITY; ++index) {
    const auto report = report_byte(static_cast<std::uint8_t>(index));
    ASSERT_TRUE(LumenVhidGamepadOutputQueuePushLatest(&queue, report.data(), report.size()));
  }
  const auto latest = report_byte(0xFF);
  ASSERT_TRUE(LumenVhidGamepadOutputQueuePushLatest(&queue, latest.data(), latest.size()));

  LUMEN_VHID_GAMEPAD_QUEUED_REPORT popped {};
  ASSERT_TRUE(LumenVhidGamepadOutputQueuePop(&queue, &popped));
  EXPECT_EQ(popped.bytes[0], 1U);
  while (queue.count > 1U) {
    ASSERT_TRUE(LumenVhidGamepadOutputQueuePop(&queue, &popped));
  }
  ASSERT_TRUE(LumenVhidGamepadOutputQueuePop(&queue, &popped));
  EXPECT_EQ(popped.bytes[0], 0xFF);
}

TEST(DynamicGamepadReportQueueTest, OrderedOutputOverflowInsertsResetBeforeCurrentReport) {
  LUMEN_VHID_GAMEPAD_OUTPUT_QUEUE queue {};
  for (std::size_t index = 0; index < LUMEN_VHID_GAMEPAD_OUTPUT_QUEUE_CAPACITY; ++index) {
    const auto report = report_byte(static_cast<std::uint8_t>(index));
    ASSERT_TRUE(LumenVhidGamepadOutputQueuePushLatest(&queue, report.data(), report.size()));
  }
  const std::array<std::uint8_t, 2> reset {0x1C, 0x03};
  const std::array<std::uint8_t, 2> current {0x1A, 0x01};

  EXPECT_EQ(
    LumenVhidGamepadOutputQueuePushWithResetOnOverflow(
      &queue,
      reset.data(),
      reset.size(),
      current.data(),
      current.size()
    ),
    2
  );
  ASSERT_EQ(queue.count, 2U);
  LUMEN_VHID_GAMEPAD_QUEUED_REPORT popped {};
  ASSERT_TRUE(LumenVhidGamepadOutputQueuePop(&queue, &popped));
  EXPECT_EQ(popped.size, reset.size());
  EXPECT_TRUE(std::equal(reset.begin(), reset.end(), popped.bytes));
  ASSERT_TRUE(LumenVhidGamepadOutputQueuePop(&queue, &popped));
  EXPECT_EQ(popped.size, current.size());
  EXPECT_TRUE(std::equal(current.begin(), current.end(), popped.bytes));
}

TEST(DynamicGamepadReportQueueTest, OrderedOutputOverflowRejectsInvalidResetOrCurrentReport) {
  LUMEN_VHID_GAMEPAD_OUTPUT_QUEUE queue {};
  const auto report = report_byte(1);

  EXPECT_FALSE(LumenVhidGamepadOutputQueuePushWithResetOnOverflow(
    nullptr,
    report.data(),
    report.size(),
    report.data(),
    report.size()
  ));
  EXPECT_FALSE(LumenVhidGamepadOutputQueuePushWithResetOnOverflow(
    &queue,
    nullptr,
    report.size(),
    report.data(),
    report.size()
  ));
  EXPECT_FALSE(LumenVhidGamepadOutputQueuePushWithResetOnOverflow(
    &queue,
    report.data(),
    report.size(),
    nullptr,
    report.size()
  ));
}

TEST(DynamicGamepadReportQueueTest, OutputQueueRejectsInvalidReports) {
  LUMEN_VHID_GAMEPAD_OUTPUT_QUEUE queue {};
  const std::array<std::uint8_t, LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE + 1U> oversized {};
  const auto valid = report_byte(1);

  EXPECT_FALSE(LumenVhidGamepadOutputQueuePushLatest(nullptr, valid.data(), valid.size()));
  EXPECT_FALSE(LumenVhidGamepadOutputQueuePushLatest(&queue, nullptr, valid.size()));
  EXPECT_FALSE(LumenVhidGamepadOutputQueuePushLatest(&queue, valid.data(), 0));
  EXPECT_FALSE(LumenVhidGamepadOutputQueuePushLatest(&queue, oversized.data(), oversized.size()));
  EXPECT_EQ(queue.count, 0U);
}

TEST(DynamicGamepadReportQueueTest, ClearRemovesAllPendingReports) {
  LUMEN_VHID_GAMEPAD_INPUT_QUEUE input {};
  LUMEN_VHID_GAMEPAD_OUTPUT_QUEUE output {};
  const auto report = report_byte(1);
  ASSERT_TRUE(LumenVhidGamepadInputQueuePush(&input, report.data(), report.size()));
  ASSERT_TRUE(LumenVhidGamepadOutputQueuePushLatest(&output, report.data(), report.size()));

  LumenVhidGamepadInputQueueClear(&input);
  LumenVhidGamepadOutputQueueClear(&output);

  EXPECT_EQ(input.head, 0U);
  EXPECT_EQ(input.count, 0U);
  EXPECT_EQ(output.head, 0U);
  EXPECT_EQ(output.count, 0U);
}
