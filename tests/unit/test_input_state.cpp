/**
 * @file tests/unit/test_input_state.cpp
 * @brief Unit tests for cross-session input ownership and controller lifecycle helpers.
 */

// standard includes
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <limits>
#include <mutex>
#include <set>
#include <vector>

extern "C" {
#include <moonlight-common-c/src/Input.h>
}

// lib includes
#include <gtest/gtest.h>

// local includes
#include "src/config.h"
#include "src/input.h"
#include "src/input_state.h"

namespace {
  template<class Packet>
  std::vector<std::uint8_t> packet_bytes(const Packet &packet) {
    const auto *begin = reinterpret_cast<const std::uint8_t *>(&packet);
    return {begin, begin + sizeof(Packet)};
  }

  struct FeedbackBlocker {
    std::mutex mutex;  ///< Synchronizes callback lifetime observations.
    std::condition_variable changed;  ///< Wakes the test and callback.
    std::size_t calls {};  ///< Number of callbacks that entered.
    bool release {};  ///< Whether the in-flight callback may return.
  };

  void blocking_feedback_callback(
    void *context,
    const input::lsp_controller_feedback_t &
  ) noexcept {
    auto &blocker = *static_cast<FeedbackBlocker *>(context);
    std::unique_lock lock(blocker.mutex);
    ++blocker.calls;
    blocker.changed.notify_all();
    blocker.changed.wait(lock, [&]() {
      return blocker.release;
    });
  }
}  // namespace

TEST(InputLspPointerBounds, RejectsInt64AmplificationBeforeAnyChunkLoop) {
  EXPECT_TRUE(input::valid_lsp_pointer_differences(input::maximum_lsp_pointer_delta, -input::maximum_lsp_pointer_delta, input::maximum_lsp_scroll_delta, -input::maximum_lsp_scroll_delta));
  EXPECT_FALSE(input::valid_lsp_pointer_differences(std::numeric_limits<std::int64_t>::max(), 0, 0, 0));
  EXPECT_FALSE(input::valid_lsp_pointer_differences(0, std::numeric_limits<std::int64_t>::min(), 0, 0));
}

TEST(InputLspKeyboardMapping, CoversPunctuationKeypadExtendedFunctionsAndModifiers) {
  EXPECT_EQ(input::virtual_key_from_hid_usage(4), static_cast<std::uint16_t>('A'));
  EXPECT_EQ(input::virtual_key_from_hid_usage(45), 0xbdU);
  EXPECT_EQ(input::virtual_key_from_hid_usage(56), 0xbfU);
  EXPECT_EQ(input::virtual_key_from_hid_usage(84), 0x6fU);
  EXPECT_EQ(input::virtual_key_from_hid_usage(98), 0x60U);
  EXPECT_EQ(input::virtual_key_from_hid_usage(104), 0x7cU);
  EXPECT_EQ(input::virtual_key_from_hid_usage(115), 0x87U);
  EXPECT_EQ(input::virtual_key_from_hid_usage(224), 0xa2U);
  EXPECT_EQ(input::virtual_key_from_hid_usage(231), 0x5cU);
  EXPECT_EQ(input::virtual_key_from_hid_usage(0), 0U);
}

TEST(InputLspPlatformFeedback, ExplicitStopJoinsAnInFlightCallbackBeforeOwnerReset) {
  using namespace std::chrono_literals;
  FeedbackBlocker blocker;
  auto input = input::alloc_lsp_platform_input(blocking_feedback_callback, &blocker);
  ASSERT_TRUE(input);
  ASSERT_TRUE(input::detail::raise_lsp_platform_feedback_for_test(*input, platf::gamepad_feedback_msg_t::make_rumble({0, 1, 1}, 1, 2)));
  {
    std::unique_lock lock(blocker.mutex);
    ASSERT_TRUE(blocker.changed.wait_for(lock, 1s, [&]() {
      return blocker.calls == 1;
    }));
  }
  auto stopping = std::async(std::launch::async, [&]() {
    input::stop_lsp_platform_input_feedback(*input);
  });
  EXPECT_EQ(stopping.wait_for(20ms), std::future_status::timeout);
  {
    std::scoped_lock lock(blocker.mutex);
    blocker.release = true;
  }
  blocker.changed.notify_all();
  EXPECT_EQ(stopping.wait_for(1s), std::future_status::ready);
  EXPECT_FALSE(input::detail::raise_lsp_platform_feedback_for_test(*input, platf::gamepad_feedback_msg_t::make_rumble({0, 1, 1}, 3, 4)));
  input.reset();
  EXPECT_EQ(blocker.calls, 1U);
}

TEST(InputHeldState, ResetOneSessionDoesNotReleaseAnotherSessionsKeyOrButton) {
  input::detail::held_state_counts_t<std::uint32_t> keys;
  input::detail::held_state_counts_t<int> buttons;
  constexpr std::uint32_t key = 0x4100;
  constexpr int button = 1;

  EXPECT_TRUE(keys.acquire(key));
  EXPECT_FALSE(keys.acquire(key));
  EXPECT_TRUE(buttons.acquire(button));
  EXPECT_FALSE(buttons.acquire(button));

  // Session A resets while session B continues holding the same input.
  EXPECT_FALSE(keys.release(key));
  EXPECT_FALSE(buttons.release(button));
  EXPECT_EQ(keys.count(key), 1u);
  EXPECT_EQ(buttons.count(button), 1u);

  // Only session B's later release reaches the platform boundary.
  EXPECT_TRUE(keys.release(key));
  EXPECT_TRUE(buttons.release(button));
  EXPECT_EQ(keys.count(key), 0u);
  EXPECT_EQ(buttons.count(button), 0u);
}

TEST(InputSlotAllocator, ConcurrentReservationsNeverDuplicateSlots) {
  input::detail::synchronized_slot_allocator_t<4> allocator;
  using reservation_t = decltype(allocator)::reservation_t;
  std::mutex reservations_mutex;
  std::vector<reservation_t> reservations;
  std::vector<std::future<void>> workers;
  for (int worker = 0; worker < 32; ++worker) {
    workers.emplace_back(std::async(std::launch::async, [&allocator, &reservations_mutex, &reservations]() {
      const auto reservation = allocator.allocate();
      if (reservation) {
        std::lock_guard lock(reservations_mutex);
        reservations.push_back(reservation);
      }
    }));
  }
  for (auto &worker : workers) {
    worker.get();
  }

  ASSERT_EQ(reservations.size(), 4u);
  std::set<int> unique_ids;
  for (const auto reservation : reservations) {
    EXPECT_TRUE(allocator.owns(reservation));
    unique_ids.insert(reservation.id);
  }
  EXPECT_EQ(unique_ids.size(), reservations.size());
}

TEST(InputSlotAllocator, StaleGenerationCannotClearReconnectedOwner) {
  input::detail::synchronized_slot_allocator_t<1> allocator;
  const auto first = allocator.allocate();
  ASSERT_TRUE(first);
  ASSERT_TRUE(allocator.release(first));

  const auto reconnected = allocator.allocate();
  ASSERT_TRUE(reconnected);
  EXPECT_EQ(reconnected.id, first.id);
  EXPECT_NE(reconnected.generation, first.generation);
  EXPECT_FALSE(allocator.release(first));
  EXPECT_TRUE(allocator.owns(reconnected));
  EXPECT_TRUE(allocator.release(reconnected));
}

TEST(ControllerTimerGeneration, ReconnectInvalidatesOldCallbacksAndReturnsBothTimers) {
  input::detail::controller_timer_generation_t timers;
  const auto first_generation = timers.connect();
  timers.set_timeout(11);
  timers.set_release(12);

  const auto cancellations = timers.disconnect();
  EXPECT_EQ(cancellations.timeout, 11u);
  EXPECT_EQ(cancellations.release, 12u);
  EXPECT_FALSE(timers.is_current(first_generation));

  const auto second_generation = timers.connect();
  EXPECT_NE(second_generation, first_generation);
  EXPECT_TRUE(timers.is_current(second_generation));
  EXPECT_FALSE(timers.is_current(first_generation));

  timers.disconnect();
  const auto third_generation = timers.connect();
  EXPECT_NE(third_generation, second_generation);
  EXPECT_FALSE(timers.is_current(second_generation));
  EXPECT_TRUE(timers.is_current(third_generation));
}

TEST(InputSessionResetGate, SharedTransportResetsOnlyAfterFinalSession) {
  input::detail::input_session_reset_gate_t gate;
  std::atomic<int> resets {0};
  const auto first = gate.register_session();
  const auto second = gate.register_session();
  ASSERT_EQ(gate.active_sessions(), 2u);

  EXPECT_TRUE(gate.unregister_session(first, [&resets]() {
    ++resets;
  }));
  EXPECT_EQ(resets, 0);
  EXPECT_EQ(gate.active_sessions(), 1u);

  EXPECT_TRUE(gate.unregister_session(second, [&resets]() {
    ++resets;
  }));
  EXPECT_EQ(resets, 1);
  EXPECT_EQ(gate.active_sessions(), 0u);
  EXPECT_FALSE(gate.unregister_session(second, [&resets]() {
    ++resets;
  }));
  EXPECT_EQ(resets, 1);
}

TEST(InputCausalWatermark, AdvancesOnlyAfterConsumerCompletionAndCapturesImmutableValue) {
  input::detail::causal_watermark_t watermark;
  ASSERT_TRUE(watermark.reserve(10, 20));
  EXPECT_EQ(watermark.capture(), (input::detail::causal_watermark_value_t {}));

  ASSERT_TRUE(watermark.mark_applied(10, 20));
  const input::detail::causal_watermark_value_t first {10, 20};
  EXPECT_EQ(watermark.capture(), first);

  ASSERT_TRUE(watermark.reserve(11, 21));
  EXPECT_EQ(watermark.capture(), first);
  ASSERT_TRUE(watermark.mark_captured(7, first));
  EXPECT_EQ(watermark.captured_frame(first), 7U);
  EXPECT_EQ(watermark.captured_frame({11, 21}), 0U);

  ASSERT_TRUE(watermark.mark_applied(11, 21));
  EXPECT_EQ(watermark.capture(), (input::detail::causal_watermark_value_t {11, 21}));
  EXPECT_EQ(first, (input::detail::causal_watermark_value_t {10, 20}));
}

TEST(InputCausalWatermark, RejectsRegressionFutureApplicationAndStaleFrame) {
  input::detail::causal_watermark_t watermark;
  ASSERT_TRUE(watermark.reserve(5, 6));
  EXPECT_FALSE(watermark.reserve(4, 6));
  EXPECT_FALSE(watermark.mark_applied(6, 6));
  ASSERT_TRUE(watermark.mark_applied(5, 6));
  ASSERT_TRUE(watermark.mark_captured(9, {5, 6}));
  EXPECT_FALSE(watermark.mark_captured(9, {5, 6}));
  EXPECT_FALSE(watermark.mark_captured(10, {6, 6}));

  watermark.reset();
  EXPECT_EQ(watermark.capture(), (input::detail::causal_watermark_value_t {}));
  EXPECT_EQ(watermark.queued_edge(), 0U);
  EXPECT_EQ(watermark.captured_frame({1, 1}), 0U);
}

TEST(InputControllerInjection, RejectsEveryAdvancedPacketWhenControllerInputIsDisabled) {
  const auto prior = config::input.controller;
  config::input.controller = false;

  SS_CONTROLLER_ARRIVAL_PACKET arrival {};
  arrival.header.magic = util::endian::little<std::uint32_t>(SS_CONTROLLER_ARRIVAL_MAGIC);
  SS_CONTROLLER_TOUCH_PACKET touch {};
  touch.header.magic = util::endian::little<std::uint32_t>(SS_CONTROLLER_TOUCH_MAGIC);
  SS_CONTROLLER_MOTION_PACKET motion {};
  motion.header.magic = util::endian::little<std::uint32_t>(SS_CONTROLLER_MOTION_MAGIC);
  SS_CONTROLLER_BATTERY_PACKET battery {};
  battery.header.magic = util::endian::little<std::uint32_t>(SS_CONTROLLER_BATTERY_MAGIC);
  NV_MULTI_CONTROLLER_PACKET state {};
  state.header.magic = util::endian::little<std::uint32_t>(MULTI_CONTROLLER_MAGIC_GEN5);

  EXPECT_FALSE(input::detail::passthrough_packet_for_test(nullptr, packet_bytes(arrival)));
  EXPECT_FALSE(input::detail::passthrough_packet_for_test(nullptr, packet_bytes(touch)));
  EXPECT_FALSE(input::detail::passthrough_packet_for_test(nullptr, packet_bytes(motion)));
  EXPECT_FALSE(input::detail::passthrough_packet_for_test(nullptr, packet_bytes(battery)));
  EXPECT_FALSE(input::detail::passthrough_packet_for_test(nullptr, packet_bytes(state)));

  config::input.controller = prior;
}
