/**
 * @file tests/unit/platform/windows/test_virtual_display.cpp
 * @brief Pure production-policy and ABI tests for Lumen virtual display code.
 */

// standard includes
#include <array>
#include <algorithm>
#include <atomic>
#include <barrier>
#include <deque>
#include <functional>
#include <string>
#include <thread>

// lib includes
#include <gtest/gtest.h>

// local includes
#include "src/platform/windows/virtual_display.h"
#include "src/platform/windows/virtual_display_driver/LumenEdidModePolicy.h"
#include "src/platform/windows/virtual_display_driver/LumenDirectFrameSlotPolicy.h"
#include "src/platform/windows/virtual_display_driver/LumenSingleDeleteOwner.h"
#include "src/platform/windows/virtual_display_driver/LumenVirtualDisplayProtocol.h"
#include "src/platform/windows/virtual_display_frame.h"

namespace {
  using namespace platf::virtual_display;
  using vdd_mode_t = platf::virtual_display::mode_t;

  constexpr vdd_mode_t mode_4k120 {
    3840,
    2160,
    {120, 1},
    dynamic_range_e::sdr,
    8,
  };

  /** @brief Return limits representing a fully capable production preflight. */
  mode_limits_t capable_limits() {
    mode_limits_t limits;
    limits.supports_hdr10 = true;
    limits.supports_10bit = true;
    limits.supports_visually_lossless = true;
    return limits;
  }

  /** @brief Count exact destruction calls in the production single-owner utility. */
  struct counted_delete_t {
    void operator()(std::atomic<unsigned int> *counter) const noexcept {
      counter->fetch_add(1, std::memory_order_relaxed);
    }
  };

  /** Deterministic concrete control channel for production coordinator transitions. */
  class recording_channel_t final: public control_channel_t {
  public:
    channel_result_t open() override {
      ++open_calls;
      return {open_ok, 0};
    }
    channel_result_t query_limits(mode_limits_t &limits) override {
      limits = capable_limits();
      return {limits_ok, 0};
    }
    channel_result_t query_state(driver_state_t &output) override {
      output = state;
      return {state_ok, 0};
    }
    channel_result_t recover_stale(std::uint64_t) override {
      return {recover_ok, 0};
    }
    channel_result_t prepare_mode(
      std::uint64_t generation,
      const vdd_mode_t &mode,
      delivery_policy_e,
      fidelity_e fidelity,
      prepared_mode_t &prepared
    ) override {
      generations.push_back(generation);
      prepared = {mode, "LUM0001", fidelity};
      return {prepare_ok, 0};
    }
    channel_result_t start_monitor(std::uint64_t) override {
      return {start_ok, 0};
    }
    channel_result_t stop_monitor(std::uint64_t) override {
      ++stop_calls;
      if (stop_results.empty()) {
        return {};
      }
      const bool result = stop_results.front();
      stop_results.pop_front();
      return {result, 0};
    }
    void close() noexcept override {
      ++close_calls;
    }

    driver_state_t state;
    std::deque<bool> stop_results;
    std::vector<std::uint64_t> generations;
    unsigned open_calls {};
    unsigned stop_calls {};
    unsigned close_calls {};
    bool open_ok {true};
    bool limits_ok {true};
    bool state_ok {true};
    bool recover_ok {true};
    bool prepare_ok {true};
    bool start_ok {true};
  };

  /** Deterministic DisplayConfig transaction used by the production coordinator. */
  class recording_display_t final: public display_config_t {
  public:
    bool snapshot(display_snapshot_t &snapshot) override {
      snapshot.paths.assign(1, std::byte {1});
      return snapshot_ok;
    }
    bool commit(const std::string &, const vdd_mode_t &mode, display_commit_t &applied) override {
      applied = {mode, "\\\\.\\DISPLAY77"};
      return commit_ok;
    }
    bool await_stable(const std::string &, const vdd_mode_t &, std::chrono::milliseconds) override {
      return stable_ok;
    }
    bool restore(const display_snapshot_t &) noexcept override {
      ++restore_calls;
      if (restore_results.empty()) {
        return true;
      }
      const bool result = restore_results.front();
      restore_results.pop_front();
      return result;
    }

    std::deque<bool> restore_results;
    unsigned restore_calls {};
    bool snapshot_ok {true};
    bool commit_ok {true};
    bool stable_ok {true};
  };

  /** Concrete lease backend with controlled real stop outcomes. */
  class lease_backend_t final: public activation_backend_t {
  public:
    start_result_t start(const stream_request_t &request, const mode_limits_t &) override {
      ++start_calls;
      if (start_error != start_error_e::none) {
        return {start_error, validation_error_e::none, std::nullopt};
      }
      return {
        start_error_e::none,
        validation_error_e::none,
        stream_selection_t {
          request.session_id,
          start_calls.load(),
          request.mode,
          request.mode,
          "\\\\.\\DISPLAY77",
          request.delivery_policy,
          request.minimum_fidelity,
          false,
        },
      };
    }
    bool stop(std::uint64_t) noexcept override {
      ++stop_calls;
      auto failures = stop_failures.load();
      while (failures != 0) {
        if (stop_failures.compare_exchange_weak(failures, failures - 1)) {
          return false;
        }
      }
      return true;
    }

    std::atomic<std::uint64_t> start_calls {};
    std::atomic<unsigned> stop_calls {};
    std::atomic<unsigned> stop_failures {};
    start_error_e start_error {start_error_e::none};
  };
}  // namespace

TEST(VirtualDisplayRational, ReducesAndRejectsHostileComponents) {
  EXPECT_EQ((rational_t {60000, 1001}.normalized()), (rational_t {60000, 1001}));
  EXPECT_EQ((rational_t {120, 2}.normalized()), (rational_t {60, 1}));
  EXPECT_FALSE((rational_t {0, 1}.normalized()));
  EXPECT_FALSE((rational_t {1, 0}.normalized()));
  EXPECT_FALSE((rational_t {LUMEN_VDD_MAX_RATIONAL_COMPONENT + 1U, 1}.normalized()));
}

TEST(VirtualDisplayDeviceBinding, RequiresExactlyOneMatchingTarget) {
  const std::array<std::uint8_t, 3> none {0, 0, 0};
  const std::array<std::uint8_t, 3> one {0, 1, 0};
  const std::array<std::uint8_t, 3> duplicate {1, 0, 1};
  EXPECT_FALSE(unique_matching_index(none));
  ASSERT_TRUE(unique_matching_index(one));
  EXPECT_EQ(*unique_matching_index(one), 1U);
  EXPECT_FALSE(unique_matching_index(duplicate));
}

TEST(VirtualDisplayValidation, AcceptsExactPracticalEvenRationalMode) {
  auto mode = mode_4k120;
  mode.refresh = {60000, 1001};
  EXPECT_EQ(validate_mode(mode, capable_limits()), validation_error_e::none);
}

TEST(VirtualDisplayValidation, RejectsEveryUnsupportedExactModeBoundary) {
  auto mode = mode_4k120;
  mode.width = 3839;
  EXPECT_EQ(validate_mode(mode, capable_limits()), validation_error_e::odd_dimensions);

  mode = mode_4k120;
  mode.refresh = {120, 2};
  EXPECT_EQ(validate_mode(mode, capable_limits()), validation_error_e::zero_or_unreduced_refresh);

  auto limits = capable_limits();
  limits.maximum_pixels = 1;
  EXPECT_EQ(validate_mode(mode_4k120, limits), validation_error_e::pixel_count_overflow);
  limits = capable_limits();
  limits.maximum_pixel_rate = 1;
  EXPECT_EQ(validate_mode(mode_4k120, limits), validation_error_e::pixel_rate_overflow);

  mode = mode_4k120;
  mode.dynamic_range = dynamic_range_e::hdr10;
  mode.bits_per_channel = 10;
  limits = capable_limits();
  limits.supports_hdr10 = false;
  EXPECT_EQ(validate_mode(mode, limits), validation_error_e::unsupported_dynamic_range);
  limits.supports_hdr10 = true;
  limits.supports_10bit = false;
  EXPECT_EQ(validate_mode(mode, limits), validation_error_e::unsupported_bit_depth);
}

TEST(VirtualDisplayValidation, IntersectsAllAuthoritativeLimitsAndRejectsDisjointDomains) {
  auto left = capable_limits();
  auto right = capable_limits();
  right.minimum_width = 320;
  right.maximum_width = 7680;
  right.maximum_height = 4320;
  right.minimum_refresh = {24000, 1001};
  right.maximum_refresh = {240, 1};
  right.supports_hdr10 = false;
  const auto result = intersect_limits(left, right);
  ASSERT_TRUE(result);
  EXPECT_EQ(result->minimum_width, 320U);
  EXPECT_EQ(result->maximum_width, 7680U);
  EXPECT_EQ(result->maximum_height, 4320U);
  EXPECT_EQ(result->minimum_refresh, (rational_t {24000, 1001}));
  EXPECT_EQ(result->maximum_refresh, (rational_t {240, 1}));
  EXPECT_FALSE(result->supports_hdr10);

  left.minimum_width = 8000;
  right.maximum_width = 4000;
  EXPECT_FALSE(intersect_limits(left, right));
}

TEST(VirtualDisplayAdapters, PreserveLegacyAndModernTuplesExactly) {
  const auto legacy = legacy_game_stream_request(17, 2560, 1600, 240, delivery_policy_e::latency);
  EXPECT_EQ(legacy.session_id, 17U);
  EXPECT_EQ(legacy.mode, (vdd_mode_t {2560, 1600, {240, 1}, dynamic_range_e::sdr, 8}));
  EXPECT_EQ(legacy.delivery_policy, delivery_policy_e::latency);
  EXPECT_EQ(legacy.minimum_fidelity, fidelity_e::lossless);

  auto selected = mode_4k120;
  selected.refresh = {60000, 1001};
  const auto modern = modern_stream_request(
    19,
    selected,
    delivery_policy_e::quality,
    fidelity_e::visually_lossless
  );
  EXPECT_EQ(modern.session_id, 19U);
  EXPECT_EQ(modern.mode, selected);
  EXPECT_EQ(modern.delivery_policy, delivery_policy_e::quality);
  EXPECT_EQ(modern.minimum_fidelity, fidelity_e::visually_lossless);
}

TEST(VirtualDisplayDriverOwnership, ConcurrentCleanupDeletesOwnedObjectExactlyOnce) {
  std::atomic<unsigned int> delete_count {};
  {
    lumen::vdd::single_delete_owner_t<std::atomic<unsigned int> *, counted_delete_t> owner(&delete_count);
    std::barrier gate(3);
    std::thread first([&]() {
      gate.arrive_and_wait();
      owner.reset();
    });
    std::thread second([&]() {
      gate.arrive_and_wait();
      owner.reset();
    });
    gate.arrive_and_wait();
    first.join();
    second.join();
    EXPECT_EQ(owner.get(), nullptr);
  }
  EXPECT_EQ(delete_count.load(), 1U);
}

TEST(VirtualDisplayCoordinator, FailedStopRetainsOwnershipForExactRetry) {
  auto channel = std::make_shared<recording_channel_t>();
  auto display = std::make_shared<recording_display_t>();
  channel->stop_results = {false, true};
  coordinator_t coordinator(channel, display);
  const auto started = coordinator.start(modern_stream_request(41, mode_4k120, delivery_policy_e::latency), capable_limits());
  ASSERT_EQ(started.error, start_error_e::none);
  EXPECT_FALSE(coordinator.stop(41));
  ASSERT_TRUE(coordinator.active_selection());
  EXPECT_EQ(coordinator.active_selection()->session_id, 41u);
  EXPECT_FALSE(coordinator.stop(42));
  EXPECT_TRUE(coordinator.stop(41));
  EXPECT_FALSE(coordinator.active_selection());
  EXPECT_EQ(channel->stop_calls, 2u);
}

TEST(VirtualDisplayCoordinator, FailedRollbackIsRetainedAndBlocksNewGeneration) {
  auto channel = std::make_shared<recording_channel_t>();
  auto display = std::make_shared<recording_display_t>();
  channel->prepare_ok = false;
  channel->stop_results = {false, true};
  display->restore_results = {false, true};
  coordinator_t coordinator(channel, display);
  const auto request = modern_stream_request(51, mode_4k120, delivery_policy_e::quality);
  EXPECT_EQ(coordinator.start(request, capable_limits()).error, start_error_e::rollback_failed);
  EXPECT_EQ(
    coordinator.start(modern_stream_request(52, mode_4k120, delivery_policy_e::quality), capable_limits()).error,
    start_error_e::busy
  );
  EXPECT_FALSE(coordinator.stop(52));
  EXPECT_TRUE(coordinator.stop(51));
  EXPECT_EQ(display->restore_calls, 2u);
}

TEST(VirtualDisplayCoordinator, ConcurrentStartsAdmitExactlyOneSession) {
  auto channel = std::make_shared<recording_channel_t>();
  auto display = std::make_shared<recording_display_t>();
  coordinator_t coordinator(channel, display);
  std::barrier gate(3);
  start_error_e first {};
  start_error_e second {};
  std::thread one([&]() {
    gate.arrive_and_wait();
    first = coordinator.start(modern_stream_request(61, mode_4k120, delivery_policy_e::latency), capable_limits()).error;
  });
  std::thread two([&]() {
    gate.arrive_and_wait();
    second = coordinator.start(modern_stream_request(62, mode_4k120, delivery_policy_e::latency), capable_limits()).error;
  });
  gate.arrive_and_wait();
  one.join();
  two.join();
  EXPECT_EQ(static_cast<unsigned>(first == start_error_e::none) + static_cast<unsigned>(second == start_error_e::none), 1u);
  EXPECT_EQ(static_cast<unsigned>(first == start_error_e::busy) + static_cast<unsigned>(second == start_error_e::busy), 1u);
  ASSERT_TRUE(coordinator.active_selection());
  EXPECT_TRUE(coordinator.stop(coordinator.active_selection()->session_id));
}

TEST(VirtualDisplayCoordinator, GenerationsRemainMonotonicAboveDriverFloor) {
  auto channel = std::make_shared<recording_channel_t>();
  auto display = std::make_shared<recording_display_t>();
  channel->state.last_generation = 500;
  coordinator_t coordinator(channel, display);
  for (std::uint64_t session = 1; session <= 64; ++session) {
    ASSERT_EQ(
      coordinator.start(modern_stream_request(session, mode_4k120, delivery_policy_e::latency), capable_limits()).error,
      start_error_e::none
    );
    ASSERT_TRUE(coordinator.stop(session));
    channel->state.last_generation = channel->generations.back();
  }
  ASSERT_EQ(channel->generations.size(), 64u);
  EXPECT_EQ(channel->generations.front(), 501u);
  EXPECT_TRUE(std::ranges::adjacent_find(channel->generations, std::greater_equal {}) == channel->generations.end());
}

TEST(VirtualDisplayLease, ConcurrentFinalReleaseStopsOnceAndFailedCleanupRetries) {
  auto backend = std::make_shared<lease_backend_t>();
  const auto request = modern_stream_request(71, mode_4k120, delivery_policy_e::latency);
  auto first = backend->start_owned(request, capable_limits());
  ASSERT_TRUE(first.lease);
  auto second_lease = backend->acquire_lease(71);
  std::barrier gate(3);
  std::thread one([&]() { gate.arrive_and_wait(); EXPECT_TRUE(first.lease->release()); });
  std::thread two([&]() { gate.arrive_and_wait(); EXPECT_TRUE(second_lease->release()); });
  gate.arrive_and_wait();
  one.join();
  two.join();
  EXPECT_EQ(backend->stop_calls.load(), 1u);

  backend->stop_failures.store(1);
  auto retry = backend->start_owned(modern_stream_request(72, mode_4k120, delivery_policy_e::latency), capable_limits());
  ASSERT_TRUE(retry.lease);
  EXPECT_FALSE(retry.lease->release());
  auto recovered = backend->start_owned(modern_stream_request(73, mode_4k120, delivery_policy_e::latency), capable_limits());
  EXPECT_EQ(recovered.started.error, start_error_e::none);
  ASSERT_TRUE(recovered.lease);
  EXPECT_TRUE(recovered.lease->release());
}

TEST(VirtualDisplayPolicy, OptionalFallbackRejectsUncertainRollback) {
  auto safe = std::make_shared<lease_backend_t>();
  safe->start_error = start_error_e::driver_unavailable;
  const auto request = modern_stream_request(81, mode_4k120, delivery_policy_e::latency);
  const auto fallback = prepare_stream_session(
    activation_policy_e::optional,
    request,
    capable_limits(),
    "physical",
    safe
  );
  EXPECT_EQ(fallback.outcome, session_prepare_e::physical);
  EXPECT_EQ(fallback.capture_name, "physical");

  auto unsafe = std::make_shared<lease_backend_t>();
  unsafe->start_error = start_error_e::rollback_failed;
  const auto rejected = prepare_stream_session(
    activation_policy_e::optional,
    request,
    capable_limits(),
    "physical",
    unsafe
  );
  EXPECT_EQ(rejected.outcome, session_prepare_e::rejected);
  EXPECT_EQ(rejected.diagnostic, start_error_e::rollback_failed);
}

TEST(VirtualDisplayProtocol, UsesBufferedAdminServiceAbiWithStableSizes) {
  EXPECT_EQ(LUMEN_VDD_ABI_VERSION, 3U);
  EXPECT_EQ(sizeof(LUMEN_VDD_MODE), 20U);
  EXPECT_EQ(sizeof(LUMEN_VDD_QUERY_ABI_RESPONSE), 56U);
  EXPECT_EQ(sizeof(LUMEN_VDD_PREPARE_MODE_REQUEST), 36U);
  EXPECT_EQ(sizeof(LUMEN_VDD_QUERY_STATE_RESPONSE), 44U);
  EXPECT_EQ(sizeof(LUMEN_VDD_OPEN_FRAME_CHANNEL_REQUEST), 16U);
  EXPECT_EQ(sizeof(LUMEN_VDD_OPEN_FRAME_CHANNEL_RESPONSE), 80U);
  EXPECT_EQ(sizeof(LUMEN_VDD_OPEN_FRAME_EVENT_RESPONSE), 24U);
  EXPECT_EQ(sizeof(LUMEN_VDD_DEQUEUE_FRAME_RESPONSE), 48U);
  EXPECT_EQ(sizeof(LUMEN_VDD_RELEASE_FRAME_REQUEST), 40U);
  EXPECT_EQ(IOCTL_LUMEN_VDD_OPEN_FRAME_CHANNEL & 3U, LUMEN_VDD_METHOD_BUFFERED);
  EXPECT_NE(IOCTL_LUMEN_VDD_OPEN_FRAME_CHANNEL & (LUMEN_VDD_FILE_WRITE_DATA << 14U), 0U);
  EXPECT_NE(IOCTL_LUMEN_VDD_DEQUEUE_FRAME & (LUMEN_VDD_FILE_READ_DATA << 14U), 0U);
  EXPECT_NE(IOCTL_LUMEN_VDD_RELEASE_FRAME & (LUMEN_VDD_FILE_WRITE_DATA << 14U), 0U);
  EXPECT_NE(IOCTL_LUMEN_VDD_OPEN_FRAME_EVENT & (LUMEN_VDD_FILE_READ_DATA << 14U), 0U);
}

TEST(VirtualDisplayDirectFrameValidation, RequiresExactUniqueTwoSlotResources) {
  frame_resources_t resources {
    9,
    123,
    mode_4k120.width,
    mode_4k120.height,
    frame_format_e::bgra8,
    2,
    {10, 11},
    {12, 13},
  };
  EXPECT_TRUE(valid_frame_resources(resources, 9, mode_4k120));
  resources.generation = 8;
  EXPECT_FALSE(valid_frame_resources(resources, 9, mode_4k120));
  resources.generation = 9;
  resources.fence_handles[1] = resources.texture_handles[0];
  EXPECT_FALSE(valid_frame_resources(resources, 9, mode_4k120));
}

TEST(VirtualDisplayDirectFrameValidation, RequiresGenerationSlotQpcAndOddProducerFence) {
  const frame_resources_t resources {
    9,
    123,
    mode_4k120.width,
    mode_4k120.height,
    frame_format_e::bgra8,
    2,
    {10, 11},
    {12, 13},
  };
  frame_descriptor_t frame {9, 1, 1, 100, 110, 0};
  EXPECT_TRUE(valid_frame_descriptor(frame, resources));
  frame.producer_fence_value = 2;
  EXPECT_FALSE(valid_frame_descriptor(frame, resources));
  frame.producer_fence_value = 1;
  frame.slot = 2;
  EXPECT_FALSE(valid_frame_descriptor(frame, resources));
}

TEST(VirtualDisplayDirectFrameSlots, NeverRecyclesFailedGpuCompletion) {
  using lumen::vdd::frame::complete_write;
  using lumen::vdd::frame::slot_state_e;
  using lumen::vdd::frame::submission_result_e;
  EXPECT_EQ(complete_write(submission_result_e::success), slot_state_e::ready);
  EXPECT_EQ(complete_write(submission_result_e::wait_failed), slot_state_e::quarantined);
  EXPECT_EQ(complete_write(submission_result_e::copy_failed), slot_state_e::quarantined);
  EXPECT_EQ(complete_write(submission_result_e::signal_failed), slot_state_e::quarantined);
  EXPECT_FALSE(lumen::vdd::frame::can_begin_write(slot_state_e::quarantined));
  EXPECT_TRUE(lumen::vdd::frame::can_begin_write(slot_state_e::released_pending));
}

TEST(VirtualDisplayEdidPolicy, DistinguishesIdentityDescriptorsFromRealTimings) {
  std::array<std::uint8_t, 128> identity_only {};
  identity_only[54 + 3] = 0xfc;
  EXPECT_EQ(lumen::vdd::edid::detailed_timing_count(identity_only), 0U);
  identity_only[54] = 0x01;
  EXPECT_EQ(lumen::vdd::edid::detailed_timing_count(identity_only), 1U);
}
