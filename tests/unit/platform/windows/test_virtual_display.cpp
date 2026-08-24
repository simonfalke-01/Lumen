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
#include <utility>
#include <vector>

#if defined(_WIN32)
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <d3d11_4.h>
  #include <dxgi1_2.h>
  #include <Windows.h>
  #include <wrl/client.h>
#endif

// lib includes
#include <gtest/gtest.h>

// local includes
#include "src/platform/windows/virtual_display.h"
#include "src/platform/windows/virtual_display_driver/LumenDirectFrameSlotPolicy.h"
#include "src/platform/windows/virtual_display_driver/LumenSingleDeleteOwner.h"
#include "src/platform/windows/virtual_display_driver/LumenVirtualDisplayProtocol.h"
#include "src/platform/windows/virtual_display_frame.h"
#include "src/utility.h"

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
      const std::uint64_t preferred_render_adapter_luid,
      prepared_mode_t &prepared
    ) override {
      generations.push_back(generation);
      preferred_render_adapter_luids.push_back(preferred_render_adapter_luid);
      prepared = {
        mode,
        "LUM0001",
        fidelity,
        preferred_render_adapter_luid,
        preferred_render_adapter_luid != 0 && preference_supported,
      };
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
    std::vector<std::uint64_t> preferred_render_adapter_luids;
    unsigned open_calls {};
    unsigned stop_calls {};
    unsigned close_calls {};
    bool open_ok {true};
    bool limits_ok {true};
    bool state_ok {true};
    bool recover_ok {true};
    bool prepare_ok {true};
    bool preference_supported {true};
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

TEST(VirtualDisplayRenderAdapter, RequiresCompleteFrozenIdentityAndPropagatesExactLuid) {
  render_adapter_identity_t identity {
    0x0000000200000001ULL,
    0x10de,
    0x28e0,
    0x18ed1043,
    0xa1,
    0x0000000100000002ULL,
  };
  EXPECT_TRUE(valid_render_adapter_identity(identity));
  auto invalid = identity;
  invalid.adapter_luid = 0;
  EXPECT_FALSE(valid_render_adapter_identity(invalid));
  invalid = identity;
  invalid.vendor_id = 0;
  EXPECT_FALSE(valid_render_adapter_identity(invalid));
  invalid = identity;
  invalid.device_id = 0;
  EXPECT_FALSE(valid_render_adapter_identity(invalid));
  invalid = identity;
  invalid.driver_version = 0;
  EXPECT_FALSE(valid_render_adapter_identity(invalid));

  auto channel = std::make_shared<recording_channel_t>();
  auto display = std::make_shared<recording_display_t>();
  coordinator_t coordinator(channel, display);
  auto request = modern_stream_request(29, mode_4k120, delivery_policy_e::latency);
  request.render_adapter = identity;
  const auto started = coordinator.start(request, capable_limits());
  ASSERT_EQ(started.error, start_error_e::none);
  ASSERT_TRUE(started.selection);
  ASSERT_EQ(channel->preferred_render_adapter_luids.size(), 1U);
  EXPECT_EQ(channel->preferred_render_adapter_luids.front(), identity.adapter_luid);
  EXPECT_EQ(started.selection->render_adapter, identity);
  EXPECT_TRUE(started.selection->render_adapter_preference_submitted);
  EXPECT_EQ(coordinator.start(request, capable_limits()).error, start_error_e::none);
  auto changed_identity_request = request;
  changed_identity_request.render_adapter->driver_version++;
  EXPECT_EQ(coordinator.start(changed_identity_request, capable_limits()).error, start_error_e::busy);
  EXPECT_TRUE(coordinator.stop(request.session_id));
}

TEST(VirtualDisplayRenderAdapter, DownlevelPreferenceAbsencePreservesSdrSelectionWithoutClaimingSubmission) {
  const render_adapter_identity_t identity {
    0x0000000200000001ULL,
    0x10de,
    0x28e0,
    0x18ed1043,
    0xa1,
    0x0000000100000002ULL,
  };
  auto channel = std::make_shared<recording_channel_t>();
  auto display = std::make_shared<recording_display_t>();
  channel->preference_supported = false;
  coordinator_t coordinator(channel, display);
  auto request = modern_stream_request(30, mode_4k120, delivery_policy_e::quality);
  request.render_adapter = identity;
  const auto started = coordinator.start(request, capable_limits());
  ASSERT_EQ(started.error, start_error_e::none);
  ASSERT_TRUE(started.selection);
  EXPECT_EQ(started.selection->render_adapter, identity);
  EXPECT_FALSE(started.selection->render_adapter_preference_submitted);
  EXPECT_TRUE(coordinator.stop(request.session_id));
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
  EXPECT_EQ(LUMEN_VDD_ABI_VERSION, 4U);
  EXPECT_EQ(sizeof(LUMEN_VDD_MODE), 20U);
  EXPECT_EQ(sizeof(LUMEN_VDD_QUERY_ABI_RESPONSE), 56U);
  EXPECT_EQ(sizeof(LUMEN_VDD_PREPARE_MODE_REQUEST), 44U);
  EXPECT_EQ(sizeof(LUMEN_VDD_PREPARE_MODE_RESPONSE), 164U);
  EXPECT_EQ(sizeof(LUMEN_VDD_QUERY_STATE_RESPONSE), 68U);
  EXPECT_EQ(sizeof(LUMEN_VDD_OPEN_FRAME_CHANNEL_REQUEST), 16U);
  EXPECT_EQ(sizeof(LUMEN_VDD_OPEN_FRAME_CHANNEL_RESPONSE), 96U);
  EXPECT_EQ(sizeof(LUMEN_VDD_OPEN_FRAME_EVENT_RESPONSE), 40U);
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

TEST(VirtualDisplayDirectFrameValidation, AutomaticallyRequiresActiveNvencAndExactNvidiaAdapterProbe) {
  const direct_frame_adapter_identity_t imported {
    0x0000000200000001ULL,
    0x10de,
    0x2882,
    0x51a31462,
    0xa1,
    0x0000000100000002ULL,
  };
  const std::optional<direct_frame_adapter_identity_t> matching_probe {imported};

  EXPECT_TRUE(valid_direct_frame_adapter_binding(true, imported, matching_probe));
  EXPECT_FALSE(valid_direct_frame_adapter_binding(false, imported, matching_probe));
  EXPECT_FALSE(valid_direct_frame_adapter_binding(true, imported, std::nullopt));

  const auto expect_rejected = [&](auto mutate) {
    auto changed_probe = imported;
    mutate(changed_probe);
    EXPECT_FALSE(valid_direct_frame_adapter_binding(true, imported, changed_probe));
  };
  expect_rejected([](auto &identity) {
    identity.adapter_luid++;
  });
  expect_rejected([](auto &identity) {
    identity.vendor_id = 0x1002;
  });
  expect_rejected([](auto &identity) {
    identity.device_id++;
  });
  expect_rejected([](auto &identity) {
    identity.subsystem_id++;
  });
  expect_rejected([](auto &identity) {
    identity.revision++;
  });
  expect_rejected([](auto &identity) {
    identity.driver_version++;
  });

  auto non_nvidia_import = imported;
  non_nvidia_import.vendor_id = 0x1002;
  EXPECT_FALSE(valid_direct_frame_adapter_binding(true, non_nvidia_import, non_nvidia_import));
}

#if defined(_WIN32)
TEST(VirtualDisplayDirectFrameKernelIdentity, DistinguishesDuplicatedAndIndependentTextureHandles) {
  using Microsoft::WRL::ComPtr;
  ComPtr<ID3D11Device> device;
  if (FAILED(D3D11CreateDevice(
        nullptr,
        D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        0,
        nullptr,
        0,
        D3D11_SDK_VERSION,
        &device,
        nullptr,
        nullptr
      ))) {
    GTEST_SKIP() << "No real D3D11 hardware device is available";
  }

  D3D11_TEXTURE2D_DESC desc {};
  desc.Width = 64;
  desc.Height = 64;
  desc.MipLevels = 1;
  desc.ArraySize = 1;
  desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
  desc.SampleDesc.Count = 1;
  desc.Usage = D3D11_USAGE_DEFAULT;
  desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
  desc.MiscFlags = D3D11_RESOURCE_MISC_SHARED_NTHANDLE;

  ComPtr<ID3D11Texture2D> texture;
  ComPtr<IDXGIResource1> shared_texture;
  if (FAILED(device->CreateTexture2D(&desc, nullptr, &texture)) ||
      FAILED(texture.As(&shared_texture))) {
    GTEST_SKIP() << "D3D11 shared-NTHANDLE textures are unavailable";
  }

  HANDLE first_handle {};
  HANDLE second_handle {};
  HANDLE distinct_handle {};
  [[maybe_unused]] auto close_handles = util::fail_guard([&]() {
    if (first_handle != nullptr) {
      CloseHandle(first_handle);
    }
    if (second_handle != nullptr) {
      CloseHandle(second_handle);
    }
    if (distinct_handle != nullptr) {
      CloseHandle(distinct_handle);
    }
  });
  if (FAILED(shared_texture->CreateSharedHandle(
        nullptr,
        DXGI_SHARED_RESOURCE_READ | DXGI_SHARED_RESOURCE_WRITE,
        nullptr,
        &first_handle
      ))) {
    GTEST_SKIP() << "D3D11 shared-NTHANDLE creation is unavailable";
  }
  ASSERT_TRUE(DuplicateHandle(
    GetCurrentProcess(),
    first_handle,
    GetCurrentProcess(),
    &second_handle,
    0,
    FALSE,
    DUPLICATE_SAME_ACCESS
  ));
  ASSERT_NE(first_handle, second_handle);

  ComPtr<ID3D11Texture2D> independent_texture;
  ComPtr<IDXGIResource1> independent_shared_texture;
  ASSERT_TRUE(SUCCEEDED(device->CreateTexture2D(&desc, nullptr, &independent_texture)));
  ASSERT_TRUE(SUCCEEDED(independent_texture.As(&independent_shared_texture)));
  ASSERT_TRUE(SUCCEEDED(independent_shared_texture->CreateSharedHandle(
    nullptr,
    DXGI_SHARED_RESOURCE_READ | DXGI_SHARED_RESOURCE_WRITE,
    nullptr,
    &distinct_handle
  )));
  const auto alias_result = compare_direct_frame_handle_identity(
    reinterpret_cast<std::uintptr_t>(first_handle),
    reinterpret_cast<std::uintptr_t>(second_handle)
  );
  const auto alias_error = GetLastError();
  const auto distinct_result = compare_direct_frame_handle_identity(
    reinterpret_cast<std::uintptr_t>(first_handle),
    reinterpret_cast<std::uintptr_t>(distinct_handle)
  );
  const auto distinct_error = GetLastError();
  if (alias_result == direct_frame_handle_identity_e::unavailable_or_error ||
      distinct_result == direct_frame_handle_identity_e::unavailable_or_error) {
    GTEST_SKIP() << "CompareObjectHandles cannot compare D3D11 texture handles on this environment"
                 << " (alias_error=" << alias_error << ", distinct_error=" << distinct_error << ')';
  }
  EXPECT_EQ(alias_result, direct_frame_handle_identity_e::alias);
  EXPECT_EQ(
    distinct_result,
    direct_frame_handle_identity_e::distinct
  );
}

TEST(VirtualDisplayDirectFrameKernelIdentity, DistinguishesDuplicatedAndIndependentFenceHandles) {
  using Microsoft::WRL::ComPtr;
  ComPtr<ID3D11Device> device;
  if (FAILED(D3D11CreateDevice(
        nullptr,
        D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        0,
        nullptr,
        0,
        D3D11_SDK_VERSION,
        &device,
        nullptr,
        nullptr
      ))) {
    GTEST_SKIP() << "No real D3D11 hardware device is available";
  }
  ComPtr<ID3D11Device5> device5;
  if (FAILED(device.As(&device5))) {
    GTEST_SKIP() << "ID3D11Device5 shared-fence import is unavailable";
  }

  ComPtr<ID3D11Fence> fence;
  if (FAILED(device5->CreateFence(0, D3D11_FENCE_FLAG_SHARED, IID_PPV_ARGS(&fence)))) {
    GTEST_SKIP() << "D3D11 shared fences are unavailable";
  }
  HANDLE first_handle {};
  HANDLE second_handle {};
  HANDLE distinct_handle {};
  [[maybe_unused]] auto close_handles = util::fail_guard([&]() {
    if (first_handle != nullptr) {
      CloseHandle(first_handle);
    }
    if (second_handle != nullptr) {
      CloseHandle(second_handle);
    }
    if (distinct_handle != nullptr) {
      CloseHandle(distinct_handle);
    }
  });
  ASSERT_TRUE(SUCCEEDED(fence->CreateSharedHandle(nullptr, GENERIC_ALL, nullptr, &first_handle)));
  ASSERT_TRUE(DuplicateHandle(
    GetCurrentProcess(),
    first_handle,
    GetCurrentProcess(),
    &second_handle,
    0,
    FALSE,
    DUPLICATE_SAME_ACCESS
  ));
  ASSERT_NE(first_handle, second_handle);

  ComPtr<ID3D11Fence> independent_fence;
  ASSERT_TRUE(SUCCEEDED(device5->CreateFence(0, D3D11_FENCE_FLAG_SHARED, IID_PPV_ARGS(&independent_fence))));
  ASSERT_TRUE(SUCCEEDED(independent_fence->CreateSharedHandle(
    nullptr,
    GENERIC_ALL,
    nullptr,
    &distinct_handle
  )));
  const auto alias_result = compare_direct_frame_handle_identity(
    reinterpret_cast<std::uintptr_t>(first_handle),
    reinterpret_cast<std::uintptr_t>(second_handle)
  );
  const auto alias_error = GetLastError();
  const auto distinct_result = compare_direct_frame_handle_identity(
    reinterpret_cast<std::uintptr_t>(first_handle),
    reinterpret_cast<std::uintptr_t>(distinct_handle)
  );
  const auto distinct_error = GetLastError();
  if (alias_result == direct_frame_handle_identity_e::unavailable_or_error ||
      distinct_result == direct_frame_handle_identity_e::unavailable_or_error) {
    GTEST_SKIP() << "CompareObjectHandles cannot compare D3D11 fence handles on this environment"
                 << " (alias_error=" << alias_error << ", distinct_error=" << distinct_error << ')';
  }
  EXPECT_EQ(alias_result, direct_frame_handle_identity_e::alias);
  EXPECT_EQ(
    distinct_result,
    direct_frame_handle_identity_e::distinct
  );
  EXPECT_EQ(
    compare_direct_frame_handle_identity(0, reinterpret_cast<std::uintptr_t>(first_handle)),
    direct_frame_handle_identity_e::unavailable_or_error
  );
}
#endif

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

TEST(VirtualDisplayAdvancedColorPolicy, HdrRequiresSupportedEnabledTargetState) {
  EXPECT_EQ(
    advanced_color_action(dynamic_range_e::hdr10, advanced_color_state_e::disabled),
    advanced_color_action_e::enable
  );
  EXPECT_EQ(
    advanced_color_action(dynamic_range_e::hdr10, advanced_color_state_e::enabled),
    advanced_color_action_e::none
  );
  EXPECT_EQ(
    advanced_color_action(dynamic_range_e::hdr10, advanced_color_state_e::unsupported),
    advanced_color_action_e::reject
  );
  EXPECT_EQ(
    advanced_color_action(dynamic_range_e::hdr10, advanced_color_state_e::api_unavailable),
    advanced_color_action_e::reject
  );
  EXPECT_TRUE(advanced_color_matches(dynamic_range_e::hdr10, advanced_color_state_e::enabled));
  EXPECT_FALSE(advanced_color_matches(dynamic_range_e::hdr10, advanced_color_state_e::disabled));
}

TEST(VirtualDisplayAdvancedColorPolicy, SdrExplicitlyDisablesWhenSupportedAndPreservesDownlevelSupport) {
  EXPECT_EQ(
    advanced_color_action(dynamic_range_e::sdr, advanced_color_state_e::enabled),
    advanced_color_action_e::disable
  );
  EXPECT_EQ(
    advanced_color_action(dynamic_range_e::sdr, advanced_color_state_e::disabled),
    advanced_color_action_e::none
  );
  EXPECT_EQ(
    advanced_color_action(dynamic_range_e::sdr, advanced_color_state_e::unsupported),
    advanced_color_action_e::none
  );
  EXPECT_EQ(
    advanced_color_action(dynamic_range_e::sdr, advanced_color_state_e::api_unavailable),
    advanced_color_action_e::none
  );
  EXPECT_FALSE(advanced_color_matches(dynamic_range_e::sdr, advanced_color_state_e::enabled));
  EXPECT_TRUE(advanced_color_matches(dynamic_range_e::sdr, advanced_color_state_e::disabled));
  EXPECT_TRUE(advanced_color_matches(dynamic_range_e::sdr, advanced_color_state_e::unsupported));
  EXPECT_TRUE(advanced_color_matches(dynamic_range_e::sdr, advanced_color_state_e::api_unavailable));
}

TEST(VirtualDisplayAdvancedColorPolicy, SnapshotIgnoresInactiveUnavailableAndDuplicateTargets) {
  const std::array<advanced_color_path_t, 8> paths {{
    {1, 10, false, true},
    {1, 11, false, false},
    {1, 12, true, false},
    {2, 20, true, true},
    {2, 20, true, true},
    {3, 20, true, true},
    {4, 40, false, true},
    {5, 50, true, true},
  }};
  const auto selected = active_advanced_color_targets(paths);
  ASSERT_EQ(selected.size(), 3U);
  EXPECT_EQ(selected[0].adapter_luid, 2U);
  EXPECT_EQ(selected[0].target_id, 20U);
  EXPECT_EQ(selected[1].adapter_luid, 3U);
  EXPECT_EQ(selected[1].target_id, 20U);
  EXPECT_EQ(selected[2].adapter_luid, 5U);
  EXPECT_EQ(selected[2].target_id, 50U);
}

TEST(VirtualDisplayAdvancedColorPolicy, RestoreAttemptsEveryMutableTargetAfterPartialFailure) {
  const std::array<target_advanced_color_t, 5> targets {{
    {1, 10, advanced_color_state_e::enabled},
    {2, 20, advanced_color_state_e::unsupported},
    {3, 30, advanced_color_state_e::disabled},
    {4, 40, advanced_color_state_e::api_unavailable},
    {5, 50, advanced_color_state_e::enabled},
  }};
  std::vector<std::pair<std::uint32_t, bool>> attempts;
  const auto restored = restore_all_advanced_color_states(targets, [&](const auto &target, const bool enabled) {
    attempts.emplace_back(target.target_id, enabled);
    return target.target_id != 10;
  });
  EXPECT_FALSE(restored);
  ASSERT_EQ(attempts.size(), 3U);
  EXPECT_EQ(attempts[0], (std::pair<std::uint32_t, bool> {10, true}));
  EXPECT_EQ(attempts[1], (std::pair<std::uint32_t, bool> {30, false}));
  EXPECT_EQ(attempts[2], (std::pair<std::uint32_t, bool> {50, true}));
}

TEST(VirtualDisplayDirectFrameSlots, NeverRecyclesFailedGpuCompletion) {
  using lumen::vdd::frame::complete_write;
  using lumen::vdd::frame::slot_state_e;
  using lumen::vdd::frame::submission_result_e;
  EXPECT_EQ(complete_write(submission_result_e::success), slot_state_e::ready);
  EXPECT_EQ(complete_write(submission_result_e::wait_failed), slot_state_e::quarantined);
  EXPECT_EQ(complete_write(submission_result_e::copy_failed), slot_state_e::quarantined);
  EXPECT_EQ(complete_write(submission_result_e::signal_failed), slot_state_e::quarantined);
  EXPECT_FALSE(lumen::vdd::frame::producer_acquisition(slot_state_e::quarantined, 1, 0).can_write);
  const auto empty_acquisition = lumen::vdd::frame::producer_acquisition(slot_state_e::empty, 0, 0);
  EXPECT_TRUE(empty_acquisition.can_write);
  EXPECT_EQ(empty_acquisition.keyed_mutex_key, 0U);
  EXPECT_EQ(empty_acquisition.consumer_fence_wait, 0U);
  EXPECT_TRUE(lumen::vdd::frame::producer_acquisition(slot_state_e::released_pending, 1, 2).can_write);
  EXPECT_TRUE(lumen::vdd::frame::render_adapter_matches(0x1234, 0x1234));
  EXPECT_FALSE(lumen::vdd::frame::render_adapter_matches(0, 0));
  EXPECT_FALSE(lumen::vdd::frame::render_adapter_matches(0x1234, 0x5678));
  EXPECT_TRUE(lumen::vdd::frame::published_handles_are_distinct(1, 2, 3, 4));
  EXPECT_FALSE(lumen::vdd::frame::published_handles_are_distinct(1, 1, 3, 4));
  EXPECT_FALSE(lumen::vdd::frame::published_handles_are_distinct(1, 2, 1, 4));
  EXPECT_FALSE(lumen::vdd::frame::published_handles_are_distinct(1, 2, 3, 0));
  EXPECT_EQ(lumen::vdd::frame::host_acquire_key(1), 1U);
  EXPECT_EQ(lumen::vdd::frame::producer_return_key(1), 2U);
}

TEST(VirtualDisplayDirectFrameSlots, LatencyDequeuePreservesDiscardedReadyOwnership) {
  using lumen::vdd::frame::complete_write;
  using lumen::vdd::frame::dequeue_ready_slot;
  using lumen::vdd::frame::select_producer_slot;
  using lumen::vdd::frame::slot_state_e;
  using lumen::vdd::frame::submission_result_e;

  /** @brief Pure state needed by the production dequeue policy. */
  struct policy_slot_t {
    slot_state_e state;
    std::uint64_t sequence;
    std::uint64_t producer_fence_value;
    std::uint64_t consumer_fence_value;
  };

  std::array<policy_slot_t, 2> slots {{
    {slot_state_e::ready, 1, 1, 0},
    {slot_state_e::ready, 2, 1, 0},
  }};

  const auto first_dequeue = dequeue_ready_slot(slots, true);
  ASSERT_EQ(first_dequeue, 1U);
  EXPECT_EQ(slots[0].state, slot_state_e::discarded_ready);
  EXPECT_EQ(slots[1].state, slot_state_e::acquired);

  const auto first_discard_reuse = select_producer_slot(slots, true);
  ASSERT_EQ(first_discard_reuse.slot, 0U);
  ASSERT_TRUE(first_discard_reuse.acquisition.can_write);
  EXPECT_EQ(first_discard_reuse.acquisition.keyed_mutex_key, 1U);
  EXPECT_EQ(first_discard_reuse.acquisition.consumer_fence_wait, 0U);
  slots[0].state = complete_write(submission_result_e::success);
  slots[0].sequence = 3;
  slots[0].producer_fence_value = 3;

  slots[1].state = slot_state_e::released_pending;
  slots[1].consumer_fence_value = 2;
  const auto released_reuse = select_producer_slot(slots, true);
  ASSERT_EQ(released_reuse.slot, 1U);
  ASSERT_TRUE(released_reuse.acquisition.can_write);
  EXPECT_EQ(released_reuse.acquisition.keyed_mutex_key, 2U);
  EXPECT_EQ(released_reuse.acquisition.consumer_fence_wait, 2U);
  slots[1].state = complete_write(submission_result_e::success);
  slots[1].sequence = 4;
  slots[1].producer_fence_value = 3;

  const auto second_dequeue = dequeue_ready_slot(slots, true);
  ASSERT_EQ(second_dequeue, 1U);
  EXPECT_EQ(slots[0].state, slot_state_e::discarded_ready);
  EXPECT_EQ(slots[1].state, slot_state_e::acquired);

  const auto second_discard_reuse = select_producer_slot(slots, true);
  ASSERT_EQ(second_discard_reuse.slot, 0U);
  ASSERT_TRUE(second_discard_reuse.acquisition.can_write);
  EXPECT_EQ(second_discard_reuse.acquisition.keyed_mutex_key, 3U);
  EXPECT_EQ(second_discard_reuse.acquisition.consumer_fence_wait, 0U);

  std::array<policy_slot_t, 2> fifo_slots {{
    {slot_state_e::ready, 9, 1, 0},
    {slot_state_e::ready, 7, 1, 0},
  }};
  const auto fifo_dequeue = dequeue_ready_slot(fifo_slots, false);
  ASSERT_EQ(fifo_dequeue, 1U);
  EXPECT_EQ(fifo_slots[0].state, slot_state_e::ready);
  EXPECT_EQ(fifo_slots[1].state, slot_state_e::acquired);

  std::array<policy_slot_t, 2> unavailable_slots {{
    {slot_state_e::discarded_ready, 1, 1, 0},
    {slot_state_e::acquired, 2, 1, 0},
  }};
  EXPECT_FALSE(dequeue_ready_slot(unavailable_slots, true).has_value());
  unavailable_slots[0].state = slot_state_e::acquired;
  EXPECT_FALSE(select_producer_slot(unavailable_slots, true).slot.has_value());
}

TEST(VirtualDisplayDirectFrameSlots, LatencyProducerOverwritesOldestReadyFrame) {
  using lumen::vdd::frame::select_producer_slot;
  using lumen::vdd::frame::slot_state_e;

  /** @brief Pure state needed by the production producer-selection policy. */
  struct policy_slot_t {
    slot_state_e state;
    std::uint64_t sequence;
    std::uint64_t producer_fence_value;
    std::uint64_t consumer_fence_value;
  };

  std::array<policy_slot_t, 2> latency_slots {{
    {slot_state_e::ready, 1, 1, 0},
    {slot_state_e::ready, 2, 1, 0},
  }};
  const auto first_overwrite = select_producer_slot(latency_slots, true);
  ASSERT_EQ(first_overwrite.slot, 0U);
  EXPECT_EQ(latency_slots[0].state, slot_state_e::writing);
  EXPECT_EQ(latency_slots[1].state, slot_state_e::ready);
  EXPECT_EQ(first_overwrite.acquisition.keyed_mutex_key, 1U);
  EXPECT_EQ(first_overwrite.acquisition.consumer_fence_wait, 0U);

  latency_slots[0] = {slot_state_e::ready, 3, 3, 0};
  const auto second_overwrite = select_producer_slot(latency_slots, true);
  ASSERT_EQ(second_overwrite.slot, 1U);
  EXPECT_EQ(latency_slots[0].state, slot_state_e::ready);
  EXPECT_EQ(latency_slots[1].state, slot_state_e::writing);
  EXPECT_EQ(second_overwrite.acquisition.keyed_mutex_key, 1U);
  EXPECT_EQ(second_overwrite.acquisition.consumer_fence_wait, 0U);

  std::array<policy_slot_t, 2> quality_slots {{
    {slot_state_e::ready, 1, 1, 0},
    {slot_state_e::ready, 2, 1, 0},
  }};
  const auto quality_drop = select_producer_slot(quality_slots, false);
  EXPECT_FALSE(quality_drop.slot.has_value());
  EXPECT_EQ(quality_slots[0].state, slot_state_e::ready);
  EXPECT_EQ(quality_slots[1].state, slot_state_e::ready);
}
