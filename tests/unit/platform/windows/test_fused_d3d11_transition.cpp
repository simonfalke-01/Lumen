/**
 * @file tests/unit/platform/windows/test_fused_d3d11_transition.cpp
 * @brief Integration-style fake context and resource tests for fused D3D11 transitions.
 */

// standard includes
#include <atomic>
#include <mutex>
#include <semaphore>
#include <thread>

// lib includes
#include <gtest/gtest.h>

// local includes
#include "src/platform/windows/fused_d3d11_policy.h"

namespace {
  using namespace platf::dxgi::fused_d3d11;

  /** @brief Fake immediate context that records serialized setup and capture operations. */
  struct fake_context_t {
    std::uint32_t setup_calls = 0;  ///< Number of encoder setup calls.
    std::uint32_t capture_calls = 0;  ///< Number of capture submissions.
  };

  /** @brief Fake capture/encode device identity used to fail closed before commit. */
  struct fake_device_t {
    bool identity_matches = true;  ///< Whether capture, context, adapter, and probe identities match.
  };

  /** @brief NVENC failure stages that all produce an empty encoded frame. */
  enum class fake_nvenc_failure_e {
    map_input,  ///< NvEncMapInputResource failure.
    encode_picture,  ///< NvEncEncodePicture or async-wait failure.
    lock_bitstream  ///< NvEncLockBitstream failure.
  };

  /** @brief Fake capture image whose lifetime drains the ownership image count. */
  struct fake_image_t {
    resource_ownership_t *ownership = nullptr;  ///< Ownership state bound by the fake resource.
    bool bound = false;  ///< Whether the fake texture is bound.

    ~fake_image_t() {
      if (bound) {
        EXPECT_TRUE(ownership->release_image());
      }
    }
  };

  /** @brief Minimal integration seam mirroring display/context/resource transition ordering. */
  class fake_pipeline_t {
  public:
    /** @brief Begin fused setup while exclusively owning the fake immediate context. */
    bool initialize_fused(bool fail_setup = false) {
      auto lock = std::lock_guard(context_mutex);
      const auto transition = ownership.begin_transition(resource_mode_e::fused);
      if (transition == transition_result_e::rejected) {
        return false;
      }
      ++context.setup_calls;
      if (fail_setup || !device.identity_matches) {
        if (transition == transition_result_e::started) {
          EXPECT_TRUE(ownership.rollback_transition(resource_mode_e::fused));
        }
        return false;
      }
      if (transition == transition_result_e::started && !ownership.commit_transition(resource_mode_e::fused)) {
        return false;
      }
      return ownership.acquire_consumer(resource_mode_e::fused);
    }

    /** @brief Allocate one capture resource under the same transition lock. */
    bool capture(fake_image_t &image) {
      auto lock = std::lock_guard(context_mutex);
      if (ownership.reinit_required()) {
        return false;
      }
      if (ownership.state() == resource_state_e::unset) {
        if (ownership.begin_transition(resource_mode_e::legacy) != transition_result_e::started ||
            !ownership.commit_transition(resource_mode_e::legacy)) {
          return false;
        }
      }
      ++context.capture_calls;
      image.ownership = &ownership;
      image.bound = ownership.bind_image(ownership.mode());
      return image.bound;
    }

    std::mutex context_mutex;  ///< Fake shared immediate-context mutex.
    resource_ownership_t ownership;  ///< Fake display capture-pool ownership.
    fake_device_t device;  ///< Fake exact device-identity seam.
    fake_context_t context;  ///< Fake D3D11 device/context operation record.
  };

  /** @brief Verify one empty-frame NVENC failure requests reinit before teardown. */
  void expect_encode_failure_requests_reinit(fake_nvenc_failure_e failure) {
    fake_pipeline_t pipeline;
    ASSERT_TRUE(pipeline.initialize_fused());
    fake_image_t image;
    ASSERT_TRUE(pipeline.capture(image));
    bool fused_healthy = true;
    bool pending_input = true;

    const auto encode = [&]() -> bool {
      switch (failure) {
        case fake_nvenc_failure_e::map_input:
        case fake_nvenc_failure_e::encode_picture:
        case fake_nvenc_failure_e::lock_bitstream:
          pending_input = false;
          fused_healthy = false;
          EXPECT_TRUE(pipeline.ownership.request_reinit());
          return false;
      }
      return true;
    };

    EXPECT_FALSE(encode());
    EXPECT_FALSE(fused_healthy);
    EXPECT_FALSE(pending_input);
    EXPECT_TRUE(pipeline.ownership.reinit_required());
    EXPECT_TRUE(pipeline.ownership.release_consumer(resource_mode_e::fused));
  }

  TEST(FusedD3D11TransitionIntegration, CaptureAllocationBeforeEncoderCommitsLegacyAndRejectsFused) {
    fake_pipeline_t pipeline;
    fake_image_t image;
    ASSERT_TRUE(pipeline.capture(image));
    EXPECT_EQ(pipeline.ownership.state(), resource_state_e::legacy);
    EXPECT_FALSE(pipeline.initialize_fused());
    EXPECT_EQ(pipeline.context.setup_calls, 0u);
  }

  TEST(FusedD3D11TransitionIntegration, TransitionLockPreventsQueuedLegacyImageDuringFusedCommit) {
    fake_pipeline_t pipeline;
    std::binary_semaphore transition_started {0};
    std::binary_semaphore allow_commit {0};
    std::atomic_bool capture_completed = false;
    fake_image_t image;

    std::thread setup([&]() {
      auto context_lock = std::unique_lock(pipeline.context_mutex);
      ASSERT_EQ(pipeline.ownership.begin_transition(resource_mode_e::fused), transition_result_e::started);
      transition_started.release();
      allow_commit.acquire();
      ASSERT_TRUE(pipeline.ownership.commit_transition(resource_mode_e::fused));
      ASSERT_TRUE(pipeline.ownership.acquire_consumer(resource_mode_e::fused));
    });

    transition_started.acquire();
    std::thread capture([&]() {
      capture_completed.store(pipeline.capture(image), std::memory_order_release);
    });
    EXPECT_FALSE(capture_completed.load(std::memory_order_acquire));
    allow_commit.release();
    setup.join();
    capture.join();

    EXPECT_TRUE(capture_completed.load(std::memory_order_acquire));
    EXPECT_EQ(pipeline.ownership.mode(), resource_mode_e::fused);
    EXPECT_EQ(pipeline.ownership.images(), 1u);
    EXPECT_TRUE(pipeline.ownership.release_consumer(resource_mode_e::fused));
  }

  TEST(FusedD3D11TransitionIntegration, SetupFailureRollsBackBeforeLegacyCaptureAllocation) {
    fake_pipeline_t pipeline;
    EXPECT_FALSE(pipeline.initialize_fused(true));
    EXPECT_EQ(pipeline.ownership.state(), resource_state_e::unset);
    fake_image_t image;
    EXPECT_TRUE(pipeline.capture(image));
    EXPECT_EQ(pipeline.ownership.state(), resource_state_e::legacy);
  }

  TEST(FusedD3D11TransitionIntegration, DeviceIdentityFailureRollsBackBeforeResourceBinding) {
    fake_pipeline_t pipeline;
    pipeline.device.identity_matches = false;
    EXPECT_FALSE(pipeline.initialize_fused());
    EXPECT_EQ(pipeline.ownership.state(), resource_state_e::unset);
    EXPECT_EQ(pipeline.ownership.images(), 0u);
  }

  TEST(FusedD3D11TransitionIntegration, FrameFailureWaitsForConsumersAndImagesBeforeReset) {
    fake_pipeline_t pipeline;
    ASSERT_TRUE(pipeline.initialize_fused());
    {
      fake_image_t image;
      ASSERT_TRUE(pipeline.capture(image));
      ASSERT_TRUE(pipeline.ownership.request_reinit());
      EXPECT_FALSE(pipeline.ownership.reset_after_reinit());
      EXPECT_TRUE(pipeline.ownership.release_consumer(resource_mode_e::fused));
      EXPECT_FALSE(pipeline.ownership.reset_after_reinit());
    }
    EXPECT_TRUE(pipeline.ownership.reset_after_reinit());
    EXPECT_EQ(pipeline.ownership.state(), resource_state_e::unset);
  }

  TEST(FusedD3D11TransitionIntegration, MapFailureRequestsReinitBeforeTeardown) {
    expect_encode_failure_requests_reinit(fake_nvenc_failure_e::map_input);
  }

  TEST(FusedD3D11TransitionIntegration, EncodeOrAsyncWaitFailureRequestsReinitBeforeTeardown) {
    expect_encode_failure_requests_reinit(fake_nvenc_failure_e::encode_picture);
  }

  TEST(FusedD3D11TransitionIntegration, LockFailureRequestsReinitBeforeTeardown) {
    expect_encode_failure_requests_reinit(fake_nvenc_failure_e::lock_bitstream);
  }
}  // namespace
