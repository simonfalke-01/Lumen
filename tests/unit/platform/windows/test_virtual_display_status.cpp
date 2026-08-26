/**
 * @file tests/unit/platform/windows/test_virtual_display_status.cpp
 * @brief Tests for generation-scoped Lumen VDD dashboard state.
 */

#include <gtest/gtest.h>

#include "src/platform/windows/virtual_display_driver/LumenVirtualDisplayProtocol.h"
#include "src/platform/windows/virtual_display_status.h"

namespace {
  using namespace platf::virtual_display;
}

TEST(VirtualDisplayStatus, LiveSnapshotPreservesStatusInvariants) {
  const auto status = query_system_status();
  EXPECT_FALSE(status.direct_frame_bound && status.fallback);
  EXPECT_FALSE(status.fallback && status.direct_frame_quarantined);
  if (!status.installed) {
    EXPECT_FALSE(status.compatible);
  }
  if (status.active) {
    EXPECT_NE(status.active->generation, 0U);
    EXPECT_NE(status.active->mode.width, 0U);
    EXPECT_NE(status.active->mode.height, 0U);
    EXPECT_NE(status.active->mode.refresh.numerator, 0U);
    EXPECT_NE(status.active->mode.refresh.denominator, 0U);
    EXPECT_TRUE(
      status.active->delivery_policy == delivery_policy_e::latency ||
      status.active->delivery_policy == delivery_policy_e::quality
    );
  } else {
    EXPECT_FALSE(status.direct_frame_bound);
    EXPECT_FALSE(status.fallback);
  }
  EXPECT_FALSE(status.diagnostic.empty());
}

TEST(VirtualDisplayStatus, InactiveDriverStateHasNoPolicyPlaceholder) {
  const driver_state_t state;
  EXPECT_FALSE(state.delivery_policy.has_value());
  EXPECT_EQ(
    static_cast<std::uint8_t>(delivery_policy_e::latency),
    LUMEN_VDD_POLICY_LATENCY
  );
  EXPECT_EQ(
    static_cast<std::uint8_t>(delivery_policy_e::quality),
    LUMEN_VDD_POLICY_QUALITY
  );
}

TEST(VirtualDisplayStatus, ActiveUnboundCaptureIsUnavailableInsteadOfHealthy) {
  EXPECT_EQ(classify_capture_path(false, {}), capture_path_status_e::inactive);
  EXPECT_EQ(classify_capture_path(true, {}), capture_path_status_e::unavailable);
  EXPECT_EQ(classify_capture_path(true, {true, false, false}), capture_path_status_e::direct);
  EXPECT_EQ(classify_capture_path(true, {false, false, true}), capture_path_status_e::fallback);
  EXPECT_EQ(classify_capture_path(true, {true, true, true}), capture_path_status_e::quarantined);
}

TEST(VirtualDisplayStatus, DirectFrameStateIsGenerationScopedAndAbaSafe) {
  report_direct_frame_bound(41);
  EXPECT_TRUE(direct_frame_status_for_generation(41).bound);
  EXPECT_FALSE(direct_frame_status_for_generation(42).bound);

  report_direct_frame_bound(42);
  report_direct_frame_stopped(41, true);
  EXPECT_TRUE(direct_frame_status_for_generation(42).bound);
  EXPECT_FALSE(direct_frame_status_for_generation(42).quarantined);
  EXPECT_FALSE(direct_frame_status_for_generation(42).fallback);

  report_direct_frame_stopped(42, true);
  const auto failed = direct_frame_status_for_generation(42);
  EXPECT_FALSE(failed.bound);
  EXPECT_TRUE(failed.quarantined);
  EXPECT_FALSE(failed.fallback);

  report_direct_frame_stopped(42, false);
  EXPECT_TRUE(direct_frame_status_for_generation(42).quarantined);

  report_direct_frame_bound(43);
  const auto recovered = direct_frame_status_for_generation(43);
  EXPECT_TRUE(recovered.bound);
  EXPECT_FALSE(recovered.quarantined);
  EXPECT_FALSE(direct_frame_status_for_generation(42).quarantined);
  report_direct_frame_stopped(43, false);
}

TEST(VirtualDisplayStatus, FailedSourceReportsFallbackOnlyForItsActiveGeneration) {
  report_direct_frame_fallback(51);
  const auto fallback = direct_frame_status_for_generation(51);
  EXPECT_FALSE(fallback.bound);
  EXPECT_FALSE(fallback.quarantined);
  EXPECT_TRUE(fallback.fallback);

  EXPECT_FALSE(direct_frame_status_for_generation(0).fallback);
  EXPECT_FALSE(direct_frame_status_for_generation(52).fallback);

  report_direct_frame_bound(52);
  EXPECT_FALSE(direct_frame_status_for_generation(51).fallback);
  EXPECT_TRUE(direct_frame_status_for_generation(52).bound);
  report_direct_frame_stopped(52, false);
}

TEST(VirtualDisplayStatus, ExplicitQuarantineOnlyMarksTheCurrentGeneration) {
  report_direct_frame_quarantined();
  EXPECT_FALSE(direct_frame_status_for_generation(0).quarantined);

  report_direct_frame_bound(73);
  report_direct_frame_quarantined();
  const auto status = direct_frame_status_for_generation(73);
  EXPECT_FALSE(status.bound);
  EXPECT_TRUE(status.quarantined);
  report_direct_frame_bound(74);
  report_direct_frame_stopped(74, false);
}
