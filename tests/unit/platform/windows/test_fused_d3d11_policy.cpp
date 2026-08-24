/**
 * @file tests/unit/platform/windows/test_fused_d3d11_policy.cpp
 * @brief Tests for the pure experimental fused D3D11 policy and lifetime model.
 */

// lib includes
#include <gtest/gtest.h>

// standard includes
#include <atomic>
#include <barrier>
#include <thread>

// local includes
#include "src/platform/windows/fused_d3d11_policy.h"

namespace {
  using namespace platf::dxgi::fused_d3d11;

  /**
   * @brief Construct a fully eligible baseline request.
   *
   * @return Eligible fused-path request.
   */
  eligibility_t eligible_request() {
    eligibility_t request;
    request.runtime_gate_enabled = true;
    request.hardware_validated = true;
    request.native_nvenc = true;
    request.adapter_is_nvidia = true;
    request.adapter_identity_matches = true;
    request.adapter_model_matches = true;
    request.driver_matches = true;
    request.com_device_matches = true;
    request.probe_baseline_matches = true;
    request.output_matches = true;
    request.surface_format = surface_format_e::nv12;
    return request;
  }

  TEST(FusedD3D11Policy, AcceptsExplicitlyValidatedSdrNv12AndP010Requests) {
    auto request = eligible_request();
    EXPECT_EQ(evaluate(request).rejection, rejection_e::none);
    EXPECT_TRUE(evaluate(request).eligible);

    request.surface_format = surface_format_e::p010;
    EXPECT_TRUE(evaluate(request).eligible);
  }

  TEST(FusedD3D11Policy, FallsBackForEveryUnvalidatedBoundary) {
    auto request = eligible_request();

    request.runtime_gate_enabled = false;
    EXPECT_EQ(evaluate(request).rejection, rejection_e::runtime_gate_disabled);
    request.runtime_gate_enabled = true;

    request.runtime_quarantined = true;
    EXPECT_EQ(evaluate(request).rejection, rejection_e::runtime_quarantined);
    request.runtime_quarantined = false;

    request.hardware_validated = false;
    EXPECT_EQ(evaluate(request).rejection, rejection_e::hardware_not_validated);
    request.hardware_validated = true;

    request.native_nvenc = false;
    EXPECT_EQ(evaluate(request).rejection, rejection_e::non_native_nvenc);
    request.native_nvenc = true;

    request.surface_format = surface_format_e::unsupported;
    EXPECT_EQ(evaluate(request).rejection, rejection_e::unsupported_surface_format);
    request.surface_format = surface_format_e::nv12;

    request.hdr = true;
    EXPECT_EQ(evaluate(request).rejection, rejection_e::hdr_not_validated);
    request.hdr = false;

    request.adapter_is_nvidia = false;
    EXPECT_EQ(evaluate(request).rejection, rejection_e::adapter_not_nvidia);
    request.adapter_is_nvidia = true;

    request.adapter_identity_matches = false;
    EXPECT_EQ(evaluate(request).rejection, rejection_e::adapter_identity_mismatch);
    request.adapter_identity_matches = true;

    request.adapter_model_matches = false;
    EXPECT_EQ(evaluate(request).rejection, rejection_e::adapter_model_mismatch);
    request.adapter_model_matches = true;

    request.driver_matches = false;
    EXPECT_EQ(evaluate(request).rejection, rejection_e::driver_mismatch);
    request.driver_matches = true;

    request.com_device_matches = false;
    EXPECT_EQ(evaluate(request).rejection, rejection_e::com_device_mismatch);
    request.com_device_matches = true;

    request.probe_baseline_matches = false;
    EXPECT_EQ(evaluate(request).rejection, rejection_e::probe_baseline_mismatch);
    request.probe_baseline_matches = true;

    request.output_matches = false;
    EXPECT_EQ(evaluate(request).rejection, rejection_e::output_mismatch);
  }

  TEST(FusedD3D11Policy, RejectionStringsRemainStableAndComplete) {
    EXPECT_EQ(rejection_string(rejection_e::none), "eligible");
    EXPECT_EQ(rejection_string(rejection_e::runtime_gate_disabled), "runtime gate disabled");
    EXPECT_EQ(rejection_string(rejection_e::hardware_not_validated), "hardware validation acknowledgement missing");
    EXPECT_EQ(rejection_string(rejection_e::non_native_nvenc), "native D3D11 NVENC is not selected");
    EXPECT_EQ(rejection_string(rejection_e::unsupported_surface_format), "surface format is not NV12 or P010");
    EXPECT_EQ(rejection_string(rejection_e::hdr_not_validated), "HDR fused conversion is not hardware validated");
    EXPECT_EQ(rejection_string(rejection_e::adapter_not_nvidia), "capture adapter is not NVIDIA");
    EXPECT_EQ(rejection_string(rejection_e::adapter_identity_mismatch), "adapter LUID or PCI identity differs");
    EXPECT_EQ(rejection_string(rejection_e::adapter_model_mismatch), "exact adapter model differs");
    EXPECT_EQ(rejection_string(rejection_e::driver_mismatch), "active driver does not match the validated driver");
    EXPECT_EQ(rejection_string(rejection_e::com_device_mismatch), "capture device and immediate-context COM identities differ");
    EXPECT_EQ(rejection_string(rejection_e::probe_baseline_mismatch), "opened display differs from encoder probe baseline");
    EXPECT_EQ(rejection_string(rejection_e::output_mismatch), "capture output identity differs");
    EXPECT_EQ(rejection_string(rejection_e::runtime_quarantined), "fused path quarantined after a prior failure");
    EXPECT_EQ(rejection_string(rejection_e::unknown), "unknown rejection");
  }

  TEST(FusedD3D11Lifetime, ReleasesSourceOnlyAfterCommandsAreSubmitted) {
    submission_lifetime_t lifetime;
    EXPECT_EQ(lifetime.state(), submission_state_e::inactive);
    EXPECT_FALSE(lifetime.begin_conversion());
    EXPECT_FALSE(lifetime.mark_commands_submitted());
    EXPECT_FALSE(lifetime.release_source());

    EXPECT_TRUE(lifetime.enable());
    EXPECT_TRUE(lifetime.enable());
    EXPECT_TRUE(lifetime.begin_conversion());
    EXPECT_EQ(lifetime.state(), submission_state_e::source_borrowed);
    EXPECT_FALSE(lifetime.begin_conversion());
    EXPECT_FALSE(lifetime.release_source());
    EXPECT_TRUE(lifetime.mark_commands_submitted());
    EXPECT_EQ(lifetime.state(), submission_state_e::commands_submitted);
    EXPECT_FALSE(lifetime.mark_commands_submitted());
    EXPECT_TRUE(lifetime.release_source());
    EXPECT_EQ(lifetime.state(), submission_state_e::idle);
  }

  TEST(FusedD3D11Lifetime, FaultRequiresEncoderReinitialization) {
    submission_lifetime_t lifetime;
    ASSERT_TRUE(lifetime.enable());
    ASSERT_TRUE(lifetime.begin_conversion());
    lifetime.fail();
    EXPECT_EQ(lifetime.state(), submission_state_e::faulted);
    EXPECT_FALSE(lifetime.enable());
    EXPECT_FALSE(lifetime.begin_conversion());
    EXPECT_FALSE(lifetime.mark_commands_submitted());
    EXPECT_FALSE(lifetime.release_source());
  }

  TEST(FusedD3D11Lifetime, CompletionFailureReinitializesOnlyForFusedRollback) {
    EXPECT_EQ(classify_capture_failure(false), capture_failure_e::terminal_error);
    EXPECT_EQ(classify_capture_failure(true), capture_failure_e::reinitialize);
  }

  TEST(FusedD3D11Lifetime, TransitionCommitBindDrainAndResetAreOrdered) {
    resource_ownership_t fused;
    EXPECT_EQ(fused.mode(), resource_mode_e::unset);
    EXPECT_EQ(fused.state(), resource_state_e::unset);
    EXPECT_EQ(fused.consumers(), 0u);
    EXPECT_EQ(fused.begin_transition(resource_mode_e::unset), transition_result_e::rejected);
    EXPECT_EQ(fused.begin_transition(resource_mode_e::fused), transition_result_e::started);
    EXPECT_EQ(fused.state(), resource_state_e::transitioning_fused);
    EXPECT_FALSE(fused.acquire_consumer(resource_mode_e::fused));
    EXPECT_FALSE(fused.bind_image(resource_mode_e::fused));
    EXPECT_FALSE(fused.commit_transition(resource_mode_e::legacy));
    EXPECT_FALSE(fused.rollback_transition(resource_mode_e::legacy));
    EXPECT_TRUE(fused.commit_transition(resource_mode_e::fused));
    EXPECT_EQ(fused.begin_transition(resource_mode_e::fused), transition_result_e::already_committed);
    EXPECT_TRUE(fused.acquire_consumer(resource_mode_e::fused));
    EXPECT_TRUE(fused.bind_image(resource_mode_e::fused));
    EXPECT_EQ(fused.mode(), resource_mode_e::fused);
    EXPECT_EQ(fused.consumers(), 1u);
    EXPECT_EQ(fused.images(), 1u);
    EXPECT_EQ(fused.begin_transition(resource_mode_e::legacy), transition_result_e::rejected);
    EXPECT_TRUE(fused.request_reinit());
    EXPECT_TRUE(fused.reinit_required());
    EXPECT_FALSE(fused.reset_after_reinit());
    EXPECT_TRUE(fused.release_consumer(resource_mode_e::fused));
    EXPECT_FALSE(fused.reset_after_reinit());
    EXPECT_TRUE(fused.release_image());
    EXPECT_FALSE(fused.release_image());
    EXPECT_TRUE(fused.reset_after_reinit());
    EXPECT_EQ(fused.consumers(), 0u);
    EXPECT_EQ(fused.images(), 0u);
    EXPECT_EQ(fused.mode(), resource_mode_e::unset);

    resource_ownership_t legacy;
    EXPECT_EQ(legacy.begin_transition(resource_mode_e::legacy), transition_result_e::started);
    EXPECT_TRUE(legacy.rollback_transition(resource_mode_e::legacy));
    EXPECT_EQ(legacy.state(), resource_state_e::unset);
    EXPECT_EQ(legacy.begin_transition(resource_mode_e::legacy), transition_result_e::started);
    EXPECT_TRUE(legacy.commit_transition(resource_mode_e::legacy));
    EXPECT_TRUE(legacy.acquire_consumer(resource_mode_e::legacy));
    EXPECT_EQ(legacy.mode(), resource_mode_e::legacy);
    EXPECT_EQ(legacy.consumers(), 1u);
    EXPECT_FALSE(legacy.request_reinit());
    EXPECT_TRUE(legacy.release_consumer(resource_mode_e::legacy));
  }

  TEST(FusedD3D11Telemetry, RecordsStageTimestampsAndRemovedBoundaryCounts) {
    telemetry_t counters;
    const auto before = counters.snapshot();
    EXPECT_EQ(before.eligibility_attempts, 0u);
    EXPECT_EQ(before.last_nvenc_map_call_entry_ns, 0u);

    counters.record_eligibility_attempt();
    counters.record_fused_activation();
    counters.record_legacy_fallback();
    counters.record_capture_acquired();
    counters.record_capture_copy_submitted();
    counters.record_shared_handle_open();
    counters.record_keyed_mutex_acquire();
    counters.record_conversion_begin();
    counters.record_conversion_submitted();
    (void) counters.record_nvenc_map_call_entry({}, 0, 123);
    counters.record_nvenc_map_failure();
    counters.record_nvenc_wait_timeout();
    counters.record_nvenc_lock_failure();
    counters.record_vdd_driver_copy(19, 250);
    counters.record_vdd_host_wait(19, 125);

    const auto after = counters.snapshot();
    EXPECT_EQ(after.eligibility_attempts, 1u);
    EXPECT_EQ(after.fused_activations, 1u);
    EXPECT_EQ(after.legacy_fallbacks, 1u);
    EXPECT_EQ(after.capture_copy_submissions, 1u);
    EXPECT_EQ(after.shared_handle_opens, 1u);
    EXPECT_EQ(after.keyed_mutex_acquires, 1u);
    EXPECT_EQ(after.fused_conversion_submissions, 1u);
    EXPECT_GT(after.last_capture_acquired_ns, 0u);
    EXPECT_GT(after.last_capture_copy_submitted_ns, 0u);
    EXPECT_GT(after.last_conversion_begin_ns, 0u);
    EXPECT_GT(after.last_conversion_submitted_ns, 0u);
    EXPECT_EQ(after.last_nvenc_map_call_entry_ns, 123u);
    EXPECT_GT(telemetry_t::now_ns(), 0u);
    EXPECT_NE(&telemetry(), nullptr);
    EXPECT_EQ(after.vdd_generation, 19u);
    EXPECT_EQ(after.vdd_acquire_to_producer_signal.p50_ns, 250u);
    EXPECT_EQ(after.vdd_producer_signal_to_host_wait.p50_ns, 125u);
  }

  TEST(FusedD3D11Telemetry, CorrelatesExactFrameStagesIntoBoundedPercentiles) {
    telemetry_t telemetry;
    const auto session = telemetry.begin_frame_session();
    const auto generation = session.generation;
    const auto capture = telemetry.begin_capture_frame(50, 100, 110);
    ASSERT_TRUE(static_cast<bool>(capture));

    const auto conversion = telemetry.begin_conversion_frame(capture, session);
    ASSERT_TRUE(static_cast<bool>(conversion));
    telemetry.record_conversion_work_begin(conversion, 120);
    telemetry.finish_conversion_frame(conversion, 130);
    const auto nvenc = telemetry.record_nvenc_map_call_entry(conversion, 7, 140);
    ASSERT_EQ(nvenc, conversion);
    telemetry.record_nvenc_wait_lock_begin(nvenc, 150);
    telemetry.record_nvenc_bitstream_locked(nvenc, 170);
    EXPECT_TRUE(telemetry.record_sender_dequeue(7, 50, 200));

    const auto snapshot = telemetry.snapshot(session);
    EXPECT_EQ(snapshot.frame_generation, generation);
    EXPECT_EQ(snapshot.correlation_misses, 0u);
    EXPECT_EQ(snapshot.capture_acquired_to_output_ready.sample_count, 1u);
    EXPECT_EQ(snapshot.capture_acquired_to_output_ready.p50_ns, 10u);
    EXPECT_EQ(snapshot.output_ready_to_conversion_work_begin.p99_ns, 10u);
    EXPECT_EQ(snapshot.conversion_work_begin_to_commands_submitted.p99_ns, 10u);
    EXPECT_EQ(snapshot.conversion_commands_to_nvenc_map_call.p99_ns, 10u);
    EXPECT_EQ(snapshot.nvenc_wait_and_bitstream_lock.p99_ns, 20u);
    EXPECT_EQ(snapshot.bitstream_lock_to_sender_dequeue.p99_ns, 30u);
    EXPECT_EQ(snapshot.capture_acquired_to_sender_dequeue.p99_ns, 100u);
    const auto completed = telemetry.completed_frame(session, 7, 50);
    ASSERT_TRUE(completed.has_value());
    EXPECT_EQ(completed->correlation_id, conversion);
    EXPECT_EQ(completed->profile, telemetry_profile_e::unknown);
    EXPECT_EQ(completed->capture_acquired_ns, 100u);
    EXPECT_EQ(completed->capture_output_ready_ns, 110u);
    EXPECT_EQ(completed->conversion_work_begin_ns, 120u);
    EXPECT_EQ(completed->conversion_commands_submitted_ns, 130u);
    EXPECT_EQ(completed->nvenc_map_call_entry_ns, 140u);
    EXPECT_EQ(completed->nvenc_wait_lock_begin_ns, 150u);
    EXPECT_EQ(completed->bitstream_locked_ns, 170u);
    EXPECT_EQ(completed->sender_dequeue_ns, 200u);
    EXPECT_FALSE(completed->clock_error_bound_ns.has_value());
  }

  TEST(FusedD3D11Telemetry, GenerationResetRejectsStaleTraceWithoutContamination) {
    telemetry_t telemetry;
    const auto old_session = telemetry.begin_frame_session();
    auto parent = telemetry.begin_capture_frame(50, 100, 110);
    const auto stale = telemetry.begin_conversion_frame(parent, old_session);
    ASSERT_TRUE(static_cast<bool>(stale));
    telemetry.record_conversion_work_begin(stale, 120);
    telemetry.finish_conversion_frame(stale, 130);

    telemetry.retire_frame_session(old_session);
    const auto new_session = telemetry.begin_frame_session();
    EXPECT_GT(new_session.generation, old_session.generation);
    EXPECT_FALSE(static_cast<bool>(telemetry.record_nvenc_map_call_entry(stale, 7, 140)));

    const auto snapshot = telemetry.snapshot(new_session);
    EXPECT_EQ(snapshot.frame_generation, new_session.generation);
    EXPECT_EQ(snapshot.capture_acquired_to_output_ready.sample_count, 0u);
    telemetry.release_capture_frame_token(parent);
  }

  TEST(FusedD3D11Telemetry, PercentilesUseNearestRankWithinFixedCapacity) {
    bounded_latency_window_t<100> samples;
    for (std::uint64_t value = 1; value <= 100; ++value) {
      samples.record(9, value);
    }

    const auto summary = samples.snapshot(9);
    EXPECT_EQ(summary.sample_count, 100u);
    EXPECT_EQ(summary.p50_ns, 50u);
    EXPECT_EQ(summary.p95_ns, 95u);
    EXPECT_EQ(summary.p99_ns, 99u);
    EXPECT_EQ(samples.snapshot(10).sample_count, 0u);
  }

  TEST(FusedD3D11Telemetry, ModeSwitchStartsAnEmptyNonAggregatedGeneration) {
    telemetry_t telemetry;
    const auto latency = telemetry.begin_frame_session(
      telemetry_profile_e::latency,
      telemetry_client_e::umbra_legacy
    );
    auto latency_owner = telemetry.begin_capture_frame(50, 100, 110);
    const auto latency_child = telemetry.begin_conversion_frame(latency_owner, latency);
    EXPECT_EQ(telemetry.snapshot(latency).profile, telemetry_profile_e::latency);
    EXPECT_EQ(telemetry.snapshot(latency).client, telemetry_client_e::umbra_legacy);
    EXPECT_EQ(telemetry.snapshot(latency).capture_acquired_to_output_ready.sample_count, 1u);

    const auto quality = telemetry.begin_frame_session(
      telemetry_profile_e::quality,
      telemetry_client_e::vanilla_legacy
    );
    EXPECT_EQ(telemetry.snapshot(quality).profile, telemetry_profile_e::quality);
    EXPECT_EQ(telemetry.snapshot(quality).client, telemetry_client_e::vanilla_legacy);
    EXPECT_EQ(telemetry.snapshot(quality).capture_acquired_to_output_ready.sample_count, 0u);
    const auto v2 = telemetry.begin_frame_session(
      telemetry_profile_e::quality,
      telemetry_client_e::umbra_v2
    );
    EXPECT_EQ(telemetry.snapshot(v2).client, telemetry_client_e::umbra_v2);
    EXPECT_EQ(telemetry.snapshot(v2).capture_acquired_to_output_ready.sample_count, 0u);
    telemetry.abandon_frame_trace(latency_child);
    telemetry.release_capture_frame_token(latency_owner);
    telemetry.retire_frame_session(latency);
    telemetry.retire_frame_session(quality);
    telemetry.retire_frame_session(v2);
  }

  TEST(FusedD3D11Telemetry, ClassifiesExactNegotiatedClientProtocolWithoutInference) {
    EXPECT_EQ(
      telemetry_profile_for(stream_policy::StreamOptimizationMode::legacy),
      telemetry_profile_e::unknown
    );
    EXPECT_EQ(
      telemetry_profile_for(stream_policy::StreamOptimizationMode::latency),
      telemetry_profile_e::latency
    );
    EXPECT_EQ(
      telemetry_profile_for(stream_policy::StreamOptimizationMode::quality),
      telemetry_profile_e::quality
    );
    EXPECT_EQ(
      telemetry_client_for(stream_policy::ClientProtocol::vanilla),
      telemetry_client_e::vanilla_legacy
    );
    EXPECT_EQ(
      telemetry_client_for(stream_policy::ClientProtocol::third_party_extension),
      telemetry_client_e::third_party_extension
    );
    EXPECT_EQ(
      telemetry_client_for(stream_policy::ClientProtocol::umbra_legacy),
      telemetry_client_e::umbra_legacy
    );
    EXPECT_EQ(
      telemetry_client_for(stream_policy::ClientProtocol::umbra_v2),
      telemetry_client_e::umbra_v2
    );
    EXPECT_EQ(
      telemetry_client_for(stream_policy::ClientProtocol::umbra_v3),
      telemetry_client_e::umbra_v3
    );
  }

  TEST(FusedD3D11Telemetry, DisabledFrameTelemetryDoesNoCorrelatedWork) {
    telemetry_t telemetry;
    telemetry.set_frame_telemetry_enabled(false);
    EXPECT_FALSE(static_cast<bool>(telemetry.begin_capture_frame(50, 100, 110)));
    EXPECT_FALSE(telemetry.record_sender_dequeue(7, 50, 200));
    const auto snapshot = telemetry.snapshot();
    EXPECT_EQ(snapshot.correlation_misses, 0u);
    EXPECT_EQ(snapshot.capture_acquired_to_output_ready.sample_count, 0u);
  }

  TEST(FusedD3D11Telemetry, AmbiguousConcurrentEncoderBindingFailsClosed) {
    telemetry_t telemetry;
    const auto session = telemetry.begin_frame_session();

    const auto first_capture = telemetry.begin_capture_frame(50, 100, 110);
    const auto first = telemetry.begin_conversion_frame(first_capture, session);
    telemetry.record_conversion_work_begin(first, 120);
    telemetry.finish_conversion_frame(first, 130);
    const auto first_bound = telemetry.record_nvenc_map_call_entry(first, 7, 140);
    telemetry.record_nvenc_wait_lock_begin(first_bound, 150);
    telemetry.record_nvenc_bitstream_locked(first_bound, 160);

    const auto second_capture = telemetry.begin_capture_frame(50, 101, 111);
    const auto second = telemetry.begin_conversion_frame(second_capture, session);
    telemetry.record_conversion_work_begin(second, 121);
    telemetry.finish_conversion_frame(second, 131);
    const auto second_bound = telemetry.record_nvenc_map_call_entry(second, 7, 141);
    telemetry.record_nvenc_wait_lock_begin(second_bound, 151);
    telemetry.record_nvenc_bitstream_locked(second_bound, 161);

    EXPECT_FALSE(telemetry.record_sender_dequeue(7, 50, 200));
    EXPECT_EQ(telemetry.snapshot(session).bitstream_lock_to_sender_dequeue.sample_count, 0u);
    EXPECT_EQ(telemetry.snapshot(session).binding_collisions, 1u);
    EXPECT_EQ(telemetry.snapshot(session).omitted_encoder_children, 2u);
  }

  TEST(FusedD3D11Telemetry, CaptureOwnerOverwriteRecoversBeyondTraceCapacity) {
    telemetry_t telemetry;
    const auto session = telemetry.begin_frame_session();
    frame_trace_token_t owner;
    for (std::uint64_t index = 0; index < 700; ++index) {
      const auto replacement = telemetry.begin_capture_frame(1'000 + index, 10'000 + index, 10'001 + index);
      ASSERT_TRUE(static_cast<bool>(replacement));
      telemetry.replace_capture_frame_token(owner, replacement);
    }

    const auto child = telemetry.begin_conversion_frame(owner, session);
    ASSERT_TRUE(static_cast<bool>(child));
    telemetry.record_conversion_work_begin(child, 20'000);
    telemetry.finish_conversion_frame(child, 20'001);
    telemetry.release_capture_frame_token(owner);

    const auto snapshot = telemetry.snapshot(session);
    EXPECT_EQ(snapshot.capture_tokens_abandoned, 700u);
    EXPECT_EQ(snapshot.omitted_encoder_children, 0u);
  }

  TEST(FusedD3D11Telemetry, CaptureParentSupportsFourBoundedEncoderChildren) {
    telemetry_t telemetry;
    const auto session = telemetry.begin_frame_session();
    auto capture = telemetry.begin_capture_frame(50, 100, 110);
    for (std::uint64_t child_index = 0; child_index < 4; ++child_index) {
      const auto child = telemetry.begin_conversion_frame(capture, session);
      ASSERT_TRUE(static_cast<bool>(child));
      telemetry.record_conversion_work_begin(child, 120 + child_index);
      telemetry.abandon_frame_trace(child);
    }
    EXPECT_FALSE(static_cast<bool>(telemetry.begin_conversion_frame(capture, session)));
    telemetry.release_capture_frame_token(capture);
    EXPECT_EQ(telemetry.snapshot(session).omitted_encoder_children, 1u);
  }

  TEST(FusedD3D11Telemetry, SharedCaptureChildrenKeepModeWindowsAndCountersIndependent) {
    telemetry_t telemetry;
    const auto latency = telemetry.begin_frame_session(
      telemetry_profile_e::latency,
      telemetry_client_e::umbra_legacy
    );
    const auto quality = telemetry.begin_frame_session(
      telemetry_profile_e::quality,
      telemetry_client_e::vanilla_legacy
    );
    auto parent = telemetry.begin_capture_frame(50, 100, 110);
    const auto latency_child = telemetry.begin_conversion_frame(parent, latency);
    const auto quality_child = telemetry.begin_conversion_frame(parent, quality);
    telemetry.record_conversion_work_begin(latency_child, 120);
    telemetry.finish_conversion_frame(latency_child, 130);
    telemetry.record_conversion_work_begin(quality_child, 121);
    telemetry.finish_conversion_frame(quality_child, 141);
    telemetry.record_nvenc_lock_failure(latency_child);

    EXPECT_EQ(telemetry.snapshot(latency).capture_acquired_to_output_ready.sample_count, 1u);
    EXPECT_EQ(telemetry.snapshot(quality).capture_acquired_to_output_ready.sample_count, 1u);
    EXPECT_EQ(telemetry.snapshot(latency).conversion_work_begin_to_commands_submitted.p50_ns, 10u);
    EXPECT_EQ(telemetry.snapshot(quality).conversion_work_begin_to_commands_submitted.p50_ns, 20u);
    EXPECT_EQ(telemetry.snapshot(latency).nvenc_lock_failures, 1u);
    EXPECT_EQ(telemetry.snapshot(quality).nvenc_lock_failures, 0u);

    telemetry.abandon_frame_trace(latency_child);
    telemetry.abandon_frame_trace(quality_child);
    telemetry.release_capture_frame_token(parent);
    telemetry.retire_frame_session(latency);
    telemetry.retire_frame_session(quality);
  }

  TEST(FusedD3D11Telemetry, SameBucketConcurrentBindingsNeverMisattribute) {
    telemetry_t telemetry;
    const auto first_session = telemetry.begin_frame_session(
      telemetry_profile_e::latency,
      telemetry_client_e::umbra_legacy
    );
    const auto second_session = telemetry.begin_frame_session(
      telemetry_profile_e::quality,
      telemetry_client_e::vanilla_legacy
    );
    const auto first_capture = telemetry.begin_capture_frame(256, 100, 110);
    const auto first = telemetry.begin_conversion_frame(first_capture, first_session);
    telemetry.record_conversion_work_begin(first, 120);
    telemetry.finish_conversion_frame(first, 130);
    const auto second_capture = telemetry.begin_capture_frame(512, 101, 111);
    const auto second = telemetry.begin_conversion_frame(second_capture, second_session);
    telemetry.record_conversion_work_begin(second, 121);
    telemetry.finish_conversion_frame(second, 131);

    std::barrier start {3};
    std::barrier bindings_complete {2};
    std::atomic<unsigned> successful_dequeues {0};
    auto run = [&](frame_trace_token_t token, std::uint64_t frame_index, std::uint64_t source_timestamp) {
      start.arrive_and_wait();
      const auto bound = telemetry.record_nvenc_map_call_entry(token, frame_index, 140 + frame_index);
      telemetry.record_nvenc_wait_lock_begin(bound, 150 + frame_index);
      telemetry.record_nvenc_bitstream_locked(bound, 160 + frame_index);
      bindings_complete.arrive_and_wait();
      if (telemetry.record_sender_dequeue(frame_index, source_timestamp, 200)) {
        successful_dequeues.fetch_add(1, std::memory_order_relaxed);
      }
    };
    std::thread first_thread {run, first, 1, 256};
    std::thread second_thread {run, second, 2, 512};
    start.arrive_and_wait();
    first_thread.join();
    second_thread.join();

    EXPECT_EQ(successful_dequeues.load(std::memory_order_relaxed), 1u);
    const auto total_samples = telemetry.snapshot(first_session).bitstream_lock_to_sender_dequeue.sample_count +
                               telemetry.snapshot(second_session).bitstream_lock_to_sender_dequeue.sample_count;
    EXPECT_EQ(total_samples, 1u);
    EXPECT_EQ(
      telemetry.snapshot(first_session).binding_collisions + telemetry.snapshot(second_session).binding_collisions,
      2u
    );
    EXPECT_EQ(
      telemetry.snapshot(first_session).omitted_encoder_children + telemetry.snapshot(second_session).omitted_encoder_children,
      1u
    );
  }

  TEST(FusedD3D11Telemetry, ChildOwnerAbandonsUntransferredTrace) {
    telemetry_t telemetry;
    const auto session = telemetry.begin_frame_session();
    auto parent = telemetry.begin_capture_frame(50, 100, 110);
    frame_trace_token_t child;
    {
      frame_trace_owner_t owner {
        telemetry,
        telemetry.begin_conversion_frame(parent, session),
      };
      child = owner.token();
      ASSERT_TRUE(static_cast<bool>(child));
      telemetry.record_conversion_work_begin(child, 120);
      telemetry.finish_conversion_frame(child, 130);
    }
    EXPECT_FALSE(static_cast<bool>(telemetry.record_nvenc_map_call_entry(child, 7, 140)));
    telemetry.release_capture_frame_token(parent);
    telemetry.retire_frame_session(session);
  }

  TEST(FusedD3D11Telemetry, ResetMapRaceReclaimsInFlightChildren) {
    for (int iteration = 0; iteration < 700; ++iteration) {
      telemetry_t telemetry;
      const auto session = telemetry.begin_frame_session();
      auto parent = telemetry.begin_capture_frame(50, 100, 110);
      const auto child = telemetry.begin_conversion_frame(parent, session);
      telemetry.record_conversion_work_begin(child, 120);
      telemetry.finish_conversion_frame(child, 130);
      std::barrier start {3};
      std::thread retire {[&] {
        start.arrive_and_wait();
        telemetry.retire_frame_session(session);
      }};
      std::thread map {[&] {
        start.arrive_and_wait();
        (void) telemetry.record_nvenc_map_call_entry(child, 7, 140);
      }};
      start.arrive_and_wait();
      retire.join();
      map.join();
      EXPECT_FALSE(telemetry.record_sender_dequeue(7, 50, 200));
      telemetry.release_capture_frame_token(parent);
    }
  }

  TEST(FusedD3D11Telemetry, OldOwnerCannotReleaseReusedSlotAfterMoreThanCapacity) {
    telemetry_t telemetry;
    const auto old_session = telemetry.begin_frame_session();
    auto old_parent = telemetry.begin_capture_frame(50, 100, 110);
    frame_trace_owner_t old_owner {
      telemetry,
      telemetry.begin_conversion_frame(old_parent, old_session),
    };
    const auto old_token = old_owner.token();
    telemetry.retire_frame_session(old_session);
    telemetry.release_capture_frame_token(old_parent);

    frame_trace_owner_t newest_owner;
    telemetry_session_t newest_session;
    frame_trace_token_t newest_parent;
    for (std::uint64_t index = 0; index < 520; ++index) {
      if (newest_session) {
        newest_owner.reset();
        telemetry.release_capture_frame_token(newest_parent);
        telemetry.retire_frame_session(newest_session);
      }
      newest_session = telemetry.begin_frame_session();
      newest_parent = telemetry.begin_capture_frame(1'000 + index, 2'000 + index, 2'001 + index);
      newest_owner = frame_trace_owner_t {
        telemetry,
        telemetry.begin_conversion_frame(newest_parent, newest_session),
      };
      ASSERT_TRUE(static_cast<bool>(newest_owner));
    }

    const auto newest_token = newest_owner.token();
    EXPECT_NE(newest_token, old_token);
    std::barrier reuse_start {2};
    std::thread old_release {[&] {
      reuse_start.arrive_and_wait();
      old_owner.reset();
    }};
    reuse_start.arrive_and_wait();
    telemetry.record_conversion_work_begin(newest_token, 3'000);
    telemetry.finish_conversion_frame(newest_token, 3'001);
    EXPECT_EQ(
      telemetry.record_nvenc_map_call_entry(newest_token, 9, 3'002),
      newest_token
    );
    old_release.join();
    (void) newest_owner.release();
    telemetry.abandon_frame_trace(newest_token);
    telemetry.release_capture_frame_token(newest_parent);
    telemetry.retire_frame_session(newest_session);
  }
}  // namespace
