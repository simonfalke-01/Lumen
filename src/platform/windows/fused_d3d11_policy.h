/**
 * @file src/platform/windows/fused_d3d11_policy.h
 * @brief Pure policy, lifetime, and telemetry helpers for experimental fused D3D11 encoding.
 */
#pragma once

// standard includes
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <utility>

// local includes
#include "src/stream_policy.h"

namespace platf::dxgi::fused_d3d11 {

  /** @brief Stream objective attached to one isolated telemetry generation. */
  enum class telemetry_profile_e : std::uint8_t {
    unknown = 0,
    latency = 1,
    quality = 2,
  };

  /** @brief Client protocol family attached to one isolated telemetry generation. */
  enum class telemetry_client_e : std::uint8_t {
    vanilla_legacy = 0,  ///< Vanilla Moonlight legacy GameStream client.
    third_party_extension = 1,  ///< Non-Umbra client using an independently negotiated extension.
    umbra_legacy = 2,  ///< Umbra using the legacy GameStream transport.
    umbra_v2 = 3,  ///< Umbra using protocol v2.
    umbra_v3 = 4,  ///< Umbra using protocol v3 over QUIC.
  };

  [[nodiscard]] constexpr telemetry_profile_e telemetry_profile_for(
    stream_policy::StreamOptimizationMode mode
  ) noexcept {
    switch (mode) {
      case stream_policy::StreamOptimizationMode::latency:
        return telemetry_profile_e::latency;
      case stream_policy::StreamOptimizationMode::quality:
        return telemetry_profile_e::quality;
      case stream_policy::StreamOptimizationMode::legacy:
        return telemetry_profile_e::unknown;
    }
    return telemetry_profile_e::unknown;
  }

  [[nodiscard]] constexpr telemetry_client_e telemetry_client_for(
    stream_policy::ClientProtocol protocol
  ) noexcept {
    switch (protocol) {
      case stream_policy::ClientProtocol::vanilla:
        return telemetry_client_e::vanilla_legacy;
      case stream_policy::ClientProtocol::third_party_extension:
        return telemetry_client_e::third_party_extension;
      case stream_policy::ClientProtocol::umbra_legacy:
        return telemetry_client_e::umbra_legacy;
      case stream_policy::ClientProtocol::umbra_v2:
        return telemetry_client_e::umbra_v2;
      case stream_policy::ClientProtocol::umbra_v3:
        return telemetry_client_e::umbra_v3;
    }
    return telemetry_client_e::vanilla_legacy;
  }

  /**
   * @brief Encoder input formats supported by the fused conversion path.
   */
  enum class surface_format_e {
    nv12,  ///< Eight-bit 4:2:0 NVENC input surface.
    p010,  ///< Ten-bit 4:2:0 NVENC input surface.
    unsupported  ///< Format that must use the legacy conversion path.
  };

  /**
   * @brief Reasons why the fused path must fall back to the legacy path.
   */
  enum class rejection_e {
    none,  ///< The request is eligible.
    runtime_gate_disabled,  ///< The explicit experimental runtime gate is disabled.
    hardware_not_validated,  ///< The operator has not acknowledged hardware validation.
    non_native_nvenc,  ///< The encoder does not use native D3D11 NVENC input.
    unsupported_surface_format,  ///< The requested input surface is not NV12 or P010.
    hdr_not_validated,  ///< HDR has not passed the experimental hardware-validation gate.
    adapter_not_nvidia,  ///< The capture adapter is not an NVIDIA adapter.
    adapter_identity_mismatch,  ///< The full adapter identity differs from the validated identity.
    adapter_model_mismatch,  ///< The exact adapter model differs from the validated model.
    driver_mismatch,  ///< The active driver does not match the explicitly validated driver.
    com_device_mismatch,  ///< Capture device and context do not share COM identity.
    probe_baseline_mismatch,  ///< The opened display differs from the recorded probe baseline.
    output_mismatch,  ///< Capture is not bound to the validated output.
    runtime_quarantined,  ///< A prior fused-path failure quarantined the experiment for this process.
    unknown  ///< Sentinel used when an external diagnostic reason is unavailable.
  };

  /**
   * @brief Inputs used to make a fail-closed fused-path decision.
   */
  struct eligibility_t {
    bool runtime_gate_enabled = false;  ///< Whether the operator explicitly enabled the experiment.
    bool hardware_validated = false;  ///< Whether the hardware-validation acknowledgement is present.
    bool native_nvenc = false;  ///< Whether native D3D11 NVENC is selected.
    bool hdr = false;  ///< Whether the stream requires HDR conversion.
    bool adapter_is_nvidia = false;  ///< Whether the capture adapter vendor is NVIDIA.
    bool adapter_identity_matches = false;  ///< Whether LUID and all PCI identity fields exactly match.
    bool adapter_model_matches = false;  ///< Whether the exact adapter description matches.
    bool driver_matches = false;  ///< Whether the current and acknowledged driver versions match.
    bool com_device_matches = false;  ///< Whether device and immediate context resolve to one COM identity.
    bool probe_baseline_matches = false;  ///< Whether current display identity equals the recorded opened baseline.
    bool output_matches = false;  ///< Whether capture remains bound to the selected output.
    bool runtime_quarantined = false;  ///< Whether a prior fused failure disabled further attempts.
    surface_format_e surface_format = surface_format_e::unsupported;  ///< Requested NVENC surface format.
  };

  /**
   * @brief Result of evaluating the fused-path policy.
   */
  struct decision_t {
    bool eligible = false;  ///< Whether the fused path may be attempted.
    rejection_e rejection = rejection_e::runtime_gate_disabled;  ///< Fail-closed rejection reason.
  };

  /**
   * @brief Evaluate experimental fused-path eligibility in fail-closed order.
   *
   * @param request Runtime, hardware, and topology properties to validate.
   * @return Eligibility decision and the first rejection reason.
   */
  [[nodiscard]] constexpr decision_t evaluate(const eligibility_t &request) noexcept {
    if (!request.runtime_gate_enabled) {
      return {false, rejection_e::runtime_gate_disabled};
    }
    if (request.runtime_quarantined) {
      return {false, rejection_e::runtime_quarantined};
    }
    if (!request.hardware_validated) {
      return {false, rejection_e::hardware_not_validated};
    }
    if (!request.native_nvenc) {
      return {false, rejection_e::non_native_nvenc};
    }
    if (request.surface_format == surface_format_e::unsupported) {
      return {false, rejection_e::unsupported_surface_format};
    }
    // HDR remains on the proven legacy path until P010 HDR output is validated on hardware.
    if (request.hdr) {
      return {false, rejection_e::hdr_not_validated};
    }
    if (!request.adapter_is_nvidia) {
      return {false, rejection_e::adapter_not_nvidia};
    }
    if (!request.adapter_identity_matches) {
      return {false, rejection_e::adapter_identity_mismatch};
    }
    if (!request.adapter_model_matches) {
      return {false, rejection_e::adapter_model_mismatch};
    }
    if (!request.driver_matches) {
      return {false, rejection_e::driver_mismatch};
    }
    if (!request.com_device_matches) {
      return {false, rejection_e::com_device_mismatch};
    }
    if (!request.probe_baseline_matches) {
      return {false, rejection_e::probe_baseline_mismatch};
    }
    if (!request.output_matches) {
      return {false, rejection_e::output_mismatch};
    }
    return {true, rejection_e::none};
  }

  /**
   * @brief Return a stable diagnostic string for a rejection reason.
   *
   * @param rejection Rejection reason to describe.
   * @return Static rejection description.
   */
  [[nodiscard]] constexpr std::string_view rejection_string(rejection_e rejection) noexcept {
    switch (rejection) {
      case rejection_e::none:
        return "eligible";
      case rejection_e::runtime_gate_disabled:
        return "runtime gate disabled";
      case rejection_e::hardware_not_validated:
        return "hardware validation acknowledgement missing";
      case rejection_e::non_native_nvenc:
        return "native D3D11 NVENC is not selected";
      case rejection_e::unsupported_surface_format:
        return "surface format is not NV12 or P010";
      case rejection_e::hdr_not_validated:
        return "HDR fused conversion is not hardware validated";
      case rejection_e::adapter_not_nvidia:
        return "capture adapter is not NVIDIA";
      case rejection_e::adapter_identity_mismatch:
        return "adapter LUID or PCI identity differs";
      case rejection_e::adapter_model_mismatch:
        return "exact adapter model differs";
      case rejection_e::driver_mismatch:
        return "active driver does not match the validated driver";
      case rejection_e::com_device_mismatch:
        return "capture device and immediate-context COM identities differ";
      case rejection_e::probe_baseline_mismatch:
        return "opened display differs from encoder probe baseline";
      case rejection_e::output_mismatch:
        return "capture output identity differs";
      case rejection_e::runtime_quarantined:
        return "fused path quarantined after a prior failure";
      case rejection_e::unknown:
        return "unknown rejection";
    }
    return "unknown rejection";
  }

  /**
   * @brief Submission states that prevent premature capture-resource reuse.
   */
  enum class submission_state_e {
    inactive,  ///< Fused submission is not enabled.
    idle,  ///< No source resource is borrowed.
    source_borrowed,  ///< A capture source is retained by the conversion transaction.
    commands_submitted,  ///< Conversion commands were submitted to the shared immediate context.
    faulted  ///< The transaction failed and requires encoder reinitialization.
  };

  /**
   * @brief Pure state machine for capture-resource borrowing and ordered command submission.
   */
  class submission_lifetime_t {
  public:
    /**
     * @brief Enable the state machine before the first fused conversion.
     *
     * @return True when the state machine entered or already was in the idle state.
     */
    bool enable() noexcept {
      if (state_ == submission_state_e::inactive) {
        state_ = submission_state_e::idle;
      }
      return state_ == submission_state_e::idle;
    }

    /**
     * @brief Borrow a capture source for conversion.
     *
     * @return True only when no prior source remains in flight.
     */
    bool begin_conversion() noexcept {
      if (state_ != submission_state_e::idle) {
        return false;
      }
      state_ = submission_state_e::source_borrowed;
      return true;
    }

    /**
     * @brief Mark all source-reading conversion commands as submitted.
     *
     * @return True only when a source was borrowed.
     */
    bool mark_commands_submitted() noexcept {
      if (state_ != submission_state_e::source_borrowed) {
        return false;
      }
      state_ = submission_state_e::commands_submitted;
      return true;
    }

    /**
     * @brief Release the source borrow after ordered command submission.
     *
     * @return True only when commands were submitted before release.
     */
    bool release_source() noexcept {
      if (state_ != submission_state_e::commands_submitted) {
        return false;
      }
      state_ = submission_state_e::idle;
      return true;
    }

    /**
     * @brief Fail the current transaction and prevent further use.
     */
    void fail() noexcept {
      state_ = submission_state_e::faulted;
    }

    /**
     * @brief Read the current submission state.
     *
     * @return Current state.
     */
    [[nodiscard]] submission_state_e state() const noexcept {
      return state_;
    }

  private:
    submission_state_e state_ = submission_state_e::inactive;  ///< Current source-lifetime state.
  };

  /**
   * @brief Sticky display resource modes that cannot be mixed for one capture pool.
   */
  enum class resource_mode_e : std::uint8_t {
    unset = 0,  ///< No encoder has committed the display resource layout.
    fused = 1,  ///< Same-device resources without shared handles or keyed mutexes.
    legacy = 2  ///< Cross-device resources with shared handles and keyed mutexes.
  };

  /**
   * @brief Atomic display ownership and rollback states.
   */
  enum class resource_state_e : std::uint8_t {
    unset,  ///< No capture resource layout has been selected.
    transitioning_fused,  ///< Fused setup exclusively owns the shared context before commit.
    transitioning_legacy,  ///< Legacy setup is in progress before commit.
    fused,  ///< Capture textures are same-device fused resources.
    legacy,  ///< Capture textures are legacy shared resources.
    reinit_required  ///< A fused failure requires capture-pool teardown and reinitialization.
  };

  /**
   * @brief Results returned when beginning an ownership transition.
   */
  enum class transition_result_e {
    started,  ///< The caller owns a new transition and must commit or roll it back.
    already_committed,  ///< The requested mode is already committed.
    rejected  ///< Another mode or reinitialization state blocks the request.
  };

  /** @brief Capture result classification after resource completion fails. */
  enum class capture_failure_e {
    terminal_error,  ///< Failure is unrelated to fused rollback.
    reinitialize  ///< Fused ownership requested capture-pool reinitialization.
  };

  /**
   * @brief Classify a resource completion failure for the capture loop.
   *
   * @param reinit_required Whether fused ownership is reinit-required.
   * @return Reinitialize only for fused rollback; otherwise terminal error.
   */
  [[nodiscard]] constexpr capture_failure_e classify_capture_failure(bool reinit_required) noexcept {
    return reinit_required ? capture_failure_e::reinitialize : capture_failure_e::terminal_error;
  }

  /**
   * @brief Thread-safe transition, resource binding, and rollback state for one capture pool.
   */
  class resource_ownership_t {
  public:
    /**
     * @brief Begin exclusive setup for a resource mode before any device/context use.
     *
     * @param requested Resource mode required by the encoder.
     * @return Started, already committed, or rejected transition result.
     */
    transition_result_e begin_transition(resource_mode_e requested) noexcept {
      if (requested == resource_mode_e::unset) {
        return transition_result_e::rejected;
      }
      const auto committed = requested == resource_mode_e::fused ? resource_state_e::fused : resource_state_e::legacy;
      const auto transitioning = requested == resource_mode_e::fused ? resource_state_e::transitioning_fused : resource_state_e::transitioning_legacy;
      auto expected = resource_state_e::unset;
      if (state_.compare_exchange_strong(expected, transitioning, std::memory_order_acq_rel)) {
        transition_mode_.store(requested, std::memory_order_release);
        return transition_result_e::started;
      }
      return expected == committed ? transition_result_e::already_committed : transition_result_e::rejected;
    }

    /**
     * @brief Commit the transition owned by the caller.
     *
     * @param requested Mode passed to begin_transition().
     * @return True when the matching transition was committed.
     */
    bool commit_transition(resource_mode_e requested) noexcept {
      auto expected = requested == resource_mode_e::fused ? resource_state_e::transitioning_fused : resource_state_e::transitioning_legacy;
      const auto committed = requested == resource_mode_e::fused ? resource_state_e::fused : resource_state_e::legacy;
      return state_.compare_exchange_strong(expected, committed, std::memory_order_acq_rel);
    }

    /**
     * @brief Roll back an uncommitted transition without poisoning the display.
     *
     * @param requested Mode passed to begin_transition().
     * @return True when the matching transition returned to unset.
     */
    bool rollback_transition(resource_mode_e requested) noexcept {
      auto expected = requested == resource_mode_e::fused ? resource_state_e::transitioning_fused : resource_state_e::transitioning_legacy;
      return state_.compare_exchange_strong(expected, resource_state_e::unset, std::memory_order_acq_rel);
    }

    /**
     * @brief Acquire one encoder consumer after the resource mode is committed.
     *
     * @param requested Committed mode required by the encoder.
     * @return True when the requested mode is committed.
     */
    bool acquire_consumer(resource_mode_e requested) noexcept {
      const auto committed = requested == resource_mode_e::fused ? resource_state_e::fused : resource_state_e::legacy;
      if (state() != committed) {
        return false;
      }
      consumers_.fetch_add(1, std::memory_order_acq_rel);
      return true;
    }

    /**
     * @brief Release one consumer without changing the sticky resource mode.
     *
     * @param released Resource mode previously acquired by the encoder.
     * @return True when a matching live consumer was released.
     */
    bool release_consumer(resource_mode_e released) noexcept {
      if (mode() != released) {
        return false;
      }

      auto count = consumers_.load(std::memory_order_acquire);
      while (count != 0) {
        if (consumers_.compare_exchange_weak(count, count - 1, std::memory_order_acq_rel)) {
          return true;
        }
      }
      return false;
    }

    /**
     * @brief Bind one completed capture image to the committed resource layout.
     *
     * @param bound Committed mode used to create the texture.
     * @return True when the image matches the committed layout.
     */
    bool bind_image(resource_mode_e bound) noexcept {
      const auto committed = bound == resource_mode_e::fused ? resource_state_e::fused : resource_state_e::legacy;
      if (state() != committed) {
        return false;
      }
      images_.fetch_add(1, std::memory_order_acq_rel);
      return true;
    }

    /**
     * @brief Release one capture image binding.
     *
     * @return True when one live image binding was released.
     */
    bool release_image() noexcept {
      auto count = images_.load(std::memory_order_acquire);
      while (count != 0) {
        if (images_.compare_exchange_weak(count, count - 1, std::memory_order_acq_rel)) {
          return true;
        }
      }
      return false;
    }

    /**
     * @brief Poison fused ownership and require capture-pool teardown.
     *
     * @return True when fused or transitioning-fused state became reinit-required.
     */
    bool request_reinit() noexcept {
      auto current = state_.load(std::memory_order_acquire);
      while (current == resource_state_e::fused || current == resource_state_e::transitioning_fused) {
        if (state_.compare_exchange_weak(current, resource_state_e::reinit_required, std::memory_order_acq_rel)) {
          return true;
        }
      }
      return current == resource_state_e::reinit_required;
    }

    /**
     * @brief Reset after every encoder consumer and bound capture image is gone.
     *
     * @return True when reinitialization state safely returned to unset.
     */
    bool reset_after_reinit() noexcept {
      if (consumers() != 0 || images() != 0) {
        return false;
      }
      auto expected = resource_state_e::reinit_required;
      return state_.compare_exchange_strong(expected, resource_state_e::unset, std::memory_order_acq_rel);
    }

    /**
     * @brief Read the selected or transitioning resource mode.
     *
     * @return Current display resource mode, or unset.
     */
    [[nodiscard]] resource_mode_e mode() const noexcept {
      switch (state()) {
        case resource_state_e::transitioning_fused:
        case resource_state_e::fused:
          return resource_mode_e::fused;
        case resource_state_e::transitioning_legacy:
        case resource_state_e::legacy:
          return resource_mode_e::legacy;
        case resource_state_e::reinit_required:
          return transition_mode_.load(std::memory_order_acquire);
        case resource_state_e::unset:
          return resource_mode_e::unset;
      }
      return resource_mode_e::unset;
    }

    /** @brief Return the atomic ownership state. */
    [[nodiscard]] resource_state_e state() const noexcept {
      return state_.load(std::memory_order_acquire);
    }

    /**
     * @brief Read the number of currently live encoders using the selected mode.
     *
     * @return Live consumer count.
     */
    [[nodiscard]] std::uint32_t consumers() const noexcept {
      return consumers_.load(std::memory_order_acquire);
    }

    /** @brief Return the number of bound capture images. */
    [[nodiscard]] std::uint32_t images() const noexcept {
      return images_.load(std::memory_order_acquire);
    }

    /** @brief Return whether capture must abort and rebuild its pool. */
    [[nodiscard]] bool reinit_required() const noexcept {
      return state() == resource_state_e::reinit_required;
    }

  private:
    std::atomic<resource_state_e> state_ {resource_state_e::unset};  ///< Atomic transition and rollback state.
    std::atomic<resource_mode_e> transition_mode_ {resource_mode_e::unset};  ///< Mode retained while reinit is pending.
    std::atomic<std::uint32_t> consumers_ {0};  ///< Live encoders using the selected mode.
    std::atomic<std::uint32_t> images_ {0};  ///< Capture textures bound to the selected mode.
  };

  /**
   * @brief Immutable snapshot of fused-path stage timings and boundary counters.
   */
  struct telemetry_snapshot_t {
    std::uint64_t eligibility_attempts = 0;  ///< Number of fused-path eligibility evaluations.
    std::uint64_t fused_activations = 0;  ///< Number of successful fused-path activations.
    std::uint64_t legacy_fallbacks = 0;  ///< Number of requests retained on the legacy path.
    std::uint64_t capture_copy_submissions = 0;  ///< BGRA capture copies submitted by the capture backend.
    std::uint64_t shared_handle_opens = 0;  ///< Legacy shared-handle opens performed by encoders.
    std::uint64_t keyed_mutex_acquires = 0;  ///< Legacy keyed-mutex acquisitions performed by the pipeline.
    std::uint64_t fused_conversion_submissions = 0;  ///< RGB-to-YUV conversion submissions on the fused path.
    std::uint64_t last_capture_acquired_ns = 0;  ///< Most recent capture-acquired steady-clock timestamp.
    std::uint64_t last_capture_copy_submitted_ns = 0;  ///< Most recent capture-copy submission timestamp.
    std::uint64_t last_conversion_begin_ns = 0;  ///< Most recent fused conversion start timestamp.
    std::uint64_t last_conversion_submitted_ns = 0;  ///< Most recent fused conversion submission timestamp.
    std::uint64_t last_nvenc_map_call_entry_ns = 0;  ///< Most recent actual nvEncMapInputResource call-entry timestamp.
    std::uint64_t frame_generation = 0;  ///< Current isolated hot-path telemetry generation.
    telemetry_profile_e profile = telemetry_profile_e::unknown;  ///< Mode whose samples populate this snapshot.
    telemetry_client_e client = telemetry_client_e::vanilla_legacy;  ///< Non-aggregated client protocol family.
    std::uint64_t correlation_misses = 0;  ///< Frames omitted because bounded correlation state was stale or unavailable.
    std::uint64_t capture_tokens_abandoned = 0;  ///< Capture owners explicitly released before encoder transfer.
    std::uint64_t omitted_encoder_children = 0;  ///< Encoder children omitted after bounded or ambiguous correlation.
    std::uint64_t binding_collisions = 0;  ///< Exact-key or hash-bucket collisions handled without misattribution.
    std::uint64_t binding_reservation_failures = 0;  ///< Binding slots that could not be atomically reserved.
    std::uint64_t nvenc_map_failures = 0;  ///< Actual nvEncMapInputResource failures.
    std::uint64_t nvenc_wait_timeouts = 0;  ///< Async NVENC completion waits that timed out.
    std::uint64_t nvenc_lock_failures = 0;  ///< Actual nvEncLockBitstream failures.

    struct latency_percentiles_t {
      std::uint64_t sample_count = 0;  ///< Number of valid samples in the current bounded generation window.
      std::uint64_t p50_ns = 0;  ///< Nearest-rank 50th percentile in nanoseconds.
      std::uint64_t p95_ns = 0;  ///< Nearest-rank 95th percentile in nanoseconds.
      std::uint64_t p99_ns = 0;  ///< Nearest-rank 99th percentile in nanoseconds.

      [[nodiscard]] bool operator==(const latency_percentiles_t &) const noexcept = default;
    };

    latency_percentiles_t capture_acquired_to_output_ready;  ///< Capture API return to encoder-visible image readiness.
    latency_percentiles_t output_ready_to_conversion_work_begin;  ///< Image readiness to per-frame conversion work after cache maintenance.
    latency_percentiles_t conversion_work_begin_to_commands_submitted;  ///< Per-frame conversion work begin to D3D commands submitted.
    latency_percentiles_t conversion_commands_to_nvenc_map_call;  ///< Conversion commands submitted to actual map call entry.
    latency_percentiles_t nvenc_wait_and_bitstream_lock;  ///< Post-encode call return through async wait and lock return.
    latency_percentiles_t bitstream_lock_to_sender_dequeue;  ///< Successful lock return to sender-thread queue dequeue.
    latency_percentiles_t capture_acquired_to_sender_dequeue;  ///< Host software proxy; not scanout or input-to-photon.
    std::uint64_t vdd_generation = 0;  ///< Exact ABI v4 generation for direct-frame stage samples.
    latency_percentiles_t vdd_acquire_to_producer_signal;  ///< IddCx acquisition to producer fence submission.
    latency_percentiles_t vdd_producer_signal_to_host_wait;  ///< Producer fence submission to completed host GPU wait.
  };

  /** @brief Opaque identity for one bounded host hot-path trace. */
  struct frame_trace_token_t {
    std::uint64_t value = 0;

    [[nodiscard]] explicit operator bool() const noexcept {
      return value != 0;
    }

    [[nodiscard]] bool operator==(const frame_trace_token_t &) const noexcept = default;
  };

  /** @brief Immutable per-encoder telemetry identity; never inferred from global or thread-local state. */
  struct telemetry_session_t {
    std::uint64_t generation = 0;
    telemetry_profile_e profile = telemetry_profile_e::unknown;
    telemetry_client_e client = telemetry_client_e::vanilla_legacy;

    [[nodiscard]] explicit operator bool() const noexcept {
      return generation != 0;
    }

    [[nodiscard]] bool operator==(const telemetry_session_t &) const noexcept = default;
  };

  /**
   * @brief One completed host-local frame trace retained for future per-event WAN accounting.
   *
   * All timestamps use this process's `steady_clock`. `clock_error_bound_ns` intentionally remains
   * unavailable until a protocol-level host/client clock calibration supplies a defensible bound.
   */
  struct completed_frame_telemetry_t {
    frame_trace_token_t correlation_id;
    std::uint64_t generation = 0;
    telemetry_profile_e profile = telemetry_profile_e::unknown;
    telemetry_client_e client = telemetry_client_e::vanilla_legacy;
    std::uint64_t frame_index = 0;
    std::uint64_t source_timestamp_ns = 0;
    std::uint64_t capture_acquired_ns = 0;
    std::uint64_t capture_output_ready_ns = 0;
    std::uint64_t conversion_work_begin_ns = 0;
    std::uint64_t conversion_commands_submitted_ns = 0;
    std::uint64_t nvenc_map_call_entry_ns = 0;
    std::uint64_t nvenc_wait_lock_begin_ns = 0;
    std::uint64_t bitstream_locked_ns = 0;
    std::uint64_t sender_dequeue_ns = 0;
    std::optional<std::uint64_t> clock_error_bound_ns;  ///< Never inferred from RTT or percentile summaries.
  };

  /**
   * @brief Fixed-capacity generation-tagged latency samples.
   *
   * Recording is lock-free and performs no allocation. Snapshotting sorts a fixed stack array and
   * filters by generation, so a concurrent generation reset cannot contaminate the next session.
   */
  template<std::size_t Capacity>
  class bounded_latency_window_t {
    static_assert(Capacity > 0);

    struct sample_t {
      std::atomic<std::uint64_t> generation {0};
      std::atomic<std::uint64_t> duration_ns {0};
    };

  public:
    void record(std::uint64_t generation, std::uint64_t duration_ns) noexcept {
      if (generation == 0) {
        return;
      }
      const auto index = cursor_.fetch_add(1, std::memory_order_relaxed) % Capacity;
      auto &sample = samples_[index];
      sample.generation.store(0, std::memory_order_release);
      sample.duration_ns.store(duration_ns, std::memory_order_relaxed);
      sample.generation.store(generation, std::memory_order_release);
    }

    [[nodiscard]] telemetry_snapshot_t::latency_percentiles_t snapshot(std::uint64_t generation) const noexcept {
      if (generation == 0) {
        return {};
      }
      std::array<std::uint64_t, Capacity> values {};
      std::size_t count = 0;
      for (const auto &sample : samples_) {
        if (sample.generation.load(std::memory_order_acquire) == generation) {
          values[count++] = sample.duration_ns.load(std::memory_order_relaxed);
        }
      }
      if (count == 0) {
        return {};
      }
      std::sort(values.begin(), values.begin() + static_cast<std::ptrdiff_t>(count));
      const auto percentile = [&](std::size_t numerator) {
        const auto rank = std::max<std::size_t>(1, (count * numerator + 99) / 100);
        return values[std::min(rank - 1, count - 1)];
      };
      return {
        static_cast<std::uint64_t>(count),
        percentile(50),
        percentile(95),
        percentile(99),
      };
    }

  private:
    std::array<sample_t, Capacity> samples_ {};
    std::atomic<std::uint64_t> cursor_ {0};
  };

  /**
   * @brief Atomic process-local telemetry for the experimental and fallback boundaries.
   */
  class telemetry_t {
    static constexpr std::size_t frame_capacity = 512;
    static constexpr std::size_t session_capacity = 32;

    struct frame_trace_t {
      std::atomic<std::uint64_t> token {0};
      std::atomic<std::uint64_t> generation {0};
      std::atomic<telemetry_profile_e> profile {telemetry_profile_e::unknown};
      std::atomic<telemetry_client_e> client {telemetry_client_e::vanilla_legacy};
      std::atomic<std::uint64_t> source_timestamp_ns {0};
      std::atomic<std::uint64_t> capture_acquired_ns {0};
      std::atomic<std::uint64_t> capture_output_ready_ns {0};
      std::atomic<std::uint64_t> conversion_work_begin_ns {0};
      std::atomic<std::uint64_t> conversion_commands_submitted_ns {0};
      std::atomic<std::uint64_t> nvenc_map_call_entry_ns {0};
      std::atomic<std::uint64_t> nvenc_wait_lock_begin_ns {0};
      std::atomic<std::uint64_t> bitstream_locked_ns {0};
      std::atomic<std::uint64_t> frame_index {0};
      std::atomic<std::uint32_t> remaining_encoder_children {0};
    };

    struct frame_binding_t {
      std::atomic<std::uint64_t> version {0};  ///< Even when stable; odd while exclusively reserved.
      std::atomic<std::uint64_t> token {0};
      std::atomic<std::uint64_t> generation {0};
      std::atomic<std::uint64_t> frame_index {0};
      std::atomic<std::uint64_t> source_timestamp_ns {0};
    };

    struct completed_frame_t {
      std::atomic<std::uint64_t> token {0};
      std::atomic<std::uint64_t> generation {0};
      std::atomic<telemetry_profile_e> profile {telemetry_profile_e::unknown};
      std::atomic<telemetry_client_e> client {telemetry_client_e::vanilla_legacy};
      std::atomic<std::uint64_t> frame_index {0};
      std::atomic<std::uint64_t> source_timestamp_ns {0};
      std::atomic<std::uint64_t> capture_acquired_ns {0};
      std::atomic<std::uint64_t> capture_output_ready_ns {0};
      std::atomic<std::uint64_t> conversion_work_begin_ns {0};
      std::atomic<std::uint64_t> conversion_commands_submitted_ns {0};
      std::atomic<std::uint64_t> nvenc_map_call_entry_ns {0};
      std::atomic<std::uint64_t> nvenc_wait_lock_begin_ns {0};
      std::atomic<std::uint64_t> bitstream_locked_ns {0};
      std::atomic<std::uint64_t> sender_dequeue_ns {0};
    };

    struct session_slot_t {
      std::atomic<std::uint64_t> generation {0};
      std::atomic<telemetry_profile_e> profile {telemetry_profile_e::unknown};
      std::atomic<telemetry_client_e> client {telemetry_client_e::vanilla_legacy};
      std::atomic<std::uint64_t> correlation_misses {0};
      std::atomic<std::uint64_t> omitted_encoder_children {0};
      std::atomic<std::uint64_t> binding_collisions {0};
      std::atomic<std::uint64_t> binding_reservation_failures {0};
      std::atomic<std::uint64_t> nvenc_map_failures {0};
      std::atomic<std::uint64_t> nvenc_wait_timeouts {0};
      std::atomic<std::uint64_t> nvenc_lock_failures {0};
    };

  public:
    /**
     * @brief Return a steady-clock timestamp expressed in nanoseconds.
     *
     * @return Monotonic timestamp in nanoseconds.
     */
    [[nodiscard]] static std::uint64_t now_ns() noexcept {
      return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                          std::chrono::steady_clock::now().time_since_epoch()
      )
                                          .count());
    }

    /** @brief Enable or disable correlated frame telemetry without affecting legacy counters. */
    void set_frame_telemetry_enabled(bool enabled) noexcept {
      frame_telemetry_enabled_.store(enabled, std::memory_order_release);
    }

    /** @brief Record one eligibility evaluation. */
    void record_eligibility_attempt() noexcept {
      ++eligibility_attempts_;
    }

    /** @brief Record one successful fused activation. */
    void record_fused_activation() noexcept {
      ++fused_activations_;
    }

    /** @brief Record one legacy fallback decision. */
    void record_legacy_fallback() noexcept {
      ++legacy_fallbacks_;
    }

    /** @brief Record capture acquisition. */
    void record_capture_acquired() noexcept {
      last_capture_acquired_ns_.store(now_ns(), std::memory_order_relaxed);
    }

    /** @brief Record a submitted BGRA capture copy. */
    void record_capture_copy_submitted() noexcept {
      ++capture_copy_submissions_;
      last_capture_copy_submitted_ns_.store(now_ns(), std::memory_order_relaxed);
    }

    /** @brief Record one exact ABI v4 driver copy/fence-submission duration. */
    void record_vdd_driver_copy(std::uint64_t generation, std::uint64_t duration_ns) noexcept {
      if (generation == 0) {
        return;
      }
      vdd_generation_.store(generation, std::memory_order_release);
      vdd_acquire_to_producer_signal_.record(generation, duration_ns);
    }

    /** @brief Record one exact ABI v4 producer-signal to host-wait duration. */
    void record_vdd_host_wait(std::uint64_t generation, std::uint64_t duration_ns) noexcept {
      if (generation == 0) {
        return;
      }
      vdd_generation_.store(generation, std::memory_order_release);
      vdd_producer_signal_to_host_wait_.record(generation, duration_ns);
    }

    /** @brief Record one legacy shared-handle open. */
    void record_shared_handle_open() noexcept {
      ++shared_handle_opens_;
    }

    /** @brief Record one legacy keyed-mutex acquisition. */
    void record_keyed_mutex_acquire() noexcept {
      ++keyed_mutex_acquires_;
    }

    /** @brief Record the beginning of a fused conversion. */
    void record_conversion_begin() noexcept {
      last_conversion_begin_ns_.store(now_ns(), std::memory_order_relaxed);
    }

    /** @brief Record a submitted fused conversion. */
    void record_conversion_submitted() noexcept {
      ++fused_conversion_submissions_;
      last_conversion_submitted_ns_.store(now_ns(), std::memory_order_relaxed);
    }

    /** @brief Compatibility hook retained for the older fused synchronize boundary. */
    void record_nvenc_map_entry() noexcept {
      // The exact production timestamp is recorded immediately before nvEncMapInputResource().
    }

    /** @brief Reserve one fixed-capacity per-encoder session identity. */
    [[nodiscard]] telemetry_session_t begin_frame_session(
      telemetry_profile_e profile = telemetry_profile_e::unknown,
      telemetry_client_e client = telemetry_client_e::vanilla_legacy
    ) noexcept {
      constexpr std::uint64_t reserved_mask = std::uint64_t {1} << 63;
      for (std::size_t attempt = 0; attempt < session_capacity; ++attempt) {
        const auto generation = frame_generation_.fetch_add(1, std::memory_order_acq_rel) + 1;
        auto &slot = sessions_[generation % session_capacity];
        auto expected = std::uint64_t {0};
        if (!slot.generation.compare_exchange_strong(
              expected,
              generation | reserved_mask,
              std::memory_order_acq_rel
            )) {
          continue;
        }
        slot.profile.store(profile, std::memory_order_relaxed);
        slot.client.store(client, std::memory_order_relaxed);
        slot.correlation_misses.store(0, std::memory_order_relaxed);
        slot.omitted_encoder_children.store(0, std::memory_order_relaxed);
        slot.binding_collisions.store(0, std::memory_order_relaxed);
        slot.binding_reservation_failures.store(0, std::memory_order_relaxed);
        slot.nvenc_map_failures.store(0, std::memory_order_relaxed);
        slot.nvenc_wait_timeouts.store(0, std::memory_order_relaxed);
        slot.nvenc_lock_failures.store(0, std::memory_order_relaxed);
        slot.generation.store(generation, std::memory_order_release);
        latest_session_generation_.store(generation, std::memory_order_release);
        return {generation, profile, client};
      }
      return {};
    }

    /** @brief Retire one encoder session and reclaim every in-flight child or stale binding. */
    void retire_frame_session(telemetry_session_t session) noexcept {
      if (!session) {
        return;
      }
      auto &slot = sessions_[session.generation % session_capacity];
      auto expected = session.generation;
      if (!slot.generation.compare_exchange_strong(expected, 0, std::memory_order_acq_rel)) {
        return;
      }
      for (auto &binding : bindings_) {
        std::uint64_t version = 0;
        if (!reserve_binding(binding, version)) {
          continue;
        }
        const frame_trace_token_t token {binding.token.load(std::memory_order_relaxed)};
        const auto *trace = trace_for(token);
        if (trace &&
            binding.generation.load(std::memory_order_relaxed) == session.generation &&
            trace->generation.load(std::memory_order_relaxed) == session.generation &&
            binding.frame_index.load(std::memory_order_relaxed) == trace->frame_index.load(std::memory_order_relaxed) &&
            binding.source_timestamp_ns.load(std::memory_order_relaxed) == trace->source_timestamp_ns.load(std::memory_order_relaxed)) {
          auto expected_token = token.value;
          if (binding.token.compare_exchange_strong(expected_token, 0, std::memory_order_acq_rel)) {
            release_trace_only(token);
          }
        }
        release_binding(binding, version);
      }
      for (auto &trace : traces_) {
        const auto token = trace.token.load(std::memory_order_acquire);
        if (token != 0 && trace.generation.load(std::memory_order_relaxed) == session.generation) {
          auto expected_token = token;
          (void) trace.token.compare_exchange_strong(expected_token, 0, std::memory_order_acq_rel);
        }
      }
    }

    /** @brief Start one correlated capture trace using only steady-clock timestamps. */
    [[nodiscard]] frame_trace_token_t begin_capture_frame(
      std::uint64_t source_timestamp_ns,
      std::uint64_t capture_acquired_ns,
      std::uint64_t capture_output_ready_ns
    ) noexcept {
      if (!frame_telemetry_enabled_.load(std::memory_order_relaxed)) {
        return {};
      }
      if (source_timestamp_ns == 0 || capture_acquired_ns == 0 || capture_output_ready_ns < capture_acquired_ns) {
        ++correlation_misses_;
        return {};
      }
      const auto token = next_frame_token_.fetch_add(1, std::memory_order_relaxed) + 1;
      if (!initialize_trace(
            token,
            0,
            telemetry_profile_e::unknown,
            telemetry_client_e::vanilla_legacy,
            source_timestamp_ns,
            capture_acquired_ns,
            capture_output_ready_ns,
            maximum_encoder_children
          )) {
        ++correlation_misses_;
        return {};
      }
      return {token};
    }

    /** @brief Replace one image-owned capture token, abandoning the prior token first. */
    void replace_capture_frame_token(
      frame_trace_token_t &owner,
      frame_trace_token_t replacement
    ) noexcept {
      if (owner && owner != replacement) {
        abandon_frame_trace(owner);
        ++capture_tokens_abandoned_;
      }
      owner = replacement;
    }

    /** @brief Release one image-owned capture token during destruction or pool reuse. */
    void release_capture_frame_token(frame_trace_token_t &owner) noexcept {
      replace_capture_frame_token(owner, {});
    }

    /** @brief Fork a shared capture parent into one explicitly identified encoder child. */
    [[nodiscard]] frame_trace_token_t begin_conversion_frame(
      frame_trace_token_t capture_token,
      telemetry_session_t session
    ) noexcept {
      if (!frame_telemetry_enabled_.load(std::memory_order_relaxed) || !session_active(session)) {
        return {};
      }
      auto *capture = trace_for(capture_token);
      if (!capture) {
        record_omitted_encoder_child(session.generation);
        return {};
      }
      auto remaining_children = capture->remaining_encoder_children.load(std::memory_order_acquire);
      while (remaining_children > 0 &&
             !capture->remaining_encoder_children.compare_exchange_weak(
               remaining_children,
               remaining_children - 1,
               std::memory_order_acq_rel
             )) {
      }
      if (remaining_children == 0) {
        record_omitted_encoder_child(session.generation);
        return {};
      }
      const auto source_timestamp_ns = capture->source_timestamp_ns.load(std::memory_order_relaxed);
      const auto capture_acquired_ns = capture->capture_acquired_ns.load(std::memory_order_relaxed);
      const auto capture_output_ready_ns = capture->capture_output_ready_ns.load(std::memory_order_relaxed);
      const auto token = next_frame_token_.fetch_add(1, std::memory_order_relaxed) + 1;
      if (capture->token.load(std::memory_order_acquire) != capture_token.value ||
          !initialize_trace(
            token,
            session.generation,
            session.profile,
            session.client,
            source_timestamp_ns,
            capture_acquired_ns,
            capture_output_ready_ns,
            0
          )) {
        record_omitted_encoder_child(session.generation);
        return {};
      }
      capture_acquired_to_output_ready_.record(
        session.generation,
        capture_output_ready_ns - capture_acquired_ns
      );
      return {token};
    }

    /** @brief Timestamp per-frame conversion work after telemetry child setup and cache maintenance. */
    void record_conversion_work_begin(frame_trace_token_t token, std::uint64_t timestamp_ns = 0) noexcept {
      auto *trace = trace_for(token);
      if (!trace || !trace_session_active(*trace)) {
        return;
      }
      const auto begin_ns = resolved_time(timestamp_ns);
      const auto output_ready_ns = trace->capture_output_ready_ns.load(std::memory_order_relaxed);
      if (output_ready_ns == 0 || begin_ns < output_ready_ns) {
        record_correlation_miss(trace->generation.load(std::memory_order_relaxed));
        abandon_frame_trace(token);
        return;
      }
      trace->conversion_work_begin_ns.store(begin_ns, std::memory_order_relaxed);
      output_ready_to_conversion_work_begin_.record(
        trace->generation.load(std::memory_order_relaxed),
        begin_ns - output_ready_ns
      );
    }

    /** @brief Finish conversion command submission for the active encoder trace. */
    void finish_conversion_frame(frame_trace_token_t token, std::uint64_t timestamp_ns = 0) noexcept {
      auto *trace = trace_for(token);
      if (!trace || !trace_session_active(*trace)) {
        return;
      }
      const auto submitted_ns = resolved_time(timestamp_ns);
      const auto begin_ns = trace->conversion_work_begin_ns.load(std::memory_order_relaxed);
      if (begin_ns == 0 || submitted_ns < begin_ns) {
        record_correlation_miss(trace->generation.load(std::memory_order_relaxed));
        abandon_frame_trace(token);
        return;
      }
      trace->conversion_commands_submitted_ns.store(submitted_ns, std::memory_order_relaxed);
      conversion_work_begin_to_commands_submitted_.record(
        trace->generation.load(std::memory_order_relaxed),
        submitted_ns - begin_ns
      );
    }

    /** @brief Record the exact NVENC map call using an explicitly transferred encoder child. */
    [[nodiscard]] frame_trace_token_t record_nvenc_map_call_entry(
      frame_trace_token_t token,
      std::uint64_t frame_index,
      std::uint64_t timestamp_ns
    ) noexcept {
      const auto map_ns = resolved_time(timestamp_ns);
      last_nvenc_map_call_entry_ns_.store(map_ns, std::memory_order_relaxed);
      if (!frame_telemetry_enabled_.load(std::memory_order_relaxed)) {
        return {};
      }
      auto *trace = trace_for(token);
      if (!trace || !trace_session_active(*trace)) {
        return {};
      }
      const auto conversion_submitted_ns = trace->conversion_commands_submitted_ns.load(std::memory_order_relaxed);
      if (conversion_submitted_ns == 0 || map_ns < conversion_submitted_ns) {
        record_correlation_miss(trace->generation.load(std::memory_order_relaxed));
        abandon_frame_trace(token);
        return {};
      }
      const auto generation = trace->generation.load(std::memory_order_relaxed);
      const auto source_timestamp_ns = trace->source_timestamp_ns.load(std::memory_order_relaxed);
      trace->frame_index.store(frame_index, std::memory_order_relaxed);
      trace->nvenc_map_call_entry_ns.store(map_ns, std::memory_order_relaxed);
      conversion_commands_to_nvenc_map_call_.record(generation, map_ns - conversion_submitted_ns);

      auto &binding = bindings_[binding_index(frame_index, source_timestamp_ns)];
      std::uint64_t binding_version = 0;
      if (!reserve_binding(binding, binding_version)) {
        ++binding_reservation_failures_;
        record_binding_reservation_failure(generation);
        record_omitted_encoder_child(generation);
        abandon_frame_trace(token);
        return {};
      }
      const auto existing_token = binding.token.load(std::memory_order_relaxed);
      const auto *existing_trace = trace_for({existing_token});
      const auto existing_generation = existing_trace ?
                                         existing_trace->generation.load(std::memory_order_relaxed) :
                                         0;
      const auto exact_key_collision = existing_token != 0 &&
                                       binding.generation.load(std::memory_order_relaxed) == generation &&
                                       binding.frame_index.load(std::memory_order_relaxed) == frame_index &&
                                       binding.source_timestamp_ns.load(std::memory_order_relaxed) == source_timestamp_ns;
      if (existing_token != 0) {
        ++binding_collisions_;
        record_binding_collision(generation);
        if (existing_generation != 0 && existing_generation != generation) {
          record_binding_collision(existing_generation);
        }
        binding.token.store(0, std::memory_order_relaxed);
      }
      if (exact_key_collision) {
        release_binding(binding, binding_version);
        release_trace_only({existing_token});
        release_trace_only(token);
        record_omitted_encoder_child(generation);
        record_omitted_encoder_child(existing_generation);
        return {};
      }
      binding.generation.store(generation, std::memory_order_relaxed);
      binding.frame_index.store(frame_index, std::memory_order_relaxed);
      binding.source_timestamp_ns.store(source_timestamp_ns, std::memory_order_relaxed);
      binding.token.store(token.value, std::memory_order_relaxed);
      release_binding(binding, binding_version);
      if (!session_generation_active(generation)) {
        abandon_frame_trace(token);
        return {};
      }
      if (existing_token != 0) {
        release_trace_only({existing_token});
        record_omitted_encoder_child(existing_generation);
      }
      return token;
    }

    /** @brief Record the exact start of async wait or synchronous bitstream-lock work. */
    void record_nvenc_wait_lock_begin(frame_trace_token_t token, std::uint64_t timestamp_ns = 0) noexcept {
      if (auto *trace = trace_for(token); trace && trace_session_active(*trace)) {
        trace->nvenc_wait_lock_begin_ns.store(resolved_time(timestamp_ns), std::memory_order_relaxed);
      }
    }

    /** @brief Record successful NVENC bitstream lock after any async wait. */
    void record_nvenc_bitstream_locked(frame_trace_token_t token, std::uint64_t timestamp_ns = 0) noexcept {
      auto *trace = trace_for(token);
      if (!trace || !trace_session_active(*trace)) {
        return;
      }
      const auto locked_ns = resolved_time(timestamp_ns);
      const auto submitted_ns = trace->nvenc_wait_lock_begin_ns.load(std::memory_order_relaxed);
      if (submitted_ns == 0 || locked_ns < submitted_ns) {
        record_correlation_miss(trace->generation.load(std::memory_order_relaxed));
        return;
      }
      trace->bitstream_locked_ns.store(locked_ns, std::memory_order_relaxed);
      nvenc_wait_and_bitstream_lock_.record(
        trace->generation.load(std::memory_order_relaxed),
        locked_ns - submitted_ns
      );
    }

    void record_nvenc_map_failure(frame_trace_token_t token = {}) noexcept {
      ++nvenc_map_failures_;
      if (const auto *trace = trace_for(token); trace) {
        if (auto *slot = session_slot(trace->generation.load(std::memory_order_relaxed))) {
          ++slot->nvenc_map_failures;
        }
      }
    }

    void record_nvenc_wait_timeout(frame_trace_token_t token = {}) noexcept {
      ++nvenc_wait_timeouts_;
      if (const auto *trace = trace_for(token); trace) {
        if (auto *slot = session_slot(trace->generation.load(std::memory_order_relaxed))) {
          ++slot->nvenc_wait_timeouts;
        }
      }
    }

    void record_nvenc_lock_failure(frame_trace_token_t token = {}) noexcept {
      ++nvenc_lock_failures_;
      if (const auto *trace = trace_for(token); trace) {
        if (auto *slot = session_slot(trace->generation.load(std::memory_order_relaxed))) {
          ++slot->nvenc_lock_failures;
        }
      }
    }

    /** @brief Finish a trace at the sender-thread queue dequeue for the exact frame key. */
    [[nodiscard]] bool record_sender_dequeue(
      std::uint64_t frame_index,
      std::uint64_t source_timestamp_ns,
      std::uint64_t timestamp_ns = 0
    ) noexcept {
      if (!frame_telemetry_enabled_.load(std::memory_order_relaxed)) {
        return false;
      }
      auto &binding = bindings_[binding_index(frame_index, source_timestamp_ns)];
      std::uint64_t binding_version = 0;
      if (!reserve_binding(binding, binding_version)) {
        ++binding_reservation_failures_;
        ++correlation_misses_;
        return false;
      }
      const frame_trace_token_t token {binding.token.load(std::memory_order_relaxed)};
      const auto generation = binding.generation.load(std::memory_order_relaxed);
      const auto bound_frame_index = binding.frame_index.load(std::memory_order_relaxed);
      const auto bound_source_timestamp_ns = binding.source_timestamp_ns.load(std::memory_order_relaxed);
      if (!token || bound_frame_index != frame_index || bound_source_timestamp_ns != source_timestamp_ns) {
        release_binding(binding, binding_version);
        record_correlation_miss(generation);
        return false;
      }
      if (!session_generation_active(generation)) {
        binding.token.store(0, std::memory_order_relaxed);
        release_binding(binding, binding_version);
        release_trace_only(token);
        return false;
      }
      auto *trace = trace_for(token);
      if (!trace || trace->generation.load(std::memory_order_relaxed) != generation ||
          trace->frame_index.load(std::memory_order_relaxed) != frame_index ||
          trace->source_timestamp_ns.load(std::memory_order_relaxed) != source_timestamp_ns) {
        binding.token.store(0, std::memory_order_relaxed);
        release_binding(binding, binding_version);
        release_trace_only(token);
        record_correlation_miss(generation);
        return false;
      }
      binding.token.store(0, std::memory_order_relaxed);
      release_binding(binding, binding_version);
      const auto handoff_ns = resolved_time(timestamp_ns);
      const auto locked_ns = trace->bitstream_locked_ns.load(std::memory_order_relaxed);
      const auto capture_ns = trace->capture_acquired_ns.load(std::memory_order_relaxed);
      if (locked_ns == 0 || capture_ns == 0 || handoff_ns < locked_ns || handoff_ns < capture_ns) {
        record_correlation_miss(generation);
        release_trace_only(token);
        return false;
      }
      if (trace->token.load(std::memory_order_acquire) != token.value ||
          trace->generation.load(std::memory_order_relaxed) != generation ||
          trace->frame_index.load(std::memory_order_relaxed) != frame_index ||
          trace->source_timestamp_ns.load(std::memory_order_relaxed) != source_timestamp_ns) {
        record_correlation_miss(generation);
        release_trace_only(token);
        return false;
      }
      bitstream_lock_to_sender_dequeue_.record(generation, handoff_ns - locked_ns);
      capture_acquired_to_sender_dequeue_.record(generation, handoff_ns - capture_ns);
      publish_completed_frame(token, *trace, handoff_ns);
      auto expected_trace_token = token.value;
      (void) trace->token.compare_exchange_strong(expected_trace_token, 0, std::memory_order_acq_rel);
      return true;
    }

    /** @brief Read one retained per-frame sample by the exact serialized frame key. */
    [[nodiscard]] std::optional<completed_frame_telemetry_t> completed_frame(
      telemetry_session_t session,
      std::uint64_t frame_index,
      std::uint64_t source_timestamp_ns
    ) const noexcept {
      for (const auto &completed : completed_frames_) {
        const auto token = completed.token.load(std::memory_order_acquire);
        if (token == 0 || completed.frame_index.load(std::memory_order_relaxed) != frame_index ||
            completed.source_timestamp_ns.load(std::memory_order_relaxed) != source_timestamp_ns ||
            completed.generation.load(std::memory_order_relaxed) != session.generation ||
            completed.profile.load(std::memory_order_relaxed) != session.profile ||
            completed.client.load(std::memory_order_relaxed) != session.client) {
          continue;
        }
        completed_frame_telemetry_t sample {
          .correlation_id = {token},
          .generation = completed.generation.load(std::memory_order_relaxed),
          .profile = completed.profile.load(std::memory_order_relaxed),
          .client = completed.client.load(std::memory_order_relaxed),
          .frame_index = frame_index,
          .source_timestamp_ns = source_timestamp_ns,
          .capture_acquired_ns = completed.capture_acquired_ns.load(std::memory_order_relaxed),
          .capture_output_ready_ns = completed.capture_output_ready_ns.load(std::memory_order_relaxed),
          .conversion_work_begin_ns = completed.conversion_work_begin_ns.load(std::memory_order_relaxed),
          .conversion_commands_submitted_ns = completed.conversion_commands_submitted_ns.load(std::memory_order_relaxed),
          .nvenc_map_call_entry_ns = completed.nvenc_map_call_entry_ns.load(std::memory_order_relaxed),
          .nvenc_wait_lock_begin_ns = completed.nvenc_wait_lock_begin_ns.load(std::memory_order_relaxed),
          .bitstream_locked_ns = completed.bitstream_locked_ns.load(std::memory_order_relaxed),
          .sender_dequeue_ns = completed.sender_dequeue_ns.load(std::memory_order_relaxed),
          .clock_error_bound_ns = std::nullopt,
        };
        if (completed.token.load(std::memory_order_acquire) == token) {
          return sample;
        }
      }
      return std::nullopt;
    }

    /** @brief Release a trace after a conversion or encode failure. */
    void abandon_frame_trace(frame_trace_token_t token) noexcept {
      if (!token) {
        return;
      }
      auto &trace = traces_[token.value % frame_capacity];
      if (trace.token.load(std::memory_order_acquire) == token.value) {
        const auto frame_index = trace.frame_index.load(std::memory_order_relaxed);
        const auto source_timestamp_ns = trace.source_timestamp_ns.load(std::memory_order_relaxed);
        auto &binding = bindings_[binding_index(frame_index, source_timestamp_ns)];
        std::uint64_t binding_version = 0;
        if (reserve_binding(binding, binding_version)) {
          if (binding.token.load(std::memory_order_relaxed) == token.value) {
            binding.token.store(0, std::memory_order_relaxed);
          }
          release_binding(binding, binding_version);
        }
        release_trace_only(token);
      }
    }

    /**
     * @brief Read all telemetry values without resetting them.
     *
     * @return Consistent-enough diagnostic snapshot of independent monotonic counters.
     */
    [[nodiscard]] telemetry_snapshot_t snapshot() const noexcept {
      const auto generation = latest_session_generation_.load(std::memory_order_acquire);
      const auto *slot = session_slot(generation);
      return snapshot(slot ? telemetry_session_t {
                               generation,
                               slot->profile.load(std::memory_order_relaxed),
                               slot->client.load(std::memory_order_relaxed),
                             } :
                             telemetry_session_t {});
    }

    /** @brief Snapshot exactly one encoder session without aggregating modes or client families. */
    [[nodiscard]] telemetry_snapshot_t snapshot(telemetry_session_t session) const noexcept {
      const auto generation = session.generation;
      const auto *slot = session_slot(generation);
      const auto vdd_generation = vdd_generation_.load(std::memory_order_acquire);
      return telemetry_snapshot_t {
        eligibility_attempts_.load(std::memory_order_relaxed),
        fused_activations_.load(std::memory_order_relaxed),
        legacy_fallbacks_.load(std::memory_order_relaxed),
        capture_copy_submissions_.load(std::memory_order_relaxed),
        shared_handle_opens_.load(std::memory_order_relaxed),
        keyed_mutex_acquires_.load(std::memory_order_relaxed),
        fused_conversion_submissions_.load(std::memory_order_relaxed),
        last_capture_acquired_ns_.load(std::memory_order_relaxed),
        last_capture_copy_submitted_ns_.load(std::memory_order_relaxed),
        last_conversion_begin_ns_.load(std::memory_order_relaxed),
        last_conversion_submitted_ns_.load(std::memory_order_relaxed),
        last_nvenc_map_call_entry_ns_.load(std::memory_order_relaxed),
        generation,
        session.profile,
        session.client,
        slot ? slot->correlation_misses.load(std::memory_order_relaxed) : 0,
        capture_tokens_abandoned_.load(std::memory_order_relaxed),
        slot ? slot->omitted_encoder_children.load(std::memory_order_relaxed) : 0,
        slot ? slot->binding_collisions.load(std::memory_order_relaxed) : 0,
        slot ? slot->binding_reservation_failures.load(std::memory_order_relaxed) : 0,
        slot ? slot->nvenc_map_failures.load(std::memory_order_relaxed) : 0,
        slot ? slot->nvenc_wait_timeouts.load(std::memory_order_relaxed) : 0,
        slot ? slot->nvenc_lock_failures.load(std::memory_order_relaxed) : 0,
        capture_acquired_to_output_ready_.snapshot(generation),
        output_ready_to_conversion_work_begin_.snapshot(generation),
        conversion_work_begin_to_commands_submitted_.snapshot(generation),
        conversion_commands_to_nvenc_map_call_.snapshot(generation),
        nvenc_wait_and_bitstream_lock_.snapshot(generation),
        bitstream_lock_to_sender_dequeue_.snapshot(generation),
        capture_acquired_to_sender_dequeue_.snapshot(generation),
        vdd_generation,
        vdd_acquire_to_producer_signal_.snapshot(vdd_generation),
        vdd_producer_signal_to_host_wait_.snapshot(vdd_generation),
      };
    }

  private:
    [[nodiscard]] static std::uint64_t resolved_time(std::uint64_t timestamp_ns) noexcept {
      return timestamp_ns == 0 ? now_ns() : timestamp_ns;
    }

    [[nodiscard]] session_slot_t *session_slot(std::uint64_t generation) noexcept {
      if (generation == 0) {
        return nullptr;
      }
      auto &slot = sessions_[generation % session_capacity];
      return slot.generation.load(std::memory_order_acquire) == generation ? &slot : nullptr;
    }

    [[nodiscard]] const session_slot_t *session_slot(std::uint64_t generation) const noexcept {
      return const_cast<telemetry_t *>(this)->session_slot(generation);
    }

    [[nodiscard]] bool session_generation_active(std::uint64_t generation) const noexcept {
      return session_slot(generation) != nullptr;
    }

    [[nodiscard]] bool session_active(telemetry_session_t session) const noexcept {
      const auto *slot = session_slot(session.generation);
      return slot &&
             slot->profile.load(std::memory_order_relaxed) == session.profile &&
             slot->client.load(std::memory_order_relaxed) == session.client;
    }

    [[nodiscard]] bool trace_session_active(const frame_trace_t &trace) const noexcept {
      const telemetry_session_t session {
        trace.generation.load(std::memory_order_relaxed),
        trace.profile.load(std::memory_order_relaxed),
        trace.client.load(std::memory_order_relaxed),
      };
      return session_active(session);
    }

    void record_omitted_encoder_child(std::uint64_t generation, std::uint64_t count = 1) noexcept {
      omitted_encoder_children_.fetch_add(count, std::memory_order_relaxed);
      if (auto *slot = session_slot(generation)) {
        slot->omitted_encoder_children.fetch_add(count, std::memory_order_relaxed);
      }
    }

    void record_correlation_miss(std::uint64_t generation) noexcept {
      ++correlation_misses_;
      if (auto *slot = session_slot(generation)) {
        ++slot->correlation_misses;
      }
    }

    void record_binding_collision(std::uint64_t generation) noexcept {
      if (auto *slot = session_slot(generation)) {
        ++slot->binding_collisions;
      }
    }

    void record_binding_reservation_failure(std::uint64_t generation) noexcept {
      if (auto *slot = session_slot(generation)) {
        ++slot->binding_reservation_failures;
      }
    }

    [[nodiscard]] std::size_t binding_index(std::uint64_t frame_index, std::uint64_t source_timestamp_ns) const noexcept {
      return static_cast<std::size_t>((frame_index ^ (source_timestamp_ns >> 8)) % frame_capacity);
    }

    [[nodiscard]] static bool reserve_binding(
      frame_binding_t &binding,
      std::uint64_t &stable_version
    ) noexcept {
      for (std::size_t attempt = 0; attempt < 64; ++attempt) {
        auto version = binding.version.load(std::memory_order_acquire);
        if ((version & 1U) != 0) {
          continue;
        }
        if (binding.version.compare_exchange_weak(
              version,
              version + 1,
              std::memory_order_acq_rel
            )) {
          stable_version = version;
          return true;
        }
      }
      return false;
    }

    static void release_binding(frame_binding_t &binding, std::uint64_t stable_version) noexcept {
      binding.version.store(stable_version + 2, std::memory_order_release);
    }

    void release_trace_only(frame_trace_token_t token) noexcept {
      if (!token) {
        return;
      }
      auto &trace = traces_[token.value % frame_capacity];
      auto expected = token.value;
      (void) trace.token.compare_exchange_strong(expected, 0, std::memory_order_acq_rel);
    }

    void publish_completed_frame(
      frame_trace_token_t token,
      const frame_trace_t &trace,
      std::uint64_t sender_dequeue_ns
    ) noexcept {
      auto &completed = completed_frames_[token.value % frame_capacity];
      completed.token.store(0, std::memory_order_release);
      completed.generation.store(trace.generation.load(std::memory_order_relaxed), std::memory_order_relaxed);
      completed.profile.store(trace.profile.load(std::memory_order_relaxed), std::memory_order_relaxed);
      completed.client.store(trace.client.load(std::memory_order_relaxed), std::memory_order_relaxed);
      completed.frame_index.store(trace.frame_index.load(std::memory_order_relaxed), std::memory_order_relaxed);
      completed.source_timestamp_ns.store(trace.source_timestamp_ns.load(std::memory_order_relaxed), std::memory_order_relaxed);
      completed.capture_acquired_ns.store(trace.capture_acquired_ns.load(std::memory_order_relaxed), std::memory_order_relaxed);
      completed.capture_output_ready_ns.store(trace.capture_output_ready_ns.load(std::memory_order_relaxed), std::memory_order_relaxed);
      completed.conversion_work_begin_ns.store(trace.conversion_work_begin_ns.load(std::memory_order_relaxed), std::memory_order_relaxed);
      completed.conversion_commands_submitted_ns.store(
        trace.conversion_commands_submitted_ns.load(std::memory_order_relaxed),
        std::memory_order_relaxed
      );
      completed.nvenc_map_call_entry_ns.store(trace.nvenc_map_call_entry_ns.load(std::memory_order_relaxed), std::memory_order_relaxed);
      completed.nvenc_wait_lock_begin_ns.store(trace.nvenc_wait_lock_begin_ns.load(std::memory_order_relaxed), std::memory_order_relaxed);
      completed.bitstream_locked_ns.store(trace.bitstream_locked_ns.load(std::memory_order_relaxed), std::memory_order_relaxed);
      completed.sender_dequeue_ns.store(sender_dequeue_ns, std::memory_order_relaxed);
      completed.token.store(token.value, std::memory_order_release);
    }

    [[nodiscard]] bool initialize_trace(
      std::uint64_t token,
      std::uint64_t generation,
      telemetry_profile_e profile,
      telemetry_client_e client,
      std::uint64_t source_timestamp_ns,
      std::uint64_t capture_acquired_ns,
      std::uint64_t capture_output_ready_ns,
      std::uint32_t remaining_encoder_children
    ) noexcept {
      auto &trace = traces_[token % frame_capacity];
      constexpr std::uint64_t reserved_mask = std::uint64_t {1} << 63;
      auto expected = std::uint64_t {0};
      if (!trace.token.compare_exchange_strong(
            expected,
            token | reserved_mask,
            std::memory_order_acq_rel
          )) {
        return false;
      }
      trace.generation.store(generation, std::memory_order_relaxed);
      trace.profile.store(profile, std::memory_order_relaxed);
      trace.client.store(client, std::memory_order_relaxed);
      trace.source_timestamp_ns.store(source_timestamp_ns, std::memory_order_relaxed);
      trace.capture_acquired_ns.store(capture_acquired_ns, std::memory_order_relaxed);
      trace.capture_output_ready_ns.store(capture_output_ready_ns, std::memory_order_relaxed);
      trace.conversion_work_begin_ns.store(0, std::memory_order_relaxed);
      trace.conversion_commands_submitted_ns.store(0, std::memory_order_relaxed);
      trace.nvenc_map_call_entry_ns.store(0, std::memory_order_relaxed);
      trace.nvenc_wait_lock_begin_ns.store(0, std::memory_order_relaxed);
      trace.bitstream_locked_ns.store(0, std::memory_order_relaxed);
      trace.frame_index.store(0, std::memory_order_relaxed);
      trace.remaining_encoder_children.store(remaining_encoder_children, std::memory_order_relaxed);
      trace.token.store(token, std::memory_order_release);
      return true;
    }

    [[nodiscard]] frame_trace_t *trace_for(frame_trace_token_t token) noexcept {
      if (!token) {
        return nullptr;
      }
      auto &trace = traces_[token.value % frame_capacity];
      if (trace.token.load(std::memory_order_acquire) != token.value) {
        return nullptr;
      }
      return &trace;
    }

    [[nodiscard]] const frame_trace_t *trace_for(frame_trace_token_t token) const noexcept {
      return const_cast<telemetry_t *>(this)->trace_for(token);
    }

    std::atomic<std::uint64_t> eligibility_attempts_ {0};  ///< Eligibility evaluation count.
    std::atomic<std::uint64_t> fused_activations_ {0};  ///< Fused activation count.
    std::atomic<std::uint64_t> legacy_fallbacks_ {0};  ///< Legacy fallback count.
    std::atomic<std::uint64_t> capture_copy_submissions_ {0};  ///< Capture-copy count.
    std::atomic<std::uint64_t> shared_handle_opens_ {0};  ///< Shared-handle open count.
    std::atomic<std::uint64_t> keyed_mutex_acquires_ {0};  ///< Keyed-mutex acquisition count.
    std::atomic<std::uint64_t> fused_conversion_submissions_ {0};  ///< Fused conversion count.
    std::atomic<std::uint64_t> last_capture_acquired_ns_ {0};  ///< Latest capture acquisition timestamp.
    std::atomic<std::uint64_t> last_capture_copy_submitted_ns_ {0};  ///< Latest capture-copy timestamp.
    std::atomic<std::uint64_t> last_conversion_begin_ns_ {0};  ///< Latest conversion start timestamp.
    std::atomic<std::uint64_t> last_conversion_submitted_ns_ {0};  ///< Latest conversion submission timestamp.
    static constexpr std::uint32_t maximum_encoder_children = 4;
    std::atomic<std::uint64_t> last_nvenc_map_call_entry_ns_ {0};  ///< Latest exact NVENC map-call entry.
    std::atomic<std::uint64_t> frame_generation_ {1};  ///< Current frame-pipeline generation; zero is reserved.
    std::atomic<std::uint64_t> latest_session_generation_ {0};  ///< Compatibility snapshot selector only.
    std::atomic_bool frame_telemetry_enabled_ {true};  ///< Fast gate for correlated hot-path work.
    std::atomic<std::uint64_t> next_frame_token_ {0};  ///< Unique process-local trace token source.
    std::atomic<std::uint64_t> correlation_misses_ {0};  ///< Dropped or stale correlation attempts.
    std::atomic<std::uint64_t> capture_tokens_abandoned_ {0};  ///< Explicit capture-owner releases.
    std::atomic<std::uint64_t> omitted_encoder_children_ {0};  ///< Bounded or ambiguous child omissions.
    std::atomic<std::uint64_t> binding_collisions_ {0};  ///< Exact-key and hash-bucket binding collisions.
    std::atomic<std::uint64_t> binding_reservation_failures_ {0};  ///< Failed bounded binding reservations.
    std::atomic<std::uint64_t> nvenc_map_failures_ {0};  ///< NVENC map failures.
    std::atomic<std::uint64_t> nvenc_wait_timeouts_ {0};  ///< NVENC async wait timeouts.
    std::atomic<std::uint64_t> nvenc_lock_failures_ {0};  ///< NVENC bitstream lock failures.
    std::array<frame_trace_t, frame_capacity> traces_ {};  ///< Fixed-capacity correlated trace storage.
    std::array<frame_binding_t, frame_capacity> bindings_ {};  ///< Exact sender lookup by frame index and source time.
    std::array<completed_frame_t, frame_capacity> completed_frames_ {};  ///< Completed per-frame host-local samples.
    std::array<session_slot_t, session_capacity> sessions_ {};  ///< Fixed-capacity concurrent encoder sessions.
    bounded_latency_window_t<frame_capacity> capture_acquired_to_output_ready_;
    bounded_latency_window_t<frame_capacity> output_ready_to_conversion_work_begin_;
    bounded_latency_window_t<frame_capacity> conversion_work_begin_to_commands_submitted_;
    bounded_latency_window_t<frame_capacity> conversion_commands_to_nvenc_map_call_;
    bounded_latency_window_t<frame_capacity> nvenc_wait_and_bitstream_lock_;
    bounded_latency_window_t<frame_capacity> bitstream_lock_to_sender_dequeue_;
    bounded_latency_window_t<frame_capacity> capture_acquired_to_sender_dequeue_;
    std::atomic<std::uint64_t> vdd_generation_ {0};  ///< Active ABI v4 direct-frame generation.
    bounded_latency_window_t<frame_capacity> vdd_acquire_to_producer_signal_;
    bounded_latency_window_t<frame_capacity> vdd_producer_signal_to_host_wait_;
  };

  /** @brief Move-only child-token owner that abandons unfinished traces on every exit path. */
  class frame_trace_owner_t {
  public:
    frame_trace_owner_t() noexcept = default;

    frame_trace_owner_t(telemetry_t &telemetry, frame_trace_token_t token) noexcept:
        telemetry_(&telemetry),
        token_(token) {
    }

    ~frame_trace_owner_t() {
      reset();
    }

    frame_trace_owner_t(const frame_trace_owner_t &) = delete;
    frame_trace_owner_t &operator=(const frame_trace_owner_t &) = delete;

    frame_trace_owner_t(frame_trace_owner_t &&other) noexcept:
        telemetry_(std::exchange(other.telemetry_, nullptr)),
        token_(std::exchange(other.token_, {})) {
    }

    frame_trace_owner_t &operator=(frame_trace_owner_t &&other) noexcept {
      if (this != &other) {
        reset();
        telemetry_ = std::exchange(other.telemetry_, nullptr);
        token_ = std::exchange(other.token_, {});
      }
      return *this;
    }

    [[nodiscard]] frame_trace_token_t token() const noexcept {
      return token_;
    }

    [[nodiscard]] explicit operator bool() const noexcept {
      return static_cast<bool>(token_);
    }

    [[nodiscard]] frame_trace_token_t release() noexcept {
      telemetry_ = nullptr;
      return std::exchange(token_, {});
    }

    void reset() noexcept {
      if (telemetry_ && token_) {
        telemetry_->abandon_frame_trace(token_);
      }
      telemetry_ = nullptr;
      token_ = {};
    }

  private:
    telemetry_t *telemetry_ = nullptr;
    frame_trace_token_t token_;
  };

  /**
   * @brief Return the process-local fused-path telemetry accumulator.
   *
   * @return Shared telemetry accumulator.
   */
  inline telemetry_t &telemetry() noexcept {
    static telemetry_t instance;
    return instance;
  }

}  // namespace platf::dxgi::fused_d3d11
