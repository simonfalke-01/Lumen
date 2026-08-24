/**
 * @file src/platform/windows/virtual_display.h
 * @brief Transactional Lumen indirect-display mode coordination.
 */
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace platf::virtual_display {
  /** @brief Return the sole matching index, or none for zero/duplicate matches. */
  [[nodiscard]] std::optional<std::size_t> unique_matching_index(
    std::span<const std::uint8_t> matches
  ) noexcept;

  /** @brief Exact positive rational used for refresh and frame rates. */
  struct rational_t {
    std::uint32_t numerator {};  ///< Positive numerator.
    std::uint32_t denominator {};  ///< Positive denominator.

    /**
     * @brief Return the reduced rational, or no value for zero/oversized input.
     * @return Reduced rational.
     */
    [[nodiscard]] std::optional<rational_t> normalized() const noexcept;

    bool operator==(const rational_t &) const = default;
  };

  /** @brief Requested or applied virtual-display dynamic range. */
  enum class dynamic_range_e : std::uint8_t {
    sdr = 0,  ///< SDR output.
    hdr10 = 1,  ///< HDR10/PQ output.
  };

  /** @brief Stream optimization policy carried through the exact VDD session. */
  enum class delivery_policy_e : std::uint8_t {
    latency = 1,  ///< Latency-first host session policy.
    quality = 2,  ///< Quality-first host session policy.
  };

  /** @brief Driver-reported fidelity for the configured surface. */
  enum class fidelity_e : std::uint8_t {
    lossless = 1,  ///< Format-preserving shared surface.
    visually_lossless = 2,  ///< Explicit, validated visually-lossless conversion.
  };

  /** @brief Exact virtual-display mode. */
  struct mode_t {
    std::uint32_t width {};  ///< Active width in pixels.
    std::uint32_t height {};  ///< Active height in pixels.
    rational_t refresh {};  ///< Exact refresh rational in hertz.
    dynamic_range_e dynamic_range {dynamic_range_e::sdr};  ///< Dynamic range.
    std::uint8_t bits_per_channel {8};  ///< 8 or 10 bits per component.

    bool operator==(const mode_t &) const = default;
  };

  /** @brief Intersectable practical limits from the driver, OS, GPU, and encoder. */
  struct mode_limits_t {
    std::uint32_t minimum_width {256};  ///< Smallest even width.
    std::uint32_t maximum_width {8192};  ///< Largest even width.
    std::uint32_t minimum_height {200};  ///< Smallest even height.
    std::uint32_t maximum_height {8192};  ///< Largest even height.
    rational_t minimum_refresh {10, 1};  ///< Minimum refresh.
    rational_t maximum_refresh {480, 1};  ///< Maximum refresh.
    std::uint64_t maximum_pixels {8192ULL * 8192ULL};  ///< Maximum active pixels.
    std::uint64_t maximum_pixel_rate {8192ULL * 8192ULL * 480ULL};  ///< Maximum active pixels per second.
    bool require_even_dimensions {true};  ///< Whether both dimensions must be even.
    bool supports_hdr10 {};  ///< Whether the full active path supports HDR10.
    bool supports_10bit {};  ///< Whether the full active path supports 10-bit surfaces.
    bool supports_lossless {true};  ///< Whether lossless surface delivery is supported.
    bool supports_visually_lossless {};  ///< Whether an explicit visually-lossless path is supported.
  };

  /** @brief Stable validation failure reported before display mutation. */
  enum class validation_error_e {
    none,  ///< Mode is valid.
    zero_or_unreduced_refresh,  ///< Refresh is zero, oversized, or not reduced.
    odd_dimensions,  ///< Encoder-incompatible odd dimension.
    dimensions_out_of_range,  ///< Width or height exceeds intersected bounds.
    refresh_out_of_range,  ///< Refresh exceeds intersected bounds.
    pixel_count_overflow,  ///< Width times height cannot be represented or exceeds the cap.
    pixel_rate_overflow,  ///< Pixel rate cannot be represented or exceeds the cap.
    unsupported_dynamic_range,  ///< HDR was requested without proven end-to-end support.
    unsupported_bit_depth,  ///< Requested bit depth is unsupported.
    unsupported_fidelity,  ///< Requested fidelity is unsupported.
    unsupported_delivery_policy,  ///< Requested VDD session policy is not defined.
  };

  /**
   * @brief Validate one exact mode against the complete intersected bound.
   * @param mode Exact mode.
   * @param limits Effective limits.
   * @param required_fidelity Minimum requested fidelity.
   * @return Stable validation status.
   */
  [[nodiscard]] validation_error_e validate_mode(
    const mode_t &mode,
    const mode_limits_t &limits,
    fidelity_e required_fidelity = fidelity_e::lossless
  ) noexcept;

  /**
   * @brief Intersect two independently authoritative mode limits.
   * @param left First limit.
   * @param right Second limit.
   * @return Effective limit, or no value when their domains do not overlap.
   */
  [[nodiscard]] std::optional<mode_limits_t> intersect_limits(
    const mode_limits_t &left,
    const mode_limits_t &right
  ) noexcept;

  /** @brief One driver-control operation result. */
  struct channel_result_t {
    bool accepted {true};  ///< Whether the operation completed.
    std::uint32_t native_status {};  ///< Win32 or driver status when rejected.

    explicit operator bool() const noexcept {
      return accepted;
    }
  };

  /** @brief Exact adapter and driver identity frozen from one successful encoder probe. */
  struct render_adapter_identity_t {
    std::uint64_t adapter_luid {};  ///< Packed DXGI adapter LUID.
    std::uint32_t vendor_id {};  ///< PCI vendor identifier.
    std::uint32_t device_id {};  ///< PCI device identifier.
    std::uint32_t subsystem_id {};  ///< PCI subsystem identifier.
    std::uint32_t revision {};  ///< PCI revision.
    std::uint64_t driver_version {};  ///< DXGI UMD driver version.

    bool operator==(const render_adapter_identity_t &) const = default;
  };

  /** @brief Exact mode returned after the driver exposes it. */
  struct prepared_mode_t {
    mode_t mode;  ///< Exact mode exposed to Windows.
    std::string connector_id;  ///< Stable driver connector identifier.
    fidelity_e fidelity {fidelity_e::lossless};  ///< Actual driver fidelity.
    std::uint64_t preferred_render_adapter_luid {};  ///< Exact encoder adapter requested through IddCx.
    bool render_adapter_preference_submitted {};  ///< Whether the runtime preference API was available and called.
  };

  /** @brief Driver generation and ownership state used for crash recovery. */
  struct driver_state_t {
    std::uint64_t generation {};  ///< Current nonzero generation.
    std::uint32_t owner_process_id {};  ///< Owning service process, or zero.
    bool monitor_started {};  ///< Whether the connector is currently present.
    mode_t mode;  ///< Current mode when active.
    std::uint64_t last_generation {};  ///< Highest generation admitted since driver start.
    std::uint64_t preferred_render_adapter_luid {};  ///< Exact adapter requested for the active generation.
    std::uint64_t assigned_render_adapter_luid {};  ///< Actual adapter observed in the latest swap-chain assignment.
    bool render_adapter_preference_submitted {};  ///< Whether the IddCx preference API was called.
  };

  /** @brief Injectable generation-fenced VDD control channel. */
  class control_channel_t {
  public:
    virtual ~control_channel_t() = default;
    virtual channel_result_t open() = 0;  ///< Discover and open the secured interface.
    virtual channel_result_t query_limits(mode_limits_t &limits) = 0;  ///< Query exact driver limits.
    virtual channel_result_t query_state(driver_state_t &state) = 0;  ///< Query current generation.
    virtual channel_result_t recover_stale(std::uint64_t generation) = 0;  ///< Reset one provably stale generation.
    virtual channel_result_t prepare_mode(
      std::uint64_t generation,
      const mode_t &mode,
      delivery_policy_e delivery_policy,
      fidelity_e minimum_fidelity,
      std::uint64_t preferred_render_adapter_luid,
      prepared_mode_t &prepared
    ) = 0;  ///< Expose an exact mode and shared-surface policy.
    virtual channel_result_t start_monitor(std::uint64_t generation) = 0;  ///< Make the connector present.
    virtual channel_result_t stop_monitor(std::uint64_t generation) = 0;  ///< Remove/reset the connector.
    virtual void close() noexcept = 0;  ///< Close the interface.
  };

  /** @brief Target-scoped Advanced Color state observed through DisplayConfig. */
  enum class advanced_color_state_e {
    api_unavailable,  ///< Downlevel OS does not implement the documented query.
    unsupported,  ///< Target cannot enter Advanced Color mode.
    disabled,  ///< Target supports Advanced Color and it is disabled.
    enabled,  ///< Target supports Advanced Color and it is enabled.
  };

  /** @brief Exact target identity and its pre-transaction Advanced Color state. */
  struct target_advanced_color_t {
    std::uint64_t adapter_luid {};  ///< Packed DisplayConfig target adapter LUID.
    std::uint32_t target_id {};  ///< DisplayConfig target identifier on that adapter.
    advanced_color_state_e state {advanced_color_state_e::api_unavailable};  ///< Saved state.
  };

  /** @brief Portable DisplayConfig path facts used to select snapshot color targets. */
  struct advanced_color_path_t {
    std::uint64_t adapter_luid {};  ///< Packed target adapter LUID.
    std::uint32_t target_id {};  ///< Target identifier on that adapter.
    bool active {};  ///< Path carries `DISPLAYCONFIG_PATH_ACTIVE`.
    bool target_available {};  ///< Target is currently available to DisplayConfig.
  };

  /** Select only unique active, available targets for Advanced Color snapshotting. */
  [[nodiscard]] std::vector<advanced_color_path_t> active_advanced_color_targets(
    std::span<const advanced_color_path_t> paths
  );

  /** @brief Required target-scoped action for one SDR or HDR10 commit. */
  enum class advanced_color_action_e {
    none,  ///< Downlevel or unsupported SDR target needs no mutation.
    enable,  ///< Explicitly enable Advanced Color for HDR10.
    disable,  ///< Explicitly disable Advanced Color for SDR.
    reject,  ///< HDR10 cannot be proven on this target.
  };

  /** Return the documented Advanced Color action for an exact mode and observed target state. */
  [[nodiscard]] constexpr advanced_color_action_e advanced_color_action(
    const dynamic_range_e dynamic_range,
    const advanced_color_state_e state
  ) noexcept {
    if (dynamic_range == dynamic_range_e::hdr10) {
      return state == advanced_color_state_e::enabled ?
               advanced_color_action_e::none :
             state == advanced_color_state_e::disabled ?
               advanced_color_action_e::enable :
               advanced_color_action_e::reject;
    }
    return state == advanced_color_state_e::enabled ? advanced_color_action_e::disable : advanced_color_action_e::none;
  }

  /** Return whether a settled target exactly satisfies the requested SDR/HDR10 state. */
  [[nodiscard]] constexpr bool advanced_color_matches(
    const dynamic_range_e dynamic_range,
    const advanced_color_state_e state
  ) noexcept {
    return dynamic_range == dynamic_range_e::hdr10 ?
             state == advanced_color_state_e::enabled :
             state != advanced_color_state_e::enabled;
  }

  /**
   * @brief Attempt every saved mutable target and aggregate restoration success.
   * @tparam RestoreTarget Callable `(target, enabled) -> bool` that applies and verifies one target.
   */
  template<typename RestoreTarget>
  [[nodiscard]] bool restore_all_advanced_color_states(
    const std::span<const target_advanced_color_t> targets,
    RestoreTarget restore_target
  ) {
    bool restored = true;
    for (const auto &target : targets) {
      if (target.state == advanced_color_state_e::api_unavailable ||
          target.state == advanced_color_state_e::unsupported) {
        continue;
      }
      const bool enabled = target.state == advanced_color_state_e::enabled;
      if (!restore_target(target, enabled)) {
        restored = false;
      }
    }
    return restored;
  }

  /** @brief Opaque DisplayConfig snapshot. */
  struct display_snapshot_t {
    std::vector<std::byte> paths;  ///< Platform-owned serialized paths.
    std::vector<std::byte> modes;  ///< Platform-owned serialized modes.
    std::vector<target_advanced_color_t> advanced_color;  ///< Per-target pre-transaction color state.
  };

  /** @brief Exact output selected by the transactional DisplayConfig backend. */
  struct display_commit_t {
    mode_t mode;  ///< Exact active mode observed after settling.
    std::string capture_name;  ///< GDI/DXGI capture selector for this output.
  };

  /** @brief Injectable Windows DisplayConfig transaction boundary. */
  class display_config_t {
  public:
    virtual ~display_config_t() = default;
    virtual bool snapshot(display_snapshot_t &snapshot) = 0;  ///< Capture the complete active topology.
    virtual bool commit(const std::string &connector_id, const mode_t &mode, display_commit_t &applied) = 0;  ///< Activate/select the VDD output.
    virtual bool await_stable(const std::string &capture_name, const mode_t &mode, std::chrono::milliseconds timeout) = 0;  ///< Await exact stable enumeration.
    virtual bool restore(const display_snapshot_t &snapshot) noexcept = 0;  ///< Restore the saved topology.
  };

  /** @brief Host request for one exclusive VDD generation. */
  struct stream_request_t {
    std::uint64_t session_id {};  ///< Nonzero Lumen stream identifier.
    mode_t mode;  ///< Exact client-requested mode.
    delivery_policy_e delivery_policy {delivery_policy_e::latency};  ///< Shared-surface delivery policy.
    fidelity_e minimum_fidelity {fidelity_e::lossless};  ///< Minimum accepted fidelity.
    std::optional<render_adapter_identity_t> render_adapter;  ///< Exact identity frozen from the active encoder probe.
  };

  /** @brief Adapt vanilla GameStream width/height/integer FPS without changing its wire protocol. */
  [[nodiscard]] stream_request_t legacy_game_stream_request(
    std::uint64_t session_id,
    std::uint32_t width,
    std::uint32_t height,
    std::uint32_t frames_per_second,
    delivery_policy_e delivery_policy
  ) noexcept;

  /** @brief Adapt an exact modern-protocol selection into the shared VDD coordinator request. */
  [[nodiscard]] stream_request_t modern_stream_request(
    std::uint64_t session_id,
    mode_t mode,
    delivery_policy_e delivery_policy,
    fidelity_e minimum_fidelity = fidelity_e::lossless
  ) noexcept;

  /** @brief Successful exact selection returned to legacy or modern control. */
  struct stream_selection_t {
    std::uint64_t session_id {};  ///< Exclusive owning stream identifier.
    std::uint64_t generation {};  ///< Driver generation fencing all operations.
    mode_t requested_mode;  ///< Original requested mode.
    mode_t selected_mode;  ///< Exact observed active mode.
    std::string capture_name;  ///< Output selected for capture.
    delivery_policy_e delivery_policy {delivery_policy_e::latency};  ///< Applied delivery policy.
    fidelity_e fidelity {fidelity_e::lossless};  ///< Applied fidelity.
    bool adjusted {};  ///< Explicit indication that selected differs from requested.
    std::optional<render_adapter_identity_t> render_adapter;  ///< Frozen encoder/render adapter identity.
    bool render_adapter_preference_submitted {};  ///< Whether IddCx received the preference before monitor arrival.
  };

  /** @brief Return whether a frozen adapter identity is usable at the VDD trust boundary. */
  [[nodiscard]] bool valid_render_adapter_identity(const render_adapter_identity_t &identity) noexcept;

  /** @brief Stable transactional start result. */
  enum class start_error_e {
    none,  ///< Started or idempotently returned the active selection.
    invalid_session,  ///< Session identifier was zero.
    invalid_mode,  ///< Mode failed host/GPU/driver validation.
    busy,  ///< Another stream owns the VDD.
    driver_unavailable,  ///< Secured interface or ABI was unavailable.
    stale_recovery_failed,  ///< A crashed owner could not be recovered safely.
    driver_prepare_failed,  ///< Driver did not expose the exact mode.
    driver_start_failed,  ///< Driver could not publish the connector.
    display_snapshot_failed,  ///< Current topology could not be captured.
    display_commit_failed,  ///< DisplayConfig could not activate the exact mode.
    display_unstable,  ///< Exact mode did not settle before the deadline.
    implicit_adjustment_rejected,  ///< Driver or OS silently changed the requested tuple.
    rollback_failed,  ///< A failed transaction could not restore prior state.
  };

  /** @brief Result of one coordinator start. */
  struct start_result_t {
    start_error_e error {start_error_e::none};  ///< Stable result.
    validation_error_e validation_error {validation_error_e::none};  ///< Detailed preflight failure.
    std::optional<stream_selection_t> selection;  ///< Exact selection on success.
  };

  /** @brief Host policy controlling whether a stream may acquire the Lumen VDD. */
  enum class activation_policy_e {
    disabled,  ///< Preserve physical capture and do not contact the VDD backend.
    optional,  ///< Prefer VDD, falling back only after a proven-safe rollback.
    required  ///< Reject startup unless the exact VDD mode becomes active.
  };

  class session_lease_t;

  /** @brief Backend start result atomically paired with one explicit session owner. */
  struct owned_start_result_t {
    start_result_t started;  ///< Transaction result.
    std::shared_ptr<session_lease_t> lease;  ///< Owner acquired before the start/release lock is dropped.
  };

  /** @brief Transport-neutral activation backend used by legacy and future protocol adapters. */
  class activation_backend_t: public std::enable_shared_from_this<activation_backend_t> {
  public:
    virtual ~activation_backend_t() = default;

    /**
     * @brief Start one exact VDD transaction.
     * @param request Exact stream request.
     * @param limits Intersected host/GPU/encoder limits.
     * @return Transaction result.
     */
    [[nodiscard]] virtual start_result_t start(
      const stream_request_t &request,
      const mode_limits_t &limits
    ) = 0;

    /**
     * @brief Restore and release the display owned by one session.
     * @param session_id Exact owning session identifier.
     * @return True after successful or idempotent release.
     */
    virtual bool stop(std::uint64_t session_id) noexcept = 0;

    /**
     * @brief Acquire one explicit owner of the active generation for a session.
     * @param session_id Exact owning session identifier.
     * @return Per-owner lease serialized through the backend registry.
     */
    [[nodiscard]] std::shared_ptr<session_lease_t> acquire_lease(std::uint64_t session_id);

    /**
     * @brief Retry cleanup, start, and acquire ownership as one atomic registry transaction.
     * @param request Exact stream request.
     * @param limits Intersected host/GPU/encoder limits.
     * @return Start result and lease acquired before final release can interleave.
     */
    [[nodiscard]] owned_start_result_t start_owned(
      const stream_request_t &request,
      const mode_limits_t &limits
    );

  private:
    friend class session_lease_t;

    struct lease_record_t {
      std::uint64_t token {};  ///< Monotonic identity preventing ABA across reconnect generations.
      std::size_t owners {};  ///< Explicit live session owners.
      bool cleanup_pending {};  ///< A final release failed and must be retried before start.
    };

    [[nodiscard]] std::shared_ptr<session_lease_t> acquire_lease_locked(std::uint64_t session_id);
    bool cleanup_pending_locked() noexcept;
    void retain_cleanup_obligation_locked(std::uint64_t session_id);
    bool release_lease(std::uint64_t session_id, std::uint64_t token, bool &owner_released) noexcept;

    std::mutex lease_mutex_;  ///< Atomically serializes acquire, final release, and reconnect cleanup.
    std::unordered_map<std::uint64_t, lease_record_t> leases_;  ///< Active or cleanup-pending ownership by session.
    std::uint64_t next_lease_token_ {1};  ///< Monotonic local lease identity.
  };

  /** @brief Explicit per-session VDD owner released through the atomic backend registry. */
  class session_lease_t {
  public:
    session_lease_t(
      std::shared_ptr<activation_backend_t> backend,
      std::uint64_t session_id,
      std::uint64_t token
    );
    ~session_lease_t();

    session_lease_t(const session_lease_t &) = delete;
    session_lease_t &operator=(const session_lease_t &) = delete;

    /**
     * @brief Release the owned generation, retrying only after a failed release.
     * @return True after the generation has been released.
     */
    bool release() noexcept;

    /** @brief Return whether a release has completed successfully. */
    [[nodiscard]] bool released() const noexcept;

  private:
    std::shared_ptr<activation_backend_t> backend_;  ///< Backend kept alive through teardown.
    std::uint64_t session_id_ {};  ///< Exact owning session.
    std::uint64_t token_ {};  ///< ABA-safe registry identity.
    mutable std::mutex mutex_;  ///< Serializes teardown from stop, cancellation, and destruction.
    bool owner_released_ {};  ///< Whether this handle already surrendered its owner count.
    bool released_ {};  ///< True only after the backend confirms release.
  };

  /** @brief Live-session capture selection after applying the configured VDD policy. */
  enum class session_prepare_e {
    physical,  ///< Preserve the caller's physical capture selector.
    virtual_display,  ///< Capture the exact selected VDD output.
    rejected  ///< Startup must fail because safe policy requirements were not met.
  };

  /** @brief Result of transport-neutral VDD live-session preparation. */
  struct session_prepare_result_t {
    session_prepare_e outcome {session_prepare_e::physical};  ///< Capture/failure decision.
    std::string capture_name;  ///< Exact capture selector; unchanged physical selector on fallback.
    std::optional<stream_selection_t> selection;  ///< Exact applied VDD selection when active.
    std::shared_ptr<session_lease_t> lease;  ///< Shared ownership transferred into the stream session.
    start_error_e diagnostic {start_error_e::none};  ///< Stable VDD diagnostic.
    validation_error_e validation_error {validation_error_e::none};  ///< Detailed invalid-mode reason.
  };

  /**
   * @brief Apply VDD policy at a transport-neutral live-session boundary.
   * @details Only exact SDR/8-bit selections are admitted until HDR support is
   * proven end to end. Optional fallback is forbidden after an uncertain
   * rollback or a backend response that cannot be safely released.
   *
   * @param policy Configured activation/fallback policy.
   * @param request Exact requested mode and Latency/Quality delivery policy.
   * @param limits Intersected host/GPU/encoder limits.
   * @param physical_capture Existing physical capture selector to preserve on fallback.
   * @param backend Injectable activation backend.
   * @return Exact capture selection, safe physical fallback, or rejection.
   */
  [[nodiscard]] session_prepare_result_t prepare_stream_session(
    activation_policy_e policy,
    const stream_request_t &request,
    const mode_limits_t &limits,
    std::string physical_capture,
    std::shared_ptr<activation_backend_t> backend
  );

  /** @brief Exclusive, generation-fenced VDD lifecycle coordinator. */
  class coordinator_t {
  public:
    coordinator_t(std::shared_ptr<control_channel_t> channel, std::shared_ptr<display_config_t> display);
    ~coordinator_t();

    coordinator_t(const coordinator_t &) = delete;
    coordinator_t &operator=(const coordinator_t &) = delete;

    /**
     * @brief Validate, expose, activate, settle, and select an exact display mode.
     * @param request Stream request.
     * @param system_limits Encoder/GPU/system limits already intersected by the caller.
     * @return Transaction result.
     */
    [[nodiscard]] start_result_t start(const stream_request_t &request, const mode_limits_t &system_limits);

    /**
     * @brief Restore topology and release the exact owning generation.
     * @param session_id Owning session ID.
     * @return True after an idempotent or successful stop.
     */
    bool stop(std::uint64_t session_id) noexcept;

    /** @brief Return the current selection for diagnostics. */
    [[nodiscard]] std::optional<stream_selection_t> active_selection() const;

  private:
    struct active_t {
      stream_selection_t selection;  ///< Current exact selection.
      display_snapshot_t snapshot;  ///< Pre-transaction topology.
    };

    struct pending_cleanup_t {
      std::uint64_t session_id {};  ///< Session whose failed start still owns cleanup.
      std::uint64_t generation {};  ///< Exact generation requiring rollback.
      display_snapshot_t snapshot;  ///< Pre-transaction topology to restore.
    };

    bool rollback_locked(std::uint64_t generation, const display_snapshot_t *snapshot) noexcept;
    start_result_t fail_transaction_locked(
      start_error_e error,
      std::uint64_t session_id,
      std::uint64_t generation,
      display_snapshot_t snapshot
    );

    std::shared_ptr<control_channel_t> channel_;  ///< Secured driver channel.
    std::shared_ptr<display_config_t> display_;  ///< DisplayConfig backend.
    mutable std::mutex mutex_;  ///< Serializes lifecycle and diagnostics.
    std::optional<active_t> active_;  ///< Exclusive active generation.
    std::optional<pending_cleanup_t> pending_cleanup_;  ///< Failed rollback retained for retry.
    std::uint64_t next_generation_ {1};  ///< Monotonic local generation.
  };

  /** @brief Create the production secured driver channel on Windows. */
  [[nodiscard]] std::shared_ptr<control_channel_t> make_system_control_channel();

  /** @brief Create the production DisplayConfig backend on Windows. */
  [[nodiscard]] std::shared_ptr<display_config_t> make_system_display_config();

  /** @brief Result of optional production VDD activation. */
  enum class system_activation_e {
    active,  ///< Exact VDD mode is active and should be captured.
    fallback,  ///< Driver/topology unavailable; preserve the existing capture path.
  };

  /** @brief Optional production activation result used at protocol boundaries. */
  struct system_activation_result_t {
    system_activation_e outcome {system_activation_e::fallback};  ///< Active or compatibility fallback.
    std::optional<stream_selection_t> selection;  ///< Exact selected mode when active.
    start_error_e diagnostic {start_error_e::driver_unavailable};  ///< Stable fallback reason.
  };

  /**
   * @brief Attempt exact VDD activation without breaking legacy capture fallback.
   * @param request Exact validated stream request.
   * @param limits GPU/encoder/system limits.
   * @return Active selection or an explicit fallback result.
   */
  [[nodiscard]] system_activation_result_t activate_system_stream(
    const stream_request_t &request,
    const mode_limits_t &limits
  );

  /**
   * @brief Stop an active optional VDD generation for one session.
   * @param session_id Exact owning stream ID.
   * @return True after successful/idempotent teardown.
   */
  bool deactivate_system_stream(std::uint64_t session_id) noexcept;

  /**
   * @brief Apply the transport-neutral live-session policy through the production coordinator.
   * @param policy Configured activation/fallback policy.
   * @param request Exact stream request.
   * @param limits Intersected host/GPU/encoder limits.
   * @param physical_capture Existing physical capture selector.
   * @return Exact VDD selection, physical fallback, or safe rejection.
   */
  [[nodiscard]] session_prepare_result_t prepare_system_stream_session(
    activation_policy_e policy,
    const stream_request_t &request,
    const mode_limits_t &limits,
    std::string physical_capture
  );
}  // namespace platf::virtual_display
