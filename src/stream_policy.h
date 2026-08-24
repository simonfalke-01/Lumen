/**
 * @file src/stream_policy.h
 * @brief Immutable per-session stream optimization policy declarations.
 */
#pragma once

// standard includes
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

// local includes
#include "nvenc/nvenc_config.h"

namespace stream_policy {

  /**
   * @brief Selects the host-side optimization objective for one stream session.
   */
  enum class StreamOptimizationMode {
    legacy,  ///< Preserve the pre-policy encoder, FEC, and pacing behavior.
    latency,  ///< Prefer the shortest bounded encode and packet-delivery path.
    quality,  ///< Prefer compression quality and stable delivery within bounded latency.
  };

  /** @brief Exact immutable client/transport family selected by negotiation. */
  enum class ClientProtocol {
    vanilla,
    third_party_extension,
    umbra_legacy,
    umbra_v2,
    umbra_v3,
  };

  /**
   * @brief Selects whether the packet sender may add an intra-frame pacing wait.
   */
  enum class PacketPacingMode {
    legacy,  ///< Preserve the existing packet pacing behavior.
    immediate,  ///< Send ready packet batches without an additional pacing wait.
    stable,  ///< Pace packet batches to avoid large bursts and visible jitter.
  };

  /**
   * @brief Exact client fidelity intent, independent of latency/quality mode.
   */
  enum class StreamFidelityRequest {
    unspecified,  ///< No Lumen fidelity extension was sent.
    visually_lossless_allowed,  ///< Explicitly permit bounded rate-controlled Quality encoding.
    codec_lossless_required,  ///< Require losslessness within the negotiated encoder input format.
  };

  /**
   * @brief Honest fidelity class for one exact codec and pixel-format selection.
   */
  enum class SelectedFidelityClass {
    legacy_rate_controlled,  ///< Legacy rate control with no fidelity guarantee.
    latency_rate_controlled,  ///< Latency rate control with no visually-lossless claim.
    visually_lossless_rate_controlled,  ///< Quality rate control; artifacts remain possible.
    codec_lossless_yuv420_8bit,  ///< Lossless after an 8-bit 4:2:0 conversion boundary.
    codec_lossless_yuv420_10bit,  ///< Lossless after a 10-bit 4:2:0 conversion boundary.
    codec_lossless_yuv444_8bit,  ///< Lossless after an 8-bit 4:4:4 conversion boundary.
    codec_lossless_yuv444_10bit,  ///< Lossless after a 10-bit 4:4:4 conversion boundary.
    rejected,  ///< A required proof failed and fallback is forbidden.
  };

  /**
   * @brief Stable fail-closed reason for a required lossless request.
   */
  enum class FidelityRejectionReason {
    none,  ///< No rejection occurred.
    quality_mode_required,  ///< Lossless was requested outside Quality mode.
    decoder_tuple_unproven,  ///< The exact client decoder tuple was not proven.
    encoder_lossless_unavailable,  ///< NVENC lacks lossless support for this codec.
    bit_depth_unavailable,  ///< NVENC lacks the requested input depth.
    chroma_unavailable,  ///< NVENC lacks the requested chroma format.
    h264_high444_required,  ///< H.264 lossless requires High 4:4:4 Predictive 8-bit input.
  };

  /**
   * @brief Runtime codec, decoder, and NVENC proof inputs.
   */
  struct FidelityProof {
    int video_format;  ///< 0 H.264, 1 HEVC, or 2 AV1.
    int bit_depth;  ///< Negotiated encoder-input depth.
    bool yuv444;  ///< Whether the negotiated encoder input is 4:4:4.
    bool decoder_tuple_proven;  ///< Client explicitly offered the exact selected tuple.
    bool encoder_lossless;  ///< Codec-specific NVENC lossless capability.
    bool encoder_bit_depth;  ///< Codec-specific NVENC input-depth capability.
    bool encoder_chroma;  ///< Codec-specific NVENC chroma capability.
  };

  /**
   * @brief Result of an exact fidelity proof.
   */
  struct FidelitySelection {
    SelectedFidelityClass selected;  ///< Selected class or `rejected`.
    FidelityRejectionReason rejection;  ///< Stable rejection reason.
  };

  /**
   * @brief Fixed frame-type FEC percentages for one built-in mode.
   *
   * This is intentionally not described as network-adaptive: Lumen currently has no
   * packet-loss feedback controller. The only production selection is between ordinary
   * interframes and recovery-critical IDR/reference-recovery frames.
   */
  struct StaticFecProfile {
    int minimum_percentage;  ///< Lowest percentage permitted after client-minimum handling.
    int maximum_percentage;  ///< Highest percentage permitted after client-minimum handling.
    int ordinary_percentage;  ///< Fixed percentage for ordinary interframes.
    int recovery_percentage;  ///< Fixed percentage for IDR or reference-recovery frames.
  };

  /**
   * @brief One fixed built-in non-legacy optimization profile.
   */
  struct FixedModeProfile {
    nvenc::nvenc_config nvenc;  ///< NVENC values applied before explicit advanced overrides.
    StaticFecProfile static_profile_fec;  ///< Fixed frame-type FEC percentages.
    PacketPacingMode packet_pacing;  ///< Packet pacing behavior.
  };

  /**
   * @brief Fixed built-in latency and quality profiles.
   *
   * These are product constants rather than host configuration. User-facing advanced
   * NVENC and FEC settings are snapshotted separately as deterministic overrides.
   */
  struct FixedProfiles {
    FixedModeProfile latency;  ///< Fixed low-latency profile.
    FixedModeProfile quality;  ///< Fixed high-quality profile.
  };

  /**
   * @brief Presence flags for legacy advanced settings explicitly configured by the user.
   */
  struct AdvancedOverridePresence {
    bool nvenc_preset;  ///< Whether `nvenc_preset` was explicitly configured.
    bool nvenc_two_pass;  ///< Whether `nvenc_twopass` was explicitly configured.
    bool nvenc_spatial_aq;  ///< Whether `nvenc_spatial_aq` was explicitly configured.
    bool nvenc_vbv_increase;  ///< Whether `nvenc_vbv_increase` was explicitly configured.
    bool fec_percentage;  ///< Whether `fec_percentage` was explicitly configured.
  };

  /**
   * @brief Immutable values captured from explicit advanced configuration at session resolution.
   */
  struct AdvancedOverrides {
    std::optional<int> nvenc_preset;  ///< Explicit NVENC preset override.
    std::optional<nvenc::nvenc_two_pass> nvenc_two_pass;  ///< Explicit NVENC multipass override.
    std::optional<bool> nvenc_spatial_aq;  ///< Explicit NVENC spatial-AQ override.
    std::optional<int> nvenc_vbv_increase;  ///< Explicit NVENC VBV increase override.
    std::optional<int> fec_percentage;  ///< Explicit FEC override before profile bounds are applied.
  };

  /**
   * @brief Fully resolved immutable policy consumed by one stream session.
   */
  struct EffectiveStreamPolicy {
    StreamOptimizationMode mode;  ///< Effective session optimization mode.
    nvenc::nvenc_config nvenc;  ///< Effective NVENC configuration for the session.
    StaticFecProfile static_profile_fec;  ///< Effective fixed frame-type FEC selection.
    PacketPacingMode packet_pacing;  ///< Effective packet pacing behavior.
    bool client_negotiated_mode;  ///< Whether the RTSP attribute explicitly selected this mode.
    StreamFidelityRequest fidelity_request;  ///< Exact requested fidelity semantics.
    SelectedFidelityClass selected_fidelity;  ///< Pre-encoder class; required lossless is re-proven at NVENC creation.
  };

  /**
   * @brief Result of strictly parsing the optional RTSP optimization-mode attribute.
   */
  struct ParsedOptimizationMode {
    /**
     * @brief Parser status for an optional optimization-mode attribute.
     */
    enum class Status {
      absent,  ///< The optional attribute was not present.
      valid,  ///< The attribute contained one exact supported value.
      invalid,  ///< The attribute was malformed, duplicated, or unsupported.
    };

    Status status;  ///< Parser outcome.
    StreamOptimizationMode mode;  ///< Parsed mode when `status` is `valid`.
  };

  /** @brief Strict client-family classification from dedicated ANNOUNCE evidence. */
  struct ParsedClientProtocol {
    enum class Status {
      valid,
      invalid,
    };
    Status status;
    ClientProtocol protocol;
  };

  /**
   * @brief Strict parser result for the optional RTSP fidelity attribute.
   */
  struct ParsedFidelityRequest {
    using Status = ParsedOptimizationMode::Status;  ///< Same absent/valid/invalid states.

    Status status;  ///< Parser outcome.
    StreamFidelityRequest request;  ///< Parsed request when valid.
  };

  /**
   * @brief FEC inputs passed to the production Reed-Solomon packetizer for one frame.
   */
  struct FrameFecSelection {
    int percentage;  ///< Fixed percentage selected for this frame type.
    std::size_t minimum_fec_packets;  ///< Negotiated minimum capped by the profile maximum.
  };

  /**
   * @brief Per-session pacing and duplicate-frame timestamp state.
   */
  struct SessionPacingState {
    std::chrono::steady_clock::time_point next_frame_start;  ///< Earliest paced start and duplicate timestamp basis for this session.
  };

  /**
   * @brief Return the fixed built-in latency and quality profiles.
   * @return Product-constant profile set.
   */
  [[nodiscard]] FixedProfiles fixed_profiles();

  /**
   * @brief Strictly parse one optional optimization-mode value.
   * @param value Optional raw attribute value.
   * @return Parse status and mode. Only exact lowercase `latency` and `quality` are valid.
   */
  [[nodiscard]] ParsedOptimizationMode parse_optimization_mode(std::optional<std::string_view> value);

  /**
   * @brief Parse the complete RTSP ANNOUNCE SDP payload for the optional mode attribute.
   *
   * Missing attributes return `absent`. Missing values, duplicates, whitespace variants,
   * unsupported values, and case variants return `invalid`.
   *
   * @param payload Complete ANNOUNCE SDP payload.
   * @return Strict end-to-end attribute parse result.
   */
  [[nodiscard]] ParsedOptimizationMode parse_rtsp_announce_optimization_mode(std::string_view payload);

  /** @brief Strictly classify vanilla, third-party extension, or Umbra legacy ANNOUNCE. */
  [[nodiscard]] ParsedClientProtocol parse_rtsp_announce_client_protocol(std::string_view payload);

  /**
   * @brief Strictly parse the optional `x-lumen-video-fidelity` ANNOUNCE attribute.
   * @param payload Complete ANNOUNCE SDP payload.
   * @return Exact absent/valid/invalid parse result.
   */
  [[nodiscard]] ParsedFidelityRequest parse_rtsp_announce_fidelity_request(std::string_view payload);

  /**
   * @brief Snapshot explicitly configured advanced settings before a session starts.
   * @param configured_nvenc Current configured NVENC values.
   * @param configured_fec_percentage Current configured FEC percentage.
   * @param presence Explicit-setting presence flags.
   * @return Immutable optional overrides for policy resolution.
   */
  [[nodiscard]] AdvancedOverrides capture_advanced_overrides(
    const nvenc::nvenc_config &configured_nvenc,
    int configured_fec_percentage,
    const AdvancedOverridePresence &presence
  );

  /**
   * @brief Resolve a complete policy once for a new session.
   *
   * Explicit advanced settings take precedence over fixed encoder values. FEC overrides
   * are clamped to the selected mode's bounds. Legacy mode returns configured values unchanged.
   * An internally defaulted latency policy retains at least two-percent ordinary-frame FEC;
   * zero-percent ordinary FEC requires an explicit RTSP latency selection.
   *
   * @param requested_mode Client-requested mode, if present.
   * @param internal_default Internal mode used when no client mode is supplied.
   * @param configured_nvenc Current configured NVENC values.
   * @param configured_fec_percentage Current configured FEC percentage.
   * @param overrides Explicit advanced-setting snapshot.
   * @return Fully resolved session policy.
   */
  [[nodiscard]] EffectiveStreamPolicy resolve_policy(
    std::optional<StreamOptimizationMode> requested_mode,
    StreamOptimizationMode internal_default,
    const nvenc::nvenc_config &configured_nvenc,
    int configured_fec_percentage,
    const AdvancedOverrides &overrides,
    std::optional<StreamFidelityRequest> requested_fidelity = std::nullopt
  );

  /**
   * @brief Resolve an honest fidelity class without silently changing the request.
   * @param mode Effective optimization mode.
   * @param request Exact client request.
   * @param proof Runtime codec/pixel-format/decoder/NVENC proof.
   * @return Selected class or fail-closed rejection.
   */
  [[nodiscard]] FidelitySelection select_fidelity(
    StreamOptimizationMode mode,
    StreamFidelityRequest request,
    const FidelityProof &proof
  );

  /**
   * @brief Decide whether one encoder backend may serve this immutable policy.
   * @param policy Effective session policy.
   * @param native_nvenc Whether the candidate is the native runtime-gated NVENC path.
   * @return False for every fallback/alternate backend when lossless is required.
   */
  [[nodiscard]] bool permits_encoder_backend(
    const EffectiveStreamPolicy &policy,
    bool native_nvenc
  ) noexcept;

  /**
   * @brief Record a codec-specific NVENC lossless observation during encoder probing.
   * @param video_format 0 H.264, 1 HEVC, or 2 AV1.
   * @param supported Whether NVENC reported lossless support.
   */
  void record_nvenc_lossless_capability(int video_format, bool supported) noexcept;

  /** @brief Clear all cached NVENC lossless observations before a fresh probe. */
  void reset_nvenc_lossless_capabilities() noexcept;

  /**
   * @brief Publish probe observations only after the final encoder/device selection is known.
   * @param selected_nvenc Whether the final encoder is the native NVENC path.
   */
  void publish_nvenc_lossless_capabilities(bool selected_nvenc) noexcept;

  /**
   * @brief Read a codec-specific lossless observation from the completed NVENC probe.
   * @param video_format 0 H.264, 1 HEVC, or 2 AV1.
   * @return True only after positive runtime proof.
   */
  [[nodiscard]] bool nvenc_lossless_capability(int video_format) noexcept;

  /**
   * @brief Select bounded packetizer FEC inputs for one encoded frame.
   * @param policy Resolved session policy.
   * @param recovery_critical Whether the frame is an IDR or reference-recovery frame.
   * @param data_shards Number of data shards in the current FEC block.
   * @param negotiated_minimum_packets Client-negotiated minimum recovery-shard count.
   * @return Fixed percentage and a negotiated minimum capped to the profile range.
   */
  [[nodiscard]] FrameFecSelection select_frame_fec(
    const EffectiveStreamPolicy &policy,
    bool recovery_critical,
    std::size_t data_shards,
    std::size_t negotiated_minimum_packets
  );

  /**
   * @brief Pack the GameStream video FEC header word used by the production sender.
   * @param shard_index Recovery/data shard index within the block.
   * @param data_shards Number of original data shards.
   * @param percentage Effective FEC percentage advertised in the packet header.
   * @return Packed `fecInfo` field.
   */
  [[nodiscard]] std::uint32_t pack_video_fec_info(
    std::size_t shard_index,
    std::size_t data_shards,
    int percentage
  );

  /**
   * @brief Return the largest FEC percentage the session can emit.
   * @param policy Resolved session policy.
   * @return Worst-case FEC percentage used for bitrate reservation.
   */
  [[nodiscard]] int maximum_fec_percentage(const EffectiveStreamPolicy &policy);

  /**
   * @brief Reserve configured video bitrate for the policy's worst-case FEC overhead.
   * @param configured_bitrate_kbps Client-configured total video traffic budget.
   * @param policy Resolved session policy.
   * @return Encoder bitrate after the same bounded FEC reservation used by RTSP production.
   */
  [[nodiscard]] std::int64_t reserve_bitrate_for_fec(
    std::int64_t configured_bitrate_kbps,
    const EffectiveStreamPolicy &policy
  );

  /**
   * @brief Derive a bounded per-session wire pacing rate from encoder and path budgets.
   * @param encoder_bitrate_kbps Selected encoded-video bitrate after FEC reservation.
   * @param policy Resolved FEC and pacing policy.
   * @param path_budget_bps Declared or measured path ceiling, or zero when unavailable.
   * @return Per-session pacing rate in bits per second, bounded to 64 Kbps..1 Gbps.
   */
  [[nodiscard]] std::uint64_t video_pacing_bitrate_bps(
    std::int64_t encoder_bitrate_kbps,
    const EffectiveStreamPolicy &policy,
    std::uint64_t path_budget_bps
  );

  /**
   * @brief Initialize pacing state for one session.
   * @param now Session-specific pacing epoch.
   * @return Initialized state.
   */
  [[nodiscard]] SessionPacingState initialize_pacing(std::chrono::steady_clock::time_point now);

  /**
   * @brief Select a frame's paced start without consulting other sessions.
   * @param state Per-session pacing state.
   * @param now Current time.
   * @return Later of the session deadline and current time.
   */
  [[nodiscard]] std::chrono::steady_clock::time_point begin_paced_frame(
    const SessionPacingState &state,
    std::chrono::steady_clock::time_point now
  );

  /**
   * @brief Commit the next per-session pacing and duplicate-timestamp basis.
   * @param state Per-session pacing state to update.
   * @param frame_start Selected frame start.
   * @param transmission_budget Estimated intra-frame transmission duration.
   */
  void complete_paced_frame(
    SessionPacingState &state,
    std::chrono::steady_clock::time_point frame_start,
    std::chrono::nanoseconds transmission_budget
  );

  /**
   * @brief Return the duplicate-frame timestamp basis for exactly one session.
   * @param state Per-session pacing state.
   * @return Session's next frame start.
   */
  [[nodiscard]] std::chrono::steady_clock::time_point duplicate_frame_timestamp(const SessionPacingState &state);

  /**
   * @brief Bind one immutable policy to the current encoder thread for a lexical scope.
   */
  class ScopedPolicyBinding {
  public:
    /**
     * @brief Bind a policy and remember the prior thread-local binding.
     * @param policy Policy that remains alive for the binding lifetime.
     */
    explicit ScopedPolicyBinding(const EffectiveStreamPolicy &policy) noexcept;

    /**
     * @brief Restore the exact prior thread-local binding.
     */
    ~ScopedPolicyBinding();

    ScopedPolicyBinding(const ScopedPolicyBinding &) = delete;  ///< Binding scopes cannot be copied.
    ScopedPolicyBinding &operator=(const ScopedPolicyBinding &) = delete;  ///< Binding scopes cannot be copy-assigned.
    ScopedPolicyBinding(ScopedPolicyBinding &&) = delete;  ///< Binding scopes cannot be moved.
    ScopedPolicyBinding &operator=(ScopedPolicyBinding &&) = delete;  ///< Binding scopes cannot be move-assigned.

  private:
    const EffectiveStreamPolicy *previous_;  ///< Prior binding restored at scope exit.
  };

  /**
   * @brief Return the policy bound to the current encoder thread.
   * @return Bound policy, or `nullptr` for probes and work outside a session scope.
   */
  [[nodiscard]] const EffectiveStreamPolicy *current_thread_policy() noexcept;

  /**
   * @brief Return session-effective NVENC settings for the actual current-thread binding seam.
   * @param configured_nvenc Configured base values.
   * @return Bound policy NVENC values, or configured values when the thread is unbound.
   */
  [[nodiscard]] nvenc::nvenc_config current_thread_nvenc_config(const nvenc::nvenc_config &configured_nvenc);

}  // namespace stream_policy
