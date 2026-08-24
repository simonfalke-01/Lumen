/**
 * @file src/stream_policy.cpp
 * @brief Immutable per-session stream optimization policy definitions.
 */

// this include
#include "stream_policy.h"

// standard includes
#include <algorithm>
#include <array>
#include <atomic>
#include <limits>

namespace stream_policy {
  namespace {
    using namespace std::literals;

    thread_local const EffectiveStreamPolicy *bound_policy;  ///< Policy visible only to the current encoder thread.
    std::array<std::atomic_bool, 3> nvenc_lossless_capabilities {};  ///< Positive observations from the active NVENC probe.
    std::atomic_bool nvenc_lossless_capabilities_published {};  ///< True only for the finally selected native NVENC device generation.

    /**
     * @brief Clamp every static FEC field to a valid ordered percentage range.
     * @param profile Profile to normalize.
     * @return Normalized profile.
     */
    StaticFecProfile normalize_static_fec_profile(StaticFecProfile profile) {
      profile.minimum_percentage = std::clamp(profile.minimum_percentage, 0, 255);
      profile.maximum_percentage = std::clamp(profile.maximum_percentage, profile.minimum_percentage, 255);
      profile.ordinary_percentage = std::clamp(profile.ordinary_percentage, profile.minimum_percentage, profile.maximum_percentage);
      profile.recovery_percentage = std::clamp(profile.recovery_percentage, profile.minimum_percentage, profile.maximum_percentage);
      return profile;
    }

    /**
     * @brief Calculate `ceil(value * percentage / 100)` without overflowing `size_t`.
     * @param value Base shard count.
     * @param percentage Nonnegative percentage.
     * @return Ceiling result, saturated only if the mathematical result exceeds `size_t`.
     */
    std::size_t ceiling_percentage_of(const std::size_t value, const int percentage) {
      if (value == 0 || percentage <= 0) {
        return 0;
      }

      constexpr auto denominator = std::size_t {100};
      const auto unsigned_percentage = static_cast<std::size_t>(percentage);
      const auto quotient = value / denominator;
      const auto remainder = value % denominator;
      if (quotient > std::numeric_limits<std::size_t>::max() / unsigned_percentage) {
        return std::numeric_limits<std::size_t>::max();
      }
      const auto whole = quotient * unsigned_percentage;
      const auto fractional = (remainder * unsigned_percentage + denominator - 1U) / denominator;
      if (whole > std::numeric_limits<std::size_t>::max() - fractional) {
        return std::numeric_limits<std::size_t>::max();
      }
      return whole + fractional;
    }
  }  // namespace

  FixedProfiles fixed_profiles() {
    auto latency_nvenc = nvenc::nvenc_config {};
    latency_nvenc.quality_preset = 1;
    latency_nvenc.tuning = nvenc::nvenc_tuning::ultra_low_latency;
    latency_nvenc.two_pass = nvenc::nvenc_two_pass::disabled;
    latency_nvenc.vbv_percentage_increase = 0;
    latency_nvenc.weighted_prediction = false;
    latency_nvenc.adaptive_quantization = false;

    auto quality_nvenc = nvenc::nvenc_config {};
    quality_nvenc.quality_preset = 5;
    quality_nvenc.tuning = nvenc::nvenc_tuning::high_quality;
    quality_nvenc.two_pass = nvenc::nvenc_two_pass::quarter_resolution;
    quality_nvenc.vbv_percentage_increase = 100;
    quality_nvenc.weighted_prediction = true;
    quality_nvenc.adaptive_quantization = true;

    return FixedProfiles {
      FixedModeProfile {
        latency_nvenc,
        StaticFecProfile {0, 10, 0, 10},
        PacketPacingMode::immediate,
      },
      FixedModeProfile {
        quality_nvenc,
        StaticFecProfile {10, 20, 10, 20},
        PacketPacingMode::stable,
      },
    };
  }

  ParsedOptimizationMode parse_optimization_mode(const std::optional<std::string_view> value) {
    if (!value) {
      return {ParsedOptimizationMode::Status::absent, StreamOptimizationMode::legacy};
    }
    if (*value == "latency") {
      return {ParsedOptimizationMode::Status::valid, StreamOptimizationMode::latency};
    }
    if (*value == "quality") {
      return {ParsedOptimizationMode::Status::valid, StreamOptimizationMode::quality};
    }
    return {ParsedOptimizationMode::Status::invalid, StreamOptimizationMode::legacy};
  }

  ParsedOptimizationMode parse_rtsp_announce_optimization_mode(const std::string_view payload) {
    constexpr auto prefix = "a=x-lumen-optimization-mode"sv;
    std::optional<std::string_view> value;
    std::size_t count {};

    std::size_t line_start {};
    while (line_start <= payload.size()) {
      auto line_end = payload.find('\n', line_start);
      if (line_end == std::string_view::npos) {
        line_end = payload.size();
      }
      auto line = payload.substr(line_start, line_end - line_start);
      if (!line.empty() && line.back() == '\r') {
        line.remove_suffix(1);
      }

      if (line == prefix) {
        ++count;
        value = ""sv;
      } else if (line.starts_with(prefix) && line.size() > prefix.size() && line[prefix.size()] == ':') {
        ++count;
        value = line.substr(prefix.size() + 1);
      }

      if (line_end == payload.size()) {
        break;
      }
      line_start = line_end + 1;
    }

    if (count > 1) {
      return {ParsedOptimizationMode::Status::invalid, StreamOptimizationMode::legacy};
    }
    return parse_optimization_mode(value);
  }

  ParsedClientProtocol parse_rtsp_announce_client_protocol(const std::string_view payload) {
    using Status = ParsedClientProtocol::Status;
    constexpr auto marker = "a=x-umbra-client-protocol"sv;
    constexpr auto legacy_value = "legacy-v1"sv;
    std::optional<std::string_view> marker_value;
    std::size_t marker_count {};
    bool generic_lumen_extension = false;

    std::size_t line_start {};
    while (line_start <= payload.size()) {
      auto line_end = payload.find('\n', line_start);
      if (line_end == std::string_view::npos) {
        line_end = payload.size();
      }
      auto line = payload.substr(line_start, line_end - line_start);
      if (!line.empty() && line.back() == '\r') {
        line.remove_suffix(1);
      }
      generic_lumen_extension = generic_lumen_extension || line.starts_with("a=x-lumen-"sv);
      if (line == marker) {
        ++marker_count;
        marker_value = ""sv;
      } else if (line.starts_with(marker) && line.size() > marker.size() && line[marker.size()] == ':') {
        ++marker_count;
        marker_value = line.substr(marker.size() + 1);
      } else if (line.starts_with(marker)) {
        ++marker_count;
        marker_value = line;
      }
      if (line_end == payload.size()) {
        break;
      }
      line_start = line_end + 1;
    }

    if (marker_count > 1 || (marker_value && *marker_value != legacy_value)) {
      return {Status::invalid, ClientProtocol::vanilla};
    }
    if (marker_value) {
      return {Status::valid, ClientProtocol::umbra_legacy};
    }
    return {
      Status::valid,
      generic_lumen_extension ? ClientProtocol::third_party_extension : ClientProtocol::vanilla,
    };
  }

  ParsedFidelityRequest parse_rtsp_announce_fidelity_request(const std::string_view payload) {
    using Status = ParsedFidelityRequest::Status;
    constexpr auto prefix = "a=x-lumen-video-fidelity"sv;
    std::optional<std::string_view> value;
    std::size_t count {};

    std::size_t line_start {};
    while (line_start <= payload.size()) {
      auto line_end = payload.find('\n', line_start);
      if (line_end == std::string_view::npos) {
        line_end = payload.size();
      }
      auto line = payload.substr(line_start, line_end - line_start);
      if (!line.empty() && line.back() == '\r') {
        line.remove_suffix(1);
      }

      if (line == prefix) {
        ++count;
        value = ""sv;
      } else if (line.starts_with(prefix) && line.size() > prefix.size() && line[prefix.size()] == ':') {
        ++count;
        value = line.substr(prefix.size() + 1);
      }

      if (line_end == payload.size()) {
        break;
      }
      line_start = line_end + 1;
    }

    if (count > 1) {
      return {Status::invalid, StreamFidelityRequest::unspecified};
    }
    if (!value) {
      return {Status::absent, StreamFidelityRequest::unspecified};
    }
    if (*value == "visually-lossless-allowed") {
      return {Status::valid, StreamFidelityRequest::visually_lossless_allowed};
    }
    if (*value == "codec-lossless-required") {
      return {Status::valid, StreamFidelityRequest::codec_lossless_required};
    }
    return {Status::invalid, StreamFidelityRequest::unspecified};
  }

  AdvancedOverrides capture_advanced_overrides(
    const nvenc::nvenc_config &configured_nvenc,
    const int configured_fec_percentage,
    const AdvancedOverridePresence &presence
  ) {
    return AdvancedOverrides {
      presence.nvenc_preset ? std::optional {configured_nvenc.quality_preset} : std::nullopt,
      presence.nvenc_two_pass ? std::optional {configured_nvenc.two_pass} : std::nullopt,
      presence.nvenc_spatial_aq ? std::optional {configured_nvenc.adaptive_quantization} : std::nullopt,
      presence.nvenc_vbv_increase ? std::optional {configured_nvenc.vbv_percentage_increase} : std::nullopt,
      presence.fec_percentage ? std::optional {configured_fec_percentage} : std::nullopt,
    };
  }

  EffectiveStreamPolicy resolve_policy(
    const std::optional<StreamOptimizationMode> requested_mode,
    const StreamOptimizationMode internal_default,
    const nvenc::nvenc_config &configured_nvenc,
    const int configured_fec_percentage,
    const AdvancedOverrides &overrides,
    const std::optional<StreamFidelityRequest> requested_fidelity
  ) {
    const auto mode = requested_mode.value_or(internal_default);
    const bool client_negotiated_mode = requested_mode.has_value();
    if (mode == StreamOptimizationMode::legacy) {
      return EffectiveStreamPolicy {
        mode,
        configured_nvenc,
        StaticFecProfile {configured_fec_percentage, configured_fec_percentage, configured_fec_percentage, configured_fec_percentage},
        PacketPacingMode::legacy,
        client_negotiated_mode,
        StreamFidelityRequest::unspecified,
        SelectedFidelityClass::legacy_rate_controlled,
      };
    }

    const auto profiles = fixed_profiles();
    const auto &profile = mode == StreamOptimizationMode::latency ? profiles.latency : profiles.quality;
    auto effective_nvenc = configured_nvenc;
    effective_nvenc.quality_preset = profile.nvenc.quality_preset;
    effective_nvenc.tuning = profile.nvenc.tuning;
    effective_nvenc.fidelity = profile.nvenc.fidelity;
    effective_nvenc.two_pass = profile.nvenc.two_pass;
    effective_nvenc.vbv_percentage_increase = profile.nvenc.vbv_percentage_increase;
    effective_nvenc.weighted_prediction = profile.nvenc.weighted_prediction;
    effective_nvenc.adaptive_quantization = profile.nvenc.adaptive_quantization;
    const auto fidelity_request = requested_fidelity.value_or(StreamFidelityRequest::unspecified);

    if (overrides.nvenc_preset) {
      effective_nvenc.quality_preset = *overrides.nvenc_preset;
    }
    if (overrides.nvenc_two_pass) {
      effective_nvenc.two_pass = *overrides.nvenc_two_pass;
    }
    if (overrides.nvenc_spatial_aq) {
      effective_nvenc.adaptive_quantization = *overrides.nvenc_spatial_aq;
    }
    if (overrides.nvenc_vbv_increase) {
      effective_nvenc.vbv_percentage_increase = *overrides.nvenc_vbv_increase;
    }
    if (mode == StreamOptimizationMode::quality &&
        fidelity_request == StreamFidelityRequest::codec_lossless_required) {
      effective_nvenc.fidelity = nvenc::nvenc_fidelity::codec_lossless_required;
      effective_nvenc.tuning = nvenc::nvenc_tuning::lossless;
      effective_nvenc.two_pass = nvenc::nvenc_two_pass::disabled;
      effective_nvenc.vbv_percentage_increase = 0;
      effective_nvenc.weighted_prediction = false;
      effective_nvenc.adaptive_quantization = false;
      effective_nvenc.enable_min_qp = false;
      effective_nvenc.insert_filler_data = false;
    }

    auto static_profile_fec = normalize_static_fec_profile(profile.static_profile_fec);
    if (mode == StreamOptimizationMode::latency && !client_negotiated_mode) {
      static_profile_fec.minimum_percentage = 2;
      static_profile_fec.ordinary_percentage = std::max(static_profile_fec.ordinary_percentage, 2);
    }
    if (overrides.fec_percentage) {
      const auto clamped = std::clamp(
        *overrides.fec_percentage,
        static_profile_fec.minimum_percentage,
        static_profile_fec.maximum_percentage
      );
      static_profile_fec.ordinary_percentage = clamped;
      static_profile_fec.recovery_percentage = clamped;
    }

    return EffectiveStreamPolicy {
      mode,
      effective_nvenc,
      static_profile_fec,
      profile.packet_pacing,
      client_negotiated_mode,
      fidelity_request,
      fidelity_request == StreamFidelityRequest::codec_lossless_required ?
        SelectedFidelityClass::rejected :
        (mode == StreamOptimizationMode::latency ?
           SelectedFidelityClass::latency_rate_controlled :
           SelectedFidelityClass::visually_lossless_rate_controlled),
    };
  }

  FidelitySelection select_fidelity(
    const StreamOptimizationMode mode,
    const StreamFidelityRequest request,
    const FidelityProof &proof
  ) {
    if (request != StreamFidelityRequest::codec_lossless_required) {
      return {
        mode == StreamOptimizationMode::legacy ?
          SelectedFidelityClass::legacy_rate_controlled :
          (mode == StreamOptimizationMode::latency ?
             SelectedFidelityClass::latency_rate_controlled :
             SelectedFidelityClass::visually_lossless_rate_controlled),
        FidelityRejectionReason::none,
      };
    }
    if (mode != StreamOptimizationMode::quality) {
      return {SelectedFidelityClass::rejected, FidelityRejectionReason::quality_mode_required};
    }
    if (!proof.decoder_tuple_proven) {
      return {SelectedFidelityClass::rejected, FidelityRejectionReason::decoder_tuple_unproven};
    }
    if (!proof.encoder_lossless) {
      return {SelectedFidelityClass::rejected, FidelityRejectionReason::encoder_lossless_unavailable};
    }
    if (!proof.encoder_bit_depth) {
      return {SelectedFidelityClass::rejected, FidelityRejectionReason::bit_depth_unavailable};
    }
    if (!proof.encoder_chroma) {
      return {SelectedFidelityClass::rejected, FidelityRejectionReason::chroma_unavailable};
    }
    if (proof.video_format == 0 && (proof.bit_depth != 8 || !proof.yuv444)) {
      return {SelectedFidelityClass::rejected, FidelityRejectionReason::h264_high444_required};
    }
    if (proof.yuv444) {
      return {
        proof.bit_depth == 10 ?
          SelectedFidelityClass::codec_lossless_yuv444_10bit :
          SelectedFidelityClass::codec_lossless_yuv444_8bit,
        FidelityRejectionReason::none,
      };
    }
    return {
      proof.bit_depth == 10 ?
        SelectedFidelityClass::codec_lossless_yuv420_10bit :
        SelectedFidelityClass::codec_lossless_yuv420_8bit,
      FidelityRejectionReason::none,
    };
  }

  bool permits_encoder_backend(
    const EffectiveStreamPolicy &policy,
    const bool native_nvenc
  ) noexcept {
    return policy.fidelity_request != StreamFidelityRequest::codec_lossless_required || native_nvenc;
  }

  void record_nvenc_lossless_capability(const int video_format, const bool supported) noexcept {
    if (video_format < 0 || video_format >= static_cast<int>(nvenc_lossless_capabilities.size())) {
      return;
    }
    if (supported) {
      nvenc_lossless_capabilities[static_cast<std::size_t>(video_format)].store(true, std::memory_order_release);
    }
  }

  void reset_nvenc_lossless_capabilities() noexcept {
    nvenc_lossless_capabilities_published.store(false, std::memory_order_release);
    for (auto &capability : nvenc_lossless_capabilities) {
      capability.store(false, std::memory_order_release);
    }
  }

  void publish_nvenc_lossless_capabilities(const bool selected_nvenc) noexcept {
    nvenc_lossless_capabilities_published.store(selected_nvenc, std::memory_order_release);
  }

  bool nvenc_lossless_capability(const int video_format) noexcept {
    if (video_format < 0 || video_format >= static_cast<int>(nvenc_lossless_capabilities.size())) {
      return false;
    }
    return nvenc_lossless_capabilities_published.load(std::memory_order_acquire) &&
           nvenc_lossless_capabilities[static_cast<std::size_t>(video_format)].load(std::memory_order_acquire);
  }

  FrameFecSelection select_frame_fec(
    const EffectiveStreamPolicy &policy,
    const bool recovery_critical,
    const std::size_t data_shards,
    const std::size_t negotiated_minimum_packets
  ) {
    const auto &profile = policy.static_profile_fec;
    const auto selected = std::clamp(
      recovery_critical ? profile.recovery_percentage : profile.ordinary_percentage,
      profile.minimum_percentage,
      profile.maximum_percentage
    );
    if (policy.mode == StreamOptimizationMode::legacy) {
      return {selected, negotiated_minimum_packets};
    }
    if (selected == 0 || data_shards == 0) {
      return {selected, 0};
    }

    const auto maximum_parity_packets = ceiling_percentage_of(data_shards, profile.maximum_percentage);
    const auto bounded_minimum = std::min(negotiated_minimum_packets, maximum_parity_packets);
    const auto selected_parity_packets = ceiling_percentage_of(data_shards, selected);
    if (selected_parity_packets >= bounded_minimum) {
      return {selected, bounded_minimum};
    }

    return {profile.maximum_percentage, bounded_minimum};
  }

  std::uint32_t pack_video_fec_info(
    const std::size_t shard_index,
    const std::size_t data_shards,
    const int percentage
  ) {
    return static_cast<std::uint32_t>(
      shard_index << 12U |
      data_shards << 22U |
      static_cast<std::size_t>(percentage) << 4U
    );
  }

  int maximum_fec_percentage(const EffectiveStreamPolicy &policy) {
    if (policy.mode != StreamOptimizationMode::legacy) {
      return policy.static_profile_fec.maximum_percentage;
    }
    return std::max(
      policy.static_profile_fec.ordinary_percentage,
      policy.static_profile_fec.recovery_percentage
    );
  }

  std::int64_t reserve_bitrate_for_fec(
    const std::int64_t configured_bitrate_kbps,
    const EffectiveStreamPolicy &policy
  ) {
    const auto maximum_percentage = maximum_fec_percentage(policy);
    if (maximum_percentage < 0 || maximum_percentage > 80) {
      return configured_bitrate_kbps;
    }
    const auto retained_percentage = std::int64_t {100 - maximum_percentage};
    const auto quotient = configured_bitrate_kbps / 100;
    const auto remainder = configured_bitrate_kbps % 100;
    return quotient * retained_percentage + remainder * retained_percentage / 100;
  }

  std::uint64_t video_pacing_bitrate_bps(
    const std::int64_t encoder_bitrate_kbps,
    const EffectiveStreamPolicy &policy,
    const std::uint64_t path_budget_bps
  ) {
    constexpr auto minimum_bps = std::uint64_t {64'000};
    constexpr auto maximum_bps = std::uint64_t {1'000'000'000};
    const auto nonnegative_kbps = static_cast<std::uint64_t>(std::max<std::int64_t>(encoder_bitrate_kbps, 0));
    const auto maximum_fec = std::clamp(maximum_fec_percentage(policy), 0, 80);
    const auto retained = static_cast<std::uint64_t>(100 - maximum_fec);
    const auto encoded_bps = nonnegative_kbps > maximum_bps / 1'000 ?
                               maximum_bps :
                               nonnegative_kbps * 1'000;
    const auto quotient = encoded_bps / retained;
    const auto remainder = encoded_bps % retained;
    const auto wire_bps = quotient > maximum_bps / 100 ?
                            maximum_bps :
                            std::min(maximum_bps, quotient * 100 + remainder * 100 / retained);
    const auto selected = path_budget_bps == 0 ? wire_bps : std::min(wire_bps, path_budget_bps);
    return std::clamp(selected, minimum_bps, maximum_bps);
  }

  SessionPacingState initialize_pacing(const std::chrono::steady_clock::time_point now) {
    return {now};
  }

  std::chrono::steady_clock::time_point begin_paced_frame(
    const SessionPacingState &state,
    const std::chrono::steady_clock::time_point now
  ) {
    return std::max(state.next_frame_start, now);
  }

  void complete_paced_frame(
    SessionPacingState &state,
    const std::chrono::steady_clock::time_point frame_start,
    const std::chrono::nanoseconds transmission_budget
  ) {
    state.next_frame_start = frame_start + transmission_budget;
  }

  std::chrono::steady_clock::time_point duplicate_frame_timestamp(const SessionPacingState &state) {
    return state.next_frame_start;
  }

  ScopedPolicyBinding::ScopedPolicyBinding(const EffectiveStreamPolicy &policy) noexcept:
      previous_ {bound_policy} {
    bound_policy = &policy;
  }

  ScopedPolicyBinding::~ScopedPolicyBinding() {
    bound_policy = previous_;
  }

  const EffectiveStreamPolicy *current_thread_policy() noexcept {
    return bound_policy;
  }

  nvenc::nvenc_config current_thread_nvenc_config(const nvenc::nvenc_config &configured_nvenc) {
    return bound_policy ? bound_policy->nvenc : configured_nvenc;
  }

}  // namespace stream_policy
