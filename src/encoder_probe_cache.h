/**
 * @file src/encoder_probe_cache.h
 * @brief Identity and reuse policy for cached encoder capability probes.
 */
#pragma once

// standard includes
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace video {
  /**
   * @brief Exact Windows adapter, driver, and output selected by a successful display open.
   */
  struct encoder_probe_device_identity_t {
    std::uint64_t adapter_luid;  ///< Locally unique DXGI adapter identifier.
    std::uint32_t vendor_id;  ///< PCI vendor identifier.
    std::uint32_t device_id;  ///< PCI device identifier.
    std::uint32_t subsystem_id;  ///< PCI subsystem identifier.
    std::uint32_t revision;  ///< PCI device revision.
    std::uint64_t driver_version;  ///< UMD driver version reported by DXGI.
    std::string output_name;  ///< Exact DXGI output opened by the display backend.

    bool operator==(const encoder_probe_device_identity_t &) const = default;
  };

  /**
   * @brief One adapter/output candidate encountered in capture-selection order.
   */
  struct encoder_probe_device_candidate_t {
    encoder_probe_device_identity_t identity;
    bool adapter_matches;  ///< Candidate passes the configured adapter filter.
    bool output_matches;  ///< Candidate passes the configured output filter.
    bool attached;  ///< Output is active on the desktop.
    bool capture_supported;  ///< Capture backend can open this output.
  };

  /**
   * @brief Ordered capture-target selection state shared by production and tests.
   */
  class encoder_probe_device_selection_t {
  public:
    /** Observe one candidate in platform enumeration order. */
    void observe(encoder_probe_device_candidate_t candidate) {
      if (!selected_ &&
          candidate.adapter_matches &&
          candidate.output_matches &&
          candidate.attached &&
          candidate.capture_supported) {
        selected_ = std::move(candidate.identity);
      }
    }

    /** Return the first eligible candidate observed. */
    [[nodiscard]] const std::optional<encoder_probe_device_identity_t> &selected() const {
      return selected_;
    }

  private:
    std::optional<encoder_probe_device_identity_t> selected_;
  };

  /**
   * @brief Configured adapter/output selection policy, independent of the concrete opened target.
   */
  struct encoder_probe_selection_intent_t {
    std::string raw_adapter_filter;  ///< Raw configured adapter name.
    std::string raw_output_filter;  ///< Raw configured display device ID or output name.
    std::string resolved_output_filter;  ///< Output name resolved from the configured display ID.
    bool adapter_was_automatic;  ///< Adapter selection was automatic in configuration.
    bool output_was_automatic;  ///< Output selection was automatic in configuration.

    bool operator==(const encoder_probe_selection_intent_t &) const = default;
  };

  /**
   * @brief Exact opened device plus the configured selection policy that produced it.
   */
  struct encoder_probe_opened_device_baseline_t {
    encoder_probe_device_identity_t identity;
    encoder_probe_selection_intent_t selection_intent;
  };

  /** Return whether current topology must replay the configured selection policy. */
  [[nodiscard]] inline bool encoder_probe_selection_requires_replay(const encoder_probe_selection_intent_t &intent) {
    return intent.adapter_was_automatic || intent.output_was_automatic;
  }

  /**
   * @brief Platform and policy identity associated with cached encoder capabilities.
   * @details Capabilities may only be reused while every field still identifies the
   * same capture target and encoder-selection policy.
   */
  struct encoder_probe_identity_t {
    std::string adapter_name;  ///< Configured display adapter identity.
    std::string raw_output_name;  ///< Raw configured display device ID or output name.
    std::string resolved_output_name;  ///< Display output resolved from the configured device ID.
    std::string capture;  ///< Capture backend used during validation.
    std::string encoder;  ///< Explicit encoder selection, or empty for automatic selection.
    int hevc_mode;  ///< HEVC capability policy used during validation.
    int av1_mode;  ///< AV1 capability policy used during validation.
    bool force_video_header_replace;  ///< Whether VUI capability was overridden by configuration.
    bool device_identity_required;  ///< Whether a successful platform display binding is required.
    std::optional<encoder_probe_device_identity_t> device_identity;  ///< Exact opened adapter/driver/output binding.

    bool operator==(const encoder_probe_identity_t &) const = default;
  };

  /**
   * @brief Check whether an encoder-probe identity can safely back a cache entry.
   */
  [[nodiscard]] inline bool encoder_probe_identity_is_cacheable(const encoder_probe_identity_t &identity) {
    const bool configured_output_resolution_failed = !identity.raw_output_name.empty() && identity.resolved_output_name.empty();
    return !configured_output_resolution_failed && (!identity.device_identity_required || identity.device_identity.has_value());
  }

  /**
   * @brief Compare the configured probe request while ignoring the device binding discovered by the probe.
   */
  [[nodiscard]] inline bool same_encoder_probe_request(
    const encoder_probe_identity_t &lhs,
    const encoder_probe_identity_t &rhs
  ) {
    return lhs.adapter_name == rhs.adapter_name &&
           lhs.raw_output_name == rhs.raw_output_name &&
           lhs.resolved_output_name == rhs.resolved_output_name &&
           lhs.capture == rhs.capture &&
           lhs.encoder == rhs.encoder &&
           lhs.hevc_mode == rhs.hevc_mode &&
           lhs.av1_mode == rhs.av1_mode &&
           lhs.force_video_header_replace == rhs.force_video_header_replace &&
           lhs.device_identity_required == rhs.device_identity_required;
  }

  /**
   * @brief Decide whether cached encoder capabilities remain safe to reuse.
   *
   * @param has_chosen_encoder Whether a previous probe selected an encoder.
   * @param always_reprobe Whether the selected encoder requires an exhaustive reprobe.
   * @param platform_reenumeration_required Whether the platform reports GPU/display state changes.
   * @param current_identity Current adapter, display, capture, and capability policy identity.
   * @param cached_identity Identity associated with the last successful exhaustive probe.
   * @return True only when the cached selection and capabilities remain valid.
   */
  [[nodiscard]] inline bool can_reuse_encoder_probe(
    bool has_chosen_encoder,
    bool always_reprobe,
    bool platform_reenumeration_required,
    const encoder_probe_identity_t &current_identity,
    const std::optional<encoder_probe_identity_t> &cached_identity
  ) {
    return has_chosen_encoder &&
           !always_reprobe &&
           !platform_reenumeration_required &&
           encoder_probe_identity_is_cacheable(current_identity) &&
           cached_identity &&
           current_identity == *cached_identity;
  }

  /**
   * @brief Decide whether lossless observations may be published for one completed probe generation.
   * @param selected_native_nvenc Whether the final backend is native NVENC.
   * @param topology_changed Whether adapter/output topology changed during the probe.
   * @param request_matches Whether the completed request still matches the starting request.
   * @param identity_committed Whether the exact adapter/output/driver identity committed successfully.
   * @return True only when every generation-binding gate succeeded.
   */
  [[nodiscard]] inline bool can_publish_nvenc_lossless_capabilities(
    bool selected_native_nvenc,
    bool topology_changed,
    bool request_matches,
    bool identity_committed
  ) noexcept {
    return selected_native_nvenc && !topology_changed && request_matches && identity_committed;
  }

  /**
   * @brief Mutable process-local encoder capability cache state.
   */
  class encoder_probe_cache_t {
  public:
    /** Clear the cached probe identity. */
    void clear() {
      identity_.reset();
    }

    /**
     * @brief Commit an identity produced by a successful exhaustive probe.
     * @return True when the identity was cacheable and retained.
     */
    bool commit(encoder_probe_identity_t identity) {
      if (!encoder_probe_identity_is_cacheable(identity)) {
        clear();
        return false;
      }
      identity_ = std::move(identity);
      return true;
    }

    /** Decide whether the retained identity is safe to reuse. */
    [[nodiscard]] bool can_reuse(
      bool has_chosen_encoder,
      bool always_reprobe,
      bool platform_reenumeration_required,
      const encoder_probe_identity_t &current_identity
    ) const {
      return can_reuse_encoder_probe(
        has_chosen_encoder,
        always_reprobe,
        platform_reenumeration_required,
        current_identity,
        identity_
      );
    }

    /** Return the retained identity for diagnostics and tests. */
    [[nodiscard]] const std::optional<encoder_probe_identity_t> &identity() const {
      return identity_;
    }

  private:
    std::optional<encoder_probe_identity_t> identity_;
  };

  /**
   * @brief Exact identity for decoder initialization produced by one encoder tuple.
   *
   * The configuration fingerprint is an unambiguous, collision-free serialization of
   * every stream and encoder setting that can affect codec headers. The probe
   * identity binds it to the concrete adapter, driver, and output generation.
   */
  struct codec_initialization_cache_key_t {
    encoder_probe_identity_t probe_identity;
    std::string encoder_name;
    std::string codec_name;
    std::string configuration_fingerprint;

    bool operator==(const codec_initialization_cache_key_t &) const = default;
  };

  /**
   * @brief Single-entry cache for exact decoder initialization bytes.
   *
   * A single entry deliberately favors the immediately repeated click-to-stream
   * case and prevents stale tuples from accumulating across configuration changes.
   * Callers provide synchronization and topology invalidation.
   */
  class codec_initialization_cache_t {
  public:
    /** Remove any retained initialization tuple. */
    void clear() {
      entry_.reset();
    }

    /**
     * @brief Retain initialization only for a complete, cacheable device identity.
     * @return True when the entry was accepted.
     */
    bool commit(codec_initialization_cache_key_t key, std::vector<std::uint8_t> initialization) {
      constexpr std::size_t maximum_initialization_bytes = 1'048'576U;
      if (!encoder_probe_identity_is_cacheable(key.probe_identity) ||
          initialization.empty() || initialization.size() > maximum_initialization_bytes) {
        clear();
        return false;
      }
      entry_ = entry_t {std::move(key), std::move(initialization)};
      return true;
    }

    /** Return a copy only when every identity and configuration field matches. */
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> lookup(
      const codec_initialization_cache_key_t &key
    ) const {
      if (!entry_ || entry_->key != key) {
        return std::nullopt;
      }
      return entry_->initialization;
    }

  private:
    struct entry_t {
      codec_initialization_cache_key_t key;
      std::vector<std::uint8_t> initialization;
    };

    std::optional<entry_t> entry_;
  };
}  // namespace video
