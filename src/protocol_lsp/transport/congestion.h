/**
 * @file src/protocol_lsp/transport/congestion.h
 * @brief Bounded LSP congestion-profile and DPLPMTUD state.
 */

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace lumen::lsp::transport {
  /** @brief Congestion-controller behavior selected during START. */
  enum class controller_profile : std::uint8_t {
    adaptive_low_latency,  ///< Safe feedback-controlled default.
    competition_lan,  ///< Explicitly provisioned wired-LAN profile.
  };

  /** @brief Static aggregate congestion-controller bounds. */
  struct controller_config {
    controller_profile profile = controller_profile::adaptive_low_latency;  ///< Selected adaptation behavior.
    std::uint64_t initial_pacing_bits_per_second = 20'000'000;  ///< Initial complete IP-layer pacing target.
    std::uint64_t minimum_pacing_bits_per_second = 1'000'000;  ///< Minimum viable aggregate rate.
    std::uint64_t maximum_pacing_bits_per_second = 1'000'000'000;  ///< Adaptive safety ceiling.
    std::uint64_t competition_capacity_bits_per_second = 0;  ///< Explicit competition ceiling; zero disables the profile.
    std::uint64_t reserved_overhead_bits_per_second = 0;  ///< Audio, input, control, and current repair overhead.
    std::uint32_t maximum_rtt_microseconds = 100'000;  ///< Profile RTT violation threshold.
    std::uint32_t queue_delay_budget_microseconds = 10'000;  ///< Negotiated positive one-way queue-delay budget.
  };

  /** @brief Typed congestion-controller configuration failure. */
  enum class controller_error : std::uint8_t {
    none,  ///< Configuration is usable.
    invalid_rate_bounds,  ///< Minimum, initial, or maximum aggregate rates are unordered.
    invalid_overhead,  ///< Reserved minima consume the complete initial or maximum rate.
    invalid_latency_budget,  ///< RTT or queue-delay budget is zero.
    competition_capacity_required,  ///< Competition mode has no explicit capacity ceiling.
    competition_capacity_out_of_range,  ///< Explicit competition ceiling conflicts with rate bounds.
  };

  /** @brief One disjoint RFC-8888-derived aggregate feedback interval. */
  struct controller_feedback {
    std::uint64_t delivered_bytes = 0;  ///< Newly delivered complete IP-layer bytes.
    std::uint64_t lost_bytes = 0;  ///< Newly inferred lost complete IP-layer bytes.
    std::uint64_t ecn_ce_bytes = 0;  ///< Newly delivered bytes carrying ECN-CE.
    std::uint64_t bytes_in_flight = 0;  ///< Current aggregate sender bytes in flight.
    std::uint32_t smoothed_rtt_microseconds = 0;  ///< Current smoothed RTT.
    std::uint32_t rtt_variation_microseconds = 0;  ///< Current RTT variation.
    std::int32_t queue_delay_trend_microseconds = 0;  ///< Signed one-way delay trend without clock synchronization.
  };

  /** @brief Observable aggregate congestion-controller state. */
  struct controller_snapshot {
    std::uint64_t pacing_bits_per_second = 0;  ///< Current complete IP-layer pacing target.
    std::uint64_t encoder_bits_per_second = 0;  ///< Frame-boundary encoder target after reserved overhead.
    std::uint64_t delivered_bytes = 0;  ///< Cumulative delivered bytes.
    std::uint64_t lost_bytes = 0;  ///< Cumulative lost bytes.
    std::uint64_t ecn_ce_bytes = 0;  ///< Cumulative ECN-CE bytes.
    std::uint64_t bytes_in_flight = 0;  ///< Latest aggregate bytes in flight.
    std::uint32_t smoothed_rtt_microseconds = 0;  ///< Latest smoothed RTT.
    std::uint32_t rtt_variation_microseconds = 0;  ///< Latest RTT variation.
    std::int32_t queue_delay_trend_microseconds = 0;  ///< Latest signed delay trend.
    bool minimum_unsustainable = false;  ///< Impairment persisted at the minimum viable aggregate rate.
  };

  /** @brief Deterministic adaptive-low-latency and explicit competition-LAN controller state. */
  class congestion_controller {
  public:
    /**
     * @brief Construct congestion state from static negotiated bounds.
     *
     * @param config Profile, aggregate-rate, overhead, RTT, and delay bounds.
     */
    constexpr explicit congestion_controller(const controller_config config) noexcept:
        config_(config),
        error_(validate(config)),
        pacing_bits_per_second_(error_ == controller_error::none ? config.initial_pacing_bits_per_second : 0) {
    }

    /**
     * @brief Return static configuration status.
     *
     * @return Typed controller error.
     */
    [[nodiscard]] constexpr controller_error error() const noexcept {
      return error_;
    }

    /**
     * @brief Apply one disjoint congestion-feedback interval.
     *
     * Any loss, ECN-CE, positive delay trend, or RTT-budget violation reduces both the pacing and
     * derived encoder targets in this interval. Clean intervals increase at a bounded rate and can
     * never exceed the adaptive maximum or explicit competition ceiling.
     *
     * @param feedback Aggregate interval observation.
     */
    constexpr void apply_feedback(const controller_feedback &feedback) noexcept {
      if (error_ != controller_error::none) {
        return;
      }
      delivered_bytes_ = saturating_add(delivered_bytes_, feedback.delivered_bytes);
      lost_bytes_ = saturating_add(lost_bytes_, feedback.lost_bytes);
      ecn_ce_bytes_ = saturating_add(ecn_ce_bytes_, feedback.ecn_ce_bytes);
      bytes_in_flight_ = feedback.bytes_in_flight;
      smoothed_rtt_microseconds_ = feedback.smoothed_rtt_microseconds;
      rtt_variation_microseconds_ = feedback.rtt_variation_microseconds;
      queue_delay_trend_microseconds_ = feedback.queue_delay_trend_microseconds;

      const auto loss = feedback.lost_bytes != 0;
      const auto ecn = feedback.ecn_ce_bytes != 0;
      filtered_queue_delay_trend_microseconds_ = static_cast<std::int32_t>(
        (static_cast<std::int64_t>(filtered_queue_delay_trend_microseconds_) * 7 +
         feedback.queue_delay_trend_microseconds) /
        8
      );
      if (filtered_queue_delay_trend_microseconds_ > 0) {
        accumulated_queue_growth_microseconds_ = std::min<std::uint64_t>(
          static_cast<std::uint64_t>(config_.queue_delay_budget_microseconds) * 4U,
          accumulated_queue_growth_microseconds_ +
            static_cast<std::uint32_t>(filtered_queue_delay_trend_microseconds_)
        );
        positive_queue_intervals_ = static_cast<std::uint8_t>(std::min<unsigned int>(
          255U,
          static_cast<unsigned int>(positive_queue_intervals_) + 1U
        ));
      } else {
        const auto recovery = static_cast<std::uint64_t>(
          std::max<std::int64_t>(1, -static_cast<std::int64_t>(filtered_queue_delay_trend_microseconds_))
        );
        accumulated_queue_growth_microseconds_ =
          accumulated_queue_growth_microseconds_ > recovery ? accumulated_queue_growth_microseconds_ - recovery : 0;
        positive_queue_intervals_ = 0;
      }
      const auto positive_delay = positive_queue_intervals_ >= 3U &&
                                  accumulated_queue_growth_microseconds_ > config_.queue_delay_budget_microseconds;
      const auto rtt_violation = feedback.smoothed_rtt_microseconds > config_.maximum_rtt_microseconds;
      if (loss || ecn || positive_delay || rtt_violation) {
        const auto reduction_percent = (loss || ecn || rtt_violation) ? 80U : 90U;
        const auto reduced = multiply_percent(pacing_bits_per_second_, reduction_percent);
        const auto prior = pacing_bits_per_second_;
        pacing_bits_per_second_ = std::max(config_.minimum_pacing_bits_per_second, reduced);
        minimum_unsustainable_ = prior == config_.minimum_pacing_bits_per_second &&
                                 pacing_bits_per_second_ == config_.minimum_pacing_bits_per_second;
        if (positive_delay) {
          accumulated_queue_growth_microseconds_ /= 2U;
          positive_queue_intervals_ = 0;
        }
        return;
      }

      if (filtered_queue_delay_trend_microseconds_ > 0) {
        minimum_unsustainable_ = false;
        return;
      }

      minimum_unsustainable_ = false;
      const auto ceiling = profile_ceiling();
      const auto increase = std::max<std::uint64_t>(64'000, pacing_bits_per_second_ / 100U);
      pacing_bits_per_second_ = saturating_bounded_add(pacing_bits_per_second_, increase, ceiling);
    }

    /**
     * @brief Update measured non-video overhead without changing aggregate capacity.
     *
     * @param bits_per_second Audio, input, control, FEC, and RTX wire rate.
     * @return `true` when the new overhead remains below the profile ceiling.
     */
    constexpr bool update_reserved_overhead(const std::uint64_t bits_per_second) noexcept {
      if (error_ != controller_error::none || bits_per_second >= profile_ceiling()) {
        return false;
      }
      config_.reserved_overhead_bits_per_second = bits_per_second;
      return true;
    }

    /**
     * @brief Return current aggregate and encoder-rate state.
     *
     * @return Immutable controller snapshot.
     */
    [[nodiscard]] constexpr controller_snapshot snapshot() const noexcept {
      return {
        .pacing_bits_per_second = pacing_bits_per_second_,
        .encoder_bits_per_second = pacing_bits_per_second_ > config_.reserved_overhead_bits_per_second ?
                                     pacing_bits_per_second_ - config_.reserved_overhead_bits_per_second :
                                     0,
        .delivered_bytes = delivered_bytes_,
        .lost_bytes = lost_bytes_,
        .ecn_ce_bytes = ecn_ce_bytes_,
        .bytes_in_flight = bytes_in_flight_,
        .smoothed_rtt_microseconds = smoothed_rtt_microseconds_,
        .rtt_variation_microseconds = rtt_variation_microseconds_,
        .queue_delay_trend_microseconds = queue_delay_trend_microseconds_,
        .minimum_unsustainable = minimum_unsustainable_,
      };
    }

  private:
    /**
     * @brief Validate profile and rate bounds.
     *
     * @param config Candidate controller configuration.
     * @return Typed validation error.
     */
    [[nodiscard]] static constexpr controller_error validate(const controller_config &config) noexcept {
      if (config.minimum_pacing_bits_per_second == 0 ||
          config.minimum_pacing_bits_per_second > config.initial_pacing_bits_per_second ||
          config.initial_pacing_bits_per_second > config.maximum_pacing_bits_per_second) {
        return controller_error::invalid_rate_bounds;
      }
      if (config.reserved_overhead_bits_per_second >= config.initial_pacing_bits_per_second ||
          config.reserved_overhead_bits_per_second >= config.maximum_pacing_bits_per_second) {
        return controller_error::invalid_overhead;
      }
      if (config.maximum_rtt_microseconds == 0 || config.queue_delay_budget_microseconds == 0) {
        return controller_error::invalid_latency_budget;
      }
      if (config.profile == controller_profile::competition_lan) {
        if (config.competition_capacity_bits_per_second == 0) {
          return controller_error::competition_capacity_required;
        }
        if (config.competition_capacity_bits_per_second < config.initial_pacing_bits_per_second ||
            config.competition_capacity_bits_per_second > config.maximum_pacing_bits_per_second ||
            config.reserved_overhead_bits_per_second >= config.competition_capacity_bits_per_second) {
          return controller_error::competition_capacity_out_of_range;
        }
      }
      return controller_error::none;
    }

    /**
     * @brief Add monotonic counters without wrap.
     *
     * @param left Retained count.
     * @param right Interval count.
     * @return Saturated sum.
     */
    [[nodiscard]] static constexpr std::uint64_t saturating_add(
      const std::uint64_t left,
      const std::uint64_t right
    ) noexcept {
      return left > std::numeric_limits<std::uint64_t>::max() - right ?
               std::numeric_limits<std::uint64_t>::max() :
               left + right;
    }

    /**
     * @brief Add a clean-path increase without exceeding the active ceiling.
     *
     * @param value Current rate.
     * @param increment Bounded additive increase.
     * @param ceiling Active profile ceiling.
     * @return Increased or clamped rate.
     */
    [[nodiscard]] static constexpr std::uint64_t saturating_bounded_add(
      const std::uint64_t value,
      const std::uint64_t increment,
      const std::uint64_t ceiling
    ) noexcept {
      if (value >= ceiling || increment >= ceiling - value) {
        return ceiling;
      }
      return value + increment;
    }

    /**
     * @brief Multiply a rate by a small whole percentage without overflow.
     *
     * @param value Aggregate bit rate.
     * @param percent Whole percentage from zero through 100.
     * @return Reduced aggregate bit rate.
     */
    [[nodiscard]] static constexpr std::uint64_t multiply_percent(
      const std::uint64_t value,
      const std::uint64_t percent
    ) noexcept {
      return (value / 100U) * percent + ((value % 100U) * percent) / 100U;
    }

    /**
     * @brief Return the hard active aggregate capacity ceiling.
     *
     * @return Adaptive maximum or explicit competition capacity.
     */
    [[nodiscard]] constexpr std::uint64_t profile_ceiling() const noexcept {
      return config_.profile == controller_profile::competition_lan ?
               config_.competition_capacity_bits_per_second :
               config_.maximum_pacing_bits_per_second;
    }

    controller_config config_ {};  ///< Validated mutable controller configuration.
    controller_error error_ = controller_error::none;  ///< Static configuration status.
    std::uint64_t pacing_bits_per_second_ = 0;  ///< Current aggregate pacing target.
    std::uint64_t delivered_bytes_ = 0;  ///< Cumulative delivered bytes.
    std::uint64_t lost_bytes_ = 0;  ///< Cumulative lost bytes.
    std::uint64_t ecn_ce_bytes_ = 0;  ///< Cumulative ECN-CE bytes.
    std::uint64_t bytes_in_flight_ = 0;  ///< Latest aggregate bytes in flight.
    std::uint32_t smoothed_rtt_microseconds_ = 0;  ///< Latest smoothed RTT.
    std::uint32_t rtt_variation_microseconds_ = 0;  ///< Latest RTT variation.
    std::int32_t queue_delay_trend_microseconds_ = 0;  ///< Latest signed delay trend.
    std::int32_t filtered_queue_delay_trend_microseconds_ = 0;  ///< Low-pass trend excluding ATO quantization noise.
    std::uint64_t accumulated_queue_growth_microseconds_ = 0;  ///< Sustained positive queue growth against budget.
    std::uint8_t positive_queue_intervals_ = 0;  ///< Consecutive filtered positive-trend intervals.
    bool minimum_unsustainable_ = false;  ///< Whether impairment persisted at minimum rate.
  };

  /** @brief IP family used to clamp standard-Ethernet UDP payload ceilings. */
  enum class path_ip_version : std::uint8_t {
    ipv4,  ///< Standard 1,500-byte Ethernet ceiling is 1,472 UDP payload bytes.
    ipv6,  ///< Standard 1,500-byte Ethernet ceiling is 1,452 UDP payload bytes.
  };

  /** @brief Negotiated RFC 8899 DPLPMTUD payload bounds. */
  struct path_mtu_config {
    path_ip_version ip_version = path_ip_version::ipv4;  ///< Active address family.
    std::uint16_t sender_interface_limit = 1'472;  ///< Sender interface UDP payload limit.
    std::uint16_t receiver_advertised_limit = 1'472;  ///< Authenticated peer-advertised UDP payload limit.
    std::uint16_t operator_configured_limit = 1'472;  ///< Local operator UDP payload limit.
  };

  /** @brief Metadata for the single outstanding authenticated DPLPMTUD probe. */
  struct path_probe {
    std::uint64_t probe_id = 0;  ///< Random nonzero authenticated control probe ID.
    std::uint16_t payload_bytes = 0;  ///< Exact padded UDP payload size.
    std::uint64_t sent_microseconds = 0;  ///< Monotonic probe submission time.

    /**
     * @brief Return whether a probe is outstanding.
     *
     * @return `true` when the probe ID is nonzero.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return probe_id != 0;
    }
  };

  /** @brief Typed DPLPMTUD transition result. */
  enum class path_mtu_result : std::uint8_t {
    accepted,  ///< Transition completed successfully.
    invalid_configuration,  ///< Effective ceiling is below the 1,200-byte safe base.
    invalid_probe_id,  ///< Probe identifier zero is forbidden.
    probe_outstanding,  ///< A second simultaneous probe is forbidden.
    no_candidate,  ///< No larger untested payload remains.
    invalid_rtt,  ///< Background probing requires a positive smoothed RTT.
    probe_too_soon,  ///< Background probing exceeds the once-per-RTT limit.
    unexpected_ack,  ///< ACK does not match the exact outstanding ID and received size.
    no_outstanding_probe,  ///< Timeout was reported without a live probe.
    invalid_black_hole_fallback,  ///< Fallback is outside 1,200 through the current confirmed size.
  };

  /** @brief Authenticated 1,200-to-1,400-to-ceiling RFC 8899 DPLPMTUD state. */
  class path_mtu_discovery {
  public:
    /** @brief Conservatively usable initial UDP payload. */
    static constexpr std::uint16_t base_payload_bytes = 1'200;

    /** @brief Mandatory initial fast-search UDP payload target. */
    static constexpr std::uint16_t fast_probe_payload_bytes = 1'400;

    /**
     * @brief Construct discovery state and clamp the effective non-fragmenting ceiling.
     *
     * @param config Sender, receiver, operator, and IP-family bounds.
     */
    constexpr explicit path_mtu_discovery(const path_mtu_config config) noexcept:
        config_(config),
        ceiling_payload_bytes_(effective_ceiling(config)),
        upper_exclusive_(static_cast<std::uint32_t>(ceiling_payload_bytes_) + 1U),
        valid_(ceiling_payload_bytes_ >= base_payload_bytes) {
    }

    /**
     * @brief Return whether negotiated bounds retain the 1,200-byte safe base.
     *
     * @return Configuration validity.
     */
    [[nodiscard]] constexpr bool valid() const noexcept {
      return valid_;
    }

    /**
     * @brief Return the largest authenticated confirmed UDP payload.
     *
     * @return Current payload maximum, initially 1,200 bytes.
     */
    [[nodiscard]] constexpr std::uint16_t current_payload_bytes() const noexcept {
      return current_payload_bytes_;
    }

    /**
     * @brief Return the effective standard-Ethernet ceiling.
     *
     * @return Smallest sender, receiver, operator, and address-family limit.
     */
    [[nodiscard]] constexpr std::uint16_t ceiling_payload_bytes() const noexcept {
      return ceiling_payload_bytes_;
    }

    /**
     * @brief Return the next fast or bounded-search candidate.
     *
     * @return Candidate UDP payload, or zero when none is available.
     */
    [[nodiscard]] constexpr std::uint16_t candidate_payload_bytes() const noexcept {
      if (!valid_ || outstanding_) {
        return 0;
      }
      if (!fast_search_complete_) {
        const auto fast_candidate = std::min(fast_probe_payload_bytes, ceiling_payload_bytes_);
        if (fast_candidate > current_payload_bytes_ && fast_candidate < upper_exclusive_) {
          return fast_candidate;
        }
      }
      if (current_payload_bytes_ >= ceiling_payload_bytes_ ||
          upper_exclusive_ <= static_cast<std::uint32_t>(current_payload_bytes_) + 1U) {
        return 0;
      }
      if (upper_exclusive_ == static_cast<std::uint32_t>(ceiling_payload_bytes_) + 1U) {
        return ceiling_payload_bytes_;
      }
      const auto candidate = static_cast<std::uint32_t>(current_payload_bytes_) +
                             (upper_exclusive_ - current_payload_bytes_) / 2U;
      return candidate > current_payload_bytes_ && candidate < upper_exclusive_ ?
               static_cast<std::uint16_t>(candidate) :
               0;
    }

    /**
     * @brief Begin one authenticated application-data-free padded path probe.
     *
     * @param probe_id Random nonzero probe identifier.
     * @param now_microseconds Current monotonic time.
     * @param smoothed_rtt_microseconds Positive SRTT required after initial fast search.
     * @return Typed transition result.
     */
    constexpr path_mtu_result start_probe(
      const std::uint64_t probe_id,
      const std::uint64_t now_microseconds,
      const std::uint64_t smoothed_rtt_microseconds
    ) noexcept {
      if (!valid_) {
        return path_mtu_result::invalid_configuration;
      }
      if (outstanding_) {
        return path_mtu_result::probe_outstanding;
      }
      if (probe_id == 0) {
        return path_mtu_result::invalid_probe_id;
      }
      const auto candidate = candidate_payload_bytes();
      if (candidate == 0) {
        return path_mtu_result::no_candidate;
      }
      if (fast_search_complete_) {
        if (smoothed_rtt_microseconds == 0) {
          return path_mtu_result::invalid_rtt;
        }
        if (has_probed_ &&
            (now_microseconds < last_probe_microseconds_ ||
             now_microseconds - last_probe_microseconds_ < smoothed_rtt_microseconds)) {
          return path_mtu_result::probe_too_soon;
        }
      }
      outstanding_ = {
        .probe_id = probe_id,
        .payload_bytes = candidate,
        .sent_microseconds = now_microseconds,
      };
      last_probe_microseconds_ = now_microseconds;
      has_probed_ = true;
      return path_mtu_result::accepted;
    }

    /**
     * @brief Confirm an exact authenticated `PATH_PROBE_ACK`.
     *
     * @param probe_id Acknowledged random identifier.
     * @param received_payload_bytes Exact payload size observed by the peer.
     * @return Typed transition result.
     */
    constexpr path_mtu_result acknowledge_probe(
      const std::uint64_t probe_id,
      const std::uint16_t received_payload_bytes
    ) noexcept {
      if (!outstanding_ || outstanding_.probe_id != probe_id ||
          outstanding_.payload_bytes != received_payload_bytes) {
        return path_mtu_result::unexpected_ack;
      }
      current_payload_bytes_ = received_payload_bytes;
      fast_search_complete_ = true;
      outstanding_ = {};
      return path_mtu_result::accepted;
    }

    /**
     * @brief Mark the outstanding probe lost without reducing congestion capacity.
     *
     * @return Typed transition result.
     */
    constexpr path_mtu_result probe_timed_out() noexcept {
      if (!outstanding_) {
        return path_mtu_result::no_outstanding_probe;
      }
      upper_exclusive_ = std::min<std::uint32_t>(upper_exclusive_, outstanding_.payload_bytes);
      fast_search_complete_ = true;
      outstanding_ = {};
      return path_mtu_result::accepted;
    }

    /**
     * @brief Apply independently confirmed black-hole fallback immediately.
     *
     * @param fallback_payload_bytes Confirmed safe size between 1,200 and current, inclusive.
     * @return Typed transition result.
     */
    constexpr path_mtu_result confirm_black_hole(
      const std::uint16_t fallback_payload_bytes
    ) noexcept {
      if (fallback_payload_bytes < base_payload_bytes || fallback_payload_bytes > current_payload_bytes_) {
        return path_mtu_result::invalid_black_hole_fallback;
      }
      upper_exclusive_ = std::min<std::uint32_t>(
        upper_exclusive_,
        static_cast<std::uint32_t>(current_payload_bytes_) + 1U
      );
      current_payload_bytes_ = fallback_payload_bytes;
      outstanding_ = {};
      fast_search_complete_ = true;
      return path_mtu_result::accepted;
    }

    /**
     * @brief Reopen bounded upward search after RFC 8899's PMTU_RAISE_TIMER.
     *
     * The largest authenticated safe payload remains unchanged. Only prior failed-candidate state
     * is forgotten so a later probe can test whether the path recovered.
     *
     * @return Accepted when a larger ceiling can be searched, otherwise a typed idle result.
     */
    constexpr path_mtu_result raise_timer_elapsed() noexcept {
      if (!valid_) return path_mtu_result::invalid_configuration;
      if (outstanding_) return path_mtu_result::probe_outstanding;
      if (current_payload_bytes_ >= ceiling_payload_bytes_) return path_mtu_result::no_candidate;
      upper_exclusive_ = static_cast<std::uint32_t>(ceiling_payload_bytes_) + 1U;
      fast_search_complete_ = true;
      return path_mtu_result::accepted;
    }

    /**
     * @brief Return the single outstanding probe.
     *
     * @return Probe metadata, with ID zero when idle.
     */
    [[nodiscard]] constexpr path_probe outstanding_probe() const noexcept {
      return outstanding_;
    }

  private:
    /**
     * @brief Compute the non-fragmenting UDP payload ceiling.
     *
     * @param config Negotiated path limits.
     * @return Smallest configured and standard-Ethernet address-family ceiling.
     */
    [[nodiscard]] static constexpr std::uint16_t effective_ceiling(const path_mtu_config &config) noexcept {
      const auto family_ceiling = config.ip_version == path_ip_version::ipv4 ? 1'472U : 1'452U;
      return static_cast<std::uint16_t>(std::min({
        static_cast<unsigned int>(config.sender_interface_limit),
        static_cast<unsigned int>(config.receiver_advertised_limit),
        static_cast<unsigned int>(config.operator_configured_limit),
        family_ceiling,
      }));
    }

    path_mtu_config config_ {};  ///< Negotiated path limits.
    path_probe outstanding_ {};  ///< Single authenticated outstanding probe.
    std::uint64_t last_probe_microseconds_ = 0;  ///< Most recent probe transmission time.
    std::uint16_t current_payload_bytes_ = base_payload_bytes;  ///< Largest confirmed payload.
    std::uint16_t ceiling_payload_bytes_ = 0;  ///< Effective standard-Ethernet ceiling.
    std::uint32_t upper_exclusive_ = 0;  ///< First known failing size or ceiling plus one.
    bool fast_search_complete_ = false;  ///< Whether the 1,400-byte fast probe resolved.
    bool has_probed_ = false;  ///< Whether the last-probe timestamp is meaningful.
    bool valid_ = false;  ///< Static configuration validity.
  };
}  // namespace lumen::lsp::transport
