/**
 * @file src/protocol_lsp/core/transport.h
 * @brief Portable DPLPMTUD, aggregate pacing, and congestion-profile primitives.
 */

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>

namespace lumen::lsp {
  /** @brief Static DPLPMTUD payload-size bounds for one path. */
  struct dplpmtud_config {
    std::uint16_t base_payload = 1'200;  ///< Conservatively usable starting UDP payload.
    std::uint16_t fast_probe_payload = 1'400;  ///< First fast-search target.
    std::uint16_t ceiling_payload = 1'472;  ///< Interface/path ceiling without IP fragmentation.
  };

  /** @brief State of the single outstanding authenticated path probe. */
  struct dplpmtud_probe {
    std::uint64_t probe_id = 0;  ///< Random nonzero authenticated probe identifier.
    std::uint16_t payload_size = 0;  ///< Exact padded UDP payload size.
    std::uint64_t sent_microseconds = 0;  ///< Monotonic probe transmission time.

    /**
     * @brief Return whether a path probe is outstanding.
     *
     * @return `true` when `probe_id` is nonzero.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return probe_id != 0;
    }
  };

  /** @brief Result of a DPLPMTUD state transition. */
  enum class dplpmtud_result : std::uint8_t {
    accepted,  ///< State transition was accepted.
    invalid_configuration,  ///< Configured sizes are not monotonically valid.
    no_candidate,  ///< Search has no larger untested payload size.
    probe_outstanding,  ///< A second simultaneous probe is forbidden.
    probe_too_soon,  ///< Post-initial probe violates the once-per-RTT limit.
    invalid_rtt,  ///< Post-initial probing requires a positive smoothed RTT.
    invalid_probe_id,  ///< Probe identifier zero is forbidden.
    unexpected_ack,  ///< ACK does not match the outstanding identifier and exact size.
    no_outstanding_probe,  ///< Timeout was reported without an outstanding probe.
    invalid_fallback,  ///< Black-hole fallback is outside base through current size.
  };

  /** @brief Authenticated RFC 8899 DPLPMTUD search state with one outstanding probe. */
  class dplpmtud {
  public:
    /**
     * @brief Construct path discovery state.
     *
     * @param config Static UDP payload bounds.
     */
    constexpr explicit dplpmtud(const dplpmtud_config config) noexcept:
        config_(config),
        upper_exclusive_(static_cast<std::uint32_t>(config.ceiling_payload) + 1U),
        current_payload_(config.base_payload),
        valid_(config.base_payload > 0 && config.base_payload <= config.fast_probe_payload && config.fast_probe_payload <= config.ceiling_payload) {
    }

    /**
     * @brief Return whether configured payload bounds are valid.
     *
     * @return Configuration validity.
     */
    [[nodiscard]] constexpr bool valid() const noexcept {
      return valid_;
    }

    /**
     * @brief Return the currently confirmed maximum UDP payload.
     *
     * @return Confirmed path payload size.
     */
    [[nodiscard]] constexpr std::uint16_t current_payload() const noexcept {
      return current_payload_;
    }

    /**
     * @brief Return the next fast or bounded-search probe size.
     *
     * @return Candidate size, or zero when no larger candidate exists.
     */
    [[nodiscard]] constexpr std::uint16_t candidate_payload() const noexcept {
      if (!valid_ || outstanding_) {
        return 0;
      }
      if (current_payload_ < config_.fast_probe_payload && config_.fast_probe_payload < upper_exclusive_) {
        return config_.fast_probe_payload;
      }
      if (current_payload_ >= config_.ceiling_payload || upper_exclusive_ <= static_cast<std::uint32_t>(current_payload_) + 1U) {
        return 0;
      }
      if (upper_exclusive_ == static_cast<std::uint32_t>(config_.ceiling_payload) + 1U) {
        return config_.ceiling_payload;
      }
      const auto candidate = static_cast<std::uint32_t>(current_payload_) +
                             (upper_exclusive_ - current_payload_) / 2U;
      return candidate > current_payload_ && candidate < upper_exclusive_ ? static_cast<std::uint16_t>(candidate) : 0;
    }

    /**
     * @brief Start one authenticated, application-data-free padded path probe.
     *
     * @param probe_id Random nonzero probe identifier supplied by the crypto/session layer.
     * @param now_microseconds Current monotonic time.
     * @param smoothed_rtt_microseconds Current positive SRTT used after initial fast search.
     * @return State-transition result.
     */
    constexpr dplpmtud_result start_probe(
      const std::uint64_t probe_id,
      const std::uint64_t now_microseconds,
      const std::uint64_t smoothed_rtt_microseconds
    ) noexcept {
      if (!valid_) {
        return dplpmtud_result::invalid_configuration;
      }
      if (outstanding_) {
        return dplpmtud_result::probe_outstanding;
      }
      if (probe_id == 0) {
        return dplpmtud_result::invalid_probe_id;
      }
      const auto candidate = candidate_payload();
      if (candidate == 0) {
        return dplpmtud_result::no_candidate;
      }
      if (!initial_search_) {
        if (smoothed_rtt_microseconds == 0) {
          return dplpmtud_result::invalid_rtt;
        }
        if (has_probed_ &&
            (now_microseconds < last_probe_microseconds_ ||
             now_microseconds - last_probe_microseconds_ < smoothed_rtt_microseconds)) {
          return dplpmtud_result::probe_too_soon;
        }
      }
      outstanding_ = {
        .probe_id = probe_id,
        .payload_size = candidate,
        .sent_microseconds = now_microseconds,
      };
      last_probe_microseconds_ = now_microseconds;
      has_probed_ = true;
      return dplpmtud_result::accepted;
    }

    /**
     * @brief Confirm an exact authenticated probe ACK.
     *
     * @param probe_id ACK probe identifier.
     * @param received_size Exact UDP payload size named by the peer.
     * @return State-transition result.
     */
    constexpr dplpmtud_result acknowledge(
      const std::uint64_t probe_id,
      const std::uint16_t received_size
    ) noexcept {
      if (!outstanding_ || outstanding_.probe_id != probe_id || outstanding_.payload_size != received_size) {
        return dplpmtud_result::unexpected_ack;
      }
      current_payload_ = received_size;
      if (current_payload_ >= config_.fast_probe_payload) {
        initial_search_ = false;
      }
      outstanding_ = {};
      return dplpmtud_result::accepted;
    }

    /**
     * @brief Mark the single outstanding probe lost without reducing congestion capacity.
     *
     * The failed size becomes an exclusive upper search bound while the confirmed payload remains
     * unchanged.
     *
     * @return State-transition result.
     */
    constexpr dplpmtud_result probe_timed_out() noexcept {
      if (!outstanding_) {
        return dplpmtud_result::no_outstanding_probe;
      }
      upper_exclusive_ = std::min<std::uint32_t>(upper_exclusive_, outstanding_.payload_size);
      outstanding_ = {};
      return dplpmtud_result::accepted;
    }

    /**
     * @brief Immediately reduce the confirmed maximum after independent black-hole evidence.
     *
     * @param fallback_payload Confirmed safe payload between base and current, inclusive.
     * @return State-transition result.
     */
    constexpr dplpmtud_result confirm_black_hole(const std::uint16_t fallback_payload) noexcept {
      if (!valid_ || fallback_payload < config_.base_payload || fallback_payload > current_payload_) {
        return dplpmtud_result::invalid_fallback;
      }
      upper_exclusive_ = std::min<std::uint32_t>(upper_exclusive_, static_cast<std::uint32_t>(current_payload_) + 1U);
      current_payload_ = fallback_payload;
      outstanding_ = {};
      initial_search_ = current_payload_ < config_.fast_probe_payload;
      return dplpmtud_result::accepted;
    }

    /**
     * @brief Return the single outstanding probe.
     *
     * @return Probe metadata, with identifier zero when none is outstanding.
     */
    [[nodiscard]] constexpr dplpmtud_probe outstanding_probe() const noexcept {
      return outstanding_;
    }

  private:
    dplpmtud_config config_ {};  ///< Static path bounds.
    dplpmtud_probe outstanding_ {};  ///< Single outstanding probe.
    std::uint64_t last_probe_microseconds_ = 0;  ///< Most recent probe transmission time.
    std::uint32_t upper_exclusive_ = 0;  ///< First known failing or ceiling-plus-one size.
    std::uint16_t current_payload_ = 0;  ///< Largest confirmed payload size.
    bool initial_search_ = true;  ///< Whether fast search may proceed without a full RTT pause.
    bool has_probed_ = false;  ///< Whether `last_probe_microseconds_` is meaningful, including time zero.
    bool valid_ = false;  ///< Configuration validity.
  };

  /** @brief Aggregate congestion-control profile. */
  enum class congestion_profile : std::uint8_t {
    adaptive_low_latency,  ///< Feedback-controlled safe default.
    competition_lan,  ///< Explicitly provisioned capacity-ceiling profile.
  };

  /** @brief Static configuration for aggregate byte pacing. */
  struct pacer_config {
    std::uint64_t pacing_bits_per_second = 0;  ///< Complete aggregate IP-layer wire rate.
    std::uint64_t input_reserve_bits_per_second = 0;  ///< Protected client-to-host input sub-rate, at most 32 Mbps.
    std::uint16_t path_datagram_bytes = 1'400;  ///< Complete path-sized IP/UDP datagram charge.
    std::uint16_t quantum_microseconds = 100;  ///< Rate-derived microbatch duration, at most 100 microseconds.
    std::uint16_t submission_horizon_microseconds = 200;  ///< Maximum future credit, at most 200 microseconds.
    std::uint8_t max_datagrams_per_batch = 8;  ///< Maximum datagrams granted per microbatch, one through eight.
  };

  /** @brief Validation failure for aggregate byte pacing. */
  enum class pacer_error : std::uint8_t {
    none,  ///< Configuration is usable.
    zero_rate,  ///< Aggregate pacing rate is zero.
    excessive_rate,  ///< Rate exceeds the portable arithmetic bound of one terabit per second.
    invalid_input_reserve,  ///< Input reserve exceeds aggregate rate or 32 Mbps.
    invalid_datagram_size,  ///< Path datagram charge is outside UDP's portable bounds.
    invalid_quantum,  ///< Quantum is zero or exceeds 100 microseconds.
    invalid_horizon,  ///< Horizon is shorter than one quantum or exceeds 200 microseconds.
    invalid_batch_limit,  ///< Batch count is outside one through eight.
  };

  /** @brief Byte and datagram grant returned by the aggregate pacer. */
  struct pacer_grant {
    std::size_t datagrams = 0;  ///< Number of leading requested datagrams granted.
    std::uint64_t bytes = 0;  ///< Complete charged bytes granted.
  };

  /** @brief Allocation-free aggregate byte pacer with a protected input sub-pacer. */
  class aggregate_pacer {
  public:
    /**
     * @brief Construct an uninitialized pacer from static configuration.
     *
     * @param config Aggregate and input pacing bounds.
     */
    constexpr explicit aggregate_pacer(const pacer_config config) noexcept:
        config_(config),
        error_(validate(config)) {
    }

    /**
     * @brief Return configuration validation status.
     *
     * @return Typed pacer error.
     */
    [[nodiscard]] constexpr pacer_error error() const noexcept {
      return error_;
    }

    /**
     * @brief Initialize monotonic timing and one-datagram startup credit per active partition.
     *
     * @param now_microseconds Current monotonic time.
     */
    constexpr void reset(const std::uint64_t now_microseconds) noexcept {
      last_update_microseconds_ = now_microseconds;
      const auto common_rate = config_.pacing_bits_per_second - config_.input_reserve_bits_per_second;
      aggregate_credit_ = config_.path_datagram_bytes;
      common_credit_ = common_rate == 0 ? 0 : config_.path_datagram_bytes;
      input_credit_ = config_.input_reserve_bits_per_second == 0 ? 0 : config_.path_datagram_bytes;
      initialized_ = error_ == pacer_error::none;
    }

    /**
     * @brief Change rate or path bounds without granting fresh startup credit or erasing debt.
     *
     * Credit is first accrued under the prior configuration through `now_microseconds`, then
     * clamped to the new submission horizon. No partition receives additional credit merely
     * because feedback changed a rate or DPLPMTUD confirmed a packet size.
     *
     * @param config Replacement pacing configuration.
     * @param now_microseconds Monotonic reconfiguration time.
     * @return True only when the replacement configuration is valid.
     */
    constexpr bool reconfigure(
      const pacer_config config,
      const std::uint64_t now_microseconds
    ) noexcept {
      const auto replacement_error = validate(config);
      if (replacement_error != pacer_error::none) {
        return false;
      }
      if (initialized_) {
        update(now_microseconds);
      }
      config_ = config;
      error_ = replacement_error;
      if (!initialized_) {
        last_update_microseconds_ = now_microseconds;
        return true;
      }
      const auto common_rate = config_.pacing_bits_per_second - config_.input_reserve_bits_per_second;
      const auto aggregate_cap = std::max<std::uint64_t>(
        config_.path_datagram_bytes,
        earned_bytes(config_.pacing_bits_per_second, config_.submission_horizon_microseconds)
      );
      const auto common_cap = common_rate == 0 ? 0 : std::max<std::uint64_t>(
        config_.path_datagram_bytes,
        earned_bytes(common_rate, config_.submission_horizon_microseconds)
      );
      const auto input_cap = config_.input_reserve_bits_per_second == 0 ? 0 : std::max<std::uint64_t>(
        config_.path_datagram_bytes,
        earned_bytes(config_.input_reserve_bits_per_second, config_.submission_horizon_microseconds)
      );
      aggregate_credit_ = std::min(aggregate_credit_, aggregate_cap);
      common_credit_ = std::min(common_credit_, common_cap);
      input_credit_ = std::min(input_credit_, input_cap);
      last_update_microseconds_ = now_microseconds;
      return true;
    }

    /**
     * @brief Grant a leading microbatch and consume its earned byte credit.
     *
     * Requested sizes must include complete IP/UDP/SRTP/RTP or DTLS accounting. Input may consume
     * protected input credit first and then unused common credit; all other traffic uses common
     * credit only.
     *
     * @param datagram_bytes Ordered complete datagram charges.
     * @param input Whether every requested datagram belongs to the protected input lane.
     * @param now_microseconds Current monotonic time.
     * @return Leading datagram and byte grant.
     */
    constexpr pacer_grant grant(
      const std::span<const std::uint16_t> datagram_bytes,
      const bool input,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (!initialized_ || datagram_bytes.empty()) {
        return {};
      }
      update(now_microseconds);
      const auto quantum_credit = std::max<std::uint64_t>(
        config_.path_datagram_bytes,
        earned_bytes(config_.pacing_bits_per_second, config_.quantum_microseconds)
      );
      const auto partition_available = input ? input_credit_ + common_credit_ : common_credit_;
      const auto available = std::min(aggregate_credit_, partition_available);
      const auto byte_limit = std::min(available, quantum_credit);
      pacer_grant result {};
      const auto count_limit = std::min<std::size_t>(config_.max_datagrams_per_batch, datagram_bytes.size());
      for (std::size_t index = 0; index < count_limit; ++index) {
        const auto size = datagram_bytes[index];
        if (size == 0 || size > config_.path_datagram_bytes || result.bytes + size > byte_limit) {
          break;
        }
        result.bytes += size;
        ++result.datagrams;
      }
      if (input) {
        const auto from_input = std::min(input_credit_, result.bytes);
        input_credit_ -= from_input;
        common_credit_ -= result.bytes - from_input;
      } else {
        common_credit_ -= result.bytes;
      }
      aggregate_credit_ -= result.bytes;
      return result;
    }

    /**
     * @brief Return the wait until a complete datagram can earn sufficient credit.
     *
     * @param datagram_bytes Complete datagram charge.
     * @param input Whether the datagram belongs to protected input.
     * @param now_microseconds Current monotonic time.
     * @return Required wait in microseconds, or maximum uint64 when no eligible rate exists.
     */
    [[nodiscard]] constexpr std::uint64_t wait_microseconds(
      const std::uint16_t datagram_bytes,
      const bool input,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (!initialized_ || datagram_bytes == 0 || datagram_bytes > config_.path_datagram_bytes) {
        return std::numeric_limits<std::uint64_t>::max();
      }
      update(now_microseconds);
      const auto partition_available = input ? input_credit_ + common_credit_ : common_credit_;
      const auto available = std::min(aggregate_credit_, partition_available);
      if (available >= datagram_bytes) {
        return 0;
      }
      const auto partition_rate = input ? config_.pacing_bits_per_second :
                                          config_.pacing_bits_per_second - config_.input_reserve_bits_per_second;
      if (partition_rate == 0) {
        return std::numeric_limits<std::uint64_t>::max();
      }
      const auto aggregate_deficit = aggregate_credit_ >= datagram_bytes ? 0 : datagram_bytes - aggregate_credit_;
      const auto partition_deficit = partition_available >= datagram_bytes ? 0 : datagram_bytes - partition_available;
      const auto aggregate_wait = divide_round_up(aggregate_deficit * 8'000'000U, config_.pacing_bits_per_second);
      const auto partition_wait = divide_round_up(partition_deficit * 8'000'000U, partition_rate);
      return std::max(aggregate_wait, partition_wait);
    }

  private:
    /**
     * @brief Validate portable byte-pacer configuration.
     *
     * @param config Candidate configuration.
     * @return Typed validation error.
     */
    [[nodiscard]] static constexpr pacer_error validate(const pacer_config &config) noexcept {
      if (config.pacing_bits_per_second == 0) {
        return pacer_error::zero_rate;
      }
      if (config.pacing_bits_per_second > 1'000'000'000'000ULL) {
        return pacer_error::excessive_rate;
      }
      if (config.input_reserve_bits_per_second > config.pacing_bits_per_second || config.input_reserve_bits_per_second > 32'000'000U) {
        return pacer_error::invalid_input_reserve;
      }
      if (config.path_datagram_bytes < 576U || config.path_datagram_bytes > 65'507U) {
        return pacer_error::invalid_datagram_size;
      }
      if (config.quantum_microseconds == 0 || config.quantum_microseconds > 100U) {
        return pacer_error::invalid_quantum;
      }
      if (config.submission_horizon_microseconds < config.quantum_microseconds || config.submission_horizon_microseconds > 200U) {
        return pacer_error::invalid_horizon;
      }
      if (config.max_datagrams_per_batch == 0 || config.max_datagrams_per_batch > 8U) {
        return pacer_error::invalid_batch_limit;
      }
      return pacer_error::none;
    }

    /**
     * @brief Calculate whole bytes earned over a bounded interval without multiplication overflow.
     *
     * @param bits_per_second Partition rate.
     * @param microseconds Bounded duration.
     * @return Whole earned bytes.
     */
    [[nodiscard]] static constexpr std::uint64_t earned_bytes(
      const std::uint64_t bits_per_second,
      const std::uint64_t microseconds
    ) noexcept {
      constexpr auto denominator = std::uint64_t {8'000'000};
      return (bits_per_second / denominator) * microseconds +
             ((bits_per_second % denominator) * microseconds) / denominator;
    }

    /**
     * @brief Divide positive integers with upward rounding.
     *
     * @param numerator Dividend.
     * @param denominator Nonzero divisor.
     * @return Mathematical ceiling of the quotient.
     */
    [[nodiscard]] static constexpr std::uint64_t divide_round_up(
      const std::uint64_t numerator,
      const std::uint64_t denominator
    ) noexcept {
      return numerator / denominator + (numerator % denominator != 0 ? 1U : 0U);
    }

    /**
     * @brief Earn bounded partition credit through the supplied time.
     *
     * @param now_microseconds Current monotonic time.
     */
    constexpr void update(const std::uint64_t now_microseconds) noexcept {
      if (now_microseconds <= last_update_microseconds_) {
        return;
      }
      const auto elapsed = std::min<std::uint64_t>(
        now_microseconds - last_update_microseconds_,
        config_.submission_horizon_microseconds
      );
      last_update_microseconds_ = now_microseconds;
      const auto common_rate = config_.pacing_bits_per_second - config_.input_reserve_bits_per_second;
      const auto aggregate_cap = std::max<std::uint64_t>(
        config_.path_datagram_bytes,
        earned_bytes(config_.pacing_bits_per_second, config_.submission_horizon_microseconds)
      );
      const auto common_cap = common_rate == 0 ? 0 : std::max<std::uint64_t>(config_.path_datagram_bytes, earned_bytes(common_rate, config_.submission_horizon_microseconds));
      const auto input_cap = config_.input_reserve_bits_per_second == 0 ? 0 : std::max<std::uint64_t>(config_.path_datagram_bytes, earned_bytes(config_.input_reserve_bits_per_second, config_.submission_horizon_microseconds));
      aggregate_credit_ = std::min(
        aggregate_cap,
        aggregate_credit_ + earned_bytes(config_.pacing_bits_per_second, elapsed)
      );
      common_credit_ = std::min(common_cap, common_credit_ + earned_bytes(common_rate, elapsed));
      input_credit_ = std::min(input_cap, input_credit_ + earned_bytes(config_.input_reserve_bits_per_second, elapsed));
    }

    pacer_config config_ {};  ///< Static pacing configuration.
    pacer_error error_ = pacer_error::none;  ///< Configuration status.
    std::uint64_t last_update_microseconds_ = 0;  ///< Latest credit-accounting time.
    std::uint64_t aggregate_credit_ = 0;  ///< Total earned byte credit shared by every lane.
    std::uint64_t common_credit_ = 0;  ///< Non-reserved aggregate byte credit.
    std::uint64_t input_credit_ = 0;  ///< Protected input byte credit.
    bool initialized_ = false;  ///< Whether `reset()` established a time origin.
  };

  /** @brief Static congestion-controller profile and capacity bounds. */
  struct congestion_config {
    congestion_profile profile = congestion_profile::adaptive_low_latency;  ///< Selected controller behavior.
    std::uint64_t initial_pacing_bits_per_second = 20'000'000;  ///< Initial aggregate IP-layer pacing rate.
    std::uint64_t minimum_pacing_bits_per_second = 1'000'000;  ///< Minimum viable aggregate pacing rate.
    std::uint64_t maximum_pacing_bits_per_second = 1'000'000'000;  ///< General safety ceiling.
    std::uint64_t competition_capacity_bits_per_second = 0;  ///< Explicit competition ceiling; zero disables competition.
    std::uint64_t reserved_overhead_bits_per_second = 0;  ///< Audio, input, protocol, and repair budget excluded from video.
    std::uint32_t maximum_rtt_microseconds = 100'000;  ///< Profile RTT failure/reduction threshold.
    std::uint32_t queue_delay_budget_microseconds = 10'000;  ///< Negotiated network queue-delay target.
  };

  /** @brief Congestion-profile configuration failure. */
  enum class congestion_error : std::uint8_t {
    none,  ///< Configuration is usable.
    invalid_rate_bounds,  ///< Minimum, initial, or maximum rates are zero or unordered.
    competition_capacity_required,  ///< Competition profile lacks an explicit nonzero ceiling.
    competition_capacity_out_of_range,  ///< Competition ceiling is outside minimum through maximum.
    invalid_latency_budget,  ///< RTT or queue-delay budget is zero.
  };

  /** @brief One aggregate RFC-8888-derived feedback summary. */
  struct congestion_feedback {
    std::uint64_t delivered_bytes = 0;  ///< Newly delivered complete IP-layer bytes.
    std::uint64_t lost_bytes = 0;  ///< Newly inferred lost complete IP-layer bytes.
    std::uint64_t ecn_ce_bytes = 0;  ///< Newly delivered bytes carrying ECN-CE.
    std::uint32_t smoothed_rtt_microseconds = 0;  ///< Current smoothed RTT.
    std::int32_t queue_delay_trend_microseconds = 0;  ///< Signed one-way queue-delay trend.
  };

  /** @brief Snapshot of aggregate congestion and encoder capacity state. */
  struct congestion_snapshot {
    std::uint64_t pacing_bits_per_second = 0;  ///< Current aggregate pacing target.
    std::uint64_t encoder_bits_per_second = 0;  ///< Pacing target minus measured reserved overhead.
    std::uint64_t delivered_bytes = 0;  ///< Cumulative delivered bytes.
    std::uint64_t lost_bytes = 0;  ///< Cumulative lost bytes.
    std::uint64_t ecn_ce_bytes = 0;  ///< Cumulative ECN-CE bytes.
    std::uint32_t smoothed_rtt_microseconds = 0;  ///< Latest smoothed RTT.
    std::int32_t queue_delay_trend_microseconds = 0;  ///< Latest signed delay trend.
  };

  /** @brief Bounded aggregate congestion-profile state and deterministic adaptation primitive. */
  class congestion_controller {
  public:
    /**
     * @brief Construct controller state from a validated profile.
     *
     * @param config Profile and rate bounds.
     */
    constexpr explicit congestion_controller(const congestion_config config) noexcept:
        config_(config),
        error_(validate(config)),
        pacing_bits_per_second_(error_ == congestion_error::none ? config.initial_pacing_bits_per_second : 0) {
    }

    /**
     * @brief Return profile validation status.
     *
     * @return Typed configuration error.
     */
    [[nodiscard]] constexpr congestion_error error() const noexcept {
      return error_;
    }

    /**
     * @brief Apply one disjoint aggregate feedback interval.
     *
     * Loss, ECN-CE, positive queue trend, or RTT violation reduces within this interval. A clean
     * interval uses a bounded additive increase and can never exceed the configured profile ceiling.
     *
     * @param feedback Feedback interval summary.
     */
    constexpr void on_feedback(const congestion_feedback &feedback) noexcept {
      if (error_ != congestion_error::none) {
        return;
      }
      delivered_bytes_ = saturating_add(delivered_bytes_, feedback.delivered_bytes);
      lost_bytes_ = saturating_add(lost_bytes_, feedback.lost_bytes);
      ecn_ce_bytes_ = saturating_add(ecn_ce_bytes_, feedback.ecn_ce_bytes);
      smoothed_rtt_microseconds_ = feedback.smoothed_rtt_microseconds;
      queue_delay_trend_microseconds_ = feedback.queue_delay_trend_microseconds;

      const auto impaired = feedback.lost_bytes != 0 || feedback.ecn_ce_bytes != 0 ||
                            feedback.queue_delay_trend_microseconds > static_cast<std::int32_t>(config_.queue_delay_budget_microseconds) ||
                            feedback.smoothed_rtt_microseconds > config_.maximum_rtt_microseconds;
      if (impaired) {
        const auto numerator = config_.profile == congestion_profile::competition_lan ? 80U : 85U;
        pacing_bits_per_second_ = std::max(
          config_.minimum_pacing_bits_per_second,
          pacing_bits_per_second_ / 100U * numerator
        );
        return;
      }
      const auto ceiling = profile_ceiling();
      const auto increase = std::max<std::uint64_t>(64'000U, pacing_bits_per_second_ / 100U);
      pacing_bits_per_second_ = pacing_bits_per_second_ > ceiling - std::min(ceiling, increase) ?
                                  ceiling :
                                  pacing_bits_per_second_ + increase;
    }

    /**
     * @brief Return immutable controller counters and current rate targets.
     *
     * @return Congestion snapshot.
     */
    [[nodiscard]] constexpr congestion_snapshot snapshot() const noexcept {
      return {
        .pacing_bits_per_second = pacing_bits_per_second_,
        .encoder_bits_per_second = pacing_bits_per_second_ > config_.reserved_overhead_bits_per_second ?
                                     pacing_bits_per_second_ - config_.reserved_overhead_bits_per_second :
                                     0,
        .delivered_bytes = delivered_bytes_,
        .lost_bytes = lost_bytes_,
        .ecn_ce_bytes = ecn_ce_bytes_,
        .smoothed_rtt_microseconds = smoothed_rtt_microseconds_,
        .queue_delay_trend_microseconds = queue_delay_trend_microseconds_,
      };
    }

  private:
    /**
     * @brief Validate a congestion profile and its explicit capacity bounds.
     *
     * @param config Candidate profile configuration.
     * @return Typed validation error.
     */
    [[nodiscard]] static constexpr congestion_error validate(const congestion_config &config) noexcept {
      if (config.minimum_pacing_bits_per_second == 0 ||
          config.minimum_pacing_bits_per_second > config.initial_pacing_bits_per_second ||
          config.initial_pacing_bits_per_second > config.maximum_pacing_bits_per_second) {
        return congestion_error::invalid_rate_bounds;
      }
      if (config.profile == congestion_profile::competition_lan) {
        if (config.competition_capacity_bits_per_second == 0) {
          return congestion_error::competition_capacity_required;
        }
        if (config.competition_capacity_bits_per_second < config.minimum_pacing_bits_per_second ||
            config.competition_capacity_bits_per_second > config.maximum_pacing_bits_per_second ||
            config.initial_pacing_bits_per_second > config.competition_capacity_bits_per_second) {
          return congestion_error::competition_capacity_out_of_range;
        }
      }
      if (config.maximum_rtt_microseconds == 0 || config.queue_delay_budget_microseconds == 0) {
        return congestion_error::invalid_latency_budget;
      }
      return congestion_error::none;
    }

    /**
     * @brief Add monotonically increasing counters without wrap.
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
     * @brief Return the active profile's absolute pacing ceiling.
     *
     * @return Explicit competition or general adaptive ceiling.
     */
    [[nodiscard]] constexpr std::uint64_t profile_ceiling() const noexcept {
      return config_.profile == congestion_profile::competition_lan ?
               config_.competition_capacity_bits_per_second :
               config_.maximum_pacing_bits_per_second;
    }

    congestion_config config_ {};  ///< Validated static profile configuration.
    congestion_error error_ = congestion_error::none;  ///< Configuration status.
    std::uint64_t pacing_bits_per_second_ = 0;  ///< Current aggregate pacing target.
    std::uint64_t delivered_bytes_ = 0;  ///< Cumulative delivered bytes.
    std::uint64_t lost_bytes_ = 0;  ///< Cumulative lost bytes.
    std::uint64_t ecn_ce_bytes_ = 0;  ///< Cumulative ECN-CE bytes.
    std::uint32_t smoothed_rtt_microseconds_ = 0;  ///< Latest smoothed RTT.
    std::int32_t queue_delay_trend_microseconds_ = 0;  ///< Latest signed queue trend.
  };
}  // namespace lumen::lsp
