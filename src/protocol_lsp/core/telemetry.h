/**
 * @file src/protocol_lsp/core/telemetry.h
 * @brief Thread-owned bounded telemetry counters and percentile snapshots.
 */

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace lumen::lsp {
  /** @brief Bounded latency-distribution snapshot in one monotonic clock domain. */
  struct latency_snapshot {
    std::uint64_t total_samples = 0;  ///< All samples observed, including overwritten history.
    std::uint32_t retained_samples = 0;  ///< Samples represented by the reported percentiles.
    std::uint64_t p50_microseconds = 0;  ///< Retained-sample median.
    std::uint64_t p95_microseconds = 0;  ///< Retained-sample 95th percentile.
    std::uint64_t p99_microseconds = 0;  ///< Retained-sample 99th percentile.
    std::uint64_t maximum_microseconds = 0;  ///< Maximum across all samples since reset.
  };

  /**
   * @brief Fixed recent-sample latency window with allocation-free updates and snapshots.
   *
   * @tparam Capacity Number of recent samples retained for percentile calculation.
   */
  template<std::size_t Capacity = 256>
  class latency_window {
  public:
    static_assert(Capacity > 0, "latency windows require nonzero capacity");

    /**
     * @brief Record one nonnegative monotonic duration.
     *
     * @param microseconds Duration in microseconds.
     */
    constexpr void record(const std::uint64_t microseconds) noexcept {
      samples_[next_] = microseconds;
      next_ = (next_ + 1U) % Capacity;
      if (retained_ < Capacity) {
        ++retained_;
      }
      if (total_ != std::numeric_limits<std::uint64_t>::max()) {
        ++total_;
      }
      maximum_ = std::max(maximum_, microseconds);
    }

    /**
     * @brief Build a bounded immutable percentile snapshot.
     *
     * Sorting occurs only at snapshot time, never on the per-packet record path.
     *
     * @return Latency distribution summary.
     */
    [[nodiscard]] constexpr latency_snapshot snapshot() const noexcept {
      if (retained_ == 0) {
        return {.total_samples = total_};
      }
      auto sorted = samples_;
      std::sort(sorted.begin(), sorted.begin() + retained_);
      return {
        .total_samples = total_,
        .retained_samples = static_cast<std::uint32_t>(retained_),
        .p50_microseconds = percentile(sorted, retained_, 50),
        .p95_microseconds = percentile(sorted, retained_, 95),
        .p99_microseconds = percentile(sorted, retained_, 99),
        .maximum_microseconds = maximum_,
      };
    }

    /** @brief Reset all retained and lifetime distribution state. */
    constexpr void reset() noexcept {
      next_ = 0;
      retained_ = 0;
      total_ = 0;
      maximum_ = 0;
    }

  private:
    /**
     * @brief Return a nearest-rank percentile from sorted retained samples.
     *
     * @param sorted Sorted sample array.
     * @param count Number of valid leading elements.
     * @param percentile_value Percentile in one through 100.
     * @return Nearest-rank sample value.
     */
    [[nodiscard]] static constexpr std::uint64_t percentile(
      const std::array<std::uint64_t, Capacity> &sorted,
      const std::size_t count,
      const std::size_t percentile_value
    ) noexcept {
      const auto rank = (count * percentile_value + 99U) / 100U;
      return sorted[rank == 0 ? 0 : rank - 1U];
    }

    std::array<std::uint64_t, Capacity> samples_ {};  ///< Recent monotonic duration samples.
    std::size_t next_ = 0;  ///< Next overwrite position.
    std::size_t retained_ = 0;  ///< Number of valid samples retained.
    std::uint64_t total_ = 0;  ///< Saturating lifetime sample count.
    std::uint64_t maximum_ = 0;  ///< Lifetime maximum duration.
  };

  /** @brief Immutable snapshot of one packet worker's hot-path telemetry. */
  struct telemetry_snapshot {
    std::uint64_t packets_received = 0;  ///< Authenticated and unauthenticated datagrams observed.
    std::uint64_t packets_transmitted = 0;  ///< Datagrams submitted to the platform socket boundary.
    std::uint64_t bytes_received = 0;  ///< Complete received IP-layer byte charge when available.
    std::uint64_t bytes_transmitted = 0;  ///< Complete transmitted IP-layer byte charge.
    std::uint64_t malformed_packets = 0;  ///< Packets rejected by bounded parsers.
    std::uint64_t authentication_failures = 0;  ///< DTLS, SRTP, or SRTCP authentication failures.
    std::uint64_t replay_rejections = 0;  ///< Authenticated replay-window rejections.
    std::uint64_t queue_drops = 0;  ///< Packets dropped because a bounded queue was full.
    std::uint64_t expired_media = 0;  ///< Authenticated media discarded after its deadline.
    std::uint64_t input_edges_retried = 0;  ///< Physical edges repeated before acknowledgement.
    std::uint64_t input_states_superseded = 0;  ///< Replaceable input states overwritten before send/apply.
    std::uint32_t peak_queue_depth = 0;  ///< Maximum owned queue depth.
    latency_snapshot pacing_error {};  ///< Scheduled-to-submitted pacing error distribution.
    latency_snapshot receive_processing {};  ///< Kernel-receive through authentication/parse distribution.
    latency_snapshot input_apply {};  ///< Host-receive through platform-input-apply distribution.
  };

  /**
   * @brief Cache-line-aligned, thread-owned hot telemetry accumulator.
   *
   * One packet worker owns and updates one instance without atomics or locks. A coarse application
   * boundary may copy `snapshot()` at no more than the product's configured publication rate.
   */
  class alignas(64) telemetry_accumulator {
  public:
    /**
     * @brief Record one received datagram.
     *
     * @param complete_bytes Complete IP-layer byte charge when known.
     */
    constexpr void record_received(const std::uint64_t complete_bytes) noexcept {
      increment(packets_received_);
      add(bytes_received_, complete_bytes);
    }

    /**
     * @brief Record one transmitted datagram.
     *
     * @param complete_bytes Complete IP-layer byte charge.
     */
    constexpr void record_transmitted(const std::uint64_t complete_bytes) noexcept {
      increment(packets_transmitted_);
      add(bytes_transmitted_, complete_bytes);
    }

    /** @brief Record one parser rejection. */
    constexpr void record_malformed() noexcept {
      increment(malformed_packets_);
    }

    /** @brief Record one cryptographic authentication failure. */
    constexpr void record_authentication_failure() noexcept {
      increment(authentication_failures_);
    }

    /** @brief Record one replay-window rejection. */
    constexpr void record_replay_rejection() noexcept {
      increment(replay_rejections_);
    }

    /** @brief Record one bounded-queue overflow drop. */
    constexpr void record_queue_drop() noexcept {
      increment(queue_drops_);
    }

    /** @brief Record one authenticated media packet discarded after its deadline. */
    constexpr void record_expired_media() noexcept {
      increment(expired_media_);
    }

    /** @brief Record one repeated input edge transmission. */
    constexpr void record_input_edge_retry() noexcept {
      increment(input_edges_retried_);
    }

    /** @brief Record one replaceable input state superseded before consumption. */
    constexpr void record_input_state_superseded() noexcept {
      increment(input_states_superseded_);
    }

    /**
     * @brief Update the maximum bounded queue depth.
     *
     * @param depth Current queue depth.
     */
    constexpr void observe_queue_depth(const std::uint32_t depth) noexcept {
      peak_queue_depth_ = std::max(peak_queue_depth_, depth);
    }

    /**
     * @brief Record absolute scheduled-to-submitted pacing error.
     *
     * @param microseconds Absolute error in microseconds.
     */
    constexpr void record_pacing_error(const std::uint64_t microseconds) noexcept {
      pacing_error_.record(microseconds);
    }

    /**
     * @brief Record kernel-receive through authentication/parse time.
     *
     * @param microseconds Processing duration.
     */
    constexpr void record_receive_processing(const std::uint64_t microseconds) noexcept {
      receive_processing_.record(microseconds);
    }

    /**
     * @brief Record host-receive through platform-input-apply time.
     *
     * @param microseconds Processing duration.
     */
    constexpr void record_input_apply(const std::uint64_t microseconds) noexcept {
      input_apply_.record(microseconds);
    }

    /**
     * @brief Copy an immutable telemetry summary without resetting hot counters.
     *
     * @return Thread-owned telemetry snapshot.
     */
    [[nodiscard]] constexpr telemetry_snapshot snapshot() const noexcept {
      return {
        .packets_received = packets_received_,
        .packets_transmitted = packets_transmitted_,
        .bytes_received = bytes_received_,
        .bytes_transmitted = bytes_transmitted_,
        .malformed_packets = malformed_packets_,
        .authentication_failures = authentication_failures_,
        .replay_rejections = replay_rejections_,
        .queue_drops = queue_drops_,
        .expired_media = expired_media_,
        .input_edges_retried = input_edges_retried_,
        .input_states_superseded = input_states_superseded_,
        .peak_queue_depth = peak_queue_depth_,
        .pacing_error = pacing_error_.snapshot(),
        .receive_processing = receive_processing_.snapshot(),
        .input_apply = input_apply_.snapshot(),
      };
    }

    /** @brief Reset all counters and recent-sample windows for a new telemetry generation. */
    constexpr void reset() noexcept {
      packets_received_ = 0;
      packets_transmitted_ = 0;
      bytes_received_ = 0;
      bytes_transmitted_ = 0;
      malformed_packets_ = 0;
      authentication_failures_ = 0;
      replay_rejections_ = 0;
      queue_drops_ = 0;
      expired_media_ = 0;
      input_edges_retried_ = 0;
      input_states_superseded_ = 0;
      peak_queue_depth_ = 0;
      pacing_error_.reset();
      receive_processing_.reset();
      input_apply_.reset();
    }

  private:
    /**
     * @brief Increment a monotonic counter without wrap.
     *
     * @param counter Counter to update.
     */
    static constexpr void increment(std::uint64_t &counter) noexcept {
      if (counter != std::numeric_limits<std::uint64_t>::max()) {
        ++counter;
      }
    }

    /**
     * @brief Add to a monotonic counter without wrap.
     *
     * @param counter Counter to update.
     * @param value Interval value to add.
     */
    static constexpr void add(std::uint64_t &counter, const std::uint64_t value) noexcept {
      counter = counter > std::numeric_limits<std::uint64_t>::max() - value ?
                  std::numeric_limits<std::uint64_t>::max() :
                  counter + value;
    }

    std::uint64_t packets_received_ = 0;  ///< Received packet count.
    std::uint64_t packets_transmitted_ = 0;  ///< Transmitted packet count.
    std::uint64_t bytes_received_ = 0;  ///< Received complete-byte charge.
    std::uint64_t bytes_transmitted_ = 0;  ///< Transmitted complete-byte charge.
    std::uint64_t malformed_packets_ = 0;  ///< Parser rejection count.
    std::uint64_t authentication_failures_ = 0;  ///< Authentication failure count.
    std::uint64_t replay_rejections_ = 0;  ///< Replay rejection count.
    std::uint64_t queue_drops_ = 0;  ///< Bounded-queue drop count.
    std::uint64_t expired_media_ = 0;  ///< Expired authenticated media count.
    std::uint64_t input_edges_retried_ = 0;  ///< Retried edge count.
    std::uint64_t input_states_superseded_ = 0;  ///< Superseded state count.
    std::uint32_t peak_queue_depth_ = 0;  ///< Maximum queue depth.
    latency_window<> pacing_error_ {};  ///< Recent pacing-error samples.
    latency_window<> receive_processing_ {};  ///< Recent receive-processing samples.
    latency_window<> input_apply_ {};  ///< Recent input-apply samples.
  };
}  // namespace lumen::lsp
