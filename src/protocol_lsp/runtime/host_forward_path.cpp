/**
 * @file src/protocol_lsp/runtime/host_forward_path.cpp
 * @brief Bounded aggregate host-to-client LSP datagram scheduler implementation.
 */

#include "host_forward_path.h"

#include "../../platform/common.h"
#include "../transport/rtcp.h"
#include "udp_socket.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <limits>
#include <mutex>
#include <thread>
#include <utility>

#if defined(_WIN32) && (defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86))
  #include <immintrin.h>
#endif

namespace lumen::lsp::runtime {
  namespace {
    constexpr std::size_t control_slot_count = 64;
    constexpr std::size_t audio_slot_count = 8;
    constexpr std::size_t congestion_feedback_slot_count = 2;
    constexpr std::size_t common_slot_count = 24;
    constexpr std::size_t recovery_slot_count = 8;
    constexpr std::size_t video_slot_count = 12;
    constexpr std::size_t total_slot_count =
      control_slot_count + audio_slot_count + congestion_feedback_slot_count + common_slot_count;
    constexpr std::size_t congestion_feedback_slot_begin = control_slot_count + audio_slot_count;
    constexpr std::size_t common_slot_begin = congestion_feedback_slot_begin + congestion_feedback_slot_count;
    constexpr std::size_t recovery_slot_begin = common_slot_begin;
    constexpr std::size_t video_slot_begin = recovery_slot_begin + recovery_slot_count;
    constexpr std::size_t shared_slot_begin = video_slot_begin + video_slot_count;
    constexpr std::uint64_t retry_delay_microseconds = 50;
    constexpr std::uint64_t microbatch_microseconds = 100;
    constexpr std::uint64_t starvation_promotion_microseconds = 2'000;
    constexpr std::uint64_t congestion_feedback_floor_microseconds =
      transport::congestion_feedback_floor_microseconds;
    constexpr std::uint8_t maximum_microbatch_datagrams = 8;

    enum class SlotState : std::uint8_t {
      free,
      reserved,
      queued,
      sending,
      retry,
    };

    struct Slot {
      std::array<std::uint8_t, host_forward_maximum_payload_bytes> bytes {};
      std::uint64_t ticket {};
      std::uint64_t token {};
      std::uint64_t deadline_microseconds {};
      std::uint64_t retry_at_microseconds {};
      std::uint64_t enqueue_ordinal {};
      std::uint64_t enqueued_microseconds {};
      std::size_t protected_bytes {};
      std::uint16_t charged_bytes {};
      HostForwardCompletionTarget target {};
      HostForwardLane lane {HostForwardLane::bulk};
      SlotState state {SlotState::free};
    };

    struct CompletionRecord {
      std::uint64_t token {};
      HostForwardLane lane {HostForwardLane::bulk};
      HostForwardCompletion completion {HostForwardCompletion::cancelled};
      std::uint64_t completed_at_microseconds {};
      std::size_t protected_bytes {};
      std::uint16_t charged_bytes {};
      HostForwardCompletionTarget target {};
      bool notify {};
    };

    [[nodiscard]] constexpr std::uint16_t ip_udp_overhead(const PeerEndpoint &peer) noexcept {
      return peer.family == IpAddressFamily::ipv6 ? 48U : 28U;
    }

    [[nodiscard]] constexpr std::uint16_t maximum_payload_for(const PeerEndpoint &peer) noexcept {
      return peer.family == IpAddressFamily::ipv6 ? 1'452U : 1'472U;
    }

    [[nodiscard]] constexpr std::uint16_t effective_probe_ceiling(const HostForwardPathConfig &config) noexcept {
      return config.probe_payload_ceiling == 0 ? maximum_payload_for(config.peer) : config.probe_payload_ceiling;
    }

    [[nodiscard]] constexpr std::uint8_t lane_priority(const HostForwardLane lane) noexcept {
      return static_cast<std::uint8_t>(lane);
    }

    [[nodiscard]] constexpr std::uint8_t effective_lane_priority(
      const Slot &slot,
      const std::uint64_t now_microseconds
    ) noexcept {
      const auto priority = lane_priority(slot.lane);
      if (priority == 0 || slot.enqueued_microseconds == 0 || now_microseconds < slot.enqueued_microseconds) {
        return priority;
      }
      const auto minimum_priority = slot.lane == HostForwardLane::congestion_feedback ?
                                      lane_priority(HostForwardLane::audio) :
                                      std::uint8_t {0};
      const auto promotions = std::min<std::uint64_t>(
        priority - minimum_priority,
        (now_microseconds - slot.enqueued_microseconds) / starvation_promotion_microseconds
      );
      return static_cast<std::uint8_t>(priority - promotions);
    }

    [[nodiscard]] constexpr bool uses_control_reserve(const HostForwardLane lane) noexcept {
      return lane == HostForwardLane::urgent_control || lane == HostForwardLane::input_feedback;
    }

    [[nodiscard]] constexpr bool uses_audio_reserve(const HostForwardLane lane) noexcept {
      return lane == HostForwardLane::audio;
    }

    /**
     * @brief Wire rate for one frame's burst, above the controller's average rate.
     *
     * Pacing at the average media rate spreads every frame across its whole frame interval, so
     * the last packet (and decode) lands most of a frame late. The controller still sets the
     * encoder bitrate; only the per-frame burst drains faster, bounded to gigabit wire speed.
     */
    [[nodiscard]] constexpr std::uint64_t frame_burst_rate(const std::uint64_t pacing_bits_per_second) noexcept {
      constexpr std::uint64_t burst_multiplier = 4;
      constexpr std::uint64_t wire_ceiling_bits_per_second = 1'000'000'000;
      if (pacing_bits_per_second >= wire_ceiling_bits_per_second / burst_multiplier) {
        return std::max(pacing_bits_per_second, wire_ceiling_bits_per_second);
      }
      return pacing_bits_per_second * burst_multiplier;
    }

  }  // namespace

  bool HostForwardPathConfig::valid() const noexcept {
    const auto probe_ceiling = effective_probe_ceiling(*this);
    if (!peer.valid() || generation == 0 || pacing_bits_per_second == 0 || callbacks.send_datagram == nullptr ||
        path_payload_bytes < 1'200U || path_payload_bytes > maximum_payload_for(peer) ||
        probe_ceiling < path_payload_bytes || probe_ceiling > maximum_payload_for(peer)) {
      return false;
    }
    const aggregate_pacer candidate {{
      .pacing_bits_per_second = pacing_bits_per_second,
      .input_reserve_bits_per_second = 0,
      .path_datagram_bytes = static_cast<std::uint16_t>(probe_ceiling + ip_udp_overhead(peer)),
      .quantum_microseconds = 100,
      .submission_horizon_microseconds = 200,
      .max_datagrams_per_batch = 8,
    }};
    return candidate.error() == pacer_error::none;
  }

  bool HostForwardLease::valid() const noexcept {
    return slot != UINT16_MAX && ticket != 0 && !storage.empty() && release_context != nullptr && release != nullptr;
  }

  HostForwardLease::HostForwardLease(HostForwardLease &&other) noexcept:
      storage {std::exchange(other.storage, {})},
      ticket {std::exchange(other.ticket, 0)},
      slot {std::exchange(other.slot, UINT16_MAX)},
      release_context {std::exchange(other.release_context, nullptr)},
      release {std::exchange(other.release, nullptr)} {
  }

  HostForwardLease &HostForwardLease::operator=(HostForwardLease &&other) noexcept {
    if (this != &other) {
      if (valid()) {
        release(release_context, slot, ticket);
      }
      storage = std::exchange(other.storage, {});
      ticket = std::exchange(other.ticket, 0);
      slot = std::exchange(other.slot, UINT16_MAX);
      release_context = std::exchange(other.release_context, nullptr);
      release = std::exchange(other.release, nullptr);
    }
    return *this;
  }

  HostForwardLease::~HostForwardLease() {
    if (valid()) {
      release(release_context, slot, ticket);
    }
  }

  void HostForwardLease::disarm() noexcept {
    storage = {};
    ticket = 0;
    slot = UINT16_MAX;
    release_context = nullptr;
    release = nullptr;
  }

  class HostForwardPath::Impl {
  public:
    explicit Impl(HostForwardPathConfig config) noexcept:
        config_ {std::move(config)},
        pacer_ {{
          .pacing_bits_per_second = frame_burst_rate(config_.pacing_bits_per_second),
          .input_reserve_bits_per_second = 0,
          .path_datagram_bytes = static_cast<std::uint16_t>(effective_probe_ceiling(config_) + ip_udp_overhead(config_.peer)),
          .quantum_microseconds = 100,
          .submission_horizon_microseconds = 200,
          .max_datagrams_per_batch = 8,
        }},
        current_pacing_bits_per_second_ {config_.pacing_bits_per_second},
        current_path_payload_bytes_ {config_.path_payload_bytes},
        probe_payload_ceiling_ {effective_probe_ceiling(config_)},
        generation_ {config_.generation},
        ready_ {false} {
      if (!config_.valid() || pacer_.error() != pacer_error::none) {
        return;
      }
      try {
        high_precision_timer_ = platf::create_high_precision_timer();
        ready_.store(high_precision_timer_ && static_cast<bool>(*high_precision_timer_), std::memory_order_release);
      } catch (...) {
        ready_.store(false, std::memory_order_release);
      }
    }

    ~Impl() {
      close();
      join();
    }

    bool start() noexcept {
      if (!ready_.load(std::memory_order_acquire) || closed_.load(std::memory_order_acquire) ||
          started_.exchange(true, std::memory_order_acq_rel)) {
        return false;
      }
      pacer_.reset(monotonic_microseconds());
      try {
        worker_ = std::jthread([this](std::stop_token stop_token) noexcept {
          run(stop_token);
        });
      } catch (...) {
        started_.store(false, std::memory_order_release);
        return false;
      }
      return true;
    }

    std::optional<HostForwardLease> acquire(const HostForwardLane lane) noexcept {
      std::scoped_lock lock(mutex_);
      if (!ready_.load(std::memory_order_relaxed) || closed_.load(std::memory_order_relaxed)) {
        return std::nullopt;
      }
      const auto slot_index = find_free_slot(lane);
      if (!slot_index) {
        capacity_rejections_.fetch_add(1, std::memory_order_relaxed);
        return std::nullopt;
      }
      return reserve_slot_locked(*slot_index, lane);
    }

    std::optional<HostForwardLease> acquire_until(
      const HostForwardLane lane,
      const std::uint64_t deadline_microseconds
    ) noexcept {
      std::unique_lock lock(mutex_);
      while (ready_.load(std::memory_order_relaxed) && !closed_.load(std::memory_order_relaxed)) {
        if (const auto slot_index = find_free_slot(lane)) {
          return reserve_slot_locked(*slot_index, lane);
        }
        const auto now = monotonic_microseconds();
        if (deadline_microseconds == 0 || now >= deadline_microseconds) {
          capacity_rejections_.fetch_add(1, std::memory_order_relaxed);
          return std::nullopt;
        }
        const auto remaining = std::min<std::uint64_t>(deadline_microseconds - now, 1'000'000U);
        condition_.wait_for(lock, std::chrono::microseconds {remaining}, [this, lane]() {
          return closed_.load(std::memory_order_relaxed) || find_free_slot(lane).has_value();
        });
      }
      return std::nullopt;
    }

    HostForwardSubmitResult commit(
      HostForwardLease &lease,
      const std::size_t protected_bytes,
      const std::uint64_t deadline_microseconds,
      const std::uint64_t token,
      const HostForwardCompletionTarget target
    ) noexcept {
      std::scoped_lock lock(mutex_);
      if (!lease.valid() || lease.slot >= slots_.size()) {
        return HostForwardSubmitResult::invalid;
      }
      if (lease.release_context != this || lease.release != release_lease_callback) {
        return HostForwardSubmitResult::invalid;
      }
      auto &slot = slots_[lease.slot];
      if (slot.state != SlotState::reserved || slot.ticket != lease.ticket) {
        lease.disarm();
        return HostForwardSubmitResult::invalid;
      }
      if (closed_.load(std::memory_order_relaxed)) {
        release_matching_lease(slot, lease);
        return HostForwardSubmitResult::closed;
      }
      const auto now = monotonic_microseconds();
      const auto payload_ceiling = slot.lane == HostForwardLane::path_probe ? probe_payload_ceiling_ :
                                                                              current_path_payload_bytes_.load(std::memory_order_relaxed);
      if (protected_bytes == 0 || protected_bytes > payload_ceiling ||
          (deadline_microseconds != 0 && deadline_microseconds <= now)) {
        release_matching_lease(slot, lease);
        return HostForwardSubmitResult::invalid;
      }
      const auto charged = protected_bytes + ip_udp_overhead(config_.peer);
      if (charged > std::numeric_limits<std::uint16_t>::max()) {
        release_matching_lease(slot, lease);
        return HostForwardSubmitResult::invalid;
      }
      slot.protected_bytes = protected_bytes;
      slot.charged_bytes = static_cast<std::uint16_t>(charged);
      slot.deadline_microseconds = deadline_microseconds;
      slot.token = token;
      slot.target = target;
      slot.enqueue_ordinal = next_enqueue_ordinal_++;
      if (slot.enqueue_ordinal == 0) {
        slot.enqueue_ordinal = next_enqueue_ordinal_++;
      }
      slot.enqueued_microseconds = now;
      slot.state = SlotState::queued;
      --active_leases_;
      accepted_datagrams_.fetch_add(1, std::memory_order_relaxed);
      lease.disarm();
      condition_.notify_one();
      return HostForwardSubmitResult::accepted;
    }

    void cancel(HostForwardLease &lease) noexcept {
      std::scoped_lock lock(mutex_);
      release_lease(lease);
    }

    HostForwardSubmitResult submit_copy(
      const HostForwardLane lane,
      const std::span<const std::uint8_t> protected_datagram,
      const std::uint64_t deadline_microseconds,
      const std::uint64_t token,
      const HostForwardCompletionTarget target
    ) noexcept {
      if (protected_datagram.empty()) {
        return HostForwardSubmitResult::invalid;
      }
      auto lease = acquire(lane);
      if (!lease) {
        return closed_.load(std::memory_order_acquire) ? HostForwardSubmitResult::closed : HostForwardSubmitResult::no_capacity;
      }
      if (protected_datagram.size() > lease->storage.size()) {
        cancel(*lease);
        return HostForwardSubmitResult::invalid;
      }
      std::memcpy(lease->storage.data(), protected_datagram.data(), protected_datagram.size());
      return commit(*lease, protected_datagram.size(), deadline_microseconds, token, target);
    }

    bool reconfigure(
      const std::uint64_t pacing_bits_per_second,
      const std::uint16_t path_payload_bytes
    ) noexcept {
      std::array<CompletionRecord, total_slot_count> completions {};
      std::size_t completion_count = 0;
      bool pressure_cleared = false;
      std::unique_lock lock(mutex_);
      if (closed_.load(std::memory_order_relaxed) || pacing_bits_per_second == 0 || path_payload_bytes < 1'200U ||
          path_payload_bytes > probe_payload_ceiling_) {
        return false;
      }
      const pacer_config replacement {
        .pacing_bits_per_second = frame_burst_rate(pacing_bits_per_second),
        .input_reserve_bits_per_second = 0,
        .path_datagram_bytes = static_cast<std::uint16_t>(probe_payload_ceiling_ + ip_udp_overhead(config_.peer)),
        .quantum_microseconds = 100,
        .submission_horizon_microseconds = 200,
        .max_datagrams_per_batch = 8,
      };
      if (!pacer_.reconfigure(replacement, monotonic_microseconds())) {
        return false;
      }
      current_pacing_bits_per_second_.store(pacing_bits_per_second, std::memory_order_release);
      const auto prior_path_payload = current_path_payload_bytes_.load(std::memory_order_acquire);
      current_path_payload_bytes_.store(path_payload_bytes, std::memory_order_release);
      const auto now = monotonic_microseconds();
      for (auto &slot : slots_) {
        if ((slot.state != SlotState::queued && slot.state != SlotState::retry) ||
            slot.lane == HostForwardLane::path_probe || slot.protected_bytes <= path_payload_bytes) {
          continue;
        }
        pressure_cleared = pressure_cleared ||
                           (slot.state == SlotState::retry && backpressured_.exchange(false, std::memory_order_acq_rel));
        completions[completion_count++] = completion_for(slot, HostForwardCompletion::message_too_large, now);
        message_too_large_events_.fetch_add(1, std::memory_order_relaxed);
        clear_slot(slot);
      }
      condition_.notify_one();
      lock.unlock();
      if (pressure_cleared) {
        publish_backpressure(false);
      }
      for (std::size_t index = 0; index < completion_count; ++index) {
        publish_completion(completions[index]);
      }
      if (path_payload_bytes != prior_path_payload && config_.callbacks.path_changed != nullptr) {
        config_.callbacks.path_changed(config_.callbacks.context, config_.peer, path_payload_bytes);
      }
      return true;
    }

    void close() noexcept {
      std::array<CompletionRecord, total_slot_count> completions {};
      std::size_t completion_count = 0;
      bool pressure_cleared = false;
      {
        std::scoped_lock lock(mutex_);
        if (closed_.exchange(true, std::memory_order_acq_rel)) {
          return;
        }
        const auto now = monotonic_microseconds();
        for (auto &slot : slots_) {
          if (slot.state == SlotState::sending || slot.state == SlotState::free || slot.state == SlotState::reserved) {
            continue;
          }
          completions[completion_count++] = completion_for(slot, HostForwardCompletion::cancelled, now);
          cancelled_datagrams_.fetch_add(1, std::memory_order_relaxed);
          clear_slot(slot);
        }
        pressure_cleared = backpressured_.exchange(false, std::memory_order_acq_rel);
      }
      condition_.notify_all();
      if (pressure_cleared) {
        publish_backpressure(false);
      }
      for (std::size_t index = 0; index < completion_count; ++index) {
        publish_completion(completions[index]);
      }
    }

    void join() noexcept {
      close();
      {
        std::unique_lock lock(mutex_);
        condition_.wait(lock, [this]() {
          return active_leases_ == 0;
        });
      }
      if (worker_.joinable()) {
        worker_.request_stop();
        condition_.notify_all();
        worker_.join();
      }
    }

    bool ready() const noexcept {
      return ready_.load(std::memory_order_acquire);
    }

    bool video_admission_open() const noexcept {
      if (!ready() || closed_.load(std::memory_order_acquire) || backpressured_.load(std::memory_order_acquire)) {
        return false;
      }
      std::scoped_lock lock(mutex_);
      return std::ranges::any_of(
        std::span<const Slot> {slots_}.subspan(video_slot_begin),
        [](const Slot &slot) {
          return slot.state == SlotState::free;
        }
      );
    }

    std::uint32_t generation() const noexcept {
      return generation_;
    }

    HostForwardPathSnapshot snapshot() const noexcept {
      return {
        .accepted_datagrams = accepted_datagrams_.load(std::memory_order_relaxed),
        .sent_datagrams = sent_datagrams_.load(std::memory_order_relaxed),
        .sent_protected_bytes = sent_protected_bytes_.load(std::memory_order_relaxed),
        .sent_charged_bytes = sent_charged_bytes_.load(std::memory_order_relaxed),
        .expired_datagrams = expired_datagrams_.load(std::memory_order_relaxed),
        .cancelled_datagrams = cancelled_datagrams_.load(std::memory_order_relaxed),
        .would_block_events = would_block_events_.load(std::memory_order_relaxed),
        .message_too_large_events = message_too_large_events_.load(std::memory_order_relaxed),
        .fatal_events = fatal_events_.load(std::memory_order_relaxed),
        .capacity_rejections = capacity_rejections_.load(std::memory_order_relaxed),
        .current_pacing_bits_per_second = current_pacing_bits_per_second_.load(std::memory_order_acquire),
        .generation = generation_,
        .path_payload_bytes = current_path_payload_bytes_.load(std::memory_order_acquire),
        .probe_payload_ceiling = probe_payload_ceiling_,
        .started = started_.load(std::memory_order_acquire),
        .closed = closed_.load(std::memory_order_acquire),
        .backpressured = backpressured_.load(std::memory_order_acquire),
      };
    }

  private:
    [[nodiscard]] std::optional<HostForwardLease> reserve_slot_locked(
      const std::size_t slot_index,
      const HostForwardLane lane
    ) noexcept {
      auto &slot = slots_[slot_index];
      slot = {};
      slot.state = SlotState::reserved;
      slot.lane = lane;
      slot.ticket = next_ticket_++;
      if (slot.ticket == 0) {
        slot.ticket = next_ticket_++;
      }
      ++active_leases_;
      HostForwardLease lease;
      lease.storage = std::span<std::uint8_t> {slot.bytes};
      lease.ticket = slot.ticket;
      lease.slot = static_cast<std::uint16_t>(slot_index);
      lease.release_context = this;
      lease.release = release_lease_callback;
      return std::optional<HostForwardLease> {std::move(lease)};
    }

    [[nodiscard]] std::optional<std::size_t> find_free_in_range(
      const std::size_t begin,
      const std::size_t end
    ) const noexcept {
      for (std::size_t index = begin; index < end; ++index) {
        if (slots_[index].state == SlotState::free) {
          return index;
        }
      }
      return std::nullopt;
    }

    [[nodiscard]] std::optional<std::size_t> find_free_slot(const HostForwardLane lane) const noexcept {
      if (uses_control_reserve(lane)) {
        if (const auto reserved = find_free_in_range(0, control_slot_count)) {
          return reserved;
        }
      }
      if (uses_audio_reserve(lane)) {
        if (const auto reserved = find_free_in_range(control_slot_count, control_slot_count + audio_slot_count)) {
          return reserved;
        }
      }
      if (lane == HostForwardLane::congestion_feedback) {
        if (const auto reserved = find_free_in_range(congestion_feedback_slot_begin, common_slot_begin)) {
          return reserved;
        }
        return find_free_in_range(shared_slot_begin, total_slot_count);
      }
      if (lane == HostForwardLane::recovery) {
        if (const auto reserved = find_free_in_range(recovery_slot_begin, video_slot_begin)) {
          return reserved;
        }
        return find_free_in_range(video_slot_begin, total_slot_count);
      }
      if (lane == HostForwardLane::path_probe) {
        if (const auto reserved = find_free_in_range(recovery_slot_begin, video_slot_begin)) {
          return reserved;
        }
        return find_free_in_range(shared_slot_begin, total_slot_count);
      }
      if (lane == HostForwardLane::video) {
        if (const auto reserved = find_free_in_range(video_slot_begin, shared_slot_begin)) {
          return reserved;
        }
        return find_free_in_range(shared_slot_begin, total_slot_count);
      }
      return find_free_in_range(shared_slot_begin, total_slot_count);
    }

    /** @brief Return whether a slot may pass the connection-wide RFC 8888 send floor. */
    [[nodiscard]] bool congestion_feedback_eligible(
      const Slot &slot,
      const std::uint64_t now
    ) const noexcept {
      return slot.lane != HostForwardLane::congestion_feedback ||
             last_congestion_feedback_sent_microseconds_ == 0 ||
             (now >= last_congestion_feedback_sent_microseconds_ &&
              now - last_congestion_feedback_sent_microseconds_ >= congestion_feedback_floor_microseconds);
    }

    /** @brief Select the first retry slot eligible for an actual send attempt. */
    [[nodiscard]] std::optional<std::size_t> retry_slot(
      const std::uint64_t now,
      const bool apply_congestion_feedback_floor = true
    ) const noexcept {
      for (std::size_t index = 0; index < slots_.size(); ++index) {
        if (slots_[index].state == SlotState::retry &&
            (!apply_congestion_feedback_floor || congestion_feedback_eligible(slots_[index], now))) {
          return index;
        }
      }
      return std::nullopt;
    }

    /** @brief Select the highest-priority queued slot currently eligible for submission. */
    [[nodiscard]] std::optional<std::size_t> next_queued_slot(
      const std::uint64_t now,
      const bool apply_congestion_feedback_floor = true
    ) const noexcept {
      std::optional<std::size_t> selected;
      for (std::size_t index = 0; index < slots_.size(); ++index) {
        const auto &slot = slots_[index];
        if (slot.state != SlotState::queued ||
            (apply_congestion_feedback_floor && !congestion_feedback_eligible(slot, now))) {
          continue;
        }
        if (!selected) {
          selected = index;
          continue;
        }
        const auto &current = slots_[*selected];
        const auto current_priority = effective_lane_priority(current, now);
        const auto candidate_priority = effective_lane_priority(slot, now);
        const auto current_deadline = current.deadline_microseconds == 0 ? std::numeric_limits<std::uint64_t>::max() : current.deadline_microseconds;
        const auto candidate_deadline = slot.deadline_microseconds == 0 ? std::numeric_limits<std::uint64_t>::max() : slot.deadline_microseconds;
        if (candidate_priority < current_priority ||
            (candidate_priority == current_priority &&
             (candidate_deadline < current_deadline ||
              (candidate_deadline == current_deadline && slot.enqueue_ordinal < current.enqueue_ordinal)))) {
          selected = index;
        }
      }
      return selected;
    }

    /** @brief Return the next connection-wide RFC 8888 eligibility instant, if one is cooling down. */
    [[nodiscard]] std::optional<std::uint64_t> next_congestion_feedback_eligibility(
      const std::uint64_t now
    ) const noexcept {
      if (last_congestion_feedback_sent_microseconds_ == 0 ||
          now < last_congestion_feedback_sent_microseconds_) {
        return std::nullopt;
      }
      const auto eligible_at = last_congestion_feedback_sent_microseconds_ >
                                   std::numeric_limits<std::uint64_t>::max() - congestion_feedback_floor_microseconds ?
                                 std::numeric_limits<std::uint64_t>::max() :
                                 last_congestion_feedback_sent_microseconds_ + congestion_feedback_floor_microseconds;
      if (now >= eligible_at) {
        return std::nullopt;
      }
      const auto waiting = std::ranges::any_of(slots_, [](const Slot &slot) {
        return (slot.state == SlotState::queued || slot.state == SlotState::retry) &&
               slot.lane == HostForwardLane::congestion_feedback;
      });
      return waiting ? std::optional<std::uint64_t> {eligible_at} : std::nullopt;
    }

    [[nodiscard]] bool has_owned_slot() const noexcept {
      return std::ranges::any_of(slots_, [](const Slot &slot) {
        return slot.state != SlotState::free;
      });
    }

    [[nodiscard]] std::optional<std::size_t> expired_slot(const std::uint64_t now) const noexcept {
      for (std::size_t index = 0; index < slots_.size(); ++index) {
        const auto &slot = slots_[index];
        if ((slot.state == SlotState::queued || slot.state == SlotState::retry) &&
            slot.deadline_microseconds != 0 && slot.deadline_microseconds <= now) {
          return index;
        }
      }
      return std::nullopt;
    }

    static CompletionRecord completion_for(
      const Slot &slot,
      const HostForwardCompletion completion,
      const std::uint64_t completed_at_microseconds
    ) noexcept {
      return {
        .token = slot.token,
        .lane = slot.lane,
        .completion = completion,
        .completed_at_microseconds = completed_at_microseconds,
        .protected_bytes = slot.protected_bytes,
        .charged_bytes = slot.charged_bytes,
        .target = slot.target,
        .notify = slot.state != SlotState::reserved,
      };
    }

    static void clear_slot(Slot &slot) noexcept {
      const auto next_ticket = slot.ticket + 1U;
      slot = {};
      slot.ticket = next_ticket == 0 ? 1 : next_ticket;
    }

    void release_matching_lease(Slot &slot, HostForwardLease &lease) noexcept {
      clear_slot(slot);
      if (active_leases_ != 0) {
        --active_leases_;
      }
      lease.disarm();
      condition_.notify_all();
    }

    void release_lease(HostForwardLease &lease) noexcept {
      if (lease.release_context != this || lease.release != release_lease_callback) {
        return;
      }
      if (!lease.valid() || lease.slot >= slots_.size()) {
        lease.disarm();
        return;
      }
      auto &slot = slots_[lease.slot];
      if (slot.state == SlotState::reserved && slot.ticket == lease.ticket) {
        release_matching_lease(slot, lease);
        return;
      }
      lease.disarm();
    }

    static void release_lease_callback(
      void *context,
      const std::uint16_t slot,
      const std::uint64_t ticket
    ) noexcept {
      auto &self = *static_cast<Impl *>(context);
      std::scoped_lock lock(self.mutex_);
      if (slot >= self.slots_.size()) {
        return;
      }
      auto &owned = self.slots_[slot];
      if (owned.state != SlotState::reserved || owned.ticket != ticket) {
        return;
      }
      clear_slot(owned);
      if (self.active_leases_ != 0) {
        --self.active_leases_;
      }
      self.condition_.notify_all();
    }

    void publish_completion(const CompletionRecord &completion) const noexcept {
      if (!completion.notify) {
        return;
      }
      if (completion.target.completed != nullptr) {
        completion.target.completed(
          completion.target.context,
          completion.token,
          completion.lane,
          completion.completion,
          completion.completed_at_microseconds,
          completion.protected_bytes,
          completion.charged_bytes
        );
      }
      if (config_.callbacks.completed != nullptr &&
          (completion.target.completed == nullptr || completion.completion == HostForwardCompletion::fatal)) {
        config_.callbacks.completed(
          config_.callbacks.context,
          completion.token,
          completion.lane,
          completion.completion,
          completion.completed_at_microseconds,
          completion.protected_bytes,
          completion.charged_bytes
        );
      }
    }

    void publish_backpressure(const bool blocked) const noexcept {
      if (config_.callbacks.backpressure_changed != nullptr) {
        config_.callbacks.backpressure_changed(config_.callbacks.context, blocked);
      }
    }

    /**
     * @brief Wait one bounded pacing interval without Windows timer wakeup quantization.
     * @param lock Scheduler lock released so urgent work can be enqueued during the wait.
     * @param microseconds Earned-credit wait, capped at the short retry interval.
     */
    void precise_wait(std::unique_lock<std::mutex> &lock, const std::uint64_t microseconds) noexcept {
      if (microseconds == 0) {
        return;
      }
      const auto bounded = std::min<std::uint64_t>(microseconds, retry_delay_microseconds);
      lock.unlock();
#ifdef _WIN32
      // High-resolution waitable timers still wake roughly half a millisecond
      // late on supported Windows hosts. These <=50us intervals must not enter
      // that scheduler path; idle queues use the condition variable in run().
      const auto started = monotonic_microseconds();
      const auto deadline = started > std::numeric_limits<std::uint64_t>::max() - bounded ?
                              std::numeric_limits<std::uint64_t>::max() :
                              started + bounded;
      while (!closed_.load(std::memory_order_relaxed) && monotonic_microseconds() < deadline) {
  #if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
        _mm_pause();
  #else
        std::atomic_signal_fence(std::memory_order_seq_cst);
  #endif
      }
#else
      high_precision_timer_->sleep_for(std::chrono::microseconds {bounded});
#endif
      lock.lock();
    }

    void run(const std::stop_token stop_token) noexcept {
      while (!stop_token.stop_requested()) {
        std::unique_lock lock(mutex_);
        const auto now = monotonic_microseconds();

        if (const auto expired = expired_slot(now)) {
          const auto pressure_cleared = slots_[*expired].state == SlotState::retry &&
                                        backpressured_.exchange(false, std::memory_order_acq_rel);
          const auto completion = completion_for(slots_[*expired], HostForwardCompletion::expired, now);
          clear_slot(slots_[*expired]);
          expired_datagrams_.fetch_add(1, std::memory_order_relaxed);
          lock.unlock();
          if (pressure_cleared) {
            publish_backpressure(false);
          }
          publish_completion(completion);
          continue;
        }

        if (closed_.load(std::memory_order_relaxed)) {
          if (!has_owned_slot()) {
            break;
          }
          auto cancelled = next_queued_slot(now, false);
          if (!cancelled) {
            cancelled = retry_slot(now, false);
          }
          if (!cancelled) {
            condition_.wait(lock, [this, &stop_token]() {
              const auto instant = monotonic_microseconds();
              return stop_token.stop_requested() || active_leases_ == 0 ||
                     next_queued_slot(instant, false).has_value() || retry_slot(instant, false).has_value();
            });
            continue;
          }
          const auto completion = completion_for(slots_[*cancelled], HostForwardCompletion::cancelled, now);
          clear_slot(slots_[*cancelled]);
          cancelled_datagrams_.fetch_add(1, std::memory_order_relaxed);
          lock.unlock();
          publish_completion(completion);
          continue;
        }

        auto selected = retry_slot(now);
        auto retrying = selected.has_value();
        const auto queued = next_queued_slot(now);
        if (!selected ||
            (queued && lane_priority(slots_[*queued].lane) < lane_priority(slots_[*selected].lane))) {
          selected = queued;
          retrying = false;
        }
        if (retrying && slots_[*selected].retry_at_microseconds > now) {
          precise_wait(lock, slots_[*selected].retry_at_microseconds - now);
          continue;
        }
        if (!selected) {
          if (const auto eligible_at = next_congestion_feedback_eligibility(now)) {
            precise_wait(lock, *eligible_at - now);
          } else {
            condition_.wait(lock, [this, &stop_token]() {
              const auto instant = monotonic_microseconds();
              // New cooling feedback must wake this idle wait so the outer
              // loop can arm its deadline even if no other traffic arrives.
              return stop_token.stop_requested() || closed_.load(std::memory_order_relaxed) ||
                     retry_slot(instant, false).has_value() || next_queued_slot(instant, false).has_value();
            });
          }
          continue;
        }

        auto &slot = slots_[*selected];
        if (batch_window_started_microseconds_ == 0 || now < batch_window_started_microseconds_ ||
            now - batch_window_started_microseconds_ >= microbatch_microseconds) {
          batch_window_started_microseconds_ = now;
          batch_datagrams_ = 0;
        }
        if (batch_datagrams_ >= maximum_microbatch_datagrams) {
          precise_wait(lock, microbatch_microseconds - (now - batch_window_started_microseconds_));
          continue;
        }
        if (!retrying) {
          const std::array<std::uint16_t, 1> charge {slot.charged_bytes};
          const auto grant = pacer_.grant(charge, false, now);
          if (grant.datagrams != 1) {
            const auto wait = pacer_.wait_microseconds(slot.charged_bytes, false, now);
            if (wait == std::numeric_limits<std::uint64_t>::max()) {
              const auto completion = completion_for(slot, HostForwardCompletion::fatal, now);
              clear_slot(slot);
              fatal_events_.fetch_add(1, std::memory_order_relaxed);
              closed_.store(true, std::memory_order_release);
              lock.unlock();
              publish_completion(completion);
              continue;
            }
            precise_wait(lock, wait);
            continue;
          }
        }
        ++batch_datagrams_;

        slot.state = SlotState::sending;
        const auto datagram = std::span<const std::uint8_t> {slot.bytes}.first(slot.protected_bytes);
        lock.unlock();
        const auto send_result = config_.callbacks.send_datagram(config_.callbacks.context, config_.peer, datagram);
        const auto completed_at = monotonic_microseconds();
        lock.lock();

        if (send_result == UdpSendResult::would_block && !closed_.load(std::memory_order_relaxed)) {
          slot.state = SlotState::retry;
          slot.retry_at_microseconds = completed_at + retry_delay_microseconds;
          would_block_events_.fetch_add(1, std::memory_order_relaxed);
          const auto publish_pressure = !backpressured_.exchange(true, std::memory_order_acq_rel);
          lock.unlock();
          if (publish_pressure) {
            publish_backpressure(true);
          }
          continue;
        }

        HostForwardCompletion completion_result = HostForwardCompletion::fatal;
        switch (send_result) {
          case UdpSendResult::sent:
            completion_result = HostForwardCompletion::sent;
            if (slot.lane == HostForwardLane::congestion_feedback) {
              last_congestion_feedback_sent_microseconds_ = completed_at;
            }
            sent_datagrams_.fetch_add(1, std::memory_order_relaxed);
            sent_protected_bytes_.fetch_add(slot.protected_bytes, std::memory_order_relaxed);
            sent_charged_bytes_.fetch_add(slot.charged_bytes, std::memory_order_relaxed);
            break;
          case UdpSendResult::message_too_large:
            completion_result = HostForwardCompletion::message_too_large;
            message_too_large_events_.fetch_add(1, std::memory_order_relaxed);
            break;
          case UdpSendResult::would_block:
            completion_result = HostForwardCompletion::cancelled;
            cancelled_datagrams_.fetch_add(1, std::memory_order_relaxed);
            break;
          case UdpSendResult::fatal:
            completion_result = HostForwardCompletion::fatal;
            fatal_events_.fetch_add(1, std::memory_order_relaxed);
            closed_.store(true, std::memory_order_release);
            break;
        }
        const auto completion = completion_for(slot, completion_result, completed_at);
        clear_slot(slot);
        const auto publish_pressure = backpressured_.exchange(false, std::memory_order_acq_rel);
        lock.unlock();
        if (publish_pressure) {
          publish_backpressure(false);
        }
        publish_completion(completion);
        condition_.notify_all();
      }
    }

    HostForwardPathConfig config_;
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    aggregate_pacer pacer_;
    std::array<Slot, total_slot_count> slots_ {};
    std::unique_ptr<platf::high_precision_timer> high_precision_timer_;
    std::jthread worker_;
    std::uint64_t next_ticket_ {1};
    std::uint64_t next_enqueue_ordinal_ {1};
    std::uint64_t batch_window_started_microseconds_ {};
    std::uint64_t last_congestion_feedback_sent_microseconds_ {};  ///< Latest final-sent RFC 8888 datagram.
    std::size_t active_leases_ {};
    std::uint8_t batch_datagrams_ {};
    std::atomic<std::uint64_t> accepted_datagrams_ {};
    std::atomic<std::uint64_t> sent_datagrams_ {};
    std::atomic<std::uint64_t> sent_protected_bytes_ {};
    std::atomic<std::uint64_t> sent_charged_bytes_ {};
    std::atomic<std::uint64_t> expired_datagrams_ {};
    std::atomic<std::uint64_t> cancelled_datagrams_ {};
    std::atomic<std::uint64_t> would_block_events_ {};
    std::atomic<std::uint64_t> message_too_large_events_ {};
    std::atomic<std::uint64_t> fatal_events_ {};
    std::atomic<std::uint64_t> capacity_rejections_ {};
    std::atomic<std::uint64_t> current_pacing_bits_per_second_ {};
    std::atomic<std::uint16_t> current_path_payload_bytes_ {};
    std::uint16_t probe_payload_ceiling_ {};
    std::uint32_t generation_ {};
    std::atomic<bool> ready_ {};
    std::atomic<bool> started_ {};
    std::atomic<bool> closed_ {};
    std::atomic<bool> backpressured_ {};
  };

  HostForwardPath::HostForwardPath(HostForwardPathConfig config) noexcept:
      impl_ {new (std::nothrow) Impl {std::move(config)}} {
  }

  HostForwardPath::~HostForwardPath() = default;

  bool HostForwardPath::start() noexcept {
    return impl_ && impl_->start();
  }

  std::optional<HostForwardLease> HostForwardPath::acquire(const HostForwardLane lane) noexcept {
    return impl_ ? impl_->acquire(lane) : std::nullopt;
  }

  std::optional<HostForwardLease> HostForwardPath::acquire_until(
    const HostForwardLane lane,
    const std::uint64_t deadline_microseconds
  ) noexcept {
    return impl_ ? impl_->acquire_until(lane, deadline_microseconds) : std::nullopt;
  }

  HostForwardSubmitResult HostForwardPath::commit(
    HostForwardLease &lease,
    const std::size_t protected_bytes,
    const std::uint64_t deadline_microseconds,
    const std::uint64_t token,
    const HostForwardCompletionTarget target
  ) noexcept {
    return impl_ ? impl_->commit(lease, protected_bytes, deadline_microseconds, token, target) : HostForwardSubmitResult::closed;
  }

  void HostForwardPath::cancel(HostForwardLease &lease) noexcept {
    if (impl_) {
      impl_->cancel(lease);
    }
  }

  HostForwardSubmitResult HostForwardPath::submit_copy(
    const HostForwardLane lane,
    const std::span<const std::uint8_t> protected_datagram,
    const std::uint64_t deadline_microseconds,
    const std::uint64_t token,
    const HostForwardCompletionTarget target
  ) noexcept {
    return impl_ ? impl_->submit_copy(lane, protected_datagram, deadline_microseconds, token, target) : HostForwardSubmitResult::closed;
  }

  bool HostForwardPath::reconfigure(
    const std::uint64_t pacing_bits_per_second,
    const std::uint16_t path_payload_bytes
  ) noexcept {
    return impl_ && impl_->reconfigure(pacing_bits_per_second, path_payload_bytes);
  }

  void HostForwardPath::close() noexcept {
    if (impl_) {
      impl_->close();
    }
  }

  void HostForwardPath::join() noexcept {
    if (impl_) {
      impl_->join();
    }
  }

  bool HostForwardPath::ready() const noexcept {
    return impl_ && impl_->ready();
  }

  bool HostForwardPath::video_admission_open() const noexcept {
    return impl_ && impl_->video_admission_open();
  }

  std::uint32_t HostForwardPath::generation() const noexcept {
    return impl_ ? impl_->generation() : 0;
  }

  HostForwardPathSnapshot HostForwardPath::snapshot() const noexcept {
    return impl_ ? impl_->snapshot() : HostForwardPathSnapshot {};
  }
}  // namespace lumen::lsp::runtime
