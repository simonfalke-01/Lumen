/**
 * @file src/input_state.h
 * @brief Thread-safe global reservations and pure per-session input state helpers.
 */
#pragma once

// standard includes
#include <array>
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

namespace input::detail {
  /** @brief Causal input state and edge watermark carried by captured frames. */
  struct causal_watermark_value_t {
    std::uint64_t state_sequence {};  ///< Latest complete state applied by the ordered consumer.
    std::uint64_t edge_id {};  ///< Latest contiguous edge applied by the ordered consumer.

    bool operator==(const causal_watermark_value_t &) const = default;
  };

  /** @brief Thread-safe queued, applied, and captured input causality state. */
  class causal_watermark_t {
  public:
    /**
     * @brief Reserve a monotonically newer batch before queueing its terminal consumer fence.
     * @return True when neither state nor edge regressed.
     */
    bool reserve(std::uint64_t state_sequence, std::uint64_t edge_id) {
      std::lock_guard lock(mutex_);
      if (state_sequence < queued_.state_sequence || edge_id < queued_.edge_id) {
        return false;
      }
      queued_ = {state_sequence, edge_id};
      return true;
    }

    /** @brief Return the newest edge already reserved for ordered injection. */
    std::uint64_t queued_edge() const {
      std::lock_guard lock(mutex_);
      return queued_.edge_id;
    }

    /** @brief Advance only after the ordered consumer completed platform injection. */
    bool mark_applied(std::uint64_t state_sequence, std::uint64_t edge_id) {
      std::lock_guard lock(mutex_);
      if (state_sequence < applied_.state_sequence || edge_id < applied_.edge_id ||
          state_sequence > queued_.state_sequence || edge_id > queued_.edge_id) {
        return false;
      }
      applied_ = {state_sequence, edge_id};
      return true;
    }

    /** @brief Snapshot the immutable watermark for one capture submission. */
    causal_watermark_value_t capture() const {
      std::lock_guard lock(mutex_);
      return applied_;
    }

    /** @brief Record one accepted encoded frame carrying its capture-time watermark. */
    bool mark_captured(std::uint64_t frame_id, causal_watermark_value_t watermark) {
      std::lock_guard lock(mutex_);
      if (frame_id == 0 || watermark.state_sequence > applied_.state_sequence ||
          watermark.edge_id > applied_.edge_id || frame_id <= captured_frame_) {
        return false;
      }
      captured_ = watermark;
      captured_frame_ = frame_id;
      return true;
    }

    /** @brief Return the newest frame proven to carry at least the requested watermark. */
    std::uint64_t captured_frame(causal_watermark_value_t watermark) const {
      std::lock_guard lock(mutex_);
      return captured_.state_sequence >= watermark.state_sequence &&
                 captured_.edge_id >= watermark.edge_id ?
               captured_frame_ :
               0;
    }

    /** @brief Clear queued, applied, and captured causality for a fresh dispatcher generation. */
    void reset() {
      std::lock_guard lock(mutex_);
      queued_ = {};
      applied_ = {};
      captured_ = {};
      captured_frame_ = 0;
    }

  private:
    mutable std::mutex mutex_;  ///< Serializes producer, consumer, capture, and sender observations.
    causal_watermark_value_t queued_;  ///< Newest batch accepted for ordered injection.
    causal_watermark_value_t applied_;  ///< Newest batch completed by platform injection.
    causal_watermark_value_t captured_;  ///< Watermark carried by `captured_frame_`.
    std::uint64_t captured_frame_ {};  ///< Newest accepted encoded frame with `captured_`.
  };

  /**
   * @brief Reference counts held state contributed by independent input sessions.
   *
   * @tparam Key Hashable platform input identity.
   */
  template<class Key>
  class held_state_counts_t {
  public:
    /**
     * @brief Add one session's held-state contribution.
     *
     * @param key Platform input identity.
     * @return True only for the first global holder.
     */
    bool acquire(const Key &key) {
      return ++counts_[key] == 1;
    }

    /**
     * @brief Remove one session's held-state contribution.
     *
     * @param key Platform input identity.
     * @return True only when the final global holder was removed.
     */
    bool release(const Key &key) {
      const auto position = counts_.find(key);
      if (position == counts_.end() || position->second == 0) {
        return false;
      }
      if (--position->second != 0) {
        return false;
      }
      counts_.erase(position);
      return true;
    }

    /**
     * @brief Return the current global holder count.
     *
     * @param key Platform input identity.
     * @return Number of contributing sessions.
     */
    std::size_t count(const Key &key) const {
      const auto position = counts_.find(key);
      return position == counts_.end() ? 0 : position->second;
    }

  private:
    std::unordered_map<Key, std::size_t> counts_;  ///< Per-identity session contribution counts.
  };

  /**
   * @brief Thread-safe fixed-slot allocator protected against stale foreign releases.
   *
   * @tparam N Number of independently reservable slots.
   */
  template<std::size_t N>
  class synchronized_slot_allocator_t {
  public:
    /**
     * @brief Generation-qualified slot reservation.
     */
    struct reservation_t {
      int id {-1};  ///< Reserved slot index, or -1 when invalid.
      std::uint64_t generation {0};  ///< Generation that owns the slot.

      /**
       * @brief Check whether this token contains a slot.
       */
      explicit operator bool() const noexcept {
        return id >= 0;
      }
    };

    /**
     * @brief Reserve the first available slot.
     *
     * @return Generation-qualified reservation, or an invalid token when full.
     */
    reservation_t allocate() {
      std::lock_guard lock(mutex_);
      for (std::size_t id = 0; id < N; ++id) {
        if (active_[id]) {
          continue;
        }
        active_.set(id);
        auto &generation = generations_[id];
        if (++generation == 0) {
          ++generation;
        }
        return {static_cast<int>(id), generation};
      }
      return {};
    }

    /**
     * @brief Release a slot only when the caller still owns its generation.
     *
     * @param reservation Generation-qualified ownership token.
     * @return True when the active matching reservation was released.
     */
    bool release(reservation_t reservation) {
      return release(reservation, []() {
      });
    }

    /**
     * @brief Release a slot and run owner cleanup while allocation remains excluded.
     *
     * @param reservation Generation-qualified ownership token.
     * @param cleanup Owner cleanup callback invoked only for the active reservation.
     * @return True when cleanup ran and the matching reservation was released.
     */
    bool release(reservation_t reservation, const std::function<void()> &cleanup) {
      if (reservation.id < 0 || static_cast<std::size_t>(reservation.id) >= N) {
        return false;
      }
      std::lock_guard lock(mutex_);
      const auto id = static_cast<std::size_t>(reservation.id);
      if (!active_[id] || generations_[id] != reservation.generation) {
        return false;
      }
      cleanup();
      active_.reset(id);
      return true;
    }

    /**
     * @brief Check whether a generation-qualified reservation is still active.
     *
     * @param reservation Reservation token to inspect.
     * @return True only for the current owner.
     */
    bool owns(reservation_t reservation) const {
      if (reservation.id < 0 || static_cast<std::size_t>(reservation.id) >= N) {
        return false;
      }
      std::lock_guard lock(mutex_);
      const auto id = static_cast<std::size_t>(reservation.id);
      return active_[id] && generations_[id] == reservation.generation;
    }

  private:
    mutable std::mutex mutex_;  ///< Reservation mutex shared by every session consumer.
    std::bitset<N> active_;  ///< Active slot bitmap.
    std::array<std::uint64_t, N> generations_ {};  ///< Latest ownership generation per slot.
  };

  /**
   * @brief Generation fence and timer identifiers for one client controller slot.
   */
  class controller_timer_generation_t {
  public:
    using timer_id_t = std::uint64_t;  ///< Ordered-dispatcher timer identifier.

    /**
     * @brief Timer identifiers invalidated by a lifecycle transition.
     */
    struct cancellations_t {
      timer_id_t timeout {0};  ///< Pending BACK hold timer.
      timer_id_t release {0};  ///< Pending emulated HOME release timer.
    };

    /**
     * @brief Start a fresh controller connection generation.
     *
     * @return New nonzero generation.
     */
    std::uint64_t connect() noexcept {
      timeout_id_ = 0;
      release_id_ = 0;
      if (++generation_ == 0) {
        ++generation_;
      }
      return generation_;
    }

    /**
     * @brief Invalidate callbacks and detach both pending timer identifiers.
     *
     * @return Timer identifiers that the dispatcher must cancel.
     */
    cancellations_t disconnect() noexcept {
      const cancellations_t cancellations {timeout_id_, release_id_};
      timeout_id_ = 0;
      release_id_ = 0;
      if (++generation_ == 0) {
        ++generation_;
      }
      return cancellations;
    }

    /**
     * @brief Check whether a callback belongs to the current controller instance.
     *
     * @param generation Captured connection generation.
     * @return True when the callback may act on the current controller.
     */
    bool is_current(std::uint64_t generation) const noexcept {
      return generation != 0 && generation == generation_;
    }

    /**
     * @brief Return the current connection generation.
     */
    std::uint64_t generation() const noexcept {
      return generation_;
    }

    /**
     * @brief Store the pending BACK timeout identifier.
     *
     * @param id Dispatcher timer identifier.
     */
    void set_timeout(timer_id_t id) noexcept {
      timeout_id_ = id;
    }

    /**
     * @brief Store the pending emulated HOME release identifier.
     *
     * @param id Dispatcher timer identifier.
     */
    void set_release(timer_id_t id) noexcept {
      release_id_ = id;
    }

    /**
     * @brief Return the pending BACK timeout identifier.
     */
    timer_id_t timeout() const noexcept {
      return timeout_id_;
    }

    /**
     * @brief Return the pending emulated HOME release identifier.
     */
    timer_id_t release() const noexcept {
      return release_id_;
    }

  private:
    std::uint64_t generation_ {0};  ///< Current controller connection generation.
    timer_id_t timeout_id_ {0};  ///< Pending BACK hold timer.
    timer_id_t release_id_ {0};  ///< Pending emulated HOME release timer.
  };

  /**
   * @brief Serializes shared transport reset against input-session registration.
   */
  class input_session_reset_gate_t {
  public:
    using session_id_t = std::uint64_t;  ///< Unique active input-session identifier.

    /**
     * @brief Register one active input session.
     *
     * @return Unique nonzero session identifier.
     */
    session_id_t register_session() {
      std::lock_guard lock(mutex_);
      const auto id = next_id_++;
      active_.insert(id);
      return id;
    }

    /**
     * @brief Unregister a session and run reset only when it was the final active session.
     *
     * The callback executes under the registration mutex so a new session cannot begin
     * between the final-session decision and shared transport neutralization.
     *
     * @param id Active session identifier.
     * @param reset_shared_transport Callback that neutralizes shared platform transport.
     * @return True when the session existed and was removed.
     */
    bool unregister_session(session_id_t id, const std::function<void()> &reset_shared_transport) {
      if (id == 0) {
        return false;
      }
      std::lock_guard lock(mutex_);
      if (active_.erase(id) == 0) {
        return false;
      }
      if (active_.empty()) {
        reset_shared_transport();
      }
      return true;
    }

    /**
     * @brief Return the number of active input sessions.
     */
    std::size_t active_sessions() const {
      std::lock_guard lock(mutex_);
      return active_.size();
    }

  private:
    mutable std::mutex mutex_;  ///< Registration and shared-reset serialization mutex.
    std::unordered_set<session_id_t> active_;  ///< Active session identifiers.
    session_id_t next_id_ {1};  ///< Next nonzero session identifier.
  };
}  // namespace input::detail
