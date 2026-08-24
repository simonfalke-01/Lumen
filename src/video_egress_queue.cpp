/**
 * @file src/video_egress_queue.cpp
 * @brief Per-session scheduling for encoded video frames awaiting transport.
 */

// standard includes
#include <algorithm>
#include <condition_variable>
#include <deque>
#include <map>
#include <mutex>
#include <utility>

// local includes
#include "video_egress_queue.h"

namespace video {
  namespace {
    /**
     * @brief Encoded frame plus the time at which it entered egress.
     */
    struct queued_frame_t {
      packet_t packet;  ///< Encoded frame awaiting transport.
      std::chrono::steady_clock::time_point queued_at;  ///< Monotonic enqueue time.
    };

    /**
     * @brief Expand a recovery range to include one dropped frame.
     *
     * @param range Optional inclusive range to update.
     * @param frame Monotonic encoded-frame index.
     */
    void include_frame(std::optional<std::pair<std::int64_t, std::int64_t>> &range, const std::int64_t frame) {
      if (!range) {
        range = std::make_pair(frame, frame);
        return;
      }

      range->first = std::min(range->first, frame);
      range->second = std::max(range->second, frame);
    }

  }  // namespace

  /**
   * @brief Mutable scheduler state shared with sender leases.
   */
  struct egress_queue_t::state_t {
    /**
     * @brief Mutable state for one registered session.
     */
    struct session_t {
      behavior_e behavior {behavior_e::fifo};  ///< Overflow behavior for this session.
      std::size_t capacity {};  ///< Immutable queued-frame bound for this session.
      std::chrono::nanoseconds max_queue_age {};  ///< Immutable age deadline, or zero.
      recovery_callback_t recovery_callback;  ///< Encoder recovery notification.
      std::deque<queued_frame_t> frames;  ///< Encoded frames retained in FIFO order.
      telemetry_t telemetry;  ///< Queue counters and age measurements.
      std::size_t in_flight {};  ///< Frames currently leased to transport.
      bool accepting {true};  ///< Whether producers may publish new frames.
      bool on_ready_queue {};  ///< Whether `ready_sessions` already names this session.
      bool awaiting_recovery {};  ///< Whether dependent frames must remain gated.
    };

    /**
     * @brief Construct scheduler state with a fixed per-session bound.
     *
     * @param max_frames_per_session Maximum queued frames retained per session.
     */
    explicit state_t(const std::size_t max_frames_per_session):
        maximum_capacity {max_frames_per_session} {
    }

    std::size_t maximum_capacity;  ///< Largest queued-frame bound accepted at registration.
    bool running {true};  ///< Whether producers and the consumer may continue.
    std::mutex mutex;  ///< Protects every mutable scheduler field.
    std::condition_variable cv;  ///< Wakes the sender and unregister waiters.
    std::map<session_key_t, session_t> sessions;  ///< Per-session queue state.
    std::deque<session_key_t> ready_sessions;  ///< Round-robin order of nonempty sessions.
  };

  namespace {
    /**
     * @brief Synchronize depth counters after a queue mutation.
     *
     * @param session Session state whose queue changed.
     */
    void update_depth(egress_queue_t::state_t::session_t &session) {
      session.telemetry.current_depth = session.frames.size();
      session.telemetry.peak_depth = std::max(session.telemetry.peak_depth, session.frames.size());
    }

    /**
     * @brief Add a nonempty session to the round-robin ready list once.
     *
     * @param state Scheduler state protected by its mutex.
     * @param key Session key whose queue became ready.
     * @param session Session state associated with `key`.
     */
    void mark_ready(
      egress_queue_t::state_t &state,
      const egress_queue_t::session_key_t key,
      egress_queue_t::state_t::session_t &session
    ) {
      if (!session.frames.empty() && !session.on_ready_queue) {
        state.ready_sessions.push_back(key);
        session.on_ready_queue = true;
      }
    }

    /**
     * @brief Remove a session from the round-robin ready list.
     *
     * @param state Scheduler state protected by its mutex.
     * @param key Session key to remove.
     * @param session Session state associated with `key`.
     */
    void remove_ready(
      egress_queue_t::state_t &state,
      const egress_queue_t::session_key_t key,
      egress_queue_t::state_t::session_t &session
    ) {
      std::erase(state.ready_sessions, key);
      session.on_ready_queue = false;
    }

    /**
     * @brief Discard every queued frame and optionally extend a recovery range.
     *
     * @param session Session queue to clear.
     * @param recovery_range Optional dropped-frame range to update.
     * @return Number of discarded frames.
     */
    std::uint64_t clear_frames(
      egress_queue_t::state_t::session_t &session,
      std::optional<std::pair<std::int64_t, std::int64_t>> *recovery_range
    ) {
      const auto dropped = static_cast<std::uint64_t>(session.frames.size());
      if (recovery_range) {
        for (const auto &frame : session.frames) {
          include_frame(*recovery_range, frame.packet->frame_index());
        }
      }
      session.frames.clear();
      session.telemetry.dropped_frames += dropped;
      update_depth(session);
      return dropped;
    }
  }  // namespace

  egress_queue_t::dequeued_frame_t::dequeued_frame_t(
    std::shared_ptr<state_t> state,
    const session_key_t session,
    packet_t packet,
    const std::chrono::nanoseconds queue_age,
    const std::size_t depth_after_dequeue
  ):
      packet {std::move(packet)},
      session {session},
      queue_age {queue_age},
      depth_after_dequeue {depth_after_dequeue},
      state_ {std::move(state)} {
  }

  egress_queue_t::dequeued_frame_t::dequeued_frame_t(dequeued_frame_t &&other) noexcept:
      packet {std::move(other.packet)},
      session {std::exchange(other.session, nullptr)},
      queue_age {other.queue_age},
      depth_after_dequeue {other.depth_after_dequeue},
      state_ {std::move(other.state_)} {
  }

  egress_queue_t::dequeued_frame_t &egress_queue_t::dequeued_frame_t::operator=(dequeued_frame_t &&other) noexcept {
    if (this == &other) {
      return *this;
    }

    release();
    packet = std::move(other.packet);
    session = std::exchange(other.session, nullptr);
    queue_age = other.queue_age;
    depth_after_dequeue = other.depth_after_dequeue;
    state_ = std::move(other.state_);
    return *this;
  }

  egress_queue_t::dequeued_frame_t::~dequeued_frame_t() {
    release();
  }

  void egress_queue_t::dequeued_frame_t::release() noexcept {
    if (!state_) {
      return;
    }

    {
      std::lock_guard lock {state_->mutex};
      const auto it = state_->sessions.find(session);
      if (it != state_->sessions.end() && it->second.in_flight > 0) {
        --it->second.in_flight;
      }
    }
    state_->cv.notify_all();
    state_.reset();
  }

  egress_queue_t::egress_queue_t(const std::size_t max_frames_per_session):
      state_ {std::make_shared<state_t>(std::max<std::size_t>(max_frames_per_session, 1))} {
  }

  bool egress_queue_t::register_session(
    const session_key_t session,
    const behavior_e behavior,
    const registration_policy_t policy,
    recovery_callback_t recovery_callback
  ) {
    std::lock_guard lock {state_->mutex};
    const bool valid_latency = behavior == behavior_e::latency && policy.capacity == 1 &&
                               policy.max_queue_age > std::chrono::nanoseconds::zero();
    const bool valid_fifo = behavior == behavior_e::fifo &&
                            policy.max_queue_age == std::chrono::nanoseconds::zero();
    if (!state_->running || state_->sessions.contains(session) || policy.capacity == 0 ||
        policy.capacity > state_->maximum_capacity || (!valid_latency && !valid_fifo)) {
      return false;
    }

    state_t::session_t new_session;
    new_session.behavior = behavior;
    new_session.capacity = policy.capacity;
    new_session.max_queue_age = policy.max_queue_age;
    new_session.recovery_callback = std::move(recovery_callback);
    new_session.telemetry.configured_capacity = policy.capacity;
    new_session.telemetry.configured_max_queue_age = policy.max_queue_age;
    state_->sessions.emplace(session, std::move(new_session));
    return true;
  }

  std::optional<egress_queue_t::telemetry_t> egress_queue_t::unregister_session(const session_key_t session) {
    std::unique_lock lock {state_->mutex};
    const auto it = state_->sessions.find(session);
    if (it == state_->sessions.end()) {
      return std::nullopt;
    }

    auto &session_state = it->second;
    session_state.accepting = false;
    remove_ready(*state_, session, session_state);
    const auto lifecycle_drops = clear_frames(session_state, nullptr);
    session_state.telemetry.lifecycle_drops += lifecycle_drops;

    state_->cv.wait(lock, [&session_state]() {
      return session_state.in_flight == 0;
    });

    auto telemetry = session_state.telemetry;
    state_->sessions.erase(it);
    return telemetry;
  }

  egress_queue_t::enqueue_e egress_queue_t::push(const session_key_t session, packet_t packet) {
    if (!packet) {
      return enqueue_e::invalid_packet;
    }

    recovery_callback_t recovery_callback;
    recovery_request_t recovery_request;
    bool request_recovery {};
    enqueue_e result {enqueue_e::queued};

    {
      std::lock_guard lock {state_->mutex};
      if (!state_->running) {
        return enqueue_e::stopped;
      }

      const auto it = state_->sessions.find(session);
      if (it == state_->sessions.end() || !it->second.accepting) {
        return enqueue_e::unknown_session;
      }

      auto &session_state = it->second;
      const bool idr_frame = packet->is_idr();
      const bool recovery_frame = idr_frame || packet->after_ref_frame_invalidation;
      const auto packet_frame = packet->frame_index();
      const auto now = std::chrono::steady_clock::now();

      const bool expired = session_state.max_queue_age > std::chrono::nanoseconds::zero() &&
                           !session_state.frames.empty() &&
                           now - session_state.frames.front().queued_at > session_state.max_queue_age;
      if (expired) {
        const auto expired_age = std::chrono::duration_cast<std::chrono::nanoseconds>(
          now - session_state.frames.front().queued_at
        );
        ++session_state.telemetry.age_expiration_events;
        session_state.telemetry.expired_frames += session_state.frames.size();
        session_state.telemetry.last_expired_age = expired_age;
        session_state.telemetry.max_expired_age = std::max(
          session_state.telemetry.max_expired_age,
          expired_age
        );
        std::optional<std::pair<std::int64_t, std::int64_t>> recovery_range;
        const auto expired_frames = clear_frames(session_state, &recovery_range);
        remove_ready(*state_, session, session_state);

        if (recovery_frame) {
          session_state.frames.push_back({std::move(packet), now});
          ++session_state.telemetry.queued_frames;
          ++session_state.telemetry.recovery_restarts;
          session_state.awaiting_recovery = false;
          update_depth(session_state);
          mark_ready(*state_, session, session_state);
          state_->cv.notify_one();
          return enqueue_e::queued_recovery;
        }

        include_frame(recovery_range, packet_frame);
        ++session_state.telemetry.dropped_frames;
        session_state.awaiting_recovery = true;
        ++session_state.telemetry.recovery_requests;
        recovery_callback = session_state.recovery_callback;
        recovery_request = {
          recovery_range->first,
          recovery_range->second,
          expired_frames + 1,
          0,
        };
        request_recovery = true;
        result = enqueue_e::dropped_expired;
      } else if (session_state.awaiting_recovery && !recovery_frame) {
        ++session_state.telemetry.dropped_frames;
        ++session_state.telemetry.gated_drops;
        return enqueue_e::dropped_awaiting_recovery;
      } else if (session_state.frames.size() < session_state.capacity) {
        session_state.frames.push_back({std::move(packet), now});
        ++session_state.telemetry.queued_frames;
        if (session_state.awaiting_recovery) {
          session_state.awaiting_recovery = false;
          ++session_state.telemetry.recovery_restarts;
          result = enqueue_e::queued_recovery;
        }
        update_depth(session_state);
        mark_ready(*state_, session, session_state);
        state_->cv.notify_one();
        return result;
      } else {
        ++session_state.telemetry.overflow_events;
        if (idr_frame) {
          if (session_state.behavior == behavior_e::latency) {
            clear_frames(session_state, nullptr);
          } else {
            session_state.frames.pop_back();
            ++session_state.telemetry.dropped_frames;
            ++session_state.telemetry.replacement_drops;
          }

          session_state.frames.push_back({std::move(packet), now});
          ++session_state.telemetry.queued_frames;
          ++session_state.telemetry.recovery_restarts;
          session_state.awaiting_recovery = false;
          update_depth(session_state);
          mark_ready(*state_, session, session_state);
          state_->cv.notify_one();
          return enqueue_e::queued_recovery;
        }

        std::optional<std::pair<std::int64_t, std::int64_t>> recovery_range;
        std::uint64_t dropped_frames {1};
        include_frame(recovery_range, packet_frame);
        ++session_state.telemetry.dropped_frames;
        if (session_state.behavior == behavior_e::latency) {
          dropped_frames += clear_frames(session_state, &recovery_range);
          remove_ready(*state_, session, session_state);
        } else {
          include_frame(recovery_range, session_state.frames.back().packet->frame_index());
          session_state.frames.pop_back();
          ++dropped_frames;
          ++session_state.telemetry.dropped_frames;
          ++session_state.telemetry.replacement_drops;
          update_depth(session_state);
          if (session_state.frames.empty()) {
            remove_ready(*state_, session, session_state);
          }
        }

        session_state.awaiting_recovery = true;
        ++session_state.telemetry.recovery_requests;
        recovery_callback = session_state.recovery_callback;
        recovery_request = {
          recovery_range->first,
          recovery_range->second,
          dropped_frames,
          session_state.frames.size(),
        };
        request_recovery = true;
        result = enqueue_e::dropped_overflow;
      }
    }

    if (request_recovery && recovery_callback) {
      try {
        recovery_callback(recovery_request);
      } catch (...) {
        std::lock_guard lock {state_->mutex};
        const auto it = state_->sessions.find(session);
        if (it != state_->sessions.end()) {
          ++it->second.telemetry.recovery_callback_failures;
        }
        return enqueue_e::recovery_callback_failed;
      }
    }

    return result;
  }

  std::optional<egress_queue_t::dequeued_frame_t> egress_queue_t::pop() {
    return pop_until(std::nullopt);
  }

  std::optional<egress_queue_t::dequeued_frame_t> egress_queue_t::pop_for(
    const std::chrono::milliseconds timeout
  ) {
    return pop_until(
      std::chrono::steady_clock::now() + std::max(timeout, std::chrono::milliseconds::zero())
    );
  }

  std::optional<egress_queue_t::dequeued_frame_t> egress_queue_t::pop_until(
    const std::optional<std::chrono::steady_clock::time_point> deadline
  ) {
    std::unique_lock lock {state_->mutex};
    while (true) {
      const auto ready = [this]() {
        return !state_->running || !state_->ready_sessions.empty();
      };
      if (deadline) {
        if (!state_->cv.wait_until(lock, *deadline, ready)) {
          return std::nullopt;
        }
      } else {
        state_->cv.wait(lock, ready);
      }
      if (!state_->running) {
        return std::nullopt;
      }

      const auto session = state_->ready_sessions.front();
      state_->ready_sessions.pop_front();
      auto it = state_->sessions.find(session);
      if (it == state_->sessions.end() || it->second.frames.empty()) {
        continue;
      }
      auto &session_state = it->second;
      session_state.on_ready_queue = false;
      const auto now = std::chrono::steady_clock::now();
      const auto queue_age = std::chrono::duration_cast<std::chrono::nanoseconds>(
        now - session_state.frames.front().queued_at
      );
      if (session_state.max_queue_age > std::chrono::nanoseconds::zero() &&
          queue_age > session_state.max_queue_age) {
        ++session_state.telemetry.age_expiration_events;
        session_state.telemetry.expired_frames += session_state.frames.size();
        session_state.telemetry.last_expired_age = queue_age;
        session_state.telemetry.max_expired_age = std::max(
          session_state.telemetry.max_expired_age,
          queue_age
        );
        std::optional<std::pair<std::int64_t, std::int64_t>> recovery_range;
        const auto dropped = clear_frames(session_state, &recovery_range);
        session_state.awaiting_recovery = true;
        ++session_state.telemetry.recovery_requests;
        const auto recovery_callback = session_state.recovery_callback;
        const recovery_request_t request {
          recovery_range->first,
          recovery_range->second,
          dropped,
          0,
        };

        lock.unlock();
        if (recovery_callback) {
          try {
            recovery_callback(request);
          } catch (...) {
            std::lock_guard failure_lock {state_->mutex};
            const auto failure_it = state_->sessions.find(session);
            if (failure_it != state_->sessions.end()) {
              ++failure_it->second.telemetry.recovery_callback_failures;
            }
          }
        }
        lock.lock();
        continue;
      }

      auto queued_frame = std::move(session_state.frames.front());
      session_state.frames.pop_front();
      ++session_state.in_flight;
      ++session_state.telemetry.dequeued_frames;
      session_state.telemetry.last_queue_age = queue_age;
      session_state.telemetry.max_queue_age = std::max(session_state.telemetry.max_queue_age, queue_age);
      update_depth(session_state);
      mark_ready(*state_, session, session_state);
      return dequeued_frame_t {
        state_,
        session,
        std::move(queued_frame.packet),
        queue_age,
        session_state.frames.size(),
      };
    }
  }

  std::optional<egress_queue_t::telemetry_t> egress_queue_t::telemetry(const session_key_t session) const {
    std::lock_guard lock {state_->mutex};
    const auto it = state_->sessions.find(session);
    if (it == state_->sessions.end()) {
      return std::nullopt;
    }
    return it->second.telemetry;
  }

  void egress_queue_t::stop() {
    {
      std::lock_guard lock {state_->mutex};
      if (!state_->running) {
        return;
      }

      state_->running = false;
      state_->ready_sessions.clear();
      for (auto &[key, session] : state_->sessions) {
        static_cast<void>(key);
        session.on_ready_queue = false;
        session.accepting = false;
        const auto lifecycle_drops = clear_frames(session, nullptr);
        session.telemetry.lifecycle_drops += lifecycle_drops;
      }
    }
    state_->cv.notify_all();
  }

  bool egress_queue_t::reset() {
    std::lock_guard lock {state_->mutex};
    if (!state_->sessions.empty()) {
      return false;
    }

    state_->ready_sessions.clear();
    state_->running = true;
    return true;
  }

  std::size_t egress_queue_t::capacity_per_session() const noexcept {
    return state_->maximum_capacity;
  }
}  // namespace video
