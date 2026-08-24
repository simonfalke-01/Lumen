/**
 * @file src/video_egress_queue.h
 * @brief Per-session scheduling for encoded video frames awaiting transport.
 */
#pragma once

// standard includes
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>

// local includes
#include "video.h"

namespace video {
  /**
   * @brief Fair bounded scheduler for encoded frames from multiple sessions.
   *
   * Each registered session owns an independent bounded queue. A single
   * consumer receives one frame from each ready session in round-robin order.
   */
  class egress_queue_t {
  public:
    /**
     * @brief Opaque implementation state retained by sender leases.
     */
    struct state_t;

    using session_key_t = void *;  ///< Opaque identity of one streaming session.

    /**
     * @brief Overflow behavior selected for one session.
     */
    enum class behavior_e {
      fifo,  ///< Preserve the retained FIFO for Quality and legacy sessions.
      latency,  ///< Discard stale unsent dependents for explicitly negotiated Latency sessions.
    };

    /**
     * @brief Result of attempting to enqueue one encoded frame.
     */
    enum class enqueue_e {
      queued,  ///< Frame was appended without discarding another frame.
      queued_recovery,  ///< Independently decodable recovery was queued after discarding stale work.
      dropped_overflow,  ///< Dependent frame was dropped when the session reached its bound.
      dropped_expired,  ///< Dependent frame and stale queued chain were dropped at the age deadline.
      dropped_awaiting_recovery,  ///< Dependent frame was suppressed until an independent restart.
      stopped,  ///< Scheduler shutdown rejected the frame.
      unknown_session,  ///< No accepting registration exists for the supplied key.
      invalid_packet,  ///< A null encoded-frame pointer was rejected.
      recovery_callback_failed,  ///< Recovery was required but its callback threw an exception.
    };

    /**
     * @brief Recovery range emitted after an overflow breaks a reference chain.
     */
    struct recovery_request_t {
      std::int64_t first_frame {};  ///< First unsent frame whose references must not be used.
      std::int64_t last_frame {};  ///< Last unsent frame covered by the recovery request.
      std::uint64_t dropped_frames {};  ///< Frames discarded by the overflow transition.
      std::size_t depth_after_drop {};  ///< Remaining queued depth for this session.
    };

    /** @brief Immutable queue bound and age deadline for one registration. */
    struct registration_policy_t {
      std::size_t capacity {};  ///< Maximum queued frames, excluding sender leases.
      std::chrono::nanoseconds max_queue_age {};  ///< Zero disables age expiry.
    };

    /**
     * @brief Per-session queue counters and queue-age observations.
     */
    struct telemetry_t {
      std::uint64_t queued_frames {};  ///< Frames accepted into the per-session queue.
      std::uint64_t dequeued_frames {};  ///< Frames handed to the transport sender.
      std::uint64_t dropped_frames {};  ///< Total frames discarded before transport.
      std::uint64_t overflow_events {};  ///< Transitions caused by a full per-session queue.
      std::uint64_t age_expiration_events {};  ///< Recovery transitions caused by an expired queued frame.
      std::uint64_t expired_frames {};  ///< Queued frames dropped after exceeding the age deadline.
      std::uint64_t gated_drops {};  ///< Dependent frames suppressed while awaiting recovery.
      std::uint64_t replacement_drops {};  ///< Retained tail frames replaced by a recovery frame.
      std::uint64_t recovery_requests {};  ///< IDR/RFI recovery callbacks requested.
      std::uint64_t recovery_restarts {};  ///< Independently decodable frames that reopened delivery.
      std::uint64_t recovery_callback_failures {};  ///< Recovery callbacks that threw an exception.
      std::uint64_t lifecycle_drops {};  ///< Queued frames discarded by unregister or shutdown.
      std::size_t current_depth {};  ///< Current queued depth, excluding a sender-owned frame.
      std::size_t peak_depth {};  ///< Maximum queued depth observed for this session.
      std::size_t configured_capacity {};  ///< Immutable per-session queued-frame bound.
      std::chrono::nanoseconds configured_max_queue_age {};  ///< Immutable age deadline, or zero.
      std::chrono::nanoseconds last_queue_age {};  ///< Age of the most recently dequeued frame.
      std::chrono::nanoseconds max_queue_age {};  ///< Maximum age observed at dequeue.
      std::chrono::nanoseconds last_expired_age {};  ///< Age that triggered the latest expiration.
      std::chrono::nanoseconds max_expired_age {};  ///< Maximum expired age observed.
    };

    /**
     * @brief Callback that requests encoder recovery after dependent-frame loss.
     */
    using recovery_callback_t = std::function<void(const recovery_request_t &)>;

    /**
     * @brief Sender-owned frame lease that releases session lifetime protection on destruction.
     */
    class dequeued_frame_t {
    public:
      dequeued_frame_t() = default;
      dequeued_frame_t(const dequeued_frame_t &) = delete;
      dequeued_frame_t &operator=(const dequeued_frame_t &) = delete;

      /**
       * @brief Move a sender lease without duplicating its in-flight reference.
       *
       * @param other Lease to transfer.
       */
      dequeued_frame_t(dequeued_frame_t &&other) noexcept;

      /**
       * @brief Replace this lease with another sender lease.
       *
       * @param other Lease to transfer.
       * @return This lease after the transfer.
       */
      dequeued_frame_t &operator=(dequeued_frame_t &&other) noexcept;

      /**
       * @brief Release the in-flight session reference.
       */
      ~dequeued_frame_t();

      packet_t packet;  ///< Encoded frame owned by the transport sender.
      session_key_t session {};  ///< Session that owns `packet`.
      std::chrono::nanoseconds queue_age {};  ///< Time spent waiting in the egress scheduler.
      std::size_t depth_after_dequeue {};  ///< Owning session depth after this frame was removed.

    private:
      friend class egress_queue_t;

      /**
       * @brief Construct an active sender lease.
       *
       * @param state Shared scheduler state used to release the lease safely.
       * @param session Session protected by the lease.
       * @param packet Encoded frame transferred to the sender.
       * @param queue_age Time spent waiting before dequeue.
       * @param depth_after_dequeue Remaining per-session queue depth.
       */
      dequeued_frame_t(
        std::shared_ptr<state_t> state,
        session_key_t session,
        packet_t packet,
        std::chrono::nanoseconds queue_age,
        std::size_t depth_after_dequeue
      );

      /**
       * @brief Release this lease if it is active.
       */
      void release() noexcept;

      std::shared_ptr<state_t> state_;  ///< Scheduler state retained through transport completion.
    };

    /**
     * @brief Construct a scheduler with a fixed queued-frame bound per session.
     *
     * One additional frame may be owned by the single transport sender while a
     * session queue remains at its bound.
     *
     * @param max_frames_per_session Maximum queued frames retained for one session.
     */
    explicit egress_queue_t(std::size_t max_frames_per_session = 32);

    egress_queue_t(const egress_queue_t &) = delete;
    egress_queue_t &operator=(const egress_queue_t &) = delete;

    /**
     * @brief Register a session before its encoder can publish frames.
     *
     * @param session Opaque stable session key.
     * @param behavior Overflow behavior selected from the negotiated stream policy.
     * @param policy Per-session capacity and age deadline.
     * @param recovery_callback Callback that requests RFI or IDR recovery.
     * @return True when a new accepting registration was created.
     */
    [[nodiscard]] bool register_session(
      session_key_t session,
      behavior_e behavior,
      registration_policy_t policy,
      recovery_callback_t recovery_callback
    );

    /**
     * @brief Stop accepting a session, discard its queued frames, and wait for transport completion.
     *
     * @param session Opaque session key previously registered.
     * @return Final telemetry, or empty when the key was not registered.
     */
    [[nodiscard]] std::optional<telemetry_t> unregister_session(session_key_t session);

    /**
     * @brief Publish one encoded frame into its session queue.
     *
     * @param session Opaque registered session key.
     * @param packet Encoded frame to schedule or discard according to policy.
     * @return Queueing result for diagnostics and recovery failures.
     */
    enqueue_e push(session_key_t session, packet_t packet);

    /**
     * @brief Wait for and remove the next round-robin scheduled frame.
     *
     * @return Sender lease, or empty after scheduler shutdown.
     */
    std::optional<dequeued_frame_t> pop();

    /**
     * @brief Wait a bounded duration for the next scheduled encoded frame.
     *
     * @param timeout Maximum wait for producer progress.
     * @return Sender lease, or empty on timeout/shutdown.
     */
    std::optional<dequeued_frame_t> pop_for(std::chrono::milliseconds timeout);

    /**
     * @brief Copy current telemetry for one registered session.
     *
     * @param session Opaque registered session key.
     * @return Telemetry snapshot, or empty when the key is not registered.
     */
    [[nodiscard]] std::optional<telemetry_t> telemetry(session_key_t session) const;

    /**
     * @brief Stop producers and consumers and discard all queued frames.
     */
    void stop();

    /**
     * @brief Restart an idle scheduler for a new broadcast lifetime.
     *
     * @return True when no registered or in-flight sessions prevented reset.
     */
    [[nodiscard]] bool reset();

    /**
     * @brief Return the configured queued-frame bound for each session.
     *
     * @return Maximum queued frames per registered session.
     */
    [[nodiscard]] std::size_t capacity_per_session() const noexcept;

  private:
    std::optional<dequeued_frame_t> pop_until(
      std::optional<std::chrono::steady_clock::time_point> deadline
    );

    std::shared_ptr<state_t> state_;  ///< Shared state retained by sender leases.
  };
}  // namespace video
