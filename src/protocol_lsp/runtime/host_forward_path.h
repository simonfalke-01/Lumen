/**
 * @file src/protocol_lsp/runtime/host_forward_path.h
 * @brief Bounded aggregate host-to-client LSP datagram scheduler and byte pacer.
 */

#pragma once

#include "../core/transport.h"
#include "../types.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>

namespace lumen::lsp::runtime {
  enum class UdpSendResult : std::uint8_t;

  /** @brief Maximum protected UDP payload retained by the host forward path. */
  inline constexpr std::size_t host_forward_maximum_payload_bytes = 1'472;

  /** @brief Scheduler priority classes for host-to-client LSP datagrams. */
  enum class HostForwardLane : std::uint8_t {
    urgent_control = 0,  ///< DTLS authority, stop, and teardown control.
    input_feedback = 1,  ///< LSPI/LSPG acknowledgements and controller output.
    audio = 2,  ///< Host Opus RTP and timing reports.
    congestion_feedback = 3,  ///< Connection-wide floor-controlled RFC 8888 feedback.
    path_probe = 4,  ///< Exact-size authenticated LSPP DPLPMTUD probe.
    recovery = 5,  ///< Deadline-eligible FEC, RTX, and recovery control.
    video = 6,  ///< Primary video RTP.
    periodic = 7,  ///< Periodic reports and telemetry.
    bulk = 8,  ///< Object chunks with no streaming reserve.
  };

  /** @brief Result of reserving or committing one bounded forward-path slot. */
  enum class HostForwardSubmitResult : std::uint8_t {
    accepted,  ///< The slot or immutable datagram was accepted.
    no_capacity,  ///< The lane's bounded storage reserve is exhausted.
    invalid,  ///< Peer, size, deadline, lease, or generation is invalid.
    closed,  ///< Admission has closed for this path generation.
  };

  /** @brief Terminal result delivered for one committed datagram. */
  enum class HostForwardCompletion : std::uint8_t {
    sent,  ///< Kernel accepted the exact protected datagram.
    expired,  ///< Deadline elapsed before submission.
    message_too_large,  ///< Local path state rejected the protected size.
    fatal,  ///< Socket or path ownership prevents continued submission.
    cancelled,  ///< Path generation closed before the datagram was submitted.
  };

  /** @brief Non-owning socket, completion, and pressure callbacks. */
  struct HostForwardCallbacks {
    /** @brief Submit one already-protected immutable UDP payload. */
    using SendDatagram = UdpSendResult (*)(
      void *context,
      const PeerEndpoint &peer,
      std::span<const std::uint8_t> datagram
    ) noexcept;

    /** @brief Observe terminal disposition after exact-byte accounting. */
    using Completed = void (*)(
      void *context,
      std::uint64_t token,
      HostForwardLane lane,
      HostForwardCompletion completion,
      std::uint64_t completed_at_microseconds,
      std::size_t protected_bytes,
      std::uint16_t charged_bytes
    ) noexcept;

    /** @brief Observe a transition into or out of kernel backpressure. */
    using BackpressureChanged = void (*)(void *context, bool blocked) noexcept;

    /** @brief Observe an authenticated path-payload generation change. */
    using PathChanged = void (*)(
      void *context,
      const PeerEndpoint &peer,
      std::uint16_t path_payload_bytes
    ) noexcept;

    void *context {};  ///< Opaque product runtime context.
    SendDatagram send_datagram {};  ///< Required final socket submission callback.
    Completed completed {};  ///< Optional asynchronous terminal callback.
    BackpressureChanged backpressure_changed {};  ///< Optional video-admission callback.
    PathChanged path_changed {};  ///< Optional ECN/path-property invalidation callback.
  };

  /** @brief Optional O(1) producer-specific terminal callback stored with one slot. */
  struct HostForwardCompletionTarget {
    void *context {};  ///< Producer instance retained by its own pending-drain lifetime.
    HostForwardCallbacks::Completed completed {};  ///< Exact producer completion callback.
  };

  /** @brief Immutable bounds for one active host-to-client path generation. */
  struct HostForwardPathConfig {
    PeerEndpoint peer {};  ///< Exact authenticated association five-tuple.
    std::uint32_t generation {};  ///< Nonzero connection/path authority generation.
    std::uint64_t pacing_bits_per_second {};  ///< Aggregate complete IP-layer ceiling.
    std::uint16_t path_payload_bytes {1'200};  ///< Current protected UDP payload ceiling.
    std::uint16_t probe_payload_ceiling {};  ///< Authenticated DPLPMTUD ceiling, or zero for the family maximum.
    HostForwardCallbacks callbacks {};  ///< Required final-send and optional observation callbacks.

    /** @brief Validate peer, generation, path size, rate, and callback invariants. */
    [[nodiscard]] bool valid() const noexcept;
  };

  /** @brief Caller-owned direct-write reservation into one final packet slab. */
  struct HostForwardLease {
    /** @brief Fixed-signature reservation release hook retained without ownership. */
    using Release = void (*)(void *context, std::uint16_t slot, std::uint64_t ticket) noexcept;

    /** @brief Construct an invalid lease. */
    HostForwardLease() noexcept = default;

    HostForwardLease(const HostForwardLease &) = delete;
    HostForwardLease &operator=(const HostForwardLease &) = delete;

    /** @brief Transfer unique reservation ownership. */
    HostForwardLease(HostForwardLease &&other) noexcept;

    /** @brief Release current ownership and transfer another reservation. */
    HostForwardLease &operator=(HostForwardLease &&other) noexcept;

    /** @brief Release an uncommitted reservation through its owning path. */
    ~HostForwardLease();

    std::span<std::uint8_t> storage {};  ///< Final writable protected-datagram slab.
    std::uint64_t ticket {};  ///< Nonzero reservation incarnation.
    std::uint16_t slot {UINT16_MAX};  ///< Fixed slot index, or `UINT16_MAX` when invalid.
    void *release_context {};  ///< Opaque owning path implementation.
    Release release {};  ///< Reservation release hook.

    /** @brief Return whether this lease names a live fixed slot. */
    [[nodiscard]] bool valid() const noexcept;

    /** @brief Invalidate without releasing after the owning path consumed the reservation. */
    void disarm() noexcept;
  };

  /** @brief Lock-free-readable aggregate forward-path counters and state. */
  struct HostForwardPathSnapshot {
    std::uint64_t accepted_datagrams {};  ///< Datagrams committed into bounded queues.
    std::uint64_t sent_datagrams {};  ///< Datagrams accepted by the kernel.
    std::uint64_t sent_protected_bytes {};  ///< Protected UDP payload bytes submitted.
    std::uint64_t sent_charged_bytes {};  ///< Complete IP/UDP bytes charged once.
    std::uint64_t expired_datagrams {};  ///< Datagrams discarded after their deadline.
    std::uint64_t cancelled_datagrams {};  ///< Datagrams cancelled during generation close.
    std::uint64_t would_block_events {};  ///< Kernel backpressure observations.
    std::uint64_t message_too_large_events {};  ///< Typed local PMTU failures.
    std::uint64_t fatal_events {};  ///< Fatal socket/path failures.
    std::uint64_t capacity_rejections {};  ///< Reservations rejected by fixed storage bounds.
    std::uint64_t current_pacing_bits_per_second {};  ///< Active aggregate rate.
    std::uint32_t generation {};  ///< Immutable path authority generation.
    std::uint16_t path_payload_bytes {};  ///< Active protected UDP payload ceiling.
    std::uint16_t probe_payload_ceiling {};  ///< Maximum authenticated LSPP candidate payload.
    bool started {};  ///< Worker has been started successfully.
    bool closed {};  ///< Admission is closed.
    bool backpressured {};  ///< Exact protected bytes await local socket writability.
  };

  /**
   * @brief Per-peer fixed-slot aggregate scheduler and byte pacer.
   *
   * Producers reserve the final slab, populate and protect it exactly once, and
   * commit the immutable leading bytes. The worker is the only active-stream
   * owner that submits those bytes to the UDP socket. Local would-block retries
   * retain the same bytes and consume neither another SRTP index nor more pacer
   * credit.
   */
  class HostForwardPath final {
  public:
    /** @brief Construct a stopped path and preallocate every datagram slot. */
    explicit HostForwardPath(HostForwardPathConfig config) noexcept;

    HostForwardPath(const HostForwardPath &) = delete;
    HostForwardPath &operator=(const HostForwardPath &) = delete;

    /** @brief Close admission, cancel queued work, and join the worker. */
    ~HostForwardPath();

    /** @brief Start the single high-resolution sender worker exactly once. */
    bool start() noexcept;

    /**
     * @brief Reserve a direct-write final slab from the lane's bounded pool.
     *
     * @param lane Scheduler and storage-reserve class.
     * @return Writable lease, or no value when capacity is unavailable.
     */
    [[nodiscard]] std::optional<HostForwardLease> acquire(HostForwardLane lane) noexcept;

    /**
     * @brief Wait for a lane slot without exceeding an admitted frame deadline.
     *
     * Producer notification wakes this wait immediately when the sender frees a
     * slot; the deadline is only a bound against sustained path backpressure.
     *
     * @param lane Scheduler and storage-reserve class.
     * @param deadline_microseconds Absolute monotonic deadline.
     * @return Writable lease, or no value after close or deadline expiry.
     */
    [[nodiscard]] std::optional<HostForwardLease> acquire_until(
      HostForwardLane lane,
      std::uint64_t deadline_microseconds
    ) noexcept;

    /**
     * @brief Commit already-protected leading bytes from a live lease.
     *
     * @param lease Reservation returned by `acquire()`.
     * @param protected_bytes Populated immutable UDP payload bytes.
     * @param deadline_microseconds Absolute monotonic deadline, or zero for none.
     * @param token Opaque completion token retained without ownership.
     * @param target Optional exact producer callback avoiding path-global lookup.
     * @return Exact bounded admission result.
     */
    HostForwardSubmitResult commit(
      HostForwardLease &lease,
      std::size_t protected_bytes,
      std::uint64_t deadline_microseconds,
      std::uint64_t token = 0,
      HostForwardCompletionTarget target = {}
    ) noexcept;

    /** @brief Release an uncommitted direct-write reservation. */
    void cancel(HostForwardLease &lease) noexcept;

    /**
     * @brief Copy transient wolfSSL output into a reserved final slot and commit it.
     *
     * @param lane Scheduler class.
     * @param protected_datagram Complete DTLS UDP payload.
     * @param deadline_microseconds Absolute monotonic deadline, or zero for none.
     * @param token Opaque completion token.
     * @param target Optional exact producer callback.
     * @return Exact bounded admission result.
     */
    HostForwardSubmitResult submit_copy(
      HostForwardLane lane,
      std::span<const std::uint8_t> protected_datagram,
      std::uint64_t deadline_microseconds,
      std::uint64_t token = 0,
      HostForwardCompletionTarget target = {}
    ) noexcept;

    /**
     * @brief Change aggregate rate and confirmed payload without granting credit.
     *
     * @param pacing_bits_per_second Replacement aggregate rate.
     * @param path_payload_bytes Replacement protected UDP payload ceiling.
     * @return True only when the new pacer bounds are valid.
     */
    bool reconfigure(
      std::uint64_t pacing_bits_per_second,
      std::uint16_t path_payload_bytes
    ) noexcept;

    /** @brief Close admission and cancel every datagram not already submitted. */
    void close() noexcept;

    /** @brief Wait for producer leases, then join the closed sender worker; safe to call repeatedly. */
    void join() noexcept;

    /** @brief Return whether construction retained valid immutable bounds. */
    [[nodiscard]] bool ready() const noexcept;

    /** @brief Return whether a video producer may reserve another common slot. */
    [[nodiscard]] bool video_admission_open() const noexcept;

    /** @brief Return the immutable path authority generation. */
    [[nodiscard]] std::uint32_t generation() const noexcept;

    /** @brief Read aggregate counters without exposing slot or queue ownership. */
    [[nodiscard]] HostForwardPathSnapshot snapshot() const noexcept;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;  ///< Hidden fixed-slot scheduler and worker owner.
  };
}  // namespace lumen::lsp::runtime
