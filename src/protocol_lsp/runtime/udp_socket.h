/**
 * @file src/protocol_lsp/runtime/udp_socket.h
 * @brief Native nonblocking single-port UDP ownership for the LSP host runtime.
 */

#pragma once

#include "../service.h"
#include "../transport/rtcp.h"

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <span>

namespace lumen::lsp::runtime {
  /** @brief Immutable no-mutation ECN reflection preview backed by authenticated CCFB bytes. */
  struct EcnFeedbackPreview {
    PeerEndpoint peer {};  ///< Exact authenticated association.
    transport::congestion_feedback_packet_view packet {};  ///< Validated borrowed packet view.
    std::uint64_t now_microseconds {};  ///< Exact receive time used by validation and commit.
  };

  /** @brief Maximum UDP payload admitted by the initial LSP socket runtime. */
  inline constexpr std::size_t maximum_runtime_datagram_size = 65'535;
  inline constexpr std::size_t maximum_runtime_peer_cache = 64;  ///< Bounded association peer-handle cache.

  /** @brief IP ECN codepoint observed or transmitted through ancillary metadata. */
  using DatagramEcn = IpEcn;  ///< Socket-facing alias for the shared authenticated ECN observation.

  /** @brief Low-rate native socket ECN and peer-cache observations. */
  struct NativeUdpSocketSnapshot {
    std::uint64_t received_ect0 {};  ///< Received ECT(0) datagrams.
    std::uint64_t received_ect1 {};  ///< Received ECT(1) datagrams.
    std::uint64_t received_ce {};  ///< Received CE datagrams.
    std::uint64_t sent_ect0 {};  ///< Datagrams submitted with ECT(0) ancillary metadata.
    std::uint64_t ecn_fallbacks {};  ///< Runtime ancillary failures that disabled ECN.
    std::uint64_t ecn_black_hole_resets {};  ///< Authenticated lost ECT probes that reset validation immediately.
    std::size_t cached_peers {};  ///< Populated canonical peer handles.
    std::size_t ecn_validated_peers {};  ///< Peers with fresh authenticated ECN reflection proof.
    bool ipv4_ecn_available {};  ///< Whether IPv4 ancillary receive/send ECN is available.
    bool ipv6_ecn_available {};  ///< Whether IPv6 ancillary receive/send ECN is available.
    bool ecn_available {};  ///< Whether either address family has ancillary ECN support.
  };

  /**
   * @brief One complete received UDP datagram and its monotonic receive time.
   */
  struct ReceivedDatagram {
    const PeerEndpoint &peer;  ///< Cached exact source and bound local endpoint.
    std::span<std::uint8_t> payload;  ///< Mutable socket-owned payload valid only for the callback.
    std::uint64_t received_at_microseconds {};  ///< Local monotonic receive timestamp.
    DatagramEcn ecn {DatagramEcn::unavailable};  ///< Received ECN codepoint or unavailable.
  };

  /**
   * @brief Result of one bounded native receive-drain operation.
   */
  enum class ReceiveBatchResult : std::uint8_t {
    drained,  ///< One or more datagrams were delivered and the bounded batch ended.
    would_block,  ///< No datagram was ready.
    closed,  ///< The socket has been closed.
    fatal,  ///< A native socket error prevents continued operation.
  };

  /** @brief Exact disposition of one nonblocking UDP send attempt. */
  enum class UdpSendResult : std::uint8_t {
    sent,  ///< The kernel accepted the complete datagram.
    would_block,  ///< Transient socket pressure permits an exact-byte retry.
    message_too_large,  ///< Kernel path state rejected this UDP payload size.
    fatal,  ///< Invalid state or a non-transient socket error forbids retry.
  };

  /**
   * @brief Native Winsock/POSIX implementation of LSP's one-port UDP boundary.
   *
   * The socket is nonblocking. A receive call drains no more than the caller's
   * bound and invokes the callback synchronously before reusing its fixed
   * datagram storage.
   */
  class NativeUdpSocket final: public SinglePortUdpSocket {
  public:
    /** @brief Construct a closed socket owner. */
    NativeUdpSocket() noexcept;

    NativeUdpSocket(const NativeUdpSocket &) = delete;
    NativeUdpSocket &operator=(const NativeUdpSocket &) = delete;

    /** @brief Close the native socket. */
    ~NativeUdpSocket() override;

    /** @copydoc SinglePortUdpSocket::bind */
    bool bind(std::uint16_t port) noexcept override;

    /** @copydoc SinglePortUdpSocket::close */
    void close() noexcept override;

    /**
     * @brief Wait for receive readiness or a bounded timeout.
     *
     * @param timeout_milliseconds Maximum wait duration.
     * @return True when the socket may be read, including a close/error wake.
     */
    [[nodiscard]] bool wait_readable(std::uint32_t timeout_milliseconds) noexcept;

    /**
     * @brief Drain a bounded batch of complete datagrams.
     *
     * @param maximum_datagrams Maximum callbacks during this call; must be nonzero.
     * @param callback Synchronous complete-datagram consumer.
     * @return Exact drain disposition.
     */
    ReceiveBatchResult receive_batch(
      std::size_t maximum_datagrams,
      const std::function<void(const ReceivedDatagram &)> &callback
    ) noexcept;

    /**
     * @brief Send one complete UDP datagram to an exact peer.
     *
     * @param peer Destination five-tuple originally produced by this socket.
     * @param datagram Complete UDP payload.
     * @return True only when the native API accepted the whole datagram.
     */
    bool send_datagram(
      const PeerEndpoint &peer,
      std::span<const std::uint8_t> datagram
    ) noexcept;

    /**
     * @brief Send with a typed transient-versus-fatal disposition.
     *
     * @param peer Destination five-tuple originally produced by this socket.
     * @param datagram Complete UDP payload.
     * @return Exact nonblocking send disposition.
     */
    UdpSendResult send_datagram_result(
      const PeerEndpoint &peer,
      std::span<const std::uint8_t> datagram
    ) noexcept;

    /**
     * @brief Return the actual bound port.
     *
     * @return Nonzero port while bound, otherwise zero.
     */
    [[nodiscard]] std::uint16_t bound_port() const noexcept;

    /**
     * @brief Return whether a native socket is currently owned.
     *
     * @return True between a successful bind and close.
     */
    [[nodiscard]] bool open() const noexcept;

    /** @brief Return whether receive ECN classification and ECT(0) transmission are active. */
    [[nodiscard]] bool ecn_available() const noexcept;

    /** @brief Return whether one peer currently has fresh authenticated ECN proof. */
    [[nodiscard]] bool peer_ecn_validated(const PeerEndpoint &peer) const noexcept;

    /**
     * @brief Apply one authenticated, structurally admitted RFC 8888 reflection transcript.
     *
     * @param peer Exact authenticated association reporting reception.
     * @param feedback Shared immutable feedback view.
     * @param now_microseconds Current monotonic receive time.
     * @return True when every reflected mark matched retained sent state.
     */
    bool observe_authenticated_ecn_feedback(
      const PeerEndpoint &peer,
      const transport::congestion_feedback_packet_view &feedback,
      std::uint64_t now_microseconds
    ) noexcept;

    /** @brief Validate retained ECN reflection without mutating peer proof state. */
    bool validate_authenticated_ecn_feedback(
      const PeerEndpoint &peer,
      const transport::congestion_feedback_packet_view &feedback,
      std::uint64_t now_microseconds
    ) noexcept;

    /** @brief Build an explicit no-mutation ECN feedback preview. */
    [[nodiscard]] std::optional<EcnFeedbackPreview> preview_authenticated_ecn_feedback(
      const PeerEndpoint &peer,
      const transport::congestion_feedback_packet_view &feedback,
      std::uint64_t now_microseconds
    ) noexcept;

    /** @brief Revalidate and commit one exact prior ECN feedback preview. */
    bool commit_authenticated_ecn_feedback(const EcnFeedbackPreview &preview) noexcept;

    /** @brief Remove peer validation after an authenticated path-property change. */
    void reset_peer_ecn_validation(const PeerEndpoint &peer) noexcept;

    /** @brief Return current ECN and peer-cache observations. */
    [[nodiscard]] NativeUdpSocketSnapshot snapshot() const noexcept;

  private:
#ifdef _WIN32
    using NativeHandle = std::uintptr_t;  ///< Winsock SOCKET stored without exposing Winsock headers.
    inline static constexpr NativeHandle invalid_handle = static_cast<NativeHandle>(~std::uintptr_t {});  ///< Invalid Winsock handle.
#else
    using NativeHandle = int;  ///< POSIX file descriptor.
    inline static constexpr NativeHandle invalid_handle = -1;  ///< Invalid POSIX file descriptor.
#endif

    /** @brief One native syscall lifetime that prevents concurrent descriptor close/reuse. */
    class OperationLease {
    public:
      /** @brief Try to retain the currently open native descriptor. */
      explicit OperationLease(NativeUdpSocket &owner) noexcept;
      OperationLease(const OperationLease &) = delete;
      OperationLease &operator=(const OperationLease &) = delete;
      /** @brief Release the retained native descriptor lifetime. */
      ~OperationLease();

      /** @brief Return whether an open descriptor was retained. */
      [[nodiscard]] explicit operator bool() const noexcept;
      /** @brief Return the retained descriptor, or the platform invalid value. */
      [[nodiscard]] NativeHandle handle() const noexcept;
      /** @brief Return the retained Darwin IPv4 descriptor, or invalid elsewhere. */
      [[nodiscard]] NativeHandle ipv4_handle() const noexcept;

    private:
      NativeUdpSocket *owner_ {};  ///< Socket whose active-operation count is retained.
      NativeHandle handle_ {invalid_handle};  ///< Stable descriptor protected from close/reuse.
      NativeHandle ipv4_handle_ {invalid_handle};  ///< Stable Darwin IPv4 companion descriptor.
    };

    /** @brief Admit one native operation while close is absent. */
    [[nodiscard]] bool acquire_operation(NativeHandle &handle, NativeHandle &ipv4_handle) noexcept;
    /** @brief Release one admitted native operation and wake close if it was last. */
    void release_operation() noexcept;

    NativeHandle handle_ {invalid_handle};  ///< Owned dual-stack no-fragment socket.
    NativeHandle ipv4_handle_ {invalid_handle};  ///< Darwin IPv4 companion bound to the same port.
    std::uint16_t bound_port_ {};  ///< Actual numeric local port.
    std::array<PeerEndpoint, maximum_runtime_peer_cache> peers_ {};  ///< Canonical binary/text peers cached per association.
    std::atomic<std::size_t> peer_count_ {};  ///< Populated leading peer cache entries.
    std::size_t next_peer_replacement_ {};  ///< Bounded replacement slot after unauthenticated peer churn.
    std::uintptr_t receive_message_ {};  ///< Windows WSARecvMsg extension pointer, zero elsewhere.
    std::uintptr_t send_message_ {};  ///< Windows WSASendMsg extension pointer, zero elsewhere.
    std::atomic<bool> ipv4_ecn_available_ {};  ///< Whether IPv4 ancillary ECN remains active.
    std::atomic<bool> ipv6_ecn_available_ {};  ///< Whether IPv6 ancillary ECN remains active.
    std::atomic<bool> ipv4_packet_info_available_ {};  ///< Whether IPv4 destination/interface ancillary data is active.
    std::atomic<bool> ipv6_packet_info_available_ {};  ///< Whether IPv6 destination/interface ancillary data is active.
    std::atomic<std::uint64_t> received_ect0_ {};  ///< Received ECT(0) datagrams.
    std::atomic<std::uint64_t> received_ect1_ {};  ///< Received ECT(1) datagrams.
    std::atomic<std::uint64_t> received_ce_ {};  ///< Received CE datagrams.
    std::atomic<std::uint64_t> sent_ect0_ {};  ///< Sent ECT(0) datagrams.
    std::atomic<std::uint64_t> ecn_fallbacks_ {};  ///< Runtime ancillary disable transitions.
    std::atomic<std::uint64_t> ecn_black_hole_resets_ {};  ///< Authenticated lost ECT probe resets.

    struct SentEcnRecord {
      std::uint32_t ssrc {};  ///< RTP SSRC visible before SRTP authentication.
      std::uint16_t sequence {};  ///< RTP sequence number visible before SRTP authentication.
      IpEcn mark {IpEcn::not_ect};  ///< Exact ECN mark submitted for this datagram.
      std::uint64_t sent_microseconds {};  ///< Successful local submission time.
      bool reflected {};  ///< Whether authenticated feedback already consumed this proof record.
    };

    /** @brief One fixed set-associative lookup entry for a retained ECN send record. */
    struct SentEcnIndexEntry {
      std::uint16_t slot_plus_one {};  ///< Retained-record slot plus one, or zero when empty.
    };

    inline static constexpr std::size_t ecn_index_bucket_count = 256;  ///< Power-of-two ECN lookup buckets.
    inline static constexpr std::size_t ecn_index_ways = 4;  ///< Fixed collision ways per ECN lookup bucket.
    static_assert((ecn_index_bucket_count & (ecn_index_bucket_count - 1U)) == 0);

    struct PeerEcnState {
      std::array<SentEcnRecord, 256> sent {};  ///< Bounded recent successful RTP marks.
      std::array<SentEcnIndexEntry, ecn_index_bucket_count * ecn_index_ways> index {};  ///< O(1) bounded SSRC/sequence lookup.
      std::size_t next_sent {};  ///< Next sent-mark replacement slot.
      std::uint64_t last_feedback_microseconds {};  ///< Latest matching authenticated reflection.
      std::uint8_t proof_count {};  ///< Matching ECT(0)/CE probe reflections.
      bool validated {};  ///< Whether steady ECT(0) is currently enabled.
    };

    /**
     * @brief Hash one SSRC/sequence key to its fixed ECN lookup bucket.
     *
     * @param ssrc Exact retained RTP SSRC.
     * @param sequence Exact retained RTP sequence.
     * @return Bucket index within the fixed peer-local index.
     */
    [[nodiscard]] static std::size_t sent_ecn_bucket(std::uint32_t ssrc, std::uint16_t sequence) noexcept;
    /**
     * @brief Remove the prior index entry naming one soon-to-be-reused ring slot.
     *
     * @param state Exact peer-local ECN state.
     * @param slot Retained-record slot being reused.
     */
    static void erase_sent_ecn_index(PeerEcnState &state, std::size_t slot) noexcept;
    /**
     * @brief Index one newly written retained send record with bounded collision replacement.
     *
     * @param state Exact peer-local ECN state.
     * @param slot Newly populated retained-record slot.
     */
    static void insert_sent_ecn_index(PeerEcnState &state, std::size_t slot) noexcept;
    /**
     * @brief Find one exact retained record in at most four comparisons.
     *
     * @param state Exact peer-local ECN state.
     * @param ssrc Reported RTP SSRC.
     * @param sequence Reported RTP sequence.
     * @return Matching live retained record, or null when absent/evicted.
     */
    [[nodiscard]] static SentEcnRecord *find_sent_ecn_record(
      PeerEcnState &state,
      std::uint32_t ssrc,
      std::uint16_t sequence
    ) noexcept;

    /** @brief Select a stable Not-ECT/probe/validated mark for one RTP datagram. */
    [[nodiscard]] IpEcn select_send_ecn(
      const PeerEndpoint &peer,
      std::span<const std::uint8_t> datagram,
      std::uint64_t now_microseconds,
      std::uint32_t &ssrc,
      std::uint16_t &sequence
    ) noexcept;
    /** @brief Retain the exact mark only after successful kernel submission. */
    void record_sent_ecn(
      const PeerEndpoint &peer,
      std::uint32_t ssrc,
      std::uint16_t sequence,
      IpEcn mark,
      std::uint64_t sent_microseconds
    ) noexcept;
    /** @brief Disable one ancillary family and reset matching peer proof. */
    void disable_ecn_family(IpAddressFamily family) noexcept;
    /** @brief Shared no-mutation/commit implementation for authenticated ECN reflection. */
    bool process_authenticated_ecn_feedback(
      const PeerEndpoint &peer,
      const transport::congestion_feedback_packet_view &feedback,
      std::uint64_t now_microseconds,
      bool commit
    ) noexcept;
    std::array<PeerEcnState, maximum_runtime_peer_cache> peer_ecn_ {};  ///< State aligned with peer-cache slots.
    mutable std::mutex ecn_mutex_;  ///< Serializes per-peer probe selection and authenticated reflection.
    mutable std::mutex lifecycle_mutex_;  ///< Serializes bind/close with native-operation admission.
    std::condition_variable lifecycle_condition_;  ///< Wakes close after the last syscall/callback returns.
    std::size_t active_operations_ {};  ///< Native calls retaining the current descriptor incarnation.
    bool closing_ {};  ///< Rejects new operations while close waits for the current incarnation.
  };

  /**
   * @brief Read the local monotonic clock in whole microseconds.
   *
   * @return Nondecreasing process-local timestamp.
   */
  [[nodiscard]] std::uint64_t monotonic_microseconds() noexcept;
}  // namespace lumen::lsp::runtime
