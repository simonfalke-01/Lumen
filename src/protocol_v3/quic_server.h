/**
 * @file src/protocol_v3/quic_server.h
 * @brief Production one-port MsQuic transport for Lumen protocol v3.
 */

#pragma once

#include "../protocol_common/cbor.h"

#include <array>
#include <chrono>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace lumen::protocol_v3::quic_server {
  using MonotonicClock = std::chrono::steady_clock;  ///< Transport boundary clock.

  inline constexpr std::string_view required_alpn = "lumen/3";  ///< Exact protocol-v3 QUIC ALPN.
  inline constexpr std::uint16_t default_udp_port = 48030;  ///< Experimental single UDP listener port.
  inline constexpr std::size_t control_header_bytes = 24;  ///< Exact ULC3 header size.
  inline constexpr std::size_t datagram_header_bytes = 44;  ///< Exact ULM3 header size.
  inline constexpr std::size_t maximum_semantic_datagram_bytes = 1'152;  ///< Immutable phase-one ULM3 cap.
  inline constexpr std::size_t maximum_control_payload_bytes = 1'048'576;  ///< ULC3 CBOR cap.
  inline constexpr std::size_t bulk_header_bytes = 64;  ///< Exact ULB3 header size.
  inline constexpr std::size_t maximum_bulk_payload_bytes = 16U * 1024U * 1024U;  ///< Per-object asset cap.
  inline constexpr std::size_t maximum_bulk_streams = 4;  ///< Concurrent host bulk-stream cap.
  inline constexpr std::size_t maximum_bulk_buffered_bytes = 32U * 1024U * 1024U;  ///< Per-connection payload cap.

  /** @brief Explicit LAN transport profile, independent of legacy crypto state. */
  enum class Profile {
    latency,  ///< Minimize queued age and preserve urgent capacity.
    quality,  ///< Maximize bounded fidelity and stable pacing.
  };

  /**
   * @brief Stable semantic lanes carried by one QUIC connection.
   *
   * Reliable control/configuration uses the one client-opened bidirectional
   * control stream. Live semantic media uses QUIC DATAGRAM and never creates a
   * stream per message. A future separately specified bulk lane may open a
   * bounded stream through the facade without changing this phase-one policy.
   */
  enum class Lane : std::uint8_t {
    control = 0,  ///< ULC3 control; the client-opened bidirectional stream.
    input_edge = 1,  ///< ULM3 input state/edge or acknowledgement.
    audio = 2,  ///< Time-bounded host audio; DATAGRAM.
    microphone = 3,  ///< Time-bounded client microphone media; DATAGRAM.
    key_config = 4,  ///< Reliable ULC3 codec/configuration semantics.
    delta_video = 5,  ///< Replaceable non-reference video media; DATAGRAM.
  };

  /** @brief Wire delivery contract for one semantic lane. */
  enum class Delivery {
    reliable_stream,  ///< The persistent ordered client-opened control stream.
    datagram,  ///< QUIC DATAGRAM with a negotiated payload maximum.
  };

  /**
   * @brief Return the fixed delivery contract for a semantic lane.
   *
   * @param lane Lane to classify.
   * @return Reliable-stream or datagram delivery.
   */
  Delivery delivery_for(Lane lane) noexcept;

  /**
   * @brief Return the latency-mode priority for a semantic lane.
   *
   * Lower values are scheduled first. Control/input edges outrank audio and
   * microphone, which outrank key/config, which outranks delta video.
   *
   * @param lane Lane to rank.
   * @return Stable priority in the inclusive range 0...3.
   */
  std::uint8_t latency_priority(Lane lane) noexcept;

  /** @brief ULC3/ULM3 direction used for exact route validation. */
  enum class Direction {
    client_to_host,
    host_to_client,
  };

  /** @brief Stable parser reason classes used by hostile tests and telemetry. */
  enum class ParseError {
    none,
    truncated,
    size_limit,
    magic_or_version,
    header_length,
    reserved_flags,
    payload_length,
    control_flags,
    control_cbor,
    zero_session,
    session_mismatch,
    reserved_route,
    flags_forbidden,
    phase_one_fec,
  };

  /** @brief Protocol-v3 QUIC application close codes from the wire contract. */
  enum class ApplicationCloseCode : std::uint64_t {
    malformed = 0x100,  ///< Invalid fixed header, CBOR, length, or pre-auth/sessionless data lane.
    connection_replaced = 0x105,  ///< A newer authenticated authority generation replaced this connection.
    abuse_limit = 0x106,  ///< A bounded malformed-record or invalid-DATAGRAM rate threshold was exceeded.
    internal_failure = 0x109,  ///< A fail-closed internal invariant failed.
    normal_shutdown = 0x10A,  ///< The server explicitly shut down the connection.
  };

  /**
   * @brief Fixed-capacity authenticated malformed-record and DATAGRAM-rate guard.
   *
   * The tracker retains only the 32 timestamps required by the rolling
   * malformed-record limit. Invalid-DATAGRAM rate accounting uses constant
   * scalar state for one-second buckets and never grows with peer traffic.
   */
  class AbuseTracker {
  public:
    static constexpr std::size_t malformed_record_limit = 32;  ///< Close on this record in ten seconds.
    static constexpr auto malformed_record_window = std::chrono::seconds {10};  ///< Rolling count window.
    static constexpr std::uint32_t invalid_datagram_rate_limit = 256;  ///< Permitted invalid records per second.
    static constexpr std::uint32_t invalid_datagram_rate_seconds = 3;  ///< Consecutive excess-rate seconds.

    /**
     * @brief Count one authenticated malformed control, ULM3, or bulk record.
     *
     * @param now Monotonic observation time.
     * @return `true` when the rolling malformed-record close threshold is met.
     */
    bool observe_malformed_record(MonotonicClock::time_point now) noexcept;

    /**
     * @brief Count one authenticated invalid DATAGRAM for the rate threshold.
     *
     * @param now Monotonic observation time.
     * @return `true` in the third consecutive one-second excess-rate bucket.
     */
    bool observe_invalid_datagram(MonotonicClock::time_point now) noexcept;

    /**
     * @brief Count one malformed authenticated ULM3 record against both limits.
     *
     * @param now Monotonic observation time.
     * @return `true` when either authenticated DATAGRAM abuse limit is met.
     */
    bool observe_malformed_datagram(MonotonicClock::time_point now) noexcept;

  private:
    std::array<MonotonicClock::time_point, malformed_record_limit> malformed_records_ {};  ///< Timestamp ring.
    std::size_t malformed_begin_ {};  ///< Oldest live timestamp index.
    std::size_t malformed_size_ {};  ///< Live timestamp count.
    MonotonicClock::time_point datagram_bucket_start_ {};  ///< Current one-second bucket boundary.
    std::uint32_t datagrams_in_bucket_ {};  ///< Saturating current invalid-DATAGRAM count.
    std::uint32_t preceding_excess_buckets_ {};  ///< Consecutive completed excess-rate bucket count.
    bool datagram_bucket_initialized_ {};  ///< Whether the current bucket boundary is live.
  };

  /** @brief Parsed complete ULC3 frame retaining exact transcript bytes. */
  struct ControlFrame {
    std::uint8_t flags {};
    std::uint16_t message_type {};
    std::uint64_t request_id {};
    std::span<const std::uint8_t> bytes;  ///< Callback-scoped byte-exact ULC3 frame.
  };

  /** @brief Parsed complete ULM3 semantic record. */
  struct DatagramRecord {
    std::uint8_t channel {};
    std::uint8_t kind {};
    std::uint8_t flags {};
    std::array<std::uint8_t, 16> session_id {};
    std::uint64_t sequence {};
    std::uint64_t object_id {};
    std::span<const std::uint8_t> payload;  ///< Callback-scoped kind-specific payload.
  };

  /** @brief Parse one byte-exact complete ULC3 frame. */
  std::expected<ControlFrame, ParseError> parse_control_frame(std::span<const std::uint8_t> bytes);

  /** @brief Parse and route one byte-exact complete ULM3 record. */
  std::expected<DatagramRecord, ParseError> parse_datagram_record(
    std::span<const std::uint8_t> bytes,
    Direction direction,
    std::span<const std::uint8_t, 16> expected_session_id,
    std::size_t negotiated_maximum
  );

  /** @brief Opaque handle used across the MinGW/MSVC MsQuic ABI facade. */
  using Handle = std::uintptr_t;
  inline constexpr Handle invalid_handle = 0;  ///< Invalid facade handle.

  /** @brief Small, stable status surface mapped from QUIC_STATUS. */
  enum class ApiStatus {
    success,
    pending,
    out_of_memory,
    invalid_state,
    not_supported,
    aborted,
    transport_error,
  };

  /**
   * @brief Return whether an asynchronous MsQuic operation was accepted.
   *
   * @param status Facade status.
   * @return True for success or pending.
   */
  bool accepted(ApiStatus status) noexcept;

  /**
   * @brief Fixed-capacity generation-checked send-slot token allocator.
   *
   * One instance belongs to one connection. Acquiring and releasing slots
   * performs no dynamic allocation; stale completion tokens cannot release a
   * slot that has since been reused.
   */
  class SendSlotPool {
  public:
    static constexpr std::size_t maximum_capacity = 256;  ///< Maximum configured connection send capacity.

    /** @brief One acquired slot and its opaque completion token. */
    struct Lease {
      std::size_t index {};  ///< Stable index into connection-owned send storage.
      std::uint64_t token {};  ///< Nonzero index/generation completion token.
    };

    /** @brief Construct a pool clamped to the supported fixed capacity. */
    explicit SendSlotPool(std::size_t capacity) noexcept;

    /** @brief Acquire one reusable slot, or no value when the pool is full. */
    std::optional<Lease> acquire() noexcept;

    /** @brief Resolve a live token to its slot index. */
    std::optional<std::size_t> index(std::uint64_t token) const noexcept;

    /** @brief Release exactly one live token; stale or duplicate tokens fail. */
    bool release(std::uint64_t token) noexcept;

    /** @brief Release every live token without changing slot generations. */
    void clear() noexcept;

    /** @brief Return whether the indexed slot is currently leased. */
    bool occupied(std::size_t index) const noexcept;

    /** @brief Return the configured slot capacity. */
    std::size_t capacity() const noexcept;

    /** @brief Return the number of live leases. */
    std::size_t active() const noexcept;

  private:
    /** @brief Per-slot generation and lease state. */
    struct Slot {
      std::uint64_t generation {};
      bool occupied {};
    };

    std::array<Slot, maximum_capacity> slots_ {};
    std::size_t capacity_ {};
    std::size_t active_ {};
    std::size_t next_ {};
  };

  /** @brief Read-only buffer passed to the MsQuic facade. */
  struct Buffer {
    const std::uint8_t *data {};  ///< Buffer bytes.
    std::size_t size {};  ///< Buffer length.
  };

  /** @brief Normalized address bucket used by pre-auth admission control. */
  struct RemoteSourcePrefix {
    enum class Family : std::uint8_t {
      ipv4,
      ipv6,
    };

    Family family {Family::ipv4};  ///< Normalized address family.
    std::array<std::uint8_t, 8> bytes {};  ///< IPv4 address or IPv6 /64 prefix.

    auto operator<=>(const RemoteSourcePrefix &) const = default;
  };

  /** @brief Normalize a Windows IPv4/IPv6 address into the pre-auth source bucket. */
  std::optional<RemoteSourcePrefix> normalize_remote_source(
    std::uint16_t address_family,
    std::span<const std::uint8_t> address
  ) noexcept;

  /** @brief Listener callback event. */
  struct ListenerEvent {
    enum class Kind {
      new_connection,
      stop_complete,
    };

    Kind kind {Kind::new_connection};  ///< Callback kind.
    Handle connection {invalid_handle};  ///< Accepted connection for new_connection.
    std::optional<RemoteSourcePrefix> remote_source;  ///< Normalized pre-auth source bucket.
  };

  /** @brief Connection callback event required by the production transport. */
  struct ConnectionEvent {
    enum class Kind {
      connected,
      datagram_state_changed,
      datagram_received,
      datagram_send_complete,
      stream_send_complete,
      peer_stream_started,
      shutdown_by_transport,
      shutdown_by_peer,
      shutdown_complete,
    };

    Kind kind {Kind::connected};  ///< Callback kind.
    Handle stream {invalid_handle};  ///< Peer stream when applicable.
    std::uint64_t stream_id {};  ///< Exact QUIC stream ID for peer_stream_started.
    std::uint64_t send_token {};  ///< Exact application send token when applicable.
    std::uint64_t transport_error {};  ///< Opaque MsQuic transport status.
    std::uint64_t peer_error {};  ///< Peer application close status.
    std::uint16_t maximum_datagram_bytes {};  ///< Negotiated DATAGRAM maximum.
    bool datagram_send_enabled {};  ///< Whether peer and path permit DATAGRAM sends.
    bool resumed {};  ///< Whether the handshake resumed a prior session.
    bool early_data_accepted {};  ///< Whether any 0-RTT data was accepted.
    bool canceled {};  ///< Whether a completed send was canceled.
    bool peer_stream_unidirectional {};  ///< Direction flag for peer_stream_started.
    std::span<const std::uint8_t> received_bytes;  ///< Callback-scoped DATAGRAM bytes.
  };

  /** @brief Stream callback event required for bounded control receive framing. */
  struct StreamEvent {
    enum class Kind {
      receive,
      send_complete,
      writable,
      start_complete,
      peer_send_shutdown,
      peer_send_aborted,
      peer_receive_aborted,
      send_shutdown_complete,
      shutdown_complete,
    };

    Kind kind {Kind::receive};
    std::span<const Buffer> buffers;  ///< Callback-scoped receive buffers.
    std::uint64_t total_buffer_bytes {};
    std::uint64_t send_token {};
    std::uint64_t error {};
    bool canceled {};
  };

  /** @brief Congestion snapshot queried from MsQuic without payload data. */
  struct CongestionSample {
    static constexpr std::uint32_t valid_rtt = 1U << 0;  ///< RTT fields are available.
    static constexpr std::uint32_t valid_congestion_window = 1U << 1;  ///< Congestion window is available.
    static constexpr std::uint32_t valid_bytes_in_flight = 1U << 2;  ///< Bytes in flight is available.
    static constexpr std::uint32_t valid_packets_lost = 1U << 3;  ///< Loss counter is available.

    std::uint32_t valid_fields {};  ///< Bitwise validity mask; zero values alone never mean unavailable.
    std::uint64_t smoothed_rtt_microseconds {};  ///< Smoothed connection RTT.
    std::uint64_t minimum_rtt_microseconds {};  ///< Minimum observed RTT.
    std::uint64_t congestion_window_bytes {};  ///< Current congestion window.
    std::uint64_t bytes_in_flight {};  ///< Bytes currently in flight.
    std::uint64_t packets_lost {};  ///< Cumulative lost packets.
  };

  /** @brief In-memory PKCS#12 server credential imported by the Schannel shim. */
  struct CertificateCredential {
    std::vector<std::uint8_t> pkcs12;  ///< DER PKCS#12 with certificate and private key.
    std::string password;  ///< Random process-memory-only import password.
    ~CertificateCredential();
  };

  /** @brief Convert configured PEM certificate/key text into a bounded PKCS#12 credential. */
  std::shared_ptr<const CertificateCredential> make_certificate_credential_from_pem(
    std::string_view certificate_pem,
    std::string_view private_key_pem
  );

  /** @brief Inputs to the pure Latency-mode video send-budget calculation. */
  struct LatencyVideoBudgetInput {
    std::size_t maximum_in_flight_sends {};
    std::size_t urgent_send_reserve {};
    std::size_t maximum_datagram_bytes {};
    std::uint64_t video_bitrate_kbps {};
    std::uint64_t smoothed_rtt_microseconds {};
    std::optional<std::uint64_t> congestion_window_bytes;
    std::optional<std::uint64_t> bytes_in_flight;
  };

  /** @brief Derive a bounded same-frame outstanding-fragment budget from BDP and congestion capacity. */
  std::size_t latency_video_send_budget(const LatencyVideoBudgetInput &input) noexcept;

  /**
   * @brief Narrow production ABI facade between the core and MSVC MsQuic shim.
   *
   * Implementations map these calls directly to MsQuic 2.6 APIs. Close calls
   * must quiesce callbacks for the closed handle before returning. Callback
   * functions are serialized per connection by MsQuic; this class adds no
   * worker pool.
   */
  class MsQuicApi {
  public:
    using ListenerCallback = std::function<ApiStatus(const ListenerEvent &)>;  ///< Listener callback.
    using ConnectionCallback = std::function<ApiStatus(const ConnectionEvent &)>;  ///< Connection callback.
    using StreamCallback = std::function<ApiStatus(const StreamEvent &)>;  ///< Stream callback.

    virtual ~MsQuicApi() = default;

    /** @brief Verify that the loaded provider is Windows Schannel. */
    virtual bool is_schannel() const noexcept = 0;

    /** @brief Open one low-latency execution-profile registration. */
    virtual ApiStatus registration_open(std::string_view application_name, Handle &registration) = 0;

    /** @brief Close one registration after all child handles close. */
    virtual void registration_close(Handle registration) noexcept = 0;

    /**
     * @brief Open a server configuration with exact ALPN and transport settings.
     *
     * Implementations must enable DATAGRAM receive, disable resumption/tickets,
     * permit no 0-RTT, and allow only the bounded long-lived semantic streams.
     */
    virtual ApiStatus configuration_open(
      Handle registration,
      std::string_view alpn,
      std::uint16_t peer_bidirectional_streams,
      std::uint16_t peer_unidirectional_streams,
      std::uint64_t handshake_timeout_ms,
      std::uint64_t initial_idle_timeout_ms,
      Handle &configuration
    ) = 0;

    /** @brief Import an in-memory PKCS#12 certificate/key into Schannel without persistence. */
    virtual ApiStatus configuration_load_pkcs12(
      Handle configuration,
      std::span<const std::uint8_t> pkcs12,
      std::string_view password
    ) = 0;

    /** @brief Read the exact loaded leaf certificate DER-SPKI SHA-256. */
    virtual ApiStatus configuration_leaf_spki_sha256(
      Handle configuration,
      std::span<std::uint8_t, 32> output
    ) = 0;

    /** @brief Close one configuration. */
    virtual void configuration_close(Handle configuration) noexcept = 0;

    /** @brief Open a listener and retain its callback until listener_close(). */
    virtual ApiStatus listener_open(
      Handle registration,
      ListenerCallback callback,
      Handle &listener
    ) = 0;

    /** @brief Bind one listener to a single configurable UDP port. */
    virtual ApiStatus listener_start(Handle listener, std::string_view alpn, std::uint16_t udp_port) = 0;

    /** @brief Stop accepting; completion arrives through stop_complete. */
    virtual void listener_stop(Handle listener) noexcept = 0;

    /** @brief Close and quiesce a listener callback. */
    virtual void listener_close(Handle listener) noexcept = 0;

    /** @brief Install one connection callback before assigning configuration. */
    virtual ApiStatus connection_set_callback(
      Handle connection,
      ConnectionCallback callback
    ) = 0;

    /** @brief Assign the server configuration to an accepted connection. */
    virtual ApiStatus connection_set_configuration(Handle connection, Handle configuration) = 0;

    /** @brief Replace the connection idle deadline in milliseconds; zero disables it. */
    virtual ApiStatus connection_set_idle_timeout(Handle connection, std::uint64_t timeout_ms) = 0;

    /** @brief Begin an application-error connection shutdown. */
    virtual void connection_shutdown(Handle connection, std::uint64_t application_error) noexcept = 0;

    /** @brief Close and quiesce a connection callback. */
    virtual void connection_close(Handle connection) noexcept = 0;

    /** @brief Open one host-to-client unidirectional stream with its callback installed. */
    virtual ApiStatus stream_open_unidirectional(
      Handle connection,
      StreamCallback callback,
      Handle &stream
    ) = 0;

    /** @brief Start one host-opened stream and fail rather than wait beyond the peer stream limit. */
    virtual ApiStatus stream_start(Handle stream) = 0;

    /** @brief Install the callback for a peer- or host-opened stream. */
    virtual ApiStatus stream_set_callback(Handle stream, StreamCallback callback) = 0;

    /**
     * @brief Submit one reliable send on a persistent stream.
     *
     * Buffer storage remains caller-owned until stream_send_complete reports the
     * same nonzero token. No facade implementation may copy into an unbounded
     * intermediate queue.
     */
    virtual ApiStatus stream_send(
      Handle stream,
      std::span<const Buffer> buffers,
      std::uint64_t send_token,
      bool urgent,
      bool fin
    ) = 0;

    /** @brief Set the native QUIC stream priority; lower is more urgent. */
    virtual ApiStatus stream_set_priority(Handle stream, std::uint16_t priority) = 0;

    /** @brief Complete exactly the callback-scoped bytes consumed by receive. */
    virtual void stream_receive_complete(Handle stream, std::uint64_t bytes) noexcept = 0;

    /** @brief Abort pending stream I/O. */
    virtual void stream_shutdown(Handle stream, std::uint64_t application_error) noexcept = 0;

    /** @brief Close one stream after abort or connection shutdown. */
    virtual void stream_close(Handle stream) noexcept = 0;

    /**
     * @brief Submit one QUIC DATAGRAM send.
     *
     * Buffer lifetime and send-token rules match stream_send().
     */
    virtual ApiStatus datagram_send(
      Handle connection,
      std::span<const Buffer> buffers,
      std::uint64_t send_token,
      bool urgent,
      bool cancel_on_blocked
    ) = 0;

    /** @brief Query a best-effort congestion snapshot. */
    virtual std::optional<CongestionSample> congestion_sample(Handle connection) noexcept = 0;
  };

  /** @brief Live QUIC identity passed once to the approved session factory. */
  struct ConnectionContext {
    std::uint64_t connection_id {};  ///< Process-local connection ID.
    RemoteSourcePrefix remote_source;  ///< Trusted normalized listener source bucket.
    std::uint16_t local_udp_port {};  ///< The single configured listener port.
    std::uint16_t maximum_datagram_bytes {};  ///< Negotiated DATAGRAM maximum, possibly zero initially.
    Profile profile {Profile::quality};  ///< Explicit queue and pacing policy.
    std::array<std::uint8_t, 32> leaf_spki_sha256 {};  ///< Live configured leaf SPKI pin.
    MonotonicClock::time_point connected_at {};  ///< Monotonic handshake-completion boundary.
  };

  /** @brief Response-owned exact ULB3 transfer released to transport after control enqueue. */
  struct BulkTransfer {
    std::uint64_t request_id {};
    std::uint64_t object_id {};
    std::shared_ptr<const std::vector<std::uint8_t>> bytes;
  };

  /** @brief Independent application-authenticated protocol-v3 session boundary. */
  class ControlSessionV3 {
  public:
    virtual ~ControlSessionV3() = default;

    /**
     * @brief Process one complete exact ULC3 frame and return encoded responses.
     *
     * The frame spans are valid only for this synchronous call and must not be
     * retained. This avoids another full-frame copy in the receive hot path.
     */
    virtual std::vector<std::shared_ptr<const std::vector<std::uint8_t>>> control(
      const ControlFrame &frame
    ) = 0;

    /** @brief Route one validated callback-scoped client-to-host ULM3 record synchronously. */
    virtual void datagram(const DatagramRecord &record) = 0;

    /** @brief Return the active authenticated session ID, when streaming. */
    virtual std::optional<std::array<std::uint8_t, 16>> active_session_id() const noexcept = 0;

    /** @brief Return whether signed application authorization completed. */
    virtual bool authenticated() const noexcept = 0;

    /** @brief Current application-phase idle deadline; zero disables transport idle timeout. */
    virtual std::uint64_t idle_timeout_ms() const noexcept = 0;

    /** @brief Apply the current path's bounded semantic DATAGRAM maximum. */
    virtual void datagram_maximum_changed(std::uint16_t maximum_bytes) = 0;

    /** @brief Drain bulk objects whose matching control responses were already cached. */
    virtual std::vector<BulkTransfer> take_bulk_transfers() = 0;

    /** @brief Notify the v3 state machine that the QUIC connection ended. */
    virtual void disconnect() noexcept = 0;
  };

  /** @brief Construct exactly one independent v3 session per QUIC connection. */
  class SessionFactory {
  public:
    virtual ~SessionFactory() = default;

    /**
     * @brief Construct the connection's sole ControlSession.
     *
     * @param context Live connection context.
     * @return Owned session, or null to reject the connection.
     */
    virtual std::unique_ptr<ControlSessionV3> create(
      const ConnectionContext &context
    ) = 0;
  };

  /** @brief Metadata-only transport event. */
  struct Event {
    enum class Kind {
      listener_started,
      connection_accepted,
      connection_connected,
      datagram_negotiated,
      packet_queued,
      packet_superseded,
      packet_expired,
      packet_backpressured,
      send_submitted,
      send_completed,
      send_canceled,
      parser_drop,
      session_failure,
      api_failure,
      connection_closed,
      listener_stopped,
    };

    Kind kind {Kind::listener_started};  ///< Observable boundary.
    std::uint64_t connection_id {};  ///< Process-local connection ID, or zero.
    std::uint64_t packet_sequence {};  ///< Connection-local packet sequence, or zero.
    Lane lane {Lane::control};  ///< Semantic lane when applicable.
    std::size_t bytes {};  ///< Application bytes, excluding lane tag.
    ParseError parse_error {ParseError::none};  ///< Typed parser diagnostic when applicable.
    ApiStatus api_status {ApiStatus::success};  ///< Typed API diagnostic when applicable.
    MonotonicClock::time_point timestamp {};  ///< Strictly monotonic observer timestamp.
  };

  /** @brief Optional metadata-only transport observer. */
  class Observer {
  public:
    virtual ~Observer() = default;
    virtual void on_event(const Event &event) = 0;
  };

  /** @brief Optional congestion-feedback sink for encoder/packetizer adaptation. */
  class CongestionObserver {
  public:
    virtual ~CongestionObserver() = default;
    virtual void on_congestion_sample(
      std::uint64_t connection_id,
      const CongestionSample &sample,
      MonotonicClock::time_point observed_at
    ) = 0;
  };

  /** @brief Immutable production listener and scheduler policy. */
  struct Config {
    std::uint16_t udp_port {default_udp_port};  ///< Exactly one UDP listener port.
    Profile profile {Profile::quality};  ///< Latency or Quality queue semantics.
    std::shared_ptr<const CertificateCredential> certificate;  ///< Owned Schannel import credential.
    std::size_t maximum_connections {64};  ///< Accepted connection cap (1...64).
    std::size_t maximum_connections_per_source {8};  ///< Normalized source cap (1...8).
    std::size_t maximum_queued_packets {256};  ///< Queue cap (1...4096).
    std::size_t maximum_queued_bytes {32U * 1024U * 1024U};  ///< Queue byte cap.
    std::size_t maximum_in_flight_sends {32};  ///< MsQuic send-context cap (1...256).
    std::size_t urgent_send_reserve {4};  ///< Slots unavailable to video (1...32).
    std::uint64_t video_bitrate_kbps {100'000};  ///< Active negotiated video bitrate.
    std::uint64_t initial_rtt_microseconds {1'000};  ///< Bounded pre-sample LAN RTT estimate.
    std::chrono::milliseconds audio_lifetime {60};  ///< Default audio/mic packet lifetime.
    std::chrono::milliseconds video_lifetime {25};  ///< Default latency delta-video lifetime.
    std::chrono::milliseconds quality_video_lifetime {100};  ///< Finite Quality video age.
    std::chrono::milliseconds handshake_timeout {5'000};  ///< QUIC/TLS handshake deadline.
    std::chrono::milliseconds hello_timeout {5'000};  ///< Handshake-to-CLIENT_HELLO deadline.
  };

  /** @brief Caller-owned immutable application payload and scheduling metadata. */
  struct Packet {
    Lane lane {Lane::control};  ///< Semantic lane.
    std::shared_ptr<const std::vector<std::uint8_t>> bytes;  ///< Stable payload storage.
    MonotonicClock::time_point deadline {};  ///< Explicit expiry; zero selects policy default.
    bool replaceable {};  ///< Permit a newer same-lane packet to supersede this packet in Latency mode.
  };

  /** @brief Lazily materialized header plus retained encoded access-unit slice. */
  struct VideoFragmentView {
    std::size_t header_size {};  ///< Bytes written into the caller's stable header storage.
    const std::uint8_t *payload {};  ///< Borrowed slice retained by the parent frame object.
    std::size_t payload_size {};  ///< Encoded access-unit slice length.
  };

  /**
   * @brief Object-level retained video admission with completion-owned storage.
   *
   * QuicServer retains at most one Latency or two Quality objects. Fragment
   * headers are written only when a MsQuic send slot opens; the encoded bytes
   * remain source slices owned by this object through send completion.
   */
  class LazyVideoFrame {
  public:
    virtual ~LazyVideoFrame() = default;
    virtual std::uint64_t object_id() const noexcept = 0;
    virtual bool independently_decodable() const noexcept = 0;
    virtual bool replaceable() const noexcept = 0;
    virtual MonotonicClock::time_point deadline() const noexcept = 0;
    virtual std::size_t fragment_count() const noexcept = 0;
    virtual std::size_t retained_bytes() const noexcept = 0;
    virtual std::size_t maximum_datagram_bytes() const noexcept = 0;
    virtual bool materialize(
      std::size_t fragment_index,
      std::span<std::uint8_t> header_storage,
      VideoFragmentView &fragment
    ) const noexcept = 0;
    /** @brief Nonblocking, non-reentrant encoder recovery notification. */
    virtual void request_recovery() const noexcept = 0;
  };

  /** @brief Typed enqueue result; no profile silently drops a newly submitted packet. */
  enum class EnqueueResult {
    queued,
    unknown_connection,
    shutting_down,
    invalid_packet,
    datagram_not_negotiated,
    datagram_too_large,
    would_block,
  };

  /**
   * @brief Production one-port QUIC server.
   *
   * This class is owned by ProtocolV3Service and remains wire-isolated from
   * legacy Moonlight listeners. start() and stop() are idempotent; MsQuic
   * dispatches transport callbacks while media producers invoke enqueue().
   */
  class QuicServer {
  public:
    QuicServer(
      MsQuicApi &api,
      Config config,
      SessionFactory &session_factory,
      Observer *observer = nullptr,
      CongestionObserver *congestion_observer = nullptr
    );

    QuicServer(const QuicServer &) = delete;
    QuicServer &operator=(const QuicServer &) = delete;
    QuicServer(QuicServer &&) noexcept = default;
    QuicServer &operator=(QuicServer &&) noexcept = default;
    ~QuicServer();

    /** @brief Open registration/configuration/listener and bind one UDP port. */
    ApiStatus start();

    /** @brief Stop listeners and asynchronously shut down accepted connections. */
    void stop() noexcept;

    /**
     * @brief Queue one packet under the selected Latency or Quality contract.
     *
     * @param connection_id Process-local connection ID.
     * @param packet Immutable packet.
     * @return Exact accepted/backpressured/rejected result.
     */
    EnqueueResult enqueue(std::uint64_t connection_id, Packet packet);

    /** @brief Admit one retained frame object under the 1/2-frame profile bound. */
    EnqueueResult enqueue_video_frame(
      std::uint64_t connection_id,
      std::shared_ptr<const LazyVideoFrame> frame
    );

    /**
     * @brief Install the negotiated media policy for one authenticated connection.
     *
     * Listener configuration is only a pre-START default. Live queue age,
     * supersession, pacing, and video congestion budget use this per-connection
     * selection after START succeeds.
     *
     * @param connection_id Process-local connection ID.
     * @param profile Negotiated LATENCY or QUALITY profile.
     * @param video_bitrate_kbps Selected video bitrate in kilobits per second.
     * @return `true` when the live connection accepted the selection.
     */
    bool set_connection_policy(
      std::uint64_t connection_id,
      Profile profile,
      std::uint64_t video_bitrate_kbps
    ) noexcept;

    /** @brief Revoke one replaced application authority without stopping the listener. */
    bool revoke_connection(std::uint64_t connection_id) noexcept;

    /** @brief Current accepted connection count. */
    std::size_t active_connections() const noexcept;

    /** @brief Current queued packet count across all connections. */
    std::size_t queued_packets() const noexcept;

    /** @brief Whether the listener is accepting. */
    bool running() const noexcept;

    /** @brief Return the live configured leaf DER-SPKI SHA-256 while running. */
    std::optional<std::array<std::uint8_t, 32>> leaf_spki_sha256() const noexcept;

  private:
    struct Impl;
    std::shared_ptr<Impl> impl_;
  };

  /**
   * @brief Create the native MsQuic 2.6 Schannel facade when compiled in.
   *
   * @return Owned facade on an opted-in Windows build; null otherwise.
   */
  std::unique_ptr<MsQuicApi> make_native_msquic_api();
}  // namespace lumen::protocol_v3::quic_server
