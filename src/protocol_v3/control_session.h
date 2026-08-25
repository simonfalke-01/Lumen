/**
 * @file src/protocol_v3/control_session.h
 * @brief Authenticated protocol-v3 HELLO, pairing, authorization, and START state machine.
 */

#pragma once

#include "quic_server.h"

#include "../protocol_common/cbor.h"
#include "../protocol_common/secure_buffer.h"

#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace lumen::protocol_v3::control_session {
  namespace cbor = lumen::protocol_common::cbor;
  using Identifier = std::array<std::uint8_t, 16>;  ///< Protocol-v3 opaque identifier.
  using Bytes32 = std::array<std::uint8_t, 32>;  ///< Nonce, hash, public key, or secret.
  using Signature = std::array<std::uint8_t, 64>;  ///< Ed25519 signature.

  /**
   * @brief Host-wide bounded cache for byte-identical same-connection responses.
   *
   * Reservations are acquired before request side effects. Completed entries
   * expire after exactly 120 seconds, local pressure retires the oldest entry
   * at 128 entries or 1 MiB, and host pressure retires the globally oldest
   * entry at 8 MiB. Retired request IDs are never admitted again.
   */
  class ResponseCacheCoordinator {
  private:
    struct SharedState;

  public:
    static constexpr auto ttl = std::chrono::seconds {120};
    static constexpr std::size_t maximum_entries_per_connection = 128;
    static constexpr std::size_t maximum_bytes_per_connection = 1U * 1024U * 1024U;
    static constexpr std::size_t maximum_bytes_host = 8U * 1024U * 1024U;
    static constexpr std::size_t fixed_entry_charge = 256;

    enum class Decision {
      reserved,
      replay,
      in_progress,
      request_id_conflict,
      retired,
      resource_limit,
    };

    class Reservation {
    public:
      Reservation() = default;
      ~Reservation();
      Reservation(const Reservation &) = delete;
      Reservation &operator=(const Reservation &) = delete;
      Reservation(Reservation &&other) noexcept;
      Reservation &operator=(Reservation &&other) noexcept;
      [[nodiscard]] explicit operator bool() const noexcept;

    private:
      friend class ResponseCacheCoordinator;
      Reservation(
        std::shared_ptr<SharedState> state,
        std::uint64_t connection_id,
        std::uint64_t generation
      ) noexcept;
      void cancel() noexcept;

      std::shared_ptr<SharedState> state_;
      std::uint64_t connection_id_ {};
      std::uint64_t generation_ {};
    };

    struct Admission {
      Decision decision {Decision::resource_limit};
      std::shared_ptr<const std::vector<std::uint8_t>> replay;
      std::optional<Reservation> reservation;
    };

    explicit ResponseCacheCoordinator(
      std::shared_ptr<resource_budget::ResourceBudgetCoordinator> resource_budget =
        std::make_shared<resource_budget::ResourceBudgetCoordinator>()
    );
    ~ResponseCacheCoordinator();
    ResponseCacheCoordinator(const ResponseCacheCoordinator &) = delete;
    ResponseCacheCoordinator &operator=(const ResponseCacheCoordinator &) = delete;

    Admission reserve(
      std::uint64_t connection_id,
      std::uint64_t request_id,
      std::span<const std::uint8_t> request,
      std::size_t worst_case_response_bytes,
      quic_server::MonotonicClock::time_point now
    );
    bool commit(
      Reservation &&reservation,
      std::shared_ptr<const std::vector<std::uint8_t>> response,
      quic_server::MonotonicClock::time_point now
    );
    void cancel(Reservation &&reservation) noexcept;
    void disconnect(std::uint64_t connection_id) noexcept;

  private:
    std::shared_ptr<SharedState> state_;
  };

  /** @brief Typed cache admission signal mapped to 0x107/0x108 by the transport lane. */
  class ResponseCacheError final: public std::runtime_error {
  public:
    enum class Kind {
      resource_limit,
      request_id_conflict,
    };

    explicit ResponseCacheError(const Kind kind):
        std::runtime_error {
          kind == Kind::request_id_conflict ? "v3 request id conflict" : "v3 response cache resource limit"
        },
        kind_ {kind} {
    }

    [[nodiscard]] Kind kind() const noexcept { return kind_; }

  private:
    Kind kind_;
  };

  inline constexpr std::uint64_t browse_permission = 1U << 0;  ///< Browse applications.
  inline constexpr std::uint64_t start_permission = 1U << 1;  ///< Start a stream.
  inline constexpr std::uint64_t input_permission = 1U << 2;  ///< Send input.
  inline constexpr std::uint64_t microphone_permission = 1U << 3;  ///< Send microphone media.
  inline constexpr std::uint64_t stop_permission = 1U << 4;  ///< Stop an owned stream.
  inline constexpr std::uint64_t application_quit_permission = 1U << 5;  ///< Quit the streamed application.
  inline constexpr std::uint64_t defined_permission_mask =
    browse_permission | start_permission | input_permission | microphone_permission |
    stop_permission | application_quit_permission;  ///< All allocated permissions; bits 6/7 are undefined.

  /** @brief Cryptographically secure random-byte source. */
  class Random {
  public:
    virtual ~Random() = default;
    virtual bool fill(std::span<std::uint8_t> output) noexcept = 0;
  };

  /** @brief Persistent host application identity and Ed25519 signer. */
  class HostIdentity {
  public:
    virtual ~HostIdentity() = default;
    virtual Identifier host_id() const noexcept = 0;
    virtual Bytes32 public_key() const noexcept = 0;
    virtual std::optional<Signature> sign(std::span<const std::uint8_t> message) noexcept = 0;
  };

  /** @brief Stored authorization for one paired client. */
  struct ClientRecord {
    Identifier client_id {};
    Bytes32 public_key {};
    std::uint64_t permissions {};
    std::uint64_t generation {};
  };

  /** @brief Fully validated QR-pairing claim before atomic persistence. */
  struct PairingClaim {
    Identifier invitation_id {};
    Bytes32 invitation_token {};
    Bytes32 invitation_sha256 {};
    Identifier pair_attempt_id {};
    Identifier client_id {};
    Bytes32 client_public_key {};
    std::string display_name;
    std::uint64_t requested_permissions {};  ///< Exact signed client request mask.
    std::uint64_t approved_permissions {};  ///< Host policy intersection eligible for persistence.
  };

  /** @brief Invitation and paired-client authorization persistence. */
  class AuthorizationStore {
  public:
    virtual ~AuthorizationStore() = default;
    virtual std::optional<ClientRecord> paired_client(const Identifier &client_id) = 0;
    virtual std::expected<ClientRecord, std::uint8_t> consume_invitation(const PairingClaim &claim) = 0;
  };

  /** @brief Bounded cross-connection nonce replay registry. */
  class NonceRegistry {
  public:
    virtual ~NonceRegistry() = default;
    virtual bool claim(
      const quic_server::RemoteSourcePrefix &source,
      const Identifier &attempt_id,
      const Bytes32 &nonce,
      quic_server::MonotonicClock::time_point now
    ) noexcept = 0;
  };

  /** @brief Cheap HELLO/pairing limiter keyed by trusted source prefix. */
  class PairingAdmission {
  public:
    virtual ~PairingAdmission() = default;
    virtual bool admit_hello(
      const quic_server::RemoteSourcePrefix &source,
      const Identifier &attempt_id,
      quic_server::MonotonicClock::time_point now
    ) noexcept = 0;
    virtual bool admit(
      const quic_server::RemoteSourcePrefix &source,
      const Identifier &invitation_id,
      quic_server::MonotonicClock::time_point now
    ) noexcept = 0;
  };

  /** @brief Host-wide current connection authority for each paired client. */
  struct AuthorityClaim {
    std::uint64_t generation {};
    std::optional<std::uint64_t> replaced_connection_id;
  };

  /** @brief Generation-bound authority held across one backend operation. */
  class ConnectionAuthorityLease {
  public:
    virtual ~ConnectionAuthorityLease() = default;
  };

  /** @brief Host-wide current connection authority for each paired client. */
  class ConnectionAuthorityRegistry {
  public:
    virtual ~ConnectionAuthorityRegistry() = default;
    virtual std::optional<AuthorityClaim> claim(
      const Identifier &client_id,
      std::uint64_t connection_id,
      bool replace_existing
    ) noexcept = 0;
    virtual bool current(
      const Identifier &client_id,
      std::uint64_t connection_id,
      std::uint64_t generation
    ) noexcept = 0;
    virtual std::unique_ptr<ConnectionAuthorityLease> lease(
      const Identifier &client_id,
      std::uint64_t connection_id,
      std::uint64_t generation
    ) noexcept = 0;
    virtual void release(
      const Identifier &client_id,
      std::uint64_t connection_id,
      std::uint64_t generation
    ) noexcept = 0;
    virtual std::vector<std::uint64_t> revoke_client(const Identifier &client_id) noexcept = 0;
  };

  /** @brief One reliable host request emitted immediately after START_RESPONSE. */
  struct HostControlRequest {
    std::uint16_t message_type {};  ///< Even-ID request type such as VIDEO_CONFIG.
    cbor::Value::Map request_fields;  ///< Exact deterministic request map.
  };

  /** @brief One request-ID-zero control event emitted after its initiating response. */
  struct HostControlEvent {
    std::uint16_t message_type {};  ///< Event type such as SESSION_ENDED.
    cbor::Value::Map fields;  ///< Exact deterministic event map.
  };

  /** @brief Successful concrete media/application START reservation. */
  struct StartResult {
    Identifier session_id {};
    cbor::Value::Map response_fields;  ///< Exact response fields 2...23; status is added by control.
    std::vector<HostControlRequest> host_requests;  ///< Required configuration requests sent after START_RESPONSE.
    bool replay_requires_attach {};  ///< Exact prior outcome returned without rebinding authority.
  };

  /** @brief Allocated authenticated client control operations routed after authorization. */
  enum class AuthenticatedControl : std::uint16_t {
    ping = 0x0005,
    session_attach = 0x0102,
    input_reset = 0x0120,
    text_composition = 0x0122,
    stop = 0x0130,
    application_list = 0x0200,
    application_asset = 0x0202,
  };

  /** @brief Client acknowledgement of one reliable host configuration request. */
  enum class ConfigurationAcknowledgement : std::uint16_t {
    video = 0x0141,
    audio = 0x0143,
    microphone = 0x0145,
  };

  /** @brief Typed backend response for one authenticated control operation. */
  struct ControlResult {
    AuthenticatedControl request {AuthenticatedControl::ping};
    cbor::Value::Map response_fields;
    std::optional<quic_server::BulkTransfer> bulk_transfer;
    std::vector<HostControlEvent> post_response_events;  ///< Request-ID-zero events emitted after the response.
  };

  /** @brief Production application/media boundary behind authenticated START and DATAGRAM. */
  class SessionBackend {
  public:
    virtual ~SessionBackend() = default;
    virtual std::expected<StartResult, std::uint8_t> start(
      const ClientRecord &client,
      const cbor::Value::Map &request_fields,
      std::uint64_t connection_id,
      std::uint16_t maximum_datagram_bytes
    ) = 0;
    virtual std::expected<ControlResult, std::uint8_t> control(
      const ClientRecord &client,
      AuthenticatedControl request,
      const cbor::Value::Map &request_fields,
      std::uint64_t request_id,
      std::uint64_t connection_id,
      std::uint64_t connection_authority_generation
    ) = 0;
    virtual std::optional<Identifier> owned_session(const ClientRecord &client) = 0;
    virtual bool acknowledge_configuration(
      const ClientRecord &client,
      ConfigurationAcknowledgement acknowledgement,
      const Identifier &session_id,
      std::uint32_t generation,
      std::optional<std::uint32_t> decoder_capacity
    ) = 0;
    virtual bool start_media(const ClientRecord &client, const Identifier &session_id) = 0;
    virtual void datagram(const ClientRecord &client, const quic_server::DatagramRecord &record) = 0;
    virtual void revoke_connection(std::uint64_t connection_id) noexcept = 0;
    virtual void disconnect(
      const std::optional<Identifier> &session_id,
      std::uint64_t connection_id
    ) noexcept = 0;
  };

  /** @brief Immutable factory policy shared by all v3 connections. */
  struct Config {
    std::uint64_t capabilities {0x37f};  ///< Advertised protocol-v3 capabilities, including compact input state.
    std::uint64_t default_pairing_permissions {0x17};  ///< Host-approved QR grants.
    std::shared_ptr<resource_budget::ResourceBudgetCoordinator> resource_budget {
      std::make_shared<resource_budget::ResourceBudgetCoordinator>()
    };  ///< Shared host-wide accounting used by control and transport.
    std::shared_ptr<ResponseCacheCoordinator> response_cache {
      std::make_shared<ResponseCacheCoordinator>(resource_budget)
    };  ///< Shared by every connection created from one factory.
    std::chrono::milliseconds server_hello_timeout {2'000};  ///< CLIENT_HELLO-to-SERVER_HELLO bound.
    std::chrono::milliseconds authorization_request_timeout {3'000};  ///< SERVER_HELLO-to-pair/auth bound.
    std::chrono::milliseconds signed_response_timeout {2'000};  ///< Pair/auth signed-response bound.
    std::chrono::milliseconds start_response_timeout {10'000};  ///< START terminal-response bound.
    std::chrono::milliseconds attach_response_timeout {3'000};  ///< ATTACH response bound.
    std::chrono::milliseconds configuration_ack_timeout {3'000};  ///< Host-config acknowledgement bound.
    std::chrono::milliseconds stop_response_timeout {2'000};  ///< STOP response bound.
    std::chrono::milliseconds teardown_timeout {5'000};  ///< Complete session teardown bound.
    std::chrono::milliseconds authenticated_idle_timeout {120'000};  ///< Nonzero authenticated idle bound.
  };

  /** @brief Concrete authenticated protocol-v3 control session. */
  class ControlSession final: public quic_server::ControlSessionV3 {
  public:
    ControlSession(
      quic_server::ConnectionContext connection,
      Config config,
      Random &random,
      HostIdentity &identity,
      AuthorizationStore &authorization,
      NonceRegistry &nonces,
      PairingAdmission &pairing_admission,
      ConnectionAuthorityRegistry &authorities,
      SessionBackend &backend
    );
    ~ControlSession() override;

    std::vector<std::shared_ptr<const std::vector<std::uint8_t>>> control(
      const quic_server::ControlFrame &frame
    ) override;
    quic_server::MonotonicClock::time_point begin_control(
      const quic_server::ControlFrame &frame
    ) noexcept override;
    quic_server::MonotonicClock::time_point application_deadline() const noexcept override;
    void datagram(const quic_server::DatagramRecord &record) override;
    std::optional<Identifier> active_session_id() const noexcept override;
    bool authenticated() const noexcept override;
    std::vector<quic_server::BulkTransfer> take_bulk_transfers() override;
    std::uint64_t idle_timeout_ms() const noexcept override;
    void datagram_maximum_changed(std::uint16_t maximum_bytes) override;
    void disconnect() noexcept override;
#ifdef SUNSHINE_TESTS
    /**
     * @brief Install one authorized client at the real post-authentication boundary for wire tests.
     * @param client Exact paired client record with START permission.
     * @return True when a connection-authority generation was claimed and the session entered ready state.
     */
    bool install_authenticated_client_for_test(const ClientRecord &client) noexcept;
#endif

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
  };

  /** @brief Concrete QuicServer factory producing the authenticated v3 session above. */
  class SessionFactory final: public quic_server::SessionFactory {
  public:
    SessionFactory(
      Config config,
      Random &random,
      HostIdentity &identity,
      AuthorizationStore &authorization,
      NonceRegistry &nonces,
      PairingAdmission &pairing_admission,
      ConnectionAuthorityRegistry &authorities,
      SessionBackend &backend
    );

    std::unique_ptr<quic_server::ControlSessionV3> create(
      const quic_server::ConnectionContext &connection
    ) override;

  private:
    Config config_;
    Random &random_;
    HostIdentity &identity_;
    AuthorizationStore &authorization_;
    NonceRegistry &nonces_;
    PairingAdmission &pairing_admission_;
    ConnectionAuthorityRegistry &authorities_;
    SessionBackend &backend_;
  };

  /** @brief OpenSSL-backed production random source. */
  class SecureRandom final: public Random {
  public:
    bool fill(std::span<std::uint8_t> output) noexcept override;
  };

  /** @brief In-memory host Ed25519 identity backed by a caller-persisted seed. */
  class SeedHostIdentity final: public HostIdentity {
  public:
    explicit SeedHostIdentity(Bytes32 private_seed);
    ~SeedHostIdentity() override;
    Identifier host_id() const noexcept override;
    Bytes32 public_key() const noexcept override;
    std::optional<Signature> sign(std::span<const std::uint8_t> message) noexcept override;
  private:
    protocol_common::SecureArray<32> private_seed_;
    Bytes32 public_key_ {};
    Identifier host_id_ {};
  };

  /** @brief Bounded ten-minute replay registry for hello nonces. */
  class BoundedNonceRegistry final: public NonceRegistry {
  public:
    BoundedNonceRegistry();
    ~BoundedNonceRegistry() override;
    bool claim(
      const quic_server::RemoteSourcePrefix &source,
      const Identifier &attempt_id,
      const Bytes32 &nonce,
      quic_server::MonotonicClock::time_point now
    ) noexcept override;
  private:
    struct Entry;
    std::mutex mutex_;
    std::vector<Entry> entries_;
  };

  /** @brief Per-source 32/s pre-signature pairing limiter with bounded state. */
  class BoundedPairingAdmission final: public PairingAdmission {
  public:
    BoundedPairingAdmission();
    ~BoundedPairingAdmission() override;
    bool admit_hello(
      const quic_server::RemoteSourcePrefix &source,
      const Identifier &attempt_id,
      quic_server::MonotonicClock::time_point now
    ) noexcept override;
    bool admit(
      const quic_server::RemoteSourcePrefix &source,
      const Identifier &invitation_id,
      quic_server::MonotonicClock::time_point now
    ) noexcept override;
  private:
    struct Entry;
    std::mutex mutex_;
    std::vector<Entry> entries_;
  };

  /** @brief Mutex-serialized connection-authority generations and replacements. */
  class ConnectionAuthorities final: public ConnectionAuthorityRegistry {
  public:
    ConnectionAuthorities();
    ~ConnectionAuthorities() override;
    std::optional<AuthorityClaim> claim(
      const Identifier &client_id,
      std::uint64_t connection_id,
      bool replace_existing
    ) noexcept override;
    bool current(
      const Identifier &client_id,
      std::uint64_t connection_id,
      std::uint64_t generation
    ) noexcept override;
    std::unique_ptr<ConnectionAuthorityLease> lease(
      const Identifier &client_id,
      std::uint64_t connection_id,
      std::uint64_t generation
    ) noexcept override;
    void release(
      const Identifier &client_id,
      std::uint64_t connection_id,
      std::uint64_t generation
    ) noexcept override;
    std::vector<std::uint64_t> revoke_client(const Identifier &client_id) noexcept override;
  private:
    struct Entry;
    struct Lease;
    void release_lease(
      const Identifier &client_id,
      std::uint64_t connection_id,
      std::uint64_t generation
    ) noexcept;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::vector<Entry> entries_;
    std::uint64_t next_generation_ {1};
  };
}  // namespace lumen::protocol_v3::control_session
