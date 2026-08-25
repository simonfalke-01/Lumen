/**
 * @file src/protocol_v3/runtime.h
 * @brief Production persistence and service adapters for Lumen protocol v3.
 */

#pragma once

#include "control_session.h"
#include "media_pipeline.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace rtsp_stream {
  struct launch_session_t;
}

namespace lumen::protocol_v3::runtime {
  namespace control = lumen::protocol_v3::control_session;

  /** @brief Bounded stable-intent cache for idempotent ATTACH responses. */
  class AttachIntentCache {
  public:
    enum class Match {
      missing,
      exact,
      conflict,
    };

    struct Lookup {
      Match match {Match::missing};
      control::cbor::Value::Map response_fields;
    };

    Lookup lookup(
      const control::Identifier &intent_id,
      std::uint64_t last_input_generation,
      const std::array<std::uint64_t, 3> &last_media_generations,
      quic_server::MonotonicClock::time_point now
    );
    bool commit(
      const control::Identifier &intent_id,
      std::uint64_t last_input_generation,
      const std::array<std::uint64_t, 3> &last_media_generations,
      control::cbor::Value::Map response_fields,
      quic_server::MonotonicClock::time_point now
    );
    std::size_t size() const noexcept;

  private:
    struct Entry {
      std::uint64_t last_input_generation {};
      std::array<std::uint64_t, 3> last_media_generations {};
      control::cbor::Value::Map response_fields;
      quic_server::MonotonicClock::time_point expires_at {};
    };

    std::map<control::Identifier, Entry> entries_;
  };

  /** @brief Stored single-use invitation accepted by QR pairing. */
  struct Invitation {
    control::Identifier invitation_id {};  ///< Random invitation identifier.
    control::Bytes32 token {};  ///< Random invitation bearer secret.
    control::Bytes32 invitation_sha256 {};  ///< Digest of the complete invitation bytes.
    std::uint64_t permissions {};  ///< Maximum permission grant carried by this invitation.
    std::uint64_t expires_at_unix_seconds {};  ///< Absolute expiry no later than five minutes after issue.
  };

  /** @brief Public WebUI view of one paired protocol-v3 client. */
  struct AuthorizedClientInfo {
    control::Identifier client_id {};
    std::string display_name;
    std::uint64_t permissions {};
    std::uint64_t generation {};
    bool enabled {true};
  };

  /**
   * @brief Atomic shared-state implementation of the v3 authorization boundary.
   *
   * The adapter stores invitations and paired clients under the existing JSON
   * transaction. The host Ed25519 seed is held by a separate protected,
   * versioned identity store and is never written back to general state JSON.
   */
  class PersistentAuthorizationStore final: public control::AuthorizationStore {
  public:
    using WallClock = std::function<std::uint64_t()>;  ///< Unix-seconds source used for expiry checks.

    /**
     * @brief Open the authorization subtree in a shared Lumen state file.
     *
     * @param state_file Shared JSON state path.
     * @param persistent Whether mutations must be committed to disk.
     * @param wall_clock Optional testable Unix-seconds clock.
     */
    explicit PersistentAuthorizationStore(
      std::string state_file,
      bool persistent = true,
      WallClock wall_clock = {}
    );
    ~PersistentAuthorizationStore() override;

    PersistentAuthorizationStore(const PersistentAuthorizationStore &) = delete;
    PersistentAuthorizationStore &operator=(const PersistentAuthorizationStore &) = delete;

    /** @brief Return whether the persisted subtree loaded without corruption. */
    [[nodiscard]] bool ready() const noexcept;

    /**
     * @brief Load or durably generate the v3 host Ed25519 seed.
     *
     * @param random Cryptographically secure random source.
     * @return Stable nonzero seed or an internal-failure status.
     */
    std::expected<control::Bytes32, std::uint8_t> host_identity_seed(control::Random &random);

    /**
     * @brief Atomically publish one bounded single-use invitation.
     *
     * @param invitation Fully encoded invitation authorization.
     * @return True only after the invitation is available to pairing.
     */
    bool add_invitation(const Invitation &invitation);

    /** @brief Atomically revoke one unconsumed invitation by identifier. */
    bool revoke_invitation(const control::Identifier &invitation_id);

    /** @brief Snapshot paired clients without public keys or invitation secrets. */
    std::vector<AuthorizedClientInfo> clients() const;
    /** @brief Atomically enable or disable one paired client. */
    bool set_client_enabled(const control::Identifier &client_id, bool enabled);
    /** @brief Atomically replace one client's permission mask and generation. */
    bool set_client_permissions(const control::Identifier &client_id, std::uint64_t permissions);
    /** @brief Atomically remove one paired client authorization. */
    bool revoke_client(const control::Identifier &client_id);
    std::optional<control::ClientRecord> paired_client(const control::Identifier &client_id) override;
    std::expected<control::ClientRecord, std::uint8_t> consume_invitation(
      const control::PairingClaim &claim
    ) override;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
  };

  /** @brief Stable application entry exposed by authenticated v3 browsing. */
  struct ApplicationEntry {
    std::uint64_t application_id {};  ///< Stable nonzero configured application ID.
    std::string display_name;  ///< Human-readable application name.
    std::uint64_t state {};  ///< 0 stopped, 1 starting, 2 running, or 3 stopping.
    std::uint64_t flags {};  ///< Protocol-defined application flags.
    std::optional<control::Bytes32> asset_sha256;  ///< Optional whole-image digest.
    std::uint64_t last_changed_revision {};  ///< Snapshot revision at the last visible change.
    std::uint64_t launch_capabilities {};  ///< Launch/resume/desktop/quit capability mask.
  };

  /** @brief Consistent configured-application snapshot. */
  struct ApplicationSnapshot {
    std::uint64_t revision {};  ///< Nonzero snapshot revision.
    std::vector<ApplicationEntry> entries;  ///< Entries sorted by application ID.
  };

  /** @brief One complete bounded application artwork object. */
  struct ApplicationAsset {
    std::uint64_t application_id {};
    control::Bytes32 sha256 {};
    std::string mime;
    std::vector<std::uint8_t> bytes;
  };

  /** @brief Application launch values selected from a valid v3 START. */
  struct ApplicationLaunch {
    std::uint32_t application_id {};  ///< Configured application ID; zero selects desktop.
    std::uint32_t width {};  ///< Selected capture width.
    std::uint32_t height {};  ///< Selected capture height.
    std::uint32_t refresh_numerator {};  ///< Selected rational refresh numerator.
    std::uint32_t refresh_denominator {1};  ///< Selected rational refresh denominator.
    bool host_audio {};  ///< Whether captured audio also remains audible on the host.
    bool enable_hdr {};  ///< Whether the selected video transfer requires HDR capture.
    media::OpusTuple audio;  ///< Exact selected host-audio layout and Opus mapping.
    bool resume {};  ///< Reuse an already running matching application when true.
  };

  /**
   * @brief Convert a validated v3 application selection into Lumen's process-launch shape.
   *
   * @param launch Complete v3 application selection.
   * @return Fully populated legacy-shaped launch state, or protocol status on invalid input.
   */
  [[nodiscard]] std::expected<std::shared_ptr<rtsp_stream::launch_session_t>, std::uint8_t>
    make_legacy_launch_session(const ApplicationLaunch &launch);

  /** @brief Concrete host application boundary used by the production backend. */
  class ApplicationBridge {
  public:
    virtual ~ApplicationBridge() = default;
    virtual std::expected<ApplicationSnapshot, std::uint8_t> snapshot() = 0;
    virtual std::expected<ApplicationAsset, std::uint8_t> asset(
      std::uint64_t application_id,
      const control::Bytes32 &expected_sha256
    ) = 0;
    virtual std::expected<bool, std::uint8_t> start(const ApplicationLaunch &launch) = 0;
    virtual bool stop(bool quit_application) noexcept = 0;
    virtual bool running() noexcept = 0;
  };

  /** @brief Adapter over Lumen's configured process registry. */
  class LumenApplicationBridge final: public ApplicationBridge {
  public:
    std::expected<ApplicationSnapshot, std::uint8_t> snapshot() override;
    std::expected<ApplicationAsset, std::uint8_t> asset(
      std::uint64_t application_id,
      const control::Bytes32 &expected_sha256
    ) override;
    std::expected<bool, std::uint8_t> start(const ApplicationLaunch &launch) override;
    bool stop(bool quit_application) noexcept override;
    bool running() noexcept override;
  };

  /**
   * @brief Revocable, generation-scoped terminal-failure latch for one START transaction.
   *
   * The backend owns the strong dispatcher reference while a START is staging or
   * committed. Native resources receive only a weak reference, so a late report
   * cannot extend or dereference backend lifetime. Reporting is allocation-free
   * and only wakes the backend watchdog; terminal work never runs inline.
   */
  class TerminalFailureDispatcher final {
  public:
    /**
     * @brief Construct one dispatcher bound to a backend watchdog control block.
     *
     * @param generation Nonzero monotonically increasing dispatcher generation.
     * @param watchdog Backend-owned watchdog wakeup control block.
     */
    TerminalFailureDispatcher(
      std::uint64_t generation,
      std::weak_ptr<std::condition_variable_any> watchdog
    ) noexcept;

    /** @brief Latch and enqueue one terminal failure without blocking or allocating. */
    void report() noexcept;
    /** @brief Revoke the dispatcher before resource stop/join begins. */
    void revoke() noexcept;
    /** @brief Return whether a terminal failure was latched for this generation. */
    [[nodiscard]] bool reported() const noexcept;
    /** @brief Return the immutable nonzero dispatcher generation. */
    [[nodiscard]] std::uint64_t generation() const noexcept;

  private:
    std::uint64_t generation_ {};  ///< Immutable backend-issued lifetime generation.
    std::weak_ptr<std::condition_variable_any> watchdog_;  ///< Weak backend watchdog control block.
    std::atomic_bool revoked_ {};  ///< True once backend ownership is withdrawn.
    std::atomic_bool reported_ {};  ///< One-way terminal-failure latch.
  };

  /** @brief START-owned live resources behind the authenticated control backend. */
  class SessionResources {
  public:
    virtual ~SessionResources() = default;
    /** Return the effective immutable media selection after platform resource activation. */
    virtual const media::NegotiatedMediaConfig &effective_media_config() const noexcept = 0;
    virtual std::span<const std::uint8_t> video_codec_initialization() const noexcept = 0;
    /**
     * @brief Replace input state and advance its authenticated authority generation.
     *
     * @param state_block Complete validated input reset state.
     * @param next_generation Nonzero generation committed only when the reset succeeds.
     * @return True when the production input backend accepted the reset.
     */
    virtual bool reset_input(
      std::span<const std::uint8_t> state_block,
      std::uint32_t next_generation
    ) = 0;
    virtual bool apply_text(const control::cbor::Value::Map &request_fields) = 0;
    virtual media::ReceiveResult datagram(const quic_server::DatagramRecord &record) = 0;
    virtual bool start_media() = 0;
    virtual void detach_connection() noexcept = 0;
    virtual bool attach_connection(std::uint64_t connection_id) = 0;
    virtual void stop() noexcept = 0;
  };

  /** @brief Transactional factory for one negotiated media/input resource set. */
  class SessionResourceFactory {
  public:
    virtual ~SessionResourceFactory() = default;
    virtual std::expected<std::unique_ptr<SessionResources>, std::uint8_t> create(
      const media::NegotiatedMediaConfig &config,
      std::uint64_t connection_id,
      std::weak_ptr<TerminalFailureDispatcher> terminal_failure
    ) = 0;
  };

  /** @brief QuicServer adapter shared by every START-owned media pipeline. */
  class QuicTransportSink
#ifndef SUNSHINE_TESTS
    final
#endif
    : public media::TransportSink {
  public:
    /** @brief Attach the fully constructed single listener before accepting START. */
    void attach(
      quic_server::QuicServer &server,
      quic_server::Profile default_profile,
      std::uint64_t default_video_bitrate_kbps
    ) noexcept;
    /** @brief Revoke a replaced connection and all queued transport work. */
    virtual bool revoke(std::uint64_t connection_id) noexcept;
    /** @brief Restore a retained authenticated connection to listener defaults. */
    virtual bool reset_policy(std::uint64_t connection_id) noexcept;
    bool update_policy(
      std::uint64_t connection_id,
      quic_server::Profile profile,
      std::uint64_t video_bitrate_kbps
    ) noexcept override;
    quic_server::EnqueueResult enqueue(
      std::uint64_t connection_id,
      quic_server::Packet packet
    ) override;
    quic_server::EnqueueResult enqueue_video_frame(
      std::uint64_t connection_id,
      std::shared_ptr<const quic_server::LazyVideoFrame> frame
    ) override;

  private:
    quic_server::QuicServer *server_ {};  ///< Sole process listener, borrowed after attach().
    quic_server::Profile default_profile_ {quic_server::Profile::quality};
    std::uint64_t default_video_bitrate_kbps_ {100'000};
  };

  /** @brief Concrete authenticated application/control/session backend. */
  class ProductionSessionBackend final: public control::SessionBackend {
  public:
    ProductionSessionBackend(
      control::Random &random,
      ApplicationBridge &applications,
      SessionResourceFactory &resources,
      QuicTransportSink &transport,
      std::shared_ptr<resource_budget::ResourceBudgetCoordinator> resource_budget =
        std::make_shared<resource_budget::ResourceBudgetCoordinator>()
    );
    ~ProductionSessionBackend() override;

    std::expected<control::StartResult, std::uint8_t> start(
      const control::ClientRecord &client,
      const control::cbor::Value::Map &request_fields,
      std::uint64_t connection_id,
      std::uint16_t maximum_datagram_bytes
    ) override;
    std::expected<control::ControlResult, std::uint8_t> control(
      const control::ClientRecord &client,
      control::AuthenticatedControl request,
      const control::cbor::Value::Map &request_fields,
      std::uint64_t request_id,
      std::uint64_t connection_id,
      std::uint64_t connection_authority_generation
    ) override;
    std::optional<control::Identifier> owned_session(const control::ClientRecord &client) override;
    bool acknowledge_configuration(
      const control::ClientRecord &client,
      control::ConfigurationAcknowledgement acknowledgement,
      const control::Identifier &session_id,
      std::uint32_t generation,
      std::optional<std::uint32_t> decoder_capacity
    ) override;
    bool start_media(const control::ClientRecord &client, const control::Identifier &session_id) override;
    void datagram(const control::ClientRecord &client, const quic_server::DatagramRecord &record) override;
    void revoke_connection(std::uint64_t connection_id) noexcept override;
    void disconnect(
      const std::optional<control::Identifier> &session_id,
      std::uint64_t connection_id
    ) noexcept override;
    /** @brief Terminate and remove any live session owned by a changed client record. */
    void revoke_client(const control::Identifier &client_id) noexcept;
#ifdef SUNSHINE_TESTS
    /**
     * @brief Install one already-constructed session for deterministic lifecycle tests.
     *
     * @param client_id Exact owner client identifier.
     * @param session_id Exact nonzero session identifier.
     * @param connection_id Exact nonzero connection identifier.
     * @param resources Owned session resources used by the production STOP path.
     * @return True when the isolated session was installed.
     */
    bool install_session_for_test(
      const control::Identifier &client_id,
      const control::Identifier &session_id,
      std::uint64_t connection_id,
      std::unique_ptr<SessionResources> resources
    );

    /**
     * @brief Route a deterministic test failure through the production terminal callback path.
     *
     * @param session_id Exact session identifier to mark failed.
     */
    void mark_failed_for_test(const control::Identifier &session_id) noexcept;
    /** @brief Inject one post-application, pre-commit resource failure. */
    void fail_next_start_before_commit_for_test() noexcept;
#endif

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
  };

  /** @brief Immutable product construction values for the one v3 listener. */
  struct ServiceConfig {
    std::string state_file;  ///< Shared Lumen JSON state file.
    std::string certificate_file;  ///< PEM certificate path.
    std::string private_key_file;  ///< Matching PEM private-key path.
    std::uint16_t udp_port {quic_server::default_udp_port};  ///< Single QUIC UDP listener port.
    quic_server::Profile profile {quic_server::Profile::quality};  ///< Default connection scheduler policy.
    bool persistent_authorization {true};  ///< False only for explicit fresh-state operation.
    std::uint64_t pairing_permissions {0x17};  ///< Host-approved QR permission ceiling.
  };

  /** @brief Owning production construction and lifecycle for protocol v3. */
  class ProtocolV3Service {
  public:
    using ResourceFactoryBuilder = std::function<std::unique_ptr<SessionResourceFactory>(media::TransportSink &)>;  ///< Native factory constructor.

    /**
     * @brief Construct a stopped service around the mandatory native resource-factory builder.
     *
     * @param builder Builder that binds live capture/audio/input/microphone resources to QUIC.
     */
    explicit ProtocolV3Service(ResourceFactoryBuilder builder);
    ~ProtocolV3Service();

    ProtocolV3Service(const ProtocolV3Service &) = delete;
    ProtocolV3Service &operator=(const ProtocolV3Service &) = delete;

    /** @brief Load credentials/state and bind the one protocol-v3 listener. */
    quic_server::ApiStatus start(const ServiceConfig &config);
    /** @brief Stop accepting and tear down every active v3 session. */
    void stop() noexcept;
    /** @brief Return whether the QUIC listener is accepting connections. */
    [[nodiscard]] bool running() const noexcept;
    /** @brief Return the last synchronous QUIC listener startup stage attempted. */
    [[nodiscard]] quic_server::StartupStage startup_stage() const noexcept;

    /** @brief Issue and persist one exact ULI3 QR invitation URI. */
    std::expected<std::string, std::uint8_t> issue_invitation(
      std::string hostname,
      bool hostname_is_ip,
      std::uint64_t permissions
    );
    /** @brief Return the current unexpired process-memory invitation URI. */
    std::optional<std::string> current_invitation() const;
    /** @brief Revoke the current invitation when its public identifier matches. */
    bool revoke_invitation(const control::Identifier &invitation_id);
    /** @brief Revoke whichever unconsumed invitation is currently displayed. */
    bool revoke_current_invitation();
    /** @brief List paired protocol-v3 clients for authenticated administration. */
    std::vector<AuthorizedClientInfo> clients() const;
    /** @brief Enable/disable one client and terminate its live authority. */
    bool set_client_enabled(const control::Identifier &client_id, bool enabled);
    /** @brief Replace permissions and terminate the client's live authority. */
    bool set_client_permissions(const control::Identifier &client_id, std::uint64_t permissions);
    /** @brief Revoke one paired client and terminate its live authority. */
    bool revoke_client(const control::Identifier &client_id);
    /** @brief Return the configured QR permission ceiling. */
    std::uint64_t pairing_permissions() const noexcept;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
  };

  /** @brief Issue through the currently running process service. */
  std::expected<std::string, std::uint8_t> issue_active_invitation(
    std::string hostname,
    bool hostname_is_ip,
    std::uint64_t permissions
  );
  /** @brief Read the current active invitation without logging or persistence. */
  std::optional<std::string> current_active_invitation();
  /** @brief Revoke an invitation through the currently running process service. */
  bool revoke_active_invitation(const control::Identifier &invitation_id);
  /** @brief Revoke the current active invitation through the running service. */
  bool revoke_current_active_invitation();
  /** @brief List paired clients through the running service. */
  std::vector<AuthorizedClientInfo> active_clients();
  /** @brief Enable/disable a paired client through the running service. */
  bool set_active_client_enabled(const control::Identifier &client_id, bool enabled);
  /** @brief Change paired-client permissions through the running service. */
  bool set_active_client_permissions(const control::Identifier &client_id, std::uint64_t permissions);
  /** @brief Revoke a paired client through the running service. */
  bool revoke_active_client(const control::Identifier &client_id);
  /** @brief Return the running service's QR permission ceiling. */
  std::uint64_t active_pairing_permissions();
}  // namespace lumen::protocol_v3::runtime
