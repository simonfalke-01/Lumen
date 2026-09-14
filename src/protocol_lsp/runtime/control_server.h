/**
 * @file src/protocol_lsp/runtime/control_server.h
 * @brief Authenticated deterministic-CBOR LSPC host control vertical slice.
 */

#pragma once

#include "../security/secure_zero.h"
#include "control/wire.h"
#include "identity.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace lumen::lsp::runtime {
  /** @brief Maximum path-safe DTLS application record used by initial LSP control. */
  inline constexpr std::size_t maximum_control_frame_bytes = 1'200;

  /** @brief Dedicated TLS pairing-exporter width bound into every PIN pairing transcript. */
  inline constexpr std::size_t pairing_dtls_exporter_size = 32;

  /** @brief Dedicated label-separated exporter retained only for an association's pairing state. */
  using PairingDtlsExporter = std::array<std::uint8_t, pairing_dtls_exporter_size>;

  /**
   * @brief Select the nonzero semantic generation used to cache one control response.
   *
   * CLIENT_HELLO is the sole request whose wire generation is zero. Its response is scoped to the
   * host-assigned association generation so duplicate first requests remain idempotent without
   * weakening the response cache's nonzero-generation invariant.
   *
   * @param message_type Request control-message type.
   * @param wire_generation Generation carried by the request header.
   * @param association_generation Nonzero generation assigned to the DTLS association.
   * @return Association generation for CLIENT_HELLO; otherwise the wire generation.
   */
  [[nodiscard]] constexpr std::uint32_t response_cache_generation(
    const std::uint16_t message_type,
    const std::uint32_t wire_generation,
    const std::uint32_t association_generation
  ) noexcept {
    return message_type == static_cast<std::uint16_t>(ControlMessageType::client_hello) ?
             association_generation :
             wire_generation;
  }

  /**
   * @brief Persisted LSP trusted-client record.
   */
  struct TrustedClient {
    Identifier128 client_id {};  ///< Stable random client identifier.
    PublicKey256 identity_key {};  ///< Ed25519 application identity public key.
    PermissionSet permissions {};  ///< Effective LSP permissions.
    std::uint32_t revocation_generation {1};  ///< Nonzero trust generation.
    bool enabled {true};  ///< Whether new authentication is allowed.

    /** @brief Return whether every trust field is valid. */
    [[nodiscard]] bool valid() const noexcept;
  };

  /** @brief Atomic persistent pairing insertion outcome. */
  enum class TrustInsertResult : std::uint8_t {
    inserted,  ///< New client identity was persisted.
    identical,  ///< The same client ID/key already exists and was not modified.
    conflict,  ///< Client ID already belongs to a different identity key.
    failure,  ///< Persistence or stored-record validation failed.
  };

  /**
   * @brief Trusted-client persistence boundary.
   */
  class ControlTrustStore {
  public:
    virtual ~ControlTrustStore() = default;

    /**
     * @brief Find one enabled trusted client.
     *
     * @param client_id Stable client identifier.
     * @return Trusted record or no value.
     */
    [[nodiscard]] virtual std::optional<TrustedClient> find(
      const Identifier128 &client_id
    ) noexcept = 0;

    /**
     * @brief Atomically insert or replace one trusted client.
     *
     * @param client Valid trusted record.
     * @return True only after persistence succeeds.
     */
    virtual bool upsert(const TrustedClient &client) noexcept = 0;

    /**
     * @brief Atomically insert new trust without overwriting any existing client.
     *
     * @param client Proposed initial trust record.
     * @param effective Persisted record on inserted or identical success.
     * @return Exact insertion outcome.
     */
    virtual TrustInsertResult insert_if_absent(
      const TrustedClient &client,
      TrustedClient &effective
    ) noexcept = 0;

    /** @brief Atomically update an existing client's permissions/enabled state and advance revocation. */
    virtual bool update_existing(
      const Identifier128 &client_id,
      PermissionSet permissions,
      bool enabled
    ) noexcept = 0;

    /** @brief Atomically remove one existing client record. */
    virtual bool revoke_existing(const Identifier128 &client_id) noexcept = 0;
  };

  /**
   * @brief Application listing boundary kept off the packet parser.
   */
  class ControlApplicationProvider {
  public:
    /** @brief One bounded artwork object referenced by an APPLICATIONS image-path field. */
    struct ArtworkObject {
      Identifier128 object_id {};  ///< Object identity encoded in the application reference.
      Digest256 sha256 {};  ///< Complete artwork commitment.
      std::vector<std::uint8_t> bytes;  ///< Complete artwork bytes, at most 16 MiB.
    };

    virtual ~ControlApplicationProvider() = default;

    /**
     * @brief Snapshot configured applications.
     *
     * @return Complete current snapshot, or no value on a product-state failure.
     */
    [[nodiscard]] virtual std::optional<std::vector<ControlApplication>> snapshot() noexcept = 0;

    /** @brief Return artwork objects frozen by the most recent successful snapshot. */
    [[nodiscard]] virtual std::optional<std::vector<ArtworkObject>> artwork_snapshot() noexcept {
      return std::vector<ArtworkObject> {};
    }
  };

  /** @brief Product authority boundary for START, ATTACH, input, video, audio, and microphone. */
  class ControlStartHandler {
  public:
    virtual ~ControlStartHandler() = default;

    /**
     * @brief Commit one authenticated input, audio, and optional-microphone START.
     *
     * @param peer Exact authenticated association.
     * @param client Authenticated trusted-client record.
     * @param connection_generation Current connection generation.
     * @param request Exact decoded START offer.
     * @return Selected response or a stable failure status.
     */
    [[nodiscard]] virtual std::expected<StartResponsePayload, ControlStatus> start_input(
      const PeerEndpoint &peer,
      const TrustedClient &client,
      std::uint32_t connection_generation,
      const StartRequestPayload &request
    ) noexcept = 0;

    /**
     * @brief Stop the authenticated client's exact session.
     *
     * @param client Authenticated trusted client.
     * @param connection_generation Current connection generation.
     * @param request Exact STOP request.
     * @return Stable terminal status.
     */
    virtual ControlStatus stop_input(
      const TrustedClient &client,
      std::uint32_t connection_generation,
      const StopRequestPayload &request
    ) noexcept = 0;

    /** @brief Terminate only the application owned by the authenticated session. */
    virtual ControlStatus quit_application(
      const TrustedClient &client,
      std::uint32_t connection_generation,
      const QuitApplicationPayload &request
    ) noexcept = 0;

    /** @brief Inject one validated UTF-8 commit after its input edge barrier. */
    virtual ControlStatus text_input(
      const PeerEndpoint &peer,
      const TrustedClient &client,
      std::uint32_t connection_generation,
      const TextInputPayload &request,
      std::span<const std::uint8_t> utf8,
      std::uint64_t deadline_microseconds
    ) noexcept = 0;

    /** @brief Select hot-plugged device rates within the current input budget. */
    [[nodiscard]] virtual std::expected<InputRateResponsePayload, ControlStatus> input_rate(
      const PeerEndpoint &peer,
      const TrustedClient &client,
      std::uint32_t connection_generation,
      const InputRateRequestPayload &request
    ) noexcept = 0;

    /**
     * @brief Transfer an existing session to this fresh authenticated connection.
     *
     * @param peer Fresh DTLS association.
     * @param client Authenticated original owner.
     * @param connection_generation Fresh connection generation.
     * @param request Exact ATTACH request.
     * @return Rotated session authority or stable failure.
     */
    [[nodiscard]] virtual std::expected<AttachResponsePayload, ControlStatus> attach_input(
      const PeerEndpoint &peer,
      const TrustedClient &client,
      std::uint32_t connection_generation,
      const AttachRequestPayload &request
    ) noexcept = 0;

    /**
     * @brief Copy the exact VIDEO_CONFIG prepared by the latest successful START or ATTACH.
     *
     * @param session_id Active session identifier.
     * @param video_generation Exact selected video generation.
     * @return Borrowed complete configuration, or null when authority changed.
     */
    [[nodiscard]] virtual const VideoConfigPayload *video_configuration(
      const Identifier128 &session_id,
      std::uint32_t video_generation
    ) noexcept = 0;

    /**
     * @brief Commit one authenticated VIDEO_CONFIG_ACK idempotently.
     *
     * @param peer Exact authenticated association.
     * @param client Authenticated stream owner.
     * @param connection_generation Current connection generation.
     * @param acknowledgement Exact decoded video acknowledgement.
     * @return True when the acknowledgement matches current or already committed video state.
     */
    virtual bool video_config_acknowledged(
      const PeerEndpoint &peer,
      const TrustedClient &client,
      std::uint32_t connection_generation,
      const VideoConfigAckPayload &acknowledgement
    ) noexcept = 0;

    /**
     * @brief Commit one authenticated AUDIO_CONFIG_ACK idempotently.
     *
     * @param peer Exact authenticated association.
     * @param client Authenticated stream owner.
     * @param connection_generation Current connection generation.
     * @param acknowledgement Exact decoded audio acknowledgement.
     * @return True when the acknowledgement matches current or already committed audio state.
     */
    virtual bool audio_config_acknowledged(
      const PeerEndpoint &peer,
      const TrustedClient &client,
      std::uint32_t connection_generation,
      const AudioConfigAckPayload &acknowledgement
    ) noexcept = 0;

    /**
     * @brief Commit one authenticated MICROPHONE_CONFIG_ACK idempotently.
     *
     * @param peer Exact authenticated association.
     * @param client Authenticated stream owner.
     * @param connection_generation Current connection generation.
     * @param acknowledgement Exact decoded microphone acknowledgement.
     * @return True when the acknowledgement matches current or already committed state.
     */
    virtual bool microphone_config_acknowledged(
      const PeerEndpoint &peer,
      const TrustedClient &client,
      std::uint32_t connection_generation,
      const MicrophoneConfigAckPayload &acknowledgement
    ) noexcept = 0;

    /** @brief Emit the protected exact-size SRTCP probe after peer LSPC intent acknowledgement. */
    virtual bool path_probe_intent_acknowledged(
      const PeerEndpoint &peer,
      const PathProbePayload &probe,
      std::uint64_t now_microseconds
    ) noexcept = 0;

    /** @brief Install one authenticated peer-initiated reverse path-probe intent. */
    virtual bool path_probe_requested(
      const PeerEndpoint &peer,
      const PathProbePayload &probe,
      std::uint64_t deadline_microseconds
    ) noexcept = 0;

    /** @brief Commit one authenticated PATH_PROBE_ACK for the host's outstanding probe. */
    virtual bool path_probe_acknowledged(
      const PeerEndpoint &peer,
      const PathProbePayload &probe
    ) noexcept = 0;

    /** @brief Retire one peer-rejected host probe without closing the association. */
    virtual bool path_probe_rejected(
      const PeerEndpoint &peer,
      const PathProbePayload &probe,
      ControlStatus status
    ) noexcept = 0;
  };

  /**
   * @brief wolfCrypt-compatible randomness and Ed25519 application-auth boundary.
   */
  class ControlCrypto {
  public:
    virtual ~ControlCrypto() = default;

    /**
     * @brief Fill a complete caller-owned random byte span.
     *
     * @param output Destination bytes.
     * @return True only when every byte was generated securely.
     */
    virtual bool random(std::span<std::uint8_t> output) noexcept = 0;

    /**
     * @brief Hash one bounded secret-verifier transcript with SHA-256.
     *
     * @param input Complete verifier input.
     * @param digest SHA-256 destination.
     * @return True only when the complete digest was written.
     */
    virtual bool sha256(
      std::span<const std::uint8_t> input,
      Digest256 &digest
    ) noexcept = 0;

    /**
     * @brief Sign a deterministic transcript with the host application key.
     *
     * @param transcript Exact deterministic transcript.
     * @param signature Fixed 64-byte signature destination.
     * @return True only after a complete signature is written.
     */
    virtual bool sign(
      std::span<const std::uint8_t> transcript,
      std::span<std::uint8_t, ed25519_signature_size> signature
    ) noexcept = 0;

    /**
     * @brief Verify a client Ed25519 signature.
     *
     * @param public_key Trusted or proposed client public key.
     * @param transcript Exact deterministic transcript.
     * @param signature Presented 64-byte signature.
     * @return True only for a valid signature.
     */
    [[nodiscard]] virtual bool verify(
      const PublicKey256 &public_key,
      std::span<const std::uint8_t> transcript,
      std::span<const std::uint8_t, ed25519_signature_size> signature
    ) noexcept = 0;

    /**
     * @brief Constant-time compare two equal-width secret values.
     *
     * @param left First secret.
     * @param right Second secret.
     * @return True only when all bytes match.
     */
    [[nodiscard]] virtual bool equal_secret(
      const Secret256 &left,
      const Secret256 &right
    ) noexcept = 0;
  };

  /** @brief Complete fixed PIN/SPAKE approval input executed away from socket and HTTP threads. */
  struct ControlPairingApprovalInput {
    std::array<std::uint8_t, 6> pin_digits {};  ///< Exact six ASCII decimal digits entered by the administrator.
    Identifier128 scrypt_salt {};  ///< Client-selected 16-byte scrypt salt.
    Identifier128 client_id {};  ///< SPAKE identity A and paired-client identity.
    Identifier128 host_id {};  ///< SPAKE identity B and stable host identity.
    std::array<std::uint8_t, pairing_spake_point_size> point_a {};  ///< Client uncompressed P-256 point.
    std::vector<std::uint8_t> final_aad;  ///< Exact deterministic transcript binding exporter and challenge fields.

    /** @brief Construct empty single-owner approval input. */
    ControlPairingApprovalInput() = default;
    ControlPairingApprovalInput(const ControlPairingApprovalInput &) = delete;
    ControlPairingApprovalInput &operator=(const ControlPairingApprovalInput &) = delete;

    /** @brief Transfer approval ownership and clear the moved-from PIN and AAD. */
    ControlPairingApprovalInput(ControlPairingApprovalInput &&other) noexcept {
      move_from(std::move(other));
    }

    /** @brief Clear current secrets before transferring another approval input. */
    ControlPairingApprovalInput &operator=(ControlPairingApprovalInput &&other) noexcept {
      if (this != &other) {
        clear();
        move_from(std::move(other));
      }
      return *this;
    }

    /** @brief Securely clear all secret-bearing approval bytes. */
    ~ControlPairingApprovalInput() {
      clear();
    }

    /** @brief Securely clear PIN and final confirmation AAD. */
    void clear() noexcept {
      secure_zero(pin_digits);
      secure_zero(final_aad);
    }

  private:
    /** @brief Move fields without retaining duplicated secret bytes in the source. */
    void move_from(ControlPairingApprovalInput &&other) noexcept {
      pin_digits = other.pin_digits;
      scrypt_salt = other.scrypt_salt;
      client_id = other.client_id;
      host_id = other.host_id;
      point_a = other.point_a;
      final_aad = std::move(other.final_aad);
      other.clear();
    }
  };

  /** @brief One host SPAKE session retained only from challenge publication through FINISH. */
  class ControlPairingSpakeSession {
  public:
    virtual ~ControlPairingSpakeSession() = default;

    /**
     * @brief Verify `cA` and produce `cB` without releasing key material to control code.
     *
     * @param confirmation_a Exact client confirmation.
     * @param confirmation_b Host confirmation destination.
     * @return True only after peer confirmation succeeds.
     */
    virtual bool finish(
      const std::array<std::uint8_t, pairing_confirmation_size> &confirmation_a,
      std::array<std::uint8_t, pairing_confirmation_size> &confirmation_b
    ) noexcept = 0;
  };

  /** @brief Synchronous SPAKE provider called only by the dedicated pairing worker. */
  class ControlPairingProvider {
  public:
    virtual ~ControlPairingProvider() = default;

    /**
     * @brief Perform scrypt and host-point creation for one approved PIN attempt.
     *
     * @param input Complete immutable approval input.
     * @param point_b Host uncompressed P-256 point destination.
     * @return Retained host session or null on invalid point/provider failure.
     */
    [[nodiscard]] virtual std::unique_ptr<ControlPairingSpakeSession> approve(
      const ControlPairingApprovalInput &input,
      std::array<std::uint8_t, pairing_spake_point_size> &point_b
    ) noexcept = 0;
  };

  /**
   * @brief Exact DTLS application-record output and association-close boundary.
   */
  class ControlTransport {
  public:
    virtual ~ControlTransport() = default;

    /**
     * @brief Send one complete protected LSPC plaintext through DTLS.
     *
     * @param peer Destination association.
     * @param frame Complete byte-identical LSPC frame.
     * @return True only when DTLS accepted the complete record.
     */
    virtual bool send(
      const PeerEndpoint &peer,
      std::span<const std::uint8_t> frame
    ) noexcept = 0;

    /**
     * @brief Close one security association after a fatal control failure.
     *
     * @param peer Exact association.
     */
    virtual void close(const PeerEndpoint &peer) noexcept = 0;
  };

  /** @brief Web-safe state of one pending PIN pairing session. */
  enum class PairingAdministrationState : std::uint8_t {
    awaiting_pin,  ///< Waiting for a six-digit administrator entry.
    deriving,  ///< Dedicated worker is running scrypt and SPAKE point derivation.
    challenge_ready,  ///< Client may poll the published generation-qualified challenge.
    cooldown,  ///< A failed challenge is waiting for its bounded retry delay.
  };

  /** @brief Secret-free pending PIN pairing summary for authenticated administration. */
  struct PendingPairingSummary {
    Identifier128 pairing_session_id {};  ///< Random pending session identifier.
    Identifier128 client_id {};  ///< Proposed stable client identifier.
    Digest256 identity_key_fingerprint {};  ///< SHA-256 of the proposed Ed25519 public key.
    std::string client_name;  ///< Client-provided display name.
    bool client_name_verified {};  ///< Always false until FINISH identity verification succeeds.
    PermissionSet effective_permissions {};  ///< Host-ceiling intersection fixed at BEGIN.
    std::uint64_t expires_at_utc_seconds {};  ///< Absolute 120-second expiry.
    std::uint8_t challenges_used {};  ///< Approval challenges consumed, zero through three.
    PairingAdministrationState state {PairingAdministrationState::awaiting_pin};  ///< Coarse current state.
  };

  /** @brief Terminal state of one host-originated certificate rotation transaction. */
  enum class CertificateRotationState : std::uint8_t {
    absent,  ///< No matching authenticated connection/rotation exists.
    pending,  ///< Client persistence acknowledgement remains outstanding.
    succeeded,  ///< Client atomically persisted the replacement pin.
    failed,  ///< Client rejected or failed persistence.
  };

  /** @brief Result of one PIN-session POLL rate admission. */
  enum class PairingPollResult : std::uint8_t {
    accepted,  ///< Poll is legal and advances exponential backoff.
    too_early,  ///< Poll arrived before its floor and increments abuse state.
    cooldown,  ///< Four early polls triggered or remain within cooldown.
  };

  /** @brief Allocation-free 20-ms-through-1-s PIN POLL limiter. */
  struct PairingPollLimiter {
    std::uint64_t next_poll_microseconds {};  ///< Earliest legal next POLL.
    std::uint64_t interval_microseconds {20'000};  ///< Current exponential interval.
    std::uint64_t cooldown_until_microseconds {};  ///< One-second early-abuse cooldown.
    std::uint8_t early_count {};  ///< Consecutive early POLLs.

    /**
     * @brief Admit one monotonic POLL and update bounded backoff state.
     *
     * @param now_microseconds Current monotonic receive time.
     * @return Accepted, too-early, or cooldown disposition.
     */
    PairingPollResult admit(const std::uint64_t now_microseconds) noexcept {
      if (now_microseconds < cooldown_until_microseconds) {
        return PairingPollResult::cooldown;
      }
      if (now_microseconds < next_poll_microseconds) {
        ++early_count;
        if (early_count >= 4) {
          early_count = 0;
          cooldown_until_microseconds = now_microseconds > std::numeric_limits<std::uint64_t>::max() - 1'000'000 ?
                                          std::numeric_limits<std::uint64_t>::max() :
                                          now_microseconds + 1'000'000;
          return PairingPollResult::cooldown;
        }
        return PairingPollResult::too_early;
      }
      early_count = 0;
      next_poll_microseconds = now_microseconds > std::numeric_limits<std::uint64_t>::max() - interval_microseconds ?
                                 std::numeric_limits<std::uint64_t>::max() :
                                 now_microseconds + interval_microseconds;
      interval_microseconds = std::min<std::uint64_t>(1'000'000, interval_microseconds * 2U);
      return PairingPollResult::accepted;
    }
  };

  /** @brief Exact non-secret/session-bound fields encoded into PIN confirmation AAD. */
  struct PairingTranscriptBindings {
    Identifier128 host_id {};  ///< Stable host identity.
    PublicKey256 host_identity_key {};  ///< Host Ed25519 public key.
    Digest256 dtls_spki_sha256 {};  ///< Pinned host certificate SPKI.
    Identifier128 client_id {};  ///< Proposed stable client identity.
    PublicKey256 client_identity_key {};  ///< Proposed client Ed25519 public key.
    Identifier128 pairing_session_id {};  ///< Host-selected pending session identifier.
    Identifier128 client_pairing_nonce {};  ///< BEGIN pairing nonce.
    std::uint32_t connection_generation {};  ///< Authenticated DTLS connection generation.
    std::uint32_t approval_generation {};  ///< Current admin challenge generation.
    Secret256 client_hello_nonce {};  ///< CLIENT_HELLO nonce.
    Secret256 server_hello_nonce {};  ///< SERVER_HELLO nonce.
    Identifier128 scrypt_salt {};  ///< BEGIN scrypt salt.
    PermissionSet requested_permissions {};  ///< Original BEGIN request.
    PermissionSet effective_permissions {};  ///< Host-ceiling intersection.
    std::uint64_t expires_at_utc_seconds {};  ///< Absolute session expiry.
    PairingDtlsExporter pairing_exporter {};  ///< Dedicated label-separated TLS exporter.
  };

  /**
   * @brief Encode the exact 18-field deterministic pairing confirmation AAD.
   *
   * @param bindings Complete association, identity, permission, expiry, and exporter bindings.
   * @return Deterministic CBOR bytes, or no value for incomplete bindings.
   */
  [[nodiscard]] std::optional<std::vector<std::uint8_t>> pairing_confirmation_aad(
    const PairingTranscriptBindings &bindings
  );

  /**
   * @brief Encode the exact client identity-signature transcript.
   *
   * @param aad Exact 18-field confirmation AAD.
   * @param confirmation_a Verified client SPAKE confirmation.
   * @return Deterministic signature transcript, or no value for invalid inputs.
   */
  [[nodiscard]] std::optional<std::vector<std::uint8_t>> pairing_client_signature_transcript(
    std::span<const std::uint8_t> aad,
    const std::array<std::uint8_t, pairing_confirmation_size> &confirmation_a
  );

  /**
   * @brief Encode the exact host identity-signature transcript.
   *
   * @param aad Exact 18-field confirmation AAD.
   * @param confirmation_a Verified client SPAKE confirmation.
   * @param confirmation_b Host SPAKE confirmation.
   * @param revocation_generation Persisted trust generation.
   * @return Deterministic signature transcript, or no value for invalid inputs.
   */
  [[nodiscard]] std::optional<std::vector<std::uint8_t>> pairing_host_signature_transcript(
    std::span<const std::uint8_t> aad,
    const std::array<std::uint8_t, pairing_confirmation_size> &confirmation_a,
    const std::array<std::uint8_t, pairing_confirmation_size> &confirmation_b,
    std::uint32_t revocation_generation
  );

  /**
   * @brief Build the exact deterministic reconnect-authentication transcript.
   *
   * @param host_id Stable host identifier.
   * @param client_id Stable trusted-client identifier.
   * @param client_nonce CLIENT_HELLO nonce.
   * @param server_nonce SERVER_HELLO nonce.
   * @param connection_generation Assigned connection generation.
   * @return Deterministic CBOR transcript bytes, or no value on allocation/encoding failure.
   */
  [[nodiscard]] std::optional<std::vector<std::uint8_t>> authentication_signature_transcript(
    const Identifier128 &host_id,
    const Identifier128 &client_id,
    const Secret256 &client_nonce,
    const Secret256 &server_nonce,
    std::uint32_t connection_generation
  );

  /**
   * @brief Bounded per-association LSPC server implementing hello, pair, auth, and browse.
   */
  class HostControlServer {
  public:
    /**
     * @brief Construct the control owner with product boundaries that outlive it.
     *
     * @param identity Stable LSP-only host identity.
     * @param spki_sha256 Exact DTLS certificate SPKI pin.
     * @param trust_store Persistent LSP trust store.
     * @param applications Application snapshot provider.
     * @param start_handler START, ATTACH, and STOP product authority owner.
     * @param crypto Randomness and Ed25519 provider.
     * @param pairing_provider Synchronous SPAKE provider used only by the dedicated worker.
     * @param pairing_permissions Host permission ceiling intersected with every BEGIN request.
     * @param transport Exact DTLS record sender.
     * @param maximum_connections Bound from one through 64.
     */
    HostControlServer(
      const HostIdentity &identity,
      Digest256 spki_sha256,
      ControlTrustStore &trust_store,
      ControlApplicationProvider &applications,
      ControlStartHandler &start_handler,
      ControlCrypto &crypto,
      ControlPairingProvider &pairing_provider,
      PermissionSet pairing_permissions,
      ControlTransport &transport,
      std::size_t maximum_connections = 64
    ) noexcept;

    HostControlServer(const HostControlServer &) = delete;
    HostControlServer &operator=(const HostControlServer &) = delete;

    /** @brief Stop the pairing worker and destroy all bounded connection and PIN-session state. */
    ~HostControlServer();

    /**
     * @brief Close control admission, join asynchronous workers, and terminally answer queued text requests.
     *
     * The transport and its DTLS/forward-path owners must remain alive until
     * this call returns and its queued terminal records have been drained.
     */
    void shutdown() noexcept;

    /**
     * @brief Admit a newly authenticated DTLS association and assign a generation.
     *
     * @param peer Exact association five-tuple.
     * @param exporter Exact raw DTLS exporter bound into any PIN pairing on this association.
     * @return Nonzero connection generation, or zero at capacity/random failure.
     */
    std::uint32_t association_ready(
      const PeerEndpoint &peer,
      const PairingDtlsExporter &exporter
    ) noexcept;

    /**
     * @brief Remove all control authority for a closed association.
     *
     * @param peer Exact association five-tuple.
     */
    void association_closed(const PeerEndpoint &peer) noexcept;

    /**
     * @brief Close every live association authenticated as one client.
     *
     * @param client_id Stable client identifier changed or revoked by administration.
     */
    void disconnect_client(const Identifier128 &client_id) noexcept;

    /** @brief Serialize pairing cancellation, persistent permission update, and association disconnect. */
    bool update_trusted_client(
      const Identifier128 &client_id,
      PermissionSet permissions,
      bool enabled
    ) noexcept;

    /** @brief Serialize pairing cancellation, persistent revocation, and association disconnect. */
    bool revoke_trusted_client(const Identifier128 &client_id) noexcept;

    /**
     * @brief Process one authenticated DTLS application record.
     *
     * @param peer Exact established association.
     * @param frame Complete LSPC frame.
     * @param now_microseconds Monotonic receive timestamp.
     * @param now_utc_seconds Whole UTC seconds used only for PIN-session expiry and cooldown.
     * @return True when the record was accepted or safely rejected with a response.
     */
    bool receive(
      const PeerEndpoint &peer,
      std::span<const std::uint8_t> frame,
      std::uint64_t now_microseconds,
      std::uint64_t now_utc_seconds
    ) noexcept;

    /**
     * @brief Dispatch receipt-ACKed media/START/input-rate work, retransmit responses, and close failed operations.
     *
     * Call outside DTLS provider callbacks after flushing receipt ACKs queued by receive().
     * Capture preparation can take longer than the control retransmission window.
     *
     * @param now_microseconds Current monotonic timestamp.
     */
    void tick(std::uint64_t now_microseconds) noexcept;

    /**
     * @brief Reliably establish intent for one host-originated exact-size SRTCP probe.
     *
     * @param peer Exact authenticated association.
     * @param probe Nonzero identifier and candidate payload size.
     * @param now_microseconds Monotonic send time.
     * @return True when retained and first-transmitted.
     */
    bool start_path_probe(
      const PeerEndpoint &peer,
      const PathProbePayload &probe,
      std::uint64_t now_microseconds
    ) noexcept;

    /**
     * @brief Complete one peer probe after authenticating its exact-size `LSPP` datagram.
     *
     * @param peer Exact authenticated association.
     * @param probe Matched identifier and received protected size.
     * @param now_microseconds Monotonic completion time.
     * @return True when the reliable PATH_PROBE_ACK response was retained and sent.
     */
    bool complete_path_probe(
      const PeerEndpoint &peer,
      const PathProbePayload &probe,
      std::uint64_t now_microseconds
    ) noexcept;

    /**
     * @brief Retire one host-originated probe after its complete PROBE_TIMER budget expires.
     *
     * @param peer Exact authenticated association.
     * @param probe Exact outstanding logical probe.
     * @return True when the matching semantic request was retired.
     */
    bool cancel_path_probe(
      const PeerEndpoint &peer,
      const PathProbePayload &probe
    ) noexcept;

    /**
     * @brief Reliably notify one authenticated peer that its exact stream generation ended.
     *
     * @param peer Exact authenticated association.
     * @param ended Generation-bound terminal event.
     * @param now_microseconds Monotonic first-send time.
     * @return True when retained and first-transmitted.
     */
    bool send_stream_ended(
      const PeerEndpoint &peer,
      const StreamEndedPayload &ended,
      std::uint64_t now_microseconds
    ) noexcept;

    /**
     * @brief Sign and reliably announce one replacement DTLS certificate SPKI.
     *
     * @param peer Exact authenticated association.
     * @param new_spki_sha256 Replacement certificate SPKI digest.
     * @param rotation_generation Next persisted nonzero rotation generation.
     * @param now_microseconds Monotonic first-send time.
     * @return True when retained and first-transmitted under the old host identity.
     */
    bool start_certificate_rotation(
      const PeerEndpoint &peer,
      const Digest256 &new_spki_sha256,
      std::uint32_t rotation_generation,
      std::uint64_t now_microseconds
    ) noexcept;

    /** @brief Snapshot authenticated association peers for an administrative rotation transaction. */
    [[nodiscard]] std::optional<std::vector<PeerEndpoint>> authenticated_peers() const noexcept;

    /** @brief Atomically cancel PIN work, suspend new pairing, and snapshot authenticated peers. */
    [[nodiscard]] std::optional<std::vector<PeerEndpoint>> begin_certificate_rotation() noexcept;

    /** @brief Re-enable PIN pairing after one rotation transaction terminates. */
    void end_certificate_rotation() noexcept;

    /** @brief Read one peer's exact certificate rotation transaction state. */
    [[nodiscard]] CertificateRotationState certificate_rotation_state(
      const PeerEndpoint &peer,
      std::uint32_t rotation_generation
    ) const noexcept;

    /** @brief Publish the successfully activated SPKI as the base for future signed rotations. */
    void commit_certificate_rotation(const Digest256 &new_spki_sha256) noexcept;

    /** @brief Return the path-safe current control RTO used as a probe interval. */
    [[nodiscard]] std::uint64_t path_probe_interval(const PeerEndpoint &peer) const noexcept;

    /** @brief Return current association count. */
    [[nodiscard]] std::size_t connection_count() const noexcept;

    /**
     * @brief Return every secret-free pending PIN session after retiring expired state.
     *
     * @param now_utc_seconds Current whole-second UTC time.
     * @return Pending session summaries without PIN, point, confirmation, or exporter material.
     */
    [[nodiscard]] std::vector<PendingPairingSummary> pending_pairings(std::uint64_t now_utc_seconds) noexcept;

    /**
     * @brief Queue one six-digit PIN for one selected eligible pending session.
     *
     * Scrypt and SPAKE work executes only on the dedicated pairing worker.
     *
     * @param pairing_session_id Non-secret selected session identifier.
     * @param pin_digits Exact six ASCII decimal digits.
     * @param now_utc_seconds Current whole-second UTC time.
     * @return Number of sessions admitted to asynchronous derivation.
     */
    std::size_t submit_pairing_pin(
      const Identifier128 &pairing_session_id,
      const std::array<std::uint8_t, 6> &pin_digits,
      std::uint64_t now_utc_seconds
    ) noexcept;

    /** @brief Cancel and clear every pending LSP PIN pairing session. */
    void cancel_pairings() noexcept;

    /**
     * @brief Return current nonexpired pending PIN session count.
     *
     * @param now_utc_seconds Current whole-second UTC time.
     * @return Zero through four pending sessions.
     */
    [[nodiscard]] std::size_t pairing_count(std::uint64_t now_utc_seconds) noexcept;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;  ///< Hidden bounded connection/control state.
  };
}  // namespace lumen::lsp::runtime
