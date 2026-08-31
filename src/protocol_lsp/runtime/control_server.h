/**
 * @file src/protocol_lsp/runtime/control_server.h
 * @brief Authenticated deterministic-CBOR LSPC host control vertical slice.
 */

#pragma once

#include "../invitation.h"
#include "control/wire.h"
#include "identity.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace lumen::lsp::runtime {
  /** @brief Maximum path-safe DTLS application record used by initial LSP control. */
  inline constexpr std::size_t maximum_control_frame_bytes = 1'200;

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
  };

  /**
   * @brief Application listing boundary kept off the packet parser.
   */
  class ControlApplicationProvider {
  public:
    virtual ~ControlApplicationProvider() = default;

    /**
     * @brief Snapshot configured applications.
     *
     * @return Complete current snapshot, or no value on a product-state failure.
     */
    [[nodiscard]] virtual std::optional<std::vector<ControlApplication>> snapshot() noexcept = 0;
  };

  /** @brief Product authority boundary for START, ATTACH, input, and host audio. */
  class ControlStartHandler {
  public:
    virtual ~ControlStartHandler() = default;

    /**
     * @brief Commit one authenticated input-and-audio START.
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

  /**
   * @brief One active single-use pairing invitation admission record.
   */
  struct PendingInvitation {
    Identifier128 invitation_id {};  ///< Random invitation identifier.
    Secret256 verifier_salt {};  ///< Random salt retained with the verifier.
    Digest256 secret_verifier {};  ///< SHA-256 of salt, invitation ID, and secret.
    std::uint64_t expires_at_utc_seconds {};  ///< Whole-second expiration.
    PermissionSet permissions {};  ///< Maximum permissions granted by admission.
    bool consumed {};  ///< Whether a prior successful pairing used the invitation.

    /** @brief Return whether required fields are nonzero and unconsumed. */
    [[nodiscard]] bool valid() const noexcept;
  };

  /**
   * @brief Build the exact deterministic client pairing-signature transcript.
   *
   * @param host_id Stable host identifier.
   * @param client_id Stable client identifier.
   * @param invitation_id Presented invitation identifier.
   * @param client_nonce CLIENT_HELLO nonce.
   * @param server_nonce SERVER_HELLO nonce.
   * @param permissions Offered permission mask.
   * @return Deterministic CBOR transcript bytes, or no value on allocation/encoding failure.
   */
  [[nodiscard]] std::optional<std::vector<std::uint8_t>> pairing_signature_transcript(
    const Identifier128 &host_id,
    const Identifier128 &client_id,
    const Identifier128 &invitation_id,
    const Secret256 &client_nonce,
    const Secret256 &server_nonce,
    PermissionSet permissions
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
      ControlTransport &transport,
      std::size_t maximum_connections = 64
    ) noexcept;

    HostControlServer(const HostControlServer &) = delete;
    HostControlServer &operator=(const HostControlServer &) = delete;

    /** @brief Destroy all bounded connection and invitation state. */
    ~HostControlServer();

    /**
     * @brief Add one valid single-use invitation and retain only a salted verifier.
     *
     * @param invitation Complete invitation; its secret is not retained.
     * @return True when retained; false when invalid or at capacity.
     */
    bool add_invitation(const PairingInvitation &invitation) noexcept;

    /** @brief Revoke every unconsumed invitation and clear its verifier. */
    void revoke_invitations() noexcept;

    /**
     * @brief Admit a newly authenticated DTLS association and assign a generation.
     *
     * @param peer Exact association five-tuple.
     * @return Nonzero connection generation, or zero at capacity/random failure.
     */
    std::uint32_t association_ready(const PeerEndpoint &peer) noexcept;

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

    /**
     * @brief Process one authenticated DTLS application record.
     *
     * @param peer Exact established association.
     * @param frame Complete LSPC frame.
     * @param now_microseconds Monotonic receive timestamp.
     * @param now_utc_seconds Whole UTC seconds used only for invitation expiry.
     * @return True when the record was accepted or safely rejected with a response.
     */
    bool receive(
      const PeerEndpoint &peer,
      std::span<const std::uint8_t> frame,
      std::uint64_t now_microseconds,
      std::uint64_t now_utc_seconds
    ) noexcept;

    /**
     * @brief Retransmit due byte-identical responses and close failed operations.
     *
     * @param now_microseconds Current monotonic timestamp.
     */
    void tick(std::uint64_t now_microseconds) noexcept;

    /** @brief Return current association count. */
    [[nodiscard]] std::size_t connection_count() const noexcept;

    /** @brief Return retained unconsumed invitation count. */
    [[nodiscard]] std::size_t invitation_count() const noexcept;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;  ///< Hidden bounded connection/control state.
  };
}  // namespace lumen::lsp::runtime
