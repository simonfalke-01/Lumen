/**
 * @file src/protocol_lsp/runtime/control/wire.h
 * @brief Frozen deterministic-CBOR schemas for the initial LSP/1 control slice.
 */

#pragma once

#include "../../types.h"

#include <array>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

namespace lumen::lsp::runtime {
  /** @brief Ed25519 signature size used by LSP pairing and authentication. */
  inline constexpr std::size_t ed25519_signature_size = 64;

  /** @brief Exact LSP/1 control-message registry values implemented by this slice. */
  enum class ControlMessageType : std::uint16_t {
    client_hello = 0x0001,  ///< Establish connection generation and nonces.
    server_hello = 0x0002,  ///< Return host identity and connection generation.
    pair_request = 0x0010,  ///< Admit one single-use invitation and client identity.
    pair_response = 0x0011,  ///< Return pairing outcome and effective permission state.
    auth_request = 0x0020,  ///< Authenticate an already trusted client identity.
    auth_response = 0x0021,  ///< Return authentication outcome and permission state.
    list_applications = 0x0100,  ///< Request configured applications.
    applications = 0x0101,  ///< Return the bounded application snapshot.
    start = 0x0200,  ///< Request authenticated input and ordered host-audio capabilities.
    start_response = 0x0201,  ///< Return exact input authority and selected audio tuple.
    attach = 0x0202,  ///< Transfer an existing session to a fresh authenticated association.
    attach_response = 0x0203,  ///< Return rotated authority, token, SSRCs, and baseline requirement.
    stop = 0x0204,  ///< Stop the authenticated client's own session.
    stop_response = 0x0205,  ///< Return the terminal owner-qualified stop outcome.
    audio_config = 0x0212,  ///< Install one exact host Opus configuration before SRTP transmission.
    audio_config_ack = 0x0213,  ///< Authenticate client decoder readiness for one audio generation.
  };

  /** @brief Stable control status codes from the normative LSP registry. */
  enum class ControlStatus : std::uint8_t {
    success = 0,  ///< Operation completed.
    malformed = 1,  ///< Frame or deterministic-CBOR payload is invalid.
    unsupported = 2,  ///< Version, type, or capability is unsupported.
    authentication_failed = 3,  ///< Invitation or signature authentication failed.
    permission_denied = 4,  ///< Authenticated client lacks the required permission.
    busy = 5,  ///< Bounded resource is unavailable.
    unsupported_media_tuple = 6,  ///< Offered audio or video capabilities have no supported exact selection.
    stale_generation = 7,  ///< Connection generation is not authoritative.
    timeout = 8,  ///< Reliable response exhausted its deadline.
    path_capacity_insufficient = 9,  ///< Offered reverse-path budget cannot carry selected input.
    internal_failure = 10,  ///< Local crypto, persistence, or application snapshot failed.
  };

  /** @brief Typed failure from an exact control payload codec. */
  enum class ControlWireError : std::uint8_t {
    malformed_cbor,  ///< Payload is not strict deterministic CBOR.
    invalid_shape,  ///< Map keys/cardinality do not match the assigned message.
    invalid_field,  ///< A field has the wrong type, width, range, or UTF-8 value.
    size_limit,  ///< Encoded payload cannot fit one initial path-safe control record.
  };

  /** @brief Exact CLIENT_HELLO map `{1: version, 2: client_nonce}`. */
  struct ClientHelloPayload {
    Secret256 client_nonce {};  ///< Fresh nonzero client nonce.
  };

  /** @brief Exact SERVER_HELLO seven-key response map. */
  struct ServerHelloPayload {
    ControlStatus status {ControlStatus::success};  ///< Operation status.
    std::uint32_t connection_generation {};  ///< Assigned nonzero authority generation.
    Identifier128 host_id {};  ///< Stable LSP host identifier.
    PublicKey256 host_identity_key {};  ///< Host application Ed25519 public key.
    Digest256 dtls_spki_sha256 {};  ///< DTLS certificate SPKI pin.
    Secret256 server_nonce {};  ///< Fresh nonzero server nonce.
  };

  /** @brief Exact PAIR_REQUEST six-key request map. */
  struct PairRequestPayload {
    Identifier128 client_id {};  ///< Stable client identifier.
    PublicKey256 client_identity_key {};  ///< Proposed client Ed25519 public key.
    Identifier128 invitation_id {};  ///< Presented invitation identifier.
    Secret256 invitation_secret {};  ///< Presented single-use invitation secret.
    std::array<std::uint8_t, ed25519_signature_size> signature {};  ///< Client transcript signature.
  };

  /** @brief Exact PAIR_RESPONSE five-key response map. */
  struct PairResponsePayload {
    ControlStatus status {ControlStatus::success};  ///< Operation status.
    PermissionSet permissions {};  ///< Effective permissions.
    std::uint32_t revocation_generation {};  ///< Nonzero trust generation.
    std::array<std::uint8_t, ed25519_signature_size> signature {};  ///< Host transcript signature.
  };

  /** @brief Exact AUTH_REQUEST three-key request map. */
  struct AuthRequestPayload {
    Identifier128 client_id {};  ///< Stable trusted-client identifier.
    std::array<std::uint8_t, ed25519_signature_size> signature {};  ///< Client auth transcript signature.
  };

  /** @brief Exact AUTH_RESPONSE six-key response map. */
  struct AuthResponsePayload {
    ControlStatus status {ControlStatus::success};  ///< Operation status.
    PermissionSet permissions {};  ///< Current effective permissions.
    std::uint32_t revocation_generation {};  ///< Current nonzero trust generation.
    std::uint32_t connection_generation {};  ///< Authenticated connection generation.
    std::array<std::uint8_t, ed25519_signature_size> signature {};  ///< Host auth transcript signature.
  };

  /** @brief One exact application entry in APPLICATIONS key three. */
  struct ControlApplication {
    std::string id;  ///< Stable configured application ID, at most 128 UTF-8 bytes.
    std::string name;  ///< Human-readable name, at most 256 UTF-8 bytes.
    std::string image_path;  ///< Optional image path, at most 512 UTF-8 bytes.
  };

  /** @brief One exact five-key Opus capability offer carried by START key eight. */
  struct AudioOfferPayload {
    std::uint8_t channels {};  ///< Offered channel count: 2, 6, or 8.
    std::uint16_t frame_samples {};  ///< Offered 48 kHz frame duration: 120, 240, 480, or 960 samples.
    std::uint32_t maximum_bitrate {};  ///< Offered total Opus bitrate ceiling.
    bool inband_fec {};  ///< Whether Opus in-band FEC may be selected.
    bool dtx {};  ///< Whether Opus discontinuous transmission may be selected.
  };

  /** @brief Exact selected host-audio tuple repeated across START, ATTACH, and AUDIO_CONFIG. */
  struct AudioSelectionPayload {
    std::uint32_t audio_generation {};  ///< Nonzero audio configuration generation.
    std::uint32_t audio_ssrc {};  ///< Random nonzero host Opus SSRC.
    std::uint8_t audio_payload_type {};  ///< Dynamic Opus RTP payload type.
    std::uint32_t clock_rate {48'000};  ///< Exact Opus RTP clock rate.
    std::uint8_t channels {};  ///< Selected channel count.
    std::uint8_t streams {};  ///< Selected Opus stream count.
    std::uint8_t coupled_streams {};  ///< Selected coupled-stream count.
    std::array<std::uint8_t, 8> mapping {};  ///< First `channels` mapping-family-one entries.
    std::uint16_t frame_samples {};  ///< Selected packet duration in 48 kHz samples.
    std::uint32_t bitrate {};  ///< Selected total Opus bitrate.
    bool inband_fec {};  ///< Selected Opus in-band FEC state.
    bool dtx {};  ///< Selected Opus DTX state.
    std::uint16_t initial_udp_payload_size {1'200};  ///< Initial protected UDP payload maximum.
    std::uint8_t initial_preroll_packets {1};  ///< Required one-packet receiver preroll.
  };

  /** @brief Exact START nine-key request map for input plus ordered audio offers. */
  struct StartRequestPayload {
    std::string application_id;  ///< Configured application ID selected for input ownership.
    std::uint32_t pointer_rate {};  ///< Requested pointer reports/s in 125 through 16,000.
    std::uint32_t controller_rate {};  ///< Requested controller reports/s in 125 through 2,000.
    std::uint32_t sensor_rate {};  ///< Requested sensor reports/s in 125 through 4,000.
    std::uint32_t reconciliation_rate {};  ///< Requested reconciliation reports/s in 50 through 1,000.
    std::uint64_t maximum_input_wire_bits_per_second {};  ///< Client input budget ceiling up to 32 Mbps.
    std::vector<AudioOfferPayload> audio_offers;  ///< Ordered exact audio offers, one through twelve entries.
    std::uint16_t offered_maximum_udp_payload {};  ///< Client path payload ceiling for the association family.
  };

  /** @brief Exact START_RESPONSE 29-key response map. */
  struct StartResponsePayload {
    ControlStatus status {ControlStatus::success};  ///< START outcome.
    Identifier128 session_id {};  ///< Random stream-session identifier.
    Secret256 attach_token {};  ///< Random reconnect token.
    std::uint32_t stream_generation {};  ///< Nonzero stream generation.
    std::uint32_t input_generation {};  ///< Nonzero input authority generation.
    std::uint32_t input_ssrc {};  ///< Negotiated client input SSRC.
    std::uint32_t acknowledgement_ssrc {};  ///< Host LSPI SRTCP sender SSRC.
    std::uint8_t input_payload_type {};  ///< Dynamic RTP payload type.
    std::uint32_t pointer_rate {};  ///< Selected pointer reports/s.
    std::uint32_t controller_rate {};  ///< Selected controller reports/s.
    std::uint32_t sensor_rate {};  ///< Selected sensor reports/s.
    std::uint32_t reconciliation_rate {};  ///< Selected reconciliation reports/s.
    std::uint64_t reserved_input_wire_bits_per_second {};  ///< Exact reserved aggregate input budget.
    bool baseline_required {true};  ///< Always true for a fresh authority.
    AudioSelectionPayload audio {};  ///< Selected audio tuple encoded at keys 16 through 29.
  };

  /** @brief Exact STOP map `{1: version, 2: session_id}`. */
  struct StopRequestPayload {
    Identifier128 session_id {};  ///< Exact session identifier returned by START_RESPONSE.
  };

  /** @brief Exact ATTACH four-key request map. */
  struct AttachRequestPayload {
    Identifier128 session_id {};  ///< Existing session identifier.
    Secret256 attach_token {};  ///< Current single-use attach token.
    Identifier128 intent_id {};  ///< Fresh nonzero idempotent attach intent identifier.
  };

  /** @brief Exact ATTACH_RESPONSE 30-key response map. */
  struct AttachResponsePayload {
    ControlStatus status {ControlStatus::success};  ///< Transfer outcome.
    Identifier128 session_id {};  ///< Retained session identifier.
    Secret256 attach_token {};  ///< Fresh replacement token; the presented token is retired.
    std::uint32_t connection_generation {};  ///< New authoritative connection generation.
    std::uint32_t stream_generation {};  ///< Retained stream-session generation.
    std::uint32_t input_generation {};  ///< Advanced input authority generation.
    std::uint32_t input_ssrc {};  ///< Fresh input SSRC for the new DTLS-SRTP keys.
    std::uint32_t acknowledgement_ssrc {};  ///< Fresh host SRTCP sender SSRC.
    std::uint8_t input_payload_type {};  ///< Fresh dynamic input payload type.
    std::uint32_t pointer_rate {};  ///< Retained selected pointer rate.
    std::uint32_t controller_rate {};  ///< Retained selected controller rate.
    std::uint32_t sensor_rate {};  ///< Retained selected sensor rate.
    std::uint32_t reconciliation_rate {};  ///< Retained selected reconciliation rate.
    std::uint64_t reserved_input_wire_bits_per_second {};  ///< Retained reverse input budget.
    bool baseline_required {true};  ///< Always true after authority transfer.
    AudioSelectionPayload audio {};  ///< Fresh audio tuple encoded at keys 17 through 30.
  };

  /** @brief Exact 17-key AUDIO_CONFIG host request. */
  struct AudioConfigPayload {
    Identifier128 session_id {};  ///< Active stream-session identifier.
    std::uint32_t stream_generation {};  ///< Active stream generation.
    AudioSelectionPayload audio {};  ///< Exact selected audio tuple encoded at keys 4 through 17.
  };

  /** @brief Exact four-key AUDIO_CONFIG_ACK client response. */
  struct AudioConfigAckPayload {
    ControlStatus status {ControlStatus::success};  ///< Client configuration result.
    Identifier128 session_id {};  ///< Exact active session identifier.
    std::uint32_t audio_generation {};  ///< Acknowledged audio configuration generation.
  };

  /** @brief Decode exact CLIENT_HELLO deterministic CBOR. */
  [[nodiscard]] std::expected<ClientHelloPayload, ControlWireError> decode_client_hello(std::span<const std::uint8_t> payload);

  /** @brief Encode exact SERVER_HELLO deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_server_hello(const ServerHelloPayload &payload);

  /** @brief Decode exact PAIR_REQUEST deterministic CBOR. */
  [[nodiscard]] std::expected<PairRequestPayload, ControlWireError> decode_pair_request(std::span<const std::uint8_t> payload);

  /** @brief Encode exact PAIR_RESPONSE deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_pair_response(const PairResponsePayload &payload);

  /** @brief Decode exact AUTH_REQUEST deterministic CBOR. */
  [[nodiscard]] std::expected<AuthRequestPayload, ControlWireError> decode_auth_request(std::span<const std::uint8_t> payload);

  /** @brief Encode exact AUTH_RESPONSE deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_auth_response(const AuthResponsePayload &payload);

  /** @brief Decode exact LIST_APPLICATIONS map `{1: version}`. */
  [[nodiscard]] std::expected<void, ControlWireError> decode_list_applications(std::span<const std::uint8_t> payload);

  /** @brief Encode exact APPLICATIONS map `{1: version, 2: status, 3: entries}`. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_applications(std::span<const ControlApplication> applications);

  /** @brief Encode exact error map `{1: version, 2: status}`. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_control_error(ControlStatus status);

  /** @brief Decode exact input-and-audio START deterministic CBOR. */
  [[nodiscard]] std::expected<StartRequestPayload, ControlWireError> decode_start(std::span<const std::uint8_t> payload);

  /** @brief Encode exact input-and-audio START_RESPONSE deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_start_response(const StartResponsePayload &payload);

  /** @brief Decode exact owner-qualified STOP deterministic CBOR. */
  [[nodiscard]] std::expected<StopRequestPayload, ControlWireError> decode_stop(std::span<const std::uint8_t> payload);

  /** @brief Encode exact STOP_RESPONSE map `{1: version, 2: status}`. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_stop_response(ControlStatus status);

  /** @brief Decode exact ATTACH deterministic CBOR. */
  [[nodiscard]] std::expected<AttachRequestPayload, ControlWireError> decode_attach(std::span<const std::uint8_t> payload);

  /** @brief Encode exact ATTACH_RESPONSE deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_attach_response(const AttachResponsePayload &payload);

  /** @brief Encode exact AUDIO_CONFIG deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_audio_config(const AudioConfigPayload &payload);

  /** @brief Decode exact AUDIO_CONFIG_ACK deterministic CBOR. */
  [[nodiscard]] std::expected<AudioConfigAckPayload, ControlWireError> decode_audio_config_ack(std::span<const std::uint8_t> payload);
}  // namespace lumen::lsp::runtime
