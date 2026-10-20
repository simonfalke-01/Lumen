/**
 * @file src/protocol_lsp/runtime/control/wire.h
 * @brief Frozen deterministic-CBOR schemas for the initial LSP/1 control slice.
 */

#pragma once

#include "../../types.h"

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace lumen::lsp::runtime {
  /** @brief Ed25519 signature size used by LSP pairing and authentication. */
  inline constexpr std::size_t ed25519_signature_size = 64;

  /** @brief Fixed uncompressed P-256 point width used by LSP PIN pairing. */
  inline constexpr std::size_t pairing_spake_point_size = 65;

  /** @brief Fixed SPAKE confirmation width used by LSP PIN pairing. */
  inline constexpr std::size_t pairing_confirmation_size = 32;

  /** @brief Dedicated incompatible schema revision for all PIN pairing maps. */
  inline constexpr std::uint8_t pairing_schema_version = 1;

  /** @brief Exact LSP/1 control-message registry values implemented by this slice. */
  enum class ControlMessageType : std::uint16_t {
    client_hello = 0x0001,  ///< Establish connection generation and nonces.
    server_hello = 0x0002,  ///< Return host identity and connection generation.
    pair_begin = 0x0010,  ///< Begin one bounded PIN/SPAKE pairing session.
    pair_pending = 0x0011,  ///< Return the pending session and effective permission ceiling.
    pair_poll = 0x0012,  ///< Poll one pending session without blocking the socket owner.
    pair_challenge = 0x0013,  ///< Return the admin-approved SPAKE challenge.
    pair_finish = 0x0014,  ///< Authenticate the client confirmation and identity signature.
    pair_result = 0x0015,  ///< Return the persisted trust result and host confirmation.
    auth_request = 0x0020,  ///< Authenticate an already trusted client identity.
    auth_response = 0x0021,  ///< Return authentication outcome and permission state.
    certificate_rotate = 0x0022,  ///< Announce one old-identity-signed DTLS certificate rotation.
    certificate_rotate_ack = 0x0023,  ///< Confirm atomic client trust persistence for a rotation.
    list_applications = 0x0100,  ///< Request configured applications.
    applications = 0x0101,  ///< Return the bounded application snapshot.
    quit_application = 0x0102,  ///< Terminate only the application owned by this session.
    quit_application_response = 0x0103,  ///< Return owner-qualified application termination status.
    start = 0x0200,  ///< Request input, ordered host audio, and optional reverse microphone.
    start_response = 0x0201,  ///< Return exact input, audio, and nullable microphone selection.
    attach = 0x0202,  ///< Transfer an existing session to a fresh authenticated association.
    attach_response = 0x0203,  ///< Return rotated authority, token, SSRCs, and baseline requirement.
    stop = 0x0204,  ///< Stop the authenticated client's own session.
    stop_response = 0x0205,  ///< Return the terminal owner-qualified stop outcome.
    video_config = 0x0210,  ///< Install one exact schema-revision-three video decoder configuration.
    video_config_ack = 0x0211,  ///< Authenticate client decoder readiness and initial credit.
    audio_config = 0x0212,  ///< Install one exact host Opus configuration before SRTP transmission.
    audio_config_ack = 0x0213,  ///< Authenticate client decoder readiness for one audio generation.
    microphone_config = 0x0214,  ///< Install one exact reverse Opus microphone configuration.
    microphone_config_ack = 0x0215,  ///< Authenticate client sender readiness for one microphone generation.
    text_input = 0x0216,  ///< Commit one UTF-8/IME payload behind an applied-edge barrier.
    text_input_response = 0x0217,  ///< Return exact generation and barrier disposition.
    input_rate_request = 0x0218,  ///< Offer hot-plugged device capture and packet-rate bounds.
    input_rate_response = 0x0219,  ///< Select device rates within the active input budget.
    stream_ended = 0x0220,  ///< Notify the client that one generation-bound stream ended.
    clipboard_update = 0x0222,  ///< Replace the peer clipboard with bounded UTF-8 text.
    clipboard_update_response = 0x0223,  ///< Return session- and sequence-bound clipboard disposition.
    cursor_state = 0x0224,  ///< Host cursor visibility and shape for a client-drawn cursor.
    cursor_state_response = 0x0225,  ///< Return session- and sequence-bound cursor disposition.
    path_probe = 0x0300,  ///< Establish authenticated intent for one exact-size SRTCP path probe.
    path_probe_ack = 0x0301,  ///< Confirm one authenticated exact-size path probe.
    object_chunk = 0x0400,  ///< Transfer or acknowledge one bounded contiguous object chunk.
  };

  /** @brief Stable control status codes from the normative LSP registry. */
  enum class ControlStatus : std::uint8_t {
    success = 0,  ///< Operation completed.
    malformed = 1,  ///< Frame or deterministic-CBOR payload is invalid.
    unsupported = 2,  ///< Version, type, or capability is unsupported.
    authentication_failed = 3,  ///< PIN confirmation, identity signature, or trusted authentication failed.
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

  /** @brief Exact nine-key PAIR_BEGIN request. */
  struct PairBeginPayload {
    Identifier128 client_id {};  ///< Stable client identifier.
    PublicKey256 client_identity_key {};  ///< Proposed client Ed25519 public key.
    std::string client_name;  ///< Display name containing one through 64 UTF-8 bytes.
    Identifier128 client_pairing_nonce {};  ///< Fresh pairing-specific client nonce.
    Identifier128 scrypt_salt {};  ///< Fresh client-selected scrypt salt.
    std::array<std::uint8_t, pairing_spake_point_size> point_a {};  ///< Uncompressed P-256 SPAKE point `pA`.
    PermissionSet requested_permissions {};  ///< Requested permission subset.
  };

  /** @brief Exact six-key PAIR_PENDING response. */
  struct PairPendingPayload {
    ControlStatus status {ControlStatus::success};  ///< Pending-session creation or poll status.
    Identifier128 pairing_session_id {};  ///< Random nonzero PIN-session identifier.
    std::uint64_t expires_at_utc_seconds {};  ///< Absolute 120-second session expiry.
    PermissionSet effective_permissions {};  ///< Host-ceiling intersection fixed for the session.
  };

  /** @brief Exact three-key PAIR_POLL request. */
  struct PairPollPayload {
    Identifier128 pairing_session_id {};  ///< Pending session returned by PAIR_PENDING.
  };

  /** @brief Exact seven-key PAIR_CHALLENGE response. */
  struct PairChallengePayload {
    Identifier128 pairing_session_id {};  ///< Approved pending session.
    std::uint32_t approval_generation {};  ///< Nonzero generation binding admin approval and finish.
    std::array<std::uint8_t, pairing_spake_point_size> point_b {};  ///< Uncompressed host SPAKE point `pB`.
    PermissionSet effective_permissions {};  ///< Fixed approved permission set.
    std::uint64_t expires_at_utc_seconds {};  ///< Unchanged session expiry.
  };

  /** @brief Exact six-key PAIR_FINISH request. */
  struct PairFinishPayload {
    Identifier128 pairing_session_id {};  ///< Approved pending session.
    std::uint32_t approval_generation {};  ///< Exact generation returned by PAIR_CHALLENGE.
    std::array<std::uint8_t, pairing_confirmation_size> confirmation_a {};  ///< Client SPAKE confirmation `cA`.
    std::array<std::uint8_t, ed25519_signature_size> client_signature {};  ///< Client identity signature over the bound transcript.

    /** @brief Compare an exact semantic FINISH for completed-result replay. */
    bool operator==(const PairFinishPayload &) const noexcept = default;
  };

  /** @brief Exact nine-key PAIR_RESULT response. */
  struct PairResultPayload {
    ControlStatus status {ControlStatus::success};  ///< Persisted trust and confirmation result.
    Identifier128 pairing_session_id {};  ///< Terminal pairing session.
    std::uint32_t approval_generation {};  ///< Exact completed approval generation.
    PermissionSet permissions {};  ///< Persisted effective permissions.
    std::uint32_t revocation_generation {};  ///< Nonzero persisted trust generation.
    std::array<std::uint8_t, pairing_confirmation_size> confirmation_b {};  ///< Host SPAKE confirmation `cB`.
    std::array<std::uint8_t, ed25519_signature_size> host_signature {};  ///< Host identity signature over the result transcript.
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

  /** @brief Exact six-key old-identity-signed certificate rotation request. */
  struct CertificateRotatePayload {
    Identifier128 host_id {};  ///< Stable host identity being rotated.
    std::uint32_t connection_generation {};  ///< Exact authenticated connection generation.
    std::uint32_t rotation_generation {};  ///< Next nonzero persisted rotation generation.
    Digest256 new_spki_sha256 {};  ///< Replacement certificate SPKI digest.
    std::array<std::uint8_t, ed25519_signature_size> host_signature {};  ///< Old identity signature.
  };

  /** @brief Exact five-key certificate rotation acknowledgement. */
  struct CertificateRotateAckPayload {
    ControlStatus status {ControlStatus::success};  ///< Atomic persistence disposition.
    Identifier128 host_id {};  ///< Exact rotated host identity.
    std::uint32_t connection_generation {};  ///< Exact association generation.
    std::uint32_t rotation_generation {};  ///< Exact acknowledged rotation generation.
  };

  /** @brief One exact six-key application entry with authoritative process/resume state. */
  enum class ApplicationKind : std::uint8_t {
    app = 0,  ///< Any configured program.
    desktop = 1,  ///< The host desktop with no launched program.
    steam = 2,  ///< Steam or Steam Big Picture.
  };

  struct ControlApplication {
    std::string id;  ///< Stable configured application ID, at most 128 UTF-8 bytes.
    std::string name;  ///< Human-readable name, at most 256 UTF-8 bytes.
    std::string image_path;  ///< Optional image path, at most 512 UTF-8 bytes.
    bool running {};  ///< Whether this is the process manager's exact active application.
    bool resume_available {};  ///< Whether the active generation is LSP-owned and may be resumed.
    std::uint64_t process_generation {};  ///< Exact active generation, or zero while not running.
    ApplicationKind kind {ApplicationKind::app};  ///< What the entry launches, for client default icons.
  };

  /** @brief Exact three-key owner-qualified application quit request. */
  struct QuitApplicationPayload {
    Identifier128 session_id {};  ///< Active owned session identifier.
    std::string application_id;  ///< Stable configured application identifier.
  };

  /** @brief Exact three-key application quit response. */
  struct QuitApplicationResponsePayload {
    ControlStatus status {ControlStatus::success};  ///< Owner-qualified termination disposition.
    Identifier128 session_id {};  ///< Exact requested session identifier.
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

  /** @brief Exact six-key optional reverse-microphone offer carried by START key ten. */
  struct MicrophoneOfferPayload {
    std::uint8_t channels {1};  ///< Exact mono channel count.
    std::uint16_t frame_samples {960};  ///< Exact 20 ms frame size at 48 kHz.
    std::uint32_t maximum_bitrate {};  ///< Offered total Opus bitrate ceiling.
    bool inband_fec {};  ///< Whether Opus in-band FEC may be selected.
    bool dtx {};  ///< Whether Opus DTX may be selected.
    bool required {};  ///< Whether START must fail instead of selecting null.
  };

  /** @brief Exact ten-key selected reverse-microphone tuple. */
  struct MicrophoneSelectionPayload {
    std::uint32_t microphone_generation {};  ///< Nonzero microphone configuration generation.
    std::uint32_t microphone_ssrc {};  ///< Random nonzero client microphone SSRC.
    std::uint8_t microphone_payload_type {};  ///< Dynamic Opus RTP payload type.
    std::uint32_t clock_rate {48'000};  ///< Exact Opus RTP clock rate.
    std::uint8_t channels {1};  ///< Exact mono channel count.
    std::uint16_t frame_samples {960};  ///< Exact 20 ms frame size.
    std::uint32_t bitrate {};  ///< Selected Opus bitrate.
    bool inband_fec {};  ///< Selected Opus FEC state.
    bool dtx {};  ///< Selected Opus DTX state.
    std::uint16_t initial_udp_payload_size {1'200};  ///< Initial protected UDP payload maximum.
  };

  /** @brief Network profile values carried by START key eleven. */
  enum class VideoNetworkProfile : std::uint8_t {
    adaptive_low_latency = 0,  ///< Safe delay-adaptive default.
    competition = 1,  ///< Explicitly provisioned competition-LAN mode.
  };

  /** @brief Codec values carried by the frozen video offer and selection maps. */
  enum class VideoCodec : std::uint8_t {
    h264 = 1,  ///< RFC 6184 H.264 non-interleaved mode.
    hevc = 2,  ///< RFC 7798 HEVC single-stream mode.
    av1 = 3,  ///< AOM AV1 RTP payload-format version 1.0.0.
  };

  /** @brief Exact codec-profile values for the LSP video schema. */
  enum class VideoProfile : std::uint8_t {
    h264_high = 1,  ///< H.264 High profile.
    h264_high_444_predictive = 2,  ///< H.264 High 4:4:4 Predictive profile.
    hevc_main = 3,  ///< HEVC Main profile.
    hevc_main10 = 4,  ///< HEVC Main 10 profile.
    hevc_range_extensions = 5,  ///< HEVC Range Extensions profile; pixel class selects depth.
    av1_main = 6,  ///< AV1 Main profile; pixel class selects 8-bit or 10-bit 4:2:0.
    av1_high = 7,  ///< AV1 High profile; pixel class selects 8-bit or 10-bit 4:4:4.
  };

  /** @brief Exact decoded pixel classes carried by video offers and selections. */
  enum class VideoPixelClass : std::uint8_t {
    yuv420_8 = 1,  ///< 8-bit 4:2:0, represented by NV12 on Windows.
    yuv420_10 = 2,  ///< 10-bit 4:2:0, represented by P010 on Windows.
    yuv444_8 = 3,  ///< 8-bit 4:4:4.
    yuv444_10 = 4,  ///< 10-bit 4:4:4.
  };

  /** @brief Compatibility name for the schema's NV12-compatible 4:2:0 8-bit pixel class. */
  inline constexpr VideoPixelClass video_pixel_format_nv12 = VideoPixelClass::yuv420_8;

  /** @brief H.273 value for BT.709 color primaries, transfer, and matrix coefficients. */
  inline constexpr std::uint8_t video_color_bt709 = 1;

  /** @brief H.273 value for BT.2020 color primaries. */
  inline constexpr std::uint8_t video_color_primaries_bt2020 = 9;

  /** @brief H.273 value for BT.2020 non-constant-luminance matrix coefficients. */
  inline constexpr std::uint8_t video_matrix_bt2020_ncl = 9;

  /** @brief H.273 value for SMPTE ST 2084 perceptual-quantizer transfer. */
  inline constexpr std::uint8_t video_transfer_pq = 16;

  /** @brief H.273 value for ARIB STD-B67 hybrid-log-gamma transfer. */
  inline constexpr std::uint8_t video_transfer_hlg = 18;

  /** @brief Exact complete-access-unit encoder-delivery value. */
  inline constexpr std::uint8_t video_delivery_complete_access_unit = 1;

  /** @brief Fixed visible RFC 9626 frame-marking extension identifier. */
  inline constexpr std::uint8_t video_frame_marking_extension_id = 1;

  /** @brief Fixed RFC 8872 absolute-capture-time extension identifier. */
  inline constexpr std::uint8_t video_absolute_capture_time_extension_id = 2;

  /** @brief Fixed encrypted LSP frame-ID extension identifier. */
  inline constexpr std::uint8_t video_frame_id_extension_id = 3;

  /** @brief Dedicated incompatible schema revision for all LSP video control maps. */
  inline constexpr std::uint8_t video_schema_version = 3;

  /** @brief Smallest realistic negotiated encoded-video source rate in bits per second. */
  inline constexpr std::uint64_t video_minimum_bits_per_second = 1'000;

  /** @brief Shared maximum frame-age and FlexFEC-window budget in microseconds. */
  inline constexpr std::uint32_t video_maximum_frame_age_microseconds = 1'000'000;

  /** @brief Fixed encrypted LSP input-watermark extension identifier. */
  inline constexpr std::uint8_t video_input_watermark_extension_id = 4;

  /** @brief Fixed encrypted LSP encoder-timing extension identifier. */
  inline constexpr std::uint8_t video_encoder_timing_extension_id = 5;

  /** @brief One exact eighteen-key ordered video offer in START key twelve. */
  struct VideoOfferPayload {
    VideoCodec codec {VideoCodec::h264};  ///< Offered H.264, HEVC, or AV1 codec.
    VideoProfile profile {VideoProfile::h264_high};  ///< Codec-matched negotiated profile.
    std::uint32_t width {};  ///< Exact encoded width in pixels.
    std::uint32_t height {};  ///< Exact encoded height in pixels.
    std::uint32_t refresh_numerator {};  ///< Exact rational refresh numerator.
    std::uint32_t refresh_denominator {};  ///< Exact rational refresh denominator.
    std::uint64_t preferred_bits_per_second {};  ///< Preferred encoded source-media rate, at least 1,000 bits/s.
    std::uint64_t maximum_bits_per_second {};  ///< Maximum accepted source-media rate, at least 1,000 bits/s.
    VideoPixelClass pixel_format {VideoPixelClass::yuv420_8};  ///< Exact chroma-sampling and bit-depth class.
    std::uint8_t color_primaries {video_color_bt709};  ///< Exact H.273 color-primaries value.
    std::uint8_t transfer_function {video_color_bt709};  ///< Exact H.273 transfer-characteristic value.
    std::uint8_t matrix_coefficients {video_color_bt709};  ///< Exact H.273 matrix-coefficients value.
    bool full_range {};  ///< Whether decoded luma/chroma use full range.
    std::uint8_t delivery {video_delivery_complete_access_unit};  ///< Exactly complete-access-unit delivery.
    bool flexfec {};  ///< Whether the client can receive negotiated RFC 8627 repair.
    bool rtx {};  ///< Whether the client can receive negotiated RFC 4588 retransmission.
    std::uint32_t maximum_complete_access_unit_bytes {};  ///< Client's positive complete-AU admission bound.
  };

  /** @brief Exact negotiated RFC 8627 single-stream repair source. */
  struct FlexFecSelectionPayload {
    std::uint32_t repair_ssrc {};  ///< Random nonzero repair SSRC distinct from the primary source.
    std::uint8_t repair_payload_type {};  ///< Dynamic FlexFEC RTP payload type.
    std::uint32_t window_microseconds {};  ///< Frame-local repair window, one through 1,000,000 microseconds.
    std::uint8_t maximum_group_packets {15};  ///< Exact maximum protected source packets per group.
  };

  /** @brief Exact negotiated RFC 4588 retransmission source. */
  struct RtxSelectionPayload {
    std::uint32_t rtx_ssrc {};  ///< Random nonzero RTX SSRC distinct from primary and repair sources.
    std::uint8_t rtx_payload_type {};  ///< Dynamic RTX RTP payload type.
    std::uint8_t associated_payload_type {};  ///< Exact primary-video payload type (`apt`).
  };

  /** @brief Exact thirty-key selected video tuple. */
  struct VideoSelectionPayload {
    std::uint32_t video_generation {};  ///< Nonzero video configuration generation.
    std::uint32_t primary_ssrc {};  ///< Random nonzero primary video SSRC.
    std::uint8_t primary_payload_type {};  ///< Dynamic primary RTP payload type.
    std::uint32_t clock_rate {90'000};  ///< Exact 90 kHz video clock.
    VideoCodec codec {VideoCodec::h264};  ///< Selected H.264, HEVC, or AV1 codec.
    VideoProfile profile {VideoProfile::h264_high};  ///< Selected matching codec profile.
    std::uint32_t width {};  ///< Selected encoded width.
    std::uint32_t height {};  ///< Selected encoded height.
    std::uint32_t refresh_numerator {};  ///< Selected rational refresh numerator.
    std::uint32_t refresh_denominator {};  ///< Selected rational refresh denominator.
    std::uint64_t selected_bits_per_second {};  ///< Selected source-media rate, at least 1,000 bits/s.
    VideoPixelClass pixel_format {VideoPixelClass::yuv420_8};  ///< Exact selected pixel class.
    std::uint8_t color_primaries {video_color_bt709};  ///< Exact H.273 color-primaries value.
    std::uint8_t transfer_function {video_color_bt709};  ///< Exact H.273 transfer-characteristic value.
    std::uint8_t matrix_coefficients {video_color_bt709};  ///< Exact H.273 matrix-coefficients value.
    bool full_range {};  ///< Whether decoded luma/chroma use full range.
    std::uint16_t initial_udp_payload_size {1'200};  ///< Exact initial protected UDP maximum.
    std::uint8_t decoder_surfaces {};  ///< Negotiated hardware submissions, two through four.
    std::uint8_t render_mailbox {1};  ///< Exact render mailbox depth one.
    std::uint8_t delivery {video_delivery_complete_access_unit};  ///< Exactly complete-access-unit delivery.
    std::uint8_t frame_marking_extension {video_frame_marking_extension_id};  ///< Visible RFC 9626 extension ID.
    std::uint8_t absolute_capture_time_extension {video_absolute_capture_time_extension_id};  ///< RFC 8872 extension ID.
    std::uint8_t frame_id_extension {video_frame_id_extension_id};  ///< Encrypted custom frame-ID extension ID.
    std::uint8_t input_watermark_extension {video_input_watermark_extension_id};  ///< Encrypted input-watermark extension ID.
    std::uint8_t encoder_timing_extension {video_encoder_timing_extension_id};  ///< Encrypted encoder-timing extension ID.
    std::optional<FlexFecSelectionPayload> flexfec;  ///< Nullable authenticated FlexFEC association.
    std::optional<RtxSelectionPayload> rtx;  ///< Nullable authenticated RTX association.
    std::uint32_t maximum_frame_age_microseconds {};  ///< Authenticated frame-age budget, one through 1,000,000 microseconds.
    std::uint32_t maximum_complete_access_unit_bytes {};  ///< Positive complete-AU parser/admission maximum.
  };

  /** @brief Who draws the pointer, carried by START key seventeen. */
  enum class CursorMode : std::uint8_t {
    host = 0,  ///< The host composes its cursor into video frames.
    client = 1,  ///< The client draws the cursor from CURSOR_STATE while the host shows one.
  };

  /** @brief Exact START seventeen-key request map including video schema revision three. */
  struct StartRequestPayload {
    std::string application_id;  ///< Configured application ID selected for input ownership.
    bool resume {};  ///< Whether START must reuse the matching running application instead of launching.
    std::uint32_t pointer_rate {};  ///< Requested pointer reports/s in 125 through 16,000.
    std::uint32_t controller_rate {};  ///< Requested controller reports/s in 125 through 2,000.
    std::uint32_t sensor_rate {};  ///< Requested sensor reports/s in 125 through 4,000.
    std::uint32_t reconciliation_rate {};  ///< Requested reconciliation reports/s in 50 through 1,000.
    std::uint64_t maximum_input_wire_bits_per_second {};  ///< Client input budget ceiling up to 32 Mbps.
    std::vector<AudioOfferPayload> audio_offers;  ///< Ordered exact audio offers, one through twelve entries.
    std::uint16_t offered_maximum_udp_payload {};  ///< Client path payload ceiling for the association family.
    std::optional<MicrophoneOfferPayload> microphone_offer;  ///< Null or exact reverse-microphone offer.
    VideoNetworkProfile network_profile {VideoNetworkProfile::adaptive_low_latency};  ///< Selected controller profile.
    std::vector<VideoOfferPayload> video_offers;  ///< Ordered exact schema-revision-three offers, one through eight entries.
    std::uint8_t client_receive_batch_capacity {};  ///< Client receive batch capacity, one through 64.
    std::uint8_t decoder_surfaces {};  ///< Offered hardware decoder submissions, two through four.
    std::uint8_t render_mailbox {};  ///< Required exact depth one.
    std::uint32_t maximum_capture_to_present_microseconds {};  ///< Positive end-to-end admission budget.
    CursorMode cursor_mode {CursorMode::host};  ///< Requested cursor drawing side.
  };

  /** @brief Exact START_RESPONSE 31-key response map. */
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
    std::optional<MicrophoneSelectionPayload> microphone;  ///< Null or selected microphone tuple at key 30.
    VideoSelectionPayload video {};  ///< Exact selected video tuple at key 31.
  };

  /** @brief Exact STOP map `{1: version, 2: session_id}`. */
  struct StopRequestPayload {
    Identifier128 session_id {};  ///< Exact session identifier returned by START_RESPONSE.
  };

  /** @brief Exact ATTACH five-key request map. */
  struct AttachRequestPayload {
    Identifier128 session_id {};  ///< Existing session identifier.
    Secret256 attach_token {};  ///< Current single-use attach token.
    Identifier128 intent_id {};  ///< Fresh nonzero idempotent attach intent identifier.
    Secret256 successor_attach_token {};  ///< Client-selected nonzero successor token installed only on commit.
  };

  /** @brief Exact ATTACH_RESPONSE 32-key response map. */
  struct AttachResponsePayload {
    ControlStatus status {ControlStatus::success};  ///< Transfer outcome.
    Identifier128 session_id {};  ///< Retained session identifier.
    Secret256 attach_token {};  ///< Exact client-selected successor token; the presented token is retired.
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
    std::optional<MicrophoneSelectionPayload> microphone;  ///< Null or fresh microphone tuple at key 31.
    VideoSelectionPayload video {};  ///< Advanced generation and fresh primary SSRC at key 32.
  };

  /** @brief Exact codec-specific decoder configuration carried by VIDEO_CONFIG key five. */
  struct VideoCodecConfigurationPayload {
    VideoCodec kind {VideoCodec::h264};  ///< Codec discriminator matching the selected video codec.
    std::vector<std::vector<std::uint8_t>> units;  ///< SPS/PPS, VPS/SPS/PPS, or one AV1 sequence-header OBU.
  };

  /** @brief Exact thirteen-key HDR10 static mastering and content-light metadata. */
  struct HdrMetadataPayload {
    std::uint16_t red_primary_x {};  ///< Red CIE 1931 x coordinate normalized to 50,000.
    std::uint16_t red_primary_y {};  ///< Red CIE 1931 y coordinate normalized to 50,000.
    std::uint16_t green_primary_x {};  ///< Green CIE 1931 x coordinate normalized to 50,000.
    std::uint16_t green_primary_y {};  ///< Green CIE 1931 y coordinate normalized to 50,000.
    std::uint16_t blue_primary_x {};  ///< Blue CIE 1931 x coordinate normalized to 50,000.
    std::uint16_t blue_primary_y {};  ///< Blue CIE 1931 y coordinate normalized to 50,000.
    std::uint16_t white_point_x {};  ///< White-point CIE 1931 x coordinate normalized to 50,000.
    std::uint16_t white_point_y {};  ///< White-point CIE 1931 y coordinate normalized to 50,000.
    std::uint16_t maximum_display_luminance {};  ///< Maximum mastering-display luminance in nits.
    std::uint16_t minimum_display_luminance {};  ///< Minimum mastering-display luminance in 0.0001-nit units.
    std::uint16_t maximum_content_light_level {};  ///< MaxCLL in nits, or zero when unknown.
    std::uint16_t maximum_frame_average_light_level {};  ///< MaxFALL in nits, or zero when unknown.
    std::uint16_t maximum_full_frame_luminance {};  ///< Display maximum full-frame luminance in nits, or zero.
  };

  /** @brief Exact eight-key VIDEO_CONFIG host request. */
  struct VideoConfigPayload {
    Identifier128 session_id {};  ///< Active stream-session identifier.
    std::uint32_t stream_generation {};  ///< Active stream generation.
    VideoSelectionPayload video {};  ///< Exact selected video tuple repeated at key four.
    VideoCodecConfigurationPayload codec_configuration {};  ///< Exact codec-specific decoder configuration map.
    std::uint64_t frame_id_origin {};  ///< Nonzero first frame-ID origin.
    std::uint32_t recovery_epoch {};  ///< Nonzero initial recovery epoch.
    std::optional<HdrMetadataPayload> hdr_metadata;  ///< Required static HDR metadata for PQ; null for SDR and HLG.
  };

  /** @brief Exact five-key VIDEO_CONFIG_ACK client response. */
  struct VideoConfigAckPayload {
    ControlStatus status {ControlStatus::success};  ///< Client configuration result.
    Identifier128 session_id {};  ///< Exact active session identifier.
    std::uint32_t video_generation {};  ///< Acknowledged video configuration generation.
    std::uint8_t decoder_credit {};  ///< Initial freshness-bounded decoder credit, two through four.
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

  /** @brief Exact 13-key MICROPHONE_CONFIG host request. */
  struct MicrophoneConfigPayload {
    Identifier128 session_id {};  ///< Active stream-session identifier.
    std::uint32_t stream_generation {};  ///< Active stream generation.
    MicrophoneSelectionPayload microphone {};  ///< Exact selected microphone tuple at keys 4 through 13.
  };

  /** @brief Exact four-key MICROPHONE_CONFIG_ACK client response. */
  struct MicrophoneConfigAckPayload {
    ControlStatus status {ControlStatus::success};  ///< Client configuration result.
    Identifier128 session_id {};  ///< Exact active session identifier.
    std::uint32_t microphone_generation {};  ///< Acknowledged microphone generation.
  };

  /** @brief Exact three-key PATH_PROBE or PATH_PROBE_ACK payload. */
  struct PathProbePayload {
    std::uint64_t probe_id {};  ///< Random nonzero authenticated probe identifier.
    std::uint16_t udp_payload_size {};  ///< Exact protected UDP payload size.

    /** @brief Compare the exact probe identifier and size. */
    [[nodiscard]] bool operator==(const PathProbePayload &) const noexcept = default;
  };

  /** @brief One reliable UTF-8/IME commit, inline or object-backed. */
  struct TextInputPayload {
    Identifier128 session_id {};  ///< Active stream-session identifier.
    std::uint32_t input_generation {};  ///< Exact active input generation.
    std::uint64_t preceding_edge_id {};  ///< Greatest edge that must already be applied.
    std::uint16_t utf8_length {};  ///< Complete UTF-8 payload length, at most 16 KiB.
    std::vector<std::uint8_t> inline_utf8;  ///< Inline UTF-8 bytes, or empty for object-backed text.
    std::optional<Identifier128> object_id;  ///< Completed object identity for non-inline text.
    std::optional<Digest256> sha256;  ///< Complete object commitment for non-inline text.
  };

  /** @brief Exact five-key text input response. */
  struct TextInputResponsePayload {
    ControlStatus status {ControlStatus::success};  ///< Injection disposition.
    Identifier128 session_id {};  ///< Exact requested session identifier.
    std::uint32_t input_generation {};  ///< Exact requested input generation.
    std::uint64_t preceding_edge_id {};  ///< Exact satisfied edge barrier.
  };

  /** @brief Device class used by authenticated runtime rate renegotiation. */
  enum class InputRateDeviceType : std::uint8_t {
    pointer = 1,  ///< Pointer state reports.
    controller = 2,  ///< Controller state reports.
    sensor = 3,  ///< Controller sensor reports.
    reconciliation = 4,  ///< Core/device reconciliation refreshes.
  };

  /** @brief Exact thirteen-key hot-plug input-rate offer or all-zero rate-tuple removal. */
  struct InputRateRequestPayload {
    Identifier128 session_id {};  ///< Active stream-session identifier.
    std::uint32_t input_generation {};  ///< Exact active input generation.
    InputRateDeviceType device_type {InputRateDeviceType::pointer};  ///< Offered device/report class.
    std::uint16_t device_id {};  ///< Device identifier, zero only for singleton classes.
    std::uint32_t instance_generation {};  ///< Nonzero device incarnation.
    std::uint32_t observed_capture_rate {};  ///< Measured callback rate, or zero with every bound for removal.
    std::uint32_t minimum_state_rate {};  ///< Minimum acceptable state rate, or zero for removal.
    std::uint32_t maximum_state_rate {};  ///< Maximum supported state rate, or zero for removal.
    std::uint32_t minimum_sensor_rate {};  ///< Minimum sensor rate, zero when absent or removing.
    std::uint32_t maximum_sensor_rate {};  ///< Maximum sensor rate, zero when absent or removing.
    std::uint16_t maximum_state_packet_bytes {};  ///< Worst-case state packet bytes, or zero for removal.
    std::uint16_t maximum_sensor_packet_bytes {};  ///< Worst-case sensor bytes, zero when absent or removing.
  };

  /** @brief Exact fourteen-key host-selected input-rate response and aggregate schedule. */
  struct InputRateResponsePayload {
    ControlStatus status {ControlStatus::success};  ///< Selection disposition.
    Identifier128 session_id {};  ///< Exact active session.
    std::uint32_t input_generation {};  ///< Exact active input generation.
    InputRateDeviceType device_type {InputRateDeviceType::pointer};  ///< Exact offered class.
    std::uint16_t device_id {};  ///< Exact offered device identifier.
    std::uint32_t instance_generation {};  ///< Exact offered device incarnation.
    std::uint32_t state_rate {};  ///< Selected state reports per second.
    std::uint32_t sensor_rate {};  ///< Selected sensor reports per second, or zero.
    std::uint32_t pointer_rate {};  ///< Updated aggregate pointer reports per second.
    std::uint32_t controller_rate {};  ///< Updated aggregate controller reports per second.
    std::uint32_t aggregate_sensor_rate {};  ///< Updated aggregate sensor reports per second.
    std::uint32_t reconciliation_rate {};  ///< Updated aggregate reconciliation reports per second.
    std::uint64_t reserved_input_wire_bits_per_second {};  ///< Updated aggregate reserved input budget.
  };

  /** @brief One clipboard bundle replacement, inline or object-backed, sent by either peer. */
  struct ClipboardUpdatePayload {
    Identifier128 session_id {};  ///< Active stream-session identifier.
    std::uint64_t sequence {};  ///< Nonzero sender-local sequence, increasing within one session.
    std::uint32_t content_length {};  ///< Complete clipboard bundle length, at most 16 MiB.
    std::vector<std::uint8_t> inline_content;  ///< Inline bundle bytes, or empty for an object-backed bundle.
    std::optional<Identifier128> object_id;  ///< Completed object identity for non-inline text.
    std::optional<Digest256> sha256;  ///< Complete object commitment for non-inline text.
  };

  /** @brief Exact four-key clipboard update response. */
  struct ClipboardUpdateResponsePayload {
    ControlStatus status {ControlStatus::success};  ///< Clipboard disposition.
    Identifier128 session_id {};  ///< Exact requested session identifier.
    std::uint64_t sequence {};  ///< Exact requested sequence.
  };

  /** @brief Largest clipboard bundle either peer may transfer. */
  inline constexpr std::uint32_t maximum_clipboard_bytes = 16U * 1'024U * 1'024U;

  /** @brief Clipboard bundle entry kinds. */
  enum class ClipboardKind : std::uint8_t {
    text = 1,  ///< UTF-8 plain text with LF line endings.
    html = 2,  ///< UTF-8 HTML markup.
    png = 3,  ///< PNG image.
  };

  /**
   * @brief Validate one clipboard bundle.
   *
   * A bundle is one or more entries of a 1-byte kind, a 4-byte big-endian length, and that many
   * bytes. Each kind appears at most once, text and HTML are valid UTF-8, and PNG data starts with
   * the PNG signature. Unknown kinds are rejected.
   */
  [[nodiscard]] bool valid_clipboard_bundle(std::span<const std::uint8_t> bundle) noexcept;

  /** @brief Largest clipboard bundle carried inline instead of through OBJECT_CHUNK. */
  inline constexpr std::size_t maximum_inline_clipboard_bytes = 768;

  /** @brief Largest cursor width or height. */
  inline constexpr std::uint32_t maximum_cursor_dimension = 256;

  /** @brief Cursor shape bundle header: big-endian u16 width, height, hotspot X, hotspot Y. */
  inline constexpr std::size_t cursor_shape_header_bytes = 8;

  /** @brief Largest cursor shape bundle: header plus premultiplied RGBA pixels. */
  inline constexpr std::uint32_t maximum_cursor_shape_bytes =
    cursor_shape_header_bytes + maximum_cursor_dimension * maximum_cursor_dimension * 4U;

  /** @brief Largest cursor shape bundle carried inline instead of through OBJECT_CHUNK. */
  inline constexpr std::size_t maximum_inline_cursor_shape_bytes = 768;
  /**
   * Standard system cursors carried by kind instead of image: 1 arrow, 2 I-beam, 3 wait,
   * 4 app starting, 5 hand, 6 crosshair, 7 resize west-east, 8 resize north-south,
   * 9 resize northwest-southeast, 10 resize northeast-southwest, 11 move, 12 not allowed,
   * 13 help, 14 up arrow, 15 pin, 16 person.
   */
  inline constexpr std::uint8_t maximum_system_cursor = 16;

  /**
   * @brief Validate one cursor shape bundle.
   *
   * The bundle is an 8-byte header of big-endian u16 width, height, hotspot X, and hotspot Y,
   * followed by exactly width * height premultiplied RGBA pixels. Dimensions are one through 256
   * and the hotspot lies inside the image.
   */
  [[nodiscard]] bool valid_cursor_shape(std::span<const std::uint8_t> shape) noexcept;

  /** @brief Exact eight-key CURSOR_STATE request. */
  struct CursorStatePayload {
    Identifier128 session_id {};  ///< Active stream-session identifier.
    std::uint64_t sequence {};  ///< Nonzero host sequence, increasing within one connection.
    bool visible {};  ///< Whether the host currently shows its cursor.
    std::optional<Digest256> shape_sha256;  ///< SHA-256 of the current shape bundle, or null before any shape.
    std::uint32_t shape_length {};  ///< Carried shape bundle length, or zero when the shape is not carried.
    std::vector<std::uint8_t> inline_shape;  ///< Inline shape bundle, or empty.
    std::optional<Identifier128> object_id;  ///< Completed object carrying a non-inline shape bundle.
    std::uint8_t system_cursor {};  ///< Standard system cursor kind the client draws natively, or 0 for the shape.
  };

  /** @brief Exact five-key successful CURSOR_STATE_RESPONSE. */
  struct CursorStateResponsePayload {
    ControlStatus status {ControlStatus::success};  ///< Cursor disposition.
    Identifier128 session_id {};  ///< Exact requested session identifier.
    std::uint64_t sequence {};  ///< Exact requested sequence.
    bool shape_present {};  ///< Whether the client holds the referenced shape (true when none was referenced).
  };

  /** @brief Decode exact eight-key CURSOR_STATE deterministic CBOR. */
  [[nodiscard]] std::expected<CursorStatePayload, ControlWireError> decode_cursor_state(std::span<const std::uint8_t> payload);

  /** @brief Encode exact eight-key CURSOR_STATE deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_cursor_state(const CursorStatePayload &payload);

  /** @brief Decode exact five-key successful CURSOR_STATE_RESPONSE deterministic CBOR. */
  [[nodiscard]] std::expected<CursorStateResponsePayload, ControlWireError> decode_cursor_state_response(std::span<const std::uint8_t> payload);

  /** @brief Encode exact five-key successful CURSOR_STATE_RESPONSE deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_cursor_state_response(const CursorStateResponsePayload &payload);

  /** @brief Exact four-key generation-bound terminal stream notification. */
  struct StreamEndedPayload {
    Identifier128 session_id {};  ///< Session that reached a terminal state.
    std::uint32_t stream_generation {};  ///< Exact ended stream generation.
    std::uint8_t reason {};  ///< Stable product terminal reason.
  };

  /** @brief Exact six-key bounded contiguous object chunk. */
  struct ObjectChunkPayload {
    Identifier128 object_id {};  ///< Stable object identifier.
    std::uint32_t offset {};  ///< Required contiguous byte offset.
    std::uint32_t total_length {};  ///< Complete object size, at most 16 MiB.
    std::vector<std::uint8_t> bytes;  ///< Nonempty chunk bytes, at most 768.
    Digest256 sha256 {};  ///< Complete-object SHA-256 commitment.
  };

  /** @brief Exact five-key object chunk acknowledgement. */
  struct ObjectChunkAckPayload {
    ControlStatus status {ControlStatus::success};  ///< Contiguous assembly disposition.
    Identifier128 object_id {};  ///< Exact object identifier.
    std::uint32_t next_offset {};  ///< Next required contiguous offset.
    std::uint32_t total_length {};  ///< Exact complete object size.
  };

  /** @brief Decode exact CLIENT_HELLO deterministic CBOR. */
  [[nodiscard]] std::expected<ClientHelloPayload, ControlWireError> decode_client_hello(std::span<const std::uint8_t> payload);

  /** @brief Encode exact SERVER_HELLO deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_server_hello(const ServerHelloPayload &payload);

  /** @brief Decode exact PAIR_BEGIN deterministic CBOR. */
  [[nodiscard]] std::expected<PairBeginPayload, ControlWireError> decode_pair_begin(std::span<const std::uint8_t> payload);

  /** @brief Encode exact PAIR_PENDING deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_pair_pending(const PairPendingPayload &payload);

  /** @brief Decode exact PAIR_POLL deterministic CBOR. */
  [[nodiscard]] std::expected<PairPollPayload, ControlWireError> decode_pair_poll(std::span<const std::uint8_t> payload);

  /** @brief Encode exact PAIR_CHALLENGE deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_pair_challenge(const PairChallengePayload &payload);

  /** @brief Decode exact PAIR_FINISH deterministic CBOR. */
  [[nodiscard]] std::expected<PairFinishPayload, ControlWireError> decode_pair_finish(std::span<const std::uint8_t> payload);

  /** @brief Encode exact PAIR_RESULT deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_pair_result(const PairResultPayload &payload);

  /** @brief Decode exact AUTH_REQUEST deterministic CBOR. */
  [[nodiscard]] std::expected<AuthRequestPayload, ControlWireError> decode_auth_request(std::span<const std::uint8_t> payload);

  /** @brief Encode exact AUTH_RESPONSE deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_auth_response(const AuthResponsePayload &payload);

  /** @brief Encode exact CERT_ROTATE deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_certificate_rotate(const CertificateRotatePayload &payload);

  /** @brief Encode the exact old-identity certificate rotation signature transcript. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_certificate_rotation_transcript(
    const Identifier128 &host_id,
    const PublicKey256 &host_identity_key,
    const Digest256 &current_spki_sha256,
    const Digest256 &new_spki_sha256,
    std::uint32_t connection_generation,
    std::uint32_t rotation_generation
  );

  /** @brief Decode exact CERT_ROTATE_ACK deterministic CBOR. */
  [[nodiscard]] std::expected<CertificateRotateAckPayload, ControlWireError> decode_certificate_rotate_ack(std::span<const std::uint8_t> payload);

  /** @brief Decode exact LIST_APPLICATIONS map `{1: version}`. */
  [[nodiscard]] std::expected<void, ControlWireError> decode_list_applications(std::span<const std::uint8_t> payload);

  /** @brief Encode exact APPLICATIONS map `{1: version, 2: status, 3: entries}`. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_applications(std::span<const ControlApplication> applications);

  /** @brief Decode exact owner-qualified QUIT_APPLICATION deterministic CBOR. */
  [[nodiscard]] std::expected<QuitApplicationPayload, ControlWireError> decode_quit_application(std::span<const std::uint8_t> payload);

  /** @brief Encode exact QUIT_APPLICATION_RESPONSE deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_quit_application_response(const QuitApplicationResponsePayload &payload);

  /** @brief Encode exact error map `{1: version, 2: status}`. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_control_error(ControlStatus status);

  /** @brief Decode an exact two-key generic control error payload. */
  [[nodiscard]] std::expected<ControlStatus, ControlWireError> decode_control_error(std::span<const std::uint8_t> payload);

  /** @brief Decode exact input, audio, and optional-microphone START deterministic CBOR. */
  [[nodiscard]] std::expected<StartRequestPayload, ControlWireError> decode_start(std::span<const std::uint8_t> payload);

  /** @brief Encode exact input, audio, and nullable-microphone START_RESPONSE deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_start_response(const StartResponsePayload &payload);

  /** @brief Decode exact owner-qualified STOP deterministic CBOR. */
  [[nodiscard]] std::expected<StopRequestPayload, ControlWireError> decode_stop(std::span<const std::uint8_t> payload);

  /** @brief Encode exact STOP_RESPONSE map `{1: version, 2: status}`. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_stop_response(ControlStatus status);

  /** @brief Decode exact ATTACH deterministic CBOR. */
  [[nodiscard]] std::expected<AttachRequestPayload, ControlWireError> decode_attach(std::span<const std::uint8_t> payload);

  /** @brief Encode exact ATTACH_RESPONSE deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_attach_response(const AttachResponsePayload &payload);

  /** @brief Encode exact VIDEO_CONFIG deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_video_config(const VideoConfigPayload &payload);

  /** @brief Decode exact VIDEO_CONFIG_ACK deterministic CBOR. */
  [[nodiscard]] std::expected<VideoConfigAckPayload, ControlWireError> decode_video_config_ack(std::span<const std::uint8_t> payload);

  /** @brief Encode exact AUDIO_CONFIG deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_audio_config(const AudioConfigPayload &payload);

  /** @brief Decode exact AUDIO_CONFIG_ACK deterministic CBOR. */
  [[nodiscard]] std::expected<AudioConfigAckPayload, ControlWireError> decode_audio_config_ack(std::span<const std::uint8_t> payload);

  /** @brief Encode exact MICROPHONE_CONFIG deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_microphone_config(const MicrophoneConfigPayload &payload);

  /** @brief Decode exact MICROPHONE_CONFIG_ACK deterministic CBOR. */
  [[nodiscard]] std::expected<MicrophoneConfigAckPayload, ControlWireError> decode_microphone_config_ack(std::span<const std::uint8_t> payload);

  /** @brief Encode exact PATH_PROBE or PATH_PROBE_ACK deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_path_probe(const PathProbePayload &payload);

  /** @brief Decode exact PATH_PROBE or PATH_PROBE_ACK deterministic CBOR. */
  [[nodiscard]] std::expected<PathProbePayload, ControlWireError> decode_path_probe(std::span<const std::uint8_t> payload);

  /** @brief Decode exact TEXT_INPUT deterministic CBOR. */
  [[nodiscard]] std::expected<TextInputPayload, ControlWireError> decode_text_input(std::span<const std::uint8_t> payload);

  /** @brief Encode exact TEXT_INPUT_RESPONSE deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_text_input_response(const TextInputResponsePayload &payload);

  /** @brief Decode exact INPUT_RATE_REQUEST deterministic CBOR. */
  [[nodiscard]] std::expected<InputRateRequestPayload, ControlWireError> decode_input_rate_request(std::span<const std::uint8_t> payload);

  /** @brief Encode exact fourteen-key INPUT_RATE_RESPONSE deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_input_rate_response(const InputRateResponsePayload &payload);

  /** @brief Encode exact generation-bound STREAM_ENDED deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_stream_ended(const StreamEndedPayload &payload);

  /** @brief Decode exact seven-key CLIPBOARD_UPDATE deterministic CBOR. */
  [[nodiscard]] std::expected<ClipboardUpdatePayload, ControlWireError> decode_clipboard_update(std::span<const std::uint8_t> payload);

  /** @brief Encode exact seven-key CLIPBOARD_UPDATE deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_clipboard_update(const ClipboardUpdatePayload &payload);

  /** @brief Decode exact four-key successful CLIPBOARD_UPDATE_RESPONSE deterministic CBOR. */
  [[nodiscard]] std::expected<ClipboardUpdateResponsePayload, ControlWireError> decode_clipboard_update_response(std::span<const std::uint8_t> payload);

  /** @brief Encode exact four-key successful CLIPBOARD_UPDATE_RESPONSE deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_clipboard_update_response(const ClipboardUpdateResponsePayload &payload);

  /** @brief Decode one exact OBJECT_CHUNK request deterministic CBOR. */
  [[nodiscard]] std::expected<ObjectChunkPayload, ControlWireError> decode_object_chunk(std::span<const std::uint8_t> payload);

  /** @brief Encode one exact OBJECT_CHUNK request deterministic CBOR. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_object_chunk(const ObjectChunkPayload &payload);

  /** @brief Decode one exact response-flagged OBJECT_CHUNK acknowledgement payload. */
  [[nodiscard]] std::expected<ObjectChunkAckPayload, ControlWireError> decode_object_chunk_ack(std::span<const std::uint8_t> payload);

  /** @brief Encode one exact response-flagged OBJECT_CHUNK acknowledgement payload. */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, ControlWireError> encode_object_chunk_ack(const ObjectChunkAckPayload &payload);
}  // namespace lumen::lsp::runtime
