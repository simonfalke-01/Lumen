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
    path_probe = 0x0300,  ///< Establish authenticated intent for one exact-size SRTCP path probe.
    path_probe_ack = 0x0301,  ///< Confirm one authenticated exact-size path probe.
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

  /** @brief Exact START sixteen-key request map including video schema revision three. */
  struct StartRequestPayload {
    std::string application_id;  ///< Configured application ID selected for input ownership.
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
}  // namespace lumen::lsp::runtime
