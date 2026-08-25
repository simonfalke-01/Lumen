/**
 * @file src/rtsp.h
 * @brief Declarations for RTSP streaming.
 */
#pragma once

// standard includes
#include <array>
#include <atomic>
#include <charconv>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

extern "C" {
#include <moonlight-common-c/src/Video.h>
}

// local includes
#include "config.h"
#include "crypto.h"
#include "thread_safe.h"

namespace rtsp_stream {
  constexpr auto RTSP_SETUP_PORT = 21;  ///< GameStream base-port offset used for the RTSP setup listener.

  /**
   * @brief Validate a client-announced GameStream video packet size.
   *
   * The complete UDP datagram must fit both the packetizer's 64-KiB block cap
   * and the conservative IPv4 UDP payload limit after RTP and optional video
   * encryption prefixes are included.
   *
   * @param packet_size Client-announced `x-nv-video[0].packetSize` value.
   * @param video_encryption Whether a GameStream video encryption prefix is enabled.
   * @return `true` only when the announced value is safe for packetization and transport.
   */
  [[nodiscard]] inline bool validate_video_packet_size(const std::int64_t packet_size, const bool video_encryption) {
    constexpr auto maximum_packetizer_block_size = std::int64_t {64U * 1024U};
    constexpr auto maximum_ipv4_udp_payload = std::int64_t {65507};
    const auto encryption_prefix_size = video_encryption ? static_cast<std::int64_t>(sizeof(ENC_VIDEO_HEADER)) : 0;
    return packet_size >= config::PACKETSIZE_MIN &&
           packet_size <= config::PACKETSIZE_MAX &&
           packet_size <= maximum_packetizer_block_size - MAX_RTP_HEADER_SIZE &&
           packet_size <= maximum_ipv4_udp_payload - MAX_RTP_HEADER_SIZE - encryption_prefix_size;
  }

  /**
   * @brief Strictly parse and validate a client-announced video packet size.
   * @param value Complete decimal SDP attribute value.
   * @param video_encryption Whether video encryption is enabled for the session.
   * @return Safe packet size, or `std::nullopt` for malformed, overflowing, or unsafe input.
   */
  [[nodiscard]] inline std::optional<int> parse_video_packet_size(
    const std::string_view value,
    const bool video_encryption
  ) {
    std::int64_t parsed {};
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (result.ec != std::errc {} || result.ptr != value.data() + value.size() || !validate_video_packet_size(parsed, video_encryption)) {
      return std::nullopt;
    }
    return static_cast<int>(parsed);
  }

  /**
   * @brief Exact SDP attributes advertising Lumen client-microphone version one.
   */
  inline constexpr std::string_view CLIENT_MICROPHONE_DESCRIBE_ATTRIBUTES =
    "a=x-lumen-mic.version:1\r\n"
    "a=x-lumen-mic.codec:opus\r\n"
    "a=x-lumen-mic.sampleRate:48000\r\n"
    "a=x-lumen-mic.channels:1\r\n"
    "a=x-lumen-mic.packetDurationMs:20\r\n"
    "a=x-lumen-mic.crypto:aes-256-gcm\r\n"
    "a=x-lumen-mic.fec:opus-inband\r\n";

  /**
   * @brief Validate the complete Umbra microphone ANNOUNCE extension.
   *
   * @param attributes Parsed SDP attribute name/value pairs.
   * @return `true` only when every required version-one value is present and exact.
   */
  [[nodiscard]] bool validate_client_microphone_announce(
    const std::unordered_map<std::string_view, std::string_view> &attributes
  );

  /**
   * @brief Determine whether an RTSP target requests the version-one Lumen microphone stream.
   *
   * @param target Complete RTSP SETUP request target.
   * @return `true` only for the `streamid=lumen-mic/1/0` media target.
   */
  [[nodiscard]] bool is_client_microphone_setup_target(std::string_view target);

  /**
   * @brief Encode a microphone session identifier or salt as forward lowercase hexadecimal.
   * @param bytes Exact 16-byte RTSP microphone credential.
   * @return Thirty-two lowercase hexadecimal characters in input byte order.
   */
  [[nodiscard]] std::string encode_client_microphone_hex(const std::array<std::uint8_t, 16> &bytes);

  /**
   * @brief RTSP launch session state shared with stream setup.
   */
  struct launch_session_t {
    uint32_t id;  ///< RTSP launch-session identifier assigned before stream startup.

    crypto::aes_t gcm_key;  ///< AES-GCM key negotiated for encrypted RTSP messages.
    crypto::aes_t iv;  ///< Initial RTSP AES-GCM IV supplied by the client.

    std::string av_ping_payload;  ///< AV ping payload.
    uint32_t control_connect_data;  ///< Client-provided token used when connecting the control channel.

    bool host_audio;  ///< Whether host audio should be played locally.
    std::string unique_id;  ///< Moonlight client unique identifier for this launch request.
    int width;  ///< Frame or display width in pixels.
    int height;  ///< Frame or display height in pixels.
    int fps;  ///< Requested video frame rate.
    std::uint32_t refresh_numerator {};  ///< Exact requested refresh numerator when available.
    std::uint32_t refresh_denominator {};  ///< Exact requested refresh denominator when available.
    int gcmap;  ///< Game controller mapping requested by the client.
    int appid;  ///< Application ID requested for launch or resume.
    int surround_info;  ///< Encoded GameStream surround-sound capability flags.
    std::string surround_params;  ///< Client-provided surround-sound layout parameters.
    bool continuous_audio;  ///< Whether audio packets continue during silence.
    bool enable_hdr;  ///< Whether HDR streaming is requested.
    bool enable_sops;  ///< Whether sequence output protection is requested.

    bool client_microphone_setup {};  ///< Whether the client completed version-one microphone SETUP.
    std::array<std::uint8_t, 16> client_microphone_session_id {};  ///< Public microphone UDP routing identifier.
    std::array<std::uint8_t, 16> client_microphone_salt {};  ///< Independent HKDF salt for microphone key derivation.

    std::optional<crypto::cipher::gcm_t> rtsp_cipher;  ///< AES-GCM cipher used once encrypted RTSP is negotiated.
    std::string rtsp_url_scheme;  ///< URL scheme selected by the RTSP SETUP flow.
    uint32_t rtsp_iv_counter;  ///< Counter value mixed into encrypted RTSP IVs.
    std::string client_cert;  ///< PEM certificate for the paired Moonlight client.
  };

  /**
   * @brief Queue a launch session until the RTSP client connects.
   *
   * @param launch_session Session state prepared by the GameStream launch handler.
   */
  void launch_session_raise(std::shared_ptr<launch_session_t> launch_session);

  /**
   * @brief Clear state for the specified launch session.
   * @param launch_session_id The ID of the session to clear.
   */
  void launch_session_clear(uint32_t launch_session_id);

  /**
   * @brief Get the number of active sessions.
   * @return Count of active sessions.
   */
  int session_count();
  /**
   * @brief Check whether any active or not-yet-attached launch session exists.
   * @return True when process/display teardown would affect another session.
   */
  bool has_session_or_pending_launch();

  /**
   * @brief Terminates all running streaming sessions.
   */
  void terminate_sessions();
  /**
   * @brief Terminate active sessions associated with a client certificate.
   *
   * @param cert Certificate data or object used by the operation.
   */
  std::size_t terminate_sessions_by_cert(std::string_view cert);

  [[nodiscard]] inline bool session_owned_by_certificate(
    std::string_view session_certificate,
    std::string_view requester_certificate
  ) {
    return !requester_certificate.empty() && session_certificate == requester_certificate;
  }

  /**
   * @brief Runs the RTSP server loop.
   */
  void start();
}  // namespace rtsp_stream
