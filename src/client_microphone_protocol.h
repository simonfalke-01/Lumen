/**
 * @file src/client_microphone_protocol.h
 * @brief Portable Lumen client-microphone datagram wire protocol.
 */
#pragma once

// standard includes
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <type_traits>
#include <vector>

namespace client_microphone::protocol {
  /** Wire magic identifying a version-one Lumen microphone datagram. */
  inline constexpr std::array<std::uint8_t, 4> magic {'L', 'M', 'C', '1'};

  /** Exact byte length of the fixed authenticated header. */
  inline constexpr std::size_t fixed_header_size = 40;

  /** Exact byte length of the AES-256-GCM authentication tag. */
  inline constexpr std::size_t authentication_tag_size = 16;

  /** Maximum encrypted Opus payload length accepted by protocol version one. */
  inline constexpr std::size_t maximum_ciphertext_size = 1275;

  /** Smallest valid datagram, containing a header and authentication tag only. */
  inline constexpr std::size_t minimum_datagram_size = fixed_header_size + authentication_tag_size;

  /** Largest valid datagram, containing the maximum ciphertext and authentication tag. */
  inline constexpr std::size_t maximum_datagram_size = fixed_header_size + maximum_ciphertext_size + authentication_tag_size;

  /** The only version-one flag, marking an audio-timeline silence packet. */
  inline constexpr std::uint8_t flag_silence = 0x01;

  /** Bit mask containing every flag defined by protocol version one. */
  inline constexpr std::uint8_t valid_flags = flag_silence;

  /** Version-one datagram types. */
  enum class packet_type_t : std::uint8_t {
    hello = 1,  ///< Starts one authenticated microphone generation.
    audio = 2,  ///< Carries Opus ciphertext or a SILENCE timeline marker.
    reset = 3,  ///< Resets decoder state without ending the generation.
    end = 4  ///< Ends one authenticated microphone generation.
  };

#pragma pack(push, 1)

  /**
   * @brief Exact packed 40-byte LMC1 version-one wire header.
   *
   * Multi-byte integer members are byte arrays because their wire representation is
   * always big-endian and must not depend on host alignment or byte order.
   */
  struct wire_header_t {
    std::array<std::uint8_t, 4> magic;  ///< ASCII `LMC1` datagram discriminator.
    std::uint8_t type;  ///< One version-one packet type.
    std::uint8_t flags;  ///< Zero or `flag_silence` for an AUDIO packet.
    std::array<std::uint8_t, 2> header_length;  ///< Big-endian fixed header length, always 40.
    std::array<std::uint8_t, 16> session_id;  ///< Public opaque microphone session identifier.
    std::array<std::uint8_t, 8> packet_sequence;  ///< Big-endian per-generation packet sequence.
    std::array<std::uint8_t, 4> timestamp_48khz;  ///< Big-endian timestamp on the 48 kHz audio clock.
    std::array<std::uint8_t, 2> ciphertext_length;  ///< Big-endian ciphertext byte length.
    std::array<std::uint8_t, 2> reserved;  ///< Reserved bytes, both zero in version one.
  };

#pragma pack(pop)

  static_assert(sizeof(wire_header_t) == fixed_header_size, "LMC1 header ABI must remain exactly 40 bytes");
  static_assert(offsetof(wire_header_t, magic) == 0, "LMC1 magic offset changed");
  static_assert(offsetof(wire_header_t, type) == 4, "LMC1 type offset changed");
  static_assert(offsetof(wire_header_t, flags) == 5, "LMC1 flags offset changed");
  static_assert(offsetof(wire_header_t, header_length) == 6, "LMC1 header length offset changed");
  static_assert(offsetof(wire_header_t, session_id) == 8, "LMC1 session identifier offset changed");
  static_assert(offsetof(wire_header_t, packet_sequence) == 24, "LMC1 packet sequence offset changed");
  static_assert(offsetof(wire_header_t, timestamp_48khz) == 32, "LMC1 timestamp offset changed");
  static_assert(offsetof(wire_header_t, ciphertext_length) == 36, "LMC1 ciphertext length offset changed");
  static_assert(offsetof(wire_header_t, reserved) == 38, "LMC1 reserved offset changed");
  static_assert(std::is_trivially_copyable_v<wire_header_t>, "LMC1 header must remain trivially copyable");

  /** Classification returned when a packet cannot be parsed or serialized. */
  enum class error_t {
    truncated_header,  ///< The datagram does not contain the entire fixed header.
    invalid_magic,  ///< The datagram does not begin with ASCII `LMC1`.
    invalid_type,  ///< The type is not defined by protocol version one.
    invalid_flags,  ///< The flags contain an undefined version-one bit.
    invalid_type_flags,  ///< A non-AUDIO packet has a flag set.
    invalid_header_length,  ///< The advertised fixed header length is not 40.
    ciphertext_too_large,  ///< The advertised or supplied ciphertext exceeds 1,275 bytes.
    nonzero_reserved,  ///< A reserved version-one header byte is nonzero.
    truncated_authentication_tag,  ///< The datagram cannot contain a complete GCM tag.
    truncated_ciphertext,  ///< The datagram is shorter than its advertised ciphertext length.
    trailing_data,  ///< The datagram is longer than its advertised ciphertext length.
    control_packet_has_ciphertext,  ///< HELLO, RESET, or END incorrectly contains ciphertext.
    audio_packet_missing_ciphertext,  ///< A non-SILENCE AUDIO packet has no ciphertext.
    silence_packet_has_ciphertext  ///< A SILENCE AUDIO packet incorrectly contains ciphertext.
  };

  /**
   * @brief Host-order representation of one authenticated client-microphone packet.
   */
  struct packet_t {
    packet_type_t type {packet_type_t::hello};  ///< Version-one packet type.
    std::uint8_t flags {};  ///< Zero or `flag_silence` for an AUDIO packet.
    std::array<std::uint8_t, 16> session_id {};  ///< Public opaque microphone session identifier.
    std::uint64_t packet_sequence {};  ///< Per-generation sequence used in the GCM nonce.
    std::uint32_t timestamp_48khz {};  ///< Timestamp on the 48 kHz audio clock.
    std::vector<std::uint8_t> ciphertext;  ///< AES-GCM ciphertext containing at most 1,275 Opus bytes.
    std::array<std::uint8_t, authentication_tag_size> authentication_tag {};  ///< AES-GCM tag.
    std::array<std::uint8_t, fixed_header_size> authenticated_header {};  ///< Exact received header bytes used as GCM AAD.
  };

  /**
   * @brief Parse and validate one complete LMC1 version-one UDP datagram.
   *
   * This function validates framing only. The caller must authenticate and decrypt
   * the returned ciphertext before handing it to an Opus decoder.
   *
   * @param datagram Complete UDP datagram bytes.
   * @return Parsed host-order packet, or the first framing error encountered.
   */
  [[nodiscard]] std::expected<packet_t, error_t> parse(std::span<const std::uint8_t> datagram);

  /**
   * @brief Validate and serialize one LMC1 version-one UDP datagram.
   *
   * @param packet Host-order packet with ciphertext and its authentication tag.
   * @return Exact wire bytes, or a packet validation error.
   */
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, error_t> serialize(const packet_t &packet);
}  // namespace client_microphone::protocol
