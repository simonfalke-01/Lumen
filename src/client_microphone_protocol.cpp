/**
 * @file src/client_microphone_protocol.cpp
 * @brief Portable Lumen client-microphone datagram parser and serializer.
 */

// local includes
#include "client_microphone_protocol.h"

// standard includes
#include <algorithm>

namespace client_microphone::protocol {
  namespace {
    /** Byte offset of the type field. */
    constexpr std::size_t type_offset = offsetof(wire_header_t, type);

    /** Byte offset of the flags field. */
    constexpr std::size_t flags_offset = offsetof(wire_header_t, flags);

    /** Byte offset of the header-length field. */
    constexpr std::size_t header_length_offset = offsetof(wire_header_t, header_length);

    /** Byte offset of the session-identifier field. */
    constexpr std::size_t session_id_offset = offsetof(wire_header_t, session_id);

    /** Byte offset of the packet-sequence field. */
    constexpr std::size_t packet_sequence_offset = offsetof(wire_header_t, packet_sequence);

    /** Byte offset of the timestamp field. */
    constexpr std::size_t timestamp_offset = offsetof(wire_header_t, timestamp_48khz);

    /** Byte offset of the ciphertext-length field. */
    constexpr std::size_t ciphertext_length_offset = offsetof(wire_header_t, ciphertext_length);

    /** Byte offset of the reserved field. */
    constexpr std::size_t reserved_offset = offsetof(wire_header_t, reserved);

    /**
     * @brief Read an unsigned integer from a big-endian byte sequence.
     *
     * @tparam Integer Unsigned destination integer type.
     * @param bytes Exact-width big-endian bytes.
     * @return Host-order integer value.
     */
    template<typename Integer>
    [[nodiscard]] constexpr Integer read_big_endian(const std::span<const std::uint8_t, sizeof(Integer)> bytes) noexcept {
      Integer value = 0;
      for (const auto byte : bytes) {
        value = static_cast<Integer>((value << 8U) | byte);
      }
      return value;
    }

    /**
     * @brief Append an unsigned integer in big-endian byte order.
     *
     * @tparam Integer Unsigned source integer type.
     * @param output Destination datagram.
     * @param value Host-order integer value.
     */
    template<typename Integer>
    void append_big_endian(std::vector<std::uint8_t> &output, const Integer value) {
      for (std::size_t index = sizeof(Integer); index > 0; --index) {
        const auto shift = static_cast<unsigned>((index - 1U) * 8U);
        output.push_back(static_cast<std::uint8_t>(value >> shift));
      }
    }

    /**
     * @brief Convert and validate a raw version-one packet type.
     *
     * @param raw_type Type byte from a packet or host object.
     * @return Validated packet type or `invalid_type`.
     */
    [[nodiscard]] std::expected<packet_type_t, error_t> parse_type(const std::uint8_t raw_type) {
      switch (raw_type) {
        case static_cast<std::uint8_t>(packet_type_t::hello):
          return packet_type_t::hello;
        case static_cast<std::uint8_t>(packet_type_t::audio):
          return packet_type_t::audio;
        case static_cast<std::uint8_t>(packet_type_t::reset):
          return packet_type_t::reset;
        case static_cast<std::uint8_t>(packet_type_t::end):
          return packet_type_t::end;
        default:
          return std::unexpected(error_t::invalid_type);
      }
    }

    /**
     * @brief Validate type, flags, and ciphertext semantics.
     *
     * @param type Packet type.
     * @param flags Packet flags.
     * @param ciphertext_size Encrypted payload byte length.
     * @return No value on success, or the first semantic framing error.
     */
    [[nodiscard]] std::expected<void, error_t> validate_semantics(
      const packet_type_t type,
      const std::uint8_t flags,
      const std::size_t ciphertext_size
    ) {
      if ((flags & static_cast<std::uint8_t>(~valid_flags)) != 0) {
        return std::unexpected(error_t::invalid_flags);
      }

      if (type != packet_type_t::audio && flags != 0) {
        return std::unexpected(error_t::invalid_type_flags);
      }

      if (ciphertext_size > maximum_ciphertext_size) {
        return std::unexpected(error_t::ciphertext_too_large);
      }

      if (type != packet_type_t::audio && ciphertext_size != 0) {
        return std::unexpected(error_t::control_packet_has_ciphertext);
      }

      if (type == packet_type_t::audio && (flags & flag_silence) == 0 && ciphertext_size == 0) {
        return std::unexpected(error_t::audio_packet_missing_ciphertext);
      }

      if (type == packet_type_t::audio && (flags & flag_silence) != 0 && ciphertext_size != 0) {
        return std::unexpected(error_t::silence_packet_has_ciphertext);
      }

      return {};
    }
  }  // namespace

  std::expected<packet_t, error_t> parse(const std::span<const std::uint8_t> datagram) {
    if (datagram.size() < fixed_header_size) {
      return std::unexpected(error_t::truncated_header);
    }

    if (!std::equal(magic.begin(), magic.end(), datagram.begin())) {
      return std::unexpected(error_t::invalid_magic);
    }

    const auto type = parse_type(datagram[type_offset]);
    if (!type) {
      return std::unexpected(type.error());
    }

    const auto flags = datagram[flags_offset];
    if ((flags & static_cast<std::uint8_t>(~valid_flags)) != 0) {
      return std::unexpected(error_t::invalid_flags);
    }

    if (*type != packet_type_t::audio && flags != 0) {
      return std::unexpected(error_t::invalid_type_flags);
    }

    const auto header_length = read_big_endian<std::uint16_t>(datagram.subspan<header_length_offset, sizeof(std::uint16_t)>());
    if (header_length != fixed_header_size) {
      return std::unexpected(error_t::invalid_header_length);
    }

    const auto ciphertext_size = read_big_endian<std::uint16_t>(datagram.subspan<ciphertext_length_offset, sizeof(std::uint16_t)>());
    if (ciphertext_size > maximum_ciphertext_size) {
      return std::unexpected(error_t::ciphertext_too_large);
    }

    if (datagram[reserved_offset] != 0 || datagram[reserved_offset + 1] != 0) {
      return std::unexpected(error_t::nonzero_reserved);
    }

    if (datagram.size() < minimum_datagram_size) {
      return std::unexpected(error_t::truncated_authentication_tag);
    }

    const auto expected_size = minimum_datagram_size + ciphertext_size;
    if (datagram.size() < expected_size) {
      return std::unexpected(error_t::truncated_ciphertext);
    }
    if (datagram.size() > expected_size) {
      return std::unexpected(error_t::trailing_data);
    }

    if (const auto validation = validate_semantics(*type, flags, ciphertext_size); !validation) {
      return std::unexpected(validation.error());
    }

    packet_t packet;
    packet.type = *type;
    packet.flags = flags;
    std::copy_n(datagram.begin() + session_id_offset, packet.session_id.size(), packet.session_id.begin());
    packet.packet_sequence = read_big_endian<std::uint64_t>(datagram.subspan<packet_sequence_offset, sizeof(std::uint64_t)>());
    packet.timestamp_48khz = read_big_endian<std::uint32_t>(datagram.subspan<timestamp_offset, sizeof(std::uint32_t)>());
    packet.ciphertext.assign(datagram.begin() + fixed_header_size, datagram.begin() + fixed_header_size + ciphertext_size);
    std::copy_n(datagram.end() - authentication_tag_size, authentication_tag_size, packet.authentication_tag.begin());
    std::copy_n(datagram.begin(), fixed_header_size, packet.authenticated_header.begin());
    return packet;
  }

  std::expected<std::vector<std::uint8_t>, error_t> serialize(const packet_t &packet) {
    const auto raw_type = static_cast<std::uint8_t>(packet.type);
    const auto type = parse_type(raw_type);
    if (!type) {
      return std::unexpected(type.error());
    }

    if (const auto validation = validate_semantics(*type, packet.flags, packet.ciphertext.size()); !validation) {
      return std::unexpected(validation.error());
    }

    std::vector<std::uint8_t> datagram;
    datagram.reserve(fixed_header_size + packet.ciphertext.size() + authentication_tag_size);
    datagram.insert(datagram.end(), magic.begin(), magic.end());
    datagram.push_back(raw_type);
    datagram.push_back(packet.flags);
    append_big_endian(datagram, static_cast<std::uint16_t>(fixed_header_size));
    datagram.insert(datagram.end(), packet.session_id.begin(), packet.session_id.end());
    append_big_endian(datagram, packet.packet_sequence);
    append_big_endian(datagram, packet.timestamp_48khz);
    append_big_endian(datagram, static_cast<std::uint16_t>(packet.ciphertext.size()));
    append_big_endian(datagram, static_cast<std::uint16_t>(0));
    datagram.insert(datagram.end(), packet.ciphertext.begin(), packet.ciphertext.end());
    datagram.insert(datagram.end(), packet.authentication_tag.begin(), packet.authentication_tag.end());
    return datagram;
  }
}  // namespace client_microphone::protocol
