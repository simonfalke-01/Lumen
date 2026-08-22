/**
 * @file tests/unit/test_client_microphone_protocol.cpp
 * @brief Test the portable LMC1 client-microphone wire protocol.
 */

#include <gtest/gtest.h>

// local includes
#include <src/client_microphone_protocol.h>

// standard includes
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <vector>

namespace {
  namespace microphone_protocol = client_microphone::protocol;

  /**
   * @brief Construct a valid AUDIO packet with nontrivial integer values.
   * @return Packet suitable for serialization and mutation tests.
   */
  microphone_protocol::packet_t make_audio_packet() {
    microphone_protocol::packet_t packet;
    packet.type = microphone_protocol::packet_type_t::audio;
    for (std::size_t index = 0; index < packet.session_id.size(); ++index) {
      packet.session_id[index] = static_cast<std::uint8_t>(0x10U + index);
    }
    packet.packet_sequence = UINT64_C(0x0102030405060708);
    packet.timestamp_48khz = UINT32_C(0x11223344);
    packet.ciphertext = {0xde, 0xad, 0xbe, 0xef};
    for (std::size_t index = 0; index < packet.authentication_tag.size(); ++index) {
      packet.authentication_tag[index] = static_cast<std::uint8_t>(0xa0U + index);
    }
    return packet;
  }

  /**
   * @brief Serialize a known-valid AUDIO packet and fail the current test on error.
   * @return Serialized datagram, or an empty vector after a test failure.
   */
  std::vector<std::uint8_t> make_audio_datagram() {
    auto serialized = microphone_protocol::serialize(make_audio_packet());
    if (!serialized) {
      ADD_FAILURE() << "Known-valid microphone packet did not serialize";
      return {};
    }
    return std::move(*serialized);
  }

  /**
   * @brief Construct a valid payload-free control packet.
   * @param type HELLO, RESET, or END packet type.
   * @return Valid control packet.
   */
  microphone_protocol::packet_t make_control_packet(const microphone_protocol::packet_type_t type) {
    auto packet = make_audio_packet();
    packet.type = type;
    packet.ciphertext.clear();
    return packet;
  }
}  // namespace

TEST(ClientMicrophoneProtocolTest, UsesExactPackedWireAbi) {
  using microphone_protocol::wire_header_t;

  EXPECT_EQ(sizeof(wire_header_t), 40U);
  EXPECT_EQ(offsetof(wire_header_t, magic), 0U);
  EXPECT_EQ(offsetof(wire_header_t, type), 4U);
  EXPECT_EQ(offsetof(wire_header_t, flags), 5U);
  EXPECT_EQ(offsetof(wire_header_t, header_length), 6U);
  EXPECT_EQ(offsetof(wire_header_t, session_id), 8U);
  EXPECT_EQ(offsetof(wire_header_t, packet_sequence), 24U);
  EXPECT_EQ(offsetof(wire_header_t, timestamp_48khz), 32U);
  EXPECT_EQ(offsetof(wire_header_t, ciphertext_length), 36U);
  EXPECT_EQ(offsetof(wire_header_t, reserved), 38U);
  EXPECT_TRUE(std::is_trivially_copyable_v<wire_header_t>);
  EXPECT_EQ(microphone_protocol::minimum_datagram_size, 56U);
  EXPECT_EQ(microphone_protocol::maximum_datagram_size, 1331U);
}

TEST(ClientMicrophoneProtocolTest, SerializesExactBigEndianWireBytes) {
  const auto datagram = make_audio_datagram();
  ASSERT_EQ(datagram.size(), 60U);

  const std::array<std::uint8_t, 40> expected_header {
    'L',
    'M',
    'C',
    '1',
    0x02,
    0x00,
    0x00,
    0x28,
    0x10,
    0x11,
    0x12,
    0x13,
    0x14,
    0x15,
    0x16,
    0x17,
    0x18,
    0x19,
    0x1a,
    0x1b,
    0x1c,
    0x1d,
    0x1e,
    0x1f,
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
    0x11,
    0x22,
    0x33,
    0x44,
    0x00,
    0x04,
    0x00,
    0x00
  };
  EXPECT_TRUE(std::equal(expected_header.begin(), expected_header.end(), datagram.begin()));
  EXPECT_EQ(std::vector<std::uint8_t>(datagram.begin() + 40, datagram.begin() + 44), (std::vector<std::uint8_t> {0xde, 0xad, 0xbe, 0xef}));

  std::array<std::uint8_t, 16> expected_tag {};
  for (std::size_t index = 0; index < expected_tag.size(); ++index) {
    expected_tag[index] = static_cast<std::uint8_t>(0xa0U + index);
  }
  EXPECT_TRUE(std::equal(expected_tag.begin(), expected_tag.end(), datagram.end() - 16));
}

TEST(ClientMicrophoneProtocolTest, ParsesExactBigEndianWireBytesAndPreservesAad) {
  const auto datagram = make_audio_datagram();
  const auto parsed = microphone_protocol::parse(datagram);
  ASSERT_TRUE(parsed);

  EXPECT_EQ(parsed->type, microphone_protocol::packet_type_t::audio);
  EXPECT_EQ(parsed->flags, 0U);
  EXPECT_EQ(parsed->session_id, make_audio_packet().session_id);
  EXPECT_EQ(parsed->packet_sequence, UINT64_C(0x0102030405060708));
  EXPECT_EQ(parsed->timestamp_48khz, UINT32_C(0x11223344));
  EXPECT_EQ(parsed->ciphertext, (std::vector<std::uint8_t> {0xde, 0xad, 0xbe, 0xef}));
  EXPECT_EQ(parsed->authentication_tag, make_audio_packet().authentication_tag);
  EXPECT_TRUE(std::equal(parsed->authenticated_header.begin(), parsed->authenticated_header.end(), datagram.begin()));
}

TEST(ClientMicrophoneProtocolTest, AcceptsEveryControlType) {
  for (const auto type : {
         microphone_protocol::packet_type_t::hello,
         microphone_protocol::packet_type_t::reset,
         microphone_protocol::packet_type_t::end,
       }) {
    const auto serialized = microphone_protocol::serialize(make_control_packet(type));
    ASSERT_TRUE(serialized) << "type=" << static_cast<unsigned>(type);
    EXPECT_EQ(serialized->size(), microphone_protocol::minimum_datagram_size);
    const auto parsed = microphone_protocol::parse(*serialized);
    ASSERT_TRUE(parsed) << "type=" << static_cast<unsigned>(type);
    EXPECT_EQ(parsed->type, type);
    EXPECT_TRUE(parsed->ciphertext.empty());
  }
}

TEST(ClientMicrophoneProtocolTest, AcceptsSilenceAudioPacket) {
  auto packet = make_audio_packet();
  packet.flags = microphone_protocol::flag_silence;
  packet.ciphertext.clear();
  packet.timestamp_48khz = 960;

  const auto serialized = microphone_protocol::serialize(packet);
  ASSERT_TRUE(serialized);
  const auto parsed = microphone_protocol::parse(*serialized);
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed->flags, microphone_protocol::flag_silence);
  EXPECT_EQ(parsed->timestamp_48khz, 960U);
  EXPECT_TRUE(parsed->ciphertext.empty());
}

TEST(ClientMicrophoneProtocolTest, AcceptsMaximumCiphertext) {
  auto packet = make_audio_packet();
  packet.ciphertext.assign(microphone_protocol::maximum_ciphertext_size, 0x7f);

  const auto serialized = microphone_protocol::serialize(packet);
  ASSERT_TRUE(serialized);
  EXPECT_EQ(serialized->size(), microphone_protocol::maximum_datagram_size);
  const auto parsed = microphone_protocol::parse(*serialized);
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed->ciphertext, packet.ciphertext);
}

TEST(ClientMicrophoneProtocolTest, RejectsTruncatedHeader) {
  const std::vector<std::uint8_t> datagram(microphone_protocol::fixed_header_size - 1, 0);
  const auto parsed = microphone_protocol::parse(datagram);
  ASSERT_FALSE(parsed);
  EXPECT_EQ(parsed.error(), microphone_protocol::error_t::truncated_header);
}

TEST(ClientMicrophoneProtocolTest, RejectsInvalidMagic) {
  auto datagram = make_audio_datagram();
  datagram[0] = 'X';
  const auto parsed = microphone_protocol::parse(datagram);
  ASSERT_FALSE(parsed);
  EXPECT_EQ(parsed.error(), microphone_protocol::error_t::invalid_magic);
}

TEST(ClientMicrophoneProtocolTest, RejectsInvalidTypeWhenParsingAndSerializing) {
  auto datagram = make_audio_datagram();
  datagram[4] = 5;
  const auto parsed = microphone_protocol::parse(datagram);
  ASSERT_FALSE(parsed);
  EXPECT_EQ(parsed.error(), microphone_protocol::error_t::invalid_type);

  auto packet = make_audio_packet();
  packet.type = static_cast<microphone_protocol::packet_type_t>(0);
  const auto serialized = microphone_protocol::serialize(packet);
  ASSERT_FALSE(serialized);
  EXPECT_EQ(serialized.error(), microphone_protocol::error_t::invalid_type);
}

TEST(ClientMicrophoneProtocolTest, RejectsUnknownFlagsWhenParsingAndSerializing) {
  auto datagram = make_audio_datagram();
  datagram[5] = 0x02;
  const auto parsed = microphone_protocol::parse(datagram);
  ASSERT_FALSE(parsed);
  EXPECT_EQ(parsed.error(), microphone_protocol::error_t::invalid_flags);

  auto packet = make_audio_packet();
  packet.flags = 0x02;
  const auto serialized = microphone_protocol::serialize(packet);
  ASSERT_FALSE(serialized);
  EXPECT_EQ(serialized.error(), microphone_protocol::error_t::invalid_flags);
}

TEST(ClientMicrophoneProtocolTest, RejectsFlagsOnControlPacketsWhenParsingAndSerializing) {
  auto datagram = make_audio_datagram();
  datagram[4] = static_cast<std::uint8_t>(microphone_protocol::packet_type_t::hello);
  datagram[5] = microphone_protocol::flag_silence;
  const auto parsed = microphone_protocol::parse(datagram);
  ASSERT_FALSE(parsed);
  EXPECT_EQ(parsed.error(), microphone_protocol::error_t::invalid_type_flags);

  auto packet = make_control_packet(microphone_protocol::packet_type_t::end);
  packet.flags = microphone_protocol::flag_silence;
  const auto serialized = microphone_protocol::serialize(packet);
  ASSERT_FALSE(serialized);
  EXPECT_EQ(serialized.error(), microphone_protocol::error_t::invalid_type_flags);
}

TEST(ClientMicrophoneProtocolTest, RejectsIncorrectHeaderLength) {
  auto datagram = make_audio_datagram();
  datagram[7] = 0x29;
  const auto parsed = microphone_protocol::parse(datagram);
  ASSERT_FALSE(parsed);
  EXPECT_EQ(parsed.error(), microphone_protocol::error_t::invalid_header_length);
}

TEST(ClientMicrophoneProtocolTest, RejectsOversizedCiphertextWhenParsingAndSerializing) {
  auto packet = make_audio_packet();
  packet.ciphertext.assign(microphone_protocol::maximum_ciphertext_size + 1, 0x7f);
  const auto serialized = microphone_protocol::serialize(packet);
  ASSERT_FALSE(serialized);
  EXPECT_EQ(serialized.error(), microphone_protocol::error_t::ciphertext_too_large);

  auto datagram = make_audio_datagram();
  datagram[36] = 0x04;
  datagram[37] = 0xfc;
  const auto parsed = microphone_protocol::parse(datagram);
  ASSERT_FALSE(parsed);
  EXPECT_EQ(parsed.error(), microphone_protocol::error_t::ciphertext_too_large);
}

TEST(ClientMicrophoneProtocolTest, RejectsEitherNonzeroReservedByte) {
  for (const std::size_t offset : {38U, 39U}) {
    auto datagram = make_audio_datagram();
    datagram[offset] = 1;
    const auto parsed = microphone_protocol::parse(datagram);
    ASSERT_FALSE(parsed) << "offset=" << offset;
    EXPECT_EQ(parsed.error(), microphone_protocol::error_t::nonzero_reserved);
  }
}

TEST(ClientMicrophoneProtocolTest, RejectsTruncatedAuthenticationTag) {
  auto datagram = make_control_packet(microphone_protocol::packet_type_t::hello);
  auto serialized = microphone_protocol::serialize(datagram);
  ASSERT_TRUE(serialized);
  serialized->resize(microphone_protocol::minimum_datagram_size - 1);

  const auto parsed = microphone_protocol::parse(*serialized);
  ASSERT_FALSE(parsed);
  EXPECT_EQ(parsed.error(), microphone_protocol::error_t::truncated_authentication_tag);
}

TEST(ClientMicrophoneProtocolTest, RejectsTruncatedCiphertextAndTag) {
  auto datagram = make_audio_datagram();
  datagram[36] = 0;
  datagram[37] = 5;
  const auto parsed = microphone_protocol::parse(datagram);
  ASSERT_FALSE(parsed);
  EXPECT_EQ(parsed.error(), microphone_protocol::error_t::truncated_ciphertext);
}

TEST(ClientMicrophoneProtocolTest, RejectsTrailingData) {
  auto datagram = make_audio_datagram();
  datagram.push_back(0);
  const auto parsed = microphone_protocol::parse(datagram);
  ASSERT_FALSE(parsed);
  EXPECT_EQ(parsed.error(), microphone_protocol::error_t::trailing_data);
}

TEST(ClientMicrophoneProtocolTest, RejectsControlCiphertextWhenParsingAndSerializing) {
  auto datagram = make_audio_datagram();
  datagram[4] = static_cast<std::uint8_t>(microphone_protocol::packet_type_t::reset);
  const auto parsed = microphone_protocol::parse(datagram);
  ASSERT_FALSE(parsed);
  EXPECT_EQ(parsed.error(), microphone_protocol::error_t::control_packet_has_ciphertext);

  auto packet = make_control_packet(microphone_protocol::packet_type_t::end);
  packet.ciphertext.push_back(0);
  const auto serialized = microphone_protocol::serialize(packet);
  ASSERT_FALSE(serialized);
  EXPECT_EQ(serialized.error(), microphone_protocol::error_t::control_packet_has_ciphertext);
}

TEST(ClientMicrophoneProtocolTest, RejectsMissingAudioCiphertextWhenParsingAndSerializing) {
  auto control = make_control_packet(microphone_protocol::packet_type_t::hello);
  auto datagram = microphone_protocol::serialize(control);
  ASSERT_TRUE(datagram);
  (*datagram)[4] = static_cast<std::uint8_t>(microphone_protocol::packet_type_t::audio);
  const auto parsed = microphone_protocol::parse(*datagram);
  ASSERT_FALSE(parsed);
  EXPECT_EQ(parsed.error(), microphone_protocol::error_t::audio_packet_missing_ciphertext);

  auto packet = make_audio_packet();
  packet.ciphertext.clear();
  const auto serialized = microphone_protocol::serialize(packet);
  ASSERT_FALSE(serialized);
  EXPECT_EQ(serialized.error(), microphone_protocol::error_t::audio_packet_missing_ciphertext);
}

TEST(ClientMicrophoneProtocolTest, RejectsSilenceCiphertextWhenParsingAndSerializing) {
  auto datagram = make_audio_datagram();
  datagram[5] = microphone_protocol::flag_silence;
  const auto parsed = microphone_protocol::parse(datagram);
  ASSERT_FALSE(parsed);
  EXPECT_EQ(parsed.error(), microphone_protocol::error_t::silence_packet_has_ciphertext);

  auto packet = make_audio_packet();
  packet.flags = microphone_protocol::flag_silence;
  const auto serialized = microphone_protocol::serialize(packet);
  ASSERT_FALSE(serialized);
  EXPECT_EQ(serialized.error(), microphone_protocol::error_t::silence_packet_has_ciphertext);
}
