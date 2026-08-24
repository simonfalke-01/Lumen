/**
 * @file tests/unit/test_video_packetizer.cpp
 * @brief Golden and lifetime tests for reusable video packetization.
 */

// standard includes
#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <future>
#include <numeric>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

// lib includes
#include <boost/asio/ip/address.hpp>
#include <rs.h>

// local includes
#include "../tests_common.h"
#include "src/video_packetizer.h"

namespace {
  constexpr std::size_t raw_header_size = video_packetizer::raw_packet_header_size;  ///< Production raw header size.
  constexpr std::size_t block_size = 1440;  ///< Representative production wire packet size.
  constexpr std::size_t payload_block_size = block_size - raw_header_size;  ///< Encoded bytes per packet.

#pragma pack(push, 1)

  /**
   * @brief Test parser for the production raw packet wire layout.
   */
  struct WireRawPacketHeader {
    RTP_PACKET rtp;  ///< RTP header.
    std::array<std::uint8_t, 4> reserved;  ///< Reserved bytes.
    NV_VIDEO_PACKET packet;  ///< GameStream video header.
  };

#pragma pack(pop)

  static_assert(sizeof(WireRawPacketHeader) == video_packetizer::raw_packet_header_size);

  /**
   * @brief Parse an unaligned raw packet header without aliasing.
   * @param packet Complete packet bytes.
   * @return Parsed production header.
   */
  WireRawPacketHeader parse_header(const std::span<const std::uint8_t> packet) {
    if (packet.size() < sizeof(WireRawPacketHeader)) {
      throw std::invalid_argument("captured packet is too short");
    }
    WireRawPacketHeader result;
    std::memcpy(&result, packet.data(), sizeof(result));
    return result;
  }

  /**
   * @brief Capture the exact scatter/gather datagrams submitted to `send_batch()`.
   * @param headers Per-packet header storage.
   * @param header_size Header bytes prepended to each payload.
   * @param payload_buffers Fixed-size aligned payload descriptors.
   * @param payload_size Payload bytes per datagram.
   * @param block_offset First block to capture.
   * @param block_count Datagrams to capture.
   * @return Materialized synchronous send datagrams.
   */
  std::vector<std::vector<std::uint8_t>> capture_send_batch(
    const char *headers,
    const std::size_t header_size,
    std::vector<platf::buffer_descriptor_t> &payload_buffers,
    const std::size_t payload_size,
    const std::size_t block_offset,
    const std::size_t block_count
  ) {
    boost::asio::ip::address loopback = boost::asio::ip::address_v4::loopback();
    auto source = loopback;
    platf::batched_send_info_t send_info {
      headers,
      header_size,
      payload_buffers,
      payload_size,
      block_offset,
      block_count,
      0,
      loopback,
      47998,
      source,
    };
    std::vector<std::vector<std::uint8_t>> result;
    result.reserve(block_count);
    for (std::size_t index = 0; index < block_count; ++index) {
      std::vector<std::uint8_t> datagram(header_size + payload_size);
      if (headers != nullptr) {
        std::memcpy(datagram.data(), headers + (block_offset + index) * header_size, header_size);
      }
      const auto payload = send_info.buffer_for_payload_offset((block_offset + index) * payload_size);
      if (payload.buffer == nullptr || payload.size < payload_size) {
        throw std::logic_error("captured send_batch payload is not block aligned");
      }
      std::memcpy(datagram.data() + header_size, payload.buffer, payload_size);
      result.push_back(std::move(datagram));
    }
    return result;
  }

  /**
   * @brief Convert bytes into lowercase hexadecimal text.
   * @param bytes Input bytes.
   * @return Hexadecimal string.
   */
  std::string to_hex(const std::span<const std::uint8_t> bytes) {
    constexpr std::string_view digits = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2U);
    for (const auto byte : bytes) {
      result.push_back(digits[byte >> 4U]);
      result.push_back(digits[byte & 0x0FU]);
    }
    return result;
  }

  /**
   * @brief Reproduce the former `concat_and_insert()` packet layout.
   * @param frame_header Frame header bytes.
   * @param payload Encoded frame bytes.
   * @return Legacy interleaved bytes before final-shard padding.
   */
  std::vector<std::uint8_t> legacy_interleave(
    const std::span<const std::uint8_t> frame_header,
    const std::span<const std::uint8_t> payload
  ) {
    std::vector<std::uint8_t> logical(frame_header.begin(), frame_header.end());
    logical.insert(logical.end(), payload.begin(), payload.end());
    const auto packet_count = logical.size() / payload_block_size + (logical.size() % payload_block_size != 0 ? 1U : 0U);
    std::vector<std::uint8_t> result(logical.size() + packet_count * raw_header_size);
    for (std::size_t packet_index = 0; packet_index < packet_count; ++packet_index) {
      const auto source_offset = packet_index * payload_block_size;
      const auto copy_size = std::min(payload_block_size, logical.size() - source_offset);
      std::copy_n(
        logical.begin() + static_cast<std::ptrdiff_t>(source_offset),
        copy_size,
        result.begin() + static_cast<std::ptrdiff_t>(packet_index * block_size + raw_header_size)
      );
    }
    return result;
  }

  /**
   * @brief Fill every packet header with deterministic protocol-like bytes.
   * @param bytes Interleaved frame storage.
   */
  void initialize_headers(std::span<std::uint8_t> bytes) {
    const auto packet_count = bytes.size() / block_size + (bytes.size() % block_size != 0 ? 1U : 0U);
    for (std::size_t packet_index = 0; packet_index < packet_count; ++packet_index) {
      const auto available = std::min(raw_header_size, bytes.size() - packet_index * block_size);
      for (std::size_t byte_index = 0; byte_index < available; ++byte_index) {
        bytes[packet_index * block_size + byte_index] = static_cast<std::uint8_t>((packet_index * 17U + byte_index * 3U) & 0xFFU);
      }
    }
  }

  /**
   * @brief Snapshot all fixed-size shards from a packetizer view.
   * @param block Encoded block view.
   * @return Concatenated wire shards.
   */
  std::vector<std::uint8_t> snapshot(const video_packetizer::EncodedBlockView &block) {
    std::vector<std::uint8_t> result(block.size() * block.block_size);
    for (std::size_t index = 0; index < block.size(); ++index) {
      std::memcpy(result.data() + index * block.block_size, block.data(index), block.block_size);
    }
    return result;
  }

  /**
   * @brief Encode a block using the exact former allocation-per-call algorithm.
   * @param payload Initialized legacy data shards.
   * @param fec_percentage Requested FEC percentage.
   * @return Concatenated data and parity shards.
   */
  std::vector<std::uint8_t> legacy_encode(std::span<const std::uint8_t> payload, const int fec_percentage) {
    const bool pad = payload.size() % block_size != 0;
    const auto aligned_data_shards = payload.size() / block_size;
    const auto data_shards = aligned_data_shards + (pad ? 1U : 0U);
    const auto parity_shards = (data_shards * static_cast<std::size_t>(fec_percentage) + 99U) / 100U;
    const auto total_shards = data_shards + parity_shards;
    std::vector<std::uint8_t> result(total_shards * block_size);
    std::memcpy(result.data(), payload.data(), payload.size());
    std::vector<std::uint8_t *> pointers(total_shards);
    for (std::size_t index = 0; index < total_shards; ++index) {
      pointers[index] = result.data() + index * block_size;
    }
    if (parity_shards != 0) {
      auto *encoder = reed_solomon_new(static_cast<int>(data_shards), static_cast<int>(parity_shards));
      if (encoder == nullptr) {
        throw std::bad_alloc {};
      }
      const auto status = reed_solomon_encode(
        encoder,
        pointers.data(),
        static_cast<int>(total_shards),
        static_cast<int>(block_size)
      );
      reed_solomon_release(encoder);
      if (status != 0) {
        throw std::runtime_error("legacy Reed-Solomon reference failed");
      }
    }
    return result;
  }

  /**
   * @brief Generate deterministic encoded-frame bytes.
   * @param size Byte count.
   * @return Frame bytes.
   */
  std::string make_payload(const std::size_t size) {
    std::string result(size, '\0');
    for (std::size_t index = 0; index < size; ++index) {
      result[index] = static_cast<char>((index * 29U + 7U) & 0xFFU);
    }
    return result;
  }

  /**
   * @brief Reconstruct fixed wire packets from a segmented workspace.
   * @param workspace Prepared packetizer workspace.
   * @param packet_count Total packet count.
   * @return Concatenated fixed-size packets.
   */
  std::vector<std::uint8_t> snapshot_segmented(
    video_packetizer::Workspace &workspace,
    const std::size_t packet_count
  ) {
    std::vector<std::uint8_t> result(packet_count * block_size);
    for (std::size_t index = 0; index < packet_count; ++index) {
      std::memcpy(result.data() + index * block_size, workspace.segmented_header(index, raw_header_size), raw_header_size);
      std::memcpy(
        result.data() + index * block_size + raw_header_size,
        workspace.segmented_payload(index, payload_block_size),
        payload_block_size
      );
    }
    return result;
  }
}  // namespace

TEST(VideoPacketizerTest, ReusedInterleavingMatchesLegacyBytesForFrameTypes) {
  const auto payload = make_payload(payload_block_size * 3U + 117U);
  for (const std::uint8_t frame_type : {std::uint8_t {1}, std::uint8_t {2}, std::uint8_t {5}}) {
    std::array<std::uint8_t, 8> frame_header {1, 0x34, 0x12, frame_type, 0x71, 0x02, 0, 0};
    auto expected = legacy_interleave(frame_header, std::span {
                                                      reinterpret_cast<const std::uint8_t *>(payload.data()),
                                                      payload.size(),
                                                    });
    video_packetizer::Workspace workspace;
    const auto actual = workspace.prepare_interleaved_frame(frame_header, payload, raw_header_size, block_size);
    EXPECT_EQ(std::vector<std::uint8_t>(actual.begin(), actual.end()), expected);
  }
}

TEST(VideoPacketizerTest, SegmentedZeroFecMatchesLegacyWireBytesWithoutFrameCopy) {
  const auto payload = make_payload(payload_block_size * 5U + 91U);
  const std::array<std::uint8_t, 8> frame_header {1, 0xA2, 0x01, 1, 0x5B, 0, 0, 0};
  auto expected = legacy_interleave(frame_header, std::span {
                                                    reinterpret_cast<const std::uint8_t *>(payload.data()),
                                                    payload.size(),
                                                  });
  initialize_headers(expected);
  expected.resize((expected.size() + block_size - 1U) / block_size * block_size);

  video_packetizer::Workspace workspace;
  const auto plan = workspace.plan_frame(frame_header.size(), payload.size(), raw_header_size, block_size, 10);
  auto &descriptors = workspace.prepare_segmented_frame(frame_header, payload, raw_header_size, block_size);
  ASSERT_LE(descriptors.size(), 3U);
  ASSERT_GE(descriptors.size(), 2U);
  EXPECT_EQ(descriptors[1].buffer, payload.data() + payload_block_size - frame_header.size());
  (void) workspace.prepare_segmented_headers(0, plan.packet_count, raw_header_size);
  for (std::size_t packet_index = 0; packet_index < plan.packet_count; ++packet_index) {
    auto *header = workspace.segmented_header(packet_index, raw_header_size);
    for (std::size_t byte_index = 0; byte_index < raw_header_size; ++byte_index) {
      header[byte_index] = static_cast<std::uint8_t>((packet_index * 17U + byte_index * 3U) & 0xFFU);
    }
  }
  EXPECT_EQ(snapshot_segmented(workspace, plan.packet_count), expected);

  const auto next_payload = make_payload(payload.size() + payload_block_size);
  auto &next_descriptors = workspace.prepare_segmented_frame(frame_header, next_payload, raw_header_size, block_size);
  ASSERT_GE(next_descriptors.size(), 2U);
  EXPECT_EQ(next_descriptors[1].buffer, next_payload.data() + payload_block_size - frame_header.size());
  EXPECT_NE(next_descriptors[1].buffer, payload.data() + payload_block_size - frame_header.size());
}

TEST(VideoPacketizerTest, ProductionSegmentedSendBatchPreservesRtpFecAndRecoveryHeaders) {
  const auto payload = make_payload(payload_block_size * 2U + 17U);
  const auto frame_header = video_packetizer::make_short_frame_header(
    video_packetizer::FrameKind::reference_recovery,
    0x1234,
    payload.size(),
    payload_block_size
  );
  video_packetizer::Workspace workspace;
  const auto plan = workspace.plan_frame(frame_header.size(), payload.size(), raw_header_size, block_size, 0);
  ASSERT_EQ(plan.block_count, 1U);
  auto &payload_buffers = workspace.prepare_segmented_frame(frame_header, payload, raw_header_size, block_size);
  (void) workspace.prepare_segmented_headers(0, plan.packet_count, raw_header_size);

  constexpr std::uint32_t frame_index = 0x11223344U;
  constexpr std::uint32_t first_stream_packet = 0x120U;
  constexpr std::uint32_t timestamp = 0x55667788U;
  for (std::size_t index = 0; index < plan.packet_count; ++index) {
    const auto fields = video_packetizer::PacketHeaderFields {
      frame_index,
      first_stream_packet + static_cast<std::uint32_t>(index),
      static_cast<std::uint16_t>(first_stream_packet + index),
      timestamp,
      index,
      plan.packet_count,
      0,
      0,
      1,
      index == 0,
      index + 1 == plan.packet_count,
    };
    auto *header = workspace.segmented_header(index, raw_header_size);
    const auto header_bytes = std::span<std::uint8_t> {header, raw_header_size};
    video_packetizer::serialize_data_packet_header(header_bytes, fields);
  }

  const auto captured = capture_send_batch(
    reinterpret_cast<const char *>(workspace.segmented_header(0, raw_header_size)),
    raw_header_size,
    payload_buffers,
    payload_block_size,
    0,
    plan.packet_count
  );
  ASSERT_EQ(captured.size(), plan.packet_count);
  EXPECT_TRUE(std::equal(frame_header.begin(), frame_header.end(), captured[0].begin() + raw_header_size));
  EXPECT_EQ(captured[0][raw_header_size + 3], static_cast<std::uint8_t>(video_packetizer::FrameKind::reference_recovery));

  const auto first = parse_header(captured.front());
  const auto last = parse_header(captured.back());
  EXPECT_EQ(first.rtp.header, 0x80 | FLAG_EXTENSION);
  EXPECT_EQ(first.rtp.sequenceNumber, util::endian::big<std::uint16_t>(first_stream_packet));
  EXPECT_EQ(first.rtp.timestamp, util::endian::big<std::uint32_t>(timestamp));
  EXPECT_EQ(first.packet.streamPacketIndex, first_stream_packet << 8U);
  EXPECT_EQ(first.packet.frameIndex, frame_index);
  EXPECT_EQ(first.packet.flags, FLAG_CONTAINS_PIC_DATA | FLAG_SOF);
  EXPECT_EQ(last.packet.flags, FLAG_CONTAINS_PIC_DATA | FLAG_EOF);
  EXPECT_EQ(first.packet.multiFecFlags, 0x10);
  EXPECT_EQ(first.packet.multiFecBlocks, 0);
  EXPECT_EQ(first.packet.fecInfo, static_cast<std::uint32_t>(plan.packet_count << 22U));
  EXPECT_EQ(
    last.packet.fecInfo,
    static_cast<std::uint32_t>((plan.packet_count - 1U) << 12U | plan.packet_count << 22U)
  );
}

TEST(VideoPacketizerTest, ProductionLegacyFecAndEncryptionPrefixMatchGoldenWire) {
  const auto payload = make_payload(payload_block_size * 5U + 37U);
  const auto frame_header = video_packetizer::make_short_frame_header(
    video_packetizer::FrameKind::idr,
    7,
    payload.size(),
    payload_block_size
  );
  video_packetizer::Workspace workspace;
  const auto plan = workspace.plan_frame(frame_header.size(), payload.size(), raw_header_size, block_size, 20);
  ASSERT_EQ(plan.block_count, 1U);
  auto prepared = workspace.prepare_interleaved_frame(frame_header, payload, raw_header_size, block_size);
  const auto packets = plan.blocks[0].packet_count;
  for (std::size_t index = 0; index < packets; ++index) {
    video_packetizer::prepare_data_packet_header(
      prepared.subspan(index * block_size, raw_header_size),
      video_packetizer::PacketHeaderFields {
        0x11223344U,
        0x220U + static_cast<std::uint32_t>(index),
        static_cast<std::uint16_t>(0x220U + index),
        0x10203040U,
        index,
        packets,
        20,
        0,
        1,
        index == 0,
        index + 1 == packets,
      }
    );
  }
  auto shards = workspace.encode_block(
    prepared,
    block_size,
    20,
    0,
    video_packetizer::encrypted_packet_prefix_size
  );
  for (std::size_t index = 0; index < shards.size(); ++index) {
    video_packetizer::finalize_packet_header(
      {reinterpret_cast<std::uint8_t *>(shards.data(index)), raw_header_size},
      video_packetizer::PacketHeaderFields {
        0x11223344U,
        0x220U + static_cast<std::uint32_t>(index),
        static_cast<std::uint16_t>(0x220U + index),
        0x10203040U,
        index,
        shards.data_shards,
        static_cast<int>(shards.percentage),
        0,
        1,
        false,
        false,
      }
    );
  }

  const auto captured = capture_send_batch(nullptr, 0, *shards.payload_buffers, block_size, 0, shards.size());
  ASSERT_EQ(captured.size(), shards.size());
  ASSERT_EQ(captured.front()[raw_header_size + 3], static_cast<std::uint8_t>(video_packetizer::FrameKind::idr));
  const auto first = parse_header(captured.front());
  const auto parity = parse_header(captured[shards.data_shards]);
  EXPECT_EQ(first.packet.flags, FLAG_CONTAINS_PIC_DATA | FLAG_SOF);
  EXPECT_EQ(parity.rtp.sequenceNumber, util::endian::big<std::uint16_t>(0x220U + shards.data_shards));
  EXPECT_EQ(
    parity.packet.fecInfo,
    static_cast<std::uint32_t>(shards.data_shards << 12U | shards.data_shards << 22U | 20U << 4U)
  );

  crypto::aes_t key(16);
  std::iota(key.begin(), key.end(), std::uint8_t {});
  crypto::cipher::gcm_t cipher {key, false};
  crypto::aes_t iv(12);
  std::uint64_t iv_counter = UINT64_C(0x0102030405060708);
  auto encrypted_packet = captured.front();
  std::array<std::uint8_t, video_packetizer::encrypted_packet_prefix_size> prefix {};
  video_packetizer::encrypt_packet(cipher, encrypted_packet, 0x11223344U, iv_counter, iv, prefix);
  EXPECT_EQ(iv_counter, UINT64_C(0x0102030405060709));
  EXPECT_EQ(to_hex(std::span<const std::uint8_t> {prefix}.first<16>()), "08070605040302010000005644332211");
  EXPECT_EQ(to_hex(std::span<const std::uint8_t> {prefix}.subspan<16>()), "ec5b07050e23e1a0956d7e4a4dd3e44c");

  std::vector<std::uint8_t> tagged_cipher(prefix.begin() + 16, prefix.end());
  tagged_cipher.insert(tagged_cipher.end(), encrypted_packet.begin(), encrypted_packet.end());
  crypto::cipher::gcm_t decryptor {key, false};
  crypto::aes_t decrypt_iv(prefix.begin(), prefix.begin() + 12);
  std::vector<std::uint8_t> decrypted;
  ASSERT_EQ(
    decryptor.decrypt(
      std::string_view {reinterpret_cast<const char *>(tagged_cipher.data()), tagged_cipher.size()},
      decrypted,
      &decrypt_iv
    ),
    0
  );
  EXPECT_EQ(decrypted, captured.front());
}

TEST(VideoPacketizerTest, ReedSolomonOutputMatchesLegacyForSupportedPercentages) {
  const auto payload = make_payload(payload_block_size * 11U + 307U);
  const std::array<std::uint8_t, 8> frame_header {1, 0, 0, 2, 0, 0, 0, 0};
  for (const int fec_percentage : {0, 2, 10, 20}) {
    video_packetizer::Workspace workspace;
    auto prepared = workspace.prepare_interleaved_frame(frame_header, payload, raw_header_size, block_size);
    initialize_headers(prepared);
    const auto expected = legacy_encode(prepared, fec_percentage);
    const auto actual = workspace.encode_block(prepared, block_size, fec_percentage, 0, 0);
    EXPECT_EQ(snapshot(actual), expected) << "FEC percentage " << fec_percentage;
  }
}

TEST(VideoPacketizerTest, MultiBlockGeometryMatchesLegacySplitAndEncoding) {
  const auto payload = make_payload(520U * 1024U);
  const std::array<std::uint8_t, 8> frame_header {1, 0, 0, 5, 0, 0, 0, 0};
  video_packetizer::Workspace workspace;
  const auto plan = workspace.plan_frame(frame_header.size(), payload.size(), raw_header_size, block_size, 20);
  ASSERT_GT(plan.block_count, 1U);
  ASSERT_FALSE(plan.exceeded_fec_block_limit);
  auto prepared = workspace.prepare_interleaved_frame(frame_header, payload, raw_header_size, block_size);
  initialize_headers(prepared);

  for (std::size_t index = 0; index < plan.block_count; ++index) {
    const auto &range = plan.blocks[index];
    const auto block = prepared.subspan(range.byte_offset, range.byte_size);
    EXPECT_EQ(snapshot(workspace.encode_block(block, block_size, 20, 0, 0)), legacy_encode(block, 20));
  }
}

TEST(VideoPacketizerTest, OversizedFecGeometryFallsBackToWireSafeZeroFecBlocks) {
  const auto payload_size = 1021U * payload_block_size - 8U;
  video_packetizer::Workspace workspace;
  const auto plan = workspace.plan_frame(8, payload_size, raw_header_size, block_size, 10);
  EXPECT_TRUE(plan.exceeded_fec_block_limit);
  EXPECT_EQ(plan.block_count, 1U);
  EXPECT_EQ(
    std::accumulate(plan.blocks.begin(), plan.blocks.end(), std::size_t {}, [](const std::size_t total, const auto &block) {
      return total + block.byte_size;
    }),
    plan.wire_bytes
  );
}

TEST(VideoPacketizerTest, ZeroFecWireBoundariesPrepareSerializeAndCaptureSafely) {
  const auto frame_header = video_packetizer::make_short_frame_header(
    video_packetizer::FrameKind::normal,
    0,
    1,
    payload_block_size
  );
  for (const std::size_t packet_count : std::array<std::size_t, 2> {1021U, video_packetizer::maximum_frame_data_shards}) {
    const auto payload = make_payload(packet_count * payload_block_size - frame_header.size());
    video_packetizer::Workspace workspace;
    const auto plan = workspace.plan_frame(frame_header.size(), payload.size(), raw_header_size, block_size, 0);
    ASSERT_EQ(plan.packet_count, packet_count);
    ASSERT_EQ(plan.block_count, (packet_count + video_packetizer::maximum_wire_data_shards - 1U) / video_packetizer::maximum_wire_data_shards);
    auto prepared = workspace.prepare_interleaved_frame(frame_header, payload, raw_header_size, block_size);

    std::size_t captured_packets {};
    std::uint32_t low_sequence = 100;
    for (std::size_t block_index = 0; block_index < plan.block_count; ++block_index) {
      const auto &range = plan.blocks[block_index];
      auto block = prepared.subspan(range.byte_offset, range.byte_size);
      for (std::size_t index = 0; index < range.packet_count; ++index) {
        video_packetizer::prepare_data_packet_header(
          block.subspan(index * block_size, raw_header_size),
          video_packetizer::PacketHeaderFields {
            9,
            low_sequence + static_cast<std::uint32_t>(index),
            static_cast<std::uint16_t>(low_sequence + index),
            90000,
            index,
            range.packet_count,
            0,
            block_index,
            plan.block_count,
            index == 0,
            index + 1 == range.packet_count,
          }
        );
      }
      auto shards = workspace.encode_block(block, block_size, 0, 0, 0);
      for (std::size_t index = 0; index < shards.size(); ++index) {
        video_packetizer::finalize_packet_header(
          {reinterpret_cast<std::uint8_t *>(shards.data(index)), raw_header_size},
          video_packetizer::PacketHeaderFields {
            9,
            low_sequence + static_cast<std::uint32_t>(index),
            static_cast<std::uint16_t>(low_sequence + index),
            90000,
            index,
            shards.data_shards,
            0,
            block_index,
            plan.block_count,
            false,
            false,
          }
        );
      }
      const auto captured = capture_send_batch(nullptr, 0, *shards.payload_buffers, block_size, 0, shards.size());
      ASSERT_EQ(captured.size(), range.packet_count);
      const auto first = parse_header(captured.front());
      const auto last = parse_header(captured.back());
      EXPECT_EQ(first.packet.fecInfo, static_cast<std::uint32_t>(range.packet_count << 22U));
      EXPECT_EQ(
        last.packet.fecInfo,
        static_cast<std::uint32_t>((range.packet_count - 1U) << 12U | range.packet_count << 22U)
      );
      EXPECT_EQ(first.packet.flags, FLAG_CONTAINS_PIC_DATA | FLAG_SOF);
      EXPECT_EQ(last.packet.flags, FLAG_CONTAINS_PIC_DATA | FLAG_EOF);
      EXPECT_EQ(first.rtp.sequenceNumber, util::endian::big<std::uint16_t>(low_sequence));
      EXPECT_EQ(first.rtp.timestamp, util::endian::big<std::uint32_t>(90000));
      EXPECT_EQ(first.packet.streamPacketIndex, low_sequence << 8U);
      EXPECT_EQ(
        first.packet.multiFecBlocks,
        static_cast<std::uint8_t>((block_index << 4U) | ((plan.block_count - 1U) << 6U))
      );
      captured_packets += captured.size();
      low_sequence += static_cast<std::uint32_t>(captured.size());
    }
    EXPECT_EQ(captured_packets, packet_count);
  }

  const auto oversized_payload = make_payload((video_packetizer::maximum_frame_data_shards + 1U) * payload_block_size - frame_header.size());
  video_packetizer::Workspace workspace;
  EXPECT_THROW(
    (void) workspace.prepare_interleaved_frame(frame_header, oversized_payload, raw_header_size, block_size),
    std::length_error
  );
}

TEST(VideoPacketizerTest, WarmWorkspaceDoesNotGrowOrRecreateMatrix) {
  const auto payload = make_payload(payload_block_size * 20U + 33U);
  const std::array<std::uint8_t, 8> frame_header {1, 0, 0, 1, 0, 0, 0, 0};
  video_packetizer::Workspace workspace;
  auto first = workspace.prepare_interleaved_frame(frame_header, payload, raw_header_size, block_size);
  initialize_headers(first);
  (void) workspace.encode_block(first, block_size, 10, 0, 32);
  const auto warmed = workspace.allocation_stats();

  auto second = workspace.prepare_interleaved_frame(frame_header, payload, raw_header_size, block_size);
  initialize_headers(second);
  (void) workspace.encode_block(second, block_size, 10, 0, 32);
  const auto repeated = workspace.allocation_stats();
  EXPECT_EQ(repeated.buffer_growth_events, warmed.buffer_growth_events);
  EXPECT_EQ(repeated.reed_solomon_creations, warmed.reed_solomon_creations);
  EXPECT_EQ(repeated.reed_solomon_creations, 1U);
}

TEST(VideoPacketizerTest, BoundedMatrixCacheReplacesColdGeometriesSafely) {
  const std::array<std::uint8_t, 8> frame_header {1, 0, 0, 1, 0, 0, 0, 0};
  video_packetizer::Workspace workspace;
  for (std::size_t packet_count = 1; packet_count <= video_packetizer::maximum_cached_rs_geometries + 2U; ++packet_count) {
    const auto payload = make_payload(packet_count * payload_block_size - frame_header.size());
    auto prepared = workspace.prepare_interleaved_frame(frame_header, payload, raw_header_size, block_size);
    initialize_headers(prepared);
    EXPECT_NO_THROW((void) workspace.encode_block(prepared, block_size, 10, 0, 0));
  }
  EXPECT_EQ(
    workspace.allocation_stats().reed_solomon_creations,
    video_packetizer::maximum_cached_rs_geometries + 2U
  );
}

TEST(VideoPacketizerTest, FirstBatchReadinessRequiresExplicitHeaderCompletion) {
  const auto payload = make_payload(payload_block_size * 2U);
  const std::array<std::uint8_t, 8> frame_header {1, 0, 0, 1, 0, 0, 0, 0};
  video_packetizer::Workspace workspace;
  (void) workspace.prepare_segmented_frame(frame_header, payload, raw_header_size, block_size);
  EXPECT_FALSE(workspace.first_batch_ready());
  (void) workspace.prepare_segmented_headers(0, 1, raw_header_size);
  EXPECT_FALSE(workspace.first_batch_ready());
  workspace.mark_first_batch_ready();
  EXPECT_TRUE(workspace.first_batch_ready());
}

TEST(VideoPacketizerTest, ConcurrentSessionsKeepStorageAndMatricesIsolated) {
  constexpr std::size_t session_count = 8;
  std::array<std::future<std::uint64_t>, session_count> tasks;
  for (std::size_t session_index = 0; session_index < session_count; ++session_index) {
    tasks[session_index] = std::async(std::launch::async, [session_index]() {
      const auto payload = make_payload(payload_block_size * (8U + session_index) + session_index);
      const std::array<std::uint8_t, 8> frame_header {1, 0, 0, 1, 0, 0, 0, 0};
      video_packetizer::Workspace workspace;
      auto prepared = workspace.prepare_interleaved_frame(frame_header, payload, raw_header_size, block_size);
      initialize_headers(prepared);
      const auto encoded = snapshot(workspace.encode_block(prepared, block_size, 10, 0, 0));
      return std::accumulate(encoded.begin(), encoded.end(), std::uint64_t {});
    });
  }

  std::array<std::uint64_t, session_count> checksums {};
  for (std::size_t index = 0; index < session_count; ++index) {
    checksums[index] = tasks[index].get();
  }
  EXPECT_EQ(std::count(checksums.begin(), checksums.end(), checksums.front()), 1);
}

TEST(VideoPacketizerTest, RejectsInvalidGeometryAndFrameCaps) {
  video_packetizer::Workspace workspace(1024);
  EXPECT_THROW((void) workspace.plan_frame(8, 2048, raw_header_size, block_size, 10), std::length_error);
  EXPECT_THROW((void) workspace.plan_frame(8, 1, block_size, block_size, 10), std::invalid_argument);
  EXPECT_THROW((void) workspace.plan_frame(8, 1, raw_header_size, block_size, -1), std::invalid_argument);
}
