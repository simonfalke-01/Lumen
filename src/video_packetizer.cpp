/**
 * @file src/video_packetizer.cpp
 * @brief Reusable video packetization storage and Reed-Solomon implementation.
 */

// this include
#include "video_packetizer.h"

// standard includes
#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace video_packetizer {
  namespace {
    constexpr std::size_t maximum_packet_bytes = 64U * 1024U;  ///< Defensive packet-size cap above every supported MTU.

#pragma pack(push, 1)

    /**
     * @brief Exact production raw packet-header layout.
     */
    struct RawPacketHeader {
      RTP_PACKET rtp;  ///< RTP header.
      std::array<std::uint8_t, 4> reserved;  ///< Legacy reserved bytes.
      NV_VIDEO_PACKET packet;  ///< GameStream video header.
    };

#pragma pack(pop)

    static_assert(sizeof(RawPacketHeader) == raw_packet_header_size, "Raw video header size must remain wire-compatible");

    /**
     * @brief Return a ceiling quotient without overflowing the numerator.
     * @param value Dividend.
     * @param divisor Nonzero divisor.
     * @return Ceiling of `value / divisor`.
     */
    std::size_t divide_round_up(const std::size_t value, const std::size_t divisor) {
      return value / divisor + (value % divisor != 0 ? 1U : 0U);
    }

    /**
     * @brief Add two sizes or reject overflow.
     * @param left First value.
     * @param right Second value.
     * @return Exact sum.
     */
    std::size_t checked_add(const std::size_t left, const std::size_t right) {
      if (right > std::numeric_limits<std::size_t>::max() - left) {
        throw std::length_error("video packetizer size overflow");
      }
      return left + right;
    }

    /**
     * @brief Multiply two sizes or reject overflow.
     * @param left First factor.
     * @param right Second factor.
     * @return Exact product.
     */
    std::size_t checked_multiply(const std::size_t left, const std::size_t right) {
      if (left != 0 && right > std::numeric_limits<std::size_t>::max() / left) {
        throw std::length_error("video packetizer size overflow");
      }
      return left * right;
    }

    /**
     * @brief Validate fixed packet geometry shared by every preparation path.
     * @param raw_header_size Inserted or segmented header bytes.
     * @param block_size Complete wire packet bytes.
     */
    void validate_packet_geometry(const std::size_t raw_header_size, const std::size_t block_size) {
      if (raw_header_size == 0 || block_size <= raw_header_size || block_size > maximum_packet_bytes) {
        throw std::invalid_argument("invalid video packet geometry");
      }
    }

    /**
     * @brief Return a validated mutable raw packet-header view.
     * @param header Caller-supplied packet-header bytes.
     * @return Packed production header.
     */
    RawPacketHeader &raw_packet_header(const std::span<std::uint8_t> header) {
      if (header.size() != raw_packet_header_size) {
        throw std::invalid_argument("invalid raw video packet header size");
      }
      return *reinterpret_cast<RawPacketHeader *>(header.data());
    }

    /**
     * @brief Pack the production FEC metadata word.
     * @param fields Header fields being serialized.
     * @return Packed GameStream FEC value.
     */
    std::uint32_t pack_fec_info(const PacketHeaderFields &fields) {
      if (fields.shard_index >= 1024 || fields.data_shards == 0 || fields.data_shards >= 1024 || fields.fec_percentage < 0 || fields.fec_percentage > 255) {
        throw std::invalid_argument("invalid video packet FEC header fields");
      }
      return static_cast<std::uint32_t>(
        fields.shard_index << 12U |
        fields.data_shards << 22U |
        static_cast<std::size_t>(fields.fec_percentage) << 4U
      );
    }

    /**
     * @brief Pack the production multi-FEC block byte.
     * @param fields Header fields being serialized.
     * @return Packed block index and count.
     */
    std::uint8_t pack_multi_fec_blocks(const PacketHeaderFields &fields) {
      if (fields.block_count == 0 || fields.block_count > maximum_fec_blocks || fields.block_index >= fields.block_count) {
        throw std::invalid_argument("invalid multi-FEC block fields");
      }
      return static_cast<std::uint8_t>((fields.block_index << 4U) | ((fields.block_count - 1U) << 6U));
    }
  }  // namespace

  std::array<std::uint8_t, 8> make_short_frame_header(
    const FrameKind kind,
    const std::uint16_t processing_latency_tenths_ms,
    const std::size_t encoded_payload_size,
    const std::size_t packet_payload_size
  ) {
    if (packet_payload_size == 0 || packet_payload_size > std::numeric_limits<std::uint16_t>::max()) {
      throw std::invalid_argument("invalid short-frame packet payload size");
    }
    auto final_payload_size = (encoded_payload_size + 8U) % packet_payload_size;
    if (final_payload_size == 0) {
      final_payload_size = packet_payload_size;
    }
    std::array<std::uint8_t, 8> result {};
    result[0] = 0x01;
    result[1] = static_cast<std::uint8_t>(processing_latency_tenths_ms);
    result[2] = static_cast<std::uint8_t>(processing_latency_tenths_ms >> 8U);
    result[3] = static_cast<std::uint8_t>(kind);
    result[4] = static_cast<std::uint8_t>(final_payload_size);
    result[5] = static_cast<std::uint8_t>(final_payload_size >> 8U);
    return result;
  }

  void prepare_data_packet_header(const std::span<std::uint8_t> header, const PacketHeaderFields &fields) {
    auto &wire = raw_packet_header(header);
    std::memset(&wire, 0, sizeof(wire));
    wire.packet.frameIndex = fields.frame_index;
    wire.packet.streamPacketIndex = fields.stream_packet_index << 8U;
    wire.packet.multiFecFlags = 0x10;
    wire.packet.multiFecBlocks = pack_multi_fec_blocks(fields);
    wire.packet.flags = FLAG_CONTAINS_PIC_DATA;
    if (fields.start_of_block) {
      wire.packet.flags |= FLAG_SOF;
    }
    if (fields.end_of_block) {
      wire.packet.flags |= FLAG_EOF;
    }
  }

  void finalize_packet_header(const std::span<std::uint8_t> header, const PacketHeaderFields &fields) {
    auto &wire = raw_packet_header(header);
    wire.packet.fecInfo = pack_fec_info(fields);
    wire.rtp.header = 0x80 | FLAG_EXTENSION;
    wire.rtp.sequenceNumber = util::endian::big<std::uint16_t>(fields.rtp_sequence_number);
    wire.rtp.timestamp = util::endian::big<std::uint32_t>(fields.rtp_timestamp);
    wire.packet.multiFecBlocks = pack_multi_fec_blocks(fields);
    wire.packet.frameIndex = fields.frame_index;
  }

  void serialize_data_packet_header(const std::span<std::uint8_t> header, const PacketHeaderFields &fields) {
    prepare_data_packet_header(header, fields);
    finalize_packet_header(header, fields);
  }

  void encrypt_packet(
    crypto::cipher::gcm_t &cipher,
    const std::span<std::uint8_t> packet,
    const std::uint32_t frame_index,
    std::uint64_t &iv_counter,
    crypto::aes_t &iv,
    const std::span<std::uint8_t> prefix
  ) {
    if (prefix.size() != encrypted_packet_prefix_size || iv.size() != 12) {
      throw std::invalid_argument("invalid encrypted video packet storage");
    }
    std::copy_n(reinterpret_cast<const std::uint8_t *>(&iv_counter), sizeof(iv_counter), iv.begin());
    iv[8] = 0;
    iv[9] = 0;
    iv[10] = 0;
    iv[11] = 'V';
    ++iv_counter;
    std::copy(iv.begin(), iv.end(), prefix.begin());
    std::memcpy(prefix.data() + 12, &frame_index, sizeof(frame_index));
    if (cipher.encrypt(
          std::string_view {reinterpret_cast<const char *>(packet.data()), packet.size()},
          prefix.data() + 16,
          packet.data(),
          &iv
        ) < 0) {
      throw std::runtime_error("video packet encryption failed");
    }
  }

  char *EncodedBlockView::data(const std::size_t index) const {
    return index < shard_pointers_.size() ? reinterpret_cast<char *>(shard_pointers_[index]) : nullptr;
  }

  char *EncodedBlockView::prefix(const std::size_t index) const {
    if (prefix_size == 0 || index >= size()) {
      return nullptr;
    }
    return prefixes_.data() + index * prefix_size;
  }

  std::size_t EncodedBlockView::size() const {
    return shard_pointers_.size();
  }

  Workspace::Workspace(const std::size_t maximum_frame_bytes):
      maximum_frame_bytes_ {maximum_frame_bytes} {
    if (maximum_frame_bytes_ == 0) {
      throw std::invalid_argument("video packetizer frame cap must be nonzero");
    }
    payload_buffers_.reserve(3);
  }

  FramePlan Workspace::plan_frame(
    const std::size_t frame_header_size,
    const std::size_t payload_size,
    const std::size_t raw_header_size,
    const std::size_t block_size,
    const int fec_percentage
  ) const {
    validate_packet_geometry(raw_header_size, block_size);
    if (fec_percentage < 0 || fec_percentage > 255) {
      throw std::invalid_argument("invalid video FEC percentage");
    }

    const auto data_size = checked_add(frame_header_size, payload_size);
    if (data_size == 0 || data_size > maximum_frame_bytes_) {
      throw std::length_error("encoded video frame exceeds packetizer cap");
    }

    const auto payload_block_size = block_size - raw_header_size;
    const auto packet_count = divide_round_up(data_size, payload_block_size);
    if (packet_count > maximum_frame_data_shards) {
      throw std::length_error("encoded video frame exceeds ten-bit multi-FEC limits");
    }
    const auto wire_bytes = checked_add(data_size, checked_multiply(packet_count, raw_header_size));
    std::size_t required_fec_block_count {};
    if (fec_percentage != 0) {
      const auto maximum_fec_data_shards = (DATA_SHARDS_MAX * 100U) / (100U + static_cast<std::size_t>(fec_percentage));
      if (maximum_fec_data_shards == 0) {
        throw std::invalid_argument("video FEC leaves no data shards");
      }
      required_fec_block_count = divide_round_up(packet_count, maximum_fec_data_shards);
    }
    const bool disable_fec_for_size = fec_percentage != 0 && required_fec_block_count > maximum_fec_blocks;
    const auto block_count = fec_percentage == 0 || disable_fec_for_size ?
                               divide_round_up(packet_count, maximum_wire_data_shards) :
                               required_fec_block_count;
    if (block_count == 0) {
      throw std::logic_error("video packetizer produced no wire blocks");
    }

    FramePlan result {
      wire_bytes,
      packet_count,
      block_count,
      disable_fec_for_size,
      {},
    };
    const auto unaligned_block_size = wire_bytes / block_count;
    const auto aligned_block_size = checked_multiply(divide_round_up(unaligned_block_size, block_size), block_size);
    for (std::size_t index = 0; index < block_count; ++index) {
      const auto byte_offset = checked_multiply(index, aligned_block_size);
      const auto byte_size = index + 1 == block_count ? wire_bytes - byte_offset : aligned_block_size;
      result.blocks[index] = {
        byte_offset,
        byte_size,
        byte_offset / block_size,
        divide_round_up(byte_size, block_size),
      };
    }
    return result;
  }

  std::span<std::uint8_t> Workspace::prepare_interleaved_frame(
    const std::span<const std::uint8_t> frame_header,
    const std::string_view payload,
    const std::size_t raw_header_size,
    const std::size_t block_size
  ) {
    const auto plan = plan_frame(frame_header.size(), payload.size(), raw_header_size, block_size, 0);
    resize_bytes(interleaved_, plan.wire_bytes);
    first_batch_ready_ = false;
    payload_buffers_.clear();
    segmented_packet_count_ = 0;

    const auto payload_block_size = block_size - raw_header_size;
    const auto total_data_size = frame_header.size() + payload.size();
    for (std::size_t packet_index = 0; packet_index < plan.packet_count; ++packet_index) {
      const auto logical_offset = packet_index * payload_block_size;
      const auto slice_size = std::min(payload_block_size, total_data_size - logical_offset);
      auto *destination = interleaved_.data() + packet_index * block_size;
      std::memset(destination, 0, raw_header_size);

      std::size_t copied {};
      if (logical_offset < frame_header.size()) {
        const auto header_bytes = std::min(slice_size, frame_header.size() - logical_offset);
        std::memcpy(destination + raw_header_size, frame_header.data() + logical_offset, header_bytes);
        copied = header_bytes;
      }
      if (copied < slice_size) {
        const auto payload_offset = logical_offset + copied - frame_header.size();
        std::memcpy(destination + raw_header_size + copied, payload.data() + payload_offset, slice_size - copied);
      }
    }
    return {interleaved_.data(), interleaved_.size()};
  }

  std::vector<platf::buffer_descriptor_t> &Workspace::prepare_segmented_frame(
    const std::span<const std::uint8_t> frame_header,
    const std::string_view payload,
    const std::size_t raw_header_size,
    const std::size_t block_size
  ) {
    const auto plan = plan_frame(frame_header.size(), payload.size(), raw_header_size, block_size, 0);
    const auto payload_block_size = block_size - raw_header_size;
    if (frame_header.size() > payload_block_size) {
      throw std::invalid_argument("video frame header exceeds packet payload");
    }

    resize_bytes(segmented_headers_, checked_multiply(plan.packet_count, raw_header_size));
    resize_bytes(segmented_first_payload_, payload_block_size);
    payload_buffers_.clear();
    first_batch_ready_ = false;
    segmented_packet_count_ = plan.packet_count;

    std::memcpy(segmented_first_payload_.data(), frame_header.data(), frame_header.size());
    const auto first_payload_bytes = std::min(payload.size(), payload_block_size - frame_header.size());
    if (first_payload_bytes != 0) {
      std::memcpy(segmented_first_payload_.data() + frame_header.size(), payload.data(), first_payload_bytes);
    }
    const auto first_used = frame_header.size() + first_payload_bytes;
    if (first_used < payload_block_size) {
      std::memset(segmented_first_payload_.data() + first_used, 0, payload_block_size - first_used);
    }
    payload_buffers_.emplace_back(reinterpret_cast<const char *>(segmented_first_payload_.data()), payload_block_size);

    if (plan.packet_count > 1) {
      const auto remaining_offset = payload_block_size - frame_header.size();
      const auto remaining_size = payload.size() - first_payload_bytes;
      const auto full_direct_packets = remaining_size / payload_block_size;
      if (full_direct_packets != 0) {
        payload_buffers_.emplace_back(
          payload.data() + remaining_offset,
          checked_multiply(full_direct_packets, payload_block_size)
        );
      }

      const auto final_bytes = remaining_size % payload_block_size;
      if (final_bytes != 0) {
        resize_bytes(segmented_final_payload_, payload_block_size);
        const auto final_offset = remaining_offset + checked_multiply(full_direct_packets, payload_block_size);
        std::memcpy(segmented_final_payload_.data(), payload.data() + final_offset, final_bytes);
        std::memset(segmented_final_payload_.data() + final_bytes, 0, payload_block_size - final_bytes);
        payload_buffers_.emplace_back(reinterpret_cast<const char *>(segmented_final_payload_.data()), payload_block_size);
      }
    }
    return payload_buffers_;
  }

  std::span<std::uint8_t> Workspace::prepare_segmented_headers(
    const std::size_t packet_offset,
    const std::size_t packet_count,
    const std::size_t raw_header_size
  ) {
    if (packet_offset > segmented_packet_count_ || packet_count > segmented_packet_count_ - packet_offset) {
      throw std::out_of_range("segmented video header range is invalid");
    }
    const auto offset = checked_multiply(packet_offset, raw_header_size);
    const auto size = checked_multiply(packet_count, raw_header_size);
    if (offset > segmented_headers_.size() || size > segmented_headers_.size() - offset) {
      throw std::out_of_range("segmented video header storage is invalid");
    }
    std::memset(segmented_headers_.data() + offset, 0, size);
    return {segmented_headers_.data() + offset, size};
  }

  std::uint8_t *Workspace::segmented_header(const std::size_t packet_index, const std::size_t raw_header_size) {
    if (packet_index >= segmented_packet_count_) {
      return nullptr;
    }
    return segmented_headers_.data() + packet_index * raw_header_size;
  }

  const char *Workspace::segmented_payload(const std::size_t packet_index, const std::size_t payload_size) const {
    if (packet_index >= segmented_packet_count_) {
      return nullptr;
    }
    auto offset = packet_index * payload_size;
    for (const auto &descriptor : payload_buffers_) {
      if (offset < descriptor.size) {
        return descriptor.buffer + offset;
      }
      offset -= descriptor.size;
    }
    return nullptr;
  }

  EncodedBlockView Workspace::encode_block(
    const std::span<std::uint8_t> payload,
    const std::size_t block_size,
    const int fec_percentage,
    const std::size_t minimum_parity_shards,
    const std::size_t prefix_size
  ) {
    if (payload.empty() || payload.size() > maximum_frame_bytes_ || block_size == 0 || block_size > maximum_packet_bytes || fec_percentage < 0 || fec_percentage > 255) {
      throw std::invalid_argument("invalid FEC block geometry");
    }
    if (minimum_parity_shards > DATA_SHARDS_MAX) {
      throw std::length_error("minimum video parity shards exceed protocol limits");
    }

    const bool pad = payload.size() % block_size != 0;
    const auto aligned_data_shards = payload.size() / block_size;
    const auto data_shards = aligned_data_shards + (pad ? 1U : 0U);
    auto parity_shards = (data_shards * static_cast<std::size_t>(fec_percentage) + 99U) / 100U;
    auto effective_percentage = static_cast<std::size_t>(fec_percentage);
    if (parity_shards < minimum_parity_shards && fec_percentage != 0) {
      parity_shards = minimum_parity_shards;
      effective_percentage = (100U * parity_shards) / data_shards;
    }
    const bool invalid_zero_fec_geometry = parity_shards == 0 && data_shards > maximum_wire_data_shards;
    const bool invalid_reed_solomon_geometry = parity_shards != 0 &&
                                               (data_shards > DATA_SHARDS_MAX || parity_shards > DATA_SHARDS_MAX - data_shards);
    if (data_shards == 0 || invalid_zero_fec_geometry || invalid_reed_solomon_geometry) {
      throw std::length_error("video FEC shard geometry exceeds protocol limits");
    }

    const auto total_shards = data_shards + parity_shards;
    const auto parity_offset = pad ? 1U : 0U;
    resize_bytes(shard_storage_, checked_multiply(parity_offset + parity_shards, block_size));
    if (shard_pointers_.capacity() < total_shards) {
      shard_pointers_.reserve(total_shards);
      ++allocation_stats_.buffer_growth_events;
    }
    shard_pointers_.resize(total_shards);
    resize_bytes(prefix_storage_, checked_multiply(total_shards, prefix_size));
    payload_buffers_.clear();

    auto *next = payload.data();
    for (std::size_t index = 0; index < aligned_data_shards; ++index) {
      shard_pointers_[index] = next;
      next += block_size;
    }
    if (aligned_data_shards != 0) {
      payload_buffers_.emplace_back(reinterpret_cast<const char *>(payload.data()), aligned_data_shards * block_size);
    }

    if (pad) {
      shard_pointers_[aligned_data_shards] = shard_storage_.data();
      const auto copy_size = payload.size() - aligned_data_shards * block_size;
      std::memcpy(shard_storage_.data(), next, copy_size);
      std::memset(shard_storage_.data() + copy_size, 0, block_size - copy_size);
    }

    if (!shard_storage_.empty()) {
      payload_buffers_.emplace_back(reinterpret_cast<const char *>(shard_storage_.data()), shard_storage_.size());
    }

    if (parity_shards != 0) {
      for (std::size_t index = 0; index < parity_shards; ++index) {
        shard_pointers_[data_shards + index] = shard_storage_.data() + (parity_offset + index) * block_size;
      }
      auto *encoder = reed_solomon_for(static_cast<int>(data_shards), static_cast<int>(parity_shards));
      if (reed_solomon_encode(encoder, shard_pointers_.data(), static_cast<int>(total_shards), static_cast<int>(block_size)) != 0) {
        throw std::runtime_error("video Reed-Solomon encode failed");
      }
    }

    EncodedBlockView result;
    result.data_shards = data_shards;
    result.percentage = effective_percentage;
    result.block_size = block_size;
    result.prefix_size = prefix_size;
    result.payload_buffers = &payload_buffers_;
    result.shard_pointers_ = {shard_pointers_.data(), shard_pointers_.size()};
    result.prefixes_ = {reinterpret_cast<char *>(prefix_storage_.data()), prefix_storage_.size()};
    return result;
  }

  AllocationStats Workspace::allocation_stats() const {
    return allocation_stats_;
  }

  void Workspace::mark_first_batch_ready() {
    first_batch_ready_ = true;
  }

  bool Workspace::first_batch_ready() const {
    return first_batch_ready_;
  }

  void Workspace::resize_bytes(std::vector<std::uint8_t> &storage, const std::size_t size) {
    if (storage.capacity() < size) {
      storage.reserve(size);
      ++allocation_stats_.buffer_growth_events;
    }
    storage.resize(size);
  }

  reed_solomon *Workspace::reed_solomon_for(const int data_shards, const int parity_shards) {
    for (std::size_t index = 0; index < rs_cache_size_; ++index) {
      auto &entry = rs_cache_[index];
      if (entry.data_shards == data_shards && entry.parity_shards == parity_shards) {
        return entry.encoder.get();
      }
    }
    auto encoder = decltype(RsCacheEntry::encoder) {reed_solomon_new(data_shards, parity_shards)};
    if (!encoder) {
      throw std::bad_alloc {};
    }
    const auto entry_index = rs_cache_size_ < rs_cache_.size() ? rs_cache_size_++ : rs_cache_next_eviction_++ % rs_cache_.size();
    auto &entry = rs_cache_[entry_index];
    entry.data_shards = data_shards;
    entry.parity_shards = parity_shards;
    entry.encoder = std::move(encoder);
    ++allocation_stats_.reed_solomon_creations;
    return entry.encoder.get();
  }
}  // namespace video_packetizer
