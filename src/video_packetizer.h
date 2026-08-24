/**
 * @file src/video_packetizer.h
 * @brief Reusable storage and Reed-Solomon state for video packetization.
 */
#pragma once

// standard includes
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

extern "C" {
#include <moonlight-common-c/src/Video.h>
}

// lib includes
#include <rs.h>

// local includes
#include "crypto.h"
#include "platform/common.h"
#include "utility.h"

namespace video_packetizer {
  constexpr std::size_t maximum_fec_blocks = 4;  ///< GameStream multi-FEC block-count limit.
  constexpr std::size_t maximum_cached_rs_geometries = 32;  ///< Per-session Reed-Solomon cache bound.
  constexpr std::size_t maximum_wire_data_shards = 1023;  ///< Ten-bit GameStream data-shard count and index limit.
  constexpr std::size_t maximum_frame_data_shards = maximum_fec_blocks * maximum_wire_data_shards;  ///< Largest safe zero-FEC frame.
  constexpr std::size_t raw_packet_header_size = sizeof(RTP_PACKET) + 4U + sizeof(NV_VIDEO_PACKET);  ///< RTP, reserved, and GameStream header bytes.
  constexpr std::size_t encrypted_packet_prefix_size = sizeof(ENC_VIDEO_HEADER);  ///< IV, frame number, and AES-GCM tag bytes.

  /**
   * @brief Frame classification serialized into the short GameStream frame header.
   */
  enum class FrameKind : std::uint8_t {
    normal = 1,  ///< Ordinary predicted frame.
    idr = 2,  ///< Independently decodable recovery frame.
    reference_recovery = 5,  ///< Frame following reference-frame invalidation.
  };

  /**
   * @brief Complete fields used by the production GameStream packet-header serializer.
   */
  struct PacketHeaderFields {
    std::uint32_t frame_index;  ///< Encoded frame sequence.
    std::uint32_t stream_packet_index;  ///< Session packet sequence before the protocol's eight-bit shift.
    std::uint16_t rtp_sequence_number;  ///< RTP sequence number.
    std::uint32_t rtp_timestamp;  ///< RTP 90-kHz timestamp.
    std::size_t shard_index;  ///< Block-relative data or parity shard index.
    std::size_t data_shards;  ///< Original data shards in this block.
    int fec_percentage;  ///< Effective advertised FEC percentage.
    std::size_t block_index;  ///< Zero-based multi-FEC block index.
    std::size_t block_count;  ///< Total frame block count.
    bool start_of_block;  ///< Whether this is the first data shard in its block.
    bool end_of_block;  ///< Whether this is the final data shard in its block.
  };

  /**
   * @brief Serialize the exact eight-byte production short frame header.
   * @param kind Normal, IDR, or reference-recovery classification.
   * @param processing_latency_tenths_ms Capture-to-packetization latency in tenths of a millisecond.
   * @param encoded_payload_size Encoded frame bytes following the short header.
   * @param packet_payload_size Bytes available after each raw packet header.
   * @return Exact wire bytes preceding the encoded frame.
   */
  [[nodiscard]] std::array<std::uint8_t, 8> make_short_frame_header(
    FrameKind kind,
    std::uint16_t processing_latency_tenths_ms,
    std::size_t encoded_payload_size,
    std::size_t packet_payload_size
  );

  /**
   * @brief Initialize data-dependent packet fields before Reed-Solomon encoding.
   * @param header Exact raw packet-header storage.
   * @param fields Production header values for this data shard.
   */
  void prepare_data_packet_header(std::span<std::uint8_t> header, const PacketHeaderFields &fields);

  /**
   * @brief Finalize RTP and FEC fields after parity generation.
   *
   * For parity shards, bytes not explicitly described by RTP/FEC remain the
   * Reed-Solomon output exactly as in the legacy sender.
   *
   * @param header Exact raw packet-header storage.
   * @param fields Production header values for this data or parity shard.
   */
  void finalize_packet_header(std::span<std::uint8_t> header, const PacketHeaderFields &fields);

  /**
   * @brief Serialize a complete zero-FEC data packet header in one call.
   * @param header Exact raw packet-header storage.
   * @param fields Production header values for this data shard.
   */
  void serialize_data_packet_header(std::span<std::uint8_t> header, const PacketHeaderFields &fields);

  /**
   * @brief Encrypt one complete packet in place and serialize its GameStream prefix.
   * @param cipher Session AES-GCM cipher.
   * @param packet Complete raw-header and fixed-payload packet bytes.
   * @param frame_index Encoded frame number written into the prefix.
   * @param iv_counter Per-session invocation counter, incremented after use.
   * @param iv Reused 12-byte IV workspace.
   * @param prefix Exact encryption-prefix storage.
   */
  void encrypt_packet(
    crypto::cipher::gcm_t &cipher,
    std::span<std::uint8_t> packet,
    std::uint32_t frame_index,
    std::uint64_t &iv_counter,
    crypto::aes_t &iv,
    std::span<std::uint8_t> prefix
  );

  /**
   * @brief One contiguous packet range in a multi-FEC frame.
   */
  struct BlockRange {
    std::size_t byte_offset;  ///< Offset into the legacy interleaved frame.
    std::size_t byte_size;  ///< Unpadded bytes in this FEC block.
    std::size_t packet_offset;  ///< First frame-relative packet in this block.
    std::size_t packet_count;  ///< Number of padded wire packets in this block.
  };

  /**
   * @brief Immutable packet geometry calculated before one frame is serialized.
   */
  struct FramePlan {
    std::size_t wire_bytes;  ///< Legacy interleaved bytes before final-shard padding.
    std::size_t packet_count;  ///< Total data packets after padding the final packet.
    std::size_t block_count;  ///< Number of valid entries in `blocks`.
    bool exceeded_fec_block_limit;  ///< Whether normal FEC geometry required more than four blocks.
    std::array<BlockRange, maximum_fec_blocks> blocks;  ///< Multi-FEC packet ranges.
  };

  /**
   * @brief Reusable encoded FEC block view owned by a `Workspace`.
   *
   * The view and every pointer it exposes remain valid only until the next mutating
   * operation on the same workspace.
   */
  class EncodedBlockView {
  public:
    /**
     * @brief Return one full packet shard.
     * @param index Block-relative shard index.
     * @return Mutable packet bytes.
     */
    [[nodiscard]] char *data(std::size_t index) const;

    /**
     * @brief Return one optional encryption prefix.
     * @param index Block-relative shard index.
     * @return Prefix bytes, or `nullptr` when prefixes are disabled.
     */
    [[nodiscard]] char *prefix(std::size_t index) const;

    /**
     * @brief Return the total data and recovery shard count.
     * @return Shard count.
     */
    [[nodiscard]] std::size_t size() const;

    std::size_t data_shards {};  ///< Original data shard count.
    std::size_t percentage {};  ///< Effective recovery percentage advertised on wire.
    std::size_t block_size {};  ///< Fixed bytes in each packet shard.
    std::size_t prefix_size {};  ///< Optional bytes prepended during send.
    std::vector<platf::buffer_descriptor_t> *payload_buffers {};  ///< Reused batched-send descriptors.

  private:
    friend class Workspace;
    std::span<std::uint8_t *> shard_pointers_;  ///< Workspace-owned shard pointer table.
    std::span<char> prefixes_;  ///< Workspace-owned optional prefix storage.
  };

  /**
   * @brief Counts capacity growth and Reed-Solomon creation for allocation tests.
   */
  struct AllocationStats {
    std::uint64_t buffer_growth_events {};  ///< Vector capacity increases after construction.
    std::uint64_t reed_solomon_creations {};  ///< Cached encoder instances created.
  };

  /**
   * @brief Per-session reusable packetization storage and Reed-Solomon cache.
   */
  class Workspace {
  public:
    /**
     * @brief Construct an isolated packetization workspace.
     * @param maximum_frame_bytes Largest accepted encoded frame plus frame header.
     */
    explicit Workspace(std::size_t maximum_frame_bytes = 256U * 1024U * 1024U);

    Workspace(const Workspace &) = delete;  ///< Session workspaces cannot share pointer-bearing state.
    Workspace &operator=(const Workspace &) = delete;  ///< Session workspaces cannot share pointer-bearing state.
    Workspace(Workspace &&) = delete;  ///< Stable per-session storage is intentionally non-movable.
    Workspace &operator=(Workspace &&) = delete;  ///< Stable per-session storage is intentionally non-movable.

    /**
     * @brief Calculate the exact legacy multi-FEC splitting geometry.
     * @param frame_header_size Bytes prepended to the encoded frame payload.
     * @param payload_size Encoded frame bytes.
     * @param raw_header_size Bytes inserted before every packet payload slice.
     * @param block_size Complete wire packet size.
     * @param fec_percentage Effective FEC percentage, or its nonzero upper bound.
     * @return Validated frame and block geometry.
     */
    [[nodiscard]] FramePlan plan_frame(
      std::size_t frame_header_size,
      std::size_t payload_size,
      std::size_t raw_header_size,
      std::size_t block_size,
      int fec_percentage
    ) const;

    /**
     * @brief Serialize legacy interleaved header slots into reusable storage.
     * @param frame_header Frame header bytes preceding the encoded frame.
     * @param payload Encoded frame bytes.
     * @param raw_header_size Zero-initialized bytes inserted before each payload slice.
     * @param block_size Complete wire packet size.
     * @return Mutable legacy frame bytes valid until this workspace is reused.
     */
    [[nodiscard]] std::span<std::uint8_t> prepare_interleaved_frame(
      std::span<const std::uint8_t> frame_header,
      std::string_view payload,
      std::size_t raw_header_size,
      std::size_t block_size
    );

    /**
     * @brief Prepare zero-copy payload descriptors for a zero-FEC frame.
     *
     * Only the first and possibly final packet payloads are copied because they
     * contain the frame header or required trailing wire padding. Complete middle
     * packet payloads reference the encoder-owned frame directly.
     *
     * @param frame_header Frame header bytes preceding the encoded frame.
     * @param payload Encoded frame bytes whose lifetime covers all sends.
     * @param raw_header_size Per-packet header bytes held separately.
     * @param block_size Complete wire packet size.
     * @return Reusable payload descriptors aligned to the packet payload size.
     */
    [[nodiscard]] std::vector<platf::buffer_descriptor_t> &prepare_segmented_frame(
      std::span<const std::uint8_t> frame_header,
      std::string_view payload,
      std::size_t raw_header_size,
      std::size_t block_size
    );

    /**
     * @brief Zero and return a range of segmented packet-header slots.
     * @param packet_offset First frame-relative packet.
     * @param packet_count Header count.
     * @param raw_header_size Header bytes per packet.
     * @return Mutable contiguous header bytes for this batch.
     */
    [[nodiscard]] std::span<std::uint8_t> prepare_segmented_headers(
      std::size_t packet_offset,
      std::size_t packet_count,
      std::size_t raw_header_size
    );

    /**
     * @brief Return one segmented packet header.
     * @param packet_index Frame-relative packet index.
     * @param raw_header_size Header bytes per packet.
     * @return Mutable header pointer.
     */
    [[nodiscard]] std::uint8_t *segmented_header(std::size_t packet_index, std::size_t raw_header_size);

    /**
     * @brief Return one fixed-size segmented payload.
     * @param packet_index Frame-relative packet index.
     * @param payload_size Fixed packet payload bytes.
     * @return Payload pointer, or `nullptr` for an invalid index.
     */
    [[nodiscard]] const char *segmented_payload(std::size_t packet_index, std::size_t payload_size) const;

    /**
     * @brief Encode one initialized legacy packet block using reusable storage.
     * @param payload Initialized interleaved data packet bytes.
     * @param block_size Fixed packet shard size.
     * @param fec_percentage Requested recovery percentage.
     * @param minimum_parity_shards Negotiated minimum recovery shards.
     * @param prefix_size Optional encryption prefix bytes per shard.
     * @return Workspace-owned encoded block view.
     */
    [[nodiscard]] EncodedBlockView encode_block(
      std::span<std::uint8_t> payload,
      std::size_t block_size,
      int fec_percentage,
      std::size_t minimum_parity_shards,
      std::size_t prefix_size
    );

    /**
     * @brief Return allocation instrumentation for this session workspace.
     * @return Monotonic counters.
     */
    [[nodiscard]] AllocationStats allocation_stats() const;

    /**
     * @brief Record when the first send batch became fully addressable.
     */
    void mark_first_batch_ready();

    /**
     * @brief Return whether the current frame reached first-batch readiness.
     * @return `true` after `mark_first_batch_ready()`.
     */
    [[nodiscard]] bool first_batch_ready() const;

  private:
    /**
     * @brief Cached Reed-Solomon encoder with one validated geometry.
     */
    struct RsCacheEntry {
      int data_shards {};  ///< Original shard count key.
      int parity_shards {};  ///< Recovery shard count key.
      util::safe_ptr<reed_solomon, [](reed_solomon *rs) {
        reed_solomon_release(rs);
      }>
        encoder;  ///< Cached nanors encoder and generator matrix.
    };

    /**
     * @brief Grow a byte vector while counting capacity changes.
     * @param storage Vector to resize.
     * @param size Required logical size.
     */
    void resize_bytes(std::vector<std::uint8_t> &storage, std::size_t size);

    /**
     * @brief Return or create a bounded cached Reed-Solomon encoder.
     * @param data_shards Original shard count.
     * @param parity_shards Recovery shard count.
     * @return Valid encoder.
     */
    reed_solomon *reed_solomon_for(int data_shards, int parity_shards);

    std::size_t maximum_frame_bytes_;  ///< Per-session input-size cap.
    std::vector<std::uint8_t> interleaved_;  ///< Reused legacy interleaved frame bytes.
    std::vector<std::uint8_t> shard_storage_;  ///< Reused padded-final and parity shards.
    std::vector<std::uint8_t> prefix_storage_;  ///< Reused optional encryption prefixes.
    std::vector<std::uint8_t *> shard_pointers_;  ///< Reused nanors pointer table.
    std::vector<std::uint8_t> segmented_headers_;  ///< Reused zero-FEC packet headers.
    std::vector<std::uint8_t> segmented_first_payload_;  ///< Frame-header-bearing first payload.
    std::vector<std::uint8_t> segmented_final_payload_;  ///< Padded final payload when required.
    std::vector<platf::buffer_descriptor_t> payload_buffers_;  ///< Reused scatter/gather descriptors.
    std::array<RsCacheEntry, maximum_cached_rs_geometries> rs_cache_;  ///< Bounded per-session FEC cache.
    std::size_t rs_cache_size_ {};  ///< Populated cache entries.
    std::size_t rs_cache_next_eviction_ {};  ///< Round-robin replacement index after the cache fills.
    std::size_t segmented_packet_count_ {};  ///< Active segmented-frame packet count.
    AllocationStats allocation_stats_;  ///< Monotonic allocation instrumentation.
    bool first_batch_ready_ {};  ///< Current-frame readiness seam.
  };
}  // namespace video_packetizer
