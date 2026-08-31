/**
 * @file src/protocol_lsp/media/frame_pipeline.h
 * @brief Bounded LSP video admission, reassembly, decode-credit, and render-mailbox primitives.
 */

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace lumen::lsp::media {
  /** @brief Competition-mode encoded-frame byte ceiling from the LSP/1 resource bounds. */
  inline constexpr std::size_t competition_frame_size_limit = 16U * 1024U * 1024U;

  /** @brief Absolute encoded-frame parser byte ceiling from the LSP/1 resource bounds. */
  inline constexpr std::size_t absolute_frame_size_limit = 64U * 1024U * 1024U;

  /** @brief Maximum number of RTP fragments retained for one encoded frame. */
  inline constexpr std::size_t maximum_fragments_per_frame = 65'536;

  /** @brief Input size basis used for complete-frame admission. */
  enum class frame_size_mode : std::uint8_t {
    complete_access_unit,  ///< Exact complete encoded access-unit bytes are known.
    bounded_incremental,  ///< Encoder-declared maximum access-unit bytes are reserved before first send.
  };

  /** @brief Values used to derive a video's network deadline. */
  struct network_deadline_request {
    std::uint64_t capture_time_us = 0;  ///< Monotonic capture-acquire time.
    std::uint64_t maximum_capture_to_client_us = 0;  ///< Selected maximum capture-to-client budget.
    std::uint64_t encode_reserve_us = 0;  ///< Measured remaining encoder reserve.
    std::uint64_t decode_reserve_us = 0;  ///< Measured decoder reserve.
    std::uint64_t render_reserve_us = 0;  ///< Measured render reserve.
    std::uint64_t next_presentation_time_us = std::numeric_limits<std::uint64_t>::max();  ///< Competition presentation clamp.
  };

  /**
   * @brief Compute the latest network completion deadline without unsigned wrap.
   *
   * The result implements `capture + maximum budget - encode/decode/render reserves`, clamped to
   * the next selected presentation opportunity. A reserve sum that consumes the budget produces
   * the capture time so admission will fail once work starts after capture.
   *
   * @param request Capture budget and measured reserves.
   * @return Monotonic network deadline in microseconds.
   */
  [[nodiscard]] constexpr std::uint64_t compute_network_deadline(const network_deadline_request &request) noexcept {
    const auto reserve_limit = request.maximum_capture_to_client_us;
    auto reserves = std::min(request.encode_reserve_us, reserve_limit);
    reserves += std::min(request.decode_reserve_us, reserve_limit - reserves);
    reserves += std::min(request.render_reserve_us, reserve_limit - reserves);
    const auto network_budget = request.maximum_capture_to_client_us - reserves;
    const auto maximum = std::numeric_limits<std::uint64_t>::max();
    const auto budget_deadline = request.capture_time_us > maximum - network_budget ? maximum : request.capture_time_us + network_budget;
    return std::min(budget_deadline, request.next_presentation_time_us);
  }

  /** @brief Complete-frame admission request evaluated before first packet submission. */
  struct frame_admission_request {
    frame_size_mode size_mode = frame_size_mode::complete_access_unit;  ///< Exact or maximum-size admission basis.
    std::size_t source_bytes = 0;  ///< Exact encoded bytes or declared maximum incremental bytes.
    std::size_t selected_repair_bytes = 0;  ///< Worst-case selected repair bytes.
    std::uint64_t pacing_rate_bits_per_second = 0;  ///< Current aggregate forward pacing rate.
    std::uint64_t now_us = 0;  ///< Admission decision time.
    std::uint64_t network_deadline_us = 0;  ///< Latest time all protected frame bytes may leave the pacer.
    std::uint8_t decoder_credits = 0;  ///< Freshness-bounded client hardware-decode credit.
    bool reference_path_valid = true;  ///< Whether encoder dependency metadata permits this frame.
  };

  /** @brief Complete-frame admission outcome. */
  enum class frame_admission_status : std::uint8_t {
    admitted,  ///< The complete protected frame can leave before its deadline.
    invalid_size,  ///< Size is zero, over the absolute parser bound, or overflows with repair.
    invalid_pacing_rate,  ///< No positive pacing rate is available.
    expired,  ///< The network deadline has already arrived.
    decoder_saturated,  ///< No hardware decoder submission credit is available.
    invalid_reference_path,  ///< Encoder dependency metadata says this frame cannot be decoded.
    misses_deadline,  ///< Complete serialization would finish after the network deadline.
  };

  /** @brief Complete-frame admission decision and serialization estimate. */
  struct frame_admission_result {
    frame_admission_status status = frame_admission_status::invalid_size;  ///< Admission outcome.
    std::uint64_t estimated_serialization_us = 0;  ///< Ceiling serialization time for source plus selected repair.
    std::uint64_t estimated_completion_us = 0;  ///< Estimated pacer completion time.

    /**
     * @brief Return whether the frame is admitted.
     *
     * @return `true` only for `frame_admission_status::admitted`.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return status == frame_admission_status::admitted;
    }
  };

  /**
   * @brief Evaluate complete-frame serialization, reference, deadline, and decoder-credit admission.
   *
   * @param request Complete admission inputs.
   * @return Admission status and timing estimate.
   */
  [[nodiscard]] constexpr frame_admission_result admit_frame(const frame_admission_request &request) noexcept {
    if (request.source_bytes == 0 || request.source_bytes > absolute_frame_size_limit ||
        request.selected_repair_bytes > absolute_frame_size_limit - request.source_bytes) {
      return {.status = frame_admission_status::invalid_size};
    }
    if (request.pacing_rate_bits_per_second == 0) {
      return {.status = frame_admission_status::invalid_pacing_rate};
    }
    if (request.now_us >= request.network_deadline_us) {
      return {.status = frame_admission_status::expired};
    }
    if (request.decoder_credits == 0) {
      return {.status = frame_admission_status::decoder_saturated};
    }
    if (!request.reference_path_valid) {
      return {.status = frame_admission_status::invalid_reference_path};
    }

    const auto total_bytes = static_cast<std::uint64_t>(request.source_bytes + request.selected_repair_bytes);
    const auto scaled_bits = total_bytes * 8U * 1'000'000U;
    const auto serialization_us = scaled_bits / request.pacing_rate_bits_per_second +
                                  (scaled_bits % request.pacing_rate_bits_per_second != 0 ? 1U : 0U);
    const auto maximum = std::numeric_limits<std::uint64_t>::max();
    const auto completion = request.now_us > maximum - serialization_us ? maximum : request.now_us + serialization_us;
    return {
      .status = completion <= request.network_deadline_us ? frame_admission_status::admitted : frame_admission_status::misses_deadline,
      .estimated_serialization_us = serialization_us,
      .estimated_completion_us = completion,
    };
  }

  /** @brief Shared immutable packet storage retained through frame reassembly. */
  using retained_packet_storage = std::shared_ptr<const std::vector<std::uint8_t>>;

  /** @brief Immutable retained byte slice backed by shared packet storage. */
  class retained_packet_slice {
  public:
    /** @brief Construct an empty invalid slice. */
    retained_packet_slice() = default;

    /**
     * @brief Retain a validated slice of immutable packet storage.
     *
     * @param storage Shared packet bytes.
     * @param offset First retained byte.
     * @param size Retained byte count.
     * @return Retained slice, or no value for null storage, an empty slice, or invalid bounds.
     */
    [[nodiscard]] static std::optional<retained_packet_slice> retain(
      retained_packet_storage storage,
      const std::size_t offset,
      const std::size_t size
    ) noexcept {
      if (!storage || size == 0 || offset > storage->size() || size > storage->size() - offset) {
        return std::nullopt;
      }
      return retained_packet_slice(std::move(storage), offset, size);
    }

    /**
     * @brief Copy bytes into new immutable retained packet storage.
     *
     * This helper is intended for ownership boundaries and tests; the live receiver normally calls
     * `retain()` on its packet-slab ownership object and performs no payload copy.
     *
     * @param bytes Bytes to retain.
     * @return Retained slice, or no value for an empty input.
     */
    [[nodiscard]] static std::optional<retained_packet_slice> copy(const std::span<const std::uint8_t> bytes) {
      if (bytes.empty()) {
        return std::nullopt;
      }
      auto storage = std::make_shared<const std::vector<std::uint8_t>>(bytes.begin(), bytes.end());
      return retained_packet_slice(std::move(storage), 0, bytes.size());
    }

    /**
     * @brief Return the retained immutable bytes.
     *
     * @return Borrowed span valid for this slice's lifetime.
     */
    [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept {
      if (!storage_) {
        return {};
      }
      return std::span<const std::uint8_t>(*storage_).subspan(offset_, size_);
    }

    /**
     * @brief Return whether this slice retains valid storage.
     *
     * @return `true` for a nonempty retained slice.
     */
    [[nodiscard]] explicit operator bool() const noexcept {
      return storage_ && size_ != 0;
    }

  private:
    /**
     * @brief Construct a slice after bounds validation.
     *
     * @param storage Shared immutable packet storage.
     * @param offset First retained byte.
     * @param size Retained byte count.
     */
    retained_packet_slice(retained_packet_storage storage, const std::size_t offset, const std::size_t size) noexcept:
        storage_(std::move(storage)),
        offset_(offset),
        size_(size) {
    }

    retained_packet_storage storage_ {};  ///< Shared immutable packet storage.
    std::size_t offset_ = 0;  ///< First retained byte in `storage_`.
    std::size_t size_ = 0;  ///< Retained byte count.
  };

  /** @brief Provisional frame key available on every authenticated video packet. */
  struct frame_key {
    std::uint32_t ssrc = 0;  ///< Negotiated nonzero primary video SSRC.
    std::uint64_t extended_timestamp = 0;  ///< Extended 90 kHz RTP timestamp.

    /** @brief Compare the complete provisional frame key. */
    [[nodiscard]] bool operator==(const frame_key &) const noexcept = default;
  };

  /** @brief One authenticated codec fragment supplied to the bounded frame reassembler. */
  struct frame_fragment {
    frame_key key {};  ///< SSRC and extended timestamp identifying provisional assembly.
    std::uint64_t frame_id = 0;  ///< Repeated nonzero frame ID, or zero when boundary metadata was lost.
    std::uint64_t extended_sequence = 0;  ///< Extended RTP sequence number.
    std::uint64_t deadline_us = 0;  ///< Frame network/decode deadline.
    bool starts_frame = false;  ///< Codec/frame-marking start indication.
    bool ends_frame = false;  ///< Codec/frame-marking end indication.
    bool marker = false;  ///< RTP marker bit, required exactly on the ending fragment.
    retained_packet_slice payload {};  ///< Retained codec bytes for this fragment.
  };

  /** @brief Immutable completed encoded frame retaining its packet payload slices. */
  class completed_frame {
  public:
    /**
     * @brief Construct a completed frame from validated ordered slices.
     *
     * @param key Provisional RTP frame key.
     * @param frame_id Repeated frame ID, or zero when metadata was lost.
     * @param deadline_us Frame deadline.
     * @param slices Ordered immutable codec slices.
     * @param total_size Total encoded bytes across all slices.
     */
    completed_frame(
      const frame_key key,
      const std::uint64_t frame_id,
      const std::uint64_t deadline_us,
      std::vector<retained_packet_slice> slices,
      const std::size_t total_size
    ):
        key_(key),
        frame_id_(frame_id),
        deadline_us_(deadline_us),
        slices_(std::move(slices)),
        total_size_(total_size) {
    }

    /**
     * @brief Return the provisional RTP frame key.
     *
     * @return SSRC and extended timestamp.
     */
    [[nodiscard]] frame_key key() const noexcept {
      return key_;
    }

    /**
     * @brief Return the bound frame ID when repeated metadata arrived.
     *
     * @return Nonzero frame ID or zero when all repeated metadata was lost.
     */
    [[nodiscard]] std::uint64_t frame_id() const noexcept {
      return frame_id_;
    }

    /**
     * @brief Return the frame deadline.
     *
     * @return Monotonic deadline in microseconds.
     */
    [[nodiscard]] std::uint64_t deadline_us() const noexcept {
      return deadline_us_;
    }

    /**
     * @brief Return ordered immutable encoded slices.
     *
     * @return Borrowed slice array retained by this completed frame.
     */
    [[nodiscard]] std::span<const retained_packet_slice> slices() const noexcept {
      return slices_;
    }

    /**
     * @brief Return total encoded-frame bytes.
     *
     * @return Sum of every retained slice length.
     */
    [[nodiscard]] std::size_t size() const noexcept {
      return total_size_;
    }

    /**
     * @brief Coalesce the frame once for decoder APIs that cannot consume chained slices.
     *
     * @return Contiguous encoded frame bytes.
     */
    [[nodiscard]] std::vector<std::uint8_t> coalesce() const {
      std::vector<std::uint8_t> bytes;
      bytes.reserve(total_size_);
      for (const auto &slice : slices_) {
        const auto source = slice.bytes();
        bytes.insert(bytes.end(), source.begin(), source.end());
      }
      return bytes;
    }

  private:
    frame_key key_ {};  ///< Provisional RTP frame key.
    std::uint64_t frame_id_ = 0;  ///< Bound repeated frame ID, or zero.
    std::uint64_t deadline_us_ = 0;  ///< Frame deadline.
    std::vector<retained_packet_slice> slices_ {};  ///< Ordered retained codec slices.
    std::size_t total_size_ = 0;  ///< Total encoded bytes.
  };

  /** @brief Copyable retained handle to one immutable complete encoded frame. */
  class retained_frame_handle {
  public:
    /** @brief Construct an empty frame handle. */
    retained_frame_handle() = default;

    /**
     * @brief Construct a retained frame handle from shared immutable frame ownership.
     *
     * @param frame Shared completed frame.
     */
    explicit retained_frame_handle(std::shared_ptr<const completed_frame> frame) noexcept:
        frame_(std::move(frame)) {
    }

    /**
     * @brief Return the retained frame.
     *
     * @return Frame pointer, or null for an empty handle.
     */
    [[nodiscard]] const completed_frame *get() const noexcept {
      return frame_.get();
    }

    /**
     * @brief Return whether this handle retains a frame.
     *
     * @return `true` for a nonempty handle.
     */
    [[nodiscard]] explicit operator bool() const noexcept {
      return static_cast<bool>(frame_);
    }

    /** @brief Release this handle's retained frame reference. */
    void reset() noexcept {
      frame_.reset();
    }

  private:
    std::shared_ptr<const completed_frame> frame_ {};  ///< Shared immutable completed-frame ownership.
  };

  /** @brief Outcome of adding one fragment to the two-frame bounded reassembler. */
  enum class frame_reassembly_status : std::uint8_t {
    stored,  ///< Fragment was stored but the frame remains incomplete.
    duplicate,  ///< Byte-identical duplicate fragment was ignored.
    completed,  ///< Frame completed and a retained handle is returned.
    expired,  ///< Fragment or existing frame reached its deadline.
    malformed,  ///< Boundary, marker, identity, deadline, or duplicate bytes conflict.
    frame_too_large,  ///< Frame byte or fragment-count resource bound would be exceeded.
    evicted_and_stored,  ///< Oldest incomplete frame was evicted to retain this newer frame.
    resource_exhausted,  ///< Preallocated storage is unavailable until a completed view is released.
  };

  /** @brief Frame-reassembly operation result. */
  struct frame_reassembly_result {
    frame_reassembly_status status = frame_reassembly_status::stored;  ///< Operation outcome.
    retained_frame_handle frame {};  ///< Completed frame only when `status` is `completed`.
    std::optional<frame_key> evicted {};  ///< Oldest frame key evicted for a third incomplete frame.
  };

  /** @brief Two-incomplete-frame bounded video reassembler with retained packet slices. */
  class video_frame_reassembler {
  public:
    /**
     * @brief Construct a reassembler with an explicit frame byte bound.
     *
     * @param maximum_frame_size Maximum accepted encoded bytes, at most the absolute parser limit.
     */
    explicit video_frame_reassembler(const std::size_t maximum_frame_size = competition_frame_size_limit) noexcept:
        maximum_frame_size_(std::min(maximum_frame_size, absolute_frame_size_limit)) {
    }

    /**
     * @brief Add one authenticated fragment and return a completed retained frame when contiguous.
     *
     * @param fragment Authenticated fragment metadata and retained codec payload.
     * @param now_us Current monotonic time.
     * @return Bounded storage, duplicate, error, eviction, or completion result.
     */
    [[nodiscard]] frame_reassembly_result add(frame_fragment fragment, const std::uint64_t now_us) {
      expire(now_us);
      if (fragment.key.ssrc == 0 || !fragment.payload || fragment.deadline_us <= now_us || fragment.marker != fragment.ends_frame) {
        return {.status = fragment.deadline_us <= now_us ? frame_reassembly_status::expired : frame_reassembly_status::malformed};
      }

      auto *slot = find_slot(fragment.key);
      std::optional<frame_key> evicted;
      auto initial_status = frame_reassembly_status::stored;
      if (slot == nullptr) {
        slot = empty_slot();
        if (slot == nullptr) {
          slot = oldest_slot();
          evicted = slot->key;
          *slot = {};
          initial_status = frame_reassembly_status::evicted_and_stored;
        }
        slot->occupied = true;
        slot->key = fragment.key;
        slot->deadline_us = fragment.deadline_us;
        slot->arrival_order = next_arrival_order_++;
      } else if (slot->deadline_us != fragment.deadline_us) {
        *slot = {};
        return {.status = frame_reassembly_status::malformed};
      }

      if (fragment.frame_id != 0) {
        if (slot->frame_id != 0 && slot->frame_id != fragment.frame_id) {
          *slot = {};
          return {.status = frame_reassembly_status::malformed};
        }
        slot->frame_id = fragment.frame_id;
      }

      for (const auto &existing : slot->fragments) {
        if (existing.extended_sequence != fragment.extended_sequence) {
          continue;
        }
        if (existing.starts_frame == fragment.starts_frame && existing.ends_frame == fragment.ends_frame &&
            std::ranges::equal(existing.payload.bytes(), fragment.payload.bytes())) {
          return {.status = frame_reassembly_status::duplicate, .evicted = evicted};
        }
        *slot = {};
        return {.status = frame_reassembly_status::malformed};
      }

      if ((slot->start_sequence && fragment.extended_sequence < *slot->start_sequence) ||
          (slot->end_sequence && fragment.extended_sequence > *slot->end_sequence) ||
          (fragment.starts_frame && slot->start_sequence) ||
          (fragment.ends_frame && slot->end_sequence)) {
        *slot = {};
        return {.status = frame_reassembly_status::malformed};
      }
      if (fragment.starts_frame) {
        const auto lower_exists = std::ranges::any_of(slot->fragments, [&](const stored_fragment &stored) {
          return stored.extended_sequence < fragment.extended_sequence;
        });
        if (lower_exists) {
          *slot = {};
          return {.status = frame_reassembly_status::malformed};
        }
        slot->start_sequence = fragment.extended_sequence;
      }
      if (fragment.ends_frame) {
        const auto higher_exists = std::ranges::any_of(slot->fragments, [&](const stored_fragment &stored) {
          return stored.extended_sequence > fragment.extended_sequence;
        });
        if (higher_exists) {
          *slot = {};
          return {.status = frame_reassembly_status::malformed};
        }
        slot->end_sequence = fragment.extended_sequence;
      }

      const auto payload_size = fragment.payload.bytes().size();
      if (payload_size > maximum_frame_size_ - slot->total_size || slot->fragments.size() >= maximum_fragments_per_frame) {
        *slot = {};
        return {.status = frame_reassembly_status::frame_too_large};
      }
      slot->total_size += payload_size;
      slot->fragments.push_back({
        .extended_sequence = fragment.extended_sequence,
        .starts_frame = fragment.starts_frame,
        .ends_frame = fragment.ends_frame,
        .payload = std::move(fragment.payload),
      });

      if (!slot->start_sequence || !slot->end_sequence) {
        return {.status = initial_status, .evicted = evicted};
      }
      if (*slot->end_sequence < *slot->start_sequence ||
          *slot->end_sequence - *slot->start_sequence + 1 != slot->fragments.size()) {
        return {.status = initial_status, .evicted = evicted};
      }

      std::ranges::sort(slot->fragments, {}, &stored_fragment::extended_sequence);
      for (std::size_t index = 0; index < slot->fragments.size(); ++index) {
        if (slot->fragments[index].extended_sequence != *slot->start_sequence + index) {
          return {.status = initial_status, .evicted = evicted};
        }
      }
      std::vector<retained_packet_slice> slices;
      slices.reserve(slot->fragments.size());
      for (auto &stored : slot->fragments) {
        slices.push_back(std::move(stored.payload));
      }
      auto completed = std::make_shared<const completed_frame>(
        slot->key,
        slot->frame_id,
        slot->deadline_us,
        std::move(slices),
        slot->total_size
      );
      *slot = {};
      return {
        .status = frame_reassembly_status::completed,
        .frame = retained_frame_handle(std::move(completed)),
        .evicted = evicted,
      };
    }

    /**
     * @brief Expire every incomplete frame whose deadline has arrived.
     *
     * @param now_us Current monotonic time.
     * @return Number of expired incomplete frames.
     */
    std::size_t expire(const std::uint64_t now_us) noexcept {
      std::size_t count = 0;
      for (auto &slot : slots_) {
        if (slot.occupied && slot.deadline_us <= now_us) {
          slot = {};
          ++count;
        }
      }
      return count;
    }

    /**
     * @brief Return the number of retained incomplete frames.
     *
     * @return Value in the closed range `0...2`.
     */
    [[nodiscard]] std::size_t incomplete_frames() const noexcept {
      return std::ranges::count_if(slots_, [](const frame_slot &slot) {
        return slot.occupied;
      });
    }

  private:
    /** @brief Stored fragment metadata and retained codec bytes. */
    struct stored_fragment {
      std::uint64_t extended_sequence = 0;  ///< Extended RTP sequence number.
      bool starts_frame = false;  ///< Whether this fragment starts the frame.
      bool ends_frame = false;  ///< Whether this fragment ends the frame.
      retained_packet_slice payload {};  ///< Retained immutable codec bytes.
    };

    /** @brief State for one of the two incomplete-frame slots. */
    struct frame_slot {
      bool occupied = false;  ///< Whether this slot currently retains a frame.
      frame_key key {};  ///< Provisional frame key.
      std::uint64_t frame_id = 0;  ///< Bound repeated frame ID, or zero.
      std::uint64_t deadline_us = 0;  ///< Frame deadline.
      std::uint64_t arrival_order = 0;  ///< Monotonic insertion order used for bounded eviction.
      std::optional<std::uint64_t> start_sequence {};  ///< Observed start fragment sequence.
      std::optional<std::uint64_t> end_sequence {};  ///< Observed end fragment sequence.
      std::vector<stored_fragment> fragments {};  ///< Unordered retained fragments.
      std::size_t total_size = 0;  ///< Total encoded bytes retained by this frame.
    };

    /**
     * @brief Find an occupied slot by provisional key.
     *
     * @param key SSRC and extended timestamp.
     * @return Matching slot, or null.
     */
    [[nodiscard]] frame_slot *find_slot(const frame_key key) noexcept {
      const auto iterator = std::ranges::find_if(slots_, [&](const frame_slot &slot) {
        return slot.occupied && slot.key == key;
      });
      return iterator == slots_.end() ? nullptr : &*iterator;
    }

    /**
     * @brief Find an unused frame slot.
     *
     * @return Empty slot, or null when both are occupied.
     */
    [[nodiscard]] frame_slot *empty_slot() noexcept {
      const auto iterator = std::ranges::find_if(slots_, [](const frame_slot &slot) {
        return !slot.occupied;
      });
      return iterator == slots_.end() ? nullptr : &*iterator;
    }

    /**
     * @brief Find the oldest occupied frame slot.
     *
     * @return Oldest slot; both slots are known occupied when called.
     */
    [[nodiscard]] frame_slot *oldest_slot() noexcept {
      return &*std::ranges::min_element(slots_, {}, &frame_slot::arrival_order);
    }

    std::array<frame_slot, 2> slots_ {};  ///< Hard-bounded incomplete-frame storage.
    std::size_t maximum_frame_size_ = competition_frame_size_limit;  ///< Per-frame encoded byte bound.
    std::uint64_t next_arrival_order_ = 1;  ///< Monotonic slot insertion order.
  };

  /** @brief One authenticated codec fragment copied into preallocated frame storage. */
  struct pooled_frame_fragment {
    frame_key key {};  ///< SSRC and extended timestamp identifying provisional assembly.
    std::uint64_t frame_id = 0;  ///< Repeated nonzero frame ID, or zero when metadata was absent.
    std::uint64_t extended_sequence = 0;  ///< Extended RTP sequence number.
    std::uint64_t deadline_us = 0;  ///< Fixed frame receive/decode deadline.
    bool starts_frame = false;  ///< Codec/frame-marking start indication.
    bool ends_frame = false;  ///< Codec/frame-marking end indication.
    bool marker = false;  ///< RTP marker bit, required exactly on the ending fragment.
    std::span<const std::uint8_t> payload {};  ///< Transient authenticated codec bytes copied by `add()`.
  };

  /** @brief Borrowed completed-frame view valid until explicitly released. */
  struct pooled_completed_frame_view {
    frame_key key {};  ///< Completed SSRC and extended timestamp.
    std::uint64_t frame_id = 0;  ///< Bound repeated nonzero frame ID.
    std::uint64_t deadline_us = 0;  ///< Fixed frame deadline.
    std::span<const std::span<const std::uint8_t>> slices {};  ///< Sequence-ordered immutable codec slices.
    std::size_t total_size = 0;  ///< Sum of all slice byte counts.
    std::uint64_t token = 0;  ///< Opaque nonzero release token.
    std::uint8_t slot = 0;  ///< Internal preallocated slot index.

    /** @brief Return whether this view names one live completed slot. */
    [[nodiscard]] explicit operator bool() const noexcept {
      return token != 0 && !slices.empty() && total_size != 0;
    }
  };

  /** @brief Allocation-free pooled reassembly operation result. */
  struct pooled_frame_reassembly_result {
    frame_reassembly_status status = frame_reassembly_status::stored;  ///< Operation outcome.
    pooled_completed_frame_view frame {};  ///< Completed borrowed frame only for `completed`.
    std::optional<frame_key> evicted {};  ///< Oldest incomplete key evicted for a third frame.
  };

  /**
   * @brief Two-frame reassembler whose packet metadata and bytes are allocated only at configuration.
   *
   * The caller must consume and release a completed view before another completed frame can reuse
   * its slot. `add()`, `expire()`, completion, and release perform no heap allocation.
   */
  class pooled_video_frame_reassembler {
  public:
    /**
     * @brief Allocate both frame byte regions and bounded fragment tables.
     *
     * @param maximum_frame_size Maximum completed codec bytes per frame.
     * @param maximum_fragments Maximum RTP fragments retained per frame.
     */
    explicit pooled_video_frame_reassembler(
      const std::size_t maximum_frame_size = competition_frame_size_limit,
      const std::size_t maximum_fragments = maximum_fragments_per_frame
    ) noexcept:
        maximum_frame_size_(std::min(maximum_frame_size, absolute_frame_size_limit)),
        maximum_fragments_(std::min(maximum_fragments, maximum_fragments_per_frame)) {
      if (maximum_frame_size_ == 0 || maximum_fragments_ == 0) {
        return;
      }
      ready_ = std::ranges::all_of(slots_, [&](frame_slot &slot) {
        slot.bytes.reset(new (std::nothrow) std::uint8_t[maximum_frame_size_]);
        slot.fragments.reset(new (std::nothrow) stored_fragment[maximum_fragments_]);
        slot.ordered_slices.reset(new (std::nothrow) std::span<const std::uint8_t>[maximum_fragments_]);
        return slot.bytes && slot.fragments && slot.ordered_slices;
      });
    }

    /** @brief Return whether every bounded slot allocation succeeded. */
    [[nodiscard]] bool ready() const noexcept {
      return ready_;
    }

    /**
     * @brief Copy one authenticated fragment and return a borrowed completed view when contiguous.
     *
     * @param fragment Authenticated transient fragment metadata and bytes.
     * @param now_us Current monotonic time.
     * @return Stored, duplicate, error, eviction, resource, or completion result.
     */
    [[nodiscard]] pooled_frame_reassembly_result add(
      const pooled_frame_fragment &fragment,
      const std::uint64_t now_us
    ) noexcept {
      if (!ready_) {
        return {.status = frame_reassembly_status::resource_exhausted};
      }
      expire(now_us);
      if (fragment.key.ssrc == 0 || fragment.payload.empty() || fragment.deadline_us <= now_us ||
          fragment.marker != fragment.ends_frame) {
        return {.status = fragment.deadline_us <= now_us ? frame_reassembly_status::expired : frame_reassembly_status::malformed};
      }

      auto *slot = find_slot(fragment.key);
      std::optional<frame_key> evicted;
      auto initial_status = frame_reassembly_status::stored;
      if (slot == nullptr) {
        slot = empty_slot();
        if (slot == nullptr) {
          slot = oldest_incomplete_slot();
          if (slot == nullptr) {
            return {.status = frame_reassembly_status::resource_exhausted};
          }
          evicted = slot->key;
          reset(*slot);
          initial_status = frame_reassembly_status::evicted_and_stored;
        }
        slot->occupied = true;
        slot->key = fragment.key;
        slot->deadline_us = fragment.deadline_us;
        slot->arrival_order = next_arrival_order_++;
        if (next_arrival_order_ == 0) {
          next_arrival_order_ = 1;
        }
      } else if (slot->complete || slot->deadline_us != fragment.deadline_us) {
        return {.status = slot->complete ? frame_reassembly_status::resource_exhausted : frame_reassembly_status::malformed};
      }

      if (fragment.frame_id != 0) {
        if (slot->frame_id != 0 && slot->frame_id != fragment.frame_id) {
          reset(*slot);
          return {.status = frame_reassembly_status::malformed};
        }
        slot->frame_id = fragment.frame_id;
      }

      for (std::size_t index = 0; index < slot->fragment_count; ++index) {
        const auto &existing = slot->fragments[index];
        if (existing.extended_sequence != fragment.extended_sequence) {
          continue;
        }
        const auto bytes = stored_bytes(*slot, existing);
        if (existing.starts_frame == fragment.starts_frame && existing.ends_frame == fragment.ends_frame &&
            std::ranges::equal(bytes, fragment.payload)) {
          return {.status = frame_reassembly_status::duplicate, .evicted = evicted};
        }
        reset(*slot);
        return {.status = frame_reassembly_status::malformed};
      }

      if ((slot->start_sequence && fragment.extended_sequence < *slot->start_sequence) ||
          (slot->end_sequence && fragment.extended_sequence > *slot->end_sequence) ||
          (fragment.starts_frame && slot->start_sequence) || (fragment.ends_frame && slot->end_sequence)) {
        reset(*slot);
        return {.status = frame_reassembly_status::malformed};
      }
      if (fragment.starts_frame) {
        for (std::size_t index = 0; index < slot->fragment_count; ++index) {
          if (slot->fragments[index].extended_sequence < fragment.extended_sequence) {
            reset(*slot);
            return {.status = frame_reassembly_status::malformed};
          }
        }
        slot->start_sequence = fragment.extended_sequence;
      }
      if (fragment.ends_frame) {
        for (std::size_t index = 0; index < slot->fragment_count; ++index) {
          if (slot->fragments[index].extended_sequence > fragment.extended_sequence) {
            reset(*slot);
            return {.status = frame_reassembly_status::malformed};
          }
        }
        slot->end_sequence = fragment.extended_sequence;
      }

      if (fragment.payload.size() > maximum_frame_size_ - slot->total_size ||
          slot->fragment_count >= maximum_fragments_) {
        reset(*slot);
        return {.status = frame_reassembly_status::frame_too_large};
      }
      const auto offset = slot->write_offset;
      std::copy(fragment.payload.begin(), fragment.payload.end(), slot->bytes.get() + static_cast<std::ptrdiff_t>(offset));
      slot->fragments[slot->fragment_count++] = {
        .extended_sequence = fragment.extended_sequence,
        .offset = offset,
        .size = fragment.payload.size(),
        .starts_frame = fragment.starts_frame,
        .ends_frame = fragment.ends_frame,
      };
      slot->write_offset += fragment.payload.size();
      slot->total_size += fragment.payload.size();

      if (!slot->start_sequence || !slot->end_sequence || *slot->end_sequence < *slot->start_sequence ||
          *slot->end_sequence - *slot->start_sequence + 1 != slot->fragment_count) {
        return {.status = initial_status, .evicted = evicted};
      }

      auto fragments = std::span<stored_fragment> {slot->fragments.get(), slot->fragment_count};
      std::ranges::sort(fragments, {}, &stored_fragment::extended_sequence);
      for (std::size_t index = 0; index < fragments.size(); ++index) {
        if (fragments[index].extended_sequence != *slot->start_sequence + index) {
          return {.status = initial_status, .evicted = evicted};
        }
        slot->ordered_slices[index] = stored_bytes(*slot, fragments[index]);
      }
      auto token = next_completion_token_++;
      if (token == 0) {
        token = next_completion_token_++;
      }
      if (token == 0) {
        reset(*slot);
        return {.status = frame_reassembly_status::resource_exhausted};
      }
      slot->complete = true;
      slot->completion_token = token;
      const auto slot_index = static_cast<std::uint8_t>(slot - slots_.data());
      return {
        .status = frame_reassembly_status::completed,
        .frame = {
          .key = slot->key,
          .frame_id = slot->frame_id,
          .deadline_us = slot->deadline_us,
          .slices = {slot->ordered_slices.get(), slot->fragment_count},
          .total_size = slot->total_size,
          .token = token,
          .slot = slot_index,
        },
        .evicted = evicted,
      };
    }

    /**
     * @brief Release one completed borrowed view and recycle its preallocated slot.
     *
     * @param frame Exact completed view returned by `add()`.
     * @return True only when the live slot and token matched.
     */
    bool release(const pooled_completed_frame_view &frame) noexcept {
      if (frame.slot >= slots_.size() || frame.token == 0) {
        return false;
      }
      auto &slot = slots_[frame.slot];
      if (!slot.occupied || !slot.complete || slot.completion_token != frame.token || slot.key != frame.key) {
        return false;
      }
      reset(slot);
      return true;
    }

    /** @brief Expire incomplete frames without invalidating unreleased completed views. */
    std::size_t expire(const std::uint64_t now_us) noexcept {
      std::size_t count = 0;
      for (auto &slot : slots_) {
        if (slot.occupied && !slot.complete && slot.deadline_us <= now_us) {
          reset(slot);
          ++count;
        }
      }
      return count;
    }

    /** @brief Return the number of retained incomplete frames in the closed range zero through two. */
    [[nodiscard]] std::size_t incomplete_frames() const noexcept {
      return std::ranges::count_if(slots_, [](const frame_slot &slot) {
        return slot.occupied && !slot.complete;
      });
    }

  private:
    /** @brief One preallocated fragment descriptor referencing slot-owned bytes. */
    struct stored_fragment {
      std::uint64_t extended_sequence = 0;  ///< Extended RTP sequence number.
      std::size_t offset = 0;  ///< First byte inside slot storage.
      std::size_t size = 0;  ///< Codec byte count.
      bool starts_frame = false;  ///< Whether this fragment starts the frame.
      bool ends_frame = false;  ///< Whether this fragment ends the frame.
    };

    /** @brief One lifetime-allocated frame byte region, descriptor table, and ordered view table. */
    struct frame_slot {
      std::unique_ptr<std::uint8_t[]> bytes;  ///< Fixed complete-frame byte region.
      std::unique_ptr<stored_fragment[]> fragments;  ///< Fixed unordered fragment descriptors.
      std::unique_ptr<std::span<const std::uint8_t>[]> ordered_slices;  ///< Fixed completion views.
      frame_key key {};  ///< Provisional frame key.
      std::uint64_t frame_id = 0;  ///< Bound repeated frame ID.
      std::uint64_t deadline_us = 0;  ///< Fixed frame deadline.
      std::uint64_t arrival_order = 0;  ///< Oldest-frame eviction order.
      std::uint64_t completion_token = 0;  ///< Nonzero token while complete.
      std::optional<std::uint64_t> start_sequence {};  ///< Observed start fragment.
      std::optional<std::uint64_t> end_sequence {};  ///< Observed end fragment.
      std::size_t fragment_count = 0;  ///< Populated descriptors.
      std::size_t write_offset = 0;  ///< Next unused byte in `bytes`.
      std::size_t total_size = 0;  ///< Total codec bytes.
      bool occupied = false;  ///< Whether this slot retains a frame.
      bool complete = false;  ///< Whether the caller owns a completed view.
    };

    /** @brief Return immutable stored fragment bytes. */
    [[nodiscard]] static std::span<const std::uint8_t> stored_bytes(
      const frame_slot &slot,
      const stored_fragment &fragment
    ) noexcept {
      return {slot.bytes.get() + static_cast<std::ptrdiff_t>(fragment.offset), fragment.size};
    }

    /** @brief Reset metadata while retaining every lifetime allocation. */
    static void reset(frame_slot &slot) noexcept {
      slot.key = {};
      slot.frame_id = 0;
      slot.deadline_us = 0;
      slot.arrival_order = 0;
      slot.completion_token = 0;
      slot.start_sequence.reset();
      slot.end_sequence.reset();
      slot.fragment_count = 0;
      slot.write_offset = 0;
      slot.total_size = 0;
      slot.occupied = false;
      slot.complete = false;
    }

    /** @brief Find an incomplete occupied slot by provisional frame key. */
    [[nodiscard]] frame_slot *find_slot(const frame_key key) noexcept {
      const auto iterator = std::ranges::find_if(slots_, [&](const frame_slot &slot) {
        return slot.occupied && slot.key == key;
      });
      return iterator == slots_.end() ? nullptr : &*iterator;
    }

    /** @brief Find an unused allocated slot. */
    [[nodiscard]] frame_slot *empty_slot() noexcept {
      const auto iterator = std::ranges::find_if(slots_, [](const frame_slot &slot) {
        return !slot.occupied;
      });
      return iterator == slots_.end() ? nullptr : &*iterator;
    }

    /** @brief Find the oldest incomplete slot without invalidating a completed caller view. */
    [[nodiscard]] frame_slot *oldest_incomplete_slot() noexcept {
      frame_slot *oldest = nullptr;
      for (auto &slot : slots_) {
        if (!slot.occupied || slot.complete) {
          continue;
        }
        if (oldest == nullptr || slot.arrival_order < oldest->arrival_order) {
          oldest = &slot;
        }
      }
      return oldest;
    }

    std::array<frame_slot, 2> slots_ {};  ///< Hard-bounded lifetime-allocated frame slots.
    std::size_t maximum_frame_size_ = competition_frame_size_limit;  ///< Bytes available in each slot.
    std::size_t maximum_fragments_ = maximum_fragments_per_frame;  ///< Descriptors available in each slot.
    std::uint64_t next_arrival_order_ = 1;  ///< Monotonic incomplete-frame insertion order.
    std::uint64_t next_completion_token_ = 1;  ///< Monotonic completed-view release token.
    bool ready_ = false;  ///< Whether every lifetime allocation succeeded.
  };

  /** @brief Hardware-decoder submission credit state constrained to two through four surfaces. */
  class decoder_credit_state {
  public:
    /**
     * @brief Configure the negotiated hardware-decoder capacity.
     *
     * Reconfiguration succeeds only while no submissions are in flight.
     *
     * @param maximum_in_flight Negotiated capacity in the closed range `2...4`.
     * @return `true` when the new capacity was installed.
     */
    bool configure(const std::uint8_t maximum_in_flight) noexcept {
      if (in_flight_ != 0 || maximum_in_flight < 2 || maximum_in_flight > 4) {
        return false;
      }
      maximum_in_flight_ = maximum_in_flight;
      return true;
    }

    /**
     * @brief Acquire one decoder submission credit.
     *
     * @return `true` when a hardware surface is available.
     */
    bool try_acquire() noexcept {
      if (in_flight_ >= maximum_in_flight_) {
        return false;
      }
      ++in_flight_;
      return true;
    }

    /**
     * @brief Release one credit after decoder completion.
     *
     * @return `true` when an in-flight submission existed.
     */
    bool release() noexcept {
      if (in_flight_ == 0) {
        return false;
      }
      --in_flight_;
      return true;
    }

    /**
     * @brief Return available submission credits.
     *
     * @return Negotiated capacity minus in-flight submissions.
     */
    [[nodiscard]] std::uint8_t available() const noexcept {
      return static_cast<std::uint8_t>(maximum_in_flight_ - in_flight_);
    }

    /**
     * @brief Return current in-flight decoder submissions.
     *
     * @return Value no greater than the configured capacity.
     */
    [[nodiscard]] std::uint8_t in_flight() const noexcept {
      return in_flight_;
    }

    /**
     * @brief Return negotiated decoder capacity.
     *
     * @return Value in the closed range `2...4` after successful configuration.
     */
    [[nodiscard]] std::uint8_t capacity() const noexcept {
      return maximum_in_flight_;
    }

  private:
    std::uint8_t maximum_in_flight_ = 2;  ///< Negotiated hardware surface capacity.
    std::uint8_t in_flight_ = 0;  ///< Current submitted frames awaiting completion.
  };

  /** @brief Latest-frame render mailbox with a hard depth of one. */
  class render_mailbox {
  public:
    /**
     * @brief Publish the latest completed frame, replacing any unconsumed older frame.
     *
     * @param frame Nonempty retained completed-frame handle.
     * @return `true` when an older unconsumed frame was replaced.
     */
    bool publish(retained_frame_handle frame) noexcept {
      if (!frame) {
        return false;
      }
      const auto replaced = static_cast<bool>(frame_);
      frame_ = std::move(frame);
      return replaced;
    }

    /**
     * @brief Take the current latest frame and empty the mailbox.
     *
     * @return Current retained frame, or an empty handle.
     */
    [[nodiscard]] retained_frame_handle take() noexcept {
      auto frame = std::move(frame_);
      frame_.reset();
      return frame;
    }

    /**
     * @brief Return whether one frame occupies the mailbox.
     *
     * @return `true` for occupancy one and `false` for zero.
     */
    [[nodiscard]] bool occupied() const noexcept {
      return static_cast<bool>(frame_);
    }

  private:
    retained_frame_handle frame_ {};  ///< Sole unconsumed latest frame.
  };
}  // namespace lumen::lsp::media
