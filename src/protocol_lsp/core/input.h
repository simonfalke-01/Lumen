/**
 * @file src/protocol_lsp/core/input.h
 * @brief Allocation-free LSP input accumulation, edge ordering, and baseline primitives.
 */

#pragma once

#include "packet.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <span>
#include <type_traits>
#include <utility>

namespace lumen::lsp {
  /** @brief Cumulative and latest-value pointer state retained across replaceable reports. */
  struct pointer_state {
    std::uint32_t instance_generation = 0;  ///< Nonzero physical pointer instance generation.
    std::uint64_t physical_ordinal = 0;  ///< Newest represented physical-sample ordinal.
    std::int64_t relative_x = 0;  ///< Cumulative horizontal relative motion.
    std::int64_t relative_y = 0;  ///< Cumulative vertical relative motion.
    std::int64_t vertical_scroll = 0;  ///< Cumulative vertical wheel motion.
    std::int64_t horizontal_scroll = 0;  ///< Cumulative horizontal wheel motion.
    std::uint32_t absolute_x = 0;  ///< Latest absolute horizontal coordinate in Q0.32.
    std::uint32_t absolute_y = 0;  ///< Latest absolute vertical coordinate in Q0.32.
    std::uint16_t represented_reports = 0;  ///< Physical reports combined since the prior network report.
    bool absolute = false;  ///< Whether latest coordinates are absolute rather than relative.

    /** @brief Compare every retained pointer-state field. */
    [[nodiscard]] bool operator==(const pointer_state &) const noexcept = default;
  };

  /** @brief Result of adding a physical pointer sample. */
  enum class pointer_update_result : std::uint8_t {
    accepted,  ///< Sample was accumulated.
    invalid_generation,  ///< Instance generation is zero or differs from the active generation.
    invalid_ordinal,  ///< Physical ordinal is zero or not newer than the retained ordinal.
    counter_overflow,  ///< A cumulative signed counter would wrap.
    report_count_overflow,  ///< More than 65,535 reports would be represented by one network packet.
  };

  /** @brief Client-side cumulative pointer accumulator for loss-tolerant replaceable state. */
  class pointer_accumulator {
  public:
    /**
     * @brief Start a fresh pointer instance with zero cumulative counters.
     *
     * @param instance_generation Nonzero device instance generation.
     * @return `true` when the generation is valid.
     */
    constexpr bool reset(const std::uint32_t instance_generation) noexcept {
      if (instance_generation == 0) {
        return false;
      }
      state_ = {};
      state_.instance_generation = instance_generation;
      return true;
    }

    /**
     * @brief Accumulate one relative pointer report without losing distance under packet replacement.
     *
     * @param instance_generation Active device instance generation.
     * @param physical_ordinal Nonzero strictly increasing physical-sample ordinal.
     * @param relative_x Horizontal relative delta.
     * @param relative_y Vertical relative delta.
     * @param vertical_scroll Vertical wheel delta.
     * @param horizontal_scroll Horizontal wheel delta.
     * @return Update result.
     */
    constexpr pointer_update_result add_relative(
      const std::uint32_t instance_generation,
      const std::uint64_t physical_ordinal,
      const std::int64_t relative_x,
      const std::int64_t relative_y,
      const std::int64_t vertical_scroll,
      const std::int64_t horizontal_scroll
    ) noexcept {
      if (instance_generation == 0 || instance_generation != state_.instance_generation) {
        return pointer_update_result::invalid_generation;
      }
      if (physical_ordinal == 0 || physical_ordinal <= state_.physical_ordinal) {
        return pointer_update_result::invalid_ordinal;
      }
      if (state_.represented_reports == std::numeric_limits<std::uint16_t>::max()) {
        return pointer_update_result::report_count_overflow;
      }
      std::int64_t new_x = 0;
      std::int64_t new_y = 0;
      std::int64_t new_vertical = 0;
      std::int64_t new_horizontal = 0;
      if (!checked_add(state_.relative_x, relative_x, new_x) ||
          !checked_add(state_.relative_y, relative_y, new_y) ||
          !checked_add(state_.vertical_scroll, vertical_scroll, new_vertical) ||
          !checked_add(state_.horizontal_scroll, horizontal_scroll, new_horizontal)) {
        return pointer_update_result::counter_overflow;
      }
      state_.physical_ordinal = physical_ordinal;
      state_.relative_x = new_x;
      state_.relative_y = new_y;
      state_.vertical_scroll = new_vertical;
      state_.horizontal_scroll = new_horizontal;
      state_.absolute_x = 0;
      state_.absolute_y = 0;
      ++state_.represented_reports;
      state_.absolute = false;
      return pointer_update_result::accepted;
    }

    /**
     * @brief Retain one latest-value absolute pointer report.
     *
     * @param instance_generation Active device instance generation.
     * @param physical_ordinal Nonzero strictly increasing physical-sample ordinal.
     * @param absolute_x Horizontal coordinate in Q0.32.
     * @param absolute_y Vertical coordinate in Q0.32.
     * @return Update result.
     */
    constexpr pointer_update_result set_absolute(
      const std::uint32_t instance_generation,
      const std::uint64_t physical_ordinal,
      const std::uint32_t absolute_x,
      const std::uint32_t absolute_y
    ) noexcept {
      if (instance_generation == 0 || instance_generation != state_.instance_generation) {
        return pointer_update_result::invalid_generation;
      }
      if (physical_ordinal == 0 || physical_ordinal <= state_.physical_ordinal) {
        return pointer_update_result::invalid_ordinal;
      }
      if (state_.represented_reports == std::numeric_limits<std::uint16_t>::max()) {
        return pointer_update_result::report_count_overflow;
      }
      state_.physical_ordinal = physical_ordinal;
      state_.absolute_x = absolute_x;
      state_.absolute_y = absolute_y;
      ++state_.represented_reports;
      state_.absolute = true;
      return pointer_update_result::accepted;
    }

    /**
     * @brief Return the current cumulative/latest state for a replaceable network report.
     *
     * @return Immutable pointer state.
     */
    [[nodiscard]] constexpr const pointer_state &state() const noexcept {
      return state_;
    }

    /**
     * @brief Mark the current sample group as emitted without resetting cumulative counters.
     *
     * The next state packet starts a new represented-report count while retaining all cumulative
     * distance and the last physical ordinal.
     */
    constexpr void mark_emitted() noexcept {
      state_.represented_reports = 0;
    }

  private:
    /**
     * @brief Add signed counters without undefined overflow.
     *
     * @param left Retained counter.
     * @param right New delta.
     * @param result Valid sum destination.
     * @return `true` when the mathematical sum is representable.
     */
    [[nodiscard]] static constexpr bool checked_add(
      const std::int64_t left,
      const std::int64_t right,
      std::int64_t &result
    ) noexcept {
      if ((right > 0 && left > std::numeric_limits<std::int64_t>::max() - right) ||
          (right < 0 && left < std::numeric_limits<std::int64_t>::min() - right)) {
        return false;
      }
      result = left + right;
      return true;
    }

    pointer_state state_ {};  ///< Active pointer's cumulative/latest state.
  };

  /** @brief Result of inserting one ordered physical edge. */
  enum class edge_insert_result : std::uint8_t {
    accepted,  ///< Edge was retained for ordered application.
    duplicate,  ///< Edge identifier and bytes were already retained or applied.
    conflicting_duplicate,  ///< Retained identifier was reused with different edge bytes.
    invalid_id,  ///< Edge identifier zero is forbidden.
    gap_too_large,  ///< Edge is beyond the fixed forward reorder window.
  };

  /**
   * @brief Fixed forward reorder buffer that applies every edge at most once and in identifier order.
   *
   * @tparam Edge Trivially copyable edge record with equality comparison.
   * @tparam Capacity Forward edge window; LSP version 1 uses 64.
   */
  template<class Edge, std::size_t Capacity = 64>
  class ordered_edge_window {
  public:
    static_assert(Capacity > 0 && Capacity <= 64, "edge window capacity must be 1 through 64");
    static_assert(std::is_default_constructible_v<Edge>, "edge records must be default constructible");

    /**
     * @brief Retain one edge for exactly-once ordered application.
     *
     * @param edge_id Nonzero edge identifier.
     * @param edge Edge record bytes/value.
     * @return Insertion result.
     */
    constexpr edge_insert_result insert(const std::uint64_t edge_id, const Edge &edge) noexcept {
      if (edge_id == 0) {
        return edge_insert_result::invalid_id;
      }
      if (edge_id <= applied_through_) {
        return edge_insert_result::duplicate;
      }
      if (edge_id - applied_through_ > Capacity) {
        return edge_insert_result::gap_too_large;
      }
      auto &slot = slots_[edge_id % Capacity];
      if (slot.occupied) {
        if (slot.edge_id != edge_id || !(slot.edge == edge)) {
          return edge_insert_result::conflicting_duplicate;
        }
        return edge_insert_result::duplicate;
      }
      slot.edge_id = edge_id;
      slot.edge = edge;
      slot.occupied = true;
      return edge_insert_result::accepted;
    }

    /**
     * @brief Apply all newly contiguous edges through a caller-owned non-reentrant callback.
     *
     * The callback must return `true` only after the edge is durably applied. A `false` return
     * retains that edge and every later edge for a future attempt.
     *
     * @tparam Apply Callable accepting `const Edge &` and returning a boolean.
     * @param apply Edge application callback.
     * @return Number of edges committed by this call.
     */
    template<class Apply>
    constexpr std::size_t drain(Apply &&apply) noexcept(noexcept(std::invoke(apply, std::declval<const Edge &>()))) {
      std::size_t applied = 0;
      while (applied_through_ != std::numeric_limits<std::uint64_t>::max()) {
        const auto next_id = applied_through_ + 1U;
        auto &slot = slots_[next_id % Capacity];
        if (!slot.occupied || slot.edge_id != next_id || !std::invoke(apply, std::as_const(slot.edge))) {
          break;
        }
        slot.occupied = false;
        applied_through_ = next_id;
        ++applied;
      }
      return applied;
    }

    /**
     * @brief Return the greatest contiguous successfully applied edge identifier.
     *
     * @return Applied edge watermark, initially zero.
     */
    [[nodiscard]] constexpr std::uint64_t applied_through() const noexcept {
      return applied_through_;
    }

    /**
     * @brief Return forward receipt bits relative to the applied watermark.
     *
     * Bit zero denotes `applied_through() + 1` and bit 63 denotes `+64`.
     *
     * @return Fixed forward reception bitmap.
     */
    [[nodiscard]] constexpr std::uint64_t reception_bitmap() const noexcept {
      std::uint64_t bitmap = 0;
      for (const auto &slot : slots_) {
        if (!slot.occupied || slot.edge_id <= applied_through_) {
          continue;
        }
        const auto distance = slot.edge_id - applied_through_;
        if (distance <= 64U) {
          bitmap |= std::uint64_t {1} << (distance - 1U);
        }
      }
      return bitmap;
    }

    /**
     * @brief Reset the input generation and expected first edge identifier.
     *
     * @param applied_through Greatest edge installed by the committed baseline.
     */
    constexpr void reset(const std::uint64_t applied_through = 0) noexcept {
      for (auto &slot : slots_) {
        slot.occupied = false;
      }
      applied_through_ = applied_through;
    }

  private:
    /** @brief One edge slot keyed by edge identifier modulo capacity. */
    struct edge_slot {
      std::uint64_t edge_id = 0;  ///< Retained edge identifier.
      Edge edge {};  ///< Retained edge record.
      bool occupied = false;  ///< Whether the slot contains a live edge.
    };

    std::array<edge_slot, Capacity> slots_ {};  ///< Fixed forward reorder slots.
    std::uint64_t applied_through_ = 0;  ///< Greatest contiguous successfully applied edge.
  };

  /** @brief Result of inserting replaceable latest-value state. */
  enum class latest_state_result : std::uint8_t {
    stored,  ///< State was inserted or replaced an older value.
    stale,  ///< Sequence is zero/not newer, or its dependent edge watermark regresses.
    table_full,  ///< A new supersession key cannot be represented.
  };

  /**
   * @brief One latest replaceable state and its dependent edge watermark.
   *
   * @tparam Key Supersession-key type.
   * @tparam State State-value type.
   */
  template<class Key, class State>
  struct latest_state_record {
    Key key {};  ///< Exact supersession key.
    State state {};  ///< Newest replaceable state.
    std::uint64_t state_sequence = 0;  ///< Nonzero monotonic state sequence.
    std::uint64_t edge_watermark = 0;  ///< Greatest edge observed before this state sample.
    bool occupied = false;  ///< Whether the record contains live state.
  };

  /**
   * @brief Fixed table retaining only the newest state for each supersession key.
   *
   * @tparam Key Supersession-key type with equality comparison.
   * @tparam State State-value type.
   * @tparam Capacity Maximum independent supersession keys.
   */
  template<class Key, class State, std::size_t Capacity>
  class latest_state_table {
  public:
    static_assert(Capacity > 0, "latest-state tables require nonzero capacity");

    /**
     * @brief Insert or replace state for one exact supersession key.
     *
     * @param key Supersession key.
     * @param state New state value.
     * @param state_sequence Nonzero monotonic logical-state sequence.
     * @param edge_watermark Greatest physical edge observed before sampling this state.
     * @return Storage result.
     */
    constexpr latest_state_result put(
      const Key &key,
      const State &state,
      const std::uint64_t state_sequence,
      const std::uint64_t edge_watermark
    ) noexcept {
      if (state_sequence == 0) {
        return latest_state_result::stale;
      }
      latest_state_record<Key, State> *free_slot = nullptr;
      for (auto &entry : entries_) {
        if (entry.occupied && entry.key == key) {
          if (state_sequence <= entry.state_sequence || edge_watermark < entry.edge_watermark) {
            return latest_state_result::stale;
          }
          entry.state = state;
          entry.state_sequence = state_sequence;
          entry.edge_watermark = edge_watermark;
          return latest_state_result::stored;
        }
        if (!entry.occupied && free_slot == nullptr) {
          free_slot = &entry;
        }
      }
      if (free_slot == nullptr) {
        return latest_state_result::table_full;
      }
      *free_slot = {
        .key = key,
        .state = state,
        .state_sequence = state_sequence,
        .edge_watermark = edge_watermark,
        .occupied = true,
      };
      return latest_state_result::stored;
    }

    /**
     * @brief Remove one watermark-ready state with the lowest state sequence.
     *
     * @param applied_edge_watermark Greatest contiguous applied physical edge.
     * @param output Destination record.
     * @return `true` when a ready state was removed.
     */
    constexpr bool take_ready(
      const std::uint64_t applied_edge_watermark,
      latest_state_record<Key, State> &output
    ) noexcept {
      latest_state_record<Key, State> *selected = nullptr;
      for (auto &entry : entries_) {
        if (!entry.occupied || entry.edge_watermark > applied_edge_watermark) {
          continue;
        }
        if (selected == nullptr || entry.state_sequence < selected->state_sequence) {
          selected = &entry;
        }
      }
      if (selected == nullptr) {
        return false;
      }
      output = *selected;
      selected->occupied = false;
      return true;
    }

    /** @brief Discard every retained replaceable state. */
    constexpr void clear() noexcept {
      for (auto &entry : entries_) {
        entry.occupied = false;
      }
    }

  private:
    std::array<latest_state_record<Key, State>, Capacity> entries_ {};  ///< Fixed latest-state records.
  };

  /** @brief Result of adding one multipart input-baseline part. */
  enum class baseline_part_result : std::uint8_t {
    accepted,  ///< New part was retained.
    duplicate,  ///< Byte-identical part was already retained.
    invalid_metadata,  ///< Identifier, count, length, index, offset, or digest size is invalid.
    conflicting_baseline,  ///< Part metadata does not describe the active baseline object.
    conflicting_part,  ///< Part index was reused with different offset, length, or bytes.
    overlapping_part,  ///< Part byte range overlaps another retained part.
  };

  /**
   * @brief Bounded multipart baseline assembler with explicit atomic commit.
   *
   * SHA-256 calculation remains in the shared crypto boundary. This primitive retains the
   * advertised digest and exposes assembled bytes only when all non-overlapping parts cover the
   * exact total. The caller validates SHA-256 and then calls `commit(true)` atomically.
   *
   * @tparam MaxBytes Maximum complete baseline bytes; LSP version 1 allows 32 KiB.
   * @tparam MaxParts Maximum baseline parts; LSP version 1 allows 32.
   */
  template<std::size_t MaxBytes = 32U * 1024U, std::size_t MaxParts = 32>
  class baseline_assembler {
  public:
    static_assert(MaxBytes > 0, "baseline storage requires nonzero capacity");
    static_assert(MaxParts > 0 && MaxParts <= 32, "LSP baseline part count must be 1 through 32");

    /**
     * @brief Retain one authenticated baseline part.
     *
     * @param baseline_id Random nonzero baseline identifier.
     * @param part_index Zero-based part index.
     * @param part_count Complete part count.
     * @param total_length Exact complete baseline length.
     * @param part_offset Byte offset of this part in the deterministic baseline.
     * @param digest Advertised 32-byte SHA-256 digest.
     * @param bytes Part bytes.
     * @return Part admission result.
     */
    constexpr baseline_part_result add_part(
      const std::uint64_t baseline_id,
      const std::uint8_t part_index,
      const std::uint8_t part_count,
      const std::uint32_t total_length,
      const std::uint32_t part_offset,
      const std::span<const std::uint8_t> digest,
      const std::span<const std::uint8_t> bytes
    ) noexcept {
      if (baseline_id == 0 || part_count == 0 || part_count > MaxParts || part_index >= part_count ||
          total_length == 0 || total_length > MaxBytes || digest.size() != digest_.size() ||
          bytes.empty() || part_offset > total_length || bytes.size() > total_length - part_offset) {
        return baseline_part_result::invalid_metadata;
      }
      if (baseline_id_ == 0) {
        baseline_id_ = baseline_id;
        part_count_ = part_count;
        total_length_ = total_length;
        for (std::size_t index = 0; index < digest_.size(); ++index) {
          digest_[index] = digest[index];
        }
      } else if (baseline_id != baseline_id_ || part_count != part_count_ || total_length != total_length_ || !equal_digest(digest)) {
        return baseline_part_result::conflicting_baseline;
      }

      auto &part = parts_[part_index];
      if (part.received) {
        if (part.offset != part_offset || part.length != bytes.size() || !equal_bytes(part_offset, bytes)) {
          return baseline_part_result::conflicting_part;
        }
        return baseline_part_result::duplicate;
      }
      const auto end = std::size_t {part_offset} + bytes.size();
      for (const auto &other : parts_) {
        if (!other.received) {
          continue;
        }
        const auto other_end = std::size_t {other.offset} + other.length;
        if (part_offset < other_end && other.offset < end) {
          return baseline_part_result::overlapping_part;
        }
      }
      for (std::size_t index = 0; index < bytes.size(); ++index) {
        storage_[part_offset + index] = bytes[index];
      }
      part.offset = part_offset;
      part.length = static_cast<std::uint32_t>(bytes.size());
      part.received = true;
      ++received_parts_;
      received_bytes_ += bytes.size();
      return baseline_part_result::accepted;
    }

    /**
     * @brief Return whether every part provides exact non-overlapping coverage.
     *
     * @return `true` when the assembled bytes are ready for SHA-256 verification.
     */
    [[nodiscard]] constexpr bool ready_for_digest() const noexcept {
      return baseline_id_ != 0 && received_parts_ == part_count_ && received_bytes_ == total_length_;
    }

    /**
     * @brief Return complete assembled bytes only after exact coverage is proven.
     *
     * @return Complete baseline bytes, or an empty span while incomplete.
     */
    [[nodiscard]] constexpr std::span<const std::uint8_t> assembled_bytes() const noexcept {
      return ready_for_digest() ? std::span<const std::uint8_t> {storage_.data(), total_length_} : std::span<const std::uint8_t> {};
    }

    /**
     * @brief Return the advertised SHA-256 digest.
     *
     * @return Digest bytes, or an empty span before the first valid part.
     */
    [[nodiscard]] constexpr std::span<const std::uint8_t> advertised_digest() const noexcept {
      return baseline_id_ == 0 ? std::span<const std::uint8_t> {} : std::span<const std::uint8_t> {digest_};
    }

    /**
     * @brief Atomically mark a complete baseline committed after external SHA-256 verification.
     *
     * @param digest_matches Result of constant-time comparison with the advertised digest.
     * @return `true` when a complete matching baseline is now or was already committed.
     */
    constexpr bool commit(const bool digest_matches) noexcept {
      committed_ = committed_ || (ready_for_digest() && digest_matches);
      return committed_;
    }

    /**
     * @brief Return whether the active baseline is atomically committed.
     *
     * @return Commit state.
     */
    [[nodiscard]] constexpr bool committed() const noexcept {
      return committed_;
    }

    /**
     * @brief Return the active baseline identifier.
     *
     * @return Nonzero baseline identifier, or zero before assembly begins.
     */
    [[nodiscard]] constexpr std::uint64_t baseline_id() const noexcept {
      return baseline_id_;
    }

    /** @brief Discard the active incomplete or committed baseline. */
    constexpr void reset() noexcept {
      baseline_id_ = 0;
      part_count_ = 0;
      total_length_ = 0;
      received_parts_ = 0;
      received_bytes_ = 0;
      committed_ = false;
      for (auto &part : parts_) {
        part = {};
      }
    }

  private:
    /** @brief Retained byte range for one part index. */
    struct part_record {
      std::uint32_t offset = 0;  ///< Byte offset in complete baseline.
      std::uint32_t length = 0;  ///< Retained part byte length.
      bool received = false;  ///< Whether this part index is present.
    };

    /**
     * @brief Compare a candidate digest with the active advertised digest.
     *
     * @param digest Candidate 32-byte digest.
     * @return `true` when every byte matches.
     */
    [[nodiscard]] constexpr bool equal_digest(const std::span<const std::uint8_t> digest) const noexcept {
      std::uint8_t difference = 0;
      for (std::size_t index = 0; index < digest_.size(); ++index) {
        difference |= static_cast<std::uint8_t>(digest_[index] ^ digest[index]);
      }
      return difference == 0;
    }

    /**
     * @brief Compare candidate bytes with an already retained part range.
     *
     * @param offset Retained byte offset.
     * @param bytes Candidate bytes.
     * @return `true` when every byte matches.
     */
    [[nodiscard]] constexpr bool equal_bytes(
      const std::size_t offset,
      const std::span<const std::uint8_t> bytes
    ) const noexcept {
      for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (storage_[offset + index] != bytes[index]) {
          return false;
        }
      }
      return true;
    }

    std::array<std::uint8_t, MaxBytes> storage_ {};  ///< Complete baseline storage.
    std::array<part_record, MaxParts> parts_ {};  ///< Per-index part ranges.
    std::array<std::uint8_t, 32> digest_ {};  ///< Advertised SHA-256 digest.
    std::uint64_t baseline_id_ = 0;  ///< Active baseline identifier.
    std::uint32_t total_length_ = 0;  ///< Exact complete baseline length.
    std::size_t received_bytes_ = 0;  ///< Sum of non-overlapping received part lengths.
    std::uint8_t part_count_ = 0;  ///< Declared complete part count.
    std::uint8_t received_parts_ = 0;  ///< Number of retained part indices.
    bool committed_ = false;  ///< Whether external digest verification committed the baseline.
  };

  /** @brief Monotonic input state-sequence generator enforcing baseline sequence one. */
  class input_state_sequence {
  public:
    /**
     * @brief Begin a fresh input generation at the reserved baseline sequence.
     *
     * @return Baseline state sequence, always one.
     */
    constexpr std::uint64_t begin_generation() noexcept {
      current_ = 1;
      baseline_committed_ = false;
      return current_;
    }

    /**
     * @brief Allow replaceable state after the sequence-one baseline commits.
     *
     * @return `true` when a generation had been started.
     */
    constexpr bool commit_baseline() noexcept {
      baseline_committed_ = baseline_committed_ || current_ == 1;
      return baseline_committed_;
    }

    /**
     * @brief Allocate the next replaceable state sequence without wrap or reuse.
     *
     * @return Next sequence beginning at two, or zero when unavailable.
     */
    constexpr std::uint64_t next_state() noexcept {
      if (!baseline_committed_ || current_ == std::numeric_limits<std::uint64_t>::max()) {
        return 0;
      }
      return ++current_;
    }

    /**
     * @brief Return the latest allocated sequence.
     *
     * @return Zero before generation start, one during baseline, or latest replaceable sequence.
     */
    [[nodiscard]] constexpr std::uint64_t current() const noexcept {
      return current_;
    }

  private:
    std::uint64_t current_ = 0;  ///< Latest allocated sequence.
    bool baseline_committed_ = false;  ///< Whether replaceable sequence allocation is enabled.
  };
}  // namespace lumen::lsp
