/**
 * @file src/lsp/input_plane/state.h
 * @brief Bounded allocation-free LSP/1 input authority and delivery state machines.
 */

#pragma once

#include "wire.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <span>
#include <utility>

namespace lumen::lsp::input_plane {
  /** @brief Exact key under which a replaceable LSP/1 input sample may supersede an older sample. */
  struct supersession_key {
    std::uint32_t input_generation = 0;  ///< Input authority generation.
    packet_kind kind = packet_kind::core_state;  ///< Replaceable packet kind.
    device_type device = device_type::keyboard;  ///< Device class.
    std::uint32_t device_id = 0;  ///< Device identifier, zero only for core state.
    std::uint32_t instance_generation = 0;  ///< Nonzero device or keyboard reconciliation generation.
    sensor_type sensor = sensor_type::gyroscope;  ///< Sensor stream when `kind` is sensor state.

    /** @brief Compare every supersession-key component. */
    [[nodiscard]] bool operator==(const supersession_key &) const noexcept = default;
  };

  /** @brief Result of deriving an exact replaceable-state supersession key. */
  enum class supersession_key_result : std::uint8_t {
    success,  ///< A valid key was derived.
    not_replaceable,  ///< Edge and baseline packets cannot supersede state.
    malformed,  ///< Kind payload or object identifier is inconsistent.
  };

  /**
   * @brief Derive the exact supersession key for a validated replaceable packet.
   *
   * @param packet Parsed LSP/1 input packet.
   * @param output Key destination.
   * @return Key derivation result.
   */
  [[nodiscard]] constexpr supersession_key_result make_supersession_key(
    const parsed_packet &packet,
    supersession_key &output
  ) noexcept {
    if (!packet || packet.header.kind == packet_kind::edge_batch || packet.header.kind == packet_kind::baseline_part) {
      return packet ? supersession_key_result::not_replaceable : supersession_key_result::malformed;
    }
    output = {
      .input_generation = packet.header.input_generation,
      .kind = packet.header.kind,
    };
    switch (packet.header.kind) {
      case packet_kind::pointer_motion:
        {
          const auto pointer = parse_pointer_payload(packet.payload);
          if (!pointer) {
            return supersession_key_result::malformed;
          }
          output.device = device_type::pointer;
          output.device_id = static_cast<std::uint32_t>(packet.header.object_id);
          output.instance_generation = pointer.value.instance_generation;
          return supersession_key_result::success;
        }
      case packet_kind::core_state:
        {
          const auto core = parse_core_state_payload(packet.payload);
          if (!core) {
            return supersession_key_result::malformed;
          }
          output.device = device_type::keyboard;
          output.instance_generation = core.value.keyboard_instance_generation;
          return supersession_key_result::success;
        }
      case packet_kind::device_state:
        {
          const auto prefix = parse_device_prefix(packet.payload);
          if (!prefix) {
            return supersession_key_result::malformed;
          }
          output.device = prefix.value.device;
          output.device_id = prefix.value.device_id;
          output.instance_generation = prefix.value.instance_generation;
          return supersession_key_result::success;
        }
      case packet_kind::sensor_state:
        {
          const auto prefix = parse_device_prefix(packet.payload, true);
          if (!prefix) {
            return supersession_key_result::malformed;
          }
          output.device = device_type::controller;
          output.device_id = prefix.value.device_id;
          output.instance_generation = prefix.value.instance_generation;
          output.sensor = static_cast<sensor_type>(packet.payload[1]);
          return supersession_key_result::success;
        }
      case packet_kind::edge_batch:
      case packet_kind::baseline_part:
        return supersession_key_result::not_replaceable;
    }
    return supersession_key_result::malformed;
  }

  /** @brief Admission result for a bounded latest-state table. */
  enum class latest_state_result : std::uint8_t {
    stored,  ///< New state was stored or replaced the same exact key.
    stale,  ///< Sequence or edge watermark does not advance.
    malformed,  ///< Packet cannot form a replaceable supersession key.
    payload_too_large,  ///< Packet payload exceeds the fixed slot size.
    full,  ///< No free supersession-key slot remains.
    baseline_conflict,  ///< Atomic baseline metadata conflicts with an existing installed key.
    inactive_lifecycle,  ///< Non-core state has no exact active same-generation device lifecycle.
  };

  /** @brief Result of atomically installing one parsed complete baseline. */
  enum class baseline_install_result : std::uint8_t {
    installed,  ///< Every record was seeded atomically.
    invalid,  ///< Baseline or record mapping is malformed.
    capacity_exhausted,  ///< Complete record set exceeds fixed latest-state/history capacity.
    conflict,  ///< Duplicate exact key or incompatible active/removal generation exists.
  };

  /** @brief Per-supersession-key sequence and physical-ordinal admission result. */
  enum class latest_sequence_result : std::uint8_t {
    advanced,  ///< New sequence, ordinal, and watermark became latest.
    stale,  ///< Sequence, strict non-core ordinal, or edge watermark did not advance safely.
    invalid,  ///< Sequence or physical ordinal is zero.
    full,  ///< No fixed key-history slot is available.
  };

  /** @brief Borrowed per-key latest-sequence snapshot. */
  struct latest_sequence_snapshot {
    supersession_key key {};  ///< Exact independently replaceable key.
    std::uint64_t state_sequence = 0;  ///< Greatest admitted state sequence.
    std::uint64_t physical_ordinal = 0;  ///< Greatest admitted physical ordinal.
    std::uint64_t edge_watermark = 0;  ///< Greatest dependent-edge watermark.
    bool found = false;  ///< Whether the key exists.
  };

  /**
   * @brief Fixed history table preventing applied state from becoming admissible again after drain.
   *
   * @tparam Capacity Maximum exact supersession keys retained for one authority generation.
   */
  template<std::size_t Capacity = 64>
  class latest_sequence_table {
  public:
    static_assert(Capacity > 0, "latest-sequence capacity must be nonzero");

    /**
     * @brief Admit one per-key sequence and physical ordinal.
     *
     * Only core reconciliation may retain an equal physical ordinal. Every other exact key requires a
     * strictly newer physical sample, and no key may lower its dependent-edge watermark.
     *
     * @param key Exact supersession key.
     * @param state_sequence Nonzero logical sequence.
     * @param physical_ordinal Nonzero newest represented physical sample.
     * @param edge_watermark Greatest edge observed before sampling state.
     * @return Admission result.
     */
    constexpr latest_sequence_result observe(
      const supersession_key &key,
      const std::uint64_t state_sequence,
      const std::uint64_t physical_ordinal,
      const std::uint64_t edge_watermark
    ) noexcept {
      if (state_sequence == 0 || physical_ordinal == 0) {
        return latest_sequence_result::invalid;
      }
      entry_type *free_entry = nullptr;
      for (auto &entry : entries_) {
        if (entry.occupied && entry.key == key) {
          const auto permits_equal_ordinal = key.kind == packet_kind::core_state;
          if (state_sequence <= entry.state_sequence || edge_watermark < entry.edge_watermark ||
              physical_ordinal < entry.physical_ordinal ||
              (!permits_equal_ordinal && physical_ordinal == entry.physical_ordinal)) {
            return latest_sequence_result::stale;
          }
          entry.state_sequence = state_sequence;
          entry.physical_ordinal = physical_ordinal;
          entry.edge_watermark = edge_watermark;
          return latest_sequence_result::advanced;
        }
        if (!entry.occupied && free_entry == nullptr) {
          free_entry = &entry;
        }
      }
      if (free_entry == nullptr) {
        return latest_sequence_result::full;
      }
      *free_entry = {
        .key = key,
        .state_sequence = state_sequence,
        .physical_ordinal = physical_ordinal,
        .edge_watermark = edge_watermark,
        .occupied = true,
      };
      return latest_sequence_result::advanced;
    }

    /**
     * @brief Return the retained sequence state for one exact key.
     *
     * @param key Exact supersession key.
     * @return Found snapshot or an empty result.
     */
    [[nodiscard]] constexpr latest_sequence_snapshot lookup(const supersession_key &key) const noexcept {
      for (const auto &entry : entries_) {
        if (entry.occupied && entry.key == key) {
          return {
            .key = entry.key,
            .state_sequence = entry.state_sequence,
            .physical_ordinal = entry.physical_ordinal,
            .edge_watermark = entry.edge_watermark,
            .found = true,
          };
        }
      }
      return {};
    }

    /** @brief Clear every retained key on input-authority replacement. */
    constexpr void clear() noexcept {
      for (auto &entry : entries_) {
        entry = {};
      }
    }

    /**
     * @brief Retire history for one exact key after a generation-bound removal is installed.
     *
     * @param key Exact retired key.
     * @return `true` when a retained entry was reclaimed.
     */
    constexpr bool retire(const supersession_key &key) noexcept {
      for (auto &entry : entries_) {
        if (entry.occupied && entry.key == key) {
          entry = {};
          return true;
        }
      }
      return false;
    }

    /**
     * @brief Reclaim all exact stream keys for one removed device generation.
     *
     * @param device Device class.
     * @param device_id Stable device identifier.
     * @param instance_generation Removed instance generation.
     * @return Number of reclaimed state/sensor keys.
     */
    constexpr std::size_t retire_device(
      const device_type device,
      const std::uint32_t device_id,
      const std::uint32_t instance_generation
    ) noexcept {
      std::size_t retired = 0;
      for (auto &entry : entries_) {
        if (entry.occupied && entry.key.device == device && entry.key.device_id == device_id &&
            entry.key.instance_generation == instance_generation) {
          entry = {};
          ++retired;
        }
      }
      return retired;
    }

  private:
    /** @brief One exact-key history slot. */
    struct entry_type {
      supersession_key key {};  ///< Exact independently replaceable key.
      std::uint64_t state_sequence = 0;  ///< Greatest logical sequence.
      std::uint64_t physical_ordinal = 0;  ///< Greatest physical ordinal.
      std::uint64_t edge_watermark = 0;  ///< Greatest dependent-edge watermark.
      bool occupied = false;  ///< Whether this history slot is live.
    };

    std::array<entry_type, Capacity> entries_ {};  ///< Fixed exact-key history.
  };

  /** @brief Device lifecycle generation admission result. */
  enum class lifecycle_generation_result : std::uint8_t {
    advanced,  ///< New arrival/removal generation or state was retained.
    duplicate,  ///< Exact generation and presence were already retained.
    stale,  ///< Generation moved backward or reused with conflicting presence.
    invalid,  ///< Device class, identifier, or generation is invalid.
    full,  ///< No device-identity tombstone slot remains.
  };

  /**
   * @brief Fixed per-device lifecycle/tombstone table that does not grow per hot-plug generation.
   *
   * Each `(device type, device ID)` owns one slot. A newer arrival replaces its removal tombstone in
   * place, while a removal preserves the greatest generation so late state cannot resurrect it.
   *
   * @tparam Capacity Maximum stable device identities retained in one input authority.
   */
  template<std::size_t Capacity = 32>
  class device_lifecycle_table {
  public:
    static_assert(Capacity > 0, "device-lifecycle capacity must be nonzero");

    /**
     * @brief Observe one generation-bound arrival or removal.
     *
     * @param device Device class.
     * @param device_id Nonzero stable device identifier.
     * @param instance_generation Nonzero monotonically increasing hot-plug generation.
     * @param presence Active or removed lifecycle state.
     * @return Lifecycle admission result.
     */
    constexpr lifecycle_generation_result observe(
      const device_type device,
      const std::uint32_t device_id,
      const std::uint32_t instance_generation,
      const device_presence presence
    ) noexcept {
      if (!valid_device_type(device) || device_id == 0 || instance_generation == 0 ||
          (presence != device_presence::active && presence != device_presence::removed)) {
        return lifecycle_generation_result::invalid;
      }
      entry_type *free_entry = nullptr;
      for (auto &entry : entries_) {
        if (entry.occupied && entry.device == device && entry.device_id == device_id) {
          if (instance_generation < entry.instance_generation ||
              (instance_generation == entry.instance_generation && entry.presence == device_presence::removed &&
               presence == device_presence::active)) {
            return lifecycle_generation_result::stale;
          }
          if (instance_generation == entry.instance_generation && presence == entry.presence) {
            return lifecycle_generation_result::duplicate;
          }
          entry.instance_generation = instance_generation;
          entry.presence = presence;
          return lifecycle_generation_result::advanced;
        }
        if (!entry.occupied && free_entry == nullptr) {
          free_entry = &entry;
        }
      }
      if (free_entry == nullptr) {
        return lifecycle_generation_result::full;
      }
      *free_entry = {
        .device = device,
        .presence = presence,
        .device_id = device_id,
        .instance_generation = instance_generation,
        .occupied = true,
      };
      return lifecycle_generation_result::advanced;
    }

    /** @brief Return whether one exact generation is currently active. */
    [[nodiscard]] constexpr bool active(
      const device_type device,
      const std::uint32_t device_id,
      const std::uint32_t instance_generation
    ) const noexcept {
      for (const auto &entry : entries_) {
        if (entry.occupied && entry.device == device && entry.device_id == device_id) {
          return entry.instance_generation == instance_generation && entry.presence == device_presence::active;
        }
      }
      return false;
    }

    /** @brief Clear all lifecycle identities on input-authority replacement. */
    constexpr void clear() noexcept {
      for (auto &entry : entries_) {
        entry = {};
      }
    }

  private:
    /** @brief One stable device identity and greatest hot-plug generation. */
    struct entry_type {
      device_type device = device_type::keyboard;  ///< Stable device class.
      device_presence presence = device_presence::removed;  ///< Current active/tombstone state.
      std::uint32_t device_id = 0;  ///< Stable device identifier.
      std::uint32_t instance_generation = 0;  ///< Greatest observed generation.
      bool occupied = false;  ///< Whether the identity slot is retained.
    };

    std::array<entry_type, Capacity> entries_ {};  ///< Fixed stable-identity tombstone table.
  };

  /**
   * @brief Derive the newest physical ordinal from one validated replaceable packet.
   *
   * @param packet Parsed replaceable packet.
   * @param physical_ordinal Destination.
   * @return `true` when the exact frozen kind body yielded a nonzero ordinal.
   */
  [[nodiscard]] constexpr bool state_physical_ordinal(
    const parsed_packet &packet,
    std::uint64_t &physical_ordinal
  ) noexcept {
    switch (packet.header.kind) {
      case packet_kind::pointer_motion:
        {
          const auto value = parse_pointer_payload(packet.payload);
          physical_ordinal = value ? value.value.physical_ordinal : 0;
          return static_cast<bool>(value);
        }
      case packet_kind::core_state:
        {
          const auto value = parse_core_state_payload(packet.payload);
          physical_ordinal = value ? value.value.physical_ordinal : 0;
          return static_cast<bool>(value);
        }
      case packet_kind::device_state:
        {
          const auto value = parse_device_prefix(packet.payload);
          physical_ordinal = value ? value.value.physical_ordinal : 0;
          return static_cast<bool>(value);
        }
      case packet_kind::sensor_state:
        {
          const auto value = parse_device_prefix(packet.payload, true);
          physical_ordinal = value ? value.value.physical_ordinal : 0;
          return static_cast<bool>(value);
        }
      case packet_kind::edge_batch:
      case packet_kind::baseline_part:
        return false;
    }
    return false;
  }

  /**
   * @brief Fixed table retaining only the newest payload for each exact supersession key.
   *
   * @tparam Capacity Maximum independently replaceable objects.
   * @tparam MaxPayload Maximum bytes retained for one state object.
   */
  template<std::size_t Capacity = 64, std::size_t MaxPayload = 1200>
  class latest_state_table {
  public:
    static_assert(Capacity > 0, "latest-state capacity must be nonzero");
    static_assert(MaxPayload > 0 && MaxPayload <= std::numeric_limits<std::uint16_t>::max(), "invalid payload slot size");

    /**
     * @brief Insert a validated replaceable packet without allocating.
     *
     * @param packet Parsed packet whose payload remains caller-owned.
     * @return Admission result.
     */
    constexpr latest_state_result put(const parsed_packet &packet) noexcept {
      supersession_key key;
      if (make_supersession_key(packet, key) != supersession_key_result::success) {
        return latest_state_result::malformed;
      }
      if (packet.payload.size() > MaxPayload) {
        return latest_state_result::payload_too_large;
      }
      std::uint64_t physical_ordinal = 0;
      if (!state_physical_ordinal(packet, physical_ordinal)) {
        return latest_state_result::malformed;
      }
      if (key.kind != packet_kind::core_state &&
          !lifecycles_.active(key.device, key.device_id, key.instance_generation)) {
        return latest_state_result::inactive_lifecycle;
      }
      slot *free_slot = nullptr;
      slot *matching_slot = nullptr;
      for (auto &candidate : slots_) {
        if (candidate.occupied && candidate.key == key) {
          matching_slot = &candidate;
          break;
        }
        if (!candidate.occupied && free_slot == nullptr) {
          free_slot = &candidate;
        }
      }
      if (matching_slot != nullptr && packet.header.edge_watermark < matching_slot->header.edge_watermark) {
        return latest_state_result::stale;
      }
      if (matching_slot == nullptr && free_slot == nullptr) {
        return latest_state_result::full;
      }
      const auto sequence_result = sequences_.observe(
        key,
        packet.header.state_sequence,
        physical_ordinal,
        packet.header.edge_watermark
      );
      if (sequence_result == latest_sequence_result::stale) {
        return latest_state_result::stale;
      }
      if (sequence_result == latest_sequence_result::full) {
        return latest_state_result::full;
      }
      if (sequence_result != latest_sequence_result::advanced) {
        return latest_state_result::malformed;
      }
      store(matching_slot != nullptr ? *matching_slot : *free_slot, packet, key);
      return latest_state_result::stored;
    }

    /**
     * @brief Apply and remove all watermark-ready state in ascending state-sequence order.
     *
     * The callback must return `true` only after the state is durably submitted. A
     * failed callback retains that state and stops the drain.
     *
     * @tparam Apply Callable accepting the common header, supersession key, and payload span.
     * @param applied_edge_watermark Greatest contiguously applied physical edge ID.
     * @param apply Non-reentrant state application callback.
     * @return Number of states successfully applied.
     */
    template<class Apply>
    constexpr std::size_t drain_ready(
      const std::uint64_t applied_edge_watermark,
      Apply &&apply
    ) noexcept(noexcept(std::invoke(apply, std::declval<const common_header &>(), std::declval<const supersession_key &>(), std::declval<std::span<const std::uint8_t>>()))) {
      std::size_t applied = 0;
      while (true) {
        slot *selected = nullptr;
        for (auto &candidate : slots_) {
          if (!candidate.occupied || candidate.header.edge_watermark > applied_edge_watermark) {
            continue;
          }
          if (selected == nullptr || candidate.header.state_sequence < selected->header.state_sequence) {
            selected = &candidate;
          }
        }
        if (selected == nullptr ||
            !std::invoke(
              apply,
              std::as_const(selected->header),
              std::as_const(selected->key),
              std::span<const std::uint8_t>(selected->payload).first(selected->payload_size)
            )) {
          return applied;
        }
        selected->occupied = false;
        ++applied;
      }
    }

    /** @brief Discard all pending replaceable state on authority loss. */
    constexpr void clear() noexcept {
      for (auto &entry : slots_) {
        entry.occupied = false;
      }
      sequences_.clear();
      lifecycles_.clear();
    }

    /**
     * @brief Return retained latest sequence/ordinal history for one exact key.
     *
     * @param key Supersession key.
     * @return Found snapshot or an empty result.
     */
    [[nodiscard]] constexpr latest_sequence_snapshot latest_sequence(const supersession_key &key) const noexcept {
      return sequences_.lookup(key);
    }

    /**
     * @brief Reclaim pending and historical state for one exact retired key.
     *
     * @param key Key whose generation has a committed removal tombstone.
     * @return `true` when pending or history state was reclaimed.
     */
    constexpr bool retire(const supersession_key &key) noexcept {
      auto reclaimed = sequences_.retire(key);
      for (auto &entry : slots_) {
        if (entry.occupied && entry.key == key) {
          entry = {};
          reclaimed = true;
        }
      }
      return reclaimed;
    }

    /**
     * @brief Install a generation-bound device arrival or removal and reclaim removed stream keys.
     *
     * @param device Device class.
     * @param device_id Stable device identifier.
     * @param instance_generation Monotonic hot-plug generation.
     * @param presence Active arrival or removed tombstone.
     * @return Lifecycle admission result.
     */
    constexpr lifecycle_generation_result observe_lifecycle(
      const device_type device,
      const std::uint32_t device_id,
      const std::uint32_t instance_generation,
      const device_presence presence
    ) noexcept {
      const auto result = lifecycles_.observe(device, device_id, instance_generation, presence);
      if ((result == lifecycle_generation_result::advanced || result == lifecycle_generation_result::duplicate) &&
          presence == device_presence::removed) {
        sequences_.retire_device(device, device_id, instance_generation);
        for (auto &entry : slots_) {
          if (entry.occupied && entry.key.device == device && entry.key.device_id == device_id &&
              entry.key.instance_generation == instance_generation) {
            entry = {};
          }
        }
      }
      return result;
    }

    /**
     * @brief Atomically seed exact per-key sequence history from a committed baseline.
     *
     * Pending replaceable packets are cleared only after the complete baseline fits and has unique keys.
     *
     * @param baseline Parsed complete baseline.
     * @param input_generation Nonzero authority generation owning it.
     * @return Atomic installation result.
     */
    constexpr baseline_install_result install_baseline(
      const parsed_input_baseline &baseline,
      const std::uint32_t input_generation
    ) noexcept {
      if (!baseline || input_generation == 0) {
        return baseline_install_result::invalid;
      }
      latest_sequence_table<Capacity> candidate_sequences;
      device_lifecycle_table<Capacity> candidate_lifecycles;
      for (std::size_t index = 0; index < baseline.record_count; ++index) {
        const auto record = baseline.record(index);
        if (record.payload.empty()) {
          return baseline_install_result::invalid;
        }
        if (record.header.kind == baseline_record_kind::device_lifecycle) {
          device_lifecycle_payload lifecycle;
          if (parse_device_lifecycle_payload(record.payload, lifecycle) != wire_error::none) {
            return baseline_install_result::invalid;
          }
          const auto lifecycle_result = candidate_lifecycles.observe(
            lifecycle.device,
            record.header.device_id,
            record.header.instance_generation,
            lifecycle.presence
          );
          if (lifecycle_result == lifecycle_generation_result::full) {
            return baseline_install_result::capacity_exhausted;
          }
          if (lifecycle_result != lifecycle_generation_result::advanced) {
            return baseline_install_result::conflict;
          }
          continue;
        }
        supersession_key key {
          .input_generation = input_generation,
          .instance_generation = record.header.instance_generation,
        };
        switch (record.header.kind) {
          case baseline_record_kind::core:
            key.kind = packet_kind::core_state;
            key.device = device_type::keyboard;
            break;
          case baseline_record_kind::pointer:
            key.kind = packet_kind::pointer_motion;
            key.device = device_type::pointer;
            key.device_id = record.header.device_id;
            break;
          case baseline_record_kind::controller:
            key.kind = packet_kind::device_state;
            key.device = device_type::controller;
            key.device_id = record.header.device_id;
            break;
          case baseline_record_kind::controller_sensor:
            key.kind = packet_kind::sensor_state;
            key.device = device_type::controller;
            key.device_id = record.header.device_id;
            key.sensor = static_cast<sensor_type>(record.header.subtype);
            break;
          case baseline_record_kind::touch:
            key.kind = packet_kind::device_state;
            key.device = device_type::touch;
            key.device_id = record.header.device_id;
            break;
          case baseline_record_kind::pen:
            key.kind = packet_kind::device_state;
            key.device = device_type::pen;
            key.device_id = record.header.device_id;
            break;
          case baseline_record_kind::device_lifecycle:
            return baseline_install_result::invalid;
        }
        const auto sequence_result = candidate_sequences.observe(
          key,
          record.header.state_sequence,
          record.header.physical_ordinal,
          baseline.edge_watermark
        );
        if (sequence_result == latest_sequence_result::full) {
          return baseline_install_result::capacity_exhausted;
        }
        if (sequence_result != latest_sequence_result::advanced) {
          return baseline_install_result::conflict;
        }
      }
      for (auto &entry : slots_) {
        entry = {};
      }
      sequences_ = candidate_sequences;
      lifecycles_ = candidate_lifecycles;
      return baseline_install_result::installed;
    }

  private:
    /** @brief One fixed latest-state slot. */
    struct slot {
      supersession_key key {};  ///< Exact supersession key.
      common_header header {};  ///< Newest state header.
      std::array<std::uint8_t, MaxPayload> payload {};  ///< Retained kind bytes.
      std::uint16_t payload_size = 0;  ///< Live bytes in `payload`.
      bool occupied = false;  ///< Whether this slot contains pending state.
    };

    /**
     * @brief Replace one slot with a packet already proven to fit.
     *
     * @param destination Target slot.
     * @param packet Parsed packet.
     * @param key Exact derived key.
     */
    static constexpr void store(slot &destination, const parsed_packet &packet, const supersession_key &key) noexcept {
      destination.key = key;
      destination.header = packet.header;
      destination.payload_size = static_cast<std::uint16_t>(packet.payload.size());
      std::copy(packet.payload.begin(), packet.payload.end(), destination.payload.begin());
      destination.occupied = true;
    }

    std::array<slot, Capacity> slots_ {};  ///< Fixed supersession-key table.
    latest_sequence_table<Capacity> sequences_ {};  ///< Applied-and-pending per-key sequence history.
    device_lifecycle_table<Capacity> lifecycles_ {};  ///< Stable device-generation arrival/removal tombstones.
  };

  /** @brief Input baseline part admission result. */
  enum class baseline_result : std::uint8_t {
    accepted,  ///< New authenticated part was retained.
    duplicate,  ///< Byte-identical part or an already committed baseline was repeated.
    invalid,  ///< Metadata or byte range violates the baseline contract.
    conflict,  ///< Metadata, digest, or bytes conflict with the active baseline.
    overlap,  ///< New part overlaps an existing part.
    incomplete,  ///< Commit was requested before exact coverage existed.
    digest_mismatch,  ///< Caller-supplied digest verifier rejected assembled bytes.
    invalid_body,  ///< Digest-authenticated bytes are not one exact deterministic complete baseline.
    committed,  ///< Complete digest-verified baseline became atomically visible.
  };

  /** @brief Dependency-injected SHA-256 verifier used at the baseline commit boundary. */
  class baseline_digest_verifier {
  public:
    /** @brief Permit safe destruction through the verifier interface. */
    virtual ~baseline_digest_verifier() = default;

    /**
     * @brief Verify assembled deterministic bytes against the advertised SHA-256 digest.
     *
     * @param bytes Complete baseline bytes.
     * @param digest Advertised SHA-256 digest.
     * @return `true` only when the digest is authentic and exact.
     */
    [[nodiscard]] virtual bool verify(
      std::span<const std::uint8_t> bytes,
      const std::array<std::uint8_t, 32> &digest
    ) const noexcept = 0;
  };

  /** @brief Fixed one-object, 32-part, 32-KiB atomic baseline receiver. */
  class baseline_receiver {
  public:
    /**
     * @brief Retain one validated authenticated baseline part.
     *
     * @param header Validated common header naming the baseline ID.
     * @param part Parsed baseline part.
     * @return Part admission result.
     */
    constexpr baseline_result add(const common_header &header, const baseline_part &part) noexcept {
      if (header.input_generation == 0 || header.kind != packet_kind::baseline_part || header.state_sequence != 1 ||
          header.object_id == 0 || part.part_count == 0 || part.part_count > maximum_baseline_parts ||
          part.part_index >= part.part_count || part.total_length == 0 || part.total_length > maximum_baseline_bytes ||
          part.part_length == 0 || part.part_length != part.bytes.size() || part.part_offset > part.total_length ||
          part.part_length > part.total_length - part.part_offset) {
        return baseline_result::invalid;
      }
      if (committed_) {
        if (header.object_id != baseline_id_ || header.input_generation != input_generation_ ||
            header.edge_watermark != edge_watermark_ || part.part_count != part_count_ ||
            part.total_length != total_length_ || part.digest != digest_) {
          return baseline_result::conflict;
        }
        const auto &retained = parts_[part.part_index];
        return retained.received && retained.offset == part.part_offset && retained.length == part.part_length &&
                   std::equal(part.bytes.begin(), part.bytes.end(), storage_.begin() + retained.offset) ?
                 baseline_result::duplicate :
                 baseline_result::conflict;
      }
      if (baseline_id_ == 0) {
        input_generation_ = header.input_generation;
        baseline_id_ = header.object_id;
        edge_watermark_ = header.edge_watermark;
        part_count_ = part.part_count;
        total_length_ = part.total_length;
        digest_ = part.digest;
      } else if (header.input_generation != input_generation_ || header.object_id != baseline_id_ ||
                 header.edge_watermark != edge_watermark_ ||
                 part.part_count != part_count_ || part.total_length != total_length_ || part.digest != digest_) {
        return baseline_result::conflict;
      }

      auto &destination = parts_[part.part_index];
      if (destination.received) {
        if (destination.offset != part.part_offset || destination.length != part.part_length ||
            !std::equal(part.bytes.begin(), part.bytes.end(), storage_.begin() + destination.offset)) {
          return baseline_result::conflict;
        }
        return baseline_result::duplicate;
      }
      const auto end = static_cast<std::size_t>(part.part_offset) + part.part_length;
      for (const auto &existing : parts_) {
        if (!existing.received) {
          continue;
        }
        const auto existing_end = static_cast<std::size_t>(existing.offset) + existing.length;
        if (part.part_offset < existing_end && existing.offset < end) {
          return baseline_result::overlap;
        }
      }
      std::copy(part.bytes.begin(), part.bytes.end(), storage_.begin() + part.part_offset);
      destination = {
        .offset = part.part_offset,
        .length = part.part_length,
        .received = true,
      };
      ++received_parts_;
      covered_bytes_ += part.part_length;
      return baseline_result::accepted;
    }

    /**
     * @brief Verify and atomically publish a fully covered baseline.
     *
     * No baseline byte view is exposed before this method succeeds.
     *
     * @param verifier Dependency-provided SHA-256 verifier.
     * @return Commit result.
     */
    baseline_result commit(const baseline_digest_verifier &verifier) noexcept {
      if (committed_) {
        return baseline_result::duplicate;
      }
      if (!complete()) {
        return baseline_result::incomplete;
      }
      const auto bytes = std::span<const std::uint8_t>(storage_).first(total_length_);
      if (!verifier.verify(bytes, digest_)) {
        return baseline_result::digest_mismatch;
      }
      const auto baseline = parse_input_baseline(bytes);
      if (!baseline || baseline.edge_watermark != edge_watermark_) {
        return baseline_result::invalid_body;
      }
      committed_ = true;
      return baseline_result::committed;
    }

    /**
     * @brief Return whether every declared part gives exact non-overlapping coverage.
     *
     * @return `true` when digest verification may run.
     */
    [[nodiscard]] constexpr bool complete() const noexcept {
      return baseline_id_ != 0 && received_parts_ == part_count_ && covered_bytes_ == total_length_;
    }

    /**
     * @brief Return the atomically committed baseline bytes.
     *
     * @return Empty span before a successful digest-verified commit.
     */
    [[nodiscard]] constexpr std::span<const std::uint8_t> committed_bytes() const noexcept {
      return committed_ ? std::span<const std::uint8_t>(storage_).first(total_length_) : std::span<const std::uint8_t> {};
    }

    /**
     * @brief Return the parsed committed deterministic baseline.
     *
     * @return Parsed borrowed baseline, or an invalid result before commit.
     */
    [[nodiscard]] constexpr parsed_input_baseline committed_baseline() const noexcept {
      return committed_ ? parse_input_baseline(std::span<const std::uint8_t>(storage_).first(total_length_)) :
                          parsed_input_baseline {.error = wire_error::invalid_baseline_body};
    }

    /** @brief Return the committed or pending random baseline identifier. */
    [[nodiscard]] constexpr std::uint64_t baseline_id() const noexcept {
      return baseline_id_;
    }

    /** @brief Return whether digest verification made the baseline authoritative. */
    [[nodiscard]] constexpr bool committed() const noexcept {
      return committed_;
    }

    /** @brief Discard the pending/committed baseline on authority-generation replacement. */
    constexpr void reset() noexcept {
      for (auto &part : parts_) {
        part = {};
      }
      input_generation_ = 0;
      baseline_id_ = 0;
      edge_watermark_ = 0;
      part_count_ = 0;
      received_parts_ = 0;
      total_length_ = 0;
      covered_bytes_ = 0;
      digest_ = {};
      committed_ = false;
    }

  private:
    /** @brief One received part range. */
    struct part_range {
      std::uint32_t offset = 0;  ///< Byte offset.
      std::uint32_t length = 0;  ///< Byte length.
      bool received = false;  ///< Whether metadata and bytes are retained.
    };

    std::array<std::uint8_t, maximum_baseline_bytes> storage_ {};  ///< Pending then committed deterministic bytes.
    std::array<part_range, maximum_baseline_parts> parts_ {};  ///< Fixed part coverage metadata.
    std::array<std::uint8_t, 32> digest_ {};  ///< Advertised complete SHA-256 digest.
    std::uint32_t input_generation_ = 0;  ///< Authority generation owning this baseline.
    std::uint64_t baseline_id_ = 0;  ///< Random baseline identifier.
    std::uint64_t edge_watermark_ = 0;  ///< Exact edge watermark shared by all parts and the body.
    std::uint8_t part_count_ = 0;  ///< Declared complete part count.
    std::uint8_t received_parts_ = 0;  ///< Unique retained part count.
    std::uint32_t total_length_ = 0;  ///< Declared complete byte length.
    std::uint32_t covered_bytes_ = 0;  ///< Sum of non-overlapping retained ranges.
    bool committed_ = false;  ///< Digest-verified atomic visibility state.
  };

  /** @brief Host edge-window admission result. */
  enum class edge_receive_result : std::uint8_t {
    accepted,  ///< At least one new edge was retained.
    duplicate,  ///< Every record was already applied or retained byte-identically.
    baseline_required,  ///< Input baseline is not committed for this authority.
    stale_generation,  ///< Packet generation does not own input authority.
    conflict,  ///< An edge ID was reused with different bytes.
    gap_too_large,  ///< Forward gap exceeds the fixed 256-edge retention window.
    malformed,  ///< Packet is not a valid contiguous edge batch.
  };

  /** @brief Fixed 256-edge reorder window with exactly-once ordered application. */
  class edge_receiver {
  public:
    /** @brief Maximum retained unacknowledged edge window. */
    static constexpr std::size_t capacity = 256;

    /**
     * @brief Begin a fresh input generation that requires a committed baseline.
     *
     * @param input_generation Nonzero authority generation.
     * @param baseline_edge_watermark Greatest edge represented by the baseline.
     * @return `true` when the generation is valid.
     */
    constexpr bool reset(const std::uint32_t input_generation, const std::uint64_t baseline_edge_watermark = 0) noexcept {
      if (input_generation == 0) {
        return false;
      }
      for (auto &entry : slots_) {
        entry.occupied = false;
      }
      input_generation_ = input_generation;
      applied_through_ = baseline_edge_watermark;
      baseline_committed_ = false;
      return true;
    }

    /** @brief Permit normal edge/state admission after atomic baseline commit. */
    constexpr void activate_baseline() noexcept {
      baseline_committed_ = input_generation_ != 0;
    }

    /**
     * @brief Admit one validated contiguous edge packet without partial mutation.
     *
     * @param packet Parsed input packet.
     * @return Batch admission result.
     */
    constexpr edge_receive_result admit(const parsed_packet &packet) noexcept {
      if (!packet || packet.header.kind != packet_kind::edge_batch) {
        return edge_receive_result::malformed;
      }
      if (packet.header.input_generation != input_generation_) {
        return edge_receive_result::stale_generation;
      }
      if (!baseline_committed_) {
        return edge_receive_result::baseline_required;
      }
      const auto batch = parse_edge_batch(packet.payload, packet.header.object_id);
      if (!batch) {
        return edge_receive_result::malformed;
      }
      bool has_new = false;
      for (std::size_t index = 0; index < batch.count; ++index) {
        const auto parsed = batch.edge(index);
        const auto edge_id = parsed.value.edge_id;
        if (edge_id <= applied_through_) {
          continue;
        }
        if (edge_id - applied_through_ > capacity) {
          return edge_receive_result::gap_too_large;
        }
        const auto &destination = slots_[edge_id % capacity];
        if (destination.occupied && (destination.value.edge_id != edge_id || destination.value != parsed.value)) {
          return edge_receive_result::conflict;
        }
        has_new = has_new || !destination.occupied;
      }
      for (std::size_t index = 0; index < batch.count; ++index) {
        const auto parsed = batch.edge(index);
        if (parsed.value.edge_id <= applied_through_) {
          continue;
        }
        auto &destination = slots_[parsed.value.edge_id % capacity];
        if (!destination.occupied) {
          destination.value = parsed.value;
          destination.occupied = true;
        }
      }
      return has_new ? edge_receive_result::accepted : edge_receive_result::duplicate;
    }

    /**
     * @brief Apply every newly contiguous edge exactly once in identifier order.
     *
     * @tparam Apply Callable accepting `const edge_record &` and returning `bool`.
     * @param apply Ordered platform-input callback.
     * @return Number of newly applied records.
     */
    template<class Apply>
    constexpr std::size_t drain(Apply &&apply) noexcept(noexcept(std::invoke(apply, std::declval<const edge_record &>()))) {
      std::size_t count = 0;
      while (applied_through_ != std::numeric_limits<std::uint64_t>::max()) {
        const auto next = applied_through_ + 1U;
        auto &entry = slots_[next % capacity];
        if (!entry.occupied || entry.value.edge_id != next || !std::invoke(apply, std::as_const(entry.value))) {
          break;
        }
        entry.occupied = false;
        applied_through_ = next;
        ++count;
      }
      return count;
    }

    /** @brief Return the greatest contiguously applied edge identifier. */
    [[nodiscard]] constexpr std::uint64_t applied_through() const noexcept {
      return applied_through_;
    }

    /**
     * @brief Return receipt bits for the next 64 edge identifiers.
     *
     * Bit zero denotes `applied_through() + 1`.
     *
     * @return Forward edge reception bitmap.
     */
    [[nodiscard]] constexpr std::uint64_t reception_bitmap() const noexcept {
      std::uint64_t bitmap = 0;
      for (std::uint64_t distance = 1; distance <= 64; ++distance) {
        if (applied_through_ > std::numeric_limits<std::uint64_t>::max() - distance) {
          break;
        }
        const auto edge_id = applied_through_ + distance;
        const auto &entry = slots_[edge_id % capacity];
        if (entry.occupied && entry.value.edge_id == edge_id) {
          bitmap |= std::uint64_t {1} << (distance - 1U);
        }
      }
      return bitmap;
    }

  private:
    /** @brief One modulo-indexed retained edge slot. */
    struct edge_slot {
      edge_record value {};  ///< Retained exact edge.
      bool occupied = false;  ///< Whether this slot contains a live gap/window edge.
    };

    std::array<edge_slot, capacity> slots_ {};  ///< Fixed retained edge window.
    std::uint32_t input_generation_ = 0;  ///< Active input authority generation.
    std::uint64_t applied_through_ = 0;  ///< Greatest contiguously applied edge.
    bool baseline_committed_ = false;  ///< Whether normal admission may mutate host input.
  };

  /** @brief Client edge-retention admission result. */
  enum class edge_send_result : std::uint8_t {
    accepted,  ///< Edge received a new sequence and was retained.
    invalid_generation,  ///< Input or instance generation is invalid.
    invalid_record,  ///< Edge kind, device, identifier, or timestamp is invalid.
    window_full,  ///< The fixed 256-edge unacknowledged window is full.
    exhausted,  ///< Nonzero 64-bit edge identifiers cannot advance without wrap.
  };

  /** @brief Fixed client-side repeated-until-ACK edge retention window. */
  class edge_sender {
  public:
    /** @brief Maximum retained unacknowledged edge count. */
    static constexpr std::size_t capacity = 256;

    /**
     * @brief Start a fresh input generation and edge namespace.
     *
     * @param input_generation Nonzero authority generation.
     * @param next_edge_id First new nonzero edge ID, normally baseline watermark plus one.
     * @return `true` when the namespace is valid.
     */
    constexpr bool reset(const std::uint32_t input_generation, const std::uint64_t next_edge_id = 1) noexcept {
      if (input_generation == 0 || next_edge_id == 0) {
        return false;
      }
      for (auto &entry : slots_) {
        entry.occupied = false;
      }
      input_generation_ = input_generation;
      next_edge_id_ = next_edge_id;
      retained_ = 0;
      return true;
    }

    /**
     * @brief Assign and retain one physical edge without allocation.
     *
     * @param edge Edge with `edge_id == 0`; all remaining wire fields must be valid.
     * @param assigned_id Assigned nonzero edge ID destination.
     * @return Retention result.
     */
    constexpr edge_send_result enqueue(edge_record edge, std::uint64_t &assigned_id) noexcept {
      if (input_generation_ == 0 || edge.instance_generation == 0) {
        return edge_send_result::invalid_generation;
      }
      if (edge.edge_id != 0 || edge.physical_time_us == 0 || !valid_edge_kind(edge.kind) ||
          !valid_device_type(edge.device) || !edge_kind_matches_device(edge.kind, edge.device) || edge.device_id == 0) {
        return edge_send_result::invalid_record;
      }
      if (retained_ == capacity) {
        return edge_send_result::window_full;
      }
      if (next_edge_id_ == 0 || next_edge_id_ == std::numeric_limits<std::uint64_t>::max()) {
        return edge_send_result::exhausted;
      }
      assigned_id = next_edge_id_++;
      edge.edge_id = assigned_id;
      auto &destination = slots_[assigned_id % capacity];
      if (destination.occupied) {
        return edge_send_result::window_full;
      }
      destination = {
        .value = edge,
        .last_sent_us = 0,
        .transmissions = 0,
        .occupied = true,
      };
      ++retained_;
      return edge_send_result::accepted;
    }

    /**
     * @brief Copy the oldest contiguous due records into a caller-owned packet batch.
     *
     * @param now_us Current monotonic time.
     * @param srtt_us Smoothed RTT in microseconds.
     * @param output Destination with capacity 1 through 16 recommended.
     * @return Number of records copied in ascending contiguous order.
     */
    constexpr std::size_t due_batch(
      const std::uint64_t now_us,
      const std::uint64_t srtt_us,
      const std::span<edge_record> output
    ) const noexcept {
      const auto limit = std::min(output.size(), maximum_edges_per_batch);
      if (limit == 0) {
        return 0;
      }
      const auto retry = retry_interval_us(srtt_us, 2'000);
      const outbound_slot *first = nullptr;
      for (const auto &entry : slots_) {
        if (!entry.occupied || (entry.last_sent_us != 0 && now_us - entry.last_sent_us < retry)) {
          continue;
        }
        if (first == nullptr || entry.value.edge_id < first->value.edge_id) {
          first = &entry;
        }
      }
      if (first == nullptr) {
        return 0;
      }
      std::size_t count = 0;
      auto edge_id = first->value.edge_id;
      while (count < limit) {
        const auto &entry = slots_[edge_id % capacity];
        if (!entry.occupied || entry.value.edge_id != edge_id ||
            (entry.last_sent_us != 0 && now_us - entry.last_sent_us < retry)) {
          break;
        }
        output[count++] = entry.value;
        if (edge_id == std::numeric_limits<std::uint64_t>::max()) {
          break;
        }
        ++edge_id;
      }
      return count;
    }

    /**
     * @brief Mark a transmitted contiguous batch while retaining exact records for retry.
     *
     * @param first_edge_id First edge ID in the submitted packet.
     * @param count Submitted contiguous record count.
     * @param sent_at_us Monotonic socket-submission time.
     * @return `true` when every named record was live.
     */
    constexpr bool mark_sent(
      const std::uint64_t first_edge_id,
      const std::size_t count,
      const std::uint64_t sent_at_us
    ) noexcept {
      if (first_edge_id == 0 || count == 0 || count > maximum_edges_per_batch || sent_at_us == 0) {
        return false;
      }
      for (std::size_t index = 0; index < count; ++index) {
        if (first_edge_id > std::numeric_limits<std::uint64_t>::max() - index) {
          return false;
        }
        const auto edge_id = first_edge_id + index;
        const auto &entry = slots_[edge_id % capacity];
        if (!entry.occupied || entry.value.edge_id != edge_id) {
          return false;
        }
      }
      for (std::size_t index = 0; index < count; ++index) {
        auto &entry = slots_[(first_edge_id + index) % capacity];
        entry.last_sent_us = sent_at_us;
        if (entry.transmissions != std::numeric_limits<std::uint8_t>::max()) {
          ++entry.transmissions;
        }
      }
      return true;
    }

    /**
     * @brief Retire every edge explicitly named by one LSPI-style ACK window.
     *
     * @param contiguous_applied Greatest contiguously applied edge ID.
     * @param forward_reception_bitmap Bit zero acknowledges `contiguous_applied + 1`.
     * @return Number of newly retired retained records.
     */
    constexpr std::size_t acknowledge(
      const std::uint64_t contiguous_applied,
      const std::uint64_t forward_reception_bitmap
    ) noexcept {
      std::size_t removed = 0;
      for (auto &entry : slots_) {
        if (!entry.occupied) {
          continue;
        }
        bool acknowledged = entry.value.edge_id <= contiguous_applied;
        if (!acknowledged && entry.value.edge_id > contiguous_applied) {
          const auto distance = entry.value.edge_id - contiguous_applied;
          acknowledged = distance <= 64 && (forward_reception_bitmap & (std::uint64_t {1} << (distance - 1U))) != 0;
        }
        if (acknowledged) {
          entry.occupied = false;
          --retained_;
          ++removed;
        }
      }
      return removed;
    }

    /** @brief Return the number of retained unacknowledged edges. */
    [[nodiscard]] constexpr std::size_t size() const noexcept {
      return retained_;
    }

    /**
     * @brief Calculate the exact LSP edge retry delay.
     *
     * @param srtt_us Smoothed RTT in microseconds.
     * @param maximum_us Upper clamp, 2 ms for input edges and 5 ms for controller output.
     * @return `clamp(SRTT/2, 250 us, maximum_us)`.
     */
    [[nodiscard]] static constexpr std::uint64_t retry_interval_us(
      const std::uint64_t srtt_us,
      const std::uint64_t maximum_us
    ) noexcept {
      return std::clamp(srtt_us / 2U, std::uint64_t {250}, maximum_us);
    }

  private:
    /** @brief One retained outbound edge and retry metadata. */
    struct outbound_slot {
      edge_record value {};  ///< Exact immutable LSP edge bytes/value.
      std::uint64_t last_sent_us = 0;  ///< Most recent transmission time.
      std::uint8_t transmissions = 0;  ///< Saturating submission count.
      bool occupied = false;  ///< Whether the edge awaits explicit ACK.
    };

    std::array<outbound_slot, capacity> slots_ {};  ///< Fixed unacknowledged edge retention.
    std::uint32_t input_generation_ = 0;  ///< Active client authority generation.
    std::uint64_t next_edge_id_ = 1;  ///< Next nonzero physical edge identifier.
    std::size_t retained_ = 0;  ///< Live retained edge count.
  };

  /** @brief Pointer sample accumulation result. */
  enum class pointer_compose_result : std::uint8_t {
    accepted,  ///< Sample was accumulated.
    invalid_generation,  ///< Device generation is zero or stale.
    invalid_ordinal,  ///< Physical ordinal is zero or does not advance.
    overflow,  ///< A cumulative signed counter would wrap.
    batch_full,  ///< One packet would represent more than 65,535 reports.
  };

  /** @brief Allocation-free cumulative pointer composer for one physical device. */
  class pointer_composer {
  public:
    /**
     * @brief Start one fresh pointer generation with reset cumulative counters.
     *
     * @param pointer_id Pointer object ID in the range 1 through 4.
     * @param instance_generation Nonzero device instance generation.
     * @return `true` when identifiers are valid.
     */
    constexpr bool reset(const std::uint32_t pointer_id, const std::uint32_t instance_generation) noexcept {
      if (pointer_id == 0 || pointer_id > 4 || instance_generation == 0) {
        return false;
      }
      pointer_id_ = pointer_id;
      state_ = {.instance_generation = instance_generation};
      return true;
    }

    /**
     * @brief Add one relative physical report to cumulative counters.
     *
     * @param instance_generation Exact active instance generation.
     * @param ordinal Nonzero increasing physical ordinal.
     * @param x Horizontal delta.
     * @param y Vertical delta.
     * @param vertical_scroll Vertical scroll delta.
     * @param horizontal_scroll Horizontal scroll delta.
     * @return Composition result.
     */
    constexpr pointer_compose_result add_relative(
      const std::uint32_t instance_generation,
      const std::uint64_t ordinal,
      const std::int64_t x,
      const std::int64_t y,
      const std::int64_t vertical_scroll,
      const std::int64_t horizontal_scroll
    ) noexcept {
      if (instance_generation == 0 || instance_generation != state_.instance_generation) {
        return pointer_compose_result::invalid_generation;
      }
      if (ordinal == 0 || ordinal <= state_.physical_ordinal) {
        return pointer_compose_result::invalid_ordinal;
      }
      if (state_.represented_reports == std::numeric_limits<std::uint16_t>::max()) {
        return pointer_compose_result::batch_full;
      }
      std::int64_t next_x = 0;
      std::int64_t next_y = 0;
      std::int64_t next_vertical = 0;
      std::int64_t next_horizontal = 0;
      if (!checked_add(state_.cumulative_x, x, next_x) || !checked_add(state_.cumulative_y, y, next_y) ||
          !checked_add(state_.cumulative_vertical_scroll, vertical_scroll, next_vertical) ||
          !checked_add(state_.cumulative_horizontal_scroll, horizontal_scroll, next_horizontal)) {
        return pointer_compose_result::overflow;
      }
      state_.mode = pointer_flag::relative;
      state_.physical_ordinal = ordinal;
      state_.cumulative_x = next_x;
      state_.cumulative_y = next_y;
      state_.cumulative_vertical_scroll = next_vertical;
      state_.cumulative_horizontal_scroll = next_horizontal;
      state_.absolute_x = 0;
      state_.absolute_y = 0;
      ++state_.represented_reports;
      return pointer_compose_result::accepted;
    }

    /**
     * @brief Retain one newest absolute physical pointer sample.
     *
     * @param instance_generation Exact active instance generation.
     * @param ordinal Nonzero increasing physical ordinal.
     * @param x Horizontal Q0.32 coordinate.
     * @param y Vertical Q0.32 coordinate.
     * @return Composition result.
     */
    constexpr pointer_compose_result set_absolute(
      const std::uint32_t instance_generation,
      const std::uint64_t ordinal,
      const std::uint32_t x,
      const std::uint32_t y
    ) noexcept {
      if (instance_generation == 0 || instance_generation != state_.instance_generation) {
        return pointer_compose_result::invalid_generation;
      }
      if (ordinal == 0 || ordinal <= state_.physical_ordinal) {
        return pointer_compose_result::invalid_ordinal;
      }
      if (state_.represented_reports == std::numeric_limits<std::uint16_t>::max()) {
        return pointer_compose_result::batch_full;
      }
      state_.mode = pointer_flag::absolute;
      state_.physical_ordinal = ordinal;
      state_.absolute_x = x;
      state_.absolute_y = y;
      ++state_.represented_reports;
      return pointer_compose_result::accepted;
    }

    /** @brief Return the current cumulative/latest pointer wire payload. */
    [[nodiscard]] constexpr const pointer_payload &state() const noexcept {
      return state_;
    }

    /** @brief Return the pointer object ID owned by this composer. */
    [[nodiscard]] constexpr std::uint32_t pointer_id() const noexcept {
      return pointer_id_;
    }

    /** @brief Start a new represented-report batch without resetting cumulative distance. */
    constexpr void mark_emitted() noexcept {
      state_.represented_reports = 0;
    }

  private:
    /**
     * @brief Add signed counters without undefined overflow.
     *
     * @param left Retained value.
     * @param right New delta.
     * @param output Valid sum destination.
     * @return `true` when the sum is representable.
     */
    [[nodiscard]] static constexpr bool checked_add(
      const std::int64_t left,
      const std::int64_t right,
      std::int64_t &output
    ) noexcept {
      if ((right > 0 && left > std::numeric_limits<std::int64_t>::max() - right) ||
          (right < 0 && left < std::numeric_limits<std::int64_t>::min() - right)) {
        return false;
      }
      output = left + right;
      return true;
    }

    pointer_payload state_ {};  ///< Current cumulative/latest state.
    std::uint32_t pointer_id_ = 0;  ///< Pointer object identifier.
  };

  /** @brief One host pointer injection operation derived from cumulative/latest state. */
  struct pointer_application {
    pointer_flag mode = pointer_flag::relative;  ///< Relative delta or absolute coordinates.
    std::int64_t relative_x = 0;  ///< Difference from the last applied cumulative X.
    std::int64_t relative_y = 0;  ///< Difference from the last applied cumulative Y.
    std::int64_t vertical_scroll = 0;  ///< Difference from the last applied cumulative wheel.
    std::int64_t horizontal_scroll = 0;  ///< Difference from the last applied cumulative wheel.
    std::uint32_t absolute_x = 0;  ///< Latest absolute Q0.32 X.
    std::uint32_t absolute_y = 0;  ///< Latest absolute Q0.32 Y.
    std::uint64_t physical_ordinal = 0;  ///< Newest represented physical sample.
    std::uint64_t state_sequence = 0;  ///< Applied logical state sequence.
  };

  /** @brief Pointer receive/admission result. */
  enum class pointer_receive_result : std::uint8_t {
    retained,  ///< Newest state was retained pending its edge watermark.
    applied,  ///< State was immediately applied.
    stale,  ///< State sequence or physical ordinal did not advance.
    stale_generation,  ///< Input, pointer, or instance generation is stale.
    waiting_for_edges,  ///< State is retained until its edge watermark applies.
    apply_failed,  ///< Platform callback rejected the ready state.
    overflow,  ///< Cumulative difference cannot be represented safely.
    malformed,  ///< Packet is not a valid pointer-motion packet.
  };

  /** @brief Host receiver for one loss-tolerant cumulative pointer stream. */
  class pointer_receiver {
  public:
    /**
     * @brief Install pointer counters represented by a committed authority baseline.
     *
     * @param input_generation Nonzero input authority generation.
     * @param pointer_id Pointer object ID in the range 1 through 4.
     * @param baseline Pointer baseline with nonzero instance generation and ordinal.
     * @param baseline_edge_watermark Greatest dependent edge represented by the baseline.
     * @return `true` when the baseline is valid.
     */
    constexpr bool reset(
      const std::uint32_t input_generation,
      const std::uint32_t pointer_id,
      const pointer_payload &baseline,
      const std::uint64_t baseline_edge_watermark = 0
    ) noexcept {
      if (input_generation == 0 || pointer_id == 0 || pointer_id > 4 || baseline.instance_generation == 0) {
        return false;
      }
      input_generation_ = input_generation;
      pointer_id_ = pointer_id;
      applied_ = baseline;
      pending_ = {};
      pending_header_ = {};
      pending_valid_ = false;
      last_state_sequence_ = 1;
      last_edge_watermark_ = baseline_edge_watermark;
      return true;
    }

    /**
     * @brief Seed pointer state and its exact per-key sequence from one committed baseline record.
     *
     * @param input_generation Nonzero authority generation.
     * @param baseline Parsed committed baseline.
     * @param record_index Pointer record index.
     * @return `true` when the record is one valid pointer key and reset succeeds atomically.
     */
    constexpr bool install_baseline_record(
      const std::uint32_t input_generation,
      const parsed_input_baseline &baseline,
      const std::size_t record_index
    ) noexcept {
      if (!baseline) {
        return false;
      }
      const auto record = baseline.record(record_index);
      if (record.header.kind != baseline_record_kind::pointer) {
        return false;
      }
      const auto pointer = parse_pointer_payload(record.payload);
      if (!pointer || pointer.value.physical_ordinal != record.header.physical_ordinal) {
        return false;
      }
      if (!reset(input_generation, record.header.device_id, pointer.value, baseline.edge_watermark)) {
        return false;
      }
      last_state_sequence_ = record.header.state_sequence;
      return true;
    }

    /**
     * @brief Retain the newest validated pointer packet without allocation.
     *
     * @param packet Parsed pointer packet.
     * @param applied_edge_watermark Current exactly-once edge watermark.
     * @return Admission readiness result.
     */
    constexpr pointer_receive_result admit(
      const parsed_packet &packet,
      const std::uint64_t applied_edge_watermark
    ) noexcept {
      if (!packet || packet.header.kind != packet_kind::pointer_motion) {
        return pointer_receive_result::malformed;
      }
      const auto pointer = parse_pointer_payload(packet.payload);
      if (!pointer) {
        return pointer_receive_result::malformed;
      }
      if (packet.header.input_generation != input_generation_ || packet.header.object_id != pointer_id_ ||
          pointer.value.instance_generation != applied_.instance_generation) {
        return pointer_receive_result::stale_generation;
      }
      if (packet.header.state_sequence <= last_state_sequence_ || packet.header.edge_watermark < last_edge_watermark_ ||
          pointer.value.physical_ordinal <= applied_.physical_ordinal ||
          (pending_valid_ && (packet.header.state_sequence <= pending_header_.state_sequence ||
                              packet.header.edge_watermark < pending_header_.edge_watermark ||
                              pointer.value.physical_ordinal <= pending_.physical_ordinal))) {
        return pointer_receive_result::stale;
      }
      pending_ = pointer.value;
      pending_header_ = packet.header;
      pending_valid_ = true;
      return packet.header.edge_watermark <= applied_edge_watermark ? pointer_receive_result::retained :
                                                                      pointer_receive_result::waiting_for_edges;
    }

    /**
     * @brief Apply the newest pointer state once its edge watermark is ready.
     *
     * @tparam Apply Callable accepting `const pointer_application &` and returning `bool`.
     * @param applied_edge_watermark Current exactly-once edge watermark.
     * @param apply Platform pointer callback.
     * @return Application result.
     */
    template<class Apply>
    constexpr pointer_receive_result apply_ready(
      const std::uint64_t applied_edge_watermark,
      Apply &&apply
    ) noexcept(noexcept(std::invoke(apply, std::declval<const pointer_application &>()))) {
      if (!pending_valid_ || pending_header_.edge_watermark > applied_edge_watermark) {
        return pointer_receive_result::waiting_for_edges;
      }
      pointer_application application {
        .mode = pending_.mode,
        .absolute_x = pending_.absolute_x,
        .absolute_y = pending_.absolute_y,
        .physical_ordinal = pending_.physical_ordinal,
        .state_sequence = pending_header_.state_sequence,
      };
      if (pending_.mode == pointer_flag::relative &&
          (!checked_subtract(pending_.cumulative_x, applied_.cumulative_x, application.relative_x) ||
           !checked_subtract(pending_.cumulative_y, applied_.cumulative_y, application.relative_y) ||
           !checked_subtract(
             pending_.cumulative_vertical_scroll,
             applied_.cumulative_vertical_scroll,
             application.vertical_scroll
           ) ||
           !checked_subtract(
             pending_.cumulative_horizontal_scroll,
             applied_.cumulative_horizontal_scroll,
             application.horizontal_scroll
           ))) {
        return pointer_receive_result::overflow;
      }
      if (!std::invoke(apply, std::as_const(application))) {
        return pointer_receive_result::apply_failed;
      }
      applied_ = pending_;
      last_state_sequence_ = pending_header_.state_sequence;
      last_edge_watermark_ = pending_header_.edge_watermark;
      pending_valid_ = false;
      return pointer_receive_result::applied;
    }

    /** @brief Return the newest successfully applied physical pointer ordinal. */
    [[nodiscard]] constexpr std::uint64_t applied_physical_ordinal() const noexcept {
      return applied_.physical_ordinal;
    }

  private:
    /**
     * @brief Subtract signed cumulative counters without undefined overflow.
     *
     * @param newer New cumulative value.
     * @param older Last applied cumulative value.
     * @param output Difference destination.
     * @return `true` when the mathematical difference is representable.
     */
    [[nodiscard]] static constexpr bool checked_subtract(
      const std::int64_t newer,
      const std::int64_t older,
      std::int64_t &output
    ) noexcept {
      if ((older < 0 && newer > std::numeric_limits<std::int64_t>::max() + older) ||
          (older > 0 && newer < std::numeric_limits<std::int64_t>::min() + older)) {
        return false;
      }
      output = newer - older;
      return true;
    }

    pointer_payload applied_ {};  ///< Last applied cumulative/latest state.
    pointer_payload pending_ {};  ///< Newest retained replaceable state.
    common_header pending_header_ {};  ///< Header binding pending state to edges.
    std::uint32_t input_generation_ = 0;  ///< Active authority generation.
    std::uint32_t pointer_id_ = 0;  ///< Active pointer object ID.
    std::uint64_t last_state_sequence_ = 0;  ///< Greatest applied state sequence.
    std::uint64_t last_edge_watermark_ = 0;  ///< Greatest applied dependent-edge watermark.
    bool pending_valid_ = false;  ///< Whether pending state is populated.
  };

  /** @brief Pen replaceable-state receive/admission result. */
  enum class pen_receive_result : std::uint8_t {
    retained,  ///< Newest pen state was retained.
    applied,  ///< Retained pen state was submitted to the platform.
    stale,  ///< State sequence or physical ordinal did not advance.
    stale_generation,  ///< Input, device, or instance generation is stale.
    waiting_for_edges,  ///< State awaits its dependent edge watermark.
    apply_failed,  ///< Platform callback rejected the ready state.
    malformed,  ///< Packet is not one exact frozen pen device-state payload.
  };

  /** @brief Allocation-free latest absolute pen receiver with edge-watermark ordering. */
  class pen_receiver {
  public:
    /**
     * @brief Install one pen state from a committed authority baseline.
     *
     * @param input_generation Nonzero input authority generation.
     * @param device_id Nonzero pen device identifier.
     * @param baseline Frozen pen baseline state.
     * @param baseline_state_sequence Nonzero per-key baseline sequence.
     * @param baseline_edge_watermark Greatest dependent edge represented by the baseline.
     * @return `true` when every generation and identifier is consistent.
     */
    constexpr bool reset(
      const std::uint32_t input_generation,
      const std::uint32_t device_id,
      const pen_state_payload &baseline,
      const std::uint64_t baseline_state_sequence = 1,
      const std::uint64_t baseline_edge_watermark = 0
    ) noexcept {
      std::array<std::uint8_t, pen_state_payload_size> encoded {};
      if (input_generation == 0 || device_id == 0 || baseline_state_sequence == 0 ||
          baseline.prefix.device != device_type::pen || baseline.prefix.device_id != device_id ||
          baseline.prefix.instance_generation == 0 || baseline.prefix.physical_ordinal == 0 ||
          serialize_pen_state_payload(baseline, encoded) != wire_error::none) {
        return false;
      }
      input_generation_ = input_generation;
      device_id_ = device_id;
      applied_ = baseline;
      pending_ = {};
      pending_header_ = {};
      last_state_sequence_ = baseline_state_sequence;
      last_edge_watermark_ = baseline_edge_watermark;
      pending_valid_ = false;
      return true;
    }

    /**
     * @brief Seed exact pen model state from one committed baseline record.
     *
     * @param input_generation Nonzero authority generation.
     * @param baseline Parsed committed baseline.
     * @param record_index Pen record index.
     * @return `true` when full model validation and reset succeed atomically.
     */
    constexpr bool install_baseline_record(
      const std::uint32_t input_generation,
      const parsed_input_baseline &baseline,
      const std::size_t record_index
    ) noexcept {
      if (!baseline) {
        return false;
      }
      const auto record = baseline.record(record_index);
      if (record.header.kind != baseline_record_kind::pen) {
        return false;
      }
      const auto pen = parse_pen_state_payload(record.payload);
      return pen && pen.value.prefix.physical_ordinal == record.header.physical_ordinal &&
             reset(
               input_generation,
               record.header.device_id,
               pen.value,
               record.header.state_sequence,
               baseline.edge_watermark
             );
    }

    /**
     * @brief Retain the newest validated pen packet without allocation.
     *
     * @param packet Parsed device-state packet.
     * @param applied_edge_watermark Current exactly-once edge watermark.
     * @return Admission readiness result.
     */
    constexpr pen_receive_result admit(
      const parsed_packet &packet,
      const std::uint64_t applied_edge_watermark
    ) noexcept {
      if (!packet || packet.header.kind != packet_kind::device_state) {
        return pen_receive_result::malformed;
      }
      device_type type {};
      std::uint32_t device_id = 0;
      const auto pen = parse_pen_state_payload(packet.payload);
      if (!pen || !decode_device_object_id(packet.header.object_id, type, device_id) || type != device_type::pen ||
          device_id != device_id_) {
        return pen_receive_result::malformed;
      }
      if (packet.header.input_generation != input_generation_ ||
          pen.value.prefix.instance_generation != applied_.prefix.instance_generation) {
        return pen_receive_result::stale_generation;
      }
      if (packet.header.state_sequence <= last_state_sequence_ || packet.header.edge_watermark < last_edge_watermark_ ||
          pen.value.prefix.physical_ordinal <= applied_.prefix.physical_ordinal ||
          (pending_valid_ && (packet.header.state_sequence <= pending_header_.state_sequence ||
                              packet.header.edge_watermark < pending_header_.edge_watermark ||
                              pen.value.prefix.physical_ordinal <= pending_.prefix.physical_ordinal))) {
        return pen_receive_result::stale;
      }
      pending_ = pen.value;
      pending_header_ = packet.header;
      pending_valid_ = true;
      return packet.header.edge_watermark <= applied_edge_watermark ? pen_receive_result::retained :
                                                                      pen_receive_result::waiting_for_edges;
    }

    /**
     * @brief Apply the newest pen state after all dependent edges are ready.
     *
     * @tparam Apply Callable accepting `const pen_state_payload &` and returning `bool`.
     * @param applied_edge_watermark Current exactly-once edge watermark.
     * @param apply Platform pen callback.
     * @return Application result.
     */
    template<class Apply>
    constexpr pen_receive_result apply_ready(
      const std::uint64_t applied_edge_watermark,
      Apply &&apply
    ) noexcept(noexcept(std::invoke(apply, std::declval<const pen_state_payload &>()))) {
      if (!pending_valid_ || pending_header_.edge_watermark > applied_edge_watermark) {
        return pen_receive_result::waiting_for_edges;
      }
      if (!std::invoke(apply, std::as_const(pending_))) {
        return pen_receive_result::apply_failed;
      }
      applied_ = pending_;
      last_state_sequence_ = pending_header_.state_sequence;
      last_edge_watermark_ = pending_header_.edge_watermark;
      pending_valid_ = false;
      return pen_receive_result::applied;
    }

    /** @brief Return the newest successfully applied frozen pen state. */
    [[nodiscard]] constexpr const pen_state_payload &applied_state() const noexcept {
      return applied_;
    }

  private:
    pen_state_payload applied_ {};  ///< Last platform-applied pen state.
    pen_state_payload pending_ {};  ///< Newest retained replaceable pen state.
    common_header pending_header_ {};  ///< Header binding pending state to dependent edges.
    std::uint32_t input_generation_ = 0;  ///< Active input authority generation.
    std::uint32_t device_id_ = 0;  ///< Active pen device identifier.
    std::uint64_t last_state_sequence_ = 0;  ///< Greatest applied pen state sequence.
    std::uint64_t last_edge_watermark_ = 0;  ///< Greatest applied dependent-edge watermark.
    bool pending_valid_ = false;  ///< Whether a newer pen state is retained.
  };

  /** @brief Text barrier admission result. */
  enum class text_result : std::uint8_t {
    accepted,  ///< New request was retained.
    duplicate,  ///< Byte-identical request ID already exists.
    conflicting_request,  ///< Request ID was reused with different content or barrier.
    invalid_generation,  ///< Input generation is zero or stale.
    invalid_text,  ///< Text is empty, oversized, or invalid UTF-8 scalar data.
    invalid_object,  ///< Chunked object metadata is incomplete or invalid.
    full,  ///< Fixed pending text table is full.
    not_found,  ///< Object completion or retirement named no retained request.
  };

  /** @brief One ready inline or chunked text commit delivered behind its edge barrier. */
  struct text_delivery {
    std::uint64_t request_id = 0;  ///< Idempotent nonzero control request ID.
    std::uint32_t input_generation = 0;  ///< Exact input authority generation.
    std::uint64_t preceding_edge_id = 0;  ///< Required contiguous edge barrier.
    std::span<const std::uint8_t> inline_utf8 {};  ///< Inline UTF-8 bytes, empty for object form.
    std::uint64_t object_id = 0;  ///< Chunked object ID, zero for inline form.
    std::uint32_t object_length = 0;  ///< Complete chunked UTF-8 length.
    std::array<std::uint8_t, 32> object_digest {};  ///< Chunked object SHA-256.
  };

  /**
   * @brief Fixed idempotent text queue that never blocks later real-time input packets.
   *
   * @tparam Capacity Maximum retained text requests awaiting response-cache retirement.
   * @tparam MaxTextBytes Maximum inline text bytes; LSP/1 permits at most 16 KiB total text.
   */
  template<std::size_t Capacity = 4, std::size_t MaxTextBytes = 16U * 1024U>
  class text_barrier_state {
  public:
    static_assert(Capacity > 0, "text barrier capacity must be nonzero");
    static_assert(MaxTextBytes > 0 && MaxTextBytes <= 16U * 1024U, "LSP/1 text is limited to 16 KiB");

    /**
     * @brief Begin a fresh authoritative input generation and discard pending text.
     *
     * @param input_generation Nonzero input generation.
     * @return `true` when the generation is valid.
     */
    constexpr bool reset(const std::uint32_t input_generation) noexcept {
      if (input_generation == 0) {
        return false;
      }
      for (auto &entry : entries_) {
        entry.occupied = false;
      }
      input_generation_ = input_generation;
      return true;
    }

    /**
     * @brief Retain one inline valid UTF-8 text request behind an edge barrier.
     *
     * @param request_id Nonzero idempotent control request ID.
     * @param input_generation Exact authority generation.
     * @param preceding_edge_id Greatest edge that must be applied before text.
     * @param utf8 Complete inline UTF-8 scalar sequence.
     * @return Admission result.
     */
    constexpr text_result submit_inline(
      const std::uint64_t request_id,
      const std::uint32_t input_generation,
      const std::uint64_t preceding_edge_id,
      const std::span<const std::uint8_t> utf8
    ) noexcept {
      if (input_generation == 0 || input_generation != input_generation_) {
        return text_result::invalid_generation;
      }
      if (request_id == 0 || utf8.empty() || utf8.size() > MaxTextBytes || !valid_utf8(utf8)) {
        return text_result::invalid_text;
      }
      entry *free_entry = nullptr;
      for (auto &candidate : entries_) {
        if (candidate.occupied && candidate.request_id == request_id) {
          return candidate.input_generation == input_generation && candidate.preceding_edge_id == preceding_edge_id &&
                     candidate.inline_form && candidate.text_length == utf8.size() &&
                     std::equal(utf8.begin(), utf8.end(), candidate.text.begin()) ?
                   text_result::duplicate :
                   text_result::conflicting_request;
        }
        if (!candidate.occupied && free_entry == nullptr) {
          free_entry = &candidate;
        }
      }
      if (free_entry == nullptr) {
        return text_result::full;
      }
      free_entry->request_id = request_id;
      free_entry->input_generation = input_generation;
      free_entry->preceding_edge_id = preceding_edge_id;
      free_entry->text_length = static_cast<std::uint16_t>(utf8.size());
      std::copy(utf8.begin(), utf8.end(), free_entry->text.begin());
      free_entry->inline_form = true;
      free_entry->object_ready = true;
      free_entry->delivered = false;
      free_entry->occupied = true;
      return text_result::accepted;
    }

    /**
     * @brief Retain one chunked text-object reference behind an edge barrier.
     *
     * @param request_id Nonzero idempotent control request ID.
     * @param input_generation Exact authority generation.
     * @param preceding_edge_id Greatest edge that must apply first.
     * @param object_id Nonzero bounded-object identifier.
     * @param object_length Complete UTF-8 byte length up to 16 KiB.
     * @param digest Complete object SHA-256.
     * @return Admission result.
     */
    constexpr text_result submit_object(
      const std::uint64_t request_id,
      const std::uint32_t input_generation,
      const std::uint64_t preceding_edge_id,
      const std::uint64_t object_id,
      const std::uint32_t object_length,
      const std::array<std::uint8_t, 32> &digest
    ) noexcept {
      if (input_generation == 0 || input_generation != input_generation_) {
        return text_result::invalid_generation;
      }
      if (request_id == 0 || object_id == 0 || object_length == 0 || object_length > MaxTextBytes) {
        return text_result::invalid_object;
      }
      entry *free_entry = nullptr;
      for (auto &candidate : entries_) {
        if (candidate.occupied && candidate.request_id == request_id) {
          return candidate.input_generation == input_generation && candidate.preceding_edge_id == preceding_edge_id &&
                     !candidate.inline_form && candidate.object_id == object_id && candidate.object_length == object_length &&
                     candidate.object_digest == digest ?
                   text_result::duplicate :
                   text_result::conflicting_request;
        }
        if (!candidate.occupied && free_entry == nullptr) {
          free_entry = &candidate;
        }
      }
      if (free_entry == nullptr) {
        return text_result::full;
      }
      free_entry->request_id = request_id;
      free_entry->input_generation = input_generation;
      free_entry->preceding_edge_id = preceding_edge_id;
      free_entry->object_id = object_id;
      free_entry->object_length = object_length;
      free_entry->object_digest = digest;
      free_entry->inline_form = false;
      free_entry->object_ready = false;
      free_entry->delivered = false;
      free_entry->occupied = true;
      return text_result::accepted;
    }

    /**
     * @brief Mark a previously validated chunked text object complete.
     *
     * The object assembler must verify length, SHA-256, and UTF-8 before calling.
     *
     * @param request_id Retained text request.
     * @return Update result.
     */
    constexpr text_result mark_object_ready(const std::uint64_t request_id) noexcept {
      for (auto &entry : entries_) {
        if (entry.occupied && entry.request_id == request_id && !entry.inline_form) {
          entry.object_ready = true;
          return text_result::accepted;
        }
      }
      return text_result::not_found;
    }

    /**
     * @brief Deliver every ready text request exactly once without blocking real-time state.
     *
     * @tparam Apply Callable accepting `const text_delivery &` and returning `bool`.
     * @param applied_edge_watermark Greatest contiguously applied physical edge.
     * @param apply Text injection callback.
     * @return Number of newly delivered requests.
     */
    template<class Apply>
    constexpr std::size_t drain_ready(
      const std::uint64_t applied_edge_watermark,
      Apply &&apply
    ) noexcept(noexcept(std::invoke(apply, std::declval<const text_delivery &>()))) {
      std::size_t count = 0;
      for (auto &entry : entries_) {
        if (!entry.occupied || entry.delivered || !entry.object_ready || entry.preceding_edge_id > applied_edge_watermark) {
          continue;
        }
        const text_delivery delivery {
          .request_id = entry.request_id,
          .input_generation = entry.input_generation,
          .preceding_edge_id = entry.preceding_edge_id,
          .inline_utf8 = entry.inline_form ? std::span<const std::uint8_t>(entry.text).first(entry.text_length) :
                                             std::span<const std::uint8_t> {},
          .object_id = entry.object_id,
          .object_length = entry.object_length,
          .object_digest = entry.object_digest,
        };
        if (std::invoke(apply, std::as_const(delivery))) {
          entry.delivered = true;
          ++count;
        }
      }
      return count;
    }

    /**
     * @brief Retire delivered request metadata after the control response cache owns idempotence.
     *
     * @param request_id Delivered request ID.
     * @return Retirement result.
     */
    constexpr text_result retire(const std::uint64_t request_id) noexcept {
      for (auto &entry : entries_) {
        if (entry.occupied && entry.request_id == request_id) {
          if (!entry.delivered) {
            return text_result::conflicting_request;
          }
          entry.occupied = false;
          return text_result::accepted;
        }
      }
      return text_result::not_found;
    }

    /**
     * @brief Validate a complete UTF-8 byte string as Unicode scalar sequences.
     *
     * Surrogates, overlong forms, invalid continuations, and values above U+10FFFF are rejected.
     *
     * @param bytes Candidate UTF-8 bytes.
     * @return `true` only for a complete valid scalar sequence.
     */
    [[nodiscard]] static constexpr bool valid_utf8(const std::span<const std::uint8_t> bytes) noexcept {
      std::size_t index = 0;
      while (index < bytes.size()) {
        const auto first = bytes[index++];
        if (first <= 0x7fU) {
          continue;
        }
        std::uint32_t scalar = 0;
        std::size_t continuations = 0;
        std::uint32_t minimum = 0;
        if (first >= 0xc2U && first <= 0xdfU) {
          scalar = first & 0x1fU;
          continuations = 1;
          minimum = 0x80U;
        } else if (first >= 0xe0U && first <= 0xefU) {
          scalar = first & 0x0fU;
          continuations = 2;
          minimum = 0x800U;
        } else if (first >= 0xf0U && first <= 0xf4U) {
          scalar = first & 0x07U;
          continuations = 3;
          minimum = 0x10000U;
        } else {
          return false;
        }
        if (continuations > bytes.size() - index) {
          return false;
        }
        for (std::size_t continuation = 0; continuation < continuations; ++continuation) {
          const auto value = bytes[index++];
          if ((value & 0xc0U) != 0x80U) {
            return false;
          }
          scalar = (scalar << 6U) | (value & 0x3fU);
        }
        if (scalar < minimum || scalar > 0x10ffffU || (scalar >= 0xd800U && scalar <= 0xdfffU)) {
          return false;
        }
      }
      return true;
    }

  private:
    /** @brief One retained inline or chunked text control request. */
    struct entry {
      std::array<std::uint8_t, MaxTextBytes> text {};  ///< Fixed inline UTF-8 storage.
      std::array<std::uint8_t, 32> object_digest {};  ///< Chunked object digest.
      std::uint64_t request_id = 0;  ///< Idempotent request identifier.
      std::uint64_t preceding_edge_id = 0;  ///< Required edge barrier.
      std::uint64_t object_id = 0;  ///< Chunked object identifier.
      std::uint32_t input_generation = 0;  ///< Authority generation.
      std::uint32_t object_length = 0;  ///< Chunked object byte length.
      std::uint16_t text_length = 0;  ///< Inline text byte length.
      bool inline_form = false;  ///< Whether `text` rather than object metadata is authoritative.
      bool object_ready = false;  ///< Whether inline/object bytes have fully validated.
      bool delivered = false;  ///< Whether platform text injection completed once.
      bool occupied = false;  ///< Whether this slot retains a request.
    };

    std::array<entry, Capacity> entries_ {};  ///< Fixed pending/delivered request table.
    std::uint32_t input_generation_ = 0;  ///< Active authority generation.
  };
}  // namespace lumen::lsp::input_plane
