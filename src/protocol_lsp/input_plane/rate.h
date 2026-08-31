/**
 * @file src/protocol_lsp/input_plane/rate.h
 * @brief Exact LSP/1 input wire-budget accounting and hot-plug rate negotiation.
 */

#pragma once

#include "wire.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace lumen::lsp::input_plane {
  /** @brief LSP/1 aggregate client-to-host input wire budget in bits per second. */
  inline constexpr std::uint64_t maximum_input_wire_bits_per_second = 32'000'000;

  /** @brief Mandatory supported pointer network-report rate. */
  inline constexpr std::uint32_t mandatory_pointer_rate = 1'000;

  /** @brief Competition target pointer network-report rate. */
  inline constexpr std::uint32_t competition_pointer_rate = 8'000;

  /** @brief Largest kind payload fitting the initial 1,200-byte UDP payload after RTP/input/SRTP overhead. */
  inline constexpr std::uint32_t maximum_safe_kind_payload_bytes =
    1'200U - 12U - static_cast<std::uint32_t>(common_header_size) - 16U;

  /** @brief Network-layer header family used for exact input accounting. */
  enum class ip_family : std::uint8_t {
    ipv4,  ///< Twenty-byte base IPv4 header.
    ipv6,  ///< Forty-byte base IPv6 header.
  };

  /** @brief Independently negotiated replaceable input report classes. */
  enum class rate_class : std::uint8_t {
    pointer_motion,  ///< Pointer cumulative/latest state.
    controller_state,  ///< Controller sticks, triggers, battery, and latest state.
    controller_sensor,  ///< Gyro or accelerometer samples.
    reconciliation,  ///< Core or device-state safety refresh.
  };

  /** @brief Supported inclusive report-rate range for one input class. */
  struct rate_range {
    std::uint32_t minimum = 0;  ///< Minimum reports per second.
    std::uint32_t maximum = 0;  ///< Maximum reports per second.
  };

  /**
   * @brief Return the frozen LSP/1 rate range for one replaceable input class.
   *
   * @param input_class Negotiated input class.
   * @return Inclusive supported range.
   */
  [[nodiscard]] constexpr rate_range supported_rate_range(const rate_class input_class) noexcept {
    switch (input_class) {
      case rate_class::pointer_motion:
        return {.minimum = 125, .maximum = 16'000};
      case rate_class::controller_state:
        return {.minimum = 125, .maximum = 2'000};
      case rate_class::controller_sensor:
        return {.minimum = 125, .maximum = 4'000};
      case rate_class::reconciliation:
        return {.minimum = 50, .maximum = 1'000};
    }
    return {};
  }

  /**
   * @brief Return the authenticated-response waiting rate for a hot-plugged device.
   *
   * @param input_class Input stream class.
   * @return Safe reports per second before final rate selection.
   */
  [[nodiscard]] constexpr std::uint32_t hotplug_safe_rate(const rate_class input_class) noexcept {
    switch (input_class) {
      case rate_class::pointer_motion:
        return 1'000;
      case rate_class::controller_state:
      case rate_class::controller_sensor:
        return 250;
      case rate_class::reconciliation:
        return 50;
    }
    return 0;
  }

  /**
   * @brief Return complete on-wire bytes for one LSP input report.
   *
   * Accounting includes base IP, UDP, fixed RTP, the 40-byte LSP input header,
   * the kind payload, and the 16-byte AEAD-GCM SRTP tag.
   *
   * @param family IPv4 or IPv6 base header.
   * @param kind_payload_bytes Bytes after the LSP input common header.
   * @return Exact IP-layer bytes, or zero on size overflow.
   */
  [[nodiscard]] constexpr std::uint32_t wire_bytes_per_report(
    const ip_family family,
    const std::uint32_t kind_payload_bytes
  ) noexcept {
    constexpr std::uint32_t udp_header = 8;
    constexpr std::uint32_t rtp_header = 12;
    constexpr std::uint32_t srtp_tag = 16;
    const std::uint32_t ip_header = family == ip_family::ipv4 ? 20 : 40;
    constexpr auto fixed_without_ip = udp_header + rtp_header + common_header_size + srtp_tag;
    if (kind_payload_bytes > std::numeric_limits<std::uint32_t>::max() - ip_header - fixed_without_ip) {
      return 0;
    }
    return ip_header + fixed_without_ip + kind_payload_bytes;
  }

  /**
   * @brief Calculate exact report-stream wire rate with overflow detection.
   *
   * @param family IPv4 or IPv6.
   * @param kind_payload_bytes Kind payload bytes.
   * @param reports_per_second Selected report rate.
   * @return Exact wire bits per second, or zero for invalid/overflow input.
   */
  [[nodiscard]] constexpr std::uint64_t wire_bits_per_second(
    const ip_family family,
    const std::uint32_t kind_payload_bytes,
    const std::uint32_t reports_per_second
  ) noexcept {
    const auto bytes = wire_bytes_per_report(family, kind_payload_bytes);
    if (bytes == 0 || reports_per_second == 0 ||
        reports_per_second > std::numeric_limits<std::uint64_t>::max() / (std::uint64_t {8} * bytes)) {
      return 0;
    }
    return std::uint64_t {8} * bytes * reports_per_second;
  }

  /** @brief Stable key for one independently negotiated per-device report stream. */
  struct rate_key {
    rate_class input_class = rate_class::pointer_motion;  ///< Independent input report class.
    device_type device = device_type::pointer;  ///< Device class.
    sensor_type sensor = sensor_type::gyroscope;  ///< Sensor stream when applicable.
    std::uint32_t device_id = 0;  ///< Nonzero per-class device identifier.
    std::uint32_t instance_generation = 0;  ///< Nonzero hot-plug instance generation.

    /** @brief Compare every stream key component. */
    [[nodiscard]] bool operator==(const rate_key &) const noexcept = default;
  };

  /** @brief Authenticated input-rate request fields needed by the native core. */
  struct rate_request {
    std::uint32_t input_generation = 0;  ///< Exact active input authority generation.
    rate_key key {};  ///< Per-device stream and instance.
    std::uint32_t observed_capture_rate = 0;  ///< Measured local callbacks per second.
    std::uint32_t minimum_rate = 0;  ///< Client minimum acceptable network rate.
    std::uint32_t preferred_rate = 0;  ///< Client preferred network rate.
    std::uint32_t maximum_rate = 0;  ///< Client maximum supported network rate.
    std::uint32_t worst_case_payload_bytes = 0;  ///< Worst-case kind payload for exact accounting.
  };

  /** @brief One selected stream rate and its exact aggregate-budget cost. */
  struct rate_selection {
    rate_key key {};  ///< Selected per-device stream.
    std::uint32_t reports_per_second = 0;  ///< Selected rate.
    std::uint64_t wire_bits_per_second = 0;  ///< Exact steady-state budget reservation.
    bool authenticated = false;  ///< Whether `INPUT_RATE_RESPONSE` selected the rate.
  };

  /** @brief Device generation lifecycle result. */
  enum class device_generation_result : std::uint8_t {
    accepted,  ///< Arrival or removal advanced state.
    duplicate,  ///< Same active arrival or already-removed generation repeated.
    stale_generation,  ///< Generation is older than or equal to the retired generation.
    generation_conflict,  ///< A different generation arrived before active removal.
    invalid,  ///< Type, ID, or generation is zero/unknown.
    full,  ///< Fixed device registry has no free slot.
  };

  /**
   * @brief Fixed device hot-plug registry retaining generation history after removal.
   *
   * @tparam Capacity Maximum independently identified devices.
   */
  template<std::size_t Capacity = 64>
  class device_generation_registry {
  public:
    static_assert(Capacity > 0, "device generation registry must be nonzero");

    /**
     * @brief Admit one device arrival generation.
     *
     * @param type Device class.
     * @param device_id Nonzero per-class device identifier.
     * @param generation Nonzero, strictly advancing instance generation after removal.
     * @return Arrival result.
     */
    constexpr device_generation_result arrive(
      const device_type type,
      const std::uint32_t device_id,
      const std::uint32_t generation
    ) noexcept {
      if (!valid_device_type(type) || device_id == 0 || generation == 0) {
        return device_generation_result::invalid;
      }
      device_entry *free_entry = nullptr;
      for (auto &entry : entries_) {
        if (entry.occupied && entry.type == type && entry.device_id == device_id) {
          if (entry.active) {
            return entry.generation == generation ? device_generation_result::duplicate :
                                                    device_generation_result::generation_conflict;
          }
          if (generation <= entry.generation) {
            return generation == entry.generation ? device_generation_result::duplicate :
                                                    device_generation_result::stale_generation;
          }
          entry.generation = generation;
          entry.active = true;
          return device_generation_result::accepted;
        }
        if (!entry.occupied && free_entry == nullptr) {
          free_entry = &entry;
        }
      }
      if (free_entry == nullptr) {
        return device_generation_result::full;
      }
      *free_entry = {
        .type = type,
        .device_id = device_id,
        .generation = generation,
        .active = true,
        .occupied = true,
      };
      return device_generation_result::accepted;
    }

    /**
     * @brief Retire exactly one active device generation.
     *
     * @param type Device class.
     * @param device_id Device identifier.
     * @param generation Exact active generation.
     * @return Removal result.
     */
    constexpr device_generation_result remove(
      const device_type type,
      const std::uint32_t device_id,
      const std::uint32_t generation
    ) noexcept {
      if (!valid_device_type(type) || device_id == 0 || generation == 0) {
        return device_generation_result::invalid;
      }
      for (auto &entry : entries_) {
        if (!entry.occupied || entry.type != type || entry.device_id != device_id) {
          continue;
        }
        if (generation != entry.generation) {
          return device_generation_result::stale_generation;
        }
        if (!entry.active) {
          return device_generation_result::duplicate;
        }
        entry.active = false;
        return device_generation_result::accepted;
      }
      return device_generation_result::stale_generation;
    }

    /**
     * @brief Test whether an exact device instance is active.
     *
     * @param type Device class.
     * @param device_id Device identifier.
     * @param generation Instance generation.
     * @return `true` only for the live exact generation.
     */
    [[nodiscard]] constexpr bool active(
      const device_type type,
      const std::uint32_t device_id,
      const std::uint32_t generation
    ) const noexcept {
      for (const auto &entry : entries_) {
        if (entry.occupied && entry.active && entry.type == type && entry.device_id == device_id &&
            entry.generation == generation) {
          return true;
        }
      }
      return false;
    }

  private:
    /** @brief One active or retired device generation record. */
    struct device_entry {
      device_type type = device_type::keyboard;  ///< Device class.
      std::uint32_t device_id = 0;  ///< Stable per-class device identifier.
      std::uint32_t generation = 0;  ///< Greatest admitted instance generation.
      bool active = false;  ///< Whether callbacks/state are currently authoritative.
      bool occupied = false;  ///< Whether this slot retains generation history.
    };

    std::array<device_entry, Capacity> entries_ {};  ///< Fixed generation registry.
  };

  /** @brief Input rate request/selection result. */
  enum class rate_result : std::uint8_t {
    selected,  ///< Requested or provisional rate was admitted exactly.
    stale_generation,  ///< Input or device generation is not authoritative.
    invalid_range,  ///< Offered min/preferred/max values violate class bounds.
    invalid_payload,  ///< Worst-case payload cannot be accounted safely.
    insufficient_capacity,  ///< Required minimum does not fit the remaining 32-Mbps budget.
    full,  ///< Fixed stream table has no free slot.
    not_found,  ///< Explicit lowering named no stream.
  };

  /**
   * @brief Bounded per-device rate manager with exact aggregate wire accounting.
   *
   * @tparam DeviceCapacity Maximum device IDs with retained generation history.
   * @tparam StreamCapacity Maximum independently rated state/sensor streams.
   */
  template<std::size_t DeviceCapacity = 64, std::size_t StreamCapacity = 64>
  class rate_manager {
  public:
    static_assert(StreamCapacity > 0, "input rate stream capacity must be nonzero");

    /**
     * @brief Begin a fresh input generation and clear all rate reservations.
     *
     * @param input_generation Nonzero authority generation.
     * @param family Negotiated IP family used for accounting.
     * @param budget_bits_per_second Operator/START budget not exceeding 32 Mbps.
     * @return `true` when parameters are valid.
     */
    constexpr bool reset(
      const std::uint32_t input_generation,
      const ip_family family,
      const std::uint64_t budget_bits_per_second = maximum_input_wire_bits_per_second
    ) noexcept {
      if (input_generation == 0 || budget_bits_per_second == 0 ||
          budget_bits_per_second > maximum_input_wire_bits_per_second) {
        return false;
      }
      for (auto &entry : streams_) {
        entry.occupied = false;
      }
      input_generation_ = input_generation;
      family_ = family;
      budget_bits_per_second_ = budget_bits_per_second;
      reserved_bits_per_second_ = 0;
      devices_ = {};
      return true;
    }

    /**
     * @brief Admit one hot-plugged device generation.
     *
     * @param type Device class.
     * @param device_id Device identifier.
     * @param generation New instance generation.
     * @return Generation result.
     */
    constexpr device_generation_result arrive(
      const device_type type,
      const std::uint32_t device_id,
      const std::uint32_t generation
    ) noexcept {
      return devices_.arrive(type, device_id, generation);
    }

    /**
     * @brief Retire a device generation and all of its replaceable rate reservations.
     *
     * Lifecycle release/cancel edges must be enqueued before calling this method.
     *
     * @param type Device class.
     * @param device_id Device identifier.
     * @param generation Exact active generation.
     * @return Generation result.
     */
    constexpr device_generation_result remove(
      const device_type type,
      const std::uint32_t device_id,
      const std::uint32_t generation
    ) noexcept {
      const auto result = devices_.remove(type, device_id, generation);
      if (result != device_generation_result::accepted) {
        return result;
      }
      for (auto &entry : streams_) {
        if (entry.occupied && entry.selection.key.device == type && entry.selection.key.device_id == device_id &&
            entry.selection.key.instance_generation == generation) {
          reserved_bits_per_second_ -= entry.selection.wire_bits_per_second;
          entry.occupied = false;
        }
      }
      return result;
    }

    /**
     * @brief Install the provisional safe rate used while an authenticated response is pending.
     *
     * @param request Authenticated request metadata and exact worst-case size.
     * @param selection Selected provisional rate destination.
     * @return Admission result.
     */
    constexpr rate_result begin_hotplug(const rate_request &request, rate_selection &selection) noexcept {
      const auto safe = hotplug_safe_rate(request.key.input_class);
      return select_exact(request, safe, false, selection);
    }

    /**
     * @brief Select the highest preferred authenticated rate that fits capabilities and budget.
     *
     * @param request Authenticated per-device request.
     * @param host_apply_capacity Measured host apply reports per second.
     * @param selection Selected final rate destination.
     * @return Selection result.
     */
    constexpr rate_result authorize(
      const rate_request &request,
      const std::uint32_t host_apply_capacity,
      rate_selection &selection
    ) noexcept {
      const auto supported = supported_rate_range(request.key.input_class);
      if (!valid_request(request, supported) || host_apply_capacity < supported.minimum) {
        return rate_result::invalid_range;
      }
      const auto maximum = std::min({request.maximum_rate, supported.maximum, host_apply_capacity});
      const auto minimum = std::max(request.minimum_rate, supported.minimum);
      if (maximum < minimum) {
        return rate_result::invalid_range;
      }
      const auto preferred = std::clamp(request.preferred_rate, minimum, maximum);
      const auto packet_bits = wire_bits_per_second(family_, request.worst_case_payload_bytes, 1);
      if (packet_bits == 0) {
        return rate_result::invalid_payload;
      }
      const auto *existing = find_stream(request.key);
      const auto reclaimed = existing == nullptr ? 0 : existing->selection.wire_bits_per_second;
      const auto available = budget_bits_per_second_ - reserved_bits_per_second_ + reclaimed;
      const auto fitting_rate = std::min<std::uint64_t>(preferred, available / packet_bits);
      if (fitting_rate < minimum) {
        return rate_result::insufficient_capacity;
      }
      return select_exact(request, static_cast<std::uint32_t>(fitting_rate), true, selection);
    }

    /**
     * @brief Explicitly lower one replaceable stream without changing its generation.
     *
     * @param key Exact stream key.
     * @param reports_per_second Lower selected rate within the class range.
     * @return Update result.
     */
    constexpr rate_result lower(const rate_key &key, const std::uint32_t reports_per_second) noexcept {
      auto *entry = find_stream(key);
      if (entry == nullptr) {
        return rate_result::not_found;
      }
      const auto supported = supported_rate_range(key.input_class);
      if (reports_per_second < supported.minimum || reports_per_second > entry->selection.reports_per_second) {
        return rate_result::invalid_range;
      }
      const auto bits = wire_bits_per_second(family_, entry->payload_bytes, reports_per_second);
      if (bits == 0) {
        return rate_result::invalid_payload;
      }
      reserved_bits_per_second_ -= entry->selection.wire_bits_per_second;
      entry->selection.reports_per_second = reports_per_second;
      entry->selection.wire_bits_per_second = bits;
      reserved_bits_per_second_ += bits;
      return rate_result::selected;
    }

    /** @brief Return exact reserved input wire bits per second. */
    [[nodiscard]] constexpr std::uint64_t reserved_bits_per_second() const noexcept {
      return reserved_bits_per_second_;
    }

    /** @brief Return the configured aggregate budget, never above 32 Mbps. */
    [[nodiscard]] constexpr std::uint64_t budget_bits_per_second() const noexcept {
      return budget_bits_per_second_;
    }

    /**
     * @brief Find the selected state of one exact stream.
     *
     * @param key Exact stream key.
     * @param output Selection destination.
     * @return `true` when the stream exists.
     */
    [[nodiscard]] constexpr bool selection(const rate_key &key, rate_selection &output) const noexcept {
      const auto *entry = find_stream(key);
      if (entry == nullptr) {
        return false;
      }
      output = entry->selection;
      return true;
    }

  private:
    /** @brief One fixed selected report stream. */
    struct stream_entry {
      rate_selection selection {};  ///< Current provisional/authenticated selection.
      std::uint32_t payload_bytes = 0;  ///< Worst-case kind payload used for accounting.
      bool occupied = false;  ///< Whether this stream consumes budget.
    };

    /**
     * @brief Check immutable authenticated request fields and class range.
     *
     * @param request Candidate request.
     * @param supported Frozen class range.
     * @return `true` when the request is structurally valid.
     */
    [[nodiscard]] constexpr bool valid_request(const rate_request &request, const rate_range supported) const noexcept {
      const bool matching_class =
        (request.key.input_class == rate_class::pointer_motion && request.key.device == device_type::pointer) ||
        ((request.key.input_class == rate_class::controller_state ||
          request.key.input_class == rate_class::controller_sensor) &&
         request.key.device == device_type::controller) ||
        request.key.input_class == rate_class::reconciliation;
      const bool matching_sensor = request.key.input_class != rate_class::controller_sensor || valid_sensor_type(request.key.sensor);
      return request.input_generation == input_generation_ && valid_device_type(request.key.device) && matching_class && matching_sensor &&
             request.key.device_id != 0 && request.key.instance_generation != 0 &&
             devices_.active(request.key.device, request.key.device_id, request.key.instance_generation) &&
             request.minimum_rate >= supported.minimum && request.minimum_rate <= request.preferred_rate &&
             request.preferred_rate <= request.maximum_rate && request.maximum_rate <= supported.maximum &&
             request.worst_case_payload_bytes != 0 && request.worst_case_payload_bytes <= maximum_safe_kind_payload_bytes;
    }

    /**
     * @brief Store one exact rate after all policy calculations.
     *
     * @param request Rate request.
     * @param reports_per_second Exact selected rate.
     * @param authenticated Whether an authenticated response selected it.
     * @param output Selection destination.
     * @return Storage result.
     */
    constexpr rate_result select_exact(
      const rate_request &request,
      const std::uint32_t reports_per_second,
      const bool authenticated,
      rate_selection &output
    ) noexcept {
      const auto supported = supported_rate_range(request.key.input_class);
      if (!valid_request(request, supported) || reports_per_second < supported.minimum ||
          reports_per_second > request.maximum_rate) {
        return rate_result::invalid_range;
      }
      const auto bits = wire_bits_per_second(family_, request.worst_case_payload_bytes, reports_per_second);
      if (bits == 0) {
        return rate_result::invalid_payload;
      }
      auto *entry = find_stream(request.key);
      const auto reclaimed = entry == nullptr ? 0 : entry->selection.wire_bits_per_second;
      if (bits > budget_bits_per_second_ - reserved_bits_per_second_ + reclaimed) {
        return rate_result::insufficient_capacity;
      }
      if (entry == nullptr) {
        for (auto &candidate : streams_) {
          if (!candidate.occupied) {
            entry = &candidate;
            break;
          }
        }
      }
      if (entry == nullptr) {
        return rate_result::full;
      }
      reserved_bits_per_second_ -= reclaimed;
      entry->selection = {
        .key = request.key,
        .reports_per_second = reports_per_second,
        .wire_bits_per_second = bits,
        .authenticated = authenticated,
      };
      entry->payload_bytes = request.worst_case_payload_bytes;
      entry->occupied = true;
      reserved_bits_per_second_ += bits;
      output = entry->selection;
      return rate_result::selected;
    }

    /** @brief Find a mutable selected stream by exact key. */
    [[nodiscard]] constexpr stream_entry *find_stream(const rate_key &key) noexcept {
      for (auto &entry : streams_) {
        if (entry.occupied && entry.selection.key == key) {
          return &entry;
        }
      }
      return nullptr;
    }

    /** @brief Find an immutable selected stream by exact key. */
    [[nodiscard]] constexpr const stream_entry *find_stream(const rate_key &key) const noexcept {
      for (const auto &entry : streams_) {
        if (entry.occupied && entry.selection.key == key) {
          return &entry;
        }
      }
      return nullptr;
    }

    device_generation_registry<DeviceCapacity> devices_ {};  ///< Hot-plug generation authority.
    std::array<stream_entry, StreamCapacity> streams_ {};  ///< Fixed per-device rate table.
    std::uint32_t input_generation_ = 0;  ///< Active input authority generation.
    ip_family family_ = ip_family::ipv4;  ///< Exact negotiated IP accounting family.
    std::uint64_t budget_bits_per_second_ = maximum_input_wire_bits_per_second;  ///< Configured budget ceiling.
    std::uint64_t reserved_bits_per_second_ = 0;  ///< Exact current reservations.
  };
}  // namespace lumen::lsp::input_plane
