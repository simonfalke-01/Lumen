/**
 * @file src/platform/windows/virtual_display_driver/LumenHdrModePolicy.h
 * @brief Portable standard HDR EDID and descriptor-mode policy.
 */
#ifndef LUMEN_PLATFORM_WINDOWS_HDR_MODE_POLICY_H
#define LUMEN_PLATFORM_WINDOWS_HDR_MODE_POLICY_H

#include "LumenVirtualDisplayProtocol.h"

#include <array>
#include <cstddef>
#include <cstdint>

namespace lumen::vdd::hdr {
  /** Standards-valid EDID 1.4 plus CTA-861 PQ/BT.2020 data and one 1080p60 baseline timing. */
  inline constexpr std::array<std::uint8_t, 256> edid {
    0x00,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0x00,
    0x32,
    0xAD,
    0x02,
    0x00,
    0x01,
    0x00,
    0x00,
    0x00,
    0x01,
    0x24,
    0x01,
    0x04,
    0xB5,
    0x34,
    0x1D,
    0x78,
    0x02,
    0x78,
    0xB1,
    0xB5,
    0x4A,
    0x2B,
    0xCC,
    0x21,
    0x0B,
    0x50,
    0x54,
    0x00,
    0x00,
    0x00,
    0x01,
    0x01,
    0x01,
    0x01,
    0x01,
    0x01,
    0x01,
    0x01,
    0x01,
    0x01,
    0x01,
    0x01,
    0x01,
    0x01,
    0x01,
    0x01,
    0x02,
    0x3A,
    0x80,
    0x18,
    0x71,
    0x38,
    0x2D,
    0x40,
    0x58,
    0x2C,
    0x45,
    0x00,
    0xFD,
    0x1E,
    0x11,
    0x00,
    0x00,
    0x1E,
    0x00,
    0x00,
    0x00,
    0xFC,
    0x00,
    0x4C,
    0x75,
    0x6D,
    0x65,
    0x6E,
    0x20,
    0x48,
    0x44,
    0x52,
    0x0A,
    0x20,
    0x20,
    0x20,
    0x00,
    0x00,
    0x00,
    0xFF,
    0x00,
    0x4C,
    0x55,
    0x4D,
    0x48,
    0x44,
    0x52,
    0x30,
    0x30,
    0x30,
    0x31,
    0x0A,
    0x20,
    0x20,
    0x00,
    0x00,
    0x00,
    0x10,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x01,
    0x32,
    0x02,
    0x03,
    0x11,
    0x00,
    0x41,
    0x90,
    0xE3,
    0x05,
    0x80,
    0x00,
    0xE6,
    0x06,
    0x04,
    0x01,
    0x8A,
    0x60,
    0x06,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0xD0,
  };

  /** Ordinary CTA VIC 16 baseline mode carried by the static EDID. */
  inline constexpr LUMEN_VDD_MODE baseline_mode {
    1920,
    1080,
    60,
    1,
    LUMEN_VDD_DYNAMIC_RANGE_HDR10,
    10,
    LUMEN_VDD_POLICY_LATENCY,
    LUMEN_VDD_FIDELITY_LOSSLESS,
  };

  /** Return whether two fixed ABI modes are identical. */
  [[nodiscard]] constexpr bool modes_equal(const LUMEN_VDD_MODE &left, const LUMEN_VDD_MODE &right) noexcept {
    return left.width == right.width && left.height == right.height &&
           static_cast<std::uint64_t>(left.refresh_numerator) * right.refresh_denominator ==
             static_cast<std::uint64_t>(right.refresh_numerator) * left.refresh_denominator &&
           left.dynamic_range == right.dynamic_range && left.bits_per_channel == right.bits_per_channel;
  }

  /** Return whether both 128-byte EDID blocks have a zero modulo-256 checksum. */
  [[nodiscard]] constexpr bool valid_edid_checksums() noexcept {
    for (std::size_t block = 0; block < 2; ++block) {
      unsigned int sum = 0;
      for (std::size_t byte = 0; byte < 128; ++byte) {
        sum += edid[block * 128 + byte];
      }
      if ((sum & 0xFFU) != 0) {
        return false;
      }
    }
    return true;
  }

  /** Return whether the CTA collection advertises PQ HDR static metadata and BT.2020 RGB. */
  [[nodiscard]] constexpr bool has_hdr10_bt2020_cta() noexcept {
    bool bt2020_rgb = false;
    bool pq_static_metadata = false;
    const std::size_t cta = 128;
    const std::size_t data_end = cta + edid[cta + 2];
    for (std::size_t index = cta + 4; index < data_end;) {
      const auto header = edid[index];
      const std::size_t length = header & 0x1FU;
      if (index + length >= data_end) {
        return false;
      }
      if ((header >> 5U) == 7U && length >= 3) {
        const auto extended_tag = edid[index + 1];
        if (extended_tag == 0x05U) {
          bt2020_rgb = (edid[index + 2] & 0x80U) != 0;
        } else if (extended_tag == 0x06U) {
          pq_static_metadata = (edid[index + 2] & 0x04U) != 0 && (edid[index + 3] & 0x01U) != 0;
        }
      }
      index += length + 1;
    }
    return bt2020_rgb && pq_static_metadata;
  }

  /** Return whether the CTA collection contains any vendor-specific data block. */
  [[nodiscard]] constexpr bool contains_vendor_specific_data_block() noexcept {
    const std::size_t cta = 128;
    const std::size_t data_end = cta + edid[cta + 2];
    for (std::size_t index = cta + 4; index < data_end;) {
      const auto header = edid[index];
      const std::size_t length = header & 0x1FU;
      if (index + length >= data_end) {
        return false;
      }
      if ((header >> 5U) == 3U) {
        return true;
      }
      index += length + 1;
    }
    return false;
  }

  /** Baseline plus the exact prepared mode returned during monitor-description parsing. */
  struct descriptor_mode_set_t {
    std::array<LUMEN_VDD_MODE, 2> modes;  ///< Baseline followed by an optional exact driver mode.
    std::size_t count;  ///< One for the baseline or two when the exact mode differs.
    std::size_t preferred_index;  ///< Exact mode when present, otherwise the baseline.
  };

  /** Return the self-consistent descriptor mode set for one immutable prepared mode. */
  [[nodiscard]] constexpr descriptor_mode_set_t descriptor_modes(const LUMEN_VDD_MODE &exact) noexcept {
    descriptor_mode_set_t output {{baseline_mode, {}}, 1, 0};
    if (!modes_equal(exact, baseline_mode)) {
      output.modes[1] = exact;
      output.count = 2;
      output.preferred_index = 1;
    }
    return output;
  }

  /** Return whether one resolved HDR10 metadata block has valid chromaticity and luminance relationships. */
  [[nodiscard]] constexpr bool valid_hdr10_metadata(const LUMEN_VDD_HDR10_METADATA &metadata) noexcept {
    const auto valid_chromaticity = [](const std::uint16_t coordinates[2]) constexpr {
      return coordinates[0] != 0 && coordinates[1] != 0 &&
             coordinates[0] <= 50000 && coordinates[1] <= 50000;
    };
    return valid_chromaticity(metadata.red_primary) && valid_chromaticity(metadata.green_primary) &&
           valid_chromaticity(metadata.blue_primary) && valid_chromaticity(metadata.white_point) &&
           metadata.maximum_mastering_luminance != 0 &&
           metadata.minimum_mastering_luminance <=
             static_cast<std::uint64_t>(metadata.maximum_mastering_luminance) * 10000ULL &&
           (metadata.maximum_content_light_level == 0 ||
            metadata.maximum_frame_average_light_level <= metadata.maximum_content_light_level);
  }

  static_assert(valid_edid_checksums(), "HDR EDID blocks must have valid checksums");
  static_assert(has_hdr10_bt2020_cta(), "HDR EDID must advertise PQ static metadata and BT.2020 RGB");
  static_assert(!contains_vendor_specific_data_block(), "HDR EDID must not carry private vendor mode data");
}  // namespace lumen::vdd::hdr

#endif  // LUMEN_PLATFORM_WINDOWS_HDR_MODE_POLICY_H
