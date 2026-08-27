/**
 * @file src/platform/windows/virtual_display_frame.cpp
 * @brief Pure validation for the production VDD direct-frame ABI.
 */

// standard includes
#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstring>
#include <limits>

// local includes
#include "virtual_display_frame.h"

namespace platf::virtual_display {
#if !defined(_WIN32)
  namespace {
    std::atomic_bool portable_runtime_quarantined {false};  ///< Mirrors sticky host behavior in portable tests.
  }
#endif
  bool valid_direct_frame_adapter_binding(
    const bool nvenc_active,
    const direct_frame_adapter_identity_t &imported,
    const std::optional<direct_frame_adapter_identity_t> &encoder_probe
  ) noexcept {
    constexpr std::uint32_t nvidia_vendor_id = 0x10de;
    return nvenc_active && imported.adapter_luid != 0 && imported.vendor_id == nvidia_vendor_id &&
           imported.device_id != 0 && imported.driver_version != 0 && encoder_probe &&
           imported == *encoder_probe;
  }

  std::shared_ptr<const color_transform_t> color_transform_cache_t::find(
    const std::uint64_t generation,
    const std::uint64_t version
  ) const noexcept {
    if (current_ && current_->generation == generation && current_->version == version) {
      return current_;
    }
    if (previous_ && previous_->generation == generation && previous_->version == version) {
      return previous_;
    }
    return {};
  }

  bool color_transform_cache_t::commit(std::shared_ptr<const color_transform_t> transform) noexcept {
    if (!transform || transform->generation == 0 || transform->version == 0) {
      return false;
    }
    if (current_ && current_->generation != transform->generation) {
      clear();
    }
    if (current_ && current_->version == transform->version) {
      return true;
    }
    previous_ = std::move(current_);
    current_ = std::move(transform);
    return true;
  }

  void color_transform_cache_t::clear() noexcept {
    current_.reset();
    previous_.reset();
  }

  bool prepare_color_transform(color_transform_t &transform) noexcept {
    if (transform.generation == 0 || transform.version == 0) {
      return false;
    }
    if (transform.type == color_transform_type_e::default_) {
      return std::holds_alternative<std::monostate>(transform.payload);
    }
    if (transform.type == color_transform_type_e::rgb256x3x16) {
      return std::holds_alternative<color_transform_rgb256_t>(transform.payload);
    }
    if (transform.type != color_transform_type_e::colorspace_3x4 ||
        !std::holds_alternative<color_transform_3x4_t>(transform.payload)) {
      return false;
    }

    auto &payload = std::get<color_transform_3x4_t>(transform.payload);
    if (payload.matrix_enabled &&
        (!std::isfinite(payload.scalar_multiplier) ||
         !std::ranges::all_of(payload.color_matrix_3x4, [](const float value) {
           return std::isfinite(value);
         }))) {
      return false;
    }
    if (!payload.matrix_enabled) {
      payload.color_matrix_3x4.fill(0.0f);
      payload.scalar_multiplier = 1.0f;
    }
    if (payload.lut_enabled &&
        !std::ranges::all_of(payload.lookup_table_1d, [](const color_transform_rgb_t &entry) {
          return std::isfinite(entry.red) && std::isfinite(entry.green) && std::isfinite(entry.blue);
        })) {
      return false;
    }
    if (!payload.lut_enabled) {
      payload.lookup_table_1d.fill({});
    }
    if (!payload.matrix_enabled && !payload.lut_enabled) {
      transform.type = color_transform_type_e::default_;
      transform.payload = std::monostate {};
      return true;
    }

    constexpr std::array<float, 9> rec709_to_xyz {
      0.4123908f, 0.3575843f, 0.1804808f,
      0.2126390f, 0.7151687f, 0.0721923f,
      0.0193308f, 0.1191948f, 0.9505322f,
    };
    constexpr std::array<float, 9> xyz_to_rec709 {
      3.2409699f, -1.5373832f, -0.4986108f,
      -0.9692436f, 1.8759675f, 0.0415551f,
      0.0556301f, -0.2039770f, 1.0569715f,
    };
    constexpr std::array<float, 9> xyz_to_rec2020 {
      1.7166512f, -0.3556708f, -0.2533663f,
      -0.6666844f, 1.6164812f, 0.0157685f,
      0.0176399f, -0.0427706f, 0.9421031f,
    };
    const auto compose = [&](const std::array<float, 9> &xyz_to_wire, std::array<float, 12> &output) {
      std::array<float, 12> xyz_transform {
        1.0f, 0.0f, 0.0f, 0.0f,
        0.0f, 1.0f, 0.0f, 0.0f,
        0.0f, 0.0f, 1.0f, 0.0f,
      };
      if (payload.matrix_enabled) {
        xyz_transform = payload.color_matrix_3x4;
        for (auto &value : xyz_transform) {
          value *= payload.scalar_multiplier;
        }
      }
      for (std::size_t row = 0; row < 3; ++row) {
        for (std::size_t column = 0; column < 3; ++column) {
          float value = 0.0f;
          for (std::size_t xyz_output = 0; xyz_output < 3; ++xyz_output) {
            for (std::size_t xyz_input = 0; xyz_input < 3; ++xyz_input) {
              value += xyz_to_wire[row * 3 + xyz_output] *
                       xyz_transform[xyz_output * 4 + xyz_input] *
                       rec709_to_xyz[xyz_input * 3 + column];
            }
          }
          output[row * 4 + column] = value;
        }
        float offset = 0.0f;
        for (std::size_t xyz_output = 0; xyz_output < 3; ++xyz_output) {
          offset += xyz_to_wire[row * 3 + xyz_output] * xyz_transform[xyz_output * 4 + 3];
        }
        output[row * 4 + 3] = offset;
      }
    };
    compose(xyz_to_rec709, payload.wire_rec709_matrix_3x4);
    compose(xyz_to_rec2020, payload.wire_rec2020_matrix_3x4);
    return std::ranges::all_of(payload.wire_rec709_matrix_3x4, [](const float value) {
             return std::isfinite(value);
           }) &&
           std::ranges::all_of(payload.wire_rec2020_matrix_3x4, [](const float value) {
             return std::isfinite(value);
           });
  }

  namespace {
    bool valid_chromaticity(const std::array<std::uint16_t, 2> &point) noexcept {
      constexpr std::uint32_t normalized_one = 50'000U;
      return point[0] != 0 && point[1] != 0 &&
             point[0] <= normalized_one && point[1] <= normalized_one;
    }

    bool zero_hdr10_metadata(const frame_hdr10_metadata_t &metadata) noexcept {
      const frame_hdr10_metadata_t zero {};
      return std::memcmp(&metadata, &zero, sizeof(metadata)) == 0;
    }

    bool valid_hdr10_metadata(const frame_hdr10_metadata_t &metadata) noexcept {
      return valid_chromaticity(metadata.red_primary) &&
             valid_chromaticity(metadata.green_primary) &&
             valid_chromaticity(metadata.blue_primary) &&
             valid_chromaticity(metadata.white_point) &&
             metadata.red_primary != metadata.green_primary &&
             metadata.red_primary != metadata.blue_primary &&
             metadata.green_primary != metadata.blue_primary &&
             metadata.maximum_mastering_luminance != 0 &&
             static_cast<std::uint32_t>(metadata.minimum_mastering_luminance) <=
               static_cast<std::uint32_t>(metadata.maximum_mastering_luminance) * 10'000U &&
             (metadata.maximum_content_light_level == 0 ?
                metadata.maximum_frame_average_light_level == 0 :
                metadata.maximum_frame_average_light_level <= metadata.maximum_content_light_level);
    }
  }  // namespace

  bool valid_frame_color_metadata(
    const frame_color_metadata_t &metadata,
    const dynamic_range_e dynamic_range,
    const frame_format_e format
  ) noexcept {
    if (metadata.sdr_white_level_nits < 80 || metadata.sdr_white_level_nits > 480) {
      return false;
    }
    if (dynamic_range == dynamic_range_e::sdr) {
      return format == frame_format_e::bgra8 &&
             metadata.surface_color_space == frame_color_space_e::srgb &&
             metadata.hdr_metadata_type == hdr_metadata_type_e::none &&
             zero_hdr10_metadata(metadata.hdr10_metadata);
    }
    return format == frame_format_e::rgba16_float &&
           metadata.surface_color_space == frame_color_space_e::scrgb &&
           metadata.hdr_metadata_type != hdr_metadata_type_e::none &&
           metadata.hdr_metadata_type <= hdr_metadata_type_e::new_ &&
           valid_hdr10_metadata(metadata.hdr10_metadata);
  }

  bool valid_frame_resources(
    const frame_resources_t &resources,
    const std::uint64_t generation,
    const mode_t &mode
  ) noexcept {
    if (generation == 0 || resources.generation != generation ||
        resources.width != mode.width || resources.height != mode.height ||
        resources.dynamic_range != mode.dynamic_range ||
        (mode.dynamic_range == dynamic_range_e::hdr10 && resources.format != frame_format_e::rgba16_float) ||
        (mode.dynamic_range == dynamic_range_e::sdr && resources.format != frame_format_e::bgra8) ||
        resources.initial_color_transform_version == 0 ||
        !valid_frame_color_metadata(resources.initial_color_metadata, mode.dynamic_range, resources.format) ||
        resources.slot_count != direct_frame_slot_count) {
      return false;
    }

    std::array<std::uintptr_t, direct_frame_slot_count * 2> handles {};
    for (std::size_t slot = 0; slot < direct_frame_slot_count; ++slot) {
      if (resources.texture_handles[slot] == 0 || resources.fence_handles[slot] == 0) {
        return false;
      }
      handles[slot] = resources.texture_handles[slot];
      handles[direct_frame_slot_count + slot] = resources.fence_handles[slot];
    }
    std::ranges::sort(handles);
    return std::ranges::adjacent_find(handles) == handles.end();
  }

  bool valid_frame_descriptor(
    const frame_descriptor_t &frame,
    const frame_resources_t &resources
  ) noexcept {
    return frame.generation == resources.generation && frame.sequence != 0 &&
           frame.slot < direct_frame_slot_count && frame.slot < resources.slot_count &&
           frame.producer_fence_value != 0 && (frame.producer_fence_value & 1U) != 0 &&
           frame.producer_fence_value != std::numeric_limits<std::uint64_t>::max() &&
           frame.capture_qpc > 0 && frame.producer_signal_qpc >= frame.capture_qpc &&
           frame.color_transform_version != 0 &&
           valid_frame_color_metadata(
             frame.color_metadata,
             resources.dynamic_range,
             resources.format
           );
  }

#if !defined(_WIN32)
  std::shared_ptr<frame_source_t> make_system_frame_source(
    const stream_selection_t &,
    std::chrono::milliseconds
  ) {
    return {};
  }

  void quarantine_direct_frame_runtime() noexcept {
    portable_runtime_quarantined.store(true, std::memory_order_release);
  }

  bool direct_frame_runtime_quarantined() noexcept {
    return portable_runtime_quarantined.load(std::memory_order_acquire);
  }

#endif
}  // namespace platf::virtual_display
