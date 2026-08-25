/**
 * @file src/platform/windows/virtual_display_frame.h
 * @brief Production generation-fenced two-slot VDD direct-frame host contract.
 */
#pragma once

// standard includes
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <variant>

// local includes
#include "src/platform/common.h"
#include "virtual_display.h"

namespace platf::virtual_display {
  inline constexpr std::size_t direct_frame_slot_count {2};  ///< Fixed persistent VDD slot count.
  inline constexpr std::size_t color_transform_lut_entry_count {4096};  ///< Fixed ABI5 3x4 LUT size.

  /** @brief Pixel format exported by the VDD direct-frame channel. */
  enum class frame_format_e : std::uint32_t {
    bgra8 = 1,  ///< DXGI_FORMAT_B8G8R8A8_UNORM.
    rgba16_float = 2,  ///< DXGI_FORMAT_R16G16B16A16_FLOAT.
  };

  /** Return the exact byte pitch for one ABI5 direct-frame pixel. */
  [[nodiscard]] constexpr std::uint32_t frame_format_pixel_pitch(const frame_format_e format) noexcept {
    return format == frame_format_e::rgba16_float ? 8U : 4U;
  }

  /** Return whether an active HDR VDD forbids untransformed DDA/WGC capture. */
  [[nodiscard]] constexpr bool requires_direct_frame_for_vdd_hdr(
    const bool hdr_requested,
    const bool virtual_display_active
  ) noexcept {
    return hdr_requested && virtual_display_active;
  }

  /** Return whether a required VDD session may enter the exact DXGI direct-frame branch. */
  [[nodiscard]] constexpr bool valid_required_direct_capture_request(
    const bool direct_required,
    const bool dxgi_capture,
    const bool has_vdd_source
  ) noexcept {
    return !direct_required || (dxgi_capture && has_vdd_source);
  }

  /** @brief Resolved surface color space carried with each leased frame. */
  enum class frame_color_space_e : std::uint32_t {
    srgb = 1,
    scrgb = 2,
    hdr10 = 3,
  };

  /** @brief Resolved HDR10 metadata source state from IddCx. */
  enum class hdr_metadata_type_e : std::uint32_t {
    none = 0,
    default_ = 1,
    unchanged = 2,
    new_ = 3,
  };

  /** @brief Exact resolved HDR10 static metadata carried by ABI5. */
  struct frame_hdr10_metadata_t {
    std::array<std::uint16_t, 2> red_primary {};
    std::array<std::uint16_t, 2> green_primary {};
    std::array<std::uint16_t, 2> blue_primary {};
    std::array<std::uint16_t, 2> white_point {};
    std::uint16_t maximum_mastering_luminance {};
    std::uint16_t minimum_mastering_luminance {};
    std::uint16_t maximum_content_light_level {};
    std::uint16_t maximum_frame_average_light_level {};

    bool operator==(const frame_hdr10_metadata_t &) const = default;
  };

  /** @brief Exact frame-scoped color metadata resolved before encoder creation or dequeue. */
  struct frame_color_metadata_t {
    frame_color_space_e surface_color_space {frame_color_space_e::srgb};
    std::uint32_t sdr_white_level_nits {};
    hdr_metadata_type_e hdr_metadata_type {hdr_metadata_type_e::none};
    frame_hdr10_metadata_t hdr10_metadata {};

    bool operator==(const frame_color_metadata_t &) const = default;
  };

  /** @brief Immutable gamma/color-transform payload kind. */
  enum class color_transform_type_e : std::uint32_t {
    default_ = 1,
    rgb256x3x16 = 2,
    colorspace_3x4 = 3,
  };

  /** @brief Exact legacy 256-entry RGB gamma ramp. */
  struct color_transform_rgb256_t {
    std::array<std::uint16_t, 256> red {};
    std::array<std::uint16_t, 256> green {};
    std::array<std::uint16_t, 256> blue {};
  };

  /** @brief One exact ABI5 floating-point RGB lookup-table entry. */
  struct color_transform_rgb_t {
    float red {};
    float green {};
    float blue {};
  };

  /** @brief Exact normalized ABI5 3x4 matrix/scalar/4096-entry LUT payload. */
  struct color_transform_3x4_t {
    bool matrix_enabled {};
    std::array<float, 12> color_matrix_3x4 {};
    float scalar_multiplier {};
    bool lut_enabled {};
    std::array<color_transform_rgb_t, color_transform_lut_entry_count> lookup_table_1d {};
    std::array<float, 12> wire_rec709_matrix_3x4 {};  ///< CPU-precomposed linear Rec.709 wire transform.
    std::array<float, 12> wire_rec2020_matrix_3x4 {};  ///< CPU-precomposed linear Rec.2020 wire transform.
  };

  /** @brief One immutable generation/version transform shared through slot ownership. */
  struct color_transform_t {
    std::uint64_t generation {};
    std::uint64_t version {};
    color_transform_type_e type {color_transform_type_e::default_};
    std::variant<std::monostate, color_transform_rgb256_t, color_transform_3x4_t> payload;
  };

  /** @brief Two-version immutable transform cache matching the driver's retained window. */
  class color_transform_cache_t {
  public:
    [[nodiscard]] std::shared_ptr<const color_transform_t> find(
      std::uint64_t generation,
      std::uint64_t version
    ) const noexcept;
    bool commit(std::shared_ptr<const color_transform_t> transform) noexcept;
    void clear() noexcept;

  private:
    std::shared_ptr<const color_transform_t> current_;
    std::shared_ptr<const color_transform_t> previous_;
  };

  /** Validate finite payload values and precompose both supported wire-primary matrices. */
  [[nodiscard]] bool prepare_color_transform(color_transform_t &transform) noexcept;

  /** @brief Stable result for one production direct-frame operation. */
  enum class frame_io_e {
    ok,  ///< Operation completed.
    empty,  ///< Driver has no completed frame or published resources yet.
    timeout,  ///< Host deadline elapsed while the driver remained empty.
    stale_generation,  ///< Driver response did not match the active generation.
    invalid_data,  ///< Driver metadata violated the fixed ABI.
    unsupported,  ///< Required D3D11 sharing, fence, or hardware gate is unavailable.
    transport_error,  ///< Device IO failed.
    stopped,  ///< Source was closed or quarantined.
  };

  /** @brief Driver-owned persistent resources duplicated into the Lumen process. */
  struct frame_resources_t {
    std::uint64_t generation {};  ///< Exact active VDD generation.
    std::uint64_t adapter_luid {};  ///< Packed render-adapter LUID.
    std::uint32_t width {};  ///< Texture width.
    std::uint32_t height {};  ///< Texture height.
    frame_format_e format {frame_format_e::bgra8};  ///< Shared texture format.
    dynamic_range_e dynamic_range {dynamic_range_e::sdr};  ///< Exact prepared stream range.
    std::uint32_t slot_count {};  ///< Must equal `direct_frame_slot_count`.
    std::array<std::uintptr_t, direct_frame_slot_count> texture_handles {};  ///< Duplicated texture handles.
    std::array<std::uintptr_t, direct_frame_slot_count> fence_handles {};  ///< Duplicated fence handles.
    std::uint64_t initial_color_transform_version {};  ///< Version required before encoder creation.
    frame_color_metadata_t initial_color_metadata;  ///< Initial resolved color/white/HDR state.
  };

  /** @brief Adapter identity required at the VDD-import and active-NVENC boundary. */
  struct direct_frame_adapter_identity_t {
    std::uint64_t adapter_luid {};  ///< Packed DXGI adapter LUID.
    std::uint32_t vendor_id {};  ///< PCI vendor identifier.
    std::uint32_t device_id {};  ///< PCI device identifier.
    std::uint32_t subsystem_id {};  ///< PCI subsystem identifier.
    std::uint32_t revision {};  ///< PCI revision.
    std::uint64_t driver_version {};  ///< DXGI UMD driver version.

    bool operator==(const direct_frame_adapter_identity_t &) const = default;
  };

  /**
   * @brief Validate the imported VDD adapter against the active encoder probe.
   * @param nvenc_active Whether the committed active encoder backend is NVENC.
   * @param imported Exact identity queried from the adapter named by the ABI5 response.
   * @param encoder_probe Exact adapter identity retained by the active encoder probe.
   * @return True only for one complete NVIDIA identity with exact LUID/PCI/driver agreement.
   */
  [[nodiscard]] bool valid_direct_frame_adapter_binding(
    bool nvenc_active,
    const direct_frame_adapter_identity_t &imported,
    const std::optional<direct_frame_adapter_identity_t> &encoder_probe
  ) noexcept;

#if defined(_WIN32)
  /** @brief Kernel-object comparison result for two direct-frame handles. */
  enum class direct_frame_handle_identity_e {
    distinct,  ///< Handles are valid and name different kernel objects.
    alias,  ///< Handles name the same underlying kernel object.
    unavailable_or_error,  ///< Comparator is unavailable or cannot decide for this kernel-object type.
  };

  /**
   * @brief Compare two still-open direct-frame handles by kernel-object identity.
   * @param first First duplicated texture or fence handle.
   * @param second Second duplicated texture or fence handle.
   * @return Alias, proven distinct, or an indeterminate unavailable/error state.
   */
  [[nodiscard]] direct_frame_handle_identity_e compare_direct_frame_handle_identity(
    std::uintptr_t first,
    std::uintptr_t second
  ) noexcept;
#endif

  /** @brief One completed driver copy leased through conversion and NVENC completion. */
  struct frame_descriptor_t {
    std::uint64_t generation {};  ///< Exact active VDD generation.
    std::uint64_t sequence {};  ///< Strictly increasing nonzero frame sequence.
    std::uint64_t producer_fence_value {};  ///< Odd per-slot producer fence value.
    std::int64_t capture_qpc {};  ///< QPC sampled after IddCx acquisition.
    std::int64_t producer_signal_qpc {};  ///< QPC sampled after producer fence submission.
    std::uint32_t slot {};  ///< Persistent slot index.
    std::uint64_t color_transform_version {};  ///< Exact transform retained while this slot is leased.
    frame_color_metadata_t color_metadata;  ///< Frame-scoped resolved surface and HDR state.
  };

  /**
   * @brief Validate exact resource metadata before importing any OS handle.
   * @param resources Driver response.
   * @param generation Expected active generation.
   * @param mode Exact selected mode.
   * @return True only for the exact two-slot SDR/FP16 HDR contract.
   */
  [[nodiscard]] bool valid_frame_resources(
    const frame_resources_t &resources,
    std::uint64_t generation,
    const mode_t &mode
  ) noexcept;

  /**
   * @brief Validate one dequeued descriptor against immutable resources.
   * @param frame Driver frame descriptor.
   * @param resources Imported resource description.
   * @return True only for a generation-matched slot and odd producer fence value.
   */
  [[nodiscard]] bool valid_frame_descriptor(
    const frame_descriptor_t &frame,
    const frame_resources_t &resources
  ) noexcept;

  /** Return whether one initial or dequeued color block matches the exact SDR/HDR mode. */
  [[nodiscard]] bool valid_frame_color_metadata(
    const frame_color_metadata_t &metadata,
    dynamic_range_e dynamic_range,
    frame_format_e format
  ) noexcept;

  class frame_source_t;

  /** @brief RAII ownership of one concrete driver slot through NVENC completion. */
  class frame_lease_t final: public platf::deinit_t {
  public:
    ~frame_lease_t() override;

    frame_lease_t(const frame_lease_t &) = delete;
    frame_lease_t &operator=(const frame_lease_t &) = delete;

    /** @brief Return the exact driver descriptor owned by this lease. */
    [[nodiscard]] const frame_descriptor_t &descriptor() const noexcept;
    /** @brief Return the imported ID3D11Texture2D pointer for this slot. */
    [[nodiscard]] void *native_texture() const noexcept;
    /** @brief Return the immutable transform retained with this slot. */
    [[nodiscard]] const std::shared_ptr<const color_transform_t> &color_transform() const noexcept;

  private:
    friend class frame_source_t;

    frame_lease_t(
      std::shared_ptr<frame_source_t> source,
      frame_descriptor_t descriptor,
      void *native_texture,
      std::shared_ptr<const color_transform_t> color_transform
    );

    std::shared_ptr<frame_source_t> source_;  ///< Source retained until exact release completes.
    frame_descriptor_t descriptor_;  ///< Exact generation/sequence/slot ownership.
    void *native_texture_ {};  ///< Non-owning imported texture retained by `source_`.
    std::shared_ptr<const color_transform_t> color_transform_;  ///< Immutable transform retained through release.
  };

  /** @brief Result of waiting for one production VDD frame. */
  struct frame_acquire_result_t {
    frame_io_e status {frame_io_e::stopped};  ///< Stable acquire result.
    std::shared_ptr<frame_lease_t> lease;  ///< Frame lease on success.
  };

  /** @brief Opaque production IOCTL, D3D11 import, and slot-lifetime owner. */
  class frame_source_t: public std::enable_shared_from_this<frame_source_t> {
  public:
    ~frame_source_t();

    frame_source_t(const frame_source_t &) = delete;
    frame_source_t &operator=(const frame_source_t &) = delete;

    /** @brief Wait for and lease one completed driver frame before the deadline. */
    frame_acquire_result_t acquire(std::chrono::milliseconds timeout);
    /** @brief Quarantine the direct path and close the concrete driver channel. */
    void stop() noexcept;

    /** @brief Return whether import and every previous production operation remain healthy. */
    [[nodiscard]] bool healthy() const noexcept;
    /** @brief Return immutable imported resource metadata. */
    [[nodiscard]] frame_resources_t resources() const;
    /** @brief Return the imported native D3D11 device. */
    [[nodiscard]] void *native_device() const noexcept;
    /** @brief Return the imported native immediate context. */
    [[nodiscard]] void *native_context() const noexcept;
    /** @brief Return the imported native DXGI adapter. */
    [[nodiscard]] void *native_adapter() const noexcept;

  private:
    friend class frame_lease_t;
    friend std::shared_ptr<frame_source_t> make_system_frame_source(
      const stream_selection_t &selection,
      std::chrono::milliseconds timeout
    );

    class impl_t;
    explicit frame_source_t(std::unique_ptr<impl_t> impl);
    void release(const frame_descriptor_t &frame) noexcept;

    std::unique_ptr<impl_t> impl_;  ///< Concrete production driver and D3D11 state.
  };

  /**
   * @brief Open the production Windows direct-frame channel for one active VDD selection.
   * @param selection Exact active VDD generation and mode.
   * @param timeout Bounded driver-resource publication/import deadline.
   * @return Healthy source, or empty when any capability/hardware/import gate fails.
   */
  [[nodiscard]] std::shared_ptr<frame_source_t> make_system_frame_source(
    const stream_selection_t &selection,
    std::chrono::milliseconds timeout
  );

  /** @brief Permanently disable the direct-frame path for this host process. */
  void quarantine_direct_frame_runtime() noexcept;

  /** @brief Return whether a prior fused-path failure disabled direct frames. */
  [[nodiscard]] bool direct_frame_runtime_quarantined() noexcept;
}  // namespace platf::virtual_display
