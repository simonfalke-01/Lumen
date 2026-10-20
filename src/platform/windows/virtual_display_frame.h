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
#include <string_view>
#include <variant>
#include <vector>

// local includes
#include "src/platform/common.h"
#include "virtual_display.h"

namespace platf::virtual_display {
  inline constexpr std::size_t direct_frame_slot_count {2};  ///< Fixed persistent VDD slot count.
  inline constexpr std::size_t color_transform_lut_entry_count {4096};  ///< Fixed VDD ABI 3x4 LUT size.

  /** @brief Pixel format exported by the VDD direct-frame channel. */
  enum class frame_format_e : std::uint32_t {
    bgra8 = 1,  ///< DXGI_FORMAT_B8G8R8A8_UNORM.
    rgba16_float = 2,  ///< DXGI_FORMAT_R16G16B16A16_FLOAT.
  };

  /** Return the exact byte pitch for one VDD direct-frame pixel. */
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

  /**
   * @brief Decide whether a failed direct-frame source may use desktop capture on the active VDD.
   *
   * @param direct_required Whether the session requires the direct-frame boundary.
   * @param dynamic_range Exact prepared VDD dynamic range.
   * @return True only for an optional SDR session.
   */
  [[nodiscard]] constexpr bool direct_frame_desktop_fallback_permitted(
    const bool direct_required,
    const dynamic_range_e dynamic_range
  ) noexcept {
    return !direct_required && dynamic_range == dynamic_range_e::sdr;
  }

  /**
   * @brief Decide whether an initialized desktop backend may publish VDD fallback success.
   *
   * @param generation Exact active VDD generation carried by the stream.
   * @param policy_permitted Whether the optional SDR policy permits desktop fallback.
   * @param virtual_display_active Whether the stream still owns the VDD generation.
   * @param direct_required Whether the stream requires direct-frame capture.
   * @param dynamic_range Exact stream dynamic range.
   * @param backend_initialized Whether DDA or WGC initialization actually succeeded.
   * @return True only after a real optional SDR desktop backend is ready for this generation.
   */
  [[nodiscard]] constexpr bool direct_frame_fallback_publishable(
    const std::uint64_t generation,
    const bool policy_permitted,
    const bool virtual_display_active,
    const bool direct_required,
    const dynamic_range_e dynamic_range,
    const bool backend_initialized
  ) noexcept {
    return generation != 0 && policy_permitted && virtual_display_active && backend_initialized &&
           direct_frame_desktop_fallback_permitted(direct_required, dynamic_range);
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

  /** @brief Exact resolved HDR10 static metadata carried by the VDD ABI. */
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

  /** @brief One exact VDD ABI floating-point RGB lookup-table entry. */
  struct color_transform_rgb_t {
    float red {};
    float green {};
    float blue {};
  };

  /** @brief Exact normalized VDD ABI 3x4 matrix/scalar/4096-entry LUT payload. */
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

  /** @brief Stable initialization stage for one VDD direct-frame diagnostic. */
  enum class direct_frame_init_stage_e : std::uint8_t {
    precondition,
    device_interface_open,
    abi_query,
    abi_contract,
    cancel_event_create,
    frame_event_query,
    publisher_identity,
    publisher_process_open,
    frame_event_duplicate,
    frame_channel_query,
    frame_channel_wait,
    frame_channel_contract,
    texture_handle_duplicate,
    fence_handle_duplicate,
    initial_color_metadata,
    resource_contract,
    color_transform,
    handle_identity,
    dxgi_factory,
    adapter_enumeration,
    adapter_identity,
    d3d11_device,
    multithread_context,
    texture_import,
    fence_import,
    texture_contract,
    ready,
  };

  /** @brief Native status namespace retained by one initialization diagnostic. */
  enum class direct_frame_native_domain_e : std::uint8_t {
    none,
    win32,
    wait,
    hresult,
    logical,
  };

  /** @brief Shared-handle kind involved in an initialization failure. */
  enum class direct_frame_handle_kind_e : std::uint8_t {
    none,
    availability_event,
    texture,
    fence,
  };

  /** @brief Whether the best-effort QUERY_STATE diagnostic produced a usable snapshot. */
  enum class direct_frame_state_query_e : std::uint8_t {
    not_attempted,
    succeeded,
    transport_failure,
    invalid_snapshot,
  };

  [[nodiscard]] constexpr std::string_view direct_frame_state_query_label(
    const direct_frame_state_query_e query
  ) noexcept {
    switch (query) {
      case direct_frame_state_query_e::not_attempted: return "not_attempted";
      case direct_frame_state_query_e::succeeded: return "succeeded";
      case direct_frame_state_query_e::transport_failure: return "transport_failure";
      case direct_frame_state_query_e::invalid_snapshot: return "invalid_snapshot";
    }
    return "not_attempted";
  }

  inline constexpr std::uint32_t direct_frame_no_handle_slot {0xffffffffU};

  /** @brief Raw QUERY_STATE facts retained only after structural validation succeeds. */
  struct direct_frame_driver_state_snapshot_t {
    std::uint64_t generation;  ///< Current driver generation.
    std::uint64_t last_generation;  ///< Highest generation admitted by the driver.
    std::uint64_t preferred_adapter_luid;  ///< Adapter requested before monitor arrival.
    std::uint64_t assigned_adapter_luid;  ///< Adapter assigned by the active swap chain.
    std::uint32_t owner_process_id;  ///< Process owning the active generation.
    std::uint32_t monitor_started;  ///< Raw zero/one monitor-present value.
    std::uint32_t preference_submitted;  ///< Raw zero/one IddCx preference-submission value.
    std::uint32_t reserved;  ///< Must remain zero.
  };

  /** @brief Raw, trivially copyable facts for one direct-frame initialization attempt. */
  struct direct_frame_init_diagnostic_t {
    direct_frame_init_stage_e stage;  ///< Exact terminal initialization stage.
    direct_frame_native_domain_e domain;  ///< Namespace for `native_status`.
    frame_io_e result;  ///< Unchanged stable initialization result.
    direct_frame_state_query_e state_query;  ///< Explicit QUERY_STATE attempt outcome.
    direct_frame_native_domain_e state_query_domain;  ///< Namespace for the best-effort snapshot status.
    frame_io_e state_query_result;  ///< Best-effort QUERY_STATE transport result.
    direct_frame_handle_kind_e handle_kind;  ///< Handle kind involved in the terminal stage.
    std::uint32_t native_status;  ///< Exact Win32, WAIT, HRESULT-bit, or logical status.
    std::uint32_t state_query_native_status;  ///< Exact best-effort QUERY_STATE native status.
    std::uint32_t adapter_enumeration_status;  ///< First non-NOT_FOUND EnumAdapters1 HRESULT bits.
    std::uint32_t adapter_description_status;  ///< First failed GetDesc1 HRESULT bits.
    std::uint32_t handle_slot;  ///< Exact slot, or `direct_frame_no_handle_slot`.
    std::uint64_t generation;  ///< Host-selected generation.
    std::uint32_t abi_version;  ///< Driver-reported ABI version.
    std::uint32_t expected_abi_version;  ///< Host ABI version.
    std::uint32_t capability_flags;  ///< Driver-reported capability bitmap.
    std::uint32_t required_capabilities;  ///< Mode-specific host capability bitmap.
    std::uint64_t expected_adapter_luid;  ///< Frozen encoder-probe adapter LUID.
    std::uint64_t resource_adapter_luid;  ///< Frame-channel resource adapter LUID.
    std::uint32_t publisher_process_id;  ///< Driver frame publisher process identifier.
    std::uint64_t publisher_process_creation_time;  ///< PID-reuse-safe publisher creation time.
    direct_frame_driver_state_snapshot_t driver_state;  ///< Valid snapshot, or zeroed absent facts.
    bool driver_state_available;  ///< Whether `driver_state` is present and structurally valid.
    bool selection_preference_submitted;  ///< Prepared-mode fact, never replaced by QUERY_STATE.
  };

  [[nodiscard]] constexpr std::string_view direct_frame_init_stage_label(
    const direct_frame_init_stage_e stage
  ) noexcept {
    switch (stage) {
      case direct_frame_init_stage_e::precondition: return "precondition";
      case direct_frame_init_stage_e::device_interface_open: return "device_interface_open";
      case direct_frame_init_stage_e::abi_query: return "abi_query";
      case direct_frame_init_stage_e::abi_contract: return "abi_contract";
      case direct_frame_init_stage_e::cancel_event_create: return "cancel_event_create";
      case direct_frame_init_stage_e::frame_event_query: return "frame_event_query";
      case direct_frame_init_stage_e::publisher_identity: return "publisher_identity";
      case direct_frame_init_stage_e::publisher_process_open: return "publisher_process_open";
      case direct_frame_init_stage_e::frame_event_duplicate: return "frame_event_duplicate";
      case direct_frame_init_stage_e::frame_channel_query: return "frame_channel_query";
      case direct_frame_init_stage_e::frame_channel_wait: return "frame_channel_wait";
      case direct_frame_init_stage_e::frame_channel_contract: return "frame_channel_contract";
      case direct_frame_init_stage_e::texture_handle_duplicate: return "texture_handle_duplicate";
      case direct_frame_init_stage_e::fence_handle_duplicate: return "fence_handle_duplicate";
      case direct_frame_init_stage_e::initial_color_metadata: return "initial_color_metadata";
      case direct_frame_init_stage_e::resource_contract: return "resource_contract";
      case direct_frame_init_stage_e::color_transform: return "color_transform";
      case direct_frame_init_stage_e::handle_identity: return "handle_identity";
      case direct_frame_init_stage_e::dxgi_factory: return "dxgi_factory";
      case direct_frame_init_stage_e::adapter_enumeration: return "adapter_enumeration";
      case direct_frame_init_stage_e::adapter_identity: return "adapter_identity";
      case direct_frame_init_stage_e::d3d11_device: return "d3d11_device";
      case direct_frame_init_stage_e::multithread_context: return "multithread_context";
      case direct_frame_init_stage_e::texture_import: return "texture_import";
      case direct_frame_init_stage_e::fence_import: return "fence_import";
      case direct_frame_init_stage_e::texture_contract: return "texture_contract";
      case direct_frame_init_stage_e::ready: return "ready";
    }
    return "precondition";
  }

  [[nodiscard]] constexpr std::string_view direct_frame_native_domain_label(
    const direct_frame_native_domain_e domain
  ) noexcept {
    switch (domain) {
      case direct_frame_native_domain_e::none: return "none";
      case direct_frame_native_domain_e::win32: return "win32";
      case direct_frame_native_domain_e::wait: return "wait";
      case direct_frame_native_domain_e::hresult: return "hresult";
      case direct_frame_native_domain_e::logical: return "logical";
    }
    return "none";
  }

  [[nodiscard]] constexpr std::string_view direct_frame_init_result_label(
    const frame_io_e result
  ) noexcept {
    switch (result) {
      case frame_io_e::ok: return "ok";
      case frame_io_e::empty: return "empty";
      case frame_io_e::timeout: return "timeout";
      case frame_io_e::stale_generation: return "stale_generation";
      case frame_io_e::invalid_data: return "invalid_data";
      case frame_io_e::unsupported: return "unsupported";
      case frame_io_e::transport_error: return "transport_error";
      case frame_io_e::stopped: return "stopped";
    }
    return "transport_error";
  }

  [[nodiscard]] constexpr std::string_view direct_frame_handle_kind_label(
    const direct_frame_handle_kind_e kind
  ) noexcept {
    switch (kind) {
      case direct_frame_handle_kind_e::none: return "none";
      case direct_frame_handle_kind_e::availability_event: return "availability_event";
      case direct_frame_handle_kind_e::texture: return "texture";
      case direct_frame_handle_kind_e::fence: return "fence";
    }
    return "none";
  }

  /** Return whether raw QUERY_STATE facts satisfy the driver-state structural contract. */
  [[nodiscard]] constexpr bool valid_direct_frame_driver_state_snapshot(
    const direct_frame_driver_state_snapshot_t &snapshot
  ) noexcept {
    return snapshot.monitor_started <= 1 && snapshot.preference_submitted <= 1 &&
           snapshot.reserved == 0 && snapshot.last_generation >= snapshot.generation &&
           ((snapshot.generation == 0 && snapshot.owner_process_id == 0 &&
             snapshot.monitor_started == 0 && snapshot.preferred_adapter_luid == 0 &&
             snapshot.assigned_adapter_luid == 0 && snapshot.preference_submitted == 0) ||
            (snapshot.generation != 0 && snapshot.owner_process_id != 0 &&
             snapshot.preferred_adapter_luid != 0));
  }

  /** Record one terminal initialization result without changing independent raw facts. */
  constexpr void record_direct_frame_initialization_result(
    direct_frame_init_diagnostic_t &diagnostic,
    const direct_frame_init_stage_e stage,
    const frame_io_e result,
    const direct_frame_native_domain_e domain,
    const std::uint32_t native_status,
    const direct_frame_handle_kind_e handle_kind = direct_frame_handle_kind_e::none,
    const std::uint32_t handle_slot = direct_frame_no_handle_slot
  ) noexcept {
    diagnostic.stage = stage;
    diagnostic.result = result;
    diagnostic.domain = domain;
    diagnostic.native_status = native_status;
    diagnostic.handle_kind = handle_kind;
    diagnostic.handle_slot = handle_slot;
  }

  /** Replace the previous best-effort state snapshot without affecting initialization decisions. */
  constexpr void record_direct_frame_driver_state_query(
    direct_frame_init_diagnostic_t &diagnostic,
    const frame_io_e result,
    const direct_frame_native_domain_e domain,
    const std::uint32_t native_status,
    const direct_frame_driver_state_snapshot_t &snapshot = {}
  ) noexcept {
    diagnostic.driver_state = {};
    diagnostic.driver_state_available = false;
    diagnostic.state_query_result = result;
    diagnostic.state_query_domain = domain;
    diagnostic.state_query_native_status = native_status;
    if (result != frame_io_e::ok) {
      diagnostic.state_query = direct_frame_state_query_e::transport_failure;
      return;
    }
    if (!valid_direct_frame_driver_state_snapshot(snapshot) ||
        snapshot.generation != diagnostic.generation) {
      diagnostic.state_query = direct_frame_state_query_e::invalid_snapshot;
      return;
    }
    diagnostic.state_query = direct_frame_state_query_e::succeeded;
    diagnostic.driver_state = snapshot;
    diagnostic.driver_state_available = true;
  }

  /** @brief Semantic platform error reported by the direct-frame device transport. */
  enum class frame_transport_error_e {
    not_ready,  ///< Driver resources are not published yet.
    no_more_items,  ///< No completed frame is currently available.
    retry,  ///< Driver explicitly requests a bounded retry.
    revision_mismatch,  ///< Generation or lease revision is stale.
    invalid_state,  ///< Driver generation state no longer matches the request.
    invalid_data,  ///< Driver rejected malformed data.
    invalid_parameter,  ///< Driver rejected an invalid request field.
    not_supported,  ///< Required ABI or hardware behavior is unavailable.
    other,  ///< Unclassified transport failure.
  };

  /**
   * @brief Map a platform transport failure into the stable direct-frame contract.
   *
   * @param error Semantic platform transport error.
   * @return Stable frame I/O result consumed by initialization and dequeue logic.
   */
  [[nodiscard]] constexpr frame_io_e frame_io_from_transport_error(
    const frame_transport_error_e error
  ) noexcept {
    switch (error) {
      case frame_transport_error_e::not_ready:
      case frame_transport_error_e::no_more_items:
      case frame_transport_error_e::retry:
        return frame_io_e::empty;
      case frame_transport_error_e::revision_mismatch:
      case frame_transport_error_e::invalid_state:
        return frame_io_e::stale_generation;
      case frame_transport_error_e::invalid_data:
      case frame_transport_error_e::invalid_parameter:
        return frame_io_e::invalid_data;
      case frame_transport_error_e::not_supported:
        return frame_io_e::unsupported;
      case frame_transport_error_e::other:
        return frame_io_e::transport_error;
    }
    return frame_io_e::transport_error;
  }

  /**
   * @brief Validate the direct-frame ABI response while preserving transport failures.
   *
   * @param transport_status Result of the ABI device request.
   * @param actual_version Driver ABI version.
   * @param expected_version Host ABI version.
   * @param actual_capabilities Driver capability bitmap.
   * @param required_capabilities Capabilities required by the selected SDR/HDR mode.
   * @return Ok for an exact compatible ABI, transport status on I/O failure, or unsupported on mismatch.
   */
  [[nodiscard]] constexpr frame_io_e validate_frame_abi_contract(
    const frame_io_e transport_status,
    const std::uint32_t actual_version,
    const std::uint32_t expected_version,
    const std::uint32_t actual_capabilities,
    const std::uint32_t required_capabilities
  ) noexcept {
    if (transport_status != frame_io_e::ok) {
      return transport_status;
    }
    return actual_version == expected_version &&
               (actual_capabilities & required_capabilities) == required_capabilities ?
             frame_io_e::ok :
             frame_io_e::unsupported;
  }

  /** @brief Generation and requestor identity returned by one frame-channel operation. */
  struct frame_channel_source_identity_t {
    std::uint64_t generation {};  ///< Exact active VDD generation.
    std::uint32_t process_id {};  ///< Authenticated process that received the transferred handles.
    std::uint32_t source_reserved {};  ///< Must be zero.
    std::uint64_t process_creation_time {};  ///< Exact requestor creation FILETIME.
    std::uint64_t response_reserved {};  ///< Must be zero.

    bool operator==(const frame_channel_source_identity_t &) const = default;
  };

  /**
   * @brief Validate a generation-scoped handle recipient as the exact current host process.
   *
   * @param source Driver response identity.
   * @param expected_generation Active host generation.
   * @param expected_process_id Exact current host process identifier.
   * @param expected_process_creation_time Exact current host process creation FILETIME.
   * @return True only for the exact generation, host identity, and zero reserved fields.
   */
  [[nodiscard]] constexpr bool valid_frame_channel_source_identity(
    const frame_channel_source_identity_t &source,
    const std::uint64_t expected_generation,
    const std::uint32_t expected_process_id,
    const std::uint64_t expected_process_creation_time
  ) noexcept {
    return expected_generation != 0 && source.generation == expected_generation &&
           expected_process_id != 0 && source.process_id == expected_process_id &&
           expected_process_creation_time != 0 &&
           source.process_creation_time == expected_process_creation_time &&
           source.source_reserved == 0 && source.response_reserved == 0;
  }

  /** @brief Driver-owned persistent resources transferred into the Lumen process. */
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

  /** @brief Normalized imported shared-texture descriptor used by portable validation. */
  struct frame_texture_descriptor_t {
    std::uint32_t width {};  ///< Texture width.
    std::uint32_t height {};  ///< Texture height.
    frame_format_e format {frame_format_e::bgra8};  ///< Imported DXGI texture format.
    std::uint32_t mip_levels {};  ///< Must equal one.
    std::uint32_t array_size {};  ///< Must equal one.
    std::uint32_t sample_count {};  ///< Must equal one.
    bool default_usage {};  ///< Whether the resource uses GPU-default allocation.
    bool shader_resource {};  ///< Whether shader-resource binding is present.
    bool no_cpu_access {};  ///< Whether CPU access flags are zero.
    bool shared_nt_handle {};  ///< Whether NT-handle sharing is present.
    bool shared_keyed_mutex {};  ///< Whether keyed-mutex sharing is present.
  };

  /**
   * @brief Validate an imported shared texture against immutable channel resources.
   *
   * @param descriptor Normalized D3D11 texture descriptor.
   * @param resources Validated frame-channel resources.
   * @return True only for the exact dimensions, format, allocation, binding, and sharing contract.
   */
  [[nodiscard]] constexpr bool valid_frame_texture_descriptor(
    const frame_texture_descriptor_t &descriptor,
    const frame_resources_t &resources
  ) noexcept {
    return descriptor.width == resources.width && descriptor.height == resources.height &&
           descriptor.format == resources.format && descriptor.mip_levels == 1 &&
           descriptor.array_size == 1 && descriptor.sample_count == 1 &&
           descriptor.default_usage && descriptor.shader_resource && descriptor.no_cpu_access &&
           descriptor.shared_nt_handle && descriptor.shared_keyed_mutex;
  }

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
   * @param imported Exact identity queried from the adapter named by the VDD response.
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
  /** @brief One client-drawable cursor image in premultiplied RGBA. */
  struct cursor_image_t {
    std::uint32_t width {};  ///< Width in pixels.
    std::uint32_t height {};  ///< Height in pixels.
    std::uint32_t hot_x {};  ///< Hotspot X from the top-left pixel.
    std::uint32_t hot_y {};  ///< Hotspot Y from the top-left pixel.
    std::vector<std::uint8_t> rgba;  ///< width * height premultiplied RGBA pixels.
  };

  /** @brief Latest hardware-cursor visibility and shape published by the VDD. */
  struct cursor_snapshot_t {
    std::uint64_t sequence {};  ///< Changes with visibility or shape; zero before the first report.
    bool visible {};  ///< Whether Windows currently shows the cursor.
    std::shared_ptr<const cursor_image_t> image;  ///< Latest shape, or null before the first shape.
    std::uint8_t system_cursor {};  ///< Standard Windows cursor kind (LSP numbering), or 0 for an app-defined shape.
  };

  /** @brief Hardware-cursor feed for one VDD generation started with `hardware_cursor`. */
  class cursor_source_t {
  public:
    virtual ~cursor_source_t() = default;

    /** @brief Return the newest cursor state without blocking on the driver. */
    [[nodiscard]] virtual cursor_snapshot_t latest() const = 0;
  };

  /**
   * @brief Open the hardware-cursor feed of an active VDD selection.
   * @param selection Active selection whose generation requested a hardware cursor.
   * @return Running feed, or null when the driver refuses it.
   */
  [[nodiscard]] std::shared_ptr<cursor_source_t> make_system_cursor_source(const stream_selection_t &selection);

  [[nodiscard]] std::shared_ptr<frame_source_t> make_system_frame_source(
    const stream_selection_t &selection,
    std::chrono::milliseconds timeout
  );

  /** @brief Permanently disable the direct-frame path for this host process. */
  void quarantine_direct_frame_runtime() noexcept;

  /** @brief Return whether a prior fused-path failure disabled direct frames. */
  [[nodiscard]] bool direct_frame_runtime_quarantined() noexcept;
}  // namespace platf::virtual_display
