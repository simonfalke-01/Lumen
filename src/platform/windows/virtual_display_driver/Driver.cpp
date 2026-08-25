/**
 * @file src/platform/windows/virtual_display_driver/Driver.cpp
 * @brief Lumen UMDF2 IddCx virtual display driver.
 */
#include "LumenColorTransformPolicy.h"
#include "LumenDirectFrameSlotPolicy.h"
#include "LumenHdrModePolicy.h"
#include "LumenModeValidationPolicy.h"
#include "LumenSingleDeleteOwner.h"
#include "LumenVirtualDisplayProtocol.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <thread>

#ifndef NOMINMAX
  #define NOMINMAX
#endif
#include <Windows.h>
#pragma warning(push)
#pragma warning(disable : 4471)
// clang-format off: IddCx requires WDF declarations first.
#include <wdf.h>
#include <iddcx.h>
// clang-format on
#pragma warning(pop)
#include "LumenVirtualDisplayGuids.h"

#include <avrt.h>
#include <d3d11_4.h>
#include <dxgi1_2.h>
#include <wrl/client.h>

using Microsoft::WRL::ComPtr;

namespace {
  constexpr WCHAR endpoint_model[] = L"Lumen Virtual Display";
  constexpr WCHAR endpoint_manufacturer[] = L"Lumen";
  constexpr char connector_id[] = "LUM0001";
  std::uint64_t pack_luid(LUID luid) noexcept;
  LUID unpack_luid(std::uint64_t packed) noexcept;
  std::uint64_t current_process_creation_time() noexcept;

  struct device_state_t;

  /** @brief Immutable versioned gamma/color-transform payload. */
  struct color_transform_blob_t {
    std::uint64_t version {};  ///< Nonzero generation-local version.
    std::uint32_t type {LUMEN_VDD_GAMMA_RAMP_TYPE_DEFAULT};  ///< LUMEN_VDD_GAMMA_RAMP_TYPE_*.
    std::uint32_t payload_size {};  ///< Exact size for type.
    LUMEN_VDD_COLOR_TRANSFORM_PAYLOAD payload {};  ///< Exact normalized payload.
  };

  /** @brief Generation-scoped color and default HDR metadata shared with the swap-chain worker. */
  struct color_state_t {
    std::mutex mutex;  ///< Serializes immutable publication and metadata snapshots.
    std::uint64_t generation {};  ///< Exact owning generation.
    std::uint64_t next_transform_version {2};  ///< DEFAULT is always version 1.
    std::shared_ptr<const color_transform_blob_t> current_transform;  ///< Current immutable transform.
    std::optional<LUMEN_VDD_HDR10_METADATA> default_hdr10_metadata;  ///< Latest copied OS default block.
  };

  /** @brief Immutable prepared mode published for context-free descriptor callbacks. */
  struct monitor_descriptor_snapshot_t {
    std::uint64_t generation {};  ///< Exact prepared generation.
    LUMEN_VDD_MODE mode {};  ///< Exact prepared mode.
  };

  /** @brief Ref-counted single-device monitor-description callback context. */
  struct monitor_descriptor_context_t {
    std::mutex mutex;  ///< Serializes snapshot replacement and acquisition.
    std::optional<monitor_descriptor_snapshot_t> snapshot;  ///< Active immutable generation snapshot.
  };

  /** @brief Resolved per-frame metadata copied from IddCx metadata2. */
  struct resolved_frame_metadata_t {
    std::uint32_t surface_color_space {};  ///< LUMEN_VDD_COLOR_SPACE_*.
    std::uint32_t sdr_white_level_nits {};  ///< Validated 80..480 nits.
    std::uint32_t hdr_metadata_type {};  ///< LUMEN_VDD_HDR_METADATA_*.
    LUMEN_VDD_HDR10_METADATA hdr10_metadata {};  ///< Resolved effective block.
  };

  std::mutex monitor_descriptor_registry_mutex;  ///< Serializes the sole registered device context.
  std::weak_ptr<monitor_descriptor_context_t> monitor_descriptor_registry;  ///< Sole registered descriptor context.

  /** Return whether every IddCx 1.10 function required by the HDR/metadata contract is available. */
  bool hdr_runtime_available() noexcept {
    return IDD_IS_FUNCTION_AVAILABLE(IddCxMonitorUpdateModes2) &&
           IDD_IS_FUNCTION_AVAILABLE(IddCxSwapChainReleaseAndAcquireBuffer2) &&
           IDD_IS_FIELD_AVAILABLE(IDD_CX_CLIENT_CONFIG, EvtIddCxAdapterCommitModes2) &&
           IDD_IS_FIELD_AVAILABLE(IDD_CX_CLIENT_CONFIG, EvtIddCxAdapterQueryTargetInfo) &&
           IDD_IS_FIELD_AVAILABLE(IDD_CX_CLIENT_CONFIG, EvtIddCxParseMonitorDescription2) &&
           IDD_IS_FIELD_AVAILABLE(IDD_CX_CLIENT_CONFIG, EvtIddCxMonitorSetDefaultHdrMetaData) &&
           IDD_IS_FIELD_AVAILABLE(IDD_CX_CLIENT_CONFIG, EvtIddCxMonitorQueryTargetModes2) &&
           IDD_IS_FIELD_AVAILABLE(IDD_CX_CLIENT_CONFIG, EvtIddCxMonitorSetGammaRamp) &&
           IDD_IS_STRUCTURE_AVAILABLE(IDDCX_METADATA2) &&
           IDD_IS_FIELD_AVAILABLE(IDDCX_METADATA2, ValidFlags) &&
           IDD_IS_FIELD_AVAILABLE(IDDCX_METADATA2, HwProtectedSurface) &&
           IDD_IS_FIELD_AVAILABLE(IDDCX_METADATA2, pSurface) &&
           IDD_IS_FIELD_AVAILABLE(IDDCX_METADATA2, SurfaceColorSpace) &&
           IDD_IS_FIELD_AVAILABLE(IDDCX_METADATA2, SdrWhiteLevel) &&
           IDD_IS_FIELD_AVAILABLE(IDDCX_METADATA2, Hdr10FrameMetaData);
  }

  /** Copy one IddCx HDR10 block into the stable private ABI representation. */
  LUMEN_VDD_HDR10_METADATA copy_hdr10_metadata(const IDDCX_HDR10_METADATA &input) noexcept {
    LUMEN_VDD_HDR10_METADATA output {};
    std::copy(std::begin(input.RedPrimary), std::end(input.RedPrimary), std::begin(output.red_primary));
    std::copy(std::begin(input.GreenPrimary), std::end(input.GreenPrimary), std::begin(output.green_primary));
    std::copy(std::begin(input.BluePrimary), std::end(input.BluePrimary), std::begin(output.blue_primary));
    std::copy(std::begin(input.WhitePoint), std::end(input.WhitePoint), std::begin(output.white_point));
    output.maximum_mastering_luminance = input.MaxMasteringLuminance;
    output.minimum_mastering_luminance = input.MinMasteringLuminance;
    output.maximum_content_light_level = input.MaxContentLightLevel;
    output.maximum_frame_average_light_level = input.MaxFrameAverageLightLevel;
    return output;
  }

  /** Create generation-local DEFAULT identity transform version 1. */
  std::shared_ptr<const color_transform_blob_t> default_color_transform() {
    auto transform = std::make_shared<color_transform_blob_t>();
    transform->version = 1;
    transform->type = LUMEN_VDD_GAMMA_RAMP_TYPE_DEFAULT;
    return transform;
  }

  /** @brief Heap-owned context attached to the WDF device. */
  struct device_context_t {
    device_state_t *state;
  };

  WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(device_context_t, device_context);

  /** @brief Heap-owned context attached to an IddCx adapter. */
  struct adapter_context_t {
    device_state_t *state;
  };

  WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(adapter_context_t, adapter_context);

  /** @brief Heap-owned context attached to an IddCx monitor. */
  struct monitor_context_t {
    device_state_t *state;
  };

  WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(monitor_context_t, monitor_context);

  struct swap_chain_deleter_t {
    void operator()(IDDCX_SWAPCHAIN swap_chain) const noexcept {
      WdfObjectDelete(swap_chain);
    }
  };

  class unique_handle_t {
  public:
    explicit unique_handle_t(HANDLE handle):
        handle_(handle) {
      if (handle_ == nullptr) {
        throw std::runtime_error("Unable to create VDD swap-chain stop event");
      }
    }

    ~unique_handle_t() {
      CloseHandle(handle_);
    }

    unique_handle_t(const unique_handle_t &) = delete;
    unique_handle_t &operator=(const unique_handle_t &) = delete;

    [[nodiscard]] HANDLE get() const noexcept {
      return handle_;
    }

  private:
    HANDLE handle_;
  };

  /** @brief Driver-side ownership state for one persistent direct-frame slot. */
  using frame_slot_state_e = lumen::vdd::frame::slot_state_e;

  /** @brief One persistent shared mode-native texture and per-slot shared fence. */
  struct frame_slot_t {
    ~frame_slot_t() {
      if (texture_handle != nullptr) {
        CloseHandle(texture_handle);
      }
      if (fence_handle != nullptr) {
        CloseHandle(fence_handle);
      }
    }

    frame_slot_t() = default;
    frame_slot_t(const frame_slot_t &) = delete;
    frame_slot_t &operator=(const frame_slot_t &) = delete;

    ComPtr<ID3D11Texture2D> texture;  ///< Driver-owned shareable copy destination.
    ComPtr<IDXGIKeyedMutex> keyed_mutex;  ///< Explicit producer/consumer CPU ownership handoff.
    ComPtr<ID3D11Fence> fence;  ///< Per-slot producer/consumer GPU timeline.
    HANDLE texture_handle {};  ///< Unnamed NT shared texture handle in the UMDF host.
    HANDLE fence_handle {};  ///< Unnamed NT shared fence handle in the UMDF host.
    frame_slot_state_e state {frame_slot_state_e::empty};  ///< Current producer/consumer ownership.
    std::uint64_t sequence {};  ///< Exact frame sequence currently stored.
    std::uint64_t producer_fence_value {};  ///< Odd value signaled after the most recent copy.
    std::uint64_t consumer_fence_value {};  ///< Even host value required before reuse.
    std::int64_t capture_qpc {};  ///< QPC sampled after IddCx acquisition.
    std::int64_t producer_signal_qpc {};  ///< QPC sampled after producer fence submission.
    std::shared_ptr<const color_transform_blob_t> color_transform;  ///< Immutable transform retained for this lease.
    resolved_frame_metadata_t metadata;  ///< Resolved IddCx metadata retained for this lease.
  };

  /** @brief IddCx swap-chain consumer and concrete two-slot direct-frame producer. */
  class swap_chain_processor_t {
  public:
    swap_chain_processor_t(
      IDDCX_SWAPCHAIN swap_chain,
      LUID adapter_luid,
      HANDLE frame_event,
      std::uint64_t generation,
      LUMEN_VDD_MODE mode,
      HANDLE frame_ready_event,
      std::shared_ptr<color_state_t> color_state,
      bool direct_frames_enabled
    ):
        swap_chain_(swap_chain),
        frame_event_(frame_event),
        generation_(generation),
        mode_(mode),
        frame_ready_event_(frame_ready_event),
        color_state_(std::move(color_state)),
        stop_event_(CreateEventW(nullptr, TRUE, FALSE, nullptr)) {
      direct_enabled_.store(direct_frames_enabled, std::memory_order_relaxed);
      worker_ = std::thread([this, adapter_luid]() {
        run(adapter_luid);
      });
    }

    ~swap_chain_processor_t() {
      SetEvent(stop_event_.get());
      if (worker_.joinable()) {
        worker_.join();
      }
    }

    swap_chain_processor_t(const swap_chain_processor_t &) = delete;
    swap_chain_processor_t &operator=(const swap_chain_processor_t &) = delete;

    /** @brief Publish exact raw unnamed texture/fence handles for authorized reverse duplication. */
    NTSTATUS open_frame_channel(LUMEN_VDD_OPEN_FRAME_CHANNEL_RESPONSE &response) noexcept {
      std::lock_guard lock(mutex_);
      if (!resources_ready_ || !direct_enabled_.load(std::memory_order_acquire)) {
        return direct_enabled_.load(std::memory_order_relaxed) ? STATUS_DEVICE_NOT_READY : STATUS_NOT_SUPPORTED;
      }
      const auto source_creation_time = current_process_creation_time();
      if (source_creation_time == 0) {
        return STATUS_UNSUCCESSFUL;
      }

      std::memset(&response, 0, sizeof(response));
      response.generation = generation_;
      response.adapter_luid = adapter_luid_;
      response.source_process_id = GetCurrentProcessId();
      response.source_process_creation_time = source_creation_time;
      response.width = mode_.width;
      response.height = mode_.height;
      response.texture_format = mode_.dynamic_range == LUMEN_VDD_DYNAMIC_RANGE_HDR10 ?
                                  LUMEN_VDD_FRAME_FORMAT_RGBA16_FLOAT :
                                  LUMEN_VDD_FRAME_FORMAT_BGRA8;
      response.slot_count = LUMEN_VDD_FRAME_SLOT_COUNT;
      for (std::size_t slot = 0; slot < LUMEN_VDD_FRAME_SLOT_COUNT; ++slot) {
        response.texture_handles[slot] = reinterpret_cast<std::uint64_t>(slots_[slot].texture_handle);
        response.fence_handles[slot] = reinterpret_cast<std::uint64_t>(slots_[slot].fence_handle);
      }
      {
        std::lock_guard color_lock(color_state_->mutex);
        if (!color_state_->current_transform) {
          return STATUS_INVALID_DEVICE_STATE;
        }
        response.color_transform_version = color_state_->current_transform->version;
      }
      response.initial_surface_color_space = initial_metadata_.surface_color_space;
      response.initial_sdr_white_level_nits = initial_metadata_.sdr_white_level_nits;
      response.initial_hdr_metadata_type = initial_metadata_.hdr_metadata_type;
      response.initial_hdr10_metadata = initial_metadata_.hdr10_metadata;
      return STATUS_SUCCESS;
    }

    /** @brief Copy one current or slot-retained immutable transform version. */
    NTSTATUS query_color_transform(
      const std::uint64_t version,
      LUMEN_VDD_QUERY_COLOR_TRANSFORM_RESPONSE &response
    ) noexcept {
      std::shared_ptr<const color_transform_blob_t> selected;
      {
        std::lock_guard color_lock(color_state_->mutex);
        if (color_state_->current_transform && color_state_->current_transform->version == version) {
          selected = color_state_->current_transform;
        }
      }
      if (!selected) {
        std::lock_guard lock(mutex_);
        for (const auto &slot : slots_) {
          if (slot.color_transform && slot.color_transform->version == version) {
            selected = slot.color_transform;
            break;
          }
        }
      }
      if (!selected) {
        return STATUS_REVISION_MISMATCH;
      }
      std::memset(&response, 0, sizeof(response));
      response.generation = generation_;
      response.transform_version = selected->version;
      response.gamma_ramp_type = selected->type;
      response.payload_size = selected->payload_size;
      std::memcpy(&response.payload, &selected->payload, sizeof(response.payload));
      return STATUS_SUCCESS;
    }

    /** @brief Lease the next policy-selected frame without blocking the driver control queue. */
    NTSTATUS dequeue_frame(LUMEN_VDD_DEQUEUE_FRAME_RESPONSE &response) noexcept {
      std::lock_guard lock(mutex_);
      if (!direct_enabled_.load(std::memory_order_acquire)) {
        return STATUS_NOT_SUPPORTED;
      }
      const auto selected = lumen::vdd::frame::dequeue_ready_slot(
        slots_,
        mode_.delivery_policy == LUMEN_VDD_POLICY_LATENCY
      );
      if (!selected) {
        return STATUS_NO_MORE_ENTRIES;
      }

      auto &slot = slots_[*selected];
      if (!slot.color_transform) {
        return STATUS_INVALID_DEVICE_STATE;
      }
      response = {};
      response.generation = generation_;
      response.sequence = slot.sequence;
      response.producer_fence_value = slot.producer_fence_value;
      response.capture_qpc = slot.capture_qpc;
      response.producer_signal_qpc = slot.producer_signal_qpc;
      response.slot = static_cast<std::uint32_t>(*selected);
      response.color_transform_version = slot.color_transform->version;
      response.surface_color_space = slot.metadata.surface_color_space;
      response.sdr_white_level_nits = slot.metadata.sdr_white_level_nits;
      response.hdr_metadata_type = slot.metadata.hdr_metadata_type;
      response.hdr10_metadata = slot.metadata.hdr10_metadata;
      if (std::any_of(slots_.begin(), slots_.end(), [](const frame_slot_t &candidate) {
            return candidate.state == frame_slot_state_e::ready;
          })) {
        SetEvent(frame_ready_event_);
      }
      return STATUS_SUCCESS;
    }

    /** @brief Accept an exact host release and retain its GPU fence before reuse. */
    NTSTATUS release_frame(const LUMEN_VDD_RELEASE_FRAME_REQUEST &request) noexcept {
      std::lock_guard lock(mutex_);
      if (!direct_enabled_.load(std::memory_order_acquire)) {
        return STATUS_NOT_SUPPORTED;
      }
      if (request.generation != generation_ || request.slot >= slots_.size() ||
          request.reserved != 0 || request.producer_fence_value == std::numeric_limits<std::uint64_t>::max() ||
          request.consumer_fence_value != request.producer_fence_value + 1) {
        return STATUS_INVALID_PARAMETER;
      }
      auto &slot = slots_[request.slot];
      if (slot.state != frame_slot_state_e::acquired || slot.sequence != request.sequence ||
          slot.producer_fence_value != request.producer_fence_value) {
        return STATUS_REVISION_MISMATCH;
      }
      slot.consumer_fence_value = request.consumer_fence_value;
      slot.state = frame_slot_state_e::released_pending;
      return STATUS_SUCCESS;
    }

    /**
     * @brief Permanently disable direct frames for this generation and wake the host fallback.
     * @param failure GPU stage that failed closed.
     */
    void disable_direct_frames(
      lumen::vdd::frame::submission_result_e failure = lumen::vdd::frame::submission_result_e::signal_failed
    ) noexcept {
      direct_enabled_.store(false, std::memory_order_release);
      {
        std::lock_guard lock(mutex_);
        resources_ready_ = false;
        for (auto &slot : slots_) {
          slot.state = lumen::vdd::frame::complete_write(failure);
        }
      }
      SetEvent(frame_ready_event_);
    }

  private:
    /** @brief Validate and resolve metadata2 plus the current immutable transform for one frame. */
    bool resolve_frame_metadata(
      const IDDCX_METADATA2 &metadata,
      resolved_frame_metadata_t &resolved,
      std::shared_ptr<const color_transform_blob_t> &transform
    ) noexcept {
      resolved = {};
      const auto metadata_size = IDD_STRUCTURE_SIZE(IDDCX_METADATA2);
      constexpr auto required_metadata_end =
        FIELD_OFFSET(IDDCX_METADATA2, Hdr10FrameMetaData) + sizeof(IDDCX_HDR10_FRAME_METADATA);
      if (!lumen::vdd::color::valid_compatible_prefix(
            metadata.Size,
            metadata_size,
            sizeof(IDDCX_METADATA2),
            required_metadata_end
          ) ||
          metadata.HwProtectedSurface != FALSE ||
          metadata.SdrWhiteLevel < 80 || metadata.SdrWhiteLevel > 480) {
        return false;
      }
      if ((static_cast<UINT>(metadata.ValidFlags) &
           ~static_cast<UINT>(IDDCX_METADATA2_VALID_FLAGS_HDR10METADATA)) != 0) {
        return false;
      }
      resolved.sdr_white_level_nits = metadata.SdrWhiteLevel;
      if (mode_.dynamic_range == LUMEN_VDD_DYNAMIC_RANGE_HDR10) {
        if (metadata.SurfaceColorSpace != DXGI_COLOR_SPACE_RGB_FULL_G10_NONE_P709 ||
            (metadata.ValidFlags & IDDCX_METADATA2_VALID_FLAGS_HDR10METADATA) == 0) {
          return false;
        }
        resolved.surface_color_space = LUMEN_VDD_COLOR_SPACE_SCRGB;
      } else {
        if (metadata.SurfaceColorSpace != DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709 ||
            (metadata.ValidFlags & IDDCX_METADATA2_VALID_FLAGS_HDR10METADATA) != 0) {
          return false;
        }
        resolved.surface_color_space = LUMEN_VDD_COLOR_SPACE_SRGB;
      }

      std::lock_guard color_lock(color_state_->mutex);
      if (color_state_->generation != generation_ || !color_state_->current_transform) {
        return false;
      }
      transform = color_state_->current_transform;
      if (mode_.dynamic_range != LUMEN_VDD_DYNAMIC_RANGE_HDR10) {
        return true;
      }
      switch (metadata.Hdr10FrameMetaData.Type) {
        case IDDCX_HDR10_FRAME_METADATA_TYPE_DEFAULT:
          if (!color_state_->default_hdr10_metadata) {
            return false;
          }
          resolved.hdr_metadata_type = LUMEN_VDD_HDR_METADATA_DEFAULT;
          resolved.hdr10_metadata = *color_state_->default_hdr10_metadata;
          break;
        case IDDCX_HDR10_FRAME_METADATA_TYPE_UNCHANGED:
          if (!last_hdr10_metadata_) {
            return false;
          }
          resolved.hdr_metadata_type = LUMEN_VDD_HDR_METADATA_UNCHANGED;
          resolved.hdr10_metadata = *last_hdr10_metadata_;
          break;
        case IDDCX_HDR10_FRAME_METADATA_TYPE_NEW:
          resolved.hdr_metadata_type = LUMEN_VDD_HDR_METADATA_NEW;
          resolved.hdr10_metadata = copy_hdr10_metadata(metadata.Hdr10FrameMetaData.NewMetaData);
          if (!lumen::vdd::hdr::valid_hdr10_metadata(resolved.hdr10_metadata)) {
            return false;
          }
          break;
        default:
          return false;
      }
      last_hdr10_metadata_ = resolved.hdr10_metadata;
      return true;
    }

    /** @brief Create the fixed shareable slots after the IddCx D3D device is established. */
    bool initialize_resources(
      ID3D11Device *device,
      ID3D11DeviceContext4 *context,
      const LUID adapter_luid
    ) noexcept {
      ComPtr<ID3D11Device5> device5;
      if (FAILED(device->QueryInterface(IID_PPV_ARGS(&device5)))) {
        return false;
      }

      D3D11_TEXTURE2D_DESC texture_desc {};
      texture_desc.Width = mode_.width;
      texture_desc.Height = mode_.height;
      texture_desc.MipLevels = 1;
      texture_desc.ArraySize = 1;
      texture_desc.Format = mode_.dynamic_range == LUMEN_VDD_DYNAMIC_RANGE_HDR10 ?
                              DXGI_FORMAT_R16G16B16A16_FLOAT :
                              DXGI_FORMAT_B8G8R8A8_UNORM;
      texture_desc.SampleDesc.Count = 1;
      texture_desc.Usage = D3D11_USAGE_DEFAULT;
      texture_desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
      texture_desc.MiscFlags = D3D11_RESOURCE_MISC_SHARED_NTHANDLE | D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX;

      for (auto &slot : slots_) {
        ComPtr<IDXGIResource1> resource;
        if (FAILED(device->CreateTexture2D(&texture_desc, nullptr, &slot.texture)) ||
            FAILED(slot.texture.As(&resource)) ||
            FAILED(slot.texture.As(&slot.keyed_mutex)) ||
            FAILED(resource->CreateSharedHandle(
              nullptr,
              DXGI_SHARED_RESOURCE_READ | DXGI_SHARED_RESOURCE_WRITE,
              nullptr,
              &slot.texture_handle
            )) ||
            FAILED(device5->CreateFence(0, D3D11_FENCE_FLAG_SHARED, IID_PPV_ARGS(&slot.fence))) ||
            FAILED(slot.fence->CreateSharedHandle(nullptr, GENERIC_ALL, nullptr, &slot.fence_handle))) {
          return false;
        }
      }

      ComPtr<IUnknown> texture0_identity;
      ComPtr<IUnknown> texture1_identity;
      ComPtr<IUnknown> fence0_identity;
      ComPtr<IUnknown> fence1_identity;
      if (FAILED(slots_[0].texture.As(&texture0_identity)) ||
          FAILED(slots_[1].texture.As(&texture1_identity)) ||
          FAILED(slots_[0].fence.As(&fence0_identity)) ||
          FAILED(slots_[1].fence.As(&fence1_identity)) ||
          texture0_identity.Get() == texture1_identity.Get() ||
          fence0_identity.Get() == fence1_identity.Get() ||
          !lumen::vdd::frame::published_handles_are_distinct(
            reinterpret_cast<std::uintptr_t>(slots_[0].texture_handle),
            reinterpret_cast<std::uintptr_t>(slots_[1].texture_handle),
            reinterpret_cast<std::uintptr_t>(slots_[0].fence_handle),
            reinterpret_cast<std::uintptr_t>(slots_[1].fence_handle)
          )) {
        return false;
      }

      {
        std::lock_guard lock(mutex_);
        context4_ = context;
        adapter_luid_ = pack_luid(adapter_luid);
        resources_created_ = true;
      }
      return true;
    }

    /** @brief Select a safe slot according to the immutable session policy. */
    std::optional<std::size_t> select_slot(
      lumen::vdd::frame::producer_acquisition_t &acquisition
    ) noexcept {
      std::lock_guard lock(mutex_);
      const auto selected = lumen::vdd::frame::select_producer_slot(
        slots_,
        mode_.delivery_policy == LUMEN_VDD_POLICY_LATENCY
      );
      if (!selected.slot) {
        return std::nullopt;
      }
      acquisition = selected.acquisition;
      return selected.slot;
    }

    void run(LUID adapter_luid) noexcept {
      const auto swap_chain = swap_chain_.get();
      DWORD task_index = 0;
      HANDLE mmcss = AvSetMmThreadCharacteristicsW(L"Distribution", &task_index);

      ComPtr<IDXGIFactory1> factory;
      ComPtr<IDXGIAdapter> adapter;
      ComPtr<ID3D11Device> device;
      ComPtr<ID3D11DeviceContext> context;
      if (SUCCEEDED(CreateDXGIFactory1(IID_PPV_ARGS(&factory)))) {
        for (UINT index = 0; factory->EnumAdapters(index, &adapter) != DXGI_ERROR_NOT_FOUND; ++index) {
          DXGI_ADAPTER_DESC description {};
          if (SUCCEEDED(adapter->GetDesc(&description)) &&
              description.AdapterLuid.HighPart == adapter_luid.HighPart &&
              description.AdapterLuid.LowPart == adapter_luid.LowPart) {
            break;
          }
          adapter.Reset();
        }
      }

      D3D_FEATURE_LEVEL feature_level {};
      if (adapter == nullptr || FAILED(D3D11CreateDevice(
                                  adapter.Get(),
                                  D3D_DRIVER_TYPE_UNKNOWN,
                                  nullptr,
                                  D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                                  nullptr,
                                  0,
                                  D3D11_SDK_VERSION,
                                  &device,
                                  &feature_level,
                                  &context
                                ))) {
        disable_direct_frames(lumen::vdd::frame::submission_result_e::copy_failed);
        finish(mmcss);
        return;
      }

      ComPtr<IDXGIDevice> dxgi_device;
      if (FAILED(device.As(&dxgi_device))) {
        disable_direct_frames(lumen::vdd::frame::submission_result_e::copy_failed);
        finish(mmcss);
        return;
      }
      IDARG_IN_SWAPCHAINSETDEVICE set_device {};
      set_device.pDevice = dxgi_device.Get();
      if (FAILED(IddCxSwapChainSetDevice(swap_chain, &set_device))) {
        disable_direct_frames(lumen::vdd::frame::submission_result_e::copy_failed);
        finish(mmcss);
        return;
      }

      ComPtr<ID3D11DeviceContext4> context4;
      const bool direct_resources_supported = direct_enabled_.load(std::memory_order_acquire) &&
                                              SUCCEEDED(context.As(&context4)) &&
                                              initialize_resources(device.Get(), context4.Get(), adapter_luid);
      if (!direct_resources_supported) {
        disable_direct_frames(lumen::vdd::frame::submission_result_e::copy_failed);
      }

      const HANDLE waits[] {frame_event_, stop_event_.get()};
      while (WaitForSingleObject(stop_event_.get(), 0) != WAIT_OBJECT_0) {
        ComPtr<IDXGIResource> acquired_surface;
        IDDCX_METADATA2 frame_metadata {};
        HRESULT status = E_FAIL;
        if (hdr_runtime_available()) {
          IDARG_IN_RELEASEANDACQUIREBUFFER2 input {};
          input.Size = sizeof(input);
          input.AcquireSystemMemoryBuffer = FALSE;
          IDARG_OUT_RELEASEANDACQUIREBUFFER2 output {};
          status = IddCxSwapChainReleaseAndAcquireBuffer2(swap_chain, &input, &output);
          if (SUCCEEDED(status)) {
            frame_metadata = output.MetaData;
            acquired_surface.Attach(output.MetaData.pSurface);
          }
        } else {
          IDARG_OUT_RELEASEANDACQUIREBUFFER output {};
          status = IddCxSwapChainReleaseAndAcquireBuffer(swap_chain, &output);
          if (SUCCEEDED(status)) {
            frame_metadata.Size = sizeof(frame_metadata);
            frame_metadata.SurfaceColorSpace = DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709;
            frame_metadata.SdrWhiteLevel = 80;
            acquired_surface.Attach(output.MetaData.pSurface);
          }
        }
        if (status == E_PENDING) {
          const auto wait = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
          if (wait == WAIT_OBJECT_0) {
            continue;
          }
          if (wait == WAIT_OBJECT_0 + 1) {
            break;
          }
          disable_direct_frames(lumen::vdd::frame::submission_result_e::wait_failed);
          break;
        }
        if (FAILED(status)) {
          disable_direct_frames(lumen::vdd::frame::submission_result_e::copy_failed);
          break;
        }

        LARGE_INTEGER capture_qpc {};
        QueryPerformanceCounter(&capture_qpc);

        if (direct_resources_supported && direct_enabled_.load(std::memory_order_acquire)) {
          ComPtr<ID3D11Texture2D> source;
          D3D11_TEXTURE2D_DESC source_desc {};
          resolved_frame_metadata_t resolved_metadata;
          std::shared_ptr<const color_transform_blob_t> frame_transform;
          const bool metadata_valid =
            resolve_frame_metadata(frame_metadata, resolved_metadata, frame_transform);
          if (SUCCEEDED(acquired_surface.As(&source))) {
            source->GetDesc(&source_desc);
          }
          const auto expected_format = mode_.dynamic_range == LUMEN_VDD_DYNAMIC_RANGE_HDR10 ?
                                         DXGI_FORMAT_R16G16B16A16_FLOAT :
                                         DXGI_FORMAT_B8G8R8A8_UNORM;
          if (source && source_desc.Width == mode_.width && source_desc.Height == mode_.height &&
              source_desc.Format == expected_format && source_desc.MipLevels == 1 && metadata_valid &&
              source_desc.ArraySize == 1 && source_desc.SampleDesc.Count == 1) {
            lumen::vdd::frame::producer_acquisition_t acquisition;
            const auto selected = select_slot(acquisition);
            if (selected) {
              auto &slot = slots_[*selected];
              const bool keyed_acquired = slot.keyed_mutex->AcquireSync(acquisition.keyed_mutex_key, 0) == S_OK;
              const bool wait_complete = keyed_acquired &&
                                         (acquisition.consumer_fence_wait == 0 ||
                                          SUCCEEDED(context4_->Wait(
                                            slot.fence.Get(),
                                            acquisition.consumer_fence_wait
                                          )));
              if (wait_complete && slot.producer_fence_value <= std::numeric_limits<std::uint64_t>::max() - 2) {
                context->CopyResource(slot.texture.Get(), source.Get());
                if (FAILED(device->GetDeviceRemovedReason())) {
                  disable_direct_frames(lumen::vdd::frame::submission_result_e::copy_failed);
                  acquired_surface.Reset();
                  if (FAILED(IddCxSwapChainFinishedProcessingFrame(swap_chain))) {
                    break;
                  }
                  continue;
                }
                const auto producer_fence = slot.producer_fence_value == 0 ?
                                              1 :
                                              slot.producer_fence_value + 2;
                if (SUCCEEDED(context4_->Signal(slot.fence.Get(), producer_fence)) &&
                    slot.keyed_mutex->ReleaseSync(lumen::vdd::frame::host_acquire_key(producer_fence)) == S_OK) {
                  LARGE_INTEGER producer_signal_qpc {};
                  QueryPerformanceCounter(&producer_signal_qpc);
                  std::lock_guard lock(mutex_);
                  slot.sequence = ++next_sequence_;
                  slot.producer_fence_value = producer_fence;
                  slot.capture_qpc = capture_qpc.QuadPart;
                  slot.producer_signal_qpc = producer_signal_qpc.QuadPart;
                  slot.color_transform = std::move(frame_transform);
                  slot.metadata = resolved_metadata;
                  slot.state = lumen::vdd::frame::complete_write(
                    lumen::vdd::frame::submission_result_e::success
                  );
                  if (!resources_ready_) {
                    initial_metadata_ = resolved_metadata;
                    resources_ready_ = resources_created_;
                  }
                  SetEvent(frame_ready_event_);
                } else {
                  disable_direct_frames(lumen::vdd::frame::submission_result_e::signal_failed);
                }
              } else {
                disable_direct_frames(lumen::vdd::frame::submission_result_e::wait_failed);
              }
            }
          } else {
            disable_direct_frames(lumen::vdd::frame::submission_result_e::copy_failed);
          }
        }
        acquired_surface.Reset();
        if (FAILED(IddCxSwapChainFinishedProcessingFrame(swap_chain))) {
          disable_direct_frames(lumen::vdd::frame::submission_result_e::copy_failed);
          break;
        }
      }
      finish(mmcss);
    }

    void finish(HANDLE mmcss) noexcept {
      if (mmcss != nullptr) {
        AvRevertMmThreadCharacteristics(mmcss);
      }
      swap_chain_.reset();
    }

    lumen::vdd::single_delete_owner_t<IDDCX_SWAPCHAIN, swap_chain_deleter_t> swap_chain_;  ///< Worker-deleted swap chain.
    HANDLE frame_event_;  ///< IddCx next-surface event.
    std::uint64_t generation_ {};  ///< Immutable active generation.
    LUMEN_VDD_MODE mode_ {};  ///< Immutable exact mode and delivery policy.
    HANDLE frame_ready_event_ {};  ///< Borrowed generation event for resource/frame availability.
    std::shared_ptr<color_state_t> color_state_;  ///< Shared immutable transform/default metadata state.
    unique_handle_t stop_event_;  ///< Constructor-safe local termination event.
    std::thread worker_;  ///< Single measured-purpose swap-chain consumer.
    std::mutex mutex_;  ///< Serializes slot state and handle publication.
    ComPtr<ID3D11DeviceContext4> context4_;  ///< Driver context used for per-slot GPU waits.
    std::array<frame_slot_t, LUMEN_VDD_FRAME_SLOT_COUNT> slots_;  ///< Persistent shared slots.
    std::uint64_t adapter_luid_ {};  ///< Packed exact IddCx render-adapter LUID.
    std::uint64_t next_sequence_ {};  ///< Strictly increasing copied-frame sequence.
    std::optional<LUMEN_VDD_HDR10_METADATA> last_hdr10_metadata_;  ///< Effective metadata for UNCHANGED frames.
    resolved_frame_metadata_t initial_metadata_;  ///< First validated frame metadata for encoder creation.
    bool resources_created_ {};  ///< Whether every shareable texture/fence was created.
    bool resources_ready_ {};  ///< Whether first validated metadata and resources are publishable.
    std::atomic_bool direct_enabled_ {true};  ///< Sticky fail-closed state for this generation.
  };

  /** @brief Generation-fenced mutable driver state. */
  struct device_state_t {
    std::mutex mutex;  ///< Serializes every control and monitor transition.
    std::shared_ptr<monitor_descriptor_context_t> descriptor_context;  ///< Registered context-free parse state.
    std::shared_ptr<color_state_t> color_state;  ///< Generation color transform and default metadata.
    WDFDEVICE device {};  ///< Parent WDF device.
    IDDCX_ADAPTER adapter {};  ///< Initialized indirect adapter.
    NTSTATUS adapter_init_status {STATUS_DEVICE_NOT_READY};  ///< Latest immediate or asynchronous adapter status.
    IDDCX_MONITOR monitor {};  ///< Present monitor, or null.
    WDFFILEOBJECT owner_file {};  ///< Exclusive requestor file.
    WDFFILEOBJECT frame_consumer_file {};  ///< Exact generation-scoped direct-frame consumer.
    HANDLE frame_ready_event {};  ///< Auto-reset availability event for the active generation.
    std::unique_ptr<swap_chain_processor_t> swap_chain;  ///< Active swap-chain consumer.
    LUMEN_VDD_MODE mode {};  ///< Exact prepared mode.
    std::uint64_t generation {};  ///< Active generation.
    std::uint64_t last_generation {};  ///< Highest generation ever admitted.
    std::uint64_t preferred_render_adapter_luid {};  ///< Exact encoder adapter requested for this generation.
    std::uint64_t assigned_render_adapter_luid {};  ///< Exact adapter used by the most recent swap chain.
    std::uint32_t owner_process_id {};  ///< Exclusive service PID.
    std::atomic_bool exact_modes_published {false};  ///< Whether post-arrival target modes are exact.
    bool render_adapter_preference_submitted {};  ///< Whether the runtime preference API was called.
    bool monitor_starting {};  ///< Arrival is running without the state lock for synchronous IddCx callbacks.
    bool monitor_stopping {};  ///< Departure is running without the state lock for synchronous IddCx callbacks.
    bool monitor_started {};  ///< Whether arrival completed.
  };

  /** @brief Return true for a supported baseline mode. */
  bool valid_mode(const LUMEN_VDD_MODE &mode) noexcept {
    return lumen::vdd::mode::valid(mode);
  }

  /** Acquire the immutable prepared mode for context-free monitor-description callbacks. */
  std::optional<LUMEN_VDD_MODE> prepared_descriptor_mode() noexcept {
    std::shared_ptr<monitor_descriptor_context_t> context;
    {
      std::lock_guard lock(monitor_descriptor_registry_mutex);
      context = monitor_descriptor_registry.lock();
    }
    if (!context) {
      return std::nullopt;
    }
    std::lock_guard lock(context->mutex);
    if (!context->snapshot || context->snapshot->generation == 0 || !valid_mode(context->snapshot->mode)) {
      return std::nullopt;
    }
    return context->snapshot->mode;
  }

  /** @brief Pack a Windows adapter LUID without sign extension. */
  std::uint64_t pack_luid(const LUID luid) noexcept {
    return static_cast<std::uint64_t>(static_cast<std::uint32_t>(luid.HighPart)) << 32U |
           static_cast<std::uint64_t>(luid.LowPart);
  }

  /** @brief Unpack the fixed ABI representation into a Windows adapter LUID. */
  LUID unpack_luid(const std::uint64_t packed) noexcept {
    return {
      static_cast<DWORD>(packed),
      static_cast<LONG>(static_cast<std::uint32_t>(packed >> 32U)),
    };
  }

  /** @brief Return the exact WUDFHost creation FILETIME for PID-reuse-safe reverse duplication. */
  std::uint64_t current_process_creation_time() noexcept {
    FILETIME creation {};
    FILETIME exit {};
    FILETIME kernel {};
    FILETIME user {};
    if (!GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user)) {
      return 0;
    }
    return static_cast<std::uint64_t>(creation.dwHighDateTime) << 32U | creation.dwLowDateTime;
  }

  /** @brief Fill exact signal metadata for a dynamic mode. */
  DISPLAYCONFIG_VIDEO_SIGNAL_INFO signal_info(const LUMEN_VDD_MODE &mode, bool monitor_mode) noexcept {
    DISPLAYCONFIG_VIDEO_SIGNAL_INFO signal {};
    signal.activeSize = {mode.width, mode.height};
    if (mode.dynamic_range == LUMEN_VDD_DYNAMIC_RANGE_HDR10 &&
        lumen::vdd::hdr::modes_equal(mode, lumen::vdd::hdr::baseline_mode)) {
      signal.totalSize = {2200, 1125};
      signal.vSyncFreq = {60, 1};
      signal.hSyncFreq = {67500, 1};
      signal.pixelRate = 148500000;
      signal.scanLineOrdering = DISPLAYCONFIG_SCANLINE_ORDERING_PROGRESSIVE;
      signal.AdditionalSignalInfo.videoStandard = 16;
      signal.AdditionalSignalInfo.vSyncFreqDivider = monitor_mode ? 0 : 1;
      return signal;
    }
    signal.totalSize = signal.activeSize;
    signal.vSyncFreq = {mode.refresh_numerator, mode.refresh_denominator};
    const auto scan_lines_per_second =
      (static_cast<std::uint64_t>(mode.refresh_numerator) * mode.height + mode.refresh_denominator / 2U) /
      mode.refresh_denominator;
    signal.hSyncFreq = {static_cast<UINT32>(scan_lines_per_second), 1};
    signal.pixelRate =
      (static_cast<UINT64>(mode.width) * mode.height * mode.refresh_numerator + mode.refresh_denominator / 2U) /
      mode.refresh_denominator;
    signal.scanLineOrdering = DISPLAYCONFIG_SCANLINE_ORDERING_PROGRESSIVE;
    signal.AdditionalSignalInfo.videoStandard = 255;
    signal.AdditionalSignalInfo.vSyncFreqDivider = monitor_mode ? 0 : 1;
    return signal;
  }

  /** @brief Return whether Windows committed the exact target signal admitted for this generation. */
  bool target_signal_matches(
    const DISPLAYCONFIG_VIDEO_SIGNAL_INFO &actual,
    const LUMEN_VDD_MODE &mode
  ) noexcept {
    const auto expected = signal_info(mode, false);
    return actual.pixelRate == expected.pixelRate &&
           actual.hSyncFreq.Numerator == expected.hSyncFreq.Numerator &&
           actual.hSyncFreq.Denominator == expected.hSyncFreq.Denominator &&
           actual.vSyncFreq.Numerator == expected.vSyncFreq.Numerator &&
           actual.vSyncFreq.Denominator == expected.vSyncFreq.Denominator &&
           actual.activeSize.cx == expected.activeSize.cx && actual.activeSize.cy == expected.activeSize.cy &&
           actual.totalSize.cx == expected.totalSize.cx && actual.totalSize.cy == expected.totalSize.cy &&
           actual.AdditionalSignalInfo.videoStandard == expected.AdditionalSignalInfo.videoStandard &&
           actual.scanLineOrdering == expected.scanLineOrdering &&
           actual.AdditionalSignalInfo.vSyncFreqDivider == expected.AdditionalSignalInfo.vSyncFreqDivider;
  }

  IDDCX_MONITOR_MODE monitor_mode(const LUMEN_VDD_MODE &mode, IDDCX_MONITOR_MODE_ORIGIN origin) noexcept {
    IDDCX_MONITOR_MODE output {};
    output.Size = sizeof(output);
    output.Origin = origin;
    output.MonitorVideoSignalInfo = signal_info(mode, true);
    return output;
  }

  IDDCX_TARGET_MODE target_mode(const LUMEN_VDD_MODE &mode) noexcept {
    IDDCX_TARGET_MODE output {};
    output.Size = sizeof(output);
    output.TargetVideoSignalInfo.targetVideoSignalInfo = signal_info(mode, false);
    output.RequiredBandwidth = output.TargetVideoSignalInfo.targetVideoSignalInfo.pixelRate;
    return output;
  }

  /** Build one IddCx 1.10 monitor mode with exact RGB wire precision. */
  IDDCX_MONITOR_MODE2 monitor_mode2(
    const LUMEN_VDD_MODE &mode,
    const IDDCX_MONITOR_MODE_ORIGIN origin
  ) noexcept {
    IDDCX_MONITOR_MODE2 output {};
    output.Size = sizeof(output);
    output.Origin = origin;
    output.MonitorVideoSignalInfo = signal_info(mode, true);
    output.BitsPerComponent.Rgb = mode.bits_per_channel == 10 ?
                                    IDDCX_BITS_PER_COMPONENT_10 :
                                    IDDCX_BITS_PER_COMPONENT_8;
    return output;
  }

  /** Build one IddCx 1.10 target mode with exact RGB wire precision. */
  IDDCX_TARGET_MODE2 target_mode2(const LUMEN_VDD_MODE &mode) noexcept {
    IDDCX_TARGET_MODE2 output {};
    output.Size = sizeof(output);
    output.TargetVideoSignalInfo.targetVideoSignalInfo = signal_info(mode, false);
    output.RequiredBandwidth = output.TargetVideoSignalInfo.targetVideoSignalInfo.pixelRate;
    output.BitsPerComponent.Rgb = mode.bits_per_channel == 10 ?
                                    IDDCX_BITS_PER_COMPONENT_10 :
                                    IDDCX_BITS_PER_COMPONENT_8;
    return output;
  }

  /** @brief Complete a buffered request with an NTSTATUS. */
  void complete(WDFREQUEST request, NTSTATUS status, size_t information = 0) noexcept {
    WdfRequestCompleteWithInformation(request, status, information);
  }

  template<class T>
  T *request_input(WDFREQUEST request, size_t exact_size, NTSTATUS &status) noexcept {
    void *buffer = nullptr;
    size_t actual = 0;
    status = WdfRequestRetrieveInputBuffer(request, exact_size, &buffer, &actual);
    if (!NT_SUCCESS(status) || actual != exact_size) {
      status = STATUS_INFO_LENGTH_MISMATCH;
      return nullptr;
    }
    return static_cast<T *>(buffer);
  }

  template<class T>
  T *request_output(WDFREQUEST request, size_t exact_size, NTSTATUS &status) noexcept {
    void *buffer = nullptr;
    size_t actual = 0;
    status = WdfRequestRetrieveOutputBuffer(request, exact_size, &buffer, &actual);
    if (!NT_SUCCESS(status) || actual != exact_size) {
      status = STATUS_INFO_LENGTH_MISMATCH;
      return nullptr;
    }
    return static_cast<T *>(buffer);
  }

  /**
   * @brief Reset one exact owner, releasing the lock only for synchronous IddCx departure callbacks.
   * @param state Mutable device state protected by state_lock.
   * @param state_lock Owned state lock.
   * @param generation Exact generation being stopped.
   * @param file Exact owning file, unless recovery is true.
   * @param recovery Whether stale-owner recovery bypasses the file comparison.
   * @return Completion status for the complete departure and state reset.
   */
  NTSTATUS stop_locked(
    device_state_t &state,
    std::unique_lock<std::mutex> &state_lock,
    std::uint64_t generation,
    WDFFILEOBJECT file,
    bool recovery
  ) noexcept {
    if (state.generation == 0) {
      return STATUS_SUCCESS;
    }
    if (state.generation != generation || (!recovery && state.owner_file != file)) {
      return STATUS_ACCESS_DENIED;
    }
    if (state.monitor_starting || state.monitor_stopping) {
      return STATUS_DEVICE_BUSY;
    }
    state.swap_chain.reset();
    if (state.monitor != nullptr) {
      state.monitor_stopping = true;
      const auto monitor = state.monitor;
      state_lock.unlock();
      const auto status = IddCxMonitorDeparture(monitor);
      state_lock.lock();
      state.monitor_stopping = false;
      if (!NT_SUCCESS(status)) {
        return status;
      }
      state.monitor = nullptr;
    }
    state.monitor_started = false;
    state.owner_file = nullptr;
    state.frame_consumer_file = nullptr;
    state.owner_process_id = 0;
    state.preferred_render_adapter_luid = 0;
    state.assigned_render_adapter_luid = 0;
    state.render_adapter_preference_submitted = false;
    state.exact_modes_published.store(false, std::memory_order_release);
    if (state.frame_ready_event != nullptr) {
      CloseHandle(state.frame_ready_event);
      state.frame_ready_event = nullptr;
    }
    {
      std::lock_guard descriptor_lock(state.descriptor_context->mutex);
      if (state.descriptor_context->snapshot &&
          state.descriptor_context->snapshot->generation == generation) {
        state.descriptor_context->snapshot.reset();
      }
    }
    {
      std::lock_guard color_lock(state.color_state->mutex);
      if (state.color_state->generation == generation) {
        state.color_state->generation = 0;
        state.color_state->current_transform.reset();
        state.color_state->default_hdr10_metadata.reset();
      }
    }
    state.generation = 0;
    state.mode = {};
    return STATUS_SUCCESS;
  }

  /**
   * @brief Create and publish the one dynamic connector without blocking synchronous IddCx callbacks on the state lock.
   * @param state Mutable device state protected by state_lock.
   * @param state_lock Owned state lock.
   * @return Completion status for monitor creation and arrival.
   */
  NTSTATUS start_monitor_locked(device_state_t &state, std::unique_lock<std::mutex> &state_lock) noexcept {
    if (state.monitor_started && state.monitor != nullptr) {
      return STATUS_SUCCESS;
    }
    if (state.adapter == nullptr || state.generation == 0 || !valid_mode(state.mode)) {
      return STATUS_INVALID_DEVICE_STATE;
    }
    if (state.monitor_starting || state.monitor_stopping) {
      return STATUS_DEVICE_BUSY;
    }
    state.monitor_starting = true;
    const auto adapter = state.adapter;
    const auto mode = state.mode;
    if (mode.dynamic_range == LUMEN_VDD_DYNAMIC_RANGE_HDR10 && !hdr_runtime_available()) {
      state.monitor_starting = false;
      return STATUS_NOT_SUPPORTED;
    }

    IDDCX_MONITOR_INFO info {};
    info.Size = sizeof(info);
    info.MonitorType = DISPLAYCONFIG_OUTPUT_TECHNOLOGY_INDIRECT_WIRED;
    info.ConnectorIndex = 0;
    info.MonitorContainerId = GUID_CONTAINERID_LUMEN_VIRTUAL_DISPLAY_MONITOR;
    info.MonitorDescription.Size = sizeof(info.MonitorDescription);
    info.MonitorDescription.Type = IDDCX_MONITOR_DESCRIPTION_TYPE_EDID;
    if (mode.dynamic_range == LUMEN_VDD_DYNAMIC_RANGE_HDR10) {
      info.MonitorDescription.DataSize = static_cast<UINT>(lumen::vdd::hdr::edid.size());
      info.MonitorDescription.pData = const_cast<std::uint8_t *>(lumen::vdd::hdr::edid.data());
    }

    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, monitor_context_t);
    IDARG_IN_MONITORCREATE input {};
    input.ObjectAttributes = &attributes;
    input.pMonitorInfo = &info;
    IDARG_OUT_MONITORCREATE output {};
    state_lock.unlock();
    bool arrived = false;
    auto status = IddCxMonitorCreate(adapter, &input, &output);
    if (NT_SUCCESS(status)) {
      monitor_context(output.MonitorObject)->state = &state;
      IDARG_OUT_MONITORARRIVAL arrival {};
      status = IddCxMonitorArrival(output.MonitorObject, &arrival);
      arrived = NT_SUCCESS(status);
    }
    if (NT_SUCCESS(status) && mode.dynamic_range == LUMEN_VDD_DYNAMIC_RANGE_HDR10) {
      auto exact_target = target_mode2(mode);
      IDARG_IN_UPDATEMODES2 update {};
      update.Reason = IDDCX_UPDATE_REASON_CONFIGURATION_CONSTRAINTS;
      update.TargetModeCount = 1;
      update.pTargetModes = &exact_target;
      state.exact_modes_published.store(true, std::memory_order_release);
      status = IddCxMonitorUpdateModes2(output.MonitorObject, &update);
      if (!NT_SUCCESS(status)) {
        state.exact_modes_published.store(false, std::memory_order_release);
      }
    }
    if (!NT_SUCCESS(status) && output.MonitorObject != nullptr) {
      if (arrived) {
        const auto departure_status = IddCxMonitorDeparture(output.MonitorObject);
        if (!NT_SUCCESS(departure_status)) {
          status = departure_status;
        }
      } else {
        WdfObjectDelete(output.MonitorObject);
      }
    }
    state_lock.lock();
    state.monitor_starting = false;
    if (!NT_SUCCESS(status)) {
      return status;
    }
    state.monitor = output.MonitorObject;
    state.monitor_started = true;
    return STATUS_SUCCESS;
  }
}  // namespace

extern "C" DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD LumenVddDeviceAdd;
EVT_WDF_DEVICE_D0_ENTRY LumenVddDeviceD0Entry;
EVT_WDF_OBJECT_CONTEXT_CLEANUP LumenVddDeviceCleanup;
EVT_WDF_FILE_CLEANUP LumenVddFileCleanup;
EVT_IDD_CX_DEVICE_IO_CONTROL LumenVddDeviceIoControl;
EVT_IDD_CX_ADAPTER_INIT_FINISHED LumenVddAdapterInitFinished;
EVT_IDD_CX_ADAPTER_COMMIT_MODES LumenVddAdapterCommitModes;
EVT_IDD_CX_ADAPTER_COMMIT_MODES2 LumenVddAdapterCommitModes2;
EVT_IDD_CX_ADAPTER_QUERY_TARGET_INFO LumenVddAdapterQueryTargetInfo;
EVT_IDD_CX_PARSE_MONITOR_DESCRIPTION LumenVddParseMonitorDescription;
EVT_IDD_CX_PARSE_MONITOR_DESCRIPTION2 LumenVddParseMonitorDescription2;
EVT_IDD_CX_MONITOR_GET_DEFAULT_DESCRIPTION_MODES LumenVddMonitorGetDefaultModes;
EVT_IDD_CX_MONITOR_SET_DEFAULT_HDR_METADATA LumenVddMonitorSetDefaultHdrMetadata;
EVT_IDD_CX_MONITOR_SET_GAMMA_RAMP LumenVddMonitorSetGammaRamp;
EVT_IDD_CX_MONITOR_QUERY_TARGET_MODES LumenVddMonitorQueryTargetModes;
EVT_IDD_CX_MONITOR_QUERY_TARGET_MODES2 LumenVddMonitorQueryTargetModes2;
EVT_IDD_CX_MONITOR_ASSIGN_SWAPCHAIN LumenVddMonitorAssignSwapChain;
EVT_IDD_CX_MONITOR_UNASSIGN_SWAPCHAIN LumenVddMonitorUnassignSwapChain;

extern "C" BOOL WINAPI DllMain(HINSTANCE, UINT, LPVOID) {
  return TRUE;
}

_Use_decl_annotations_ extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
  WDF_DRIVER_CONFIG config;
  WDF_DRIVER_CONFIG_INIT(&config, LumenVddDeviceAdd);
  WDF_OBJECT_ATTRIBUTES attributes;
  WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
  return WdfDriverCreate(driver_object, registry_path, &attributes, &config, WDF_NO_HANDLE);
}

_Use_decl_annotations_
  NTSTATUS
  LumenVddDeviceAdd(WDFDRIVER driver, PWDFDEVICE_INIT device_init) {
  UNREFERENCED_PARAMETER(driver);
  WDF_PNPPOWER_EVENT_CALLBACKS power_callbacks;
  WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&power_callbacks);
  power_callbacks.EvtDeviceD0Entry = LumenVddDeviceD0Entry;
  WdfDeviceInitSetPnpPowerEventCallbacks(device_init, &power_callbacks);

  WDF_FILEOBJECT_CONFIG file_config;
  WDF_FILEOBJECT_CONFIG_INIT(&file_config, WDF_NO_EVENT_CALLBACK, WDF_NO_EVENT_CALLBACK, LumenVddFileCleanup);
  WdfDeviceInitSetFileObjectConfig(device_init, &file_config, WDF_NO_OBJECT_ATTRIBUTES);
  NTSTATUS status = STATUS_SUCCESS;

  IDD_CX_CLIENT_CONFIG idd_config;
  IDD_CX_CLIENT_CONFIG_INIT(&idd_config);
  idd_config.EvtIddCxDeviceIoControl = LumenVddDeviceIoControl;
  idd_config.EvtIddCxAdapterInitFinished = LumenVddAdapterInitFinished;
  idd_config.EvtIddCxAdapterCommitModes = LumenVddAdapterCommitModes;
  idd_config.EvtIddCxParseMonitorDescription = LumenVddParseMonitorDescription;
  idd_config.EvtIddCxMonitorGetDefaultDescriptionModes = LumenVddMonitorGetDefaultModes;
  idd_config.EvtIddCxMonitorQueryTargetModes = LumenVddMonitorQueryTargetModes;
  idd_config.EvtIddCxMonitorAssignSwapChain = LumenVddMonitorAssignSwapChain;
  idd_config.EvtIddCxMonitorUnassignSwapChain = LumenVddMonitorUnassignSwapChain;
  if (hdr_runtime_available()) {
    idd_config.EvtIddCxAdapterCommitModes2 = LumenVddAdapterCommitModes2;
    idd_config.EvtIddCxAdapterQueryTargetInfo = LumenVddAdapterQueryTargetInfo;
    idd_config.EvtIddCxParseMonitorDescription2 = LumenVddParseMonitorDescription2;
    idd_config.EvtIddCxMonitorSetDefaultHdrMetaData = LumenVddMonitorSetDefaultHdrMetadata;
    idd_config.EvtIddCxMonitorSetGammaRamp = LumenVddMonitorSetGammaRamp;
    idd_config.EvtIddCxMonitorQueryTargetModes2 = LumenVddMonitorQueryTargetModes2;
  }
  status = IddCxDeviceInitConfig(device_init, &idd_config);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  WDF_OBJECT_ATTRIBUTES attributes;
  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, device_context_t);
  attributes.EvtCleanupCallback = LumenVddDeviceCleanup;
  WDFDEVICE device = nullptr;
  status = WdfDeviceCreate(&device_init, &attributes, &device);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  status = IddCxDeviceInitialize(device);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  device_state_t *state = nullptr;
  try {
    auto pending_state = std::make_unique<device_state_t>();
    auto descriptor_context = std::make_shared<monitor_descriptor_context_t>();
    auto color_state = std::make_shared<color_state_t>();
    {
      std::lock_guard lock(monitor_descriptor_registry_mutex);
      if (!monitor_descriptor_registry.expired()) {
        return STATUS_DEVICE_BUSY;
      }
      monitor_descriptor_registry = descriptor_context;
    }
    pending_state->descriptor_context = std::move(descriptor_context);
    pending_state->color_state = std::move(color_state);
    state = pending_state.release();
  } catch (const std::bad_alloc &) {
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  state->device = device;
  device_context(device)->state = state;
  status = WdfDeviceCreateDeviceInterface(device, &GUID_DEVINTERFACE_LUMEN_VIRTUAL_DISPLAY, nullptr);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  return STATUS_SUCCESS;
}

_Use_decl_annotations_
  NTSTATUS
  LumenVddParseMonitorDescription(
    const IDARG_IN_PARSEMONITORDESCRIPTION *input,
    IDARG_OUT_PARSEMONITORDESCRIPTION *output
  ) {
  if (input->MonitorDescription.Type != IDDCX_MONITOR_DESCRIPTION_TYPE_EDID ||
      input->MonitorDescription.DataSize != lumen::vdd::hdr::edid.size() ||
      input->MonitorDescription.pData == nullptr ||
      std::memcmp(input->MonitorDescription.pData, lumen::vdd::hdr::edid.data(), lumen::vdd::hdr::edid.size()) != 0) {
    return STATUS_INVALID_PARAMETER;
  }
  const auto exact = prepared_descriptor_mode();
  if (!exact || exact->dynamic_range != LUMEN_VDD_DYNAMIC_RANGE_HDR10) {
    return STATUS_INVALID_DEVICE_STATE;
  }
  const auto modes = lumen::vdd::hdr::descriptor_modes(*exact);
  output->MonitorModeBufferOutputCount = static_cast<UINT>(modes.count);
  output->PreferredMonitorModeIdx = static_cast<UINT>(modes.preferred_index);
  if (input->MonitorModeBufferInputCount == 0) {
    return STATUS_SUCCESS;
  }
  if (input->MonitorModeBufferInputCount < modes.count || input->pMonitorModes == nullptr) {
    return STATUS_BUFFER_TOO_SMALL;
  }
  input->pMonitorModes[0] = monitor_mode(
    modes.modes[0],
    IDDCX_MONITOR_MODE_ORIGIN_MONITORDESCRIPTOR
  );
  if (modes.count == 2) {
    input->pMonitorModes[1] = monitor_mode(modes.modes[1], IDDCX_MONITOR_MODE_ORIGIN_DRIVER);
  }
  return STATUS_SUCCESS;
}

_Use_decl_annotations_
  NTSTATUS
  LumenVddParseMonitorDescription2(
    const IDARG_IN_PARSEMONITORDESCRIPTION2 *input,
    IDARG_OUT_PARSEMONITORDESCRIPTION *output
  ) {
  if (input->MonitorDescription.Type != IDDCX_MONITOR_DESCRIPTION_TYPE_EDID ||
      input->MonitorDescription.DataSize != lumen::vdd::hdr::edid.size() ||
      input->MonitorDescription.pData == nullptr ||
      std::memcmp(input->MonitorDescription.pData, lumen::vdd::hdr::edid.data(), lumen::vdd::hdr::edid.size()) != 0) {
    return STATUS_INVALID_PARAMETER;
  }
  const auto exact = prepared_descriptor_mode();
  if (!exact || exact->dynamic_range != LUMEN_VDD_DYNAMIC_RANGE_HDR10) {
    return STATUS_INVALID_DEVICE_STATE;
  }
  const auto modes = lumen::vdd::hdr::descriptor_modes(*exact);
  output->MonitorModeBufferOutputCount = static_cast<UINT>(modes.count);
  output->PreferredMonitorModeIdx = static_cast<UINT>(modes.preferred_index);
  if (input->MonitorModeBufferInputCount == 0) {
    return STATUS_SUCCESS;
  }
  if (input->MonitorModeBufferInputCount < modes.count || input->pMonitorModes == nullptr) {
    return STATUS_BUFFER_TOO_SMALL;
  }
  input->pMonitorModes[0] = monitor_mode2(
    modes.modes[0],
    IDDCX_MONITOR_MODE_ORIGIN_MONITORDESCRIPTOR
  );
  if (modes.count == 2) {
    input->pMonitorModes[1] = monitor_mode2(modes.modes[1], IDDCX_MONITOR_MODE_ORIGIN_DRIVER);
  }
  return STATUS_SUCCESS;
}

_Use_decl_annotations_
  NTSTATUS
  LumenVddDeviceD0Entry(WDFDEVICE device, WDF_POWER_DEVICE_STATE previous_state) {
  UNREFERENCED_PARAMETER(previous_state);
  auto *state = device_context(device)->state;
  if (state == nullptr) {
    return STATUS_INVALID_DEVICE_STATE;
  }
  {
    std::lock_guard lock(state->mutex);
    if (state->adapter != nullptr) {
      return STATUS_SUCCESS;
    }
    state->adapter_init_status = STATUS_PENDING;
  }

  IDDCX_ADAPTER_CAPS capabilities {};
  capabilities.Size = sizeof(capabilities);
  if (hdr_runtime_available()) {
    capabilities.Flags = IDDCX_ADAPTER_FLAGS_CAN_PROCESS_FP16;
  }
  capabilities.MaxMonitorsSupported = 1;
  capabilities.MaxDisplayPipelineRate = static_cast<UINT64>(LUMEN_VDD_MAX_WIDTH) * LUMEN_VDD_MAX_HEIGHT * 480ULL;
  capabilities.EndPointDiagnostics.Size = sizeof(capabilities.EndPointDiagnostics);
  capabilities.EndPointDiagnostics.GammaSupport = hdr_runtime_available() ?
                                                    IDDCX_FEATURE_IMPLEMENTATION_SOFTWARE :
                                                    IDDCX_FEATURE_IMPLEMENTATION_NONE;
  capabilities.EndPointDiagnostics.TransmissionType = IDDCX_TRANSMISSION_TYPE_WIRED_OTHER;
  capabilities.EndPointDiagnostics.pEndPointFriendlyName = endpoint_model;
  capabilities.EndPointDiagnostics.pEndPointModelName = endpoint_model;
  capabilities.EndPointDiagnostics.pEndPointManufacturerName = endpoint_manufacturer;
  IDDCX_ENDPOINT_VERSION version {};
  version.Size = sizeof(version);
  version.MajorVer = 1;
  version.MinorVer = 0;
  capabilities.EndPointDiagnostics.pFirmwareVersion = &version;
  capabilities.EndPointDiagnostics.pHardwareVersion = &version;

  WDF_OBJECT_ATTRIBUTES adapter_attributes;
  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&adapter_attributes, adapter_context_t);
  IDARG_IN_ADAPTER_INIT adapter_input {};
  adapter_input.WdfDevice = state->device;
  adapter_input.pCaps = &capabilities;
  adapter_input.ObjectAttributes = &adapter_attributes;
  IDARG_OUT_ADAPTER_INIT adapter_output {};
  const auto status = IddCxAdapterInitAsync(&adapter_input, &adapter_output);
  {
    std::lock_guard lock(state->mutex);
    state->adapter_init_status = status;
    if (NT_SUCCESS(status)) {
      state->adapter = adapter_output.AdapterObject;
      adapter_context(adapter_output.AdapterObject)->state = state;
    }
  }
  return STATUS_SUCCESS;
}

_Use_decl_annotations_ void LumenVddDeviceCleanup(WDFOBJECT object) {
  auto *context = device_context(object);
  if (context->state != nullptr) {
    {
      std::unique_lock lock(context->state->mutex);
      if (context->state->generation != 0) {
        static_cast<void>(
          stop_locked(*context->state, lock, context->state->generation, context->state->owner_file, true)
        );
      }
    }
    {
      std::lock_guard lock(monitor_descriptor_registry_mutex);
      if (monitor_descriptor_registry.lock() == context->state->descriptor_context) {
        monitor_descriptor_registry.reset();
      }
    }
    delete context->state;
    context->state = nullptr;
  }
}

_Use_decl_annotations_ void LumenVddFileCleanup(WDFFILEOBJECT file_object) {
  auto *state = device_context(WdfFileObjectGetDevice(file_object))->state;
  std::unique_lock lock(state->mutex);
  if (state->owner_file == file_object && state->generation != 0) {
    static_cast<void>(stop_locked(*state, lock, state->generation, file_object, false));
  } else if (state->frame_consumer_file == file_object) {
    state->frame_consumer_file = nullptr;
    if (state->swap_chain != nullptr) {
      state->swap_chain->disable_direct_frames();
    }
  }
}

_Use_decl_annotations_ void LumenVddDeviceIoControl(
  WDFDEVICE device,
  WDFREQUEST request,
  size_t output_buffer_length,
  size_t input_buffer_length,
  ULONG control_code
) {
  auto *state = device_context(device)->state;
  WDFFILEOBJECT file = WdfRequestGetFileObject(request);
  NTSTATUS status = STATUS_SUCCESS;
  size_t information = 0;
  std::unique_lock lock(state->mutex);

  switch (control_code) {
    case IOCTL_LUMEN_VDD_QUERY_ABI:
      {
        if (input_buffer_length != 0 || output_buffer_length != sizeof(LUMEN_VDD_QUERY_ABI_RESPONSE)) {
          status = STATUS_INFO_LENGTH_MISMATCH;
          break;
        }
        auto *output = request_output<LUMEN_VDD_QUERY_ABI_RESPONSE>(request, sizeof(LUMEN_VDD_QUERY_ABI_RESPONSE), status);
        if (output == nullptr) {
          break;
        }
        const auto capability_flags =
          LUMEN_VDD_CAP_DYNAMIC_MODES | LUMEN_VDD_CAP_SDR8 | LUMEN_VDD_CAP_DIRECT_FRAME_V1 |
          LUMEN_VDD_CAP_LOSSLESS |
          (IDD_IS_FUNCTION_AVAILABLE(IddCxAdapterSetRenderAdapter) ? LUMEN_VDD_CAP_RENDER_ADAPTER_PREFERENCE : 0U) |
          (hdr_runtime_available() ?
             LUMEN_VDD_CAP_HDR10 | LUMEN_VDD_CAP_10BIT | LUMEN_VDD_CAP_DIRECT_FRAME_FP16 |
               LUMEN_VDD_CAP_FRAME_METADATA_V2 | LUMEN_VDD_CAP_COLOR_TRANSFORM_V1 :
             0U);
        *output = {
          LUMEN_VDD_ABI_VERSION,
          capability_flags,
          256,
          LUMEN_VDD_MAX_WIDTH,
          200,
          LUMEN_VDD_MAX_HEIGHT,
          10,
          1,
          480,
          1,
          static_cast<std::uint64_t>(LUMEN_VDD_MAX_WIDTH) * LUMEN_VDD_MAX_HEIGHT,
          static_cast<std::uint64_t>(LUMEN_VDD_MAX_WIDTH) * LUMEN_VDD_MAX_HEIGHT * 480ULL,
        };
        information = sizeof(*output);
        break;
      }
    case IOCTL_LUMEN_VDD_QUERY_STATE:
      {
        if (input_buffer_length != 0 || output_buffer_length != sizeof(LUMEN_VDD_QUERY_STATE_RESPONSE)) {
          status = STATUS_INFO_LENGTH_MISMATCH;
          break;
        }
        auto *output = request_output<LUMEN_VDD_QUERY_STATE_RESPONSE>(request, sizeof(LUMEN_VDD_QUERY_STATE_RESPONSE), status);
        if (output != nullptr) {
          *output = {
            state->generation,
            state->owner_process_id,
            state->monitor_started ? 1U : 0U,
            state->mode,
            state->last_generation,
            state->preferred_render_adapter_luid,
            state->assigned_render_adapter_luid,
            state->render_adapter_preference_submitted ? 1U : 0U,
            0,
          };
          information = sizeof(*output);
        }
        break;
      }
    case IOCTL_LUMEN_VDD_PREPARE_MODE:
      {
        if (input_buffer_length != sizeof(LUMEN_VDD_PREPARE_MODE_REQUEST) ||
            output_buffer_length != sizeof(LUMEN_VDD_PREPARE_MODE_RESPONSE)) {
          status = STATUS_INFO_LENGTH_MISMATCH;
          break;
        }
        auto *input = request_input<LUMEN_VDD_PREPARE_MODE_REQUEST>(request, sizeof(LUMEN_VDD_PREPARE_MODE_REQUEST), status);
        auto *output = request_output<LUMEN_VDD_PREPARE_MODE_RESPONSE>(request, sizeof(LUMEN_VDD_PREPARE_MODE_RESPONSE), status);
        const auto requestor_pid = static_cast<std::uint32_t>(WdfRequestGetRequestorProcessId(request));
        if (input == nullptr || output == nullptr) {
          break;
        }
        if (input->reserved != 0 || input->owner_process_id != requestor_pid || input->generation == 0 ||
            input->preferred_render_adapter_luid == 0 || !valid_mode(input->mode)) {
          status = STATUS_INVALID_PARAMETER;
          break;
        }
        if (input->mode.dynamic_range == LUMEN_VDD_DYNAMIC_RANGE_HDR10 && !hdr_runtime_available()) {
          status = STATUS_NOT_SUPPORTED;
          break;
        }
        if (state->adapter == nullptr || !NT_SUCCESS(state->adapter_init_status)) {
          status = STATUS_DEVICE_NOT_READY;
          break;
        }
        if (state->generation != 0) {
          if (state->generation != input->generation || state->owner_file != file ||
              state->preferred_render_adapter_luid != input->preferred_render_adapter_luid ||
              std::memcmp(&state->mode, &input->mode, sizeof(input->mode)) != 0) {
            status = STATUS_DEVICE_BUSY;
            break;
          }
        } else {
          if (input->generation <= state->last_generation) {
            status = STATUS_REVISION_MISMATCH;
            break;
          }
          HANDLE frame_ready_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
          if (frame_ready_event == nullptr) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
          }
          std::shared_ptr<const color_transform_blob_t> default_transform;
          try {
            default_transform = default_color_transform();
          } catch (const std::bad_alloc &) {
            CloseHandle(frame_ready_event);
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
          }
          state->generation = input->generation;
          state->last_generation = input->generation;
          state->owner_process_id = requestor_pid;
          state->owner_file = file;
          state->frame_ready_event = frame_ready_event;
          state->mode = input->mode;
          state->preferred_render_adapter_luid = input->preferred_render_adapter_luid;
          state->assigned_render_adapter_luid = 0;
          state->exact_modes_published.store(false, std::memory_order_release);
          state->render_adapter_preference_submitted = false;
          {
            std::lock_guard descriptor_lock(state->descriptor_context->mutex);
            state->descriptor_context->snapshot = monitor_descriptor_snapshot_t {
              state->generation,
              state->mode,
            };
          }
          {
            std::lock_guard color_lock(state->color_state->mutex);
            state->color_state->generation = state->generation;
            state->color_state->next_transform_version = 2;
            state->color_state->current_transform = std::move(default_transform);
            state->color_state->default_hdr10_metadata.reset();
          }
          if (IDD_IS_FUNCTION_AVAILABLE(IddCxAdapterSetRenderAdapter)) {
            const IDARG_IN_ADAPTERSETRENDERADAPTER render_adapter {
              unpack_luid(state->preferred_render_adapter_luid),
            };
            IddCxAdapterSetRenderAdapter(state->adapter, &render_adapter);
            state->render_adapter_preference_submitted = true;
          }
        }
        *output = {};
        output->mode = state->mode;
        output->fidelity = LUMEN_VDD_FIDELITY_LOSSLESS;
        output->render_adapter_preference_submitted = state->render_adapter_preference_submitted ? 1U : 0U;
        output->preferred_render_adapter_luid = state->preferred_render_adapter_luid;
        std::memcpy(output->connector_id_utf8, connector_id, sizeof(connector_id));
        information = sizeof(*output);
        break;
      }
    case IOCTL_LUMEN_VDD_START_MONITOR:
      {
        auto *input = request_input<LUMEN_VDD_GENERATION_REQUEST>(request, sizeof(LUMEN_VDD_GENERATION_REQUEST), status);
        if (input == nullptr || input_buffer_length != sizeof(*input) || output_buffer_length != 0) {
          status = STATUS_INFO_LENGTH_MISMATCH;
          break;
        }
        if (state->generation != input->generation || state->owner_file != file) {
          status = STATUS_ACCESS_DENIED;
          break;
        }
        status = start_monitor_locked(*state, lock);
        break;
      }
    case IOCTL_LUMEN_VDD_STOP_MONITOR:
      {
        auto *input = request_input<LUMEN_VDD_GENERATION_REQUEST>(request, sizeof(LUMEN_VDD_GENERATION_REQUEST), status);
        if (input == nullptr || input_buffer_length != sizeof(*input) || output_buffer_length != 0) {
          status = STATUS_INFO_LENGTH_MISMATCH;
          break;
        }
        status = stop_locked(*state, lock, input->generation, file, false);
        break;
      }
    case IOCTL_LUMEN_VDD_RECOVER_STALE:
      {
        auto *input = request_input<LUMEN_VDD_GENERATION_REQUEST>(request, sizeof(LUMEN_VDD_GENERATION_REQUEST), status);
        if (input == nullptr || input_buffer_length != sizeof(*input) || output_buffer_length != 0) {
          status = STATUS_INFO_LENGTH_MISMATCH;
          break;
        }
        if (state->generation != input->generation || state->owner_process_id == 0) {
          status = STATUS_REVISION_MISMATCH;
          break;
        }
        HANDLE owner = OpenProcess(SYNCHRONIZE, FALSE, state->owner_process_id);
        if (owner != nullptr) {
          const auto wait = WaitForSingleObject(owner, 0);
          CloseHandle(owner);
          if (wait == WAIT_TIMEOUT) {
            status = STATUS_DEVICE_BUSY;
            break;
          }
          if (wait != WAIT_OBJECT_0) {
            status = STATUS_UNSUCCESSFUL;
            break;
          }
        } else {
          const auto error = GetLastError();
          if (error != ERROR_INVALID_PARAMETER) {
            status = error == ERROR_ACCESS_DENIED ? STATUS_ACCESS_DENIED : STATUS_UNSUCCESSFUL;
            break;
          }
        }
        status = stop_locked(*state, lock, input->generation, state->owner_file, true);
        break;
      }
    case IOCTL_LUMEN_VDD_OPEN_FRAME_CHANNEL:
      {
        if (input_buffer_length != sizeof(LUMEN_VDD_OPEN_FRAME_CHANNEL_REQUEST) ||
            output_buffer_length != sizeof(LUMEN_VDD_OPEN_FRAME_CHANNEL_RESPONSE)) {
          status = STATUS_INFO_LENGTH_MISMATCH;
          break;
        }
        auto *input = request_input<LUMEN_VDD_OPEN_FRAME_CHANNEL_REQUEST>(
          request,
          sizeof(LUMEN_VDD_OPEN_FRAME_CHANNEL_REQUEST),
          status
        );
        auto *output = request_output<LUMEN_VDD_OPEN_FRAME_CHANNEL_RESPONSE>(
          request,
          sizeof(LUMEN_VDD_OPEN_FRAME_CHANNEL_RESPONSE),
          status
        );
        const auto requestor_pid = static_cast<std::uint32_t>(WdfRequestGetRequestorProcessId(request));
        if (input == nullptr || output == nullptr) {
          break;
        }
        if (input->reserved != 0 || input->generation != state->generation ||
            input->owner_process_id != requestor_pid || requestor_pid != state->owner_process_id) {
          status = STATUS_ACCESS_DENIED;
          break;
        }
        if (state->frame_consumer_file != nullptr && state->frame_consumer_file != file) {
          status = STATUS_DEVICE_BUSY;
          break;
        }
        state->frame_consumer_file = file;
        if (state->swap_chain == nullptr) {
          status = STATUS_DEVICE_NOT_READY;
          break;
        }
        status = state->swap_chain->open_frame_channel(*output);
        if (NT_SUCCESS(status)) {
          information = sizeof(*output);
        }
        break;
      }
    case IOCTL_LUMEN_VDD_DEQUEUE_FRAME:
      {
        if (input_buffer_length != sizeof(LUMEN_VDD_DEQUEUE_FRAME_REQUEST) ||
            output_buffer_length != sizeof(LUMEN_VDD_DEQUEUE_FRAME_RESPONSE)) {
          status = STATUS_INFO_LENGTH_MISMATCH;
          break;
        }
        auto *input = request_input<LUMEN_VDD_DEQUEUE_FRAME_REQUEST>(
          request,
          sizeof(LUMEN_VDD_DEQUEUE_FRAME_REQUEST),
          status
        );
        auto *output = request_output<LUMEN_VDD_DEQUEUE_FRAME_RESPONSE>(
          request,
          sizeof(LUMEN_VDD_DEQUEUE_FRAME_RESPONSE),
          status
        );
        const auto requestor_pid = static_cast<std::uint32_t>(WdfRequestGetRequestorProcessId(request));
        if (input == nullptr || output == nullptr) {
          break;
        }
        if (input->generation != state->generation || requestor_pid != state->owner_process_id ||
            state->frame_consumer_file != file) {
          status = STATUS_REVISION_MISMATCH;
          break;
        }
        if (state->swap_chain == nullptr) {
          status = STATUS_DEVICE_NOT_READY;
          break;
        }
        status = state->swap_chain->dequeue_frame(*output);
        if (NT_SUCCESS(status)) {
          information = sizeof(*output);
        }
        break;
      }
    case IOCTL_LUMEN_VDD_RELEASE_FRAME:
      {
        if (input_buffer_length != sizeof(LUMEN_VDD_RELEASE_FRAME_REQUEST) || output_buffer_length != 0) {
          status = STATUS_INFO_LENGTH_MISMATCH;
          break;
        }
        auto *input = request_input<LUMEN_VDD_RELEASE_FRAME_REQUEST>(
          request,
          sizeof(LUMEN_VDD_RELEASE_FRAME_REQUEST),
          status
        );
        const auto requestor_pid = static_cast<std::uint32_t>(WdfRequestGetRequestorProcessId(request));
        if (input == nullptr) {
          break;
        }
        if (input->generation != state->generation || requestor_pid != state->owner_process_id ||
            state->frame_consumer_file != file) {
          status = STATUS_REVISION_MISMATCH;
          break;
        }
        if (state->swap_chain == nullptr) {
          status = STATUS_DEVICE_NOT_READY;
          break;
        }
        status = state->swap_chain->release_frame(*input);
        break;
      }
    case IOCTL_LUMEN_VDD_QUERY_COLOR_TRANSFORM:
      {
        if (input_buffer_length != sizeof(LUMEN_VDD_QUERY_COLOR_TRANSFORM_REQUEST) ||
            output_buffer_length != sizeof(LUMEN_VDD_QUERY_COLOR_TRANSFORM_RESPONSE)) {
          status = STATUS_INFO_LENGTH_MISMATCH;
          break;
        }
        auto *input = request_input<LUMEN_VDD_QUERY_COLOR_TRANSFORM_REQUEST>(
          request,
          sizeof(LUMEN_VDD_QUERY_COLOR_TRANSFORM_REQUEST),
          status
        );
        auto *output = request_output<LUMEN_VDD_QUERY_COLOR_TRANSFORM_RESPONSE>(
          request,
          sizeof(LUMEN_VDD_QUERY_COLOR_TRANSFORM_RESPONSE),
          status
        );
        const auto requestor_pid = static_cast<std::uint32_t>(WdfRequestGetRequestorProcessId(request));
        if (input == nullptr || output == nullptr) {
          break;
        }
        if (input->generation != state->generation || input->transform_version == 0 ||
            requestor_pid != state->owner_process_id || state->frame_consumer_file != file) {
          status = STATUS_REVISION_MISMATCH;
          break;
        }
        if (state->swap_chain == nullptr) {
          status = STATUS_DEVICE_NOT_READY;
          break;
        }
        status = state->swap_chain->query_color_transform(input->transform_version, *output);
        if (NT_SUCCESS(status)) {
          information = sizeof(*output);
        }
        break;
      }
    case IOCTL_LUMEN_VDD_OPEN_FRAME_EVENT:
      {
        if (input_buffer_length != sizeof(LUMEN_VDD_OPEN_FRAME_CHANNEL_REQUEST) ||
            output_buffer_length != sizeof(LUMEN_VDD_OPEN_FRAME_EVENT_RESPONSE)) {
          status = STATUS_INFO_LENGTH_MISMATCH;
          break;
        }
        auto *input = request_input<LUMEN_VDD_OPEN_FRAME_CHANNEL_REQUEST>(
          request,
          sizeof(LUMEN_VDD_OPEN_FRAME_CHANNEL_REQUEST),
          status
        );
        auto *output = request_output<LUMEN_VDD_OPEN_FRAME_EVENT_RESPONSE>(
          request,
          sizeof(LUMEN_VDD_OPEN_FRAME_EVENT_RESPONSE),
          status
        );
        const auto requestor_pid = static_cast<std::uint32_t>(WdfRequestGetRequestorProcessId(request));
        if (input == nullptr || output == nullptr) {
          break;
        }
        if (input->reserved != 0 || input->generation != state->generation ||
            input->owner_process_id != requestor_pid || requestor_pid != state->owner_process_id ||
            state->frame_ready_event == nullptr) {
          status = STATUS_ACCESS_DENIED;
          break;
        }
        if (state->frame_consumer_file != nullptr && state->frame_consumer_file != file) {
          status = STATUS_DEVICE_BUSY;
          break;
        }
        state->frame_consumer_file = file;
        const auto source_creation_time = current_process_creation_time();
        if (source_creation_time == 0) {
          status = STATUS_UNSUCCESSFUL;
          break;
        }
        *output = {
          state->generation,
          GetCurrentProcessId(),
          0,
          source_creation_time,
          reinterpret_cast<std::uint64_t>(state->frame_ready_event),
          0,
        };
        information = sizeof(*output);
        break;
      }
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
  }
  complete(request, status, NT_SUCCESS(status) ? information : 0);
}

_Use_decl_annotations_
  NTSTATUS
  LumenVddAdapterInitFinished(IDDCX_ADAPTER adapter, const IDARG_IN_ADAPTER_INIT_FINISHED *input) {
  auto *state = adapter_context(adapter)->state;
  std::lock_guard lock(state->mutex);
  state->adapter_init_status = input->AdapterInitStatus;
  if (!NT_SUCCESS(state->adapter_init_status)) {
    state->adapter = nullptr;
  }
  return STATUS_SUCCESS;
}

_Use_decl_annotations_
  NTSTATUS
  LumenVddAdapterCommitModes(IDDCX_ADAPTER adapter, const IDARG_IN_COMMITMODES *input) {
  auto *state = adapter_context(adapter)->state;
  std::lock_guard lock(state->mutex);
  if (state->mode.dynamic_range == LUMEN_VDD_DYNAMIC_RANGE_HDR10) {
    return STATUS_NOT_SUPPORTED;
  }
  if (input->PathCount != 0 && input->pPaths == nullptr) {
    return STATUS_INVALID_PARAMETER;
  }
  std::uint32_t active_paths = 0;
  for (std::uint32_t index = 0; index < input->PathCount; ++index) {
    const auto &path = input->pPaths[index];
    if (path.Size != sizeof(path) || path.MonitorObject == nullptr ||
        monitor_context(path.MonitorObject)->state != state) {
      return STATUS_INVALID_PARAMETER;
    }
    if ((path.Flags & IDDCX_PATH_FLAGS_ACTIVE) == IDDCX_PATH_FLAGS_NONE) {
      continue;
    }
    ++active_paths;
    if (active_paths > 1 || state->generation == 0 || !valid_mode(state->mode) ||
        !target_signal_matches(path.TargetVideoSignalInfo, state->mode)) {
      return STATUS_INVALID_PARAMETER;
    }
  }
  return STATUS_SUCCESS;
}

_Use_decl_annotations_
  NTSTATUS
  LumenVddAdapterQueryTargetInfo(
    IDDCX_ADAPTER adapter,
    IDARG_IN_QUERYTARGET_INFO *input,
    IDARG_OUT_QUERYTARGET_INFO *output
  ) {
  UNREFERENCED_PARAMETER(adapter);
  if (input->ConnectorIndex != 0) {
    return STATUS_INVALID_PARAMETER;
  }
  output->TargetCaps = IDDCX_TARGET_CAPS_WIDE_COLOR_SPACE | IDDCX_TARGET_CAPS_HIGH_COLOR_SPACE;
  output->DitheringSupport = {};
  return STATUS_SUCCESS;
}

_Use_decl_annotations_
  NTSTATUS
  LumenVddAdapterCommitModes2(IDDCX_ADAPTER adapter, const IDARG_IN_COMMITMODES2 *input) {
  auto *state = adapter_context(adapter)->state;
  std::lock_guard lock(state->mutex);
  if (input->PathCount != 0 && input->pPaths == nullptr) {
    return STATUS_INVALID_PARAMETER;
  }
  std::uint32_t active_paths = 0;
  for (std::uint32_t index = 0; index < input->PathCount; ++index) {
    const auto &path = input->pPaths[index];
    if (path.Size != sizeof(path) || path.MonitorObject == nullptr ||
        monitor_context(path.MonitorObject)->state != state) {
      return STATUS_INVALID_PARAMETER;
    }
    if ((path.Flags & IDDCX_PATH_FLAGS_ACTIVE) == IDDCX_PATH_FLAGS_NONE) {
      continue;
    }
    ++active_paths;
    const auto expected_color_space = state->mode.dynamic_range == LUMEN_VDD_DYNAMIC_RANGE_HDR10 ?
                                        IDDCX_COLOR_SPACE_G2084_P2020 :
                                        IDDCX_COLOR_SPACE_G22_P709;
    const auto expected_bpc = state->mode.bits_per_channel == 10 ?
                                IDDCX_BITS_PER_COMPONENT_10 :
                                IDDCX_BITS_PER_COMPONENT_8;
    if (active_paths > 1 || state->generation == 0 || !valid_mode(state->mode) ||
        !target_signal_matches(path.TargetVideoSignalInfo, state->mode) ||
        path.WireFormatInfo.ColorSpace != expected_color_space ||
        path.WireFormatInfo.BitsPerComponent.Rgb != expected_bpc ||
        path.WireFormatInfo.BitsPerComponent.YCbCr444 != IDDCX_BITS_PER_COMPONENT_NONE ||
        path.WireFormatInfo.BitsPerComponent.YCbCr422 != IDDCX_BITS_PER_COMPONENT_NONE ||
        path.WireFormatInfo.BitsPerComponent.YCbCr420 != IDDCX_BITS_PER_COMPONENT_NONE) {
      return STATUS_INVALID_PARAMETER;
    }
  }
  return STATUS_SUCCESS;
}

_Use_decl_annotations_
  NTSTATUS
  LumenVddMonitorSetDefaultHdrMetadata(
    IDDCX_MONITOR monitor,
    const IDARG_IN_MONITOR_SET_DEFAULT_HDR_METADATA *input
  ) {
  auto *state = monitor_context(monitor)->state;
  if (input->Type != IDDCX_HDRMETADATA_TYPE_HDR10 || input->Size != sizeof(IDDCX_HDR10_METADATA) ||
      input->Data.pHdr10 == nullptr) {
    return STATUS_INVALID_PARAMETER;
  }
  const auto metadata = copy_hdr10_metadata(*input->Data.pHdr10);
  if (!lumen::vdd::hdr::valid_hdr10_metadata(metadata)) {
    return STATUS_INVALID_PARAMETER;
  }
  std::shared_ptr<color_state_t> color_state;
  std::uint64_t generation = 0;
  HANDLE frame_ready_event = nullptr;
  {
    std::lock_guard lock(state->mutex);
    if (state->generation == 0 || state->mode.dynamic_range != LUMEN_VDD_DYNAMIC_RANGE_HDR10) {
      return STATUS_INVALID_DEVICE_STATE;
    }
    color_state = state->color_state;
    generation = state->generation;
    frame_ready_event = state->frame_ready_event;
  }
  {
    std::lock_guard color_lock(color_state->mutex);
    if (color_state->generation != generation) {
      return STATUS_REVISION_MISMATCH;
    }
    color_state->default_hdr10_metadata = metadata;
  }
  if (frame_ready_event != nullptr) {
    SetEvent(frame_ready_event);
  }
  return STATUS_SUCCESS;
}

_Use_decl_annotations_
  NTSTATUS
  LumenVddMonitorSetGammaRamp(IDDCX_MONITOR monitor, const IDARG_IN_SET_GAMMARAMP *input) {
  auto *state = monitor_context(monitor)->state;
  std::shared_ptr<color_transform_blob_t> next;
  try {
    next = std::make_shared<color_transform_blob_t>();
  } catch (const std::bad_alloc &) {
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  switch (input->Type) {
    case IDDCX_GAMMARAMP_TYPE_DEFAULT:
      if (input->GammaRampSizeInBytes != 0 || input->pGammaRampData != nullptr) {
        return STATUS_INVALID_PARAMETER;
      }
      next->type = LUMEN_VDD_GAMMA_RAMP_TYPE_DEFAULT;
      break;
    case IDDCX_GAMMARAMP_TYPE_RGB256x3x16:
      if (input->GammaRampSizeInBytes != sizeof(IDDCX_GAMMARAMP_RGB256x3x16) ||
          input->pGammaRampData == nullptr) {
        return STATUS_INVALID_PARAMETER;
      }
      next->type = LUMEN_VDD_GAMMA_RAMP_TYPE_RGB256X3X16;
      next->payload_size = sizeof(LUMEN_VDD_GAMMA_RAMP_RGB256X3X16);
      {
        const auto &source = *static_cast<const IDDCX_GAMMARAMP_RGB256x3x16 *>(input->pGammaRampData);
        std::copy(std::begin(source.Red), std::end(source.Red), std::begin(next->payload.rgb256x3x16.red));
        std::copy(std::begin(source.Green), std::end(source.Green), std::begin(next->payload.rgb256x3x16.green));
        std::copy(std::begin(source.Blue), std::end(source.Blue), std::begin(next->payload.rgb256x3x16.blue));
      }
      break;
    case IDDCX_GAMMARAMP_TYPE_3x4_COLORSPACE_TRANSFORM:
      if (input->GammaRampSizeInBytes != sizeof(IDDCX_GAMMARAMP_3X4_COLORSPACE_TRANSFORM) ||
          input->pGammaRampData == nullptr) {
        return STATUS_INVALID_PARAMETER;
      }
      next->type = LUMEN_VDD_GAMMA_RAMP_TYPE_3X4_COLORSPACE_TRANSFORM;
      next->payload_size = sizeof(LUMEN_VDD_GAMMA_RAMP_3X4_COLORSPACE_TRANSFORM);
      {
        const auto &source =
          *static_cast<const IDDCX_GAMMARAMP_3X4_COLORSPACE_TRANSFORM *>(input->pGammaRampData);
        if ((source.MatrixEnabled != FALSE && source.MatrixEnabled != TRUE) ||
            (source.LutEnabled != FALSE && source.LutEnabled != TRUE)) {
          return STATUS_INVALID_PARAMETER;
        }
        auto &transform = next->payload.transform_3x4;
        transform.matrix_enabled = source.MatrixEnabled == TRUE ? 1U : 0U;
        transform.lut_enabled = source.LutEnabled == TRUE ? 1U : 0U;
        if (transform.matrix_enabled != 0) {
          for (std::size_t row = 0; row < 3; ++row) {
            for (std::size_t column = 0; column < 4; ++column) {
              transform.color_matrix_3x4[row][column] = source.ColorMatrix3x4[row][column];
            }
          }
          transform.scalar_multiplier = source.ScalarMultiplier;
        }
        if (transform.lut_enabled != 0) {
          for (std::size_t index = 0; index < LUMEN_VDD_COLOR_TRANSFORM_LUT_ENTRY_COUNT; ++index) {
            transform.lookup_table_1d[index] = {
              source.LookupTable1D[index].Red,
              source.LookupTable1D[index].Green,
              source.LookupTable1D[index].Blue,
            };
          }
        }
        if (!lumen::vdd::color::valid_transform(transform)) {
          return STATUS_INVALID_PARAMETER;
        }
        lumen::vdd::color::clear_disabled_sections(transform);
        if (lumen::vdd::color::effective_type(next->type, transform) ==
            LUMEN_VDD_GAMMA_RAMP_TYPE_DEFAULT) {
          next->type = LUMEN_VDD_GAMMA_RAMP_TYPE_DEFAULT;
          next->payload_size = 0;
          std::memset(&next->payload, 0, sizeof(next->payload));
        }
      }
      break;
    default:
      return STATUS_INVALID_PARAMETER;
  }

  std::shared_ptr<color_state_t> color_state;
  std::uint64_t generation = 0;
  HANDLE frame_ready_event = nullptr;
  {
    std::lock_guard lock(state->mutex);
    if (state->generation == 0) {
      return STATUS_INVALID_DEVICE_STATE;
    }
    color_state = state->color_state;
    generation = state->generation;
    frame_ready_event = state->frame_ready_event;
  }
  {
    std::lock_guard color_lock(color_state->mutex);
    if (color_state->generation != generation || !color_state->current_transform) {
      return STATUS_REVISION_MISMATCH;
    }
    if (color_state->current_transform->type == next->type &&
        color_state->current_transform->payload_size == next->payload_size &&
        std::memcmp(
          &color_state->current_transform->payload,
          &next->payload,
          sizeof(next->payload)
        ) == 0) {
      return STATUS_SUCCESS;
    }
    if (color_state->next_transform_version == std::numeric_limits<std::uint64_t>::max()) {
      return STATUS_INTEGER_OVERFLOW;
    }
    next->version = color_state->next_transform_version++;
    color_state->current_transform = std::move(next);
  }
  if (frame_ready_event != nullptr) {
    SetEvent(frame_ready_event);
  }
  return STATUS_SUCCESS;
}

_Use_decl_annotations_
  NTSTATUS
  LumenVddMonitorGetDefaultModes(
    IDDCX_MONITOR monitor,
    const IDARG_IN_GETDEFAULTDESCRIPTIONMODES *input,
    IDARG_OUT_GETDEFAULTDESCRIPTIONMODES *output
  ) {
  auto *state = monitor_context(monitor)->state;
  std::lock_guard lock(state->mutex);
  if (!valid_mode(state->mode)) {
    return STATUS_INVALID_DEVICE_STATE;
  }
  output->DefaultMonitorModeBufferOutputCount = 1;
  output->PreferredMonitorModeIdx = 0;
  if (input->DefaultMonitorModeBufferInputCount == 0) {
    return STATUS_SUCCESS;
  }
  if (input->DefaultMonitorModeBufferInputCount < 1 || input->pDefaultMonitorModes == nullptr) {
    return STATUS_BUFFER_TOO_SMALL;
  }
  input->pDefaultMonitorModes[0] = monitor_mode(state->mode, IDDCX_MONITOR_MODE_ORIGIN_DRIVER);
  return STATUS_SUCCESS;
}

_Use_decl_annotations_
  NTSTATUS
  LumenVddMonitorQueryTargetModes(
    IDDCX_MONITOR monitor,
    const IDARG_IN_QUERYTARGETMODES *input,
    IDARG_OUT_QUERYTARGETMODES *output
  ) {
  auto *state = monitor_context(monitor)->state;
  std::lock_guard lock(state->mutex);
  if (!valid_mode(state->mode)) {
    return STATUS_INVALID_DEVICE_STATE;
  }
  output->TargetModeBufferOutputCount = 1;
  if (input->TargetModeBufferInputCount == 0) {
    return STATUS_SUCCESS;
  }
  if (input->TargetModeBufferInputCount < 1 || input->pTargetModes == nullptr) {
    return STATUS_BUFFER_TOO_SMALL;
  }
  const auto &advertised_mode =
    state->mode.dynamic_range == LUMEN_VDD_DYNAMIC_RANGE_HDR10 &&
        !state->exact_modes_published.load(std::memory_order_acquire) ?
      lumen::vdd::hdr::baseline_mode :
      state->mode;
  input->pTargetModes[0] = target_mode(advertised_mode);
  return STATUS_SUCCESS;
}

_Use_decl_annotations_
  NTSTATUS
  LumenVddMonitorQueryTargetModes2(
    IDDCX_MONITOR monitor,
    const IDARG_IN_QUERYTARGETMODES2 *input,
    IDARG_OUT_QUERYTARGETMODES *output
  ) {
  auto *state = monitor_context(monitor)->state;
  std::lock_guard lock(state->mutex);
  if (!valid_mode(state->mode)) {
    return STATUS_INVALID_DEVICE_STATE;
  }
  output->TargetModeBufferOutputCount = 1;
  if (input->TargetModeBufferInputCount == 0) {
    return STATUS_SUCCESS;
  }
  if (input->TargetModeBufferInputCount < 1 || input->pTargetModes == nullptr) {
    return STATUS_BUFFER_TOO_SMALL;
  }
  const auto &advertised_mode =
    state->mode.dynamic_range == LUMEN_VDD_DYNAMIC_RANGE_HDR10 &&
        !state->exact_modes_published.load(std::memory_order_acquire) ?
      lumen::vdd::hdr::baseline_mode :
      state->mode;
  input->pTargetModes[0] = target_mode2(advertised_mode);
  return STATUS_SUCCESS;
}

_Use_decl_annotations_
  NTSTATUS
  LumenVddMonitorAssignSwapChain(IDDCX_MONITOR monitor, const IDARG_IN_SETSWAPCHAIN *input) {
  auto *state = monitor_context(monitor)->state;
  std::lock_guard lock(state->mutex);
  state->swap_chain.reset();
  state->assigned_render_adapter_luid = pack_luid(input->RenderAdapterLuid);
  const bool direct_frames_enabled = lumen::vdd::frame::render_adapter_matches(
    state->preferred_render_adapter_luid,
    state->assigned_render_adapter_luid
  );
  lumen::vdd::single_delete_owner_t<IDDCX_SWAPCHAIN, swap_chain_deleter_t> pending_swap_chain(input->hSwapChain);
  try {
    state->swap_chain.reset(new swap_chain_processor_t(
      pending_swap_chain.release(),
      input->RenderAdapterLuid,
      input->hNextSurfaceAvailable,
      state->generation,
      state->mode,
      state->frame_ready_event,
      state->color_state,
      direct_frames_enabled
    ));
  } catch (...) {
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  return STATUS_SUCCESS;
}

_Use_decl_annotations_
  NTSTATUS
  LumenVddMonitorUnassignSwapChain(IDDCX_MONITOR monitor) {
  auto *state = monitor_context(monitor)->state;
  std::lock_guard lock(state->mutex);
  state->swap_chain.reset();
  return STATUS_SUCCESS;
}
