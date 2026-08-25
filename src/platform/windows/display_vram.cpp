/**
 * @file src/platform/windows/display_vram.cpp
 * @brief Definitions for handling video ram.
 */
// standard includes
#include <array>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

// platform includes
#include <d3dcompiler.h>
#include <DirectXMath.h>

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavutil/hwcontext_d3d11va.h>
}

// lib includes
#include <AMF/core/Factory.h>
#include <boost/algorithm/string/predicate.hpp>

// local includes
#include "display.h"
#include "fused_d3d11_policy.h"
#include "misc.h"
#include "src/config.h"
#include "src/logging.h"
#include "src/nvenc/nvenc_config.h"
#include "src/nvenc/nvenc_dynamic_factory.h"
#include "src/nvenc/nvenc_hdr_metadata.h"
#include "src/stream_policy.h"
#include "src/video.h"
#include "utf_utils.h"

#if !defined(SUNSHINE_SHADERS_DIR)  // for testing this needs to be defined in cmake as we don't do an install
  /**
   * @def SUNSHINE_SHADERS_DIR
   * @brief Macro for SUNSHINE SHADERS DIR.
   */
  #define SUNSHINE_SHADERS_DIR SUNSHINE_ASSETS_DIR "/shaders/directx"
#endif
namespace platf {
  using namespace std::literals;
}

static void free_frame(AVFrame *frame) {
  av_frame_free(&frame);
}

/**
 * @brief FFmpeg hardware frame pointer released with `av_frame_free`.
 */
using frame_t = util::safe_ptr<AVFrame, free_frame>;

namespace platf::dxgi {

  namespace {
    /**
     * @brief Name of the explicit opt-in gate for the experimental fused path.
     */
    constexpr auto fused_runtime_gate_env = "LUMEN_EXPERIMENTAL_FUSED_D3D11_NVENC";

    /**
     * @brief Name of the RTX 4060 hardware acknowledgement gate.
     */
    constexpr auto fused_hardware_gate_env = "LUMEN_EXPERIMENTAL_FUSED_D3D11_NVENC_HARDWARE_VALIDATED";

    /**
     * @brief Name of the exact validated driver-version gate.
     */
    constexpr auto fused_driver_gate_env = "LUMEN_EXPERIMENTAL_FUSED_D3D11_NVENC_VALIDATED_DRIVER";
    constexpr auto fused_luid_gate_env = "LUMEN_EXPERIMENTAL_FUSED_D3D11_NVENC_ADAPTER_LUID";  ///< Exact validated adapter LUID.
    constexpr auto fused_vendor_gate_env = "LUMEN_EXPERIMENTAL_FUSED_D3D11_NVENC_VENDOR_ID";  ///< Exact validated PCI vendor ID.
    constexpr auto fused_device_gate_env = "LUMEN_EXPERIMENTAL_FUSED_D3D11_NVENC_DEVICE_ID";  ///< Exact validated PCI device ID.
    constexpr auto fused_subsystem_gate_env = "LUMEN_EXPERIMENTAL_FUSED_D3D11_NVENC_SUBSYSTEM_ID";  ///< Exact validated PCI subsystem ID.
    constexpr auto fused_revision_gate_env = "LUMEN_EXPERIMENTAL_FUSED_D3D11_NVENC_REVISION";  ///< Exact validated PCI revision.
    constexpr auto fused_model_gate_env = "LUMEN_EXPERIMENTAL_FUSED_D3D11_NVENC_MODEL";  ///< Exact validated adapter description.
    constexpr auto fused_output_gate_env = "LUMEN_EXPERIMENTAL_FUSED_D3D11_NVENC_OUTPUT";  ///< Exact validated DXGI output name.
    std::atomic_bool fused_runtime_quarantined {false};  ///< Process-wide fail-closed quarantine after a fused-path failure.

    /** @brief Map the immutable client configuration to an isolated telemetry profile. */
    fused_d3d11::telemetry_profile_e telemetry_profile(const ::video::config_t &config) noexcept {
      if (!config.optimization_policy) {
        return fused_d3d11::telemetry_profile_e::unknown;
      }
      return fused_d3d11::telemetry_profile_for(config.optimization_policy->mode);
    }

    /** @brief Map the exact immutable negotiation/transport source without inference. */
    fused_d3d11::telemetry_client_e telemetry_client(const ::video::config_t &config) noexcept {
      return fused_d3d11::telemetry_client_for(config.client_protocol);
    }

    /** @brief Read and validate the exact HDR10 static block from the active capture display. */
    std::optional<nvenc::hdr_static_metadata_t> active_hdr_static_metadata(display_vram_t &display) {
      SS_HDR_METADATA metadata {};
      if (!display.is_hdr() || !display.get_hdr_metadata(metadata)) {
        return std::nullopt;
      }
      const nvenc::hdr_static_metadata_t converted {
        std::array<nvenc::hdr_chromaticity_t, 3> {{
          {metadata.displayPrimaries[0].x, metadata.displayPrimaries[0].y},
          {metadata.displayPrimaries[1].x, metadata.displayPrimaries[1].y},
          {metadata.displayPrimaries[2].x, metadata.displayPrimaries[2].y},
        }},
        {metadata.whitePoint.x, metadata.whitePoint.y},
        metadata.maxDisplayLuminance,
        metadata.minDisplayLuminance,
        metadata.maxContentLightLevel,
        metadata.maxFrameAverageLightLevel,
      };
      return nvenc::valid_hdr_static_metadata(converted) ?
               std::optional {converted} :
               std::nullopt;
    }

    std::optional<nvenc::hdr_static_metadata_t> frame_hdr_static_metadata(
      const virtual_display::frame_color_metadata_t &metadata
    ) {
      if (metadata.hdr_metadata_type == virtual_display::hdr_metadata_type_e::none) {
        return std::nullopt;
      }
      const auto &source = metadata.hdr10_metadata;
      const nvenc::hdr_static_metadata_t converted {
        std::array<nvenc::hdr_chromaticity_t, 3> {{
          {source.red_primary[0], source.red_primary[1]},
          {source.green_primary[0], source.green_primary[1]},
          {source.blue_primary[0], source.blue_primary[1]},
        }},
        {source.white_point[0], source.white_point[1]},
        source.maximum_mastering_luminance,
        source.minimum_mastering_luminance,
        source.maximum_content_light_level,
        source.maximum_frame_average_light_level,
      };
      return nvenc::valid_hdr_static_metadata(converted) ?
               std::optional {converted} :
               std::nullopt;
    }

    /**
     * @brief Read one process environment variable without a fixed-size buffer.
     *
     * @param name Environment variable name.
     * @return Environment value, or an empty optional when absent or unreadable.
     */
    std::optional<std::string> environment_value(const char *name) {
      const auto required = GetEnvironmentVariableA(name, nullptr, 0);
      if (required == 0) {
        return std::nullopt;
      }

      std::string value(required, '\0');
      const auto written = GetEnvironmentVariableA(name, value.data(), required);
      if (written == 0 || written >= required) {
        return std::nullopt;
      }
      value.resize(written);
      return value;
    }

    /**
     * @brief Parse an unsigned decimal environment value.
     *
     * @param value Decimal string to parse.
     * @return Parsed integer, or an empty optional when the entire string is not valid decimal.
     */
    std::optional<std::uint64_t> parse_decimal_u64(std::string_view value) {
      std::uint64_t parsed = 0;
      const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed, 10);
      if (result.ec != std::errc {} || result.ptr != value.data() + value.size()) {
        return std::nullopt;
      }
      return parsed;
    }

    /** @brief Convert a Windows LUID into its stable 64-bit value. */
    std::uint64_t luid_value(const LUID &luid) {
      return static_cast<std::uint64_t>(static_cast<std::uint32_t>(luid.HighPart)) << 32 |
             static_cast<std::uint64_t>(luid.LowPart);
    }

    /** @brief Match an exact decimal environment value against an actual identity field. */
    bool environment_decimal_matches(const char *name, std::uint64_t actual) {
      const auto value = environment_value(name);
      const auto parsed = value ? parse_decimal_u64(*value) : std::nullopt;
      return parsed && *parsed == actual;
    }

    /** @brief Verify that the capture device and immediate context share COM identity. */
    bool context_matches_device(ID3D11Device *device, ID3D11DeviceContext *context) {
      ID3D11Device *context_device = nullptr;
      context->GetDevice(&context_device);
      if (!context_device) {
        return false;
      }
      auto release_context_device = util::fail_guard([&]() {
        context_device->Release();
      });
      IUnknown *device_identity = nullptr;
      IUnknown *context_identity = nullptr;
      if (FAILED(device->QueryInterface(IID_IUnknown, (void **) &device_identity)) ||
          FAILED(context_device->QueryInterface(IID_IUnknown, (void **) &context_identity))) {
        if (device_identity) {
          device_identity->Release();
        }
        return false;
      }
      const bool matches = device_identity == context_identity;
      device_identity->Release();
      context_identity->Release();
      return matches;
    }

    /** @brief Map a failed image completion to reinit only when fused rollback requested it. */
    capture_e capture_completion_failure(const display_vram_t &display) {
      return fused_d3d11::classify_capture_failure(display.fused_reinit_required()) == fused_d3d11::capture_failure_e::reinitialize ?
               capture_e::reinit :
               capture_e::error;
    }

    /**
     * @brief Map a Sunshine pixel format to the pure fused-path policy format.
     *
     * @param format Sunshine encoder input format.
     * @return Policy surface format.
     */
    fused_d3d11::surface_format_e fused_surface_format(pix_fmt_e format) {
      switch (format) {
        case pix_fmt_e::nv12:
          return fused_d3d11::surface_format_e::nv12;
        case pix_fmt_e::p010:
          return fused_d3d11::surface_format_e::p010;
        default:
          return fused_d3d11::surface_format_e::unsupported;
      }
    }

    /**
     * @brief Verify that a D3D11 device resolves to the expected adapter LUID.
     *
     * @param device D3D11 device whose adapter is queried.
     * @param expected Expected capture adapter.
     * @return True when both adapters report the same LUID.
     */
    bool device_uses_adapter(ID3D11Device *device, IDXGIAdapter1 *expected) {
      dxgi_t dxgi_device;
      if (FAILED(device->QueryInterface(IID_IDXGIDevice, (void **) &dxgi_device))) {
        return false;
      }

      IDXGIAdapter *adapter_raw = nullptr;
      if (FAILED(dxgi_device->GetAdapter(&adapter_raw))) {
        return false;
      }
      auto release_adapter = util::fail_guard([&]() {
        adapter_raw->Release();
      });

      DXGI_ADAPTER_DESC actual_desc {};
      DXGI_ADAPTER_DESC1 expected_desc {};
      if (FAILED(adapter_raw->GetDesc(&actual_desc)) || FAILED(expected->GetDesc1(&expected_desc))) {
        return false;
      }

      return actual_desc.AdapterLuid.HighPart == expected_desc.AdapterLuid.HighPart &&
             actual_desc.AdapterLuid.LowPart == expected_desc.AdapterLuid.LowPart;
    }

    /**
     * @brief Build the fail-closed fused-path request for one display and surface format.
     *
     * @param display Capture display whose exact device, adapter, output, HDR, and driver are validated.
     * @param format Requested encoder input format.
     * @param active_driver Output receiving the current driver version for diagnostics.
     * @return Pure eligibility request.
     */
    fused_d3d11::eligibility_t fused_eligibility(
      display_vram_t &display,
      pix_fmt_e format,
      std::uint64_t &active_driver
    ) {
      const auto runtime_gate = environment_value(fused_runtime_gate_env);
      const auto hardware_gate = environment_value(fused_hardware_gate_env);

      DXGI_ADAPTER_DESC1 adapter_desc {};
      const bool adapter_desc_ok = display.adapter && SUCCEEDED(display.adapter->GetDesc1(&adapter_desc));
      const auto adapter_description = adapter_desc_ok ? utf_utils::to_utf8(adapter_desc.Description) : std::string {};

      LARGE_INTEGER driver_version {};
      const bool driver_query_ok = display.adapter && SUCCEEDED(display.adapter->CheckInterfaceSupport(IID_IDXGIDevice, &driver_version));
      active_driver = driver_query_ok ? static_cast<std::uint64_t>(driver_version.QuadPart) : 0;

      DXGI_OUTPUT_DESC output_desc {};
      const bool output_desc_ok = display.output && SUCCEEDED(display.output->GetDesc(&output_desc)) && output_desc.AttachedToDesktop;
      const auto output_name = output_desc_ok ? utf_utils::to_utf8(output_desc.DeviceName) : std::string {};

      const ::video::encoder_probe_device_identity_t local_identity {
        adapter_desc_ok ? luid_value(adapter_desc.AdapterLuid) : 0,
        adapter_desc_ok ? adapter_desc.VendorId : 0,
        adapter_desc_ok ? adapter_desc.DeviceId : 0,
        adapter_desc_ok ? adapter_desc.SubSysId : 0,
        adapter_desc_ok ? adapter_desc.Revision : 0,
        active_driver,
        output_name,
      };
      const auto probe_identity = encoder_probe_device_identity();

      const auto model_gate = environment_value(fused_model_gate_env);
      const auto output_gate = environment_value(fused_output_gate_env);
      const bool full_adapter_identity_matches = adapter_desc_ok &&
                                                 environment_decimal_matches(fused_luid_gate_env, local_identity.adapter_luid) &&
                                                 environment_decimal_matches(fused_vendor_gate_env, local_identity.vendor_id) &&
                                                 environment_decimal_matches(fused_device_gate_env, local_identity.device_id) &&
                                                 environment_decimal_matches(fused_subsystem_gate_env, local_identity.subsystem_id) &&
                                                 environment_decimal_matches(fused_revision_gate_env, local_identity.revision);

      return {
        runtime_gate && *runtime_gate == "1",
        hardware_gate && *hardware_gate == "RTX4060",
        true,
        display.is_hdr(),
        adapter_desc_ok && adapter_desc.VendorId == 0x10de,
        full_adapter_identity_matches,
        model_gate && *model_gate == adapter_description,
        driver_query_ok && environment_decimal_matches(fused_driver_gate_env, active_driver),
        display.device && display.device_ctx && context_matches_device(display.device.get(), display.device_ctx.get()) &&
          device_uses_adapter(display.device.get(), display.adapter.get()),
        probe_identity && *probe_identity == local_identity,
        output_desc_ok && output_gate && *output_gate == output_name,
        fused_runtime_quarantined.load(std::memory_order_acquire),
        fused_surface_format(format),
      };
    }
  }  // namespace

  /**
   * @brief Create a buffer object or message.
   *
   * @param device D3D, audio, or platform device used by the operation.
   * @param t Initial value used to populate the GPU buffer.
   * @return Constructed buffer object.
   */
  template<class T>
  buf_t make_buffer(device_t::pointer device, const T &t) {
    static_assert(sizeof(T) % 16 == 0, "Buffer needs to be aligned on a 16-byte alignment");

    D3D11_BUFFER_DESC buffer_desc {
      sizeof(T),
      D3D11_USAGE_IMMUTABLE,
      D3D11_BIND_CONSTANT_BUFFER
    };

    D3D11_SUBRESOURCE_DATA init_data {
      &t
    };

    buf_t::pointer buf_p;
    auto status = device->CreateBuffer(&buffer_desc, &init_data, &buf_p);
    if (status) {
      BOOST_LOG(error) << "Failed to create buffer: [0x"sv << util::hex(status).to_string_view() << ']';
      return nullptr;
    }

    return buf_t {buf_p};
  }

  /**
   * @brief Create a blend object or message.
   *
   * @param device D3D, audio, or platform device used by the operation.
   * @param enable Whether the blend state should enable blending.
   * @param invert Whether the blend state should invert the color channels.
   * @return Constructed blend object.
   */
  blend_t make_blend(device_t::pointer device, bool enable, bool invert) {
    D3D11_BLEND_DESC bdesc {};
    auto &rt = bdesc.RenderTarget[0];
    rt.BlendEnable = enable;
    rt.RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;

    if (enable) {
      rt.BlendOp = D3D11_BLEND_OP_ADD;
      rt.BlendOpAlpha = D3D11_BLEND_OP_ADD;

      if (invert) {
        // Invert colors
        rt.SrcBlend = D3D11_BLEND_INV_DEST_COLOR;
        rt.DestBlend = D3D11_BLEND_INV_SRC_COLOR;
      } else {
        // Regular alpha blending
        rt.SrcBlend = D3D11_BLEND_SRC_ALPHA;
        rt.DestBlend = D3D11_BLEND_INV_SRC_ALPHA;
      }

      rt.SrcBlendAlpha = D3D11_BLEND_ZERO;
      rt.DestBlendAlpha = D3D11_BLEND_ZERO;
    }

    blend_t blend;
    auto status = device->CreateBlendState(&bdesc, &blend);
    if (status) {
      BOOST_LOG(error) << "Failed to create blend state: [0x"sv << util::hex(status).to_string_view() << ']';
      return nullptr;
    }

    return blend;
  }

  blob_t convert_yuv420_packed_uv_type0_ps_hlsl;  ///< Convert yuv420 packed uv type0 ps hlsl.
  blob_t convert_yuv420_packed_uv_type0_ps_linear_hlsl;  ///< Convert yuv420 packed uv type0 ps linear hlsl.
  blob_t convert_yuv420_packed_uv_type0_ps_perceptual_quantizer_hlsl;  ///< Convert yuv420 packed uv type0 ps perceptual quantizer hlsl.
  blob_t convert_yuv420_packed_uv_type0_ps_vdd_color_transform_hlsl;  ///< ABI5 VDD color-transform UV shader.
  blob_t convert_yuv420_packed_uv_type0_vs_hlsl;  ///< Convert yuv420 packed uv type0 vs hlsl.
  blob_t convert_yuv420_packed_uv_type0s_ps_hlsl;  ///< Convert yuv420 packed uv type0s ps hlsl.
  blob_t convert_yuv420_packed_uv_type0s_ps_linear_hlsl;  ///< Convert yuv420 packed uv type0s ps linear hlsl.
  blob_t convert_yuv420_packed_uv_type0s_ps_perceptual_quantizer_hlsl;  ///< Convert yuv420 packed uv type0s ps perceptual quantizer hlsl.
  blob_t convert_yuv420_packed_uv_type0s_ps_vdd_color_transform_hlsl;  ///< ABI5 downscaled VDD color-transform UV shader.
  blob_t convert_yuv420_packed_uv_type0s_vs_hlsl;  ///< Convert yuv420 packed uv type0s vs hlsl.
  blob_t convert_yuv420_planar_y_ps_hlsl;  ///< Convert yuv420 planar y ps hlsl.
  blob_t convert_yuv420_planar_y_ps_linear_hlsl;  ///< Convert yuv420 planar y ps linear hlsl.
  blob_t convert_yuv420_planar_y_ps_perceptual_quantizer_hlsl;  ///< Convert yuv420 planar y ps perceptual quantizer hlsl.
  blob_t convert_yuv420_planar_y_ps_vdd_color_transform_hlsl;  ///< ABI5 VDD color-transform luma shader.
  blob_t convert_yuv420_planar_y_vs_hlsl;  ///< Convert yuv420 planar y vs hlsl.
  blob_t convert_yuv444_packed_ayuv_ps_hlsl;  ///< Convert YUV444 packed ayuv ps hlsl.
  blob_t convert_yuv444_packed_ayuv_ps_linear_hlsl;  ///< Convert YUV444 packed ayuv ps linear hlsl.
  blob_t convert_yuv444_packed_ayuv_ps_vdd_color_transform_hlsl;  ///< ABI5 VDD color-transform AYUV shader.
  blob_t convert_yuv444_packed_vs_hlsl;  ///< Convert YUV444 packed vs hlsl.
  blob_t convert_yuv444_planar_ps_hlsl;  ///< Convert YUV444 planar ps hlsl.
  blob_t convert_yuv444_planar_ps_linear_hlsl;  ///< Convert YUV444 planar ps linear hlsl.
  blob_t convert_yuv444_planar_ps_perceptual_quantizer_hlsl;  ///< Convert YUV444 planar ps perceptual quantizer hlsl.
  blob_t convert_yuv444_planar_ps_vdd_color_transform_hlsl;  ///< ABI5 VDD color-transform planar shader.
  blob_t convert_yuv444_packed_y410_ps_hlsl;  ///< Convert YUV444 packed y410 ps hlsl.
  blob_t convert_yuv444_packed_y410_ps_linear_hlsl;  ///< Convert YUV444 packed y410 ps linear hlsl.
  blob_t convert_yuv444_packed_y410_ps_perceptual_quantizer_hlsl;  ///< Convert YUV444 packed y410 ps perceptual quantizer hlsl.
  blob_t convert_yuv444_packed_y410_ps_vdd_color_transform_hlsl;  ///< ABI5 VDD color-transform Y410 shader.
  blob_t convert_yuv444_planar_vs_hlsl;  ///< Convert YUV444 planar vs hlsl.
  blob_t cursor_ps_hlsl;  ///< Cursor ps hlsl.
  blob_t cursor_ps_normalize_white_hlsl;  ///< Cursor ps normalize white hlsl.
  blob_t cursor_vs_hlsl;  ///< Cursor vs hlsl.

  /**
   * @brief D3D-backed captured image and duplication metadata.
   */
  struct img_d3d_t: public platf::img_t {
    // These objects are owned by the display_t's ID3D11Device
    texture2d_t capture_texture;  ///< Capture texture.
    render_target_t capture_rt;  ///< Capture rt.
    keyed_mutex_t capture_mutex;  ///< Capture mutex.

    // This is the shared handle used by hwdevice_t to open capture_texture
    HANDLE encoder_texture_handle = {};  ///< Encoder texture handle.

    // Set to true if the image corresponds to a dummy texture used prior to
    // the first successful capture of a desktop frame
    bool dummy = false;  ///< Whether this image is a dummy placeholder.

    // Set to true if the image is blank (contains no content at all, including a cursor)
    bool blank = true;  ///< Whether the texture currently contains a blank frame.

    // Unique identifier for this image
    uint32_t id = 0;  ///< Unique identifier used to cache encoder resources for this image.

    // DXGI format of this image texture
    DXGI_FORMAT format;  ///< DXGI format of the captured texture.

    // True when capture and encode use this texture through the same D3D11 device.
    bool fused_resource = false;  ///< Whether legacy shared-handle and keyed-mutex boundaries are absent.
    std::shared_ptr<const virtual_display::color_transform_t> color_transform;  ///< ABI5 transform retained with the slot lease.
    virtual_display::frame_color_metadata_t color_metadata;  ///< ABI5 resolved frame color/HDR state.
    fused_d3d11::frame_trace_token_t telemetry_capture_token;  ///< Image-owned parent trace for bounded encoder children.
    std::shared_ptr<fused_d3d11::resource_ownership_t> resource_ownership;  ///< Capture-pool transition state retained by this image.
    bool resource_bound = false;  ///< Whether this image contributes to the bound-image drain count.

    virtual ~img_d3d_t() override {
      fused_d3d11::telemetry().release_capture_frame_token(telemetry_capture_token);
      if (resource_bound) {
        const bool released = resource_ownership && resource_ownership->release_image();
        assert(released);
        (void) released;
        if (resource_ownership->reinit_required()) {
          resource_ownership->reset_after_reinit();
        }
      }
      if (encoder_texture_handle) {
        CloseHandle(encoder_texture_handle);
      }
    };
  };

  /**
   * @brief Keyed-mutex guard used while sharing a D3D texture.
   */
  struct texture_lock_helper {
    keyed_mutex_t _mutex;  ///< D3D keyed mutex acquired for shared-texture access.
    bool _locked = false;  ///< Whether the keyed mutex is currently locked.

    texture_lock_helper(const texture_lock_helper &) = delete;
    texture_lock_helper &operator=(const texture_lock_helper &) = delete;

    /**
     * @brief Move a keyed-mutex lock helper while preserving lock ownership.
     *
     * @param other Helper whose acquired keyed mutex is transferred.
     */
    texture_lock_helper(texture_lock_helper &&other) {
      _mutex.reset(other._mutex.release());
      _locked = other._locked;
      other._locked = false;
    }

    /**
     * @brief Assign state from another instance while preserving ownership semantics.
     *
     * @param other Source object whose state is copied or moved into this object.
     * @return Reference or value produced by the operator.
     */
    texture_lock_helper &operator=(texture_lock_helper &&other) {
      if (_locked) {
        _mutex->ReleaseSync(0);
      }
      _mutex.reset(other._mutex.release());
      _locked = other._locked;
      other._locked = false;
      return *this;
    }

    /**
     * @brief Acquire a D3D keyed mutex for scoped texture access.
     *
     * @param mutex Keyed mutex to acquire for texture access.
     */
    texture_lock_helper(IDXGIKeyedMutex *mutex):
        _mutex(mutex) {
      if (_mutex) {
        _mutex->AddRef();
      }
    }

    ~texture_lock_helper() {
      if (_locked) {
        _mutex->ReleaseSync(0);
      }
    }

    /**
     * @brief Acquire the underlying lock or keyed mutex.
     *
     * @return True when the keyed mutex is acquired.
     */
    bool lock() {
      if (_locked) {
        return true;
      }
      if (!_mutex) {
        return true;
      }
      HRESULT status = _mutex->AcquireSync(0, INFINITE);
      if (status == S_OK) {
        _locked = true;
        fused_d3d11::telemetry().record_keyed_mutex_acquire();
      } else {
        BOOST_LOG(error) << "Failed to acquire texture mutex [0x"sv << util::hex(status).to_string_view() << ']';
      }
      return _locked;
    }
  };

  /**
   * @brief Create cursor xor image.
   *
   * @param img_data Raw pointer-shape bytes returned by DXGI.
   * @param shape_info DXGI metadata describing the pointer shape.
   * @return Constructed cursor xor image object.
   */
  util::buffer_t<std::uint8_t> make_cursor_xor_image(const util::buffer_t<std::uint8_t> &img_data, DXGI_OUTDUPL_POINTER_SHAPE_INFO shape_info) {
    constexpr std::uint32_t inverted = 0xFFFFFFFF;
    constexpr std::uint32_t transparent = 0;

    switch (shape_info.Type) {
      case DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR:
        // This type doesn't require any XOR-blending
        return {};
      case DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MASKED_COLOR:
        {
          util::buffer_t<std::uint8_t> cursor_img = img_data;
          std::for_each((std::uint32_t *) std::begin(cursor_img), (std::uint32_t *) std::end(cursor_img), [](auto &pixel) {
            auto alpha = (std::uint8_t) ((pixel >> 24) & 0xFF);
            if (alpha == 0xFF) {
              // Pixels with 0xFF alpha will be XOR-blended as is.
            } else if (alpha == 0x00) {
              // Pixels with 0x00 alpha will be blended by make_cursor_alpha_image().
              // We make them transparent for the XOR-blended cursor image.
              pixel = transparent;
            } else {
              // Other alpha values are illegal in masked color cursors
              BOOST_LOG(warning) << "Illegal alpha value in masked color cursor: " << alpha;
            }
          });
          return cursor_img;
        }
      case DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME:
        // Monochrome is handled below
        break;
      default:
        BOOST_LOG(error) << "Invalid cursor shape type: " << shape_info.Type;
        return {};
    }

    shape_info.Height /= 2;

    util::buffer_t<std::uint8_t> cursor_img {shape_info.Width * shape_info.Height * 4};

    auto bytes = shape_info.Pitch * shape_info.Height;
    auto pixel_begin = (std::uint32_t *) std::begin(cursor_img);
    auto pixel_data = pixel_begin;
    auto and_mask = std::begin(img_data);
    auto xor_mask = std::begin(img_data) + bytes;

    for (auto x = 0; x < bytes; ++x) {
      for (auto c = 7; c >= 0 && ((std::uint8_t *) pixel_data) != std::end(cursor_img); --c) {
        auto bit = 1 << c;
        auto color_type = ((*and_mask & bit) ? 1 : 0) + ((*xor_mask & bit) ? 2 : 0);

        switch (color_type) {
          case 0:  // Opaque black (handled by alpha-blending)
          case 2:  // Opaque white (handled by alpha-blending)
          case 1:  // Color of screen (transparent)
            *pixel_data = transparent;
            break;
          case 3:  // Inverse of screen
            *pixel_data = inverted;
            break;
        }

        ++pixel_data;
      }
      ++and_mask;
      ++xor_mask;
    }

    return cursor_img;
  }

  /**
   * @brief Create cursor alpha image.
   *
   * @param img_data Raw pointer-shape bytes returned by DXGI.
   * @param shape_info DXGI metadata describing the pointer shape.
   * @return Constructed cursor alpha image object.
   */
  util::buffer_t<std::uint8_t> make_cursor_alpha_image(const util::buffer_t<std::uint8_t> &img_data, DXGI_OUTDUPL_POINTER_SHAPE_INFO shape_info) {
    constexpr std::uint32_t black = 0xFF000000;
    constexpr std::uint32_t white = 0xFFFFFFFF;
    constexpr std::uint32_t transparent = 0;

    switch (shape_info.Type) {
      case DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MASKED_COLOR:
        {
          util::buffer_t<std::uint8_t> cursor_img = img_data;
          std::for_each((std::uint32_t *) std::begin(cursor_img), (std::uint32_t *) std::end(cursor_img), [](auto &pixel) {
            auto alpha = (std::uint8_t) ((pixel >> 24) & 0xFF);
            if (alpha == 0xFF) {
              // Pixels with 0xFF alpha will be XOR-blended by make_cursor_xor_image().
              // We make them transparent for the alpha-blended cursor image.
              pixel = transparent;
            } else if (alpha == 0x00) {
              // Pixels with 0x00 alpha will be blended as opaque with the alpha-blended image.
              pixel |= 0xFF000000;
            } else {
              // Other alpha values are illegal in masked color cursors
              BOOST_LOG(warning) << "Illegal alpha value in masked color cursor: " << alpha;
            }
          });
          return cursor_img;
        }
      case DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR:
        // Color cursors are just an ARGB bitmap which requires no processing.
        return img_data;
      case DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME:
        // Monochrome cursors are handled below.
        break;
      default:
        BOOST_LOG(error) << "Invalid cursor shape type: " << shape_info.Type;
        return {};
    }

    shape_info.Height /= 2;

    util::buffer_t<std::uint8_t> cursor_img {shape_info.Width * shape_info.Height * 4};

    auto bytes = shape_info.Pitch * shape_info.Height;
    auto pixel_begin = (std::uint32_t *) std::begin(cursor_img);
    auto pixel_data = pixel_begin;
    auto and_mask = std::begin(img_data);
    auto xor_mask = std::begin(img_data) + bytes;

    for (auto x = 0; x < bytes; ++x) {
      for (auto c = 7; c >= 0 && ((std::uint8_t *) pixel_data) != std::end(cursor_img); --c) {
        auto bit = 1 << c;
        auto color_type = ((*and_mask & bit) ? 1 : 0) + ((*xor_mask & bit) ? 2 : 0);

        switch (color_type) {
          case 0:  // Opaque black
            *pixel_data = black;
            break;
          case 2:  // Opaque white
            *pixel_data = white;
            break;
          case 3:  // Inverse of screen (handled by XOR blending)
          case 1:  // Color of screen (transparent)
            *pixel_data = transparent;
            break;
        }

        ++pixel_data;
      }
      ++and_mask;
      ++xor_mask;
    }

    return cursor_img;
  }

  /**
   * @brief Compile an HLSL shader from source text.
   *
   * @param file Optional stdio file handle connected to the child process.
   * @param entrypoint Function entry point to resolve from the library.
   * @param shader_model Shader model.
   * @return Compiled shader blob, or an empty blob when compilation fails.
   */
  blob_t compile_shader(LPCSTR file, LPCSTR entrypoint, LPCSTR shader_model) {
    blob_t::pointer msg_p = nullptr;
    blob_t::pointer compiled_p;

    DWORD flags = D3DCOMPILE_ENABLE_STRICTNESS;

#ifndef NDEBUG
    flags |= D3DCOMPILE_DEBUG | D3DCOMPILE_SKIP_OPTIMIZATION;
#endif

    auto wFile = utf_utils::from_utf8(file);
    auto status = D3DCompileFromFile(wFile.c_str(), nullptr, D3D_COMPILE_STANDARD_FILE_INCLUDE, entrypoint, shader_model, flags, 0, &compiled_p, &msg_p);

    if (msg_p) {
      BOOST_LOG(warning) << std::string_view {(const char *) msg_p->GetBufferPointer(), msg_p->GetBufferSize() - 1};
      msg_p->Release();
    }

    if (status) {
      BOOST_LOG(error) << "Couldn't compile ["sv << file << "] [0x"sv << util::hex(status).to_string_view() << ']';
      return nullptr;
    }

    return blob_t {compiled_p};
  }

  /**
   * @brief Compile an HLSL pixel shader from source text.
   *
   * @param file Optional stdio file handle connected to the child process.
   * @return Compiled pixel shader object, or an empty handle when compilation fails.
   */
  blob_t compile_pixel_shader(LPCSTR file) {
    return compile_shader(file, "main_ps", "ps_5_0");
  }

  /**
   * @brief Compile an HLSL vertex shader from source text.
   *
   * @param file Optional stdio file handle connected to the child process.
   * @return Compiled vertex shader object, or an empty handle when compilation fails.
   */
  blob_t compile_vertex_shader(LPCSTR file) {
    return compile_shader(file, "main_vs", "vs_5_0");
  }

  /**
   * @brief Shared D3D11 conversion resources for AVCodec and NVENC encode devices.
   */
  class d3d_base_encode_device final {
  public:
    struct alignas(16) vdd_color_shader_params_t {
      std::array<float, 12> matrix {};
      std::uint32_t transform_type {};
      std::uint32_t input_linear {};
      std::uint32_t output_transfer {};  ///< Zero SDR, one PQ, or two HLG.
      std::uint32_t lut_size {};
    };
    static_assert(sizeof(vdd_color_shader_params_t) == 64);

    struct vdd_gpu_color_transform_t {
      std::shared_ptr<const virtual_display::color_transform_t> source;
      buf_t parameters;
      texture1d_t lut_texture;
      shader_res_t lut_view;
    };

    ~d3d_base_encode_device() {
      pending_telemetry_child.reset();
      fused_d3d11::telemetry().retire_frame_session(telemetry_session);
    }

    void set_telemetry_session(fused_d3d11::telemetry_session_t session) noexcept {
      pending_telemetry_child.reset();
      fused_d3d11::telemetry().retire_frame_session(telemetry_session);
      telemetry_session = session;
    }

    [[nodiscard]] fused_d3d11::frame_trace_token_t take_telemetry_child() noexcept {
      return pending_telemetry_child.release();
    }

    std::shared_ptr<vdd_gpu_color_transform_t> create_vdd_gpu_color_transform(const img_d3d_t &img) {
      if (!img.color_transform || img.color_transform->type == virtual_display::color_transform_type_e::default_) {
        return {};
      }
      auto gpu = std::make_shared<vdd_gpu_color_transform_t>();
      gpu->source = img.color_transform;
      vdd_color_shader_params_t parameters;
      parameters.transform_type = static_cast<std::uint32_t>(img.color_transform->type);
      parameters.input_linear = img.color_metadata.surface_color_space == virtual_display::frame_color_space_e::scrgb ? 1U : 0U;
      parameters.output_transfer = vdd_output_transfer;

      std::vector<std::array<float, 4>> lut;
      if (img.color_transform->type == virtual_display::color_transform_type_e::rgb256x3x16) {
        const auto &source = std::get<virtual_display::color_transform_rgb256_t>(img.color_transform->payload);
        parameters.lut_size = static_cast<std::uint32_t>(source.red.size());
        lut.resize(source.red.size());
        for (std::size_t index = 0; index < source.red.size(); ++index) {
          constexpr float normalization = 1.0f / 65'535.0f;
          lut[index] = {
            source.red[index] * normalization,
            source.green[index] * normalization,
            source.blue[index] * normalization,
            0.0f,
          };
        }
      } else {
        const auto &source = std::get<virtual_display::color_transform_3x4_t>(img.color_transform->payload);
        parameters.matrix = parameters.output_transfer != 0 ?
                              source.wire_rec2020_matrix_3x4 :
                              source.wire_rec709_matrix_3x4;
        if (source.lut_enabled) {
          parameters.lut_size = static_cast<std::uint32_t>(source.lookup_table_1d.size());
          lut.resize(source.lookup_table_1d.size());
          for (std::size_t index = 0; index < source.lookup_table_1d.size(); ++index) {
            lut[index] = {
              source.lookup_table_1d[index].red,
              source.lookup_table_1d[index].green,
              source.lookup_table_1d[index].blue,
              0.0f,
            };
          }
        }
      }

      gpu->parameters = make_buffer(device.get(), parameters);
      if (!gpu->parameters) {
        return {};
      }
      if (!lut.empty()) {
        D3D11_TEXTURE1D_DESC texture_desc {};
        texture_desc.Width = static_cast<UINT>(lut.size());
        texture_desc.MipLevels = 1;
        texture_desc.ArraySize = 1;
        texture_desc.Format = DXGI_FORMAT_R32G32B32A32_FLOAT;
        texture_desc.Usage = D3D11_USAGE_IMMUTABLE;
        texture_desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        const D3D11_SUBRESOURCE_DATA initial_data {
          lut.data(),
          static_cast<UINT>(lut.size() * sizeof(lut.front())),
          0,
        };
        if (FAILED(device->CreateTexture1D(&texture_desc, &initial_data, &gpu->lut_texture)) ||
            FAILED(device->CreateShaderResourceView(gpu->lut_texture.get(), nullptr, &gpu->lut_view))) {
          return {};
        }
      }
      return gpu;
    }

    bool apply_vdd_color_transform(const img_d3d_t &img) {
      vdd_color_transform_active = false;
      if (!img.color_transform || img.color_transform->type == virtual_display::color_transform_type_e::default_) {
        return true;
      }
      auto selected = vdd_gpu_transform_current;
      if (!selected || selected->source != img.color_transform) {
        selected = vdd_gpu_transform_previous;
      }
      if (!selected || selected->source != img.color_transform) {
        try {
          selected = create_vdd_gpu_color_transform(img);
        } catch (...) {
          return false;
        }
        if (!selected) {
          return false;
        }
        vdd_gpu_transform_previous = std::move(vdd_gpu_transform_current);
        vdd_gpu_transform_current = selected;
      }
      auto *parameters = selected->parameters.get();
      auto *lut_view = selected->lut_view.get();
      device_ctx->PSSetConstantBuffers(1, 1, &parameters);
      device_ctx->PSSetShaderResources(1, 1, &lut_view);
      vdd_color_transform_active = true;
      return true;
    }

    /**
     * @brief Convert a captured D3D image into encoder input textures.
     *
     * @param img_base D3D image supplied by the capture backend.
     * @return Conversion status.
     */
    int convert(platf::img_t &img_base) {
      pending_telemetry_child.reset();
      // Garbage collect mapped capture images whose weak references have expired
      for (auto it = img_ctx_map.begin(); it != img_ctx_map.end();) {
        if (it->second.img_weak.expired()) {
          it = img_ctx_map.erase(it);
        } else {
          it++;
        }
      }

      auto &img = (img_d3d_t &) img_base;
      if (!img.blank) {
        auto telemetry_child = fused_d3d11::frame_trace_owner_t {
          fused_d3d11::telemetry(),
          fused_d3d11::telemetry().begin_conversion_frame(
            img.telemetry_capture_token,
            telemetry_session
          ),
        };
        const auto telemetry_trace = telemetry_child.token();
        const auto telemetry_conversion_work_begin_ns = fused_d3d11::telemetry_t::now_ns();
        fused_d3d11::telemetry().record_conversion_work_begin(
          telemetry_trace,
          telemetry_conversion_work_begin_ns
        );
        std::unique_lock<std::mutex> fused_context_lock;
        auto fused_transaction_failed = fused;
        auto fused_failure_guard = util::fail_guard([&]() {
          if (fused_transaction_failed) {
            submission_lifetime.fail();
            if (auto vram_display = std::dynamic_pointer_cast<display_vram_t>(display)) {
              vram_display->request_fused_reinit();
            }
          }
        });

        if (fused) {
          auto vram_display = std::dynamic_pointer_cast<display_vram_t>(display);
          if (!vram_display || !vram_display->fused_nvenc_is_active() || !img.fused_resource ||
              img.resource_ownership != vram_display->encode_resource_ownership ||
              !submission_lifetime.begin_conversion()) {
            BOOST_LOG(error) << "Fused D3D11 conversion resource lifetime violation";
            return -1;
          }
          fused_context_lock = std::unique_lock(*shared_context_mutex);
          fused_d3d11::telemetry().record_conversion_begin();
        }

        auto &img_ctx = img_ctx_map[img.id];

        // Open the legacy shared texture or bind the same-device fused texture directly.
        if (initialize_image_context(img, img_ctx)) {
          return -1;
        }
        if (!apply_vdd_color_transform(img)) {
          BOOST_LOG(error) << "Failed to prepare ABI5 VDD color transform"sv;
          return -1;
        }

        // Only the legacy cross-device path needs a keyed mutex.
        if (!fused) {
          auto status = img_ctx.encoder_mutex->AcquireSync(0, INFINITE);
          if (status != S_OK) {
            BOOST_LOG(error) << "Failed to acquire encoder mutex [0x"sv << util::hex(status).to_string_view() << ']';
            return -1;
          }
          fused_d3d11::telemetry().record_keyed_mutex_acquire();
        }

        auto draw = [&](auto &input, auto &y_or_yuv_viewports, auto &uv_viewport) {
          device_ctx->PSSetShaderResources(0, 1, &input);

          // Draw Y/YUV
          device_ctx->OMSetRenderTargets(1, &out_Y_or_YUV_rtv, nullptr);
          device_ctx->VSSetShader(convert_Y_or_YUV_vs.get(), nullptr, 0);
          device_ctx->PSSetShader(
            vdd_color_transform_active ? convert_Y_or_YUV_vdd_ps.get() :
            img.format == DXGI_FORMAT_R16G16B16A16_FLOAT ? convert_Y_or_YUV_fp16_ps.get() :
                                                           convert_Y_or_YUV_ps.get(),
            nullptr,
            0
          );
          auto viewport_count = (format == DXGI_FORMAT_R16_UINT) ? 3 : 1;
          assert(viewport_count <= y_or_yuv_viewports.size());
          device_ctx->RSSetViewports(viewport_count, y_or_yuv_viewports.data());
          device_ctx->Draw(3 * viewport_count, 0);  // vertex shader will spread vertices across viewports

          // Draw UV if needed
          if (out_UV_rtv) {
            assert(format == DXGI_FORMAT_NV12 || format == DXGI_FORMAT_P010);
            device_ctx->OMSetRenderTargets(1, &out_UV_rtv, nullptr);
            device_ctx->VSSetShader(convert_UV_vs.get(), nullptr, 0);
            device_ctx->PSSetShader(
              vdd_color_transform_active ? convert_UV_vdd_ps.get() :
              img.format == DXGI_FORMAT_R16G16B16A16_FLOAT ? convert_UV_fp16_ps.get() :
                                                             convert_UV_ps.get(),
              nullptr,
              0
            );
            device_ctx->RSSetViewports(1, &uv_viewport);
            device_ctx->Draw(3, 0);
          }
        };

        // Clear render target view(s) once so that the aspect ratio mismatch "bars" appear black
        if (!rtvs_cleared) {
          auto black = create_black_texture_for_rtv_clear();
          if (black) {
            draw(black, out_Y_or_YUV_viewports_for_clear, out_UV_viewport_for_clear);
          }
          rtvs_cleared = true;
        }

        // Draw captured frame
        draw(img_ctx.encoder_input_res, out_Y_or_YUV_viewports, out_UV_viewport);

        // Release the legacy cross-device mutex after source reads are submitted.
        if (!fused) {
          img_ctx.encoder_mutex->ReleaseSync(0);
        }

        ID3D11ShaderResourceView *emptyShaderResourceView = nullptr;
        device_ctx->PSSetShaderResources(0, 1, &emptyShaderResourceView);

        if (fused) {
          if (!submission_lifetime.mark_commands_submitted()) {
            BOOST_LOG(error) << "Fused D3D11 conversion submission state violation";
            return -1;
          }
          fused_d3d11::telemetry().record_conversion_submitted();
          fused_context_lock.unlock();
          if (!submission_lifetime.release_source()) {
            BOOST_LOG(error) << "Fused D3D11 capture source released before command submission";
            return -1;
          }
          fused_transaction_failed = false;
          fused_failure_guard.disable();
        }

        const auto telemetry_conversion_commands_submitted_ns = fused_d3d11::telemetry_t::now_ns();
        fused_d3d11::telemetry().finish_conversion_frame(
          telemetry_trace,
          telemetry_conversion_commands_submitted_ns
        );
        pending_telemetry_child = std::move(telemetry_child);
      }

      return 0;
    }

    /**
     * @brief Apply the configured colorspace metadata to the active frame.
     *
     * @param colorspace Colorimetry information used for conversion or encoding.
     */
    void apply_colorspace(const ::video::sunshine_colorspace_t &colorspace) {
      std::unique_lock<std::mutex> context_lock;
      if (fused) {
        context_lock = std::unique_lock(*shared_context_mutex);
      }
      vdd_output_transfer = colorspace.colorspace == ::video::colorspace_e::bt2020 ? 1U :
                            colorspace.colorspace == ::video::colorspace_e::bt2020hlg ? 2U :
                                                                                       0U;
      auto color_vectors = ::video::color_vectors_from_colorspace(colorspace, true);

      if (format == DXGI_FORMAT_AYUV || format == DXGI_FORMAT_R16_UINT || format == DXGI_FORMAT_Y410) {
        color_vectors = ::video::color_vectors_from_colorspace(colorspace, false);
      }

      if (!color_vectors) {
        BOOST_LOG(error) << "No vector data for colorspace"sv;
        return;
      }

      auto color_matrix = make_buffer(device.get(), *color_vectors);
      if (!color_matrix) {
        BOOST_LOG(warning) << "Failed to create color matrix"sv;
        return;
      }

      device_ctx->VSSetConstantBuffers(3, 1, &color_matrix);
      device_ctx->PSSetConstantBuffers(0, 1, &color_matrix);
      this->color_matrix = std::move(color_matrix);
    }

    /**
     * @brief Create D3D11 output textures, views, and shaders for frame conversion.
     *
     * @param frame_texture Frame texture.
     * @param width Frame or display width in pixels.
     * @param height Frame or display height in pixels.
     * @return 0 when output resources are initialized; nonzero on D3D failure.
     */
    int init_output(ID3D11Texture2D *frame_texture, int width, int height) {
      std::unique_lock<std::mutex> context_lock;
      if (fused) {
        context_lock = std::unique_lock(*shared_context_mutex);
      }
      // The underlying frame pool owns the texture, so we must reference it for ourselves
      frame_texture->AddRef();
      output_texture.reset(frame_texture);

      HRESULT status = S_OK;

#ifndef DOXYGEN
  #define create_vertex_shader_helper(x, y) \
    if (FAILED(status = device->CreateVertexShader(x->GetBufferPointer(), x->GetBufferSize(), nullptr, &y))) { \
      BOOST_LOG(error) << "Failed to create vertex shader " << #x << ": " << util::log_hex(status); \
      return -1; \
    }
#endif
#ifndef DOXYGEN
  #define create_pixel_shader_helper(x, y) \
    if (FAILED(status = device->CreatePixelShader(x->GetBufferPointer(), x->GetBufferSize(), nullptr, &y))) { \
      BOOST_LOG(error) << "Failed to create pixel shader " << #x << ": " << util::log_hex(status); \
      return -1; \
    }
#endif

      const bool downscaling = display->width > width || display->height > height;

      switch (format) {
        case DXGI_FORMAT_NV12:
          // Semi-planar 8-bit YUV 4:2:0
          create_vertex_shader_helper(convert_yuv420_planar_y_vs_hlsl, convert_Y_or_YUV_vs);
          create_pixel_shader_helper(convert_yuv420_planar_y_ps_hlsl, convert_Y_or_YUV_ps);
          create_pixel_shader_helper(convert_yuv420_planar_y_ps_linear_hlsl, convert_Y_or_YUV_fp16_ps);
          if (display->direct_vdd_is_active()) {
            create_pixel_shader_helper(convert_yuv420_planar_y_ps_vdd_color_transform_hlsl, convert_Y_or_YUV_vdd_ps);
          }
          if (downscaling) {
            create_vertex_shader_helper(convert_yuv420_packed_uv_type0s_vs_hlsl, convert_UV_vs);
            create_pixel_shader_helper(convert_yuv420_packed_uv_type0s_ps_hlsl, convert_UV_ps);
            create_pixel_shader_helper(convert_yuv420_packed_uv_type0s_ps_linear_hlsl, convert_UV_fp16_ps);
            if (display->direct_vdd_is_active()) {
              create_pixel_shader_helper(convert_yuv420_packed_uv_type0s_ps_vdd_color_transform_hlsl, convert_UV_vdd_ps);
            }
          } else {
            create_vertex_shader_helper(convert_yuv420_packed_uv_type0_vs_hlsl, convert_UV_vs);
            create_pixel_shader_helper(convert_yuv420_packed_uv_type0_ps_hlsl, convert_UV_ps);
            create_pixel_shader_helper(convert_yuv420_packed_uv_type0_ps_linear_hlsl, convert_UV_fp16_ps);
            if (display->direct_vdd_is_active()) {
              create_pixel_shader_helper(convert_yuv420_packed_uv_type0_ps_vdd_color_transform_hlsl, convert_UV_vdd_ps);
            }
          }
          break;

        case DXGI_FORMAT_P010:
          // Semi-planar 16-bit YUV 4:2:0, 10 most significant bits store the value
          create_vertex_shader_helper(convert_yuv420_planar_y_vs_hlsl, convert_Y_or_YUV_vs);
          create_pixel_shader_helper(convert_yuv420_planar_y_ps_hlsl, convert_Y_or_YUV_ps);
          if (display->is_hdr()) {
            create_pixel_shader_helper(convert_yuv420_planar_y_ps_perceptual_quantizer_hlsl, convert_Y_or_YUV_fp16_ps);
          } else {
            create_pixel_shader_helper(convert_yuv420_planar_y_ps_linear_hlsl, convert_Y_or_YUV_fp16_ps);
          }
          if (display->direct_vdd_is_active()) {
            create_pixel_shader_helper(convert_yuv420_planar_y_ps_vdd_color_transform_hlsl, convert_Y_or_YUV_vdd_ps);
          }
          if (downscaling) {
            create_vertex_shader_helper(convert_yuv420_packed_uv_type0s_vs_hlsl, convert_UV_vs);
            create_pixel_shader_helper(convert_yuv420_packed_uv_type0s_ps_hlsl, convert_UV_ps);
            if (display->is_hdr()) {
              create_pixel_shader_helper(convert_yuv420_packed_uv_type0s_ps_perceptual_quantizer_hlsl, convert_UV_fp16_ps);
            } else {
              create_pixel_shader_helper(convert_yuv420_packed_uv_type0s_ps_linear_hlsl, convert_UV_fp16_ps);
            }
            if (display->direct_vdd_is_active()) {
              create_pixel_shader_helper(convert_yuv420_packed_uv_type0s_ps_vdd_color_transform_hlsl, convert_UV_vdd_ps);
            }
          } else {
            create_vertex_shader_helper(convert_yuv420_packed_uv_type0_vs_hlsl, convert_UV_vs);
            create_pixel_shader_helper(convert_yuv420_packed_uv_type0_ps_hlsl, convert_UV_ps);
            if (display->is_hdr()) {
              create_pixel_shader_helper(convert_yuv420_packed_uv_type0_ps_perceptual_quantizer_hlsl, convert_UV_fp16_ps);
            } else {
              create_pixel_shader_helper(convert_yuv420_packed_uv_type0_ps_linear_hlsl, convert_UV_fp16_ps);
            }
            if (display->direct_vdd_is_active()) {
              create_pixel_shader_helper(convert_yuv420_packed_uv_type0_ps_vdd_color_transform_hlsl, convert_UV_vdd_ps);
            }
          }
          break;

        case DXGI_FORMAT_R16_UINT:
          // Planar 16-bit YUV 4:4:4, 10 most significant bits store the value
          create_vertex_shader_helper(convert_yuv444_planar_vs_hlsl, convert_Y_or_YUV_vs);
          create_pixel_shader_helper(convert_yuv444_planar_ps_hlsl, convert_Y_or_YUV_ps);
          if (display->is_hdr()) {
            create_pixel_shader_helper(convert_yuv444_planar_ps_perceptual_quantizer_hlsl, convert_Y_or_YUV_fp16_ps);
          } else {
            create_pixel_shader_helper(convert_yuv444_planar_ps_linear_hlsl, convert_Y_or_YUV_fp16_ps);
          }
          if (display->direct_vdd_is_active()) {
            create_pixel_shader_helper(convert_yuv444_planar_ps_vdd_color_transform_hlsl, convert_Y_or_YUV_vdd_ps);
          }
          break;

        case DXGI_FORMAT_AYUV:
          // Packed 8-bit YUV 4:4:4
          create_vertex_shader_helper(convert_yuv444_packed_vs_hlsl, convert_Y_or_YUV_vs);
          create_pixel_shader_helper(convert_yuv444_packed_ayuv_ps_hlsl, convert_Y_or_YUV_ps);
          create_pixel_shader_helper(convert_yuv444_packed_ayuv_ps_linear_hlsl, convert_Y_or_YUV_fp16_ps);
          if (display->direct_vdd_is_active()) {
            create_pixel_shader_helper(convert_yuv444_packed_ayuv_ps_vdd_color_transform_hlsl, convert_Y_or_YUV_vdd_ps);
          }
          break;

        case DXGI_FORMAT_Y410:
          // Packed 10-bit YUV 4:4:4
          create_vertex_shader_helper(convert_yuv444_packed_vs_hlsl, convert_Y_or_YUV_vs);
          create_pixel_shader_helper(convert_yuv444_packed_y410_ps_hlsl, convert_Y_or_YUV_ps);
          if (display->is_hdr()) {
            create_pixel_shader_helper(convert_yuv444_packed_y410_ps_perceptual_quantizer_hlsl, convert_Y_or_YUV_fp16_ps);
          } else {
            create_pixel_shader_helper(convert_yuv444_packed_y410_ps_linear_hlsl, convert_Y_or_YUV_fp16_ps);
          }
          if (display->direct_vdd_is_active()) {
            create_pixel_shader_helper(convert_yuv444_packed_y410_ps_vdd_color_transform_hlsl, convert_Y_or_YUV_vdd_ps);
          }
          break;

        default:
          BOOST_LOG(error) << "Unable to create shaders because of the unrecognized surface format";
          return -1;
      }

#undef create_vertex_shader_helper
#undef create_pixel_shader_helper

      auto out_width = width;
      auto out_height = height;

      float in_width = display->width;
      float in_height = display->height;

      // Ensure aspect ratio is maintained
      auto scalar = std::fminf(out_width / in_width, out_height / in_height);
      auto out_width_f = in_width * scalar;
      auto out_height_f = in_height * scalar;

      // result is always positive
      auto offsetX = (out_width - out_width_f) / 2;
      auto offsetY = (out_height - out_height_f) / 2;

      out_Y_or_YUV_viewports[0] = {offsetX, offsetY, out_width_f, out_height_f, 0.0f, 1.0f};  // Y plane
      out_Y_or_YUV_viewports[1] = out_Y_or_YUV_viewports[0];  // U plane
      out_Y_or_YUV_viewports[1].TopLeftY += out_height;
      out_Y_or_YUV_viewports[2] = out_Y_or_YUV_viewports[1];  // V plane
      out_Y_or_YUV_viewports[2].TopLeftY += out_height;

      out_Y_or_YUV_viewports_for_clear[0] = {0, 0, (float) out_width, (float) out_height, 0.0f, 1.0f};  // Y plane
      out_Y_or_YUV_viewports_for_clear[1] = out_Y_or_YUV_viewports_for_clear[0];  // U plane
      out_Y_or_YUV_viewports_for_clear[1].TopLeftY += out_height;
      out_Y_or_YUV_viewports_for_clear[2] = out_Y_or_YUV_viewports_for_clear[1];  // V plane
      out_Y_or_YUV_viewports_for_clear[2].TopLeftY += out_height;

      out_UV_viewport = {offsetX / 2, offsetY / 2, out_width_f / 2, out_height_f / 2, 0.0f, 1.0f};
      out_UV_viewport_for_clear = {0, 0, (float) out_width / 2, (float) out_height / 2, 0.0f, 1.0f};

      float subsample_offset_in[16 / sizeof(float)] {1.0f / (float) out_width_f, 1.0f / (float) out_height_f};  // aligned to 16-byte
      subsample_offset = make_buffer(device.get(), subsample_offset_in);

      if (!subsample_offset) {
        BOOST_LOG(error) << "Failed to create subsample offset vertex constant buffer";
        return -1;
      }
      device_ctx->VSSetConstantBuffers(0, 1, &subsample_offset);

      {
        int32_t rotation_modifier = display->display_rotation == DXGI_MODE_ROTATION_UNSPECIFIED ? 0 : display->display_rotation - 1;
        int32_t rotation_data[16 / sizeof(int32_t)] {-rotation_modifier};  // aligned to 16-byte
        auto rotation = make_buffer(device.get(), rotation_data);
        if (!rotation) {
          BOOST_LOG(error) << "Failed to create display rotation vertex constant buffer";
          return -1;
        }
        device_ctx->VSSetConstantBuffers(1, 1, &rotation);
      }

      DXGI_FORMAT rtv_Y_or_YUV_format = DXGI_FORMAT_UNKNOWN;
      DXGI_FORMAT rtv_UV_format = DXGI_FORMAT_UNKNOWN;
      bool rtv_simple_clear = false;

      switch (format) {
        case DXGI_FORMAT_NV12:
          rtv_Y_or_YUV_format = DXGI_FORMAT_R8_UNORM;
          rtv_UV_format = DXGI_FORMAT_R8G8_UNORM;
          rtv_simple_clear = true;
          break;

        case DXGI_FORMAT_P010:
          rtv_Y_or_YUV_format = DXGI_FORMAT_R16_UNORM;
          rtv_UV_format = DXGI_FORMAT_R16G16_UNORM;
          rtv_simple_clear = true;
          break;

        case DXGI_FORMAT_AYUV:
          rtv_Y_or_YUV_format = DXGI_FORMAT_R8G8B8A8_UINT;
          break;

        case DXGI_FORMAT_R16_UINT:
          rtv_Y_or_YUV_format = DXGI_FORMAT_R16_UINT;
          break;

        case DXGI_FORMAT_Y410:
          rtv_Y_or_YUV_format = DXGI_FORMAT_R10G10B10A2_UINT;
          break;

        default:
          BOOST_LOG(error) << "Unable to create render target views because of the unrecognized surface format";
          return -1;
      }

      auto create_rtv = [&](auto &rt, DXGI_FORMAT rt_format) -> bool {
        D3D11_RENDER_TARGET_VIEW_DESC rtv_desc = {};
        rtv_desc.Format = rt_format;
        rtv_desc.ViewDimension = D3D11_RTV_DIMENSION_TEXTURE2D;

        auto status = device->CreateRenderTargetView(output_texture.get(), &rtv_desc, &rt);
        if (FAILED(status)) {
          BOOST_LOG(error) << "Failed to create render target view: " << util::log_hex(status);
          return false;
        }

        return true;
      };

      // Create Y/YUV render target view
      if (!create_rtv(out_Y_or_YUV_rtv, rtv_Y_or_YUV_format)) {
        return -1;
      }

      // Create UV render target view if needed
      if (rtv_UV_format != DXGI_FORMAT_UNKNOWN && !create_rtv(out_UV_rtv, rtv_UV_format)) {
        return -1;
      }

      if (rtv_simple_clear) {
        // Clear the RTVs to ensure the aspect ratio padding is black
        const float y_black[] = {0.0f, 0.0f, 0.0f, 0.0f};
        device_ctx->ClearRenderTargetView(out_Y_or_YUV_rtv.get(), y_black);
        if (out_UV_rtv) {
          const float uv_black[] = {0.5f, 0.5f, 0.5f, 0.5f};
          device_ctx->ClearRenderTargetView(out_UV_rtv.get(), uv_black);
        }
        rtvs_cleared = true;
      } else {
        // Can't use ClearRenderTargetView(), will clear on first convert()
        rtvs_cleared = false;
      }

      return 0;
    }

    /**
     * @brief Initialize shared D3D conversion resources for the encoder.
     *
     * @param display Display object or identifier associated with the operation.
     * @param adapter_p Adapter p.
     * @param pix_fmt Sunshine pixel format to convert or allocate for.
     * @param use_capture_device Whether conversion reuses the capture D3D11 device and immediate context.
     * @return 0 on success; nonzero or negative platform status on failure.
     */
    int init(
      std::shared_ptr<platf::display_t> display,
      adapter_t::pointer adapter_p,
      pix_fmt_e pix_fmt,
      bool use_capture_device = false
    ) {
      switch (pix_fmt) {
        case pix_fmt_e::nv12:
          format = DXGI_FORMAT_NV12;
          break;

        case pix_fmt_e::p010:
          format = DXGI_FORMAT_P010;
          break;

        case pix_fmt_e::ayuv:
          format = DXGI_FORMAT_AYUV;
          break;

        case pix_fmt_e::yuv444p16:
          format = DXGI_FORMAT_R16_UINT;
          break;

        case pix_fmt_e::y410:
          format = DXGI_FORMAT_Y410;
          break;

        default:
          BOOST_LOG(error) << "D3D11 backend doesn't support pixel format: " << from_pix_fmt(pix_fmt);
          return -1;
      }

      this->display = std::dynamic_pointer_cast<display_base_t>(display);
      if (!this->display) {
        return -1;
      }
      display = nullptr;

      HRESULT status = S_OK;
      if (use_capture_device) {
        auto vram_display = std::dynamic_pointer_cast<display_vram_t>(this->display);
        if (!vram_display) {
          return -1;
        }
        this->display->device->AddRef();
        device.reset(this->display->device.get());
        this->display->device_ctx->AddRef();
        device_ctx.reset(this->display->device_ctx.get());
        shared_context_mutex = &vram_display->fused_context_mutex;
        fused = submission_lifetime.enable();
        if (!fused) {
          BOOST_LOG(error) << "Failed to initialize fused D3D11 submission lifetime";
          return -1;
        }
      } else {
        D3D_FEATURE_LEVEL featureLevels[] {
          D3D_FEATURE_LEVEL_11_1,
          D3D_FEATURE_LEVEL_11_0,
          D3D_FEATURE_LEVEL_10_1,
          D3D_FEATURE_LEVEL_10_0,
          D3D_FEATURE_LEVEL_9_3,
          D3D_FEATURE_LEVEL_9_2,
          D3D_FEATURE_LEVEL_9_1
        };

        status = D3D11CreateDevice(
          adapter_p,
          D3D_DRIVER_TYPE_UNKNOWN,
          nullptr,
          D3D11_CREATE_DEVICE_FLAGS | D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
          featureLevels,
          sizeof(featureLevels) / sizeof(D3D_FEATURE_LEVEL),
          D3D11_SDK_VERSION,
          &device,
          nullptr,
          &device_ctx
        );

        if (FAILED(status)) {
          BOOST_LOG(error) << "Failed to create encoder D3D11 device [0x"sv << util::hex(status).to_string_view() << ']';
          return -1;
        }
      }

      dxgi::dxgi_t dxgi;
      status = device->QueryInterface(IID_IDXGIDevice, (void **) &dxgi);
      if (FAILED(status)) {
        BOOST_LOG(warning) << "Failed to query DXGI interface from device [0x"sv << util::hex(status).to_string_view() << ']';
        return -1;
      }

      status = dxgi->SetGPUThreadPriority(7);
      if (FAILED(status)) {
        BOOST_LOG(warning) << "Failed to increase encoding GPU thread priority. Please run application as administrator for optimal performance.";
      }

      auto default_color_vectors = ::video::color_vectors_from_colorspace({::video::colorspace_e::rec601, false, 8}, true);
      if (!default_color_vectors) {
        BOOST_LOG(error) << "Missing color vectors for Rec. 601"sv;
        return -1;
      }

      color_matrix = make_buffer(device.get(), *default_color_vectors);
      if (!color_matrix) {
        BOOST_LOG(error) << "Failed to create color matrix buffer"sv;
        return -1;
      }
      device_ctx->VSSetConstantBuffers(3, 1, &color_matrix);
      device_ctx->PSSetConstantBuffers(0, 1, &color_matrix);

      blend_disable = make_blend(device.get(), false, false);
      if (!blend_disable) {
        return -1;
      }

      D3D11_SAMPLER_DESC sampler_desc {};
      sampler_desc.Filter = D3D11_FILTER_MIN_MAG_MIP_LINEAR;
      sampler_desc.AddressU = D3D11_TEXTURE_ADDRESS_CLAMP;
      sampler_desc.AddressV = D3D11_TEXTURE_ADDRESS_CLAMP;
      sampler_desc.AddressW = D3D11_TEXTURE_ADDRESS_WRAP;
      sampler_desc.ComparisonFunc = D3D11_COMPARISON_NEVER;
      sampler_desc.MinLOD = 0;
      sampler_desc.MaxLOD = D3D11_FLOAT32_MAX;

      status = device->CreateSamplerState(&sampler_desc, &sampler_linear);
      if (FAILED(status)) {
        BOOST_LOG(error) << "Failed to create point sampler state [0x"sv << util::hex(status).to_string_view() << ']';
        return -1;
      }

      device_ctx->OMSetBlendState(blend_disable.get(), nullptr, 0xFFFFFFFFu);
      device_ctx->PSSetSamplers(0, 1, &sampler_linear);
      device_ctx->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);

      return 0;
    }

    /**
     * @brief D3D texture and format information for encoder input.
     */
    struct encoder_img_ctx_t {
      // Used to determine if the underlying texture changes.
      // Not safe for actual use by the encoder!
      texture2d_t::const_pointer capture_texture_p;  ///< Capture texture p.

      texture2d_t encoder_texture;  ///< Encoder texture.
      shader_res_t encoder_input_res;  ///< Encoder input res.
      keyed_mutex_t encoder_mutex;  ///< Encoder mutex.

      std::weak_ptr<const platf::img_t> img_weak;  ///< Captured image lifetime tracked for cache cleanup.

      /**
       * @brief Reset the object to its initial empty state.
       */
      void reset() {
        capture_texture_p = nullptr;
        encoder_texture.reset();
        encoder_input_res.reset();
        encoder_mutex.reset();
        img_weak.reset();
      }
    };

    /**
     * @brief Initialize encoder-side D3D resources for a captured image.
     *
     * @param img Image or frame object to read from or populate.
     * @param img_ctx Cached encoder resources associated with the image ID.
     * @return 0 when the shared texture is opened and bound; nonzero on D3D failure.
     */
    int initialize_image_context(img_d3d_t &img, encoder_img_ctx_t &img_ctx) {
      // If we've already opened the shared texture, we're done
      if (img_ctx.encoder_texture && img.capture_texture.get() == img_ctx.capture_texture_p) {
        return 0;
      }

      // Reset this image context in case it was used before with a different texture.
      // Textures can change when transitioning from a dummy image to a real image.
      img_ctx.reset();

      if (fused) {
        if (!img.fused_resource || !img.capture_texture) {
          BOOST_LOG(error) << "Fused D3D11 image is not a same-device resource";
          return -1;
        }

        img.capture_texture->AddRef();
        img_ctx.encoder_texture.reset(img.capture_texture.get());
        auto status = device->CreateShaderResourceView(img_ctx.encoder_texture.get(), nullptr, &img_ctx.encoder_input_res);
        if (FAILED(status)) {
          BOOST_LOG(error) << "Failed to create fused capture shader resource view [0x"sv << util::hex(status).to_string_view() << ']';
          return -1;
        }

        img_ctx.capture_texture_p = img.capture_texture.get();
        img_ctx.img_weak = img.weak_from_this();
        return 0;
      }

      device1_t device1;
      auto status = device->QueryInterface(__uuidof(ID3D11Device1), (void **) &device1);
      if (FAILED(status)) {
        BOOST_LOG(error) << "Failed to query ID3D11Device1 [0x"sv << util::hex(status).to_string_view() << ']';
        return -1;
      }

      // Open a handle to the shared texture
      status = device1->OpenSharedResource1(img.encoder_texture_handle, __uuidof(ID3D11Texture2D), (void **) &img_ctx.encoder_texture);
      if (FAILED(status)) {
        BOOST_LOG(error) << "Failed to open shared image texture [0x"sv << util::hex(status).to_string_view() << ']';
        return -1;
      }
      fused_d3d11::telemetry().record_shared_handle_open();

      // Get the keyed mutex to synchronize with the capture code
      status = img_ctx.encoder_texture->QueryInterface(__uuidof(IDXGIKeyedMutex), (void **) &img_ctx.encoder_mutex);
      if (FAILED(status)) {
        BOOST_LOG(error) << "Failed to query IDXGIKeyedMutex [0x"sv << util::hex(status).to_string_view() << ']';
        return -1;
      }

      // Create the SRV for the encoder texture
      status = device->CreateShaderResourceView(img_ctx.encoder_texture.get(), nullptr, &img_ctx.encoder_input_res);
      if (FAILED(status)) {
        BOOST_LOG(error) << "Failed to create shader resource view for encoding [0x"sv << util::hex(status).to_string_view() << ']';
        return -1;
      }

      img_ctx.capture_texture_p = img.capture_texture.get();

      img_ctx.img_weak = img.weak_from_this();

      return 0;
    }

    /**
     * @brief Create black texture for rtv clear.
     *
     * @return Created black texture for rtv clear object or status.
     */
    shader_res_t create_black_texture_for_rtv_clear() {
      constexpr auto width = 32;
      constexpr auto height = 32;

      D3D11_TEXTURE2D_DESC texture_desc = {};
      texture_desc.Width = width;
      texture_desc.Height = height;
      texture_desc.MipLevels = 1;
      texture_desc.ArraySize = 1;
      texture_desc.SampleDesc.Count = 1;
      texture_desc.Usage = D3D11_USAGE_IMMUTABLE;
      texture_desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
      texture_desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

      std::vector<uint8_t> mem(4 * width * height, 0);
      D3D11_SUBRESOURCE_DATA texture_data = {mem.data(), 4 * width, 0};

      texture2d_t texture;
      auto status = device->CreateTexture2D(&texture_desc, &texture_data, &texture);
      if (FAILED(status)) {
        BOOST_LOG(error) << "Failed to create black texture: " << util::log_hex(status);
        return {};
      }

      shader_res_t resource_view;
      status = device->CreateShaderResourceView(texture.get(), nullptr, &resource_view);
      if (FAILED(status)) {
        BOOST_LOG(error) << "Failed to create black texture resource view: " << util::log_hex(status);
        return {};
      }

      return resource_view;
    }

    ::video::color_t *color_p;  ///< Color p.

    buf_t subsample_offset;  ///< Subsample offset.
    buf_t color_matrix;  ///< Color matrix.
    std::shared_ptr<vdd_gpu_color_transform_t> vdd_gpu_transform_current;  ///< Current GPU transform resources.
    std::shared_ptr<vdd_gpu_color_transform_t> vdd_gpu_transform_previous;  ///< Previous retained GPU transform resources.
    bool vdd_color_transform_active {};  ///< Select ABI5 transform shaders for this conversion.
    std::uint32_t vdd_output_transfer {};  ///< Zero SDR, one PQ, or two HLG from negotiated colorimetry.

    blend_t blend_disable;  ///< Blend disable.
    sampler_state_t sampler_linear;  ///< Sampler linear.

    render_target_t out_Y_or_YUV_rtv;  ///< Out y or YUV rtv.
    render_target_t out_UV_rtv;  ///< Out UV rtv.
    bool rtvs_cleared = false;  ///< Whether render-target views have been cleared for the frame.

    // d3d_img_t::id -> encoder_img_ctx_t
    // These store the encoder textures for each img_t that passes through
    // convert(). We can't store them in the img_t itself because it is shared
    // amongst multiple hwdevice_t objects (and therefore multiple ID3D11Devices).
    std::map<uint32_t, encoder_img_ctx_t> img_ctx_map;  ///< Encoder resources cached by captured image ID.

    std::shared_ptr<display_base_t> display;  ///< Display capture backend that supplies source textures.

    vs_t convert_Y_or_YUV_vs;  ///< Convert y or YUV vs.
    ps_t convert_Y_or_YUV_ps;  ///< Convert y or YUV ps.
    ps_t convert_Y_or_YUV_fp16_ps;  ///< Convert y or YUV fp16 ps.
    ps_t convert_Y_or_YUV_vdd_ps;  ///< Convert y or YUV with ABI5 VDD transform.

    vs_t convert_UV_vs;  ///< Convert UV vs.
    ps_t convert_UV_ps;  ///< Convert UV ps.
    ps_t convert_UV_fp16_ps;  ///< Convert UV fp16 ps.
    ps_t convert_UV_vdd_ps;  ///< Convert UV with ABI5 VDD transform.

    std::array<D3D11_VIEWPORT, 3> out_Y_or_YUV_viewports;  ///< Out y or YUV viewports.
    std::array<D3D11_VIEWPORT, 3> out_Y_or_YUV_viewports_for_clear;  ///< Out y or YUV viewports for clear.
    D3D11_VIEWPORT out_UV_viewport;  ///< Out UV viewport.
    D3D11_VIEWPORT out_UV_viewport_for_clear;  ///< Out UV viewport for clear.

    DXGI_FORMAT format;  ///< DXGI format required by the encoder input texture.

    device_t device;  ///< D3D11 device used for encoder-side texture conversion.
    device_ctx_t device_ctx;  ///< D3D11 device context used to issue conversion commands.

    texture2d_t output_texture;  ///< Output texture.
    bool fused = false;  ///< Whether capture and conversion share the exact D3D11 device and context.
    std::mutex *shared_context_mutex = nullptr;  ///< Mutex serializing complete operations on the shared immediate context.
    fused_d3d11::submission_lifetime_t submission_lifetime;  ///< Ordered source-borrow submission state.
    fused_d3d11::telemetry_session_t telemetry_session;  ///< Immutable mode/client identity for this encoder.
    fused_d3d11::frame_trace_owner_t pending_telemetry_child;  ///< Converted child awaiting explicit NVENC transfer.
  };

  /**
   * @brief D3D11 encode device that exposes captured textures to FFmpeg AVCodec.
   */
  class d3d_avcodec_encode_device_t: public avcodec_encode_device_t {
  public:
    /**
     * @brief Release legacy display resource ownership when the encoder ends.
     */
    ~d3d_avcodec_encode_device_t() override {
      if (auto display = resource_display.lock()) {
        auto context_lock = std::lock_guard(display->fused_context_mutex);
        display->release_legacy_encoder();
      }
    }

    /**
     * @brief Initialize the D3D11 AVCodec encode device.
     *
     * @param display Display object or identifier associated with the operation.
     * @param adapter_p Adapter p.
     * @param pix_fmt Sunshine pixel format to convert or allocate for.
     * @return 0 on success; nonzero or negative platform status on failure.
     */
    int init(std::shared_ptr<platf::display_t> display, adapter_t::pointer adapter_p, pix_fmt_e pix_fmt) {
      auto vram_display = std::dynamic_pointer_cast<display_vram_t>(display);
      if (!vram_display) {
        return -1;
      }
      int result = -1;
      {
        auto context_lock = std::lock_guard(vram_display->fused_context_mutex);
        const auto transition = vram_display->encode_resource_ownership->begin_transition(fused_d3d11::resource_mode_e::legacy);
        if (transition == fused_d3d11::transition_result_e::rejected) {
          BOOST_LOG(error) << "Cannot mix AVCodec legacy and fused NVENC ownership on one capture display";
          return -1;
        }
        result = base.init(display, adapter_p, pix_fmt);
        if (result != 0) {
          if (transition == fused_d3d11::transition_result_e::started) {
            vram_display->encode_resource_ownership->rollback_transition(fused_d3d11::resource_mode_e::legacy);
          }
          return result;
        }
        if (transition == fused_d3d11::transition_result_e::started &&
            !vram_display->encode_resource_ownership->commit_transition(fused_d3d11::resource_mode_e::legacy)) {
          return -1;
        }
        if (!vram_display->acquire_legacy_encoder()) {
          return -1;
        }
        resource_display = vram_display;
      }

      data = base.device.get();
      return result;
    }

    /**
     * @brief Convert a captured D3D texture for FFmpeg AVCodec encoding.
     *
     * @param img_base D3D image supplied by the capture backend.
     * @return Conversion status.
     */
    int convert(platf::img_t &img_base) override {
      return base.convert(img_base);
    }

    /**
     * @brief Apply the configured colorspace metadata to the active frame.
     */
    void apply_colorspace() override {
      base.apply_colorspace(colorspace);
    }

    /**
     * @brief Configure FFmpeg hardware frames for D3D11 encoder input textures.
     *
     * @param frames FFmpeg hardware frames context to initialize.
     */
    void init_hwframes(AVHWFramesContext *frames) override {
      // We may be called with a QSV or D3D11VA context
      if (frames->device_ctx->type == AV_HWDEVICE_TYPE_D3D11VA) {
        auto d3d11_frames = (AVD3D11VAFramesContext *) frames->hwctx;

        // The encoder requires textures with D3D11_BIND_RENDER_TARGET set
        d3d11_frames->BindFlags = D3D11_BIND_RENDER_TARGET;
        d3d11_frames->MiscFlags = 0;
      }

      // We require a single texture
      frames->initial_pool_size = 1;
    }

    /**
     * @brief Prepare the D3D device before FFmpeg derives a child hardware context.
     *
     * @param hw_device_type FFmpeg hardware device type requested for context derivation.
     * @return 0 when context derivation may continue; nonzero to abort.
     */
    int prepare_to_derive_context(int hw_device_type) override {
      // QuickSync requires our device to be multithread-protected
      if (hw_device_type == AV_HWDEVICE_TYPE_QSV) {
        multithread_t mt;

        auto status = base.device->QueryInterface(IID_ID3D11Multithread, (void **) &mt);
        if (FAILED(status)) {
          BOOST_LOG(warning) << "Failed to query ID3D11Multithread interface from device [0x"sv << util::hex(status).to_string_view() << ']';
          return -1;
        }

        mt->SetMultithreadProtected(TRUE);
      }

      return 0;
    }

    /**
     * @brief Attach frame resources used by the next conversion or encode operation.
     *
     * @param frame Video or graphics frame being processed.
     * @param hw_frames_ctx FFmpeg hardware frames context associated with the frame.
     * @return Status from updating frame.
     */
    int set_frame(AVFrame *frame, AVBufferRef *hw_frames_ctx) override {
      this->hwframe.reset(frame);
      this->frame = frame;

      // Populate this frame with a hardware buffer if one isn't there already
      if (!frame->buf[0]) {
        auto err = av_hwframe_get_buffer(hw_frames_ctx, frame, 0);
        if (err) {
          char err_str[AV_ERROR_MAX_STRING_SIZE] {0};
          BOOST_LOG(error) << "Failed to get hwframe buffer: "sv << av_make_error_string(err_str, AV_ERROR_MAX_STRING_SIZE, err);
          return -1;
        }
      }

      // If this is a frame from a derived context, we'll need to map it to D3D11
      ID3D11Texture2D *frame_texture;
      if (frame->format != AV_PIX_FMT_D3D11) {
        frame_t d3d11_frame {av_frame_alloc()};

        d3d11_frame->format = AV_PIX_FMT_D3D11;

        auto err = av_hwframe_map(d3d11_frame.get(), frame, AV_HWFRAME_MAP_WRITE | AV_HWFRAME_MAP_OVERWRITE);
        if (err) {
          char err_str[AV_ERROR_MAX_STRING_SIZE] {0};
          BOOST_LOG(error) << "Failed to map D3D11 frame: "sv << av_make_error_string(err_str, AV_ERROR_MAX_STRING_SIZE, err);
          return -1;
        }

        // Get the texture from the mapped frame
        frame_texture = (ID3D11Texture2D *) d3d11_frame->data[0];
      } else {
        // Otherwise, we can just use the texture inside the original frame
        frame_texture = (ID3D11Texture2D *) frame->data[0];
      }

      return base.init_output(frame_texture, frame->width, frame->height);
    }

  private:
    d3d_base_encode_device base;
    frame_t hwframe;
    std::weak_ptr<display_vram_t> resource_display;  ///< Display whose legacy resource mode is owned by this encoder.
  };

  /**
   * @brief NVENC proxy that converts empty encode results into an owning-device failure callback.
   */
  class nvenc_failure_proxy_t final: public nvenc::nvenc_encoder {
  public:
    /** @brief Function invoked before an empty encoded frame is returned to the session. */
    using failure_callback_t = void (*)(void *context);

    /**
     * @brief Bind the concrete encoder and its failure owner.
     *
     * @param target Concrete NVENC implementation.
     * @param context Opaque encode-device owner.
     * @param callback Failure callback invoked for empty encode output.
     */
    void bind(nvenc::nvenc_encoder *target, void *context, failure_callback_t callback) {
      target_ = target;
      context_ = context;
      callback_ = callback;
    }

    /** @copydoc nvenc::nvenc_encoder::create_encoder() */
    bool create_encoder(
      const nvenc::nvenc_config &config,
      const ::video::config_t &client_config,
      const ::video::sunshine_colorspace_t &colorspace,
      platf::pix_fmt_e buffer_format,
      const std::optional<nvenc::hdr_static_metadata_t> &hdr_metadata
    ) override {
      return target_ && target_->create_encoder(config, client_config, colorspace, buffer_format, hdr_metadata);
    }

    /** @copydoc nvenc::nvenc_encoder::update_hdr_metadata() */
    bool update_hdr_metadata(const nvenc::hdr_static_metadata_t &metadata) override {
      return target_ && target_->update_hdr_metadata(metadata);
    }

    /** @copydoc nvenc::nvenc_encoder::destroy_encoder() */
    void destroy_encoder() override {
      if (target_) {
        target_->destroy_encoder();
      }
    }

    /** @copydoc nvenc::nvenc_encoder::encode_frame() */
    nvenc::nvenc_encoded_frame encode_frame(std::uint64_t frame_index, bool force_idr) override {
      auto result = target_ ? target_->encode_frame(frame_index, force_idr) : nvenc::nvenc_encoded_frame {};
      if (result.data.empty() && callback_) {
        callback_(context_);
      }
      return result;
    }

    /** @copydoc nvenc::nvenc_encoder::invalidate_ref_frames() */
    bool invalidate_ref_frames(std::uint64_t first_frame, std::uint64_t last_frame) override {
      return target_ && target_->invalidate_ref_frames(first_frame, last_frame);
    }

  private:
    nvenc::nvenc_encoder *target_ = nullptr;  ///< Non-owning concrete encoder forwarded by this proxy.
    void *context_ = nullptr;  ///< Opaque encode-device owner passed to the callback.
    failure_callback_t callback_ = nullptr;  ///< Callback invoked before empty output escapes.
  };

  /**
   * @brief D3D11 encode device that exposes captured textures to NVENC.
   */
  class d3d_nvenc_encode_device_t: public nvenc_encode_device_t {
  public:
    /**
     * @brief Release fused display ownership when the encoder attempt or session ends.
     */
    ~d3d_nvenc_encode_device_t() override {
      if (auto display = resource_display.lock()) {
        auto context_lock = std::lock_guard(display->fused_context_mutex);
        if (fused_path) {
          if (!fused_healthy) {
            display->request_fused_reinit();
            display->disable_direct_vdd();
          }
          if (nvenc_d3d) {
            nvenc_d3d->set_fused_input_enabled(false);
          }
          failure_proxy.bind(nullptr, nullptr, nullptr);
          nvenc = nullptr;
          nvenc_d3d.reset();
          base.reset();
          display->release_fused_nvenc();
          if (display->fused_reinit_required()) {
            display->encode_resource_ownership->reset_after_reinit();
          }
        } else if (legacy_path) {
          display->release_legacy_encoder();
        }
      }
    }

    /**
     * @brief Create D3D11 and NVENC resources for texture-based encoding.
     *
     * @param display Display object or identifier associated with the operation.
     * @param adapter_p Adapter p.
     * @param pix_fmt Sunshine pixel format to convert or allocate for.
     * @return True when the D3D11 device resources are initialized.
     */
    bool init_device(std::shared_ptr<platf::display_t> display, adapter_t::pointer adapter_p, pix_fmt_e pix_fmt) {
      auto vram_display = std::dynamic_pointer_cast<display_vram_t>(display);
      if (!vram_display) {
        return false;
      }

      if (vram_display->direct_vdd_is_active()) {
        auto context_lock = std::lock_guard(vram_display->fused_context_mutex);
        const auto transition = vram_display->encode_resource_ownership->begin_transition(fused_d3d11::resource_mode_e::fused);
        if (transition != fused_d3d11::transition_result_e::rejected) {
          auto fused_base = std::make_unique<d3d_base_encode_device>();
          if (fused_base->init(display, adapter_p, pix_fmt, true) == 0) {
            if (transition == fused_d3d11::transition_result_e::started &&
                !vram_display->encode_resource_ownership->commit_transition(fused_d3d11::resource_mode_e::fused)) {
              return false;
            }
            if (!vram_display->acquire_fused_nvenc()) {
              return false;
            }
            resource_display = vram_display;
            fused_path = true;
            base = std::move(fused_base);
            fused_d3d11::telemetry().record_fused_activation();
            BOOST_LOG(info) << "Lumen VDD direct-frame source bound to same-device conversion/NVENC; one driver copy, no host capture copy";
          } else {
            if (transition == fused_d3d11::transition_result_e::started) {
              vram_display->encode_resource_ownership->rollback_transition(fused_d3d11::resource_mode_e::fused);
            }
          }
        }
        if (!base) {
          if (vram_display->direct_vdd_is_required()) {
            vram_display->request_fused_reinit();
            vram_display->disable_direct_vdd();
            BOOST_LOG(error) << "Required Lumen VDD direct-frame NVENC binding failed; refusing legacy encode fallback";
            return false;
          }
          vram_display->disable_direct_vdd();
          BOOST_LOG(warning) << "Lumen VDD direct-frame NVENC binding failed; scheduling DDA/WGC fallback";
        }
      } else {
        std::uint64_t active_driver = 0;
        fused_d3d11::telemetry().record_eligibility_attempt();
        const auto request = fused_eligibility(*vram_display, pix_fmt, active_driver);
        const auto decision = fused_d3d11::evaluate(request);

        if (decision.eligible) {
          auto context_lock = std::lock_guard(vram_display->fused_context_mutex);
          const auto transition = vram_display->encode_resource_ownership->begin_transition(fused_d3d11::resource_mode_e::fused);
          if (transition == fused_d3d11::transition_result_e::rejected) {
            BOOST_LOG(warning) << "Experimental fused D3D11 path cannot join a display using legacy encoder resources";
          } else {
            auto fused_base = std::make_unique<d3d_base_encode_device>();
            if (fused_base->init(display, adapter_p, pix_fmt, true) == 0) {
              if (transition == fused_d3d11::transition_result_e::started &&
                  !vram_display->encode_resource_ownership->commit_transition(fused_d3d11::resource_mode_e::fused)) {
                return false;
              }
              if (!vram_display->acquire_fused_nvenc()) {
                return false;
              }
              resource_display = vram_display;
              fused_path = true;
              base = std::move(fused_base);
              fused_d3d11::telemetry().record_fused_activation();
              BOOST_LOG(info)
                << "Experimental fused D3D11 capture-to-NVENC path enabled; driver=" << active_driver
                << ", shared-handle opens and keyed-mutex acquisitions removed";
            } else {
              if (transition == fused_d3d11::transition_result_e::started) {
                vram_display->encode_resource_ownership->rollback_transition(fused_d3d11::resource_mode_e::fused);
              }
              BOOST_LOG(warning) << "Experimental fused D3D11 initialization failed; retaining legacy D3D11 path";
            }
          }
        } else if (request.runtime_gate_enabled) {
          BOOST_LOG(warning)
            << "Experimental fused D3D11 request rejected: " << fused_d3d11::rejection_string(decision.rejection)
            << "; active driver=" << active_driver;
        }
      }

      if (!base) {
        fused_d3d11::telemetry().record_legacy_fallback();
        auto legacy_base = std::make_unique<d3d_base_encode_device>();
        {
          auto context_lock = std::lock_guard(vram_display->fused_context_mutex);
          const auto transition = vram_display->encode_resource_ownership->begin_transition(fused_d3d11::resource_mode_e::legacy);
          if (transition == fused_d3d11::transition_result_e::rejected) {
            BOOST_LOG(error) << "Cannot mix legacy and fused D3D11 resource ownership on one capture display";
            return false;
          }
          if (legacy_base->init(display, adapter_p, pix_fmt) != 0) {
            if (transition == fused_d3d11::transition_result_e::started) {
              vram_display->encode_resource_ownership->rollback_transition(fused_d3d11::resource_mode_e::legacy);
            }
            return false;
          }
          if (transition == fused_d3d11::transition_result_e::started &&
              !vram_display->encode_resource_ownership->commit_transition(fused_d3d11::resource_mode_e::legacy)) {
            return false;
          }
          if (!vram_display->acquire_legacy_encoder()) {
            return false;
          }
          resource_display = vram_display;
          legacy_path = true;
        }
        base = std::move(legacy_base);
      }

      auto factory = nvenc::nvenc_dynamic_factory::get();
      if (!factory) {
        return false;
      }

      if (pix_fmt == pix_fmt_e::yuv444p16) {
        nvenc_d3d = factory->create_nvenc_d3d11_on_cuda(base->device.get());
      } else {
        nvenc_d3d = factory->create_nvenc_d3d11_native(base->device.get());
      }
      if (!nvenc_d3d) {
        return false;
      }
      nvenc_d3d->set_fused_input_enabled(fused_path);

      buffer_format = pix_fmt;
      failure_proxy.bind(nvenc_d3d.get(), this, &d3d_nvenc_encode_device_t::handle_nvenc_failure_callback);
      nvenc = &failure_proxy;

      return true;
    }

    /**
     * @brief Initialize the platform encoder for the client stream configuration.
     *
     * @param client_config Client stream configuration negotiated for this session.
     * @param colorspace Colorimetry information used for conversion or encoding.
     * @return True when the NVENC encoder initializes for the client configuration.
     */
    bool init_encoder(const ::video::config_t &client_config, const ::video::sunshine_colorspace_t &colorspace) override {
      if (!nvenc_d3d) {
        return false;
      }

      std::optional<nvenc::hdr_static_metadata_t> hdr_metadata;
      const auto transfer = colorspace.colorspace == ::video::colorspace_e::bt2020 ?
                              nvenc::hdr_transfer_e::hdr10_pq :
                            colorspace.colorspace == ::video::colorspace_e::bt2020hlg ?
                              nvenc::hdr_transfer_e::hlg :
                              nvenc::hdr_transfer_e::sdr;
      if (transfer == nvenc::hdr_transfer_e::hdr10_pq) {
        const auto display = resource_display.lock();
        hdr_metadata = display ? active_hdr_static_metadata(*display) : std::nullopt;
      }
      const auto hdr_policy = nvenc::evaluate_hdr_metadata_policy(
        client_config.videoFormat,
        transfer,
        hdr_metadata
      );
      if (!hdr_policy.accepted) {
        BOOST_LOG(error) << "NVENC rejected the codec/transfer/static-metadata tuple"sv;
        return false;
      }

      base->set_telemetry_session(fused_d3d11::telemetry().begin_frame_session(
        telemetry_profile(client_config),
        telemetry_client(client_config)
      ));

      if (!nvenc_d3d->create_encoder(
            config::video.nv,
            client_config,
            colorspace,
            buffer_format,
            hdr_metadata
          )) {
        if (fused_path) {
          if (auto display = resource_display.lock()) {
            display->request_fused_reinit();
          }
        }
        return false;
      }

      base->apply_colorspace(colorspace);
      const bool initialized = base->init_output(nvenc_d3d->get_input_texture(), client_config.width, client_config.height) == 0;
      if (!initialized && fused_path) {
        if (auto display = resource_display.lock()) {
          display->request_fused_reinit();
        }
      }
      fused_healthy = initialized && fused_path;
      current_hdr_transfer = initialized ? transfer : nvenc::hdr_transfer_e::sdr;
      current_hdr_static_metadata = initialized ? hdr_metadata : std::nullopt;
      return initialized;
    }

    /**
     * @brief Convert a captured D3D texture for NVENC encoding.
     *
     * @param img_base D3D image supplied by the capture backend.
     * @return Conversion status.
     */
    int convert(platf::img_t &img_base) override {
      const auto &img = static_cast<const img_d3d_t &>(img_base);
      if (img.color_transform) {
        if (current_hdr_transfer == nvenc::hdr_transfer_e::hdr10_pq) {
          const auto metadata = frame_hdr_static_metadata(img.color_metadata);
          if (!metadata) {
            BOOST_LOG(error) << "ABI5 PQ frame omitted valid resolved static metadata"sv;
            return -1;
          }
          if (!current_hdr_static_metadata || *metadata != *current_hdr_static_metadata) {
            if (!nvenc_d3d->update_hdr_metadata(*metadata)) {
              BOOST_LOG(error) << "NVENC rejected changed ABI5 PQ static metadata"sv;
              return -1;
            }
            current_hdr_static_metadata = metadata;
          }
        } else if (current_hdr_transfer == nvenc::hdr_transfer_e::sdr &&
                   img.color_metadata.hdr_metadata_type != virtual_display::hdr_metadata_type_e::none) {
          BOOST_LOG(error) << "ABI5 SDR frame unexpectedly carried HDR metadata"sv;
          return -1;
        }
      }
      const auto result = base->convert(img_base);
      if (result == 0) {
        const auto child = base->take_telemetry_child();
        if (child && !nvenc_d3d->set_frame_telemetry_token(child.value)) {
          fused_d3d11::telemetry().abandon_frame_trace(child);
        }
      } else {
        nvenc_d3d->clear_frame_telemetry_token();
      }
      return result;
    }

  private:
    /** @brief Static trampoline used by the SDK-neutral encoder proxy. */
    static void handle_nvenc_failure_callback(void *context) {
      static_cast<d3d_nvenc_encode_device_t *>(context)->handle_nvenc_failure();
    }

    /** @brief Quarantine fused mode and request capture reinitialization before teardown. */
    void handle_nvenc_failure() {
      if (!fused_path) {
        return;
      }
      fused_healthy = false;
      if (nvenc_d3d) {
        nvenc_d3d->clear_frame_telemetry_token();
      }
      if (auto display = resource_display.lock()) {
        display->request_fused_reinit();
        display->disable_direct_vdd();
      }
    }

    std::unique_ptr<d3d_base_encode_device> base;  ///< Selected fused or legacy D3D11 conversion implementation.
    std::unique_ptr<nvenc::nvenc_d3d11_interface> nvenc_d3d;
    nvenc_failure_proxy_t failure_proxy;  ///< Instance-local hook for Map/Encode/wait/Lock failures.
    platf::pix_fmt_e buffer_format = platf::pix_fmt_e::unknown;
    bool fused_path = false;  ///< Whether this encoder removed legacy cross-device resource boundaries.
    bool fused_healthy = false;  ///< Whether fused encoder initialization completed without requiring rollback.
    bool legacy_path = false;  ///< Whether this encoder owns legacy cross-device capture resources.
    std::optional<nvenc::hdr_static_metadata_t> current_hdr_static_metadata;  ///< Last ABI5 block accepted by NVENC.
    nvenc::hdr_transfer_e current_hdr_transfer {nvenc::hdr_transfer_e::sdr};  ///< Negotiated wire transfer for ABI5 conversion.
    std::weak_ptr<display_vram_t> resource_display;  ///< Display whose resource mode is owned by this encoder.
  };

  /**
   * @brief Set cursor texture.
   *
   * @param device D3D, audio, or platform device used by the operation.
   * @param cursor Cursor image or visibility state to composite.
   * @param cursor_img Cursor img.
   * @param shape_info Shape info.
   * @return True when the cursor image is uploaded to the D3D texture.
   */
  bool set_cursor_texture(device_t::pointer device, gpu_cursor_t &cursor, util::buffer_t<std::uint8_t> &&cursor_img, DXGI_OUTDUPL_POINTER_SHAPE_INFO &shape_info) {
    // This cursor image may not be used
    if (cursor_img.size() == 0) {
      cursor.input_res.reset();
      cursor.set_texture(0, 0, nullptr);
      return true;
    }

    D3D11_SUBRESOURCE_DATA data {
      std::begin(cursor_img),
      4 * shape_info.Width,
      0
    };

    // Create texture for cursor
    D3D11_TEXTURE2D_DESC t {};
    t.Width = shape_info.Width;
    t.Height = cursor_img.size() / data.SysMemPitch;
    t.MipLevels = 1;
    t.ArraySize = 1;
    t.SampleDesc.Count = 1;
    t.Usage = D3D11_USAGE_IMMUTABLE;
    t.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    t.BindFlags = D3D11_BIND_SHADER_RESOURCE;

    texture2d_t texture;
    auto status = device->CreateTexture2D(&t, &data, &texture);
    if (FAILED(status)) {
      BOOST_LOG(error) << "Failed to create mouse texture [0x"sv << util::hex(status).to_string_view() << ']';
      return false;
    }

    // Free resources before allocating on the next line.
    cursor.input_res.reset();
    status = device->CreateShaderResourceView(texture.get(), nullptr, &cursor.input_res);
    if (FAILED(status)) {
      BOOST_LOG(error) << "Failed to create cursor shader resource view [0x"sv << util::hex(status).to_string_view() << ']';
      return false;
    }

    cursor.set_texture(t.Width, t.Height, std::move(texture));
    return true;
  }

  capture_e display_ddup_vram_t::snapshot(const pull_free_image_cb_t &pull_free_image_cb, std::shared_ptr<platf::img_t> &img_out, std::chrono::milliseconds timeout, bool cursor_visible) {
    if (fused_reinit_required()) {
      return capture_e::reinit;
    }
    HRESULT status;
    DXGI_OUTDUPL_FRAME_INFO frame_info;

    resource_t::pointer res_p {};
    auto capture_status = dup.next_frame(frame_info, timeout, &res_p);
    resource_t res {res_p};

    if (capture_status != capture_e::ok) {
      return capture_status;
    }
    const auto telemetry_capture_acquired_ns = fused_d3d11::telemetry_t::now_ns();
    {
      auto context_lock = lock_fused_context();
      if (fused_nvenc_is_active()) {
        fused_d3d11::telemetry().record_capture_acquired();
      }
    }

    const bool mouse_update_flag = frame_info.LastMouseUpdateTime.QuadPart != 0 || frame_info.PointerShapeBufferSize > 0;
    const bool frame_update_flag = frame_info.LastPresentTime.QuadPart != 0;
    const bool update_flag = mouse_update_flag || frame_update_flag;

    if (!update_flag) {
      return capture_e::timeout;
    }

    std::optional<std::chrono::steady_clock::time_point> frame_timestamp;
    if (auto qpc_displayed = std::max(frame_info.LastPresentTime.QuadPart, frame_info.LastMouseUpdateTime.QuadPart)) {
      // Translate QueryPerformanceCounter() value to steady_clock time point
      frame_timestamp = std::chrono::steady_clock::now() - qpc_time_difference(qpc_counter(), qpc_displayed);
    }

    if (frame_info.PointerShapeBufferSize > 0) {
      DXGI_OUTDUPL_POINTER_SHAPE_INFO shape_info {};

      util::buffer_t<std::uint8_t> img_data {frame_info.PointerShapeBufferSize};

      UINT dummy;
      status = dup.dup->GetFramePointerShape(img_data.size(), std::begin(img_data), &dummy, &shape_info);
      if (FAILED(status)) {
        BOOST_LOG(error) << "Failed to get new pointer shape [0x"sv << util::hex(status).to_string_view() << ']';

        return capture_e::error;
      }

      auto alpha_cursor_img = make_cursor_alpha_image(img_data, shape_info);
      auto xor_cursor_img = make_cursor_xor_image(img_data, shape_info);

      if (!set_cursor_texture(device.get(), cursor_alpha, std::move(alpha_cursor_img), shape_info) || !set_cursor_texture(device.get(), cursor_xor, std::move(xor_cursor_img), shape_info)) {
        return capture_e::error;
      }
    }

    if (frame_info.LastMouseUpdateTime.QuadPart) {
      cursor_alpha.set_pos(frame_info.PointerPosition.Position.x, frame_info.PointerPosition.Position.y, width, height, display_rotation, frame_info.PointerPosition.Visible);

      cursor_xor.set_pos(frame_info.PointerPosition.Position.x, frame_info.PointerPosition.Position.y, width, height, display_rotation, frame_info.PointerPosition.Visible);
    }

    const bool blend_mouse_cursor_flag = (cursor_alpha.visible || cursor_xor.visible) && cursor_visible;

    texture2d_t src {};
    if (frame_update_flag) {
      // Get the texture object from this frame
      status = res->QueryInterface(IID_ID3D11Texture2D, (void **) &src);
      if (FAILED(status)) {
        BOOST_LOG(error) << "Couldn't query interface [0x"sv << util::hex(status).to_string_view() << ']';
        return capture_e::error;
      }

      D3D11_TEXTURE2D_DESC desc;
      src->GetDesc(&desc);

      // It's possible for our display enumeration to race with mode changes and result in
      // mismatched image pool and desktop texture sizes. If this happens, just reinit again.
      if (desc.Width != width_before_rotation || desc.Height != height_before_rotation) {
        BOOST_LOG(info) << "Capture size changed ["sv << width << 'x' << height << " -> "sv << desc.Width << 'x' << desc.Height << ']';
        return capture_e::reinit;
      }

      // If we don't know the capture format yet, grab it from this texture
      if (capture_format == DXGI_FORMAT_UNKNOWN) {
        capture_format = desc.Format;
        BOOST_LOG(info) << "Capture format ["sv << dxgi_format_to_string(capture_format) << ']';
      }

      // It's also possible for the capture format to change on the fly. If that happens,
      // reinitialize capture to try format detection again and create new images.
      if (capture_format != desc.Format) {
        BOOST_LOG(info) << "Capture format changed ["sv << dxgi_format_to_string(capture_format) << " -> "sv << dxgi_format_to_string(desc.Format) << ']';
        return capture_e::reinit;
      }
    }

    enum class lfa {
      nothing,
      replace_surface_with_img,
      replace_img_with_surface,
      copy_src_to_img,
      copy_src_to_surface,
    };

    enum class ofa {
      forward_last_img,
      copy_last_surface_and_blend_cursor,
      dummy_fallback,
    };

    auto last_frame_action = lfa::nothing;
    auto out_frame_action = ofa::dummy_fallback;

    if (capture_format == DXGI_FORMAT_UNKNOWN) {
      // We don't know the final capture format yet, so we will encode a black dummy image
      last_frame_action = lfa::nothing;
      out_frame_action = ofa::dummy_fallback;
    } else {
      if (src) {
        // We got a new frame from DesktopDuplication...
        if (blend_mouse_cursor_flag) {
          // ...and we need to blend the mouse cursor onto it.
          // Copy the frame to intermediate surface so we can blend this and future mouse cursor updates
          // without new frames from DesktopDuplication. We use direct3d surface directly here and not
          // an image from pull_free_image_cb mainly because it's lighter (surface sharing between
          // direct3d devices produce significant memory overhead).
          last_frame_action = lfa::copy_src_to_surface;
          // Copy the intermediate surface to a new image from pull_free_image_cb and blend the mouse cursor onto it.
          out_frame_action = ofa::copy_last_surface_and_blend_cursor;
        } else {
          // ...and we don't need to blend the mouse cursor.
          // Copy the frame to a new image from pull_free_image_cb and save the shared pointer to the image
          // in case the mouse cursor appears without a new frame from DesktopDuplication.
          last_frame_action = lfa::copy_src_to_img;
          // Use saved last image shared pointer as output image evading copy.
          out_frame_action = ofa::forward_last_img;
        }
      } else if (!std::holds_alternative<std::monostate>(last_frame_variant)) {
        // We didn't get a new frame from DesktopDuplication...
        if (blend_mouse_cursor_flag) {
          // ...but we need to blend the mouse cursor.
          if (std::holds_alternative<std::shared_ptr<platf::img_t>>(last_frame_variant)) {
            // We have the shared pointer of the last image, replace it with intermediate surface
            // while copying contents so we can blend this and future mouse cursor updates.
            last_frame_action = lfa::replace_img_with_surface;
          }
          // Copy the intermediate surface which contains last DesktopDuplication frame
          // to a new image from pull_free_image_cb and blend the mouse cursor onto it.
          out_frame_action = ofa::copy_last_surface_and_blend_cursor;
        } else {
          // ...and we don't need to blend the mouse cursor.
          // This happens when the mouse cursor disappears from screen,
          // or there's mouse cursor on screen, but its drawing is disabled in sunshine.
          if (std::holds_alternative<texture2d_t>(last_frame_variant)) {
            // We have the intermediate surface that was used as the mouse cursor blending base.
            // Replace it with an image from pull_free_image_cb copying contents and freeing up the surface memory.
            // Save the shared pointer to the image in case the mouse cursor reappears.
            last_frame_action = lfa::replace_surface_with_img;
          }
          // Use saved last image shared pointer as output image evading copy.
          out_frame_action = ofa::forward_last_img;
        }
      }
    }

    auto create_surface = [&](texture2d_t &surface) -> bool {
      // Try to reuse the old surface if it hasn't been destroyed yet.
      if (old_surface_delayed_destruction) {
        surface.reset(old_surface_delayed_destruction.release());
        return true;
      }

      // Otherwise create a new surface.
      D3D11_TEXTURE2D_DESC t {};
      t.Width = width_before_rotation;
      t.Height = height_before_rotation;
      t.MipLevels = 1;
      t.ArraySize = 1;
      t.SampleDesc.Count = 1;
      t.Usage = D3D11_USAGE_DEFAULT;
      t.Format = capture_format;
      t.BindFlags = 0;
      status = device->CreateTexture2D(&t, nullptr, &surface);
      if (FAILED(status)) {
        BOOST_LOG(error) << "Failed to create frame copy texture [0x"sv << util::hex(status).to_string_view() << ']';
        return false;
      }

      return true;
    };

    auto get_locked_d3d_img = [&](std::shared_ptr<platf::img_t> &img, bool dummy = false) -> std::tuple<std::shared_ptr<img_d3d_t>, texture_lock_helper> {
      auto d3d_img = std::static_pointer_cast<img_d3d_t>(img);

      // Finish creating the image (if it hasn't happened already),
      // also creates synchronization primitives for shared access from multiple direct3d devices.
      if (complete_img(d3d_img.get(), dummy)) {
        return {nullptr, nullptr};
      }

      // This image is shared between capture direct3d device and encoders direct3d devices,
      // we must acquire lock before doing anything to it.
      texture_lock_helper lock_helper(d3d_img->capture_mutex.get());
      if (!lock_helper.lock()) {
        BOOST_LOG(error) << "Failed to lock capture texture";
        return {nullptr, nullptr};
      }

      // Clear the blank flag now that we're ready to capture into the image
      d3d_img->blank = false;

      return {std::move(d3d_img), std::move(lock_helper)};
    };

    switch (last_frame_action) {
      case lfa::nothing:
        {
          break;
        }

      case lfa::replace_surface_with_img:
        {
          auto p_surface = std::get_if<texture2d_t>(&last_frame_variant);
          if (!p_surface) {
            BOOST_LOG(error) << "Logical error at " << __FILE__ << ":" << __LINE__;
            return capture_e::error;
          }

          std::shared_ptr<platf::img_t> img;
          if (!pull_free_image_cb(img)) {
            return capture_e::interrupted;
          }

          auto [d3d_img, lock] = get_locked_d3d_img(img);
          if (!d3d_img) {
            return capture_completion_failure(*this);
          }

          {
            auto context_lock = lock_fused_context();
            device_ctx->CopyResource(d3d_img->capture_texture.get(), p_surface->get());
            if (fused_nvenc_is_active()) {
              fused_d3d11::telemetry().record_capture_copy_submitted();
            }
          }

          // We delay the destruction of intermediate surface in case the mouse cursor reappears shortly.
          old_surface_delayed_destruction.reset(p_surface->release());
          old_surface_timestamp = std::chrono::steady_clock::now();

          last_frame_variant = img;
          break;
        }

      case lfa::replace_img_with_surface:
        {
          auto p_img = std::get_if<std::shared_ptr<platf::img_t>>(&last_frame_variant);
          if (!p_img) {
            BOOST_LOG(error) << "Logical error at " << __FILE__ << ":" << __LINE__;
            return capture_e::error;
          }
          auto [d3d_img, lock] = get_locked_d3d_img(*p_img);
          if (!d3d_img) {
            return capture_completion_failure(*this);
          }

          p_img = nullptr;
          last_frame_variant = texture2d_t {};
          auto &surface = std::get<texture2d_t>(last_frame_variant);
          if (!create_surface(surface)) {
            return capture_e::error;
          }

          {
            auto context_lock = lock_fused_context();
            device_ctx->CopyResource(surface.get(), d3d_img->capture_texture.get());
            if (fused_nvenc_is_active()) {
              fused_d3d11::telemetry().record_capture_copy_submitted();
            }
          }
          break;
        }

      case lfa::copy_src_to_img:
        {
          last_frame_variant = {};

          std::shared_ptr<platf::img_t> img;
          if (!pull_free_image_cb(img)) {
            return capture_e::interrupted;
          }

          auto [d3d_img, lock] = get_locked_d3d_img(img);
          if (!d3d_img) {
            return capture_completion_failure(*this);
          }

          {
            auto context_lock = lock_fused_context();
            device_ctx->CopyResource(d3d_img->capture_texture.get(), src.get());
            if (fused_nvenc_is_active()) {
              fused_d3d11::telemetry().record_capture_copy_submitted();
            }
          }
          last_frame_variant = img;
          break;
        }

      case lfa::copy_src_to_surface:
        {
          auto p_surface = std::get_if<texture2d_t>(&last_frame_variant);
          if (!p_surface) {
            last_frame_variant = texture2d_t {};
            p_surface = std::get_if<texture2d_t>(&last_frame_variant);
            if (!create_surface(*p_surface)) {
              return capture_e::error;
            }
          }
          {
            auto context_lock = lock_fused_context();
            device_ctx->CopyResource(p_surface->get(), src.get());
            if (fused_nvenc_is_active()) {
              fused_d3d11::telemetry().record_capture_copy_submitted();
            }
          }
          break;
        }
    }

    auto blend_cursor = [&](img_d3d_t &d3d_img) {
      auto context_lock = lock_fused_context();
      device_ctx->VSSetShader(cursor_vs.get(), nullptr, 0);
      device_ctx->PSSetShader(cursor_ps.get(), nullptr, 0);
      device_ctx->OMSetRenderTargets(1, &d3d_img.capture_rt, nullptr);

      if (cursor_alpha.texture.get()) {
        // Perform an alpha blending operation
        device_ctx->OMSetBlendState(blend_alpha.get(), nullptr, 0xFFFFFFFFu);

        device_ctx->PSSetShaderResources(0, 1, &cursor_alpha.input_res);
        device_ctx->RSSetViewports(1, &cursor_alpha.cursor_view);
        device_ctx->Draw(3, 0);
      }

      if (cursor_xor.texture.get()) {
        // Perform an invert blending without touching alpha values
        device_ctx->OMSetBlendState(blend_invert.get(), nullptr, 0x00FFFFFFu);

        device_ctx->PSSetShaderResources(0, 1, &cursor_xor.input_res);
        device_ctx->RSSetViewports(1, &cursor_xor.cursor_view);
        device_ctx->Draw(3, 0);
      }

      device_ctx->OMSetBlendState(blend_disable.get(), nullptr, 0xFFFFFFFFu);

      ID3D11RenderTargetView *emptyRenderTarget = nullptr;
      device_ctx->OMSetRenderTargets(1, &emptyRenderTarget, nullptr);
      device_ctx->RSSetViewports(0, nullptr);
      ID3D11ShaderResourceView *emptyShaderResourceView = nullptr;
      device_ctx->PSSetShaderResources(0, 1, &emptyShaderResourceView);
    };

    switch (out_frame_action) {
      case ofa::forward_last_img:
        {
          auto p_img = std::get_if<std::shared_ptr<platf::img_t>>(&last_frame_variant);
          if (!p_img) {
            BOOST_LOG(error) << "Logical error at " << __FILE__ << ":" << __LINE__;
            return capture_e::error;
          }
          img_out = *p_img;
          break;
        }

      case ofa::copy_last_surface_and_blend_cursor:
        {
          auto p_surface = std::get_if<texture2d_t>(&last_frame_variant);
          if (!p_surface) {
            BOOST_LOG(error) << "Logical error at " << __FILE__ << ":" << __LINE__;
            return capture_e::error;
          }
          if (!blend_mouse_cursor_flag) {
            BOOST_LOG(error) << "Logical error at " << __FILE__ << ":" << __LINE__;
            return capture_e::error;
          }

          if (!pull_free_image_cb(img_out)) {
            return capture_e::interrupted;
          }

          auto [d3d_img, lock] = get_locked_d3d_img(img_out);
          if (!d3d_img) {
            return capture_completion_failure(*this);
          }

          {
            auto context_lock = lock_fused_context();
            device_ctx->CopyResource(d3d_img->capture_texture.get(), p_surface->get());
            if (fused_nvenc_is_active()) {
              fused_d3d11::telemetry().record_capture_copy_submitted();
            }
          }
          blend_cursor(*d3d_img);
          break;
        }

      case ofa::dummy_fallback:
        {
          if (!pull_free_image_cb(img_out)) {
            return capture_e::interrupted;
          }

          // Clear the image if it has been used as a dummy.
          // It can have the mouse cursor blended onto it.
          auto old_d3d_img = (img_d3d_t *) img_out.get();
          bool reclear_dummy = !old_d3d_img->blank && old_d3d_img->capture_texture;

          auto [d3d_img, lock] = get_locked_d3d_img(img_out, true);
          if (!d3d_img) {
            return capture_completion_failure(*this);
          }

          if (reclear_dummy) {
            const float rgb_black[] = {0.0f, 0.0f, 0.0f, 0.0f};
            auto context_lock = lock_fused_context();
            device_ctx->ClearRenderTargetView(d3d_img->capture_rt.get(), rgb_black);
          }

          if (blend_mouse_cursor_flag) {
            blend_cursor(*d3d_img);
          }

          break;
        }
    }

    // Perform delayed destruction of the unused surface if the time is due.
    if (old_surface_delayed_destruction && old_surface_timestamp + 10s < std::chrono::steady_clock::now()) {
      old_surface_delayed_destruction.reset();
    }

    if (img_out) {
      img_out->frame_timestamp = frame_timestamp;
      auto d3d_img = std::static_pointer_cast<img_d3d_t>(img_out);
      auto capture_token = fused_d3d11::frame_trace_token_t {};
      if (frame_timestamp) {
        const auto source_timestamp_ns = static_cast<std::uint64_t>(
          std::chrono::duration_cast<std::chrono::nanoseconds>(frame_timestamp->time_since_epoch()).count()
        );
        capture_token = fused_d3d11::telemetry().begin_capture_frame(
          source_timestamp_ns,
          telemetry_capture_acquired_ns,
          fused_d3d11::telemetry_t::now_ns()
        );
      }
      fused_d3d11::telemetry().replace_capture_frame_token(
        d3d_img->telemetry_capture_token,
        capture_token
      );
    }

    return capture_e::ok;
  }

  capture_e display_ddup_vram_t::release_snapshot() {
    return dup.release_frame();
  }

  int display_ddup_vram_t::init(const ::video::config_t &config, const std::string &display_name) {
    if (virtual_display::requires_direct_frame_for_vdd_hdr(
          config.dynamicRange != 0,
          config.virtual_display_active
        )) {
      BOOST_LOG(error) << "HDR VDD requires the ABI5 direct FP16 transform path; refusing DDA fallback"sv;
      return -1;
    }
    if (display_base_t::init(config, display_name) || dup.init(this, config)) {
      return -1;
    }

    D3D11_SAMPLER_DESC sampler_desc {};
    sampler_desc.Filter = D3D11_FILTER_MIN_MAG_MIP_LINEAR;
    sampler_desc.AddressU = D3D11_TEXTURE_ADDRESS_CLAMP;
    sampler_desc.AddressV = D3D11_TEXTURE_ADDRESS_CLAMP;
    sampler_desc.AddressW = D3D11_TEXTURE_ADDRESS_WRAP;
    sampler_desc.ComparisonFunc = D3D11_COMPARISON_NEVER;
    sampler_desc.MinLOD = 0;
    sampler_desc.MaxLOD = D3D11_FLOAT32_MAX;

    auto status = device->CreateSamplerState(&sampler_desc, &sampler_linear);
    if (FAILED(status)) {
      BOOST_LOG(error) << "Failed to create point sampler state [0x"sv << util::hex(status).to_string_view() << ']';
      return -1;
    }

    status = device->CreateVertexShader(cursor_vs_hlsl->GetBufferPointer(), cursor_vs_hlsl->GetBufferSize(), nullptr, &cursor_vs);
    if (status) {
      BOOST_LOG(error) << "Failed to create scene vertex shader [0x"sv << util::hex(status).to_string_view() << ']';
      return -1;
    }

    {
      int32_t rotation_modifier = display_rotation == DXGI_MODE_ROTATION_UNSPECIFIED ? 0 : display_rotation - 1;
      int32_t rotation_data[16 / sizeof(int32_t)] {rotation_modifier};  // aligned to 16-byte
      auto rotation = make_buffer(device.get(), rotation_data);
      if (!rotation) {
        BOOST_LOG(error) << "Failed to create display rotation vertex constant buffer";
        return -1;
      }
      device_ctx->VSSetConstantBuffers(2, 1, &rotation);
    }

    if (config.dynamicRange && is_hdr()) {
      // This shader will normalize scRGB white levels to a user-defined white level
      status = device->CreatePixelShader(cursor_ps_normalize_white_hlsl->GetBufferPointer(), cursor_ps_normalize_white_hlsl->GetBufferSize(), nullptr, &cursor_ps);
      if (status) {
        BOOST_LOG(error) << "Failed to create cursor blending (normalized white) pixel shader [0x"sv << util::hex(status).to_string_view() << ']';
        return -1;
      }

      // Use a 300 nit target for the mouse cursor. We should really get
      // the user's SDR white level in nits, but there is no API that
      // provides that information to Win32 apps.
      float white_multiplier_data[16 / sizeof(float)] {300.0f / 80.f};  // aligned to 16-byte
      auto white_multiplier = make_buffer(device.get(), white_multiplier_data);
      if (!white_multiplier) {
        BOOST_LOG(warning) << "Failed to create cursor blending (normalized white) white multiplier constant buffer";
        return -1;
      }

      device_ctx->PSSetConstantBuffers(1, 1, &white_multiplier);
    } else {
      status = device->CreatePixelShader(cursor_ps_hlsl->GetBufferPointer(), cursor_ps_hlsl->GetBufferSize(), nullptr, &cursor_ps);
      if (status) {
        BOOST_LOG(error) << "Failed to create cursor blending pixel shader [0x"sv << util::hex(status).to_string_view() << ']';
        return -1;
      }
    }

    blend_alpha = make_blend(device.get(), true, false);
    blend_invert = make_blend(device.get(), true, true);
    blend_disable = make_blend(device.get(), false, false);

    if (!blend_disable || !blend_alpha || !blend_invert) {
      return -1;
    }

    device_ctx->OMSetBlendState(blend_disable.get(), nullptr, 0xFFFFFFFFu);
    device_ctx->PSSetSamplers(0, 1, &sampler_linear);
    device_ctx->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);

    return 0;
  }

  /**
   * Get the next frame from the Windows.Graphics.Capture API and copy it into a new snapshot texture.
   */
  capture_e display_wgc_vram_t::snapshot(const pull_free_image_cb_t &pull_free_image_cb, std::shared_ptr<platf::img_t> &img_out, std::chrono::milliseconds timeout, bool cursor_visible) {
    if (fused_reinit_required()) {
      return capture_e::reinit;
    }
    texture2d_t src;
    uint64_t frame_qpc;
    dup.set_cursor_visible(cursor_visible);
    auto capture_status = dup.next_frame(timeout, &src, frame_qpc);
    if (capture_status != capture_e::ok) {
      return capture_status;
    }
    const auto telemetry_capture_acquired_ns = fused_d3d11::telemetry_t::now_ns();
    {
      auto context_lock = lock_fused_context();
      if (fused_nvenc_is_active()) {
        fused_d3d11::telemetry().record_capture_acquired();
      }
    }

    auto frame_timestamp = std::chrono::steady_clock::now() - qpc_time_difference(qpc_counter(), frame_qpc);
    D3D11_TEXTURE2D_DESC desc;
    src->GetDesc(&desc);

    // It's possible for our display enumeration to race with mode changes and result in
    // mismatched image pool and desktop texture sizes. If this happens, just reinit again.
    if (desc.Width != width_before_rotation || desc.Height != height_before_rotation) {
      BOOST_LOG(info) << "Capture size changed ["sv << width << 'x' << height << " -> "sv << desc.Width << 'x' << desc.Height << ']';
      return capture_e::reinit;
    }

    // It's also possible for the capture format to change on the fly. If that happens,
    // reinitialize capture to try format detection again and create new images.
    if (capture_format != desc.Format) {
      BOOST_LOG(info) << "Capture format changed ["sv << dxgi_format_to_string(capture_format) << " -> "sv << dxgi_format_to_string(desc.Format) << ']';
      return capture_e::reinit;
    }

    std::shared_ptr<platf::img_t> img;
    if (!pull_free_image_cb(img)) {
      return capture_e::interrupted;
    }

    auto d3d_img = std::static_pointer_cast<img_d3d_t>(img);
    d3d_img->blank = false;  // image is always ready for capture
    if (complete_img(d3d_img.get(), false) == 0) {
      texture_lock_helper lock_helper(d3d_img->capture_mutex.get());
      if (lock_helper.lock()) {
        auto context_lock = lock_fused_context();
        device_ctx->CopyResource(d3d_img->capture_texture.get(), src.get());
        if (fused_nvenc_is_active()) {
          fused_d3d11::telemetry().record_capture_copy_submitted();
        }
      } else {
        BOOST_LOG(error) << "Failed to lock capture texture";
        return capture_e::error;
      }
    } else {
      return capture_completion_failure(*this);
    }
    img_out = img;
    if (img_out) {
      img_out->frame_timestamp = frame_timestamp;
      auto output = std::static_pointer_cast<img_d3d_t>(img_out);
      const auto source_timestamp_ns = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(frame_timestamp.time_since_epoch()).count()
      );
      const auto capture_token = fused_d3d11::telemetry().begin_capture_frame(
        source_timestamp_ns,
        telemetry_capture_acquired_ns,
        fused_d3d11::telemetry_t::now_ns()
      );
      fused_d3d11::telemetry().replace_capture_frame_token(
        output->telemetry_capture_token,
        capture_token
      );
    }

    return capture_e::ok;
  }

  capture_e display_wgc_vram_t::release_snapshot() {
    return dup.release_frame();
  }

  int display_wgc_vram_t::init(const ::video::config_t &config, const std::string &display_name) {
    if (virtual_display::requires_direct_frame_for_vdd_hdr(
          config.dynamicRange != 0,
          config.virtual_display_active
        )) {
      BOOST_LOG(error) << "HDR VDD requires the ABI5 direct FP16 transform path; refusing WGC fallback"sv;
      return -1;
    }
    if (display_base_t::init(config, display_name) || dup.init(this, config)) {
      return -1;
    }

    return 0;
  }

  std::shared_ptr<platf::img_t> display_vram_t::alloc_img() {
    auto img = std::make_shared<img_d3d_t>();

    // Initialize format-independent fields
    img->width = width_before_rotation;
    img->height = height_before_rotation;
    img->id = next_image_id++;
    img->blank = true;
    img->resource_ownership = encode_resource_ownership;

    return img;
  }

  int display_vdd_vram_t::init(const ::video::config_t &config, const std::string &display_name) {
    source_ = config.virtual_display_frame_source;
    direct_required_ = config.virtual_display_direct_required;
    if (!source_ || !source_->healthy()) {
      return -1;
    }
    resources_ = source_->resources();
    if (resources_.width != static_cast<std::uint32_t>(config.width) ||
        resources_.height != static_cast<std::uint32_t>(config.height) ||
        resources_.dynamic_range != (config.dynamicRange ?
                                      virtual_display::dynamic_range_e::hdr10 :
                                      virtual_display::dynamic_range_e::sdr)) {
      source_->stop();
      return -1;
    }

    auto *native_device = static_cast<ID3D11Device *>(source_->native_device());
    auto *native_context = static_cast<ID3D11DeviceContext *>(source_->native_context());
    auto *native_adapter = static_cast<IDXGIAdapter1 *>(source_->native_adapter());
    if (native_device == nullptr || native_context == nullptr || native_adapter == nullptr) {
      source_->stop();
      return -1;
    }
    native_device->AddRef();
    device.reset(native_device);
    native_context->AddRef();
    device_ctx.reset(native_context);
    native_adapter->AddRef();
    adapter.reset(native_adapter);

    factory1_t::pointer factory_raw = nullptr;
    if (FAILED(CreateDXGIFactory1(IID_IDXGIFactory1, reinterpret_cast<void **>(&factory_raw)))) {
      source_->stop();
      return -1;
    }
    factory.reset(factory_raw);
    const auto expected_output = utf_utils::from_utf8(display_name);
    for (UINT index = 0;; ++index) {
      output_t::pointer candidate_raw = nullptr;
      if (adapter->EnumOutputs(index, &candidate_raw) == DXGI_ERROR_NOT_FOUND) {
        break;
      }
      output_t candidate {candidate_raw};
      DXGI_OUTPUT_DESC description {};
      if (SUCCEEDED(candidate->GetDesc(&description)) && description.AttachedToDesktop &&
          expected_output == description.DeviceName) {
        if (output) {
          source_->stop();
          return -1;
        }
        output = std::move(candidate);
      }
    }
    if (!output) {
      source_->stop();
      return -1;
    }
    DXGI_OUTPUT_DESC output_desc {};
    if (FAILED(output->GetDesc(&output_desc)) ||
        output_desc.DesktopCoordinates.right - output_desc.DesktopCoordinates.left != config.width ||
        output_desc.DesktopCoordinates.bottom - output_desc.DesktopCoordinates.top != config.height) {
      source_->stop();
      return -1;
    }

    width = config.width;
    height = config.height;
    width_before_rotation = width;
    height_before_rotation = height;
    logical_width = width;
    logical_height = height;
    env_width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    env_height = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    env_logical_width = env_width;
    env_logical_height = env_height;
    offset_x = output_desc.DesktopCoordinates.left - GetSystemMetrics(SM_XVIRTUALSCREEN);
    offset_y = output_desc.DesktopCoordinates.top - GetSystemMetrics(SM_YVIRTUALSCREEN);
    display_rotation = output_desc.Rotation;
    if (display_rotation != DXGI_MODE_ROTATION_IDENTITY && display_rotation != DXGI_MODE_ROTATION_UNSPECIFIED) {
      source_->stop();
      return -1;
    }
    capture_format = resources_.format == virtual_display::frame_format_e::rgba16_float ?
                       DXGI_FORMAT_R16G16B16A16_FLOAT :
                       DXGI_FORMAT_B8G8R8A8_UNORM;
    feature_level = device->GetFeatureLevel();
    next_image_id.store(0, std::memory_order_relaxed);
    display_refresh_rate = {
      static_cast<UINT>(::video::framerate_to_rational(config).num),
      static_cast<UINT>(::video::framerate_to_rational(config).den),
    };
    display_refresh_rate_rounded = config.framerate;
    client_frame_rate = config.framerate;
    client_frame_rate_strict = display_refresh_rate;
    return timer && *timer ? 0 : -1;
  }

  capture_e display_vdd_vram_t::snapshot(
    const pull_free_image_cb_t &pull_free_image_cb,
    std::shared_ptr<platf::img_t> &img_out,
    const std::chrono::milliseconds timeout,
    const bool cursor_visible
  ) {
    static_cast<void>(cursor_visible);
    if (!source_ || !source_->healthy()) {
      return capture_e::reinit;
    }
    auto acquired = source_->acquire(timeout);
    if (acquired.status == virtual_display::frame_io_e::timeout) {
      return capture_e::timeout;
    }
    if (acquired.status != virtual_display::frame_io_e::ok || !acquired.lease) {
      source_->stop();
      return capture_e::reinit;
    }
    if (!pull_free_image_cb(img_out) || !img_out) {
      return capture_e::interrupted;
    }

    auto d3d_img = std::dynamic_pointer_cast<img_d3d_t>(img_out);
    auto *texture = static_cast<ID3D11Texture2D *>(acquired.lease->native_texture());
    if (!d3d_img || texture == nullptr || d3d_img->encode_source_lifetime ||
        !acquired.lease->color_transform()) {
      source_->stop();
      return capture_e::reinit;
    }
    const auto resource_mode = encode_resource_ownership->mode();
    if (resource_mode != fused_d3d11::resource_mode_e::fused) {
      source_->stop();
      return capture_e::reinit;
    }

    d3d_img->capture_texture.reset();
    d3d_img->capture_rt.reset();
    d3d_img->capture_mutex.reset();
    if (d3d_img->encoder_texture_handle != nullptr) {
      CloseHandle(std::exchange(d3d_img->encoder_texture_handle, nullptr));
    }
    texture->AddRef();
    d3d_img->capture_texture.reset(texture);
    d3d_img->data = reinterpret_cast<std::uint8_t *>(texture);
    d3d_img->width = width;
    d3d_img->height = height;
    d3d_img->pixel_pitch = static_cast<std::int32_t>(virtual_display::frame_format_pixel_pitch(resources_.format));
    d3d_img->row_pitch = width * d3d_img->pixel_pitch;
    d3d_img->format = capture_format;
    d3d_img->dummy = false;
    d3d_img->blank = false;
    d3d_img->fused_resource = true;
    if (!d3d_img->resource_bound) {
      if (!d3d_img->resource_ownership ||
          !d3d_img->resource_ownership->bind_image(fused_d3d11::resource_mode_e::fused)) {
        source_->stop();
        return capture_e::reinit;
      }
      d3d_img->resource_bound = true;
    }
    d3d_img->frame_timestamp = std::chrono::steady_clock::now() - qpc_time_difference(
      qpc_counter(),
      acquired.lease->descriptor().capture_qpc
    );
    d3d_img->color_transform = acquired.lease->color_transform();
    d3d_img->color_metadata = acquired.lease->descriptor().color_metadata;
    d3d_img->encode_source_lifetime = std::move(acquired.lease);
    return capture_e::ok;
  }

  capture_e display_vdd_vram_t::release_snapshot() {
    return capture_e::ok;
  }

  bool display_vdd_vram_t::is_hdr() {
    return resources_.dynamic_range == virtual_display::dynamic_range_e::hdr10;
  }

  bool display_vdd_vram_t::get_hdr_metadata(SS_HDR_METADATA &metadata) {
    std::memset(&metadata, 0, sizeof(metadata));
    if (!is_hdr()) {
      return false;
    }
    const auto &source = resources_.initial_color_metadata.hdr10_metadata;
    metadata.displayPrimaries[0] = {source.red_primary[0], source.red_primary[1]};
    metadata.displayPrimaries[1] = {source.green_primary[0], source.green_primary[1]};
    metadata.displayPrimaries[2] = {source.blue_primary[0], source.blue_primary[1]};
    metadata.whitePoint = {source.white_point[0], source.white_point[1]};
    metadata.maxDisplayLuminance = source.maximum_mastering_luminance;
    metadata.minDisplayLuminance = source.minimum_mastering_luminance;
    metadata.maxContentLightLevel = source.maximum_content_light_level;
    metadata.maxFrameAverageLightLevel = source.maximum_frame_average_light_level;
    return true;
  }

  std::vector<DXGI_FORMAT> display_vdd_vram_t::get_supported_capture_formats() {
    return {capture_format};
  }

  bool display_vdd_vram_t::direct_vdd_is_active() const noexcept {
    return source_ && source_->healthy();
  }

  bool display_vdd_vram_t::direct_vdd_is_required() const noexcept {
    return direct_required_;
  }

  void display_vdd_vram_t::disable_direct_vdd() noexcept {
    if (source_) {
      source_->stop();
    }
  }

  void display_vram_t::request_fused_reinit() {
    fused_runtime_quarantined.store(true, std::memory_order_release);
    virtual_display::quarantine_direct_frame_runtime();
    if (!encode_resource_ownership->request_reinit()) {
      BOOST_LOG(error) << "Failed to transition fused D3D11 ownership to reinit-required";
    }
  }

  // This cannot use ID3D11DeviceContext because it can be called concurrently by the encoding thread
  int display_vram_t::complete_img(platf::img_t *img_base, bool dummy) {
    auto img = (img_d3d_t *) img_base;
    auto context_lock = lock_fused_context();
    if (fused_reinit_required()) {
      return -1;
    }

    if (encode_resource_ownership->state() == fused_d3d11::resource_state_e::unset) {
      if (encode_resource_ownership->begin_transition(fused_d3d11::resource_mode_e::legacy) != fused_d3d11::transition_result_e::started ||
          !encode_resource_ownership->commit_transition(fused_d3d11::resource_mode_e::legacy)) {
        BOOST_LOG(error) << "Failed to commit legacy D3D11 capture resource ownership";
        return -1;
      }
    }
    const auto resource_mode = encode_resource_ownership->mode();
    const bool fused_resource = resource_mode == fused_d3d11::resource_mode_e::fused;
    bool fused_completion_failed = fused_resource;
    auto fused_completion_guard = util::fail_guard([&]() {
      if (fused_completion_failed) {
        request_fused_reinit();
      }
    });

    // Recreate the image when switching between legacy shared and fused same-device ownership.
    if (img->capture_texture && img->dummy == dummy && img->fused_resource == fused_resource) {
      fused_completion_failed = false;
      fused_completion_guard.disable();
      return 0;
    }

    // If this is not a dummy image, we must know the format by now
    if (!dummy && capture_format == DXGI_FORMAT_UNKNOWN) {
      BOOST_LOG(error) << "display_vram_t::complete_img() called with unknown capture format!";
      return -1;
    }

    // Reset the image (in case this was previously a dummy)
    img->capture_texture.reset();
    img->capture_rt.reset();
    img->capture_mutex.reset();
    img->data = nullptr;
    if (img->encoder_texture_handle) {
      CloseHandle(img->encoder_texture_handle);
      img->encoder_texture_handle = nullptr;
    }

    // Initialize format-dependent fields
    img->pixel_pitch = get_pixel_pitch();
    img->row_pitch = img->pixel_pitch * img->width;
    img->dummy = dummy;
    img->fused_resource = fused_resource;
    img->format = (capture_format == DXGI_FORMAT_UNKNOWN) ? DXGI_FORMAT_B8G8R8A8_UNORM : capture_format;

    D3D11_TEXTURE2D_DESC t {};
    t.Width = img->width;
    t.Height = img->height;
    t.MipLevels = 1;
    t.ArraySize = 1;
    t.SampleDesc.Count = 1;
    t.Usage = D3D11_USAGE_DEFAULT;
    t.Format = img->format;
    t.BindFlags = D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_RENDER_TARGET;
    t.MiscFlags = fused_resource ? 0 : D3D11_RESOURCE_MISC_SHARED_NTHANDLE | D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX;

    auto status = device->CreateTexture2D(&t, nullptr, &img->capture_texture);
    if (FAILED(status)) {
      BOOST_LOG(error) << "Failed to create img buf texture [0x"sv << util::hex(status).to_string_view() << ']';
      return -1;
    }

    status = device->CreateRenderTargetView(img->capture_texture.get(), nullptr, &img->capture_rt);
    if (FAILED(status)) {
      BOOST_LOG(error) << "Failed to create render target view [0x"sv << util::hex(status).to_string_view() << ']';
      return -1;
    }

    if (!fused_resource) {
      // Get the keyed mutex to synchronize with the legacy encoder device.
      status = img->capture_texture->QueryInterface(__uuidof(IDXGIKeyedMutex), (void **) &img->capture_mutex);
      if (FAILED(status)) {
        BOOST_LOG(error) << "Failed to query IDXGIKeyedMutex [0x"sv << util::hex(status).to_string_view() << ']';
        return -1;
      }

      resource1_t resource;
      status = img->capture_texture->QueryInterface(__uuidof(IDXGIResource1), (void **) &resource);
      if (FAILED(status)) {
        BOOST_LOG(error) << "Failed to query IDXGIResource1 [0x"sv << util::hex(status).to_string_view() << ']';
        return -1;
      }

      // Create a handle for the legacy encoder device to open this texture.
      status = resource->CreateSharedHandle(nullptr, DXGI_SHARED_RESOURCE_READ, nullptr, &img->encoder_texture_handle);
      if (FAILED(status)) {
        BOOST_LOG(error) << "Failed to create shared texture handle [0x"sv << util::hex(status).to_string_view() << ']';
        return -1;
      }
    }

    img->data = (std::uint8_t *) img->capture_texture.get();

    if (!img->resource_bound) {
      if (!img->resource_ownership || !img->resource_ownership->bind_image(resource_mode)) {
        BOOST_LOG(error) << "Failed to bind capture image to committed D3D11 resource ownership";
        return -1;
      }
      img->resource_bound = true;
    }

    fused_completion_failed = false;
    fused_completion_guard.disable();

    return 0;
  }

  // This cannot use ID3D11DeviceContext because it can be called concurrently by the encoding thread
  /**
   * @memberof platf::dxgi::display_vram_t
   */
  int display_vram_t::dummy_img(platf::img_t *img_base) {
    return complete_img(img_base, true);
  }

  std::vector<DXGI_FORMAT> display_vram_t::get_supported_capture_formats() {
    return {
      // scRGB FP16 is the ideal format for Wide Color Gamut and Advanced Color
      // displays (both SDR and HDR). This format uses linear gamma, so we will
      // use a linear->PQ shader for HDR and a linear->sRGB shader for SDR.
      DXGI_FORMAT_R16G16B16A16_FLOAT,

      // DXGI_FORMAT_R10G10B10A2_UNORM seems like it might give us frames already
      // converted to SMPTE 2084 PQ, however it seems to actually just clamp the
      // scRGB FP16 values that DWM is using when the desktop format is scRGB FP16.
      //
      // If there is a case where the desktop format is really SMPTE 2084 PQ, it
      // might make sense to support capturing it without conversion to scRGB,
      // but we avoid it for now.

      // We include the 8-bit modes too for when the display is in SDR mode,
      // while the client stream is HDR-capable. These UNORM formats can
      // use our normal pixel shaders that expect sRGB input.
      DXGI_FORMAT_B8G8R8A8_UNORM,
      DXGI_FORMAT_B8G8R8X8_UNORM,
      DXGI_FORMAT_R8G8B8A8_UNORM,
    };
  }

  /**
   * @brief Check that a given codec is supported by the display device.
   * @param name The FFmpeg codec name (or similar for non-FFmpeg codecs).
   * @param config The codec configuration.
   * @return `true` if supported, `false` otherwise.
   */
  bool display_vram_t::is_codec_supported(std::string_view name, const ::video::config_t &config) {
    DXGI_ADAPTER_DESC adapter_desc;
    adapter->GetDesc(&adapter_desc);

    if (adapter_desc.VendorId == 0x1002) {  // AMD
      // If it's not an AMF encoder, it's not compatible with an AMD GPU
      if (!boost::algorithm::ends_with(name, "_amf")) {
        return false;
      }

      // Perform AMF version checks if we're using an AMD GPU. This check is placed in display_vram_t
      // to avoid hitting the display_ram_t path which uses software encoding and doesn't touch AMF.
      HMODULE amfrt = LoadLibraryW(AMF_DLL_NAME);
      if (amfrt) {
        auto unload_amfrt = util::fail_guard([amfrt]() {
          FreeLibrary(amfrt);
        });

        auto fnAMFQueryVersion = (AMFQueryVersion_Fn) GetProcAddress(amfrt, AMF_QUERY_VERSION_FUNCTION_NAME);
        if (fnAMFQueryVersion) {
          amf_uint64 version;
          auto result = fnAMFQueryVersion(&version);
          if (result == AMF_OK) {
            if (config.videoFormat == 2 && version < AMF_MAKE_FULL_VERSION(1, 4, 30, 0)) {
              // AMF 1.4.30 adds ultra low latency mode for AV1. Don't use AV1 on earlier versions.
              // This corresponds to driver version 23.5.2 (23.10.01.45) or newer.
              BOOST_LOG(warning) << "AV1 encoding is disabled on AMF version "sv
                                 << AMF_GET_MAJOR_VERSION(version) << '.'
                                 << AMF_GET_MINOR_VERSION(version) << '.'
                                 << AMF_GET_SUBMINOR_VERSION(version) << '.'
                                 << AMF_GET_BUILD_VERSION(version);
              BOOST_LOG(warning) << "If your AMD GPU supports AV1 encoding, update your graphics drivers!"sv;
              return false;
            } else if (config.dynamicRange && version < AMF_MAKE_FULL_VERSION(1, 4, 23, 0)) {
              // Older versions of the AMD AMF runtime can crash when fed P010 surfaces.
              // Fail if AMF version is below 1.4.23 where HEVC Main10 encoding was introduced.
              // AMF 1.4.23 corresponds to driver version 21.12.1 (21.40.11.03) or newer.
              BOOST_LOG(warning) << "HDR encoding is disabled on AMF version "sv
                                 << AMF_GET_MAJOR_VERSION(version) << '.'
                                 << AMF_GET_MINOR_VERSION(version) << '.'
                                 << AMF_GET_SUBMINOR_VERSION(version) << '.'
                                 << AMF_GET_BUILD_VERSION(version);
              BOOST_LOG(warning) << "If your AMD GPU supports HEVC Main10 encoding, update your graphics drivers!"sv;
              return false;
            }
          } else {
            BOOST_LOG(warning) << "AMFQueryVersion() failed: "sv << result;
          }
        } else {
          BOOST_LOG(warning) << "AMF DLL missing export: "sv << AMF_QUERY_VERSION_FUNCTION_NAME;
        }
      } else {
        BOOST_LOG(warning) << "Detected AMD GPU but AMF failed to load"sv;
      }
    } else if (adapter_desc.VendorId == 0x8086) {  // Intel
      // If it's not a QSV encoder, it's not compatible with an Intel GPU
      if (!boost::algorithm::ends_with(name, "_qsv")) {
        return false;
      }
      if (config.chromaSamplingType == 1) {
        if (config.videoFormat == 0 || config.videoFormat == 2) {
          // QSV doesn't support 4:4:4 in H.264 or AV1
          return false;
        }
        const auto input_format = config.dynamicRange ? DXGI_FORMAT_Y410 : DXGI_FORMAT_AYUV;
        UINT format_support = 0;
        constexpr UINT required_support = D3D11_FORMAT_SUPPORT_TEXTURE2D |
                                          D3D11_FORMAT_SUPPORT_SHADER_SAMPLE |
                                          D3D11_FORMAT_SUPPORT_RENDER_TARGET;
        if (FAILED(device->CheckFormatSupport(input_format, &format_support)) ||
            (format_support & required_support) != required_support) {
          return false;
        }
        // The later real encoder probe remains authoritative for HEVC RExt
        // support; this boundary only admits a GPU that can create and render
        // the exact AYUV/Y410 input surface required by that probe.
      }
    } else if (adapter_desc.VendorId == 0x10de) {  // Nvidia
      // If it's not an NVENC encoder, it's not compatible with an Nvidia GPU
      if (!boost::algorithm::ends_with(name, "_nvenc")) {
        return false;
      }
    } else if (adapter_desc.VendorId == 0x4D4F4351 ||  // Qualcomm (QCOM as MOQC reversed)
               adapter_desc.VendorId == 0x5143) {  // Qualcomm alternate ID
      // If it's not a MediaFoundation encoder, it's not compatible with a Qualcomm GPU
      if (!boost::algorithm::ends_with(name, "_mf")) {
        return false;
      }
    } else {
      BOOST_LOG(warning) << "Unknown GPU vendor ID: " << util::hex(adapter_desc.VendorId).to_string_view();
    }

    return true;
  }

  std::unique_ptr<avcodec_encode_device_t> display_vram_t::make_avcodec_encode_device(pix_fmt_e pix_fmt) {
    auto device = std::make_unique<d3d_avcodec_encode_device_t>();
    if (device->init(shared_from_this(), adapter.get(), pix_fmt) != 0) {
      return nullptr;
    }
    return device;
  }

  std::unique_ptr<nvenc_encode_device_t> display_vram_t::make_nvenc_encode_device(pix_fmt_e pix_fmt) {
    auto device = std::make_unique<d3d_nvenc_encode_device_t>();
    if (!device->init_device(shared_from_this(), adapter.get(), pix_fmt)) {
      return nullptr;
    }
    return device;
  }

  /**
   * @brief Initialize global D3D11 desktop duplication support.
   */
  int init() {
    BOOST_LOG(info) << "Compiling shaders..."sv;

#ifndef DOXYGEN
  #define compile_vertex_shader_helper(x) \
    if (!(x##_hlsl = compile_vertex_shader(SUNSHINE_SHADERS_DIR "/" #x ".hlsl"))) \
      return -1;
#endif
#ifndef DOXYGEN
  #define compile_pixel_shader_helper(x) \
    if (!(x##_hlsl = compile_pixel_shader(SUNSHINE_SHADERS_DIR "/" #x ".hlsl"))) \
      return -1;
#endif

    compile_pixel_shader_helper(convert_yuv420_packed_uv_type0_ps);
    compile_pixel_shader_helper(convert_yuv420_packed_uv_type0_ps_linear);
    compile_pixel_shader_helper(convert_yuv420_packed_uv_type0_ps_perceptual_quantizer);
    compile_pixel_shader_helper(convert_yuv420_packed_uv_type0_ps_vdd_color_transform);
    compile_vertex_shader_helper(convert_yuv420_packed_uv_type0_vs);
    compile_pixel_shader_helper(convert_yuv420_packed_uv_type0s_ps);
    compile_pixel_shader_helper(convert_yuv420_packed_uv_type0s_ps_linear);
    compile_pixel_shader_helper(convert_yuv420_packed_uv_type0s_ps_perceptual_quantizer);
    compile_pixel_shader_helper(convert_yuv420_packed_uv_type0s_ps_vdd_color_transform);
    compile_vertex_shader_helper(convert_yuv420_packed_uv_type0s_vs);
    compile_pixel_shader_helper(convert_yuv420_planar_y_ps);
    compile_pixel_shader_helper(convert_yuv420_planar_y_ps_linear);
    compile_pixel_shader_helper(convert_yuv420_planar_y_ps_perceptual_quantizer);
    compile_pixel_shader_helper(convert_yuv420_planar_y_ps_vdd_color_transform);
    compile_vertex_shader_helper(convert_yuv420_planar_y_vs);
    compile_pixel_shader_helper(convert_yuv444_packed_ayuv_ps);
    compile_pixel_shader_helper(convert_yuv444_packed_ayuv_ps_linear);
    compile_pixel_shader_helper(convert_yuv444_packed_ayuv_ps_vdd_color_transform);
    compile_vertex_shader_helper(convert_yuv444_packed_vs);
    compile_pixel_shader_helper(convert_yuv444_planar_ps);
    compile_pixel_shader_helper(convert_yuv444_planar_ps_linear);
    compile_pixel_shader_helper(convert_yuv444_planar_ps_perceptual_quantizer);
    compile_pixel_shader_helper(convert_yuv444_planar_ps_vdd_color_transform);
    compile_pixel_shader_helper(convert_yuv444_packed_y410_ps);
    compile_pixel_shader_helper(convert_yuv444_packed_y410_ps_linear);
    compile_pixel_shader_helper(convert_yuv444_packed_y410_ps_perceptual_quantizer);
    compile_pixel_shader_helper(convert_yuv444_packed_y410_ps_vdd_color_transform);
    compile_vertex_shader_helper(convert_yuv444_planar_vs);
    compile_pixel_shader_helper(cursor_ps);
    compile_pixel_shader_helper(cursor_ps_normalize_white);
    compile_vertex_shader_helper(cursor_vs);

    BOOST_LOG(info) << "Compiled shaders"sv;

#undef compile_vertex_shader_helper
#undef compile_pixel_shader_helper

    return 0;
  }
}  // namespace platf::dxgi
