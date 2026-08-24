/**
 * @file src/nvenc/nvenc_d3d11_native.h
 * @brief Declarations for native Direct3D11 NVENC encoder.
 */
#pragma once
#ifdef _WIN32
  // standard includes
  #include <comdef.h>
  #include <d3d11.h>

  // local includes
  #include "nvenc_d3d11.h"
  #include "src/platform/windows/fused_d3d11_policy.h"

namespace NVENC_NAMESPACE {

  /**
   * @brief Native Direct3D11 NVENC encoder.
   */
  class nvenc_d3d11_native final: public nvenc_d3d11 {
  public:
    /**
     * @param d3d_device Direct3D11 device used for encoding.
     * @param dll Shared NVENC driver module.
     */
    explicit nvenc_d3d11_native(ID3D11Device *d3d_device, ::nvenc::shared_dll dll);
    ~nvenc_d3d11_native() override;

    ID3D11Texture2D *get_input_texture() override;
    /** @copydoc nvenc::nvenc_d3d11_interface::set_fused_input_enabled() */
    void set_fused_input_enabled(bool enabled) override;
    /** @copydoc nvenc::nvenc_d3d11_interface::set_frame_telemetry_token() */
    bool set_frame_telemetry_token(std::uint64_t token) override;
    /** @copydoc nvenc::nvenc_d3d11_interface::clear_frame_telemetry_token() */
    void clear_frame_telemetry_token() override;

  private:
    /**
     * @brief Create and register the persistent native D3D11 input surface.
     *
     * @return True when the texture is created and registered once for the encoder lifetime.
     */
    bool create_and_register_input_buffer() override;
    /**
     * @brief Record fused submissions at the actual NVENC MapInputResource entry boundary.
     *
     * @return Always true because the shared immediate context preserves command order.
     */
    bool synchronize_input_buffer() override;

    const ID3D11DevicePtr d3d_device;
    ID3D11Texture2DPtr d3d_input_texture;
    bool fused_input_enabled = false;  ///< Whether same-device fused command ordering is active.
    platf::dxgi::fused_d3d11::frame_trace_owner_t pending_frame_trace;  ///< Explicit instance-local child token.
  };

}  // namespace NVENC_NAMESPACE
#endif
