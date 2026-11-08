/**
 * @file src/nvenc/nvenc_d3d12.h
 * @brief Declarations for the Direct3D12 NVENC encoder.
 */
#pragma once
#ifdef _WIN32

  // platform includes
  #include <d3d12.h>
  #include <wrl/client.h>

  // local includes
  #include "nvenc_base.h"
  #include "nvenc_d3d12_interface.h"
  #include "nvenc_shared_dll.h"

  // The D3D12 interface first appears in NVENC SDK 11.1; the 11.0 build has none of its types.
  #if NVENC_SDK_VERSION >= 1200

namespace NVENC_NAMESPACE {

  /**
   * @brief NVENC encoder on a Direct3D12 device with fence-ordered input and output.
   *
   * The input NV12 texture is written on the caller's queue. Each picture carries the caller's
   * fence point, so NVENC starts on the GPU as soon as that write lands. Output goes to a
   * registered readback buffer and still completes through the async event, which keeps the
   * shared encode path, reference invalidation, and bitrate reconfiguration unchanged.
   */
  class nvenc_d3d12 final: public nvenc_base, public ::nvenc::nvenc_d3d12_interface {
  public:
    /**
     * @brief Create the encoder for one Direct3D12 device.
     *
     * @param d3d_device Device that owns the input texture and the caller's queue.
     * @param dll Shared NVENC driver module.
     */
    explicit nvenc_d3d12(ID3D12Device *d3d_device, ::nvenc::shared_dll dll);
    ~nvenc_d3d12() override;

    /** @copydoc ::nvenc::nvenc_d3d12_interface::get_input_resource() */
    ID3D12Resource *get_input_resource() override;

    /** @copydoc ::nvenc::nvenc_d3d12_interface::set_input_fence_point() */
    void set_input_fence_point(ID3D12Fence *fence, std::uint64_t value) override;

  protected:
    bool init_library() override;
    bool create_and_register_input_buffer() override;
    bool create_output_bitstream() override;
    void destroy_output_bitstream() override;
    void *picture_input_buffer(NV_ENC_INPUT_PTR mapped_input) override;
    void *picture_output_bitstream() override;
    bool wait_for_async_event(uint32_t timeout_ms) override;

    bool supports_weighted_prediction() const override {
      return false;
    }

    bool requires_initialize_buffer_format() const override {
      return true;
    }

  private:
    ::nvenc::shared_dll dll;
    const Microsoft::WRL::ComPtr<ID3D12Device> d3d_device;
    Microsoft::WRL::ComPtr<ID3D12Resource> input_texture;  ///< NV12 surface written by the caller.
    Microsoft::WRL::ComPtr<ID3D12Resource> output_buffer;  ///< Readback buffer NVENC writes the bitstream into.
    Microsoft::WRL::ComPtr<ID3D12Fence> output_fence;  ///< Signalled by NVENC once each picture is written.
    NV_ENC_REGISTERED_PTR registered_output_buffer = nullptr;
    NV_ENC_INPUT_PTR mapped_output_buffer = nullptr;
    NV_ENC_INPUT_RESOURCE_D3D12 input_resource {};  ///< Per-picture input description; must outlive the encode call.
    NV_ENC_OUTPUT_RESOURCE_D3D12 output_resource {};  ///< Output description reused for encode and lock.
    ID3D12Fence *input_fence = nullptr;  ///< Caller's fence for the next picture.
    std::uint64_t input_fence_value = 0;  ///< Value that marks the next picture as written.
    std::uint64_t output_fence_value = 0;  ///< Last value NVENC was asked to signal.
  };

}  // namespace NVENC_NAMESPACE
  #endif
#endif
