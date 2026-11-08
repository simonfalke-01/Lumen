/**
 * @file src/nvenc/nvenc_d3d12_interface.h
 * @brief Declarations for the SDK-neutral Direct3D12 NVENC interface.
 */
#pragma once
#ifdef _WIN32

  // standard includes
  #include <cstdint>

  // lib includes
  #include <d3d12.h>

  // local includes
  #include "nvenc_encoder.h"

namespace nvenc {

  /**
   * @brief SDK-neutral Direct3D12 NVENC encoder interface.
   *
   * The encoder owns one NV12 input texture. The caller writes each picture into it on its own
   * queue and names the fence point that write signals; NVENC waits for that point on the GPU,
   * so no CPU wait or graphics-queue work separates conversion from encoding.
   */
  // Virtual inheritance is required because concrete encoders also inherit their SDK-specific implementation.
  class nvenc_d3d12_interface: public virtual nvenc_encoder {  // NOSONAR(cpp:S1011)
  public:
    /**
     * @brief Destroy the SDK-neutral Direct3D12 encoder interface.
     */
    ~nvenc_d3d12_interface() override = default;

    /**
     * @brief Return the NV12 texture the next picture must be written into.
     *
     * Created in the COMMON state with unordered access allowed. A writer must return it to
     * COMMON before signalling the input fence.
     *
     * @return Input texture, valid after `create_encoder()` succeeds.
     */
    virtual ID3D12Resource *get_input_resource() = 0;

    /**
     * @brief Name the fence point NVENC must wait for before reading the next picture.
     *
     * @param fence Fence the writer signals.
     * @param value Value that marks the next picture as written.
     */
    virtual void set_input_fence_point(ID3D12Fence *fence, std::uint64_t value) = 0;
  };

}  // namespace nvenc
#endif
