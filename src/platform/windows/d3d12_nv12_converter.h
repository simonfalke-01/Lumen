/**
 * @file src/platform/windows/d3d12_nv12_converter.h
 * @brief BGRA to NV12 conversion on a Direct3D12 compute queue.
 */
#pragma once

// standard includes
#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

// platform includes
#include <d3d12.h>
#include <dxgi.h>
#include <wrl/client.h>

// local includes
#include "src/video_colorspace.h"

namespace platf::dxgi {

  /**
   * @brief GPU timings of one conversion, read back after NVENC finished the picture.
   */
  struct d3d12_conversion_timing_t {
    std::uint32_t copy_wait_us {};  ///< Submission to conversion start: the capture copy plus compute-queue scheduling.
    std::uint32_t convert_gpu_us {};  ///< Conversion dispatch duration on the compute queue.
    std::chrono::steady_clock::time_point convert_end;  ///< CPU time the conversion finished.
  };

  /**
   * @brief Converts captured desktop textures to NV12 on a compute queue of its own.
   *
   * The desktop-duplication copy is the only work left on the D3D11 graphics queue. This queue
   * waits for that copy through a shared fence, runs a compute port of the D3D11 NV12 shaders
   * (same matrix, range, aspect-fit viewport, chroma siting and filtering), and signals a second
   * shared fence that NVENC waits on before encoding and the capture side waits on before it
   * overwrites the texture. Nothing here waits on the CPU in the steady state.
   */
  class d3d12_nv12_converter_t {
  public:
    ~d3d12_nv12_converter_t();

    d3d12_nv12_converter_t(const d3d12_nv12_converter_t &) = delete;
    d3d12_nv12_converter_t &operator=(const d3d12_nv12_converter_t &) = delete;

    /**
     * @brief Create the device, compute queue, fences and pipelines.
     *
     * @param adapter Adapter the capture device runs on; the D3D12 device is created on it.
     * @param capture_fence Shared handle of the fence the capture copy signals.
     * @param consumption_fence Shared handle of the fence this converter signals.
     * @return Converter, or empty when any step fails (the caller falls back to D3D11).
     */
    static std::unique_ptr<d3d12_nv12_converter_t> create(IDXGIAdapter *adapter, HANDLE capture_fence, HANDLE consumption_fence);

    /** @brief Return the Direct3D12 device NVENC must open its session on. */
    [[nodiscard]] ID3D12Device *device() const noexcept {
      return device_.Get();
    }

    /** @brief Return the fence that marks finished conversions. */
    [[nodiscard]] ID3D12Fence *consumption_fence() const noexcept {
      return consumption_fence_.Get();
    }

    /** @brief Return the queue priority that was granted, for logging. */
    [[nodiscard]] std::string_view queue_priority() const noexcept {
      return queue_priority_;
    }

    /**
     * @brief Bind the NV12 output and its aspect-fit placement, then fill it with black.
     *
     * @param output NV12 texture in the COMMON state.
     * @param out_width Encoded width.
     * @param out_height Encoded height.
     * @param in_width Captured width.
     * @param in_height Captured height.
     * @param color RGB to YUV vectors for the stream colorspace.
     * @param fill_value Consumption-fence value to signal once the black fill is written.
     * @return True when the output is ready.
     */
    bool init_output(
      ID3D12Resource *output,
      std::uint32_t out_width,
      std::uint32_t out_height,
      std::uint32_t in_width,
      std::uint32_t in_height,
      const ::video::color_t &color,
      std::uint64_t fill_value
    );

    /**
     * @brief Open a capture texture the D3D11 device shared with an NT handle.
     *
     * @param handle Shared handle of the capture texture.
     * @return Opened resource, or empty on failure.
     */
    Microsoft::WRL::ComPtr<ID3D12Resource> open_shared_texture(HANDLE handle) const;

    /**
     * @brief Queue one conversion.
     *
     * @param source Captured texture opened by `open_shared_texture()`.
     * @param source_format Format of the captured texture.
     * @param capture_value Capture-fence value that marks the texture as written, or zero.
     * @param consumption_value Consumption-fence value to signal when the conversion is done.
     * @return True when the work was submitted.
     */
    bool convert(ID3D12Resource *source, DXGI_FORMAT source_format, std::uint64_t capture_value, std::uint64_t consumption_value);

    /**
     * @brief Read the timings of a finished conversion without waiting.
     *
     * @param consumption_value Value passed to `convert()`.
     * @return Timings, or empty when the conversion has not finished or the clock was not readable.
     */
    std::optional<d3d12_conversion_timing_t> timing(std::uint64_t consumption_value);

    /**
     * @brief Block until every submitted conversion finished, bounded to one second.
     */
    void wait_idle() noexcept;

  private:
    d3d12_nv12_converter_t() = default;

    /** @brief Root constants; the layout matches the shader's `params` constant buffer. */
    struct constants_t {
      float color_vec_y[4];
      float color_vec_u[4];
      float color_vec_v[4];
      float range_y[2];
      float range_uv[2];
      float viewport[4];
      float subsample_offset[2];
      std::uint32_t luma_size[2];
      std::uint32_t fill_black;
    };

    /** @brief Per-submission resources reused round-robin. */
    struct frame_slot_t {
      Microsoft::WRL::ComPtr<ID3D12CommandAllocator> allocator;
      std::uint64_t consumption_value {};  ///< Value this slot's last submission signals.
      std::chrono::steady_clock::time_point submitted;  ///< CPU time of the last submission.
    };

    static constexpr std::size_t slot_count = 4;

    bool create_pipelines();
    ID3D12PipelineState *pipeline_for(DXGI_FORMAT source_format);
    bool wait_for_slot(const frame_slot_t &slot) noexcept;
    bool submit(ID3D12Resource *source, DXGI_FORMAT source_format, bool fill_black, std::uint64_t capture_value, std::uint64_t consumption_value);

    Microsoft::WRL::ComPtr<ID3D12Device> device_;
    Microsoft::WRL::ComPtr<ID3D12CommandQueue> queue_;
    Microsoft::WRL::ComPtr<ID3D12GraphicsCommandList> list_;
    Microsoft::WRL::ComPtr<ID3D12Fence> capture_fence_;  ///< Signalled by the D3D11 capture copy.
    Microsoft::WRL::ComPtr<ID3D12Fence> consumption_fence_;  ///< Signalled here; NVENC and the capture copy wait on it.
    Microsoft::WRL::ComPtr<ID3D12RootSignature> root_signature_;
    std::array<Microsoft::WRL::ComPtr<ID3D12PipelineState>, 4> pipelines_;  ///< {UNORM, scRGB} x {same size, downscaled}.
    Microsoft::WRL::ComPtr<ID3D12DescriptorHeap> descriptors_;
    Microsoft::WRL::ComPtr<ID3D12QueryHeap> timestamps_;
    Microsoft::WRL::ComPtr<ID3D12Resource> timestamp_readback_;
    const std::uint64_t *timestamp_values_ = nullptr;  ///< Persistently mapped readback of two ticks per slot.
    std::array<frame_slot_t, slot_count> slots_;
    std::size_t next_slot_ = 0;
    UINT descriptor_size_ = 0;
    std::uint64_t timestamp_frequency_ = 0;
    HANDLE wait_event_ = nullptr;
    std::string_view queue_priority_ = "normal";
    ID3D12Resource *output_ = nullptr;  ///< NV12 texture owned by the NVENC session.
    constants_t constants_ {};
    bool downscaling_ = false;
  };

}  // namespace platf::dxgi
