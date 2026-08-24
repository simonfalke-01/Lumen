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

// local includes
#include "src/platform/common.h"
#include "virtual_display.h"

namespace platf::virtual_display {
  inline constexpr std::size_t direct_frame_slot_count {2};  ///< Fixed persistent VDD slot count.

  /** @brief Pixel format exported by the VDD direct-frame channel. */
  enum class frame_format_e : std::uint32_t {
    bgra8 = 1,  ///< DXGI_FORMAT_B8G8R8A8_UNORM.
  };

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
    std::uint32_t slot_count {};  ///< Must equal `direct_frame_slot_count`.
    std::array<std::uintptr_t, direct_frame_slot_count> texture_handles {};  ///< Duplicated texture handles.
    std::array<std::uintptr_t, direct_frame_slot_count> fence_handles {};  ///< Duplicated fence handles.
  };

  /** @brief One completed driver copy leased through conversion and NVENC completion. */
  struct frame_descriptor_t {
    std::uint64_t generation {};  ///< Exact active VDD generation.
    std::uint64_t sequence {};  ///< Strictly increasing nonzero frame sequence.
    std::uint64_t producer_fence_value {};  ///< Odd per-slot producer fence value.
    std::int64_t capture_qpc {};  ///< QPC sampled after IddCx acquisition.
    std::int64_t producer_signal_qpc {};  ///< QPC sampled after producer fence submission.
    std::uint32_t slot {};  ///< Persistent slot index.
  };

  /**
   * @brief Validate exact resource metadata before importing any OS handle.
   * @param resources Driver response.
   * @param generation Expected active generation.
   * @param mode Exact selected mode.
   * @return True only for the fixed two-slot BGRA8 contract.
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

  private:
    friend class frame_source_t;

    frame_lease_t(
      std::shared_ptr<frame_source_t> source,
      frame_descriptor_t descriptor,
      void *native_texture
    );

    std::shared_ptr<frame_source_t> source_;  ///< Source retained until exact release completes.
    frame_descriptor_t descriptor_;  ///< Exact generation/sequence/slot ownership.
    void *native_texture_ {};  ///< Non-owning imported texture retained by `source_`.
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
