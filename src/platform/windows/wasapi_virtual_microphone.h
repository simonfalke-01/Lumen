/**
 * @file src/platform/windows/wasapi_virtual_microphone.h
 * @brief Event-driven WASAPI fallback for existing virtual microphone cables.
 */
#pragma once

// local includes
#include "virtual_microphone.h"

// standard includes
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace platf::win_audio {
  /**
   * @brief Supported endpoint sample encodings for mono microphone conversion.
   */
  enum class wasapi_sample_format_e {
    pcm_s16,  ///< Signed 16-bit little-endian PCM.
    pcm_s24,  ///< Signed packed 24-bit little-endian PCM.
    pcm_s32,  ///< Signed 32-bit little-endian PCM.
    float_f32  ///< IEEE 754 32-bit floating point PCM.
  };

  /**
   * @brief Validated endpoint mix format used by the portable converter.
   */
  struct wasapi_mix_format_t {
    std::uint32_t sample_rate {};  ///< Output sample rate in hertz.
    std::uint16_t channels {};  ///< Interleaved output channel count.
    std::uint16_t block_align {};  ///< Bytes in one interleaved output frame.
    wasapi_sample_format_e sample_format {wasapi_sample_format_e::float_f32};  ///< Output encoding.
  };

  /**
   * @brief One exact render/capture virtual-cable identity.
   */
  struct wasapi_endpoint_pair_t {
    std::wstring_view render_name;  ///< Exact active render endpoint friendly name.
    std::wstring_view capture_name;  ///< Exact active paired capture endpoint friendly name.
  };

  /**
   * @brief Select the first complete exact virtual-cable pair in security preference order.
   *
   * @param render_names Active render endpoint friendly names.
   * @param capture_names Active capture endpoint friendly names.
   * @return Selected pair, or `nullptr` when no complete whitelisted pair exists.
   */
  [[nodiscard]] const wasapi_endpoint_pair_t *select_wasapi_virtual_microphone_pair(
    std::span<const std::wstring> render_names,
    std::span<const std::wstring> capture_names
  ) noexcept;

  /**
   * @brief Stateful streaming converter from 48 kHz mono signed-16 PCM.
   */
  class wasapi_mono_converter_t {
  public:
    /**
     * @brief Configure a validated endpoint mix format and reset resampling history.
     * @param format Endpoint mix format.
     * @return `true` when every format field is supported and internally consistent.
     */
    bool reset(const wasapi_mix_format_t &format) noexcept;

    /**
     * @brief Convert the next contiguous source chunk into endpoint frames.
     * @param samples 48 kHz mono signed-16 PCM.
     * @return Complete interleaved endpoint frames, or an empty vector when no resampled frame is ready.
     */
    [[nodiscard]] std::vector<std::byte> convert(std::span<const std::int16_t> samples);

    /**
     * @brief Return the configured mix format.
     * @return Current validated format.
     */
    [[nodiscard]] const wasapi_mix_format_t &format() const noexcept;

  private:
    wasapi_mix_format_t format_ {};  ///< Validated output format.
    std::uint64_t source_frames_ {};  ///< Total contiguous input frames observed.
    std::uint64_t output_frames_ {};  ///< Total output frames emitted.
    std::int16_t previous_sample_ {};  ///< Last sample from the previous source chunk.
    bool configured_ {};  ///< Whether reset accepted the current format.
    bool have_previous_ {};  ///< Whether the previous source sample is available.
  };

  /**
   * @brief Bounded frame-aligned byte ring used between receiver and WASAPI threads.
   */
  class wasapi_frame_ring_t {
  public:
    /**
     * @brief Construct an unconfigured ring.
     */
    wasapi_frame_ring_t() = default;

    /**
     * @brief Allocate fixed frame capacity and clear queued data.
     * @param capacity_frames Maximum queued frames.
     * @param block_align Bytes in one frame.
     * @return `true` when both dimensions are nonzero and the allocation succeeds.
     */
    bool reset(std::size_t capacity_frames, std::size_t block_align);

    /**
     * @brief Enqueue complete frames without overwriting unread audio.
     * @param bytes Frame-aligned source bytes.
     * @return `false` on misalignment or bounded backpressure.
     */
    bool push(std::span<const std::byte> bytes) noexcept;

    /**
     * @brief Dequeue up to the destination's complete-frame capacity.
     * @param destination Frame-aligned destination bytes.
     * @return Number of frames copied.
     */
    std::size_t pop(std::span<std::byte> destination) noexcept;

    /**
     * @brief Return queued frame count.
     * @return Frames currently queued.
     */
    [[nodiscard]] std::size_t size_frames() const noexcept;

    /**
     * @brief Return remaining writable frame count.
     * @return Frames available before backpressure.
     */
    [[nodiscard]] std::size_t free_frames() const noexcept;

  private:
    std::vector<std::byte> storage_;  ///< Fixed circular byte storage.
    std::size_t block_align_ {};  ///< Bytes per frame.
    std::size_t read_frame_ {};  ///< Next readable frame index.
    std::size_t write_frame_ {};  ///< Next writable frame index.
    std::size_t size_frames_ {};  ///< Queued frame count.
  };

  /**
   * @brief Portable generation and fail-close state for the WASAPI sink.
   */
  class wasapi_generation_state_t {
  public:
    /**
     * @brief Activate a nonzero generation.
     * @param generation New owning generation.
     * @return `true` when generation is nonzero.
     */
    bool begin(std::uint64_t generation) noexcept;

    /**
     * @brief Test whether one generation may write.
     * @param generation Candidate generation.
     * @return `true` only for the active generation before failure.
     */
    [[nodiscard]] bool accepts(std::uint64_t generation) const noexcept;

    /**
     * @brief Mark the active generation permanently failed until a new begin.
     */
    void fail() noexcept;

    /**
     * @brief End a matching active or failed generation.
     * @param generation Candidate generation.
     * @return `true` when the matching generation was cleared.
     */
    bool end(std::uint64_t generation) noexcept;

    /**
     * @brief Return the current generation, or zero while idle.
     * @return Owned generation.
     */
    [[nodiscard]] std::uint64_t generation() const noexcept;

    /**
     * @brief Test whether backpressure or a backend error failed the generation closed.
     * @return `true` in fail-closed state.
     */
    [[nodiscard]] bool failed() const noexcept;

  private:
    std::uint64_t generation_ {};  ///< Current owning generation.
    bool failed_ {};  ///< Fail-close latch for the current generation.
  };

  /**
   * @brief Create the exact-pair, event-driven WASAPI virtual microphone fallback.
   * @return Unprobed fallback sink.
   */
  std::unique_ptr<virtual_microphone_sink_t> make_wasapi_virtual_microphone();
}  // namespace platf::win_audio
