/**
 * @file src/nvenc/nvenc_encoder.h
 * @brief Declarations for the SDK-neutral NVENC encoder interface.
 */
#pragma once

// standard includes
#include <cstdint>
#include <optional>

// local includes
#include "nvenc_config.h"
#include "nvenc_encoded_frame.h"
#include "nvenc_hdr_metadata.h"

namespace platf {
  enum class pix_fmt_e;
}

namespace video {
  struct config_t;
  struct sunshine_colorspace_t;
}  // namespace video

namespace nvenc {

  /**
   * @brief SDK-neutral standalone NVENC encoder interface.
   */
  class nvenc_encoder {
  public:
    /**
     * @brief Destroy the SDK-neutral encoder interface.
     */
    virtual ~nvenc_encoder() = default;

    /**
     * @brief Create the encoder.
     *
     * @param config NVENC encoder configuration.
     * @param client_config Stream configuration requested by the client.
     * @param colorspace Sunshine colorspace metadata.
     * @param buffer_format Platform-agnostic input surface format.
     * @param hdr_metadata Validated HDR10 static metadata, or empty for SDR.
     * @return `true` on success, `false` on error.
     */
    virtual bool create_encoder(
      const nvenc_config &config,
      const video::config_t &client_config,
      const video::sunshine_colorspace_t &colorspace,
      platf::pix_fmt_e buffer_format,
      const std::optional<hdr_static_metadata_t> &hdr_metadata
    ) = 0;

    /**
     * @brief Update the validated HDR10 static block for the next encoded picture.
     * @param metadata Complete validated mastering-display and content-light values.
     * @return True when unchanged or queued; false when unsupported or malformed.
     */
    virtual bool update_hdr_metadata(const hdr_static_metadata_t &metadata) = 0;

    /**
     * @brief Destroy the encoder.
     */
    virtual void destroy_encoder() = 0;

    /**
     * @brief Encode the next frame using the platform-specific input surface.
     *
     * @param frame_index Frame index that uniquely identifies the frame.
     * @param force_idr Whether to encode the frame as a forced IDR.
     * @return Encoded frame.
     */
    virtual nvenc_encoded_frame encode_frame(std::uint64_t frame_index, bool force_idr) = 0;

    /**
     * @brief Invalidate reference frames in the requested range.
     *
     * @param first_frame First frame index of the invalidation range.
     * @param last_frame Last frame index of the invalidation range.
     * @return `true` on success, `false` on error.
     */
    virtual bool invalidate_ref_frames(std::uint64_t first_frame, std::uint64_t last_frame) = 0;
  };

}  // namespace nvenc
