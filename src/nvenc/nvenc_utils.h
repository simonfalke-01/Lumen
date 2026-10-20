/**
 * @file src/nvenc/nvenc_utils.h
 * @brief Declarations for NVENC utilities.
 */
#pragma once

// plafform includes
#ifdef _WIN32
  #include <dxgiformat.h>
#endif

// local includes
#include "nvenc_colorspace.h"
#include "nvenc_sdk.h"
#include "src/platform/common.h"
#include "src/video_colorspace.h"

namespace NVENC_NAMESPACE {

#ifdef _WIN32
  /**
   * @brief Convert an NVENC buffer format to the matching DXGI format.
   *
   * @param format Pixel, audio, or protocol format being converted.
   * @return DXGI texture format that matches the NVENC buffer format.
   */
  DXGI_FORMAT dxgi_format_from_nvenc_format(NV_ENC_BUFFER_FORMAT format);
#endif

  /**
   * @brief Convert a Lumen pixel format to the matching NVENC buffer format.
   *
   * @param format Pixel, audio, or protocol format being converted.
   * @return NVENC buffer format compatible with the Lumen pixel format.
   */
  NV_ENC_BUFFER_FORMAT nvenc_format_from_stream_format(platf::pix_fmt_e format);

  /**
   * @brief Convert Lumen colorspace metadata to NVENC VUI metadata.
   *
   * @param stream_colorspace Lumen colorspace.
   * @return NVENC colorspace and VUI fields for the Lumen metadata.
   */
  nvenc_colorspace_t nvenc_colorspace_from_stream_colorspace(const video::stream_colorspace_t &stream_colorspace);

}  // namespace NVENC_NAMESPACE
