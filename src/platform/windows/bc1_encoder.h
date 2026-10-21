/**
 * @file src/platform/windows/bc1_encoder.h
 * @brief Intra-only BC1 encoder that stands in for NVENC on very fast links.
 */
#pragma once

// standard includes
#include <cstdint>
#include <memory>

// platform includes
#include <d3d11.h>

// local includes
#include "src/nvenc/nvenc_d3d11_interface.h"

namespace platf::dxgi {

  /**
   * @brief Compress each captured BGRA frame to BC1 blocks with a D3D11 compute shader.
   *
   * Every frame is independent, so there is no reference state, rate control, or codec
   * configuration. Each output access unit is one AV1 padding OBU holding a 16-byte header
   * ("LBC1", width, height, block bytes, reserved) followed by row-major BC1 blocks.
   */
  std::unique_ptr<nvenc::nvenc_d3d11_interface> make_bc1_encoder(ID3D11Device *device);

}  // namespace platf::dxgi
