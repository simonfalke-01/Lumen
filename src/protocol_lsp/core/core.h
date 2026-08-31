/**
 * @file src/protocol_lsp/core/core.h
 * @brief Umbrella include for the dependency-free Lumen Streaming Protocol core foundation.
 */

#pragma once

#include "control.h"
#include "input.h"
#include "packet.h"
#include "rtp.h"
#include "telemetry.h"
#include "transport.h"
#include "wire.h"

namespace lumen::lsp {
  /** @brief Source-compatible portable-core API version used by Lumen and mirrored clients. */
  inline constexpr std::uint32_t core_api_version = 1;
}  // namespace lumen::lsp
