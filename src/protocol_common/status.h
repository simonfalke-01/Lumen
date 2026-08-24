/**
 * @file src/protocol_common/status.h
 * @brief Shared control-response status registry.
 */

#pragma once

#include <cstdint>

namespace lumen::protocol_common {
  enum class Status : std::uint8_t {
    success = 0,
    malformed = 1,
    unauthenticated = 2,
    unauthorized = 3,
    expired = 4,
    consumed = 5,
    version_mismatch = 6,
    capability_mismatch = 7,
    busy = 8,
    application_not_found = 9,
    unsupported_media = 10,
    resource_failure = 11,
    internal_failure = 12,
    rekey_collision_lost = 13,
    rekey_epoch_mismatch = 14,
  };
}  // namespace lumen::protocol_common
