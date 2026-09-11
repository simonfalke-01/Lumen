/**
 * @file src/protocol_lsp/types.cpp
 * @brief Fundamental host-side Lumen Streaming Protocol value-type validation.
 */

#include "types.h"

namespace lumen::lsp {
  bool HostConfig::valid() const noexcept {
    if (port == 0) {
      return false;
    }
    switch (profile) {
      case NetworkProfile::adaptive_low_latency:
        return true;
      case NetworkProfile::competition:
        return competition_capacity_mbps != 0;
    }
    return false;
  }

  bool PeerEndpoint::valid() const noexcept {
    switch (family) {
      case IpAddressFamily::ipv4:
      case IpAddressFamily::ipv6:
        break;
      default:
        return false;
    }
    return !local_address.empty() && local_port != 0 && !remote_address.empty() && remote_port != 0;
  }

  bool PeerEndpoint::operator==(const PeerEndpoint &other) const noexcept {
    return family == other.family && local_address == other.local_address && local_port == other.local_port &&
           canonical_local == other.canonical_local && interface_index == other.interface_index &&
           remote_address == other.remote_address && remote_port == other.remote_port &&
           canonical_remote == other.canonical_remote;
  }

  bool Generations::valid() const noexcept {
    return connection != 0 && stream != 0 && video != 0 && audio != 0 && microphone != 0 && input != 0;
  }
}  // namespace lumen::lsp
