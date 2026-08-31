/**
 * @file src/protocol_lsp/packet_classifier.cpp
 * @brief RFC 7983 and RFC 5761 packet classification for the LSP UDP socket.
 */

#include "packet_classifier.h"

namespace lumen::lsp {
  SecurePacketClass classify_secure_packet(const std::span<const std::uint8_t> datagram) noexcept {
    if (datagram.size() < 2 || classify_packet(datagram) != PacketClass::rtp_or_rtcp) {
      return SecurePacketClass::invalid;
    }
    const auto second = datagram[1];
    if (second >= 192 && second <= 223) {
      return SecurePacketClass::rtcp;
    }
    return SecurePacketClass::rtp;
  }
}  // namespace lumen::lsp
