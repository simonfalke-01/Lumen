/**
 * @file src/protocol_lsp/packet_classifier.h
 * @brief RFC 7983 and RFC 5761 packet classification for the LSP UDP socket.
 */

#pragma once

#include "core/packet.h"

#include <cstdint>
#include <span>

namespace lumen::lsp {
  using PacketClass = packet_class;  ///< Shared portable RFC 7983 classification.

  /**
   * @brief RFC 5761 classification after the RFC 7983 SRTP range is selected.
   */
  enum class SecurePacketClass : std::uint8_t {
    invalid,  ///< Too short or not an RTP-version-two packet.
    rtp,  ///< SRTP packet.
    rtcp,  ///< SRTCP packet with an RTCP packet type in byte two.
  };

  /**
   * @brief Distinguish SRTP from SRTCP according to RFC 5761.
   *
   * Dynamic RTP payload types must be selected so byte-two values 192 through
   * 223 are unambiguously RTCP packet types.
   *
   * @param datagram Complete protected RTP or RTCP packet.
   * @return Secure packet classification.
   */
  [[nodiscard]] SecurePacketClass classify_secure_packet(std::span<const std::uint8_t> datagram) noexcept;
}  // namespace lumen::lsp
