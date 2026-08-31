/**
 * @file src/protocol_lsp/ssrc_registry.h
 * @brief Authenticated LSP RTP lane and SSRC registry validation.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <vector>

namespace lumen::lsp {
  /**
   * @brief Direction of one negotiated RTP source.
   */
  enum class MediaDirection : std::uint8_t {
    host_to_client,  ///< Source packets originate at Lumen.
    client_to_host,  ///< Source packets originate at the LSP client.
  };

  /**
   * @brief Semantic lane assigned by authenticated LSP control.
   */
  enum class MediaLane : std::uint8_t {
    video_primary,  ///< Primary encoded video source.
    video_repair,  ///< FlexFEC repair source for primary video.
    video_rtx,  ///< Deadline-eligible RFC 4588 retransmission source.
    audio,  ///< Host Opus audio source.
    input,  ///< Client LSP input state and edge source.
    microphone,  ///< Client Opus microphone source.
  };

  /**
   * @brief Payload semantics selected for an RTP payload type.
   */
  enum class PayloadFormat : std::uint8_t {
    h264,  ///< H.264 RTP payload.
    hevc,  ///< HEVC RTP payload.
    av1,  ///< AOM AV1 RTP payload.
    flexfec,  ///< RFC 8627 FlexFEC payload.
    video_rtx,  ///< RFC 4588 retransmission payload.
    opus,  ///< RFC 7587 Opus payload.
    lsp_input,  ///< LSP input RTP payload.
  };

  /**
   * @brief One authenticated RTP source assignment.
   */
  struct SsrcAssignment {
    std::uint32_t ssrc {};  ///< Random nonzero synchronization source identifier.
    std::uint8_t payload_type {};  ///< Dynamic RTP payload type outside RFC 5761 conflict ranges.
    MediaLane lane {MediaLane::video_primary};  ///< Exact semantic lane.
    MediaDirection direction {MediaDirection::host_to_client};  ///< Expected packet direction.
    PayloadFormat format {PayloadFormat::h264};  ///< Payload parser selected by control negotiation.
    std::uint32_t clock_rate {};  ///< RTP clock rate in hertz.
    std::uint32_t generation {};  ///< Nonzero configuration generation owning this assignment.
    std::uint32_t associated_primary_ssrc {};  ///< Protected primary SSRC for FlexFEC/RTX, otherwise zero.

    bool operator==(const SsrcAssignment &) const = default;
  };

  /**
   * @brief SSRC registry validation failure.
   */
  enum class SsrcRegistryError : std::uint8_t {
    empty,  ///< No RTP source was supplied.
    too_many_entries,  ///< Registry exceeds the bounded LSP/1 source count.
    zero_ssrc,  ///< An SSRC is zero.
    duplicate_ssrc,  ///< Two lanes use the same SSRC.
    duplicate_lane,  ///< One LSP/1 semantic lane appears more than once.
    invalid_payload_type,  ///< Payload type is not in the safe dynamic range 96 through 127.
    conflicting_payload_type,  ///< One payload type maps to different payload semantics.
    invalid_direction,  ///< Lane direction differs from the LSP/1 registry.
    invalid_format,  ///< Payload format is not valid for the lane.
    invalid_clock_rate,  ///< RTP clock rate differs from the lane's required clock.
    zero_generation,  ///< Assignment generation is zero.
    invalid_repair_association,  ///< Repair association is missing, unexpected, or not a same-direction primary video source.
  };

  /**
   * @brief Validated, immutable authenticated SSRC registry.
   */
  class SsrcRegistry {
  public:
    inline static constexpr std::size_t maximum_entries = 16;  ///< Hard LSP/1 registry bound.

    /**
     * @brief Validate and construct a registry.
     *
     * @param assignments Candidate authenticated control assignments.
     * @return Immutable registry or the first concrete invariant violation.
     */
    [[nodiscard]] static std::expected<SsrcRegistry, SsrcRegistryError> create(
      std::span<const SsrcAssignment> assignments
    );

    /**
     * @brief Find the exact assignment for an incoming SSRC.
     *
     * @param ssrc Incoming nonzero SSRC.
     * @return Assignment pointer, or null for an unknown SSRC. Unknown values never create state.
     */
    [[nodiscard]] const SsrcAssignment *find(std::uint32_t ssrc) const noexcept;

    /**
     * @brief Return all validated assignments.
     *
     * @return Immutable assignment span.
     */
    [[nodiscard]] std::span<const SsrcAssignment> assignments() const noexcept;

  private:
    explicit SsrcRegistry(std::vector<SsrcAssignment> assignments);

    std::vector<SsrcAssignment> assignments_;  ///< Validated source mappings.
  };
}  // namespace lumen::lsp
