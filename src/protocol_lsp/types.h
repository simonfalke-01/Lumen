/**
 * @file src/protocol_lsp/types.h
 * @brief Fundamental host-side Lumen Streaming Protocol value types.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace lumen::lsp {
  inline constexpr std::uint8_t wire_version = 1;  ///< LSP wire version implemented by this foundation.
  inline constexpr std::uint16_t default_udp_port = 48'030;  ///< Default and recommended LSP application port.
  inline constexpr std::string_view alpn = "lumen-stream/1";  ///< Exact DTLS ALPN required by LSP/1.
  inline constexpr std::string_view discovery_service = "_lumen-stream._udp";  ///< LSP mDNS service type.
  inline constexpr std::size_t maximum_controller_slots = 16;  ///< Bounded controller-instance slots tracked by one session.

  using Identifier128 = std::array<std::uint8_t, 16>;  ///< Fixed-width host, client, and session identifier.
  using PublicKey256 = std::array<std::uint8_t, 32>;  ///< Ed25519 public key bytes.
  using Digest256 = std::array<std::uint8_t, 32>;  ///< SHA-256 digest bytes.
  using Secret256 = std::array<std::uint8_t, 32>;  ///< Fixed-width nonce, confirmation, digest, or attach secret.

  /** @brief Bounded stable RTCP SDES CNAME supplied once per authenticated association. */
  struct RtcpCname {
    std::array<std::uint8_t, 64> bytes {};  ///< Host-unique opaque CNAME bytes.
    std::uint8_t size {};  ///< Populated leading bytes, one through 64.

    /** @brief Return whether one nonempty bounded CNAME is present. */
    [[nodiscard]] constexpr bool valid() const noexcept {
      return size != 0 && size <= bytes.size();
    }

    /** @brief Return the populated immutable CNAME bytes. */
    [[nodiscard]] constexpr std::span<const std::uint8_t> view() const noexcept {
      return valid() ? std::span<const std::uint8_t> {bytes}.first(size) : std::span<const std::uint8_t> {};
    }

    bool operator==(const RtcpCname &) const = default;
  };

  /**
   * @brief Return whether every byte in a fixed-width protocol value is zero.
   *
   * @tparam Size Number of bytes in the value.
   * @param value Value to inspect.
   * @return True only when every byte is zero.
   */
  template<std::size_t Size>
  [[nodiscard]] constexpr bool is_zero(const std::array<std::uint8_t, Size> &value) noexcept {
    std::uint8_t aggregate = 0;
    for (const auto byte : value) {
      aggregate = static_cast<std::uint8_t>(aggregate | byte);
    }
    return aggregate == 0;
  }

  /**
   * @brief Permission granted to one paired LSP client.
   */
  enum class Permission : std::uint32_t {
    browse_applications = 1U << 0U,  ///< Enumerate host applications.
    start_attach = 1U << 1U,  ///< Start or attach the client's own stream.
    input = 1U << 2U,  ///< Send device input and text.
    microphone = 1U << 3U,  ///< Send client microphone audio.
    stop_own_stream = 1U << 4U,  ///< Stop a stream owned by the client.
    quit_application = 1U << 5U,  ///< Quit the hosted application.
    controller_output = 1U << 6U,  ///< Receive controller output and haptics.
  };

  /**
   * @brief Validated LSP permission bit set.
   */
  class PermissionSet {
  public:
    inline static constexpr std::uint32_t known_mask = 0x7fU;  ///< Mask containing every LSP/1 permission bit.
    inline static constexpr std::uint32_t default_pairing_mask =
      static_cast<std::uint32_t>(Permission::browse_applications) |
      static_cast<std::uint32_t>(Permission::start_attach) |
      static_cast<std::uint32_t>(Permission::input) |
      static_cast<std::uint32_t>(Permission::stop_own_stream) |
      static_cast<std::uint32_t>(Permission::controller_output);  ///< Safe default pairing permissions.

    /**
     * @brief Construct an empty permission set.
     */
    constexpr PermissionSet() noexcept = default;

    /**
     * @brief Validate and construct a permission set.
     *
     * @param mask Candidate permission mask.
     * @return A permission set when no unknown bits are present.
     */
    [[nodiscard]] static constexpr std::optional<PermissionSet> from_mask(const std::uint32_t mask) noexcept {
      if ((mask & ~known_mask) != 0) {
        return std::nullopt;
      }
      return PermissionSet {mask};
    }

    /**
     * @brief Construct the safe default pairing permissions.
     *
     * @return Browse, start/attach, input, stop-own-stream, and controller-output permissions.
     */
    [[nodiscard]] static constexpr PermissionSet default_pairing() noexcept {
      return PermissionSet {default_pairing_mask};
    }

    /**
     * @brief Return the encoded permission mask.
     *
     * @return LSP/1 permission bits.
     */
    [[nodiscard]] constexpr std::uint32_t mask() const noexcept {
      return mask_;
    }

    /**
     * @brief Test whether a permission is present.
     *
     * @param permission Permission to test.
     * @return True when the permission is granted.
     */
    [[nodiscard]] constexpr bool contains(const Permission permission) const noexcept {
      return (mask_ & static_cast<std::uint32_t>(permission)) != 0;
    }

    /**
     * @brief Remove permissions from this set.
     *
     * @param revoked Permissions to remove.
     */
    constexpr void revoke(const PermissionSet revoked) noexcept {
      mask_ &= ~revoked.mask_;
    }

    bool operator==(const PermissionSet &) const = default;

  private:
    /**
     * @brief Construct a permission set from an internally validated mask.
     *
     * @param mask Mask containing only LSP/1 permission bits.
     */
    explicit constexpr PermissionSet(const std::uint32_t mask) noexcept:
        mask_ {mask} {
    }

    std::uint32_t mask_ {};  ///< Validated permission bits.
  };

  /**
   * @brief LSP congestion-control profile.
   */
  enum class NetworkProfile : std::uint8_t {
    adaptive_low_latency = 0,  ///< Congestion-safe default for uncharacterized paths.
    competition = 1,  ///< Explicitly capacity-bounded competition LAN mode.
  };

  /**
   * @brief IP address family used by one LSP UDP five-tuple.
   */
  enum class IpAddressFamily : std::uint8_t {
    ipv4,  ///< IPv4 UDP socket.
    ipv6,  ///< IPv6 UDP socket.
  };

  /** @brief Canonical binary remote address cached by the native socket per association. */
  struct CanonicalPeerAddress {
    std::array<std::uint8_t, 16> address {};  ///< IPv4 bytes in the leading four positions or full IPv6 bytes.
    std::uint32_t scope_id {};  ///< IPv6 scope identifier, zero for IPv4/global IPv6.
    bool valid {};  ///< Whether binary family/address bytes are authoritative.

    bool operator==(const CanonicalPeerAddress &) const = default;
  };

  /**
   * @brief Host-visible LSP configuration values.
   */
  struct HostConfig {
#ifdef _WIN32
    bool enabled {true};  ///< Whether the LSP listener is enabled on this full Windows build.
#else
    bool enabled {false};  ///< Whether the unsupported host-platform LSP listener is enabled.
#endif
    std::uint16_t port {default_udp_port};  ///< Single UDP application port used by every LSP flow.
    NetworkProfile profile {NetworkProfile::adaptive_low_latency};  ///< Initial network profile.
    std::uint32_t competition_capacity_mbps {};  ///< Configured competition ceiling; zero disables competition mode.
    PermissionSet pairing_permissions {PermissionSet::default_pairing()};  ///< Permissions offered by default when pairing.

    /**
     * @brief Validate configuration invariants without opening a socket.
     *
     * @return True when the port is nonzero, the profile is known, and competition has an explicit ceiling.
     */
    [[nodiscard]] bool valid() const noexcept;
  };

  /**
   * @brief Portable UDP five-tuple identity supplied by the socket owner.
   */
  struct PeerEndpoint {
    IpAddressFamily family {IpAddressFamily::ipv4};  ///< IP protocol family.
    std::string local_address;  ///< Numeric local address that received the datagram.
    std::uint16_t local_port {};  ///< Local LSP application port.
    CanonicalPeerAddress canonical_local;  ///< Exact received local destination address and IPv6 scope.
    std::uint32_t interface_index {};  ///< Receiving interface used for same-source replies, zero when unavailable.
    std::string remote_address;  ///< Numeric remote source address.
    std::uint16_t remote_port {};  ///< Nonzero remote UDP source port.
    CanonicalPeerAddress canonical_remote;  ///< Cached binary address avoiding steady-state text parsing.

    /**
     * @brief Validate the endpoint before passing it to a security provider.
     *
     * @return True when the family, both addresses, and both ports are valid.
     */
    [[nodiscard]] bool valid() const noexcept;

    /** @brief Compare semantic five-tuple fields while ignoring the derived binary cache. */
    bool operator==(const PeerEndpoint &other) const noexcept;
  };

  /**
   * @brief Independent nonzero LSP generation counters.
   */
  struct Generations {
    std::uint32_t connection {};  ///< DTLS connection authority generation.
    std::uint32_t stream {};  ///< Stream-session generation.
    std::uint32_t video {};  ///< Video configuration generation.
    std::uint32_t audio {};  ///< Audio configuration generation.
    std::uint32_t microphone {};  ///< Microphone configuration generation.
    std::uint32_t input {};  ///< Input authority generation.
    std::array<std::uint32_t, maximum_controller_slots> controller_instances {};  ///< Per-slot controller generations; zero marks an inactive slot.

    /**
     * @brief Validate that every required generation is nonzero.
     *
     * @return True only when every generation is nonzero.
     */
    [[nodiscard]] bool valid() const noexcept;

    bool operator==(const Generations &) const = default;
  };
}  // namespace lumen::lsp
