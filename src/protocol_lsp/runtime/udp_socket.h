/**
 * @file src/protocol_lsp/runtime/udp_socket.h
 * @brief Native nonblocking single-port UDP ownership for the LSP host runtime.
 */

#pragma once

#include "../service.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>

namespace lumen::lsp::runtime {
  /** @brief Maximum UDP payload admitted by the initial LSP socket runtime. */
  inline constexpr std::size_t maximum_runtime_datagram_size = 65'535;

  /**
   * @brief One complete received UDP datagram and its monotonic receive time.
   */
  struct ReceivedDatagram {
    PeerEndpoint peer;  ///< Exact source and bound local endpoint.
    std::span<const std::uint8_t> payload;  ///< Complete payload valid only for the callback.
    std::uint64_t received_at_microseconds {};  ///< Local monotonic receive timestamp.
  };

  /**
   * @brief Result of one bounded native receive-drain operation.
   */
  enum class ReceiveBatchResult : std::uint8_t {
    drained,  ///< One or more datagrams were delivered and the bounded batch ended.
    would_block,  ///< No datagram was ready.
    closed,  ///< The socket has been closed.
    fatal,  ///< A native socket error prevents continued operation.
  };

  /**
   * @brief Native Winsock/POSIX implementation of LSP's one-port UDP boundary.
   *
   * The socket is nonblocking. A receive call drains no more than the caller's
   * bound and invokes the callback synchronously before reusing its fixed
   * datagram storage.
   */
  class NativeUdpSocket final: public SinglePortUdpSocket {
  public:
    /** @brief Construct a closed socket owner. */
    NativeUdpSocket() noexcept;

    NativeUdpSocket(const NativeUdpSocket &) = delete;
    NativeUdpSocket &operator=(const NativeUdpSocket &) = delete;

    /** @brief Close the native socket. */
    ~NativeUdpSocket() override;

    /** @copydoc SinglePortUdpSocket::bind */
    bool bind(std::uint16_t port) noexcept override;

    /** @copydoc SinglePortUdpSocket::close */
    void close() noexcept override;

    /**
     * @brief Wait for receive readiness or a bounded timeout.
     *
     * @param timeout_milliseconds Maximum wait duration.
     * @return True when the socket may be read, including a close/error wake.
     */
    [[nodiscard]] bool wait_readable(std::uint32_t timeout_milliseconds) noexcept;

    /**
     * @brief Drain a bounded batch of complete datagrams.
     *
     * @param maximum_datagrams Maximum callbacks during this call; must be nonzero.
     * @param callback Synchronous complete-datagram consumer.
     * @return Exact drain disposition.
     */
    ReceiveBatchResult receive_batch(
      std::size_t maximum_datagrams,
      const std::function<void(const ReceivedDatagram &)> &callback
    ) noexcept;

    /**
     * @brief Send one complete UDP datagram to an exact peer.
     *
     * @param peer Destination five-tuple originally produced by this socket.
     * @param datagram Complete UDP payload.
     * @return True only when the native API accepted the whole datagram.
     */
    bool send_datagram(
      const PeerEndpoint &peer,
      std::span<const std::uint8_t> datagram
    ) noexcept;

    /**
     * @brief Return the actual bound port.
     *
     * @return Nonzero port while bound, otherwise zero.
     */
    [[nodiscard]] std::uint16_t bound_port() const noexcept;

    /**
     * @brief Return whether a native socket is currently owned.
     *
     * @return True between a successful bind and close.
     */
    [[nodiscard]] bool open() const noexcept;

  private:
#ifdef _WIN32
    using NativeHandle = std::uintptr_t;  ///< Winsock SOCKET stored without exposing Winsock headers.
    inline static constexpr NativeHandle invalid_handle = static_cast<NativeHandle>(~std::uintptr_t {});  ///< Invalid Winsock handle.
#else
    using NativeHandle = int;  ///< POSIX file descriptor.
    inline static constexpr NativeHandle invalid_handle = -1;  ///< Invalid POSIX file descriptor.
#endif

    NativeHandle handle_ {invalid_handle};  ///< Owned native socket.
    std::uint16_t bound_port_ {};  ///< Actual numeric local port.
  };

  /**
   * @brief Read the local monotonic clock in whole microseconds.
   *
   * @return Nondecreasing process-local timestamp.
   */
  [[nodiscard]] std::uint64_t monotonic_microseconds() noexcept;
}  // namespace lumen::lsp::runtime
