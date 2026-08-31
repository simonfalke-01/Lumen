/**
 * @file src/protocol_lsp/runtime/udp_socket.cpp
 * @brief Native nonblocking single-port UDP ownership for the LSP host runtime.
 */

#ifdef __APPLE__
  #ifndef __APPLE_USE_RFC_3542
    #define __APPLE_USE_RFC_3542
  #endif
#endif

#include "udp_socket.h"

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
  #include <cerrno>
  #include <fcntl.h>
  #include <netinet/in.h>
  #include <poll.h>
  #include <sys/socket.h>
  #include <unistd.h>
#endif

#include <array>
#include <chrono>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>

namespace lumen::lsp::runtime {
  namespace {
#ifdef _WIN32
    using SocketLength = int;

    bool initialize_winsock() noexcept {
      static std::once_flag once;
      static bool initialized = false;
      try {
        std::call_once(once, []() noexcept {
          WSADATA data {};
          initialized = WSAStartup(MAKEWORD(2, 2), &data) == 0;
        });
      } catch (...) {
        return false;
      }
      return initialized;
    }

    bool would_block_error() noexcept {
      return WSAGetLastError() == WSAEWOULDBLOCK;
    }

    bool configure_no_fragment(const SOCKET socket) noexcept {
      const DWORD mode = IP_PMTUDISC_PROBE;
      return setsockopt(
               socket,
               IPPROTO_IP,
               IP_MTU_DISCOVER,
               reinterpret_cast<const char *>(&mode),
               sizeof(mode)
             ) == 0 &&
             setsockopt(
               socket,
               IPPROTO_IPV6,
               IPV6_MTU_DISCOVER,
               reinterpret_cast<const char *>(&mode),
               sizeof(mode)
             ) == 0;
    }

    void close_socket(const SOCKET socket) noexcept {
      closesocket(socket);
    }
#else
    using SocketLength = socklen_t;

    bool initialize_winsock() noexcept {
      return true;
    }

    bool would_block_error() noexcept {
      return errno == EAGAIN || errno == EWOULDBLOCK;
    }


    bool configure_no_fragment(const int socket) noexcept {
#if defined(__linux__)
      const int ipv4_mode = IP_PMTUDISC_PROBE;
      const int ipv6_mode = IPV6_PMTUDISC_PROBE;
      return setsockopt(socket, IPPROTO_IP, IP_MTU_DISCOVER, &ipv4_mode, sizeof(ipv4_mode)) == 0 &&
             setsockopt(socket, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &ipv6_mode, sizeof(ipv6_mode)) == 0;
#else
      const int enabled = 1;
      return setsockopt(socket, IPPROTO_IPV6, IPV6_DONTFRAG, &enabled, sizeof(enabled)) == 0;
#endif
    }

    void close_socket(const int socket) noexcept {
      ::close(socket);
    }
#endif

    template<class NativeSocket>
    bool set_nonblocking(const NativeSocket socket) noexcept {
#ifdef _WIN32
      u_long enabled = 1;
      return ioctlsocket(socket, FIONBIO, &enabled) == 0;
#else
      const auto flags = fcntl(socket, F_GETFL, 0);
      return flags >= 0 && fcntl(socket, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
    }

    std::string numeric_address(const sockaddr_storage &storage) {
      std::array<char, INET6_ADDRSTRLEN> text {};
      if (storage.ss_family == AF_INET) {
        const auto &address = reinterpret_cast<const sockaddr_in &>(storage);
        return inet_ntop(AF_INET, &address.sin_addr, text.data(), static_cast<SocketLength>(text.size())) != nullptr ?
                 std::string {text.data()} : std::string {};
      }
      if (storage.ss_family == AF_INET6) {
        const auto &address = reinterpret_cast<const sockaddr_in6 &>(storage);
        if (IN6_IS_ADDR_V4MAPPED(&address.sin6_addr)) {
          in_addr mapped {};
          std::memcpy(&mapped, &address.sin6_addr.s6_addr[12], sizeof(mapped));
          return inet_ntop(AF_INET, &mapped, text.data(), static_cast<SocketLength>(text.size())) != nullptr ?
                   std::string {text.data()} : std::string {};
        }
        return inet_ntop(AF_INET6, &address.sin6_addr, text.data(), static_cast<SocketLength>(text.size())) != nullptr ?
                 std::string {text.data()} : std::string {};
      }
      return {};
    }

    std::uint16_t numeric_port(const sockaddr_storage &storage) noexcept {
      if (storage.ss_family == AF_INET) {
        return ntohs(reinterpret_cast<const sockaddr_in &>(storage).sin_port);
      }
      if (storage.ss_family == AF_INET6) {
        return ntohs(reinterpret_cast<const sockaddr_in6 &>(storage).sin6_port);
      }
      return 0;
    }

    IpAddressFamily address_family(const sockaddr_storage &storage) noexcept {
      if (storage.ss_family == AF_INET6 &&
          IN6_IS_ADDR_V4MAPPED(&reinterpret_cast<const sockaddr_in6 &>(storage).sin6_addr)) {
        return IpAddressFamily::ipv4;
      }
      return storage.ss_family == AF_INET6 ? IpAddressFamily::ipv6 : IpAddressFamily::ipv4;
    }

    bool encode_destination(
      const PeerEndpoint &peer,
      sockaddr_storage &storage,
      SocketLength &size
    ) noexcept {
      std::memset(&storage, 0, sizeof(storage));
      if (peer.family == IpAddressFamily::ipv4) {
        in_addr mapped {};
        if (inet_pton(AF_INET, peer.remote_address.c_str(), &mapped) != 1) {
          return false;
        }
        auto &address = reinterpret_cast<sockaddr_in6 &>(storage);
        address.sin6_family = AF_INET6;
        address.sin6_port = htons(peer.remote_port);
        address.sin6_addr.s6_addr[10] = 0xff;
        address.sin6_addr.s6_addr[11] = 0xff;
        std::memcpy(&address.sin6_addr.s6_addr[12], &mapped, sizeof(mapped));
        size = sizeof(address);
        return true;
      }
      if (peer.family == IpAddressFamily::ipv6) {
        auto &address = reinterpret_cast<sockaddr_in6 &>(storage);
        address.sin6_family = AF_INET6;
        address.sin6_port = htons(peer.remote_port);
        size = sizeof(address);
        return inet_pton(AF_INET6, peer.remote_address.c_str(), &address.sin6_addr) == 1;
      }
      return false;
    }
  }  // namespace

  NativeUdpSocket::NativeUdpSocket() noexcept = default;

  NativeUdpSocket::~NativeUdpSocket() {
    close();
  }

  bool NativeUdpSocket::bind(const std::uint16_t port) noexcept {
    if (open() || !initialize_winsock()) {
      return false;
    }

    const auto native = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
#ifdef _WIN32
    if (native == INVALID_SOCKET) {
#else
    if (native < 0) {
#endif
      return false;
    }

    int dual_stack = 0;
    if (setsockopt(native, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char *>(&dual_stack), sizeof(dual_stack)) != 0 ||
        !configure_no_fragment(native) ||
        !set_nonblocking(native)) {
      close_socket(native);
      return false;
    }

    sockaddr_in6 address {};
    address.sin6_family = AF_INET6;
    address.sin6_addr = in6addr_any;
    address.sin6_port = htons(port);
    if (::bind(native, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0) {
      close_socket(native);
      return false;
    }

    sockaddr_in6 actual {};
    SocketLength actual_size = sizeof(actual);
    if (getsockname(native, reinterpret_cast<sockaddr *>(&actual), &actual_size) != 0) {
      close_socket(native);
      return false;
    }

    handle_ = static_cast<NativeHandle>(native);
    bound_port_ = ntohs(actual.sin6_port);
    return bound_port_ != 0;
  }

  void NativeUdpSocket::close() noexcept {
    if (!open()) {
      return;
    }
#ifdef _WIN32
    close_socket(static_cast<SOCKET>(handle_));
#else
    close_socket(handle_);
#endif
    handle_ = invalid_handle;
    bound_port_ = 0;
  }

  bool NativeUdpSocket::wait_readable(const std::uint32_t timeout_milliseconds) noexcept {
    if (!open()) {
      return true;
    }
#ifdef _WIN32
    WSAPOLLFD descriptor {
      .fd = static_cast<SOCKET>(handle_),
      .events = POLLRDNORM,
    };
    const auto bounded = timeout_milliseconds > static_cast<std::uint32_t>(std::numeric_limits<int>::max()) ?
                           std::numeric_limits<int>::max() : static_cast<int>(timeout_milliseconds);
    return WSAPoll(&descriptor, 1, bounded) != 0;
#else
    pollfd descriptor {
      .fd = handle_,
      .events = POLLIN,
    };
    const auto bounded = timeout_milliseconds > static_cast<std::uint32_t>(std::numeric_limits<int>::max()) ?
                           std::numeric_limits<int>::max() : static_cast<int>(timeout_milliseconds);
    return poll(&descriptor, 1, bounded) != 0;
#endif
  }

  ReceiveBatchResult NativeUdpSocket::receive_batch(
    const std::size_t maximum_datagrams,
    const std::function<void(const ReceivedDatagram &)> &callback
  ) noexcept {
    if (!open()) {
      return ReceiveBatchResult::closed;
    }
    if (maximum_datagrams == 0 || !callback) {
      return ReceiveBatchResult::fatal;
    }

    std::array<std::uint8_t, maximum_runtime_datagram_size> storage {};
    std::size_t received = 0;
    while (received < maximum_datagrams) {
      sockaddr_storage remote {};
      SocketLength remote_size = sizeof(remote);
#ifdef _WIN32
      const auto size = recvfrom(
        static_cast<SOCKET>(handle_),
        reinterpret_cast<char *>(storage.data()),
        static_cast<int>(storage.size()),
        0,
        reinterpret_cast<sockaddr *>(&remote),
        &remote_size
      );
      if (size == SOCKET_ERROR) {
#else
      const auto size = recvfrom(
        handle_,
        storage.data(),
        storage.size(),
        0,
        reinterpret_cast<sockaddr *>(&remote),
        &remote_size
      );
      if (size < 0) {
#endif
        if (would_block_error()) {
          return received == 0 ? ReceiveBatchResult::would_block : ReceiveBatchResult::drained;
        }
        return open() ? ReceiveBatchResult::fatal : ReceiveBatchResult::closed;
      }

      const auto remote_address = numeric_address(remote);
      const auto remote_port = numeric_port(remote);
      if (!remote_address.empty() && remote_port != 0) {
        callback(ReceivedDatagram {
          .peer = {
            .family = address_family(remote),
            .local_address = address_family(remote) == IpAddressFamily::ipv6 ? "::" : "0.0.0.0",
            .local_port = bound_port_,
            .remote_address = remote_address,
            .remote_port = remote_port,
          },
          .payload = std::span<const std::uint8_t> {storage.data(), static_cast<std::size_t>(size)},
          .received_at_microseconds = monotonic_microseconds(),
        });
      }
      ++received;
    }
    return ReceiveBatchResult::drained;
  }

  bool NativeUdpSocket::send_datagram(
    const PeerEndpoint &peer,
    const std::span<const std::uint8_t> datagram
  ) noexcept {
    return send_datagram_result(peer, datagram) == UdpSendResult::sent;
  }

  UdpSendResult NativeUdpSocket::send_datagram_result(
    const PeerEndpoint &peer,
    const std::span<const std::uint8_t> datagram
  ) noexcept {
    if (!open() || !peer.valid() || peer.local_port != bound_port_ || datagram.empty() ||
        datagram.size() > maximum_runtime_datagram_size) {
      return UdpSendResult::fatal;
    }

    sockaddr_storage remote {};
    SocketLength remote_size = 0;
    if (!encode_destination(peer, remote, remote_size)) {
      return UdpSendResult::fatal;
    }
#ifdef _WIN32
    const auto sent = sendto(
      static_cast<SOCKET>(handle_),
      reinterpret_cast<const char *>(datagram.data()),
      static_cast<int>(datagram.size()),
      0,
      reinterpret_cast<const sockaddr *>(&remote),
      remote_size
    );
    if (sent != SOCKET_ERROR && static_cast<std::size_t>(sent) == datagram.size()) {
      return UdpSendResult::sent;
    }
    const auto error = WSAGetLastError();
    if (error == WSAEMSGSIZE) {
      return UdpSendResult::message_too_large;
    }
    return error == WSAEWOULDBLOCK || error == WSAENOBUFS ? UdpSendResult::would_block : UdpSendResult::fatal;
#else
    const auto sent = sendto(
      handle_,
      datagram.data(),
      datagram.size(),
      0,
      reinterpret_cast<const sockaddr *>(&remote),
      remote_size
    );
    if (sent >= 0 && static_cast<std::size_t>(sent) == datagram.size()) {
      return UdpSendResult::sent;
    }
    if (errno == EMSGSIZE) {
      return UdpSendResult::message_too_large;
    }
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS ?
             UdpSendResult::would_block : UdpSendResult::fatal;
#endif
  }

  std::uint16_t NativeUdpSocket::bound_port() const noexcept {
    return bound_port_;
  }

  bool NativeUdpSocket::open() const noexcept {
    return handle_ != invalid_handle;
  }

  std::uint64_t monotonic_microseconds() noexcept {
    const auto elapsed = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count());
  }
}  // namespace lumen::lsp::runtime
