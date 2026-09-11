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
  #include <mswsock.h>
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
    struct EcnCapabilities {
      bool ipv4 {};  ///< IPv4 receive/send ancillary ECN support.
      bool ipv6 {};  ///< IPv6 receive/send ancillary ECN support.
    };

    struct PacketInfoCapabilities {
      bool ipv4 {};  ///< IPv4 local-destination/interface ancillary support.
      bool ipv6 {};  ///< IPv6 local-destination/interface ancillary support.
    };

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

    EcnCapabilities configure_ecn(
      const SOCKET socket,
      std::uintptr_t &receive_message,
      std::uintptr_t &send_message
    ) noexcept {
      const DWORD enabled = 1;
      EcnCapabilities capabilities {
        .ipv4 = setsockopt(socket, IPPROTO_IP, IP_RECVTOS, reinterpret_cast<const char *>(&enabled), sizeof(enabled)) == 0,
        .ipv6 = setsockopt(socket, IPPROTO_IPV6, IPV6_RECVTCLASS, reinterpret_cast<const char *>(&enabled), sizeof(enabled)) == 0,
      };
      LPFN_WSARECVMSG receive_function = nullptr;
      LPFN_WSASENDMSG send_function = nullptr;
      DWORD bytes = 0;
      GUID receive_guid = WSAID_WSARECVMSG;
      GUID send_guid = WSAID_WSASENDMSG;
      if (WSAIoctl(
            socket,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &receive_guid,
            sizeof(receive_guid),
            &receive_function,
            sizeof(receive_function),
            &bytes,
            nullptr,
            nullptr
          ) != 0 ||
          WSAIoctl(
            socket,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &send_guid,
            sizeof(send_guid),
            &send_function,
            sizeof(send_function),
            &bytes,
            nullptr,
            nullptr
          ) != 0 ||
          receive_function == nullptr || send_function == nullptr) {
        return {};
      }
      receive_message = reinterpret_cast<std::uintptr_t>(receive_function);
      send_message = reinterpret_cast<std::uintptr_t>(send_function);
      return capabilities;
    }

    PacketInfoCapabilities configure_packet_info(const SOCKET socket) noexcept {
      const DWORD enabled = 1;
      return {
        .ipv4 = setsockopt(socket, IPPROTO_IP, IP_PKTINFO, reinterpret_cast<const char *>(&enabled), sizeof(enabled)) == 0,
        .ipv6 = setsockopt(socket, IPPROTO_IPV6, IPV6_PKTINFO, reinterpret_cast<const char *>(&enabled), sizeof(enabled)) == 0,
      };
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
  #elif defined(__APPLE__) && defined(IPV6_DONTFRAG)
      const int enabled = 1;
      return setsockopt(socket, IPPROTO_IPV6, IPV6_DONTFRAG, &enabled, sizeof(enabled)) == 0;
  #else
      (void) socket;
      return false;
  #endif
    }

  #if defined(__APPLE__)
    bool configure_ipv4_no_fragment(const int socket) noexcept {
    #if defined(IP_DONTFRAG)
      const int enabled = 1;
      return setsockopt(socket, IPPROTO_IP, IP_DONTFRAG, &enabled, sizeof(enabled)) == 0;
    #else
      (void) socket;
      return false;
    #endif
    }
  #endif

    EcnCapabilities configure_ecn(
      const int socket,
      std::uintptr_t &receive_message,
      std::uintptr_t &send_message
    ) noexcept {
      receive_message = 0;
      send_message = 0;
  #if defined(IP_RECVTOS) && defined(IPV6_RECVTCLASS)
      const int enabled = 1;
      return {
        .ipv4 = setsockopt(socket, IPPROTO_IP, IP_RECVTOS, &enabled, sizeof(enabled)) == 0,
        .ipv6 = setsockopt(socket, IPPROTO_IPV6, IPV6_RECVTCLASS, &enabled, sizeof(enabled)) == 0,
      };
  #else
      (void) socket;
      return {};
  #endif
    }

    PacketInfoCapabilities configure_packet_info(const int socket) noexcept {
      const int enabled = 1;
      PacketInfoCapabilities result;
  #if defined(IP_PKTINFO)
      result.ipv4 = setsockopt(socket, IPPROTO_IP, IP_PKTINFO, &enabled, sizeof(enabled)) == 0;
  #elif defined(IP_RECVDSTADDR)
      result.ipv4 = setsockopt(socket, IPPROTO_IP, IP_RECVDSTADDR, &enabled, sizeof(enabled)) == 0;
  #endif
  #if defined(IPV6_RECVPKTINFO)
      result.ipv6 = setsockopt(socket, IPPROTO_IPV6, IPV6_RECVPKTINFO, &enabled, sizeof(enabled)) == 0;
  #elif defined(IPV6_PKTINFO)
      result.ipv6 = setsockopt(socket, IPPROTO_IPV6, IPV6_PKTINFO, &enabled, sizeof(enabled)) == 0;
  #endif
      return result;
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
                 std::string {text.data()} :
                 std::string {};
      }
      if (storage.ss_family == AF_INET6) {
        const auto &address = reinterpret_cast<const sockaddr_in6 &>(storage);
        if (IN6_IS_ADDR_V4MAPPED(&address.sin6_addr)) {
          in_addr mapped {};
          std::memcpy(&mapped, &address.sin6_addr.s6_addr[12], sizeof(mapped));
          return inet_ntop(AF_INET, &mapped, text.data(), static_cast<SocketLength>(text.size())) != nullptr ?
                   std::string {text.data()} :
                   std::string {};
        }
        return inet_ntop(AF_INET6, &address.sin6_addr, text.data(), static_cast<SocketLength>(text.size())) != nullptr ?
                 std::string {text.data()} :
                 std::string {};
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

    CanonicalPeerAddress canonical_address(const sockaddr_storage &storage) noexcept {
      CanonicalPeerAddress result;
      if (storage.ss_family == AF_INET) {
        const auto &address = reinterpret_cast<const sockaddr_in &>(storage);
        std::memcpy(result.address.data(), &address.sin_addr, sizeof(address.sin_addr));
        result.valid = true;
      } else if (storage.ss_family == AF_INET6) {
        const auto &address = reinterpret_cast<const sockaddr_in6 &>(storage);
        if (IN6_IS_ADDR_V4MAPPED(&address.sin6_addr)) {
          std::memcpy(result.address.data(), &address.sin6_addr.s6_addr[12], sizeof(in_addr));
        } else {
          std::memcpy(result.address.data(), &address.sin6_addr, sizeof(address.sin6_addr));
          result.scope_id = address.sin6_scope_id;
        }
        result.valid = true;
      }
      return result;
    }

    std::string numeric_address(
      const CanonicalPeerAddress &canonical,
      const IpAddressFamily family
    ) {
      if (!canonical.valid) {
        return {};
      }
      std::array<char, INET6_ADDRSTRLEN> text {};
      const auto native_family = family == IpAddressFamily::ipv4 ? AF_INET : AF_INET6;
      return inet_ntop(
               native_family,
               canonical.address.data(),
               text.data(),
               static_cast<SocketLength>(text.size())
             ) != nullptr ?
               std::string {text.data()} :
               std::string {};
    }

    bool encode_destination(
      const PeerEndpoint &peer,
      sockaddr_storage &storage,
      SocketLength &size,
      const bool separate_ipv4
    ) noexcept {
      std::memset(&storage, 0, sizeof(storage));
      if (peer.family == IpAddressFamily::ipv4) {
        in_addr mapped {};
        if (peer.canonical_remote.valid) {
          std::memcpy(&mapped, peer.canonical_remote.address.data(), sizeof(mapped));
        } else if (inet_pton(AF_INET, peer.remote_address.c_str(), &mapped) != 1) {
          return false;
        }
        if (separate_ipv4) {
          auto &address = reinterpret_cast<sockaddr_in &>(storage);
          address.sin_family = AF_INET;
          address.sin_port = htons(peer.remote_port);
          address.sin_addr = mapped;
          size = sizeof(address);
        } else {
          auto &address = reinterpret_cast<sockaddr_in6 &>(storage);
          address.sin6_family = AF_INET6;
          address.sin6_port = htons(peer.remote_port);
          address.sin6_addr.s6_addr[10] = 0xff;
          address.sin6_addr.s6_addr[11] = 0xff;
          std::memcpy(&address.sin6_addr.s6_addr[12], &mapped, sizeof(mapped));
          size = sizeof(address);
        }
        return true;
      }
      if (peer.family == IpAddressFamily::ipv6) {
        auto &address = reinterpret_cast<sockaddr_in6 &>(storage);
        address.sin6_family = AF_INET6;
        address.sin6_port = htons(peer.remote_port);
        size = sizeof(address);
        if (peer.canonical_remote.valid) {
          std::memcpy(&address.sin6_addr, peer.canonical_remote.address.data(), sizeof(address.sin6_addr));
          address.sin6_scope_id = peer.canonical_remote.scope_id;
          return true;
        }
        return inet_pton(AF_INET6, peer.remote_address.c_str(), &address.sin6_addr) == 1;
      }
      return false;
    }
  }  // namespace

  NativeUdpSocket::NativeUdpSocket() noexcept = default;

  NativeUdpSocket::OperationLease::OperationLease(NativeUdpSocket &owner) noexcept {
    if (owner.acquire_operation(handle_, ipv4_handle_)) {
      owner_ = &owner;
    }
  }

  NativeUdpSocket::OperationLease::~OperationLease() {
    if (owner_ != nullptr) {
      owner_->release_operation();
    }
  }

  NativeUdpSocket::OperationLease::operator bool() const noexcept {
    return owner_ != nullptr;
  }

  NativeUdpSocket::NativeHandle NativeUdpSocket::OperationLease::handle() const noexcept {
    return handle_;
  }

  NativeUdpSocket::NativeHandle NativeUdpSocket::OperationLease::ipv4_handle() const noexcept {
    return ipv4_handle_;
  }

  bool NativeUdpSocket::acquire_operation(NativeHandle &handle, NativeHandle &ipv4_handle) noexcept {
    std::scoped_lock lock(lifecycle_mutex_);
    if (closing_ || handle_ == invalid_handle) {
      return false;
    }
    handle = handle_;
    ipv4_handle = ipv4_handle_;
    ++active_operations_;
    return true;
  }

  void NativeUdpSocket::release_operation() noexcept {
    std::scoped_lock lock(lifecycle_mutex_);
    if (active_operations_ != 0) {
      --active_operations_;
      if (active_operations_ == 0) {
        lifecycle_condition_.notify_all();
      }
    }
  }

  IpEcn NativeUdpSocket::select_send_ecn(
    const PeerEndpoint &peer,
    const std::span<const std::uint8_t> datagram,
    const std::uint64_t now_microseconds,
    std::uint32_t &ssrc,
    std::uint16_t &sequence
  ) noexcept {
    ssrc = 0;
    sequence = 0;
    const auto family_capable = peer.family == IpAddressFamily::ipv4 ?
                                  ipv4_ecn_available_.load(std::memory_order_acquire) :
                                  ipv6_ecn_available_.load(std::memory_order_acquire);
    if (!family_capable || classify_secure_packet(datagram) != SecurePacketClass::rtp || datagram.size() < 12U) {
      return IpEcn::not_ect;
    }
    sequence = static_cast<std::uint16_t>((static_cast<std::uint16_t>(datagram[2]) << 8U) | datagram[3]);
    ssrc = (static_cast<std::uint32_t>(datagram[8]) << 24U) |
           (static_cast<std::uint32_t>(datagram[9]) << 16U) |
           (static_cast<std::uint32_t>(datagram[10]) << 8U) |
           datagram[11];
    if (ssrc == 0) {
      return IpEcn::not_ect;
    }

    std::scoped_lock lock(ecn_mutex_);
    const auto count = peer_count_.load(std::memory_order_acquire);
    for (std::size_t index = 0; index < count; ++index) {
      if (peers_[index] != peer) {
        continue;
      }
      auto &state = peer_ecn_[index];
      if (state.validated &&
          (now_microseconds < state.last_feedback_microseconds ||
           now_microseconds - state.last_feedback_microseconds > 3'000'000U)) {
        state.validated = false;
        state.proof_count = 0;
        ecn_fallbacks_.fetch_add(1, std::memory_order_relaxed);
      }
      if (state.validated) {
        return IpEcn::ect_0;
      }
      const auto probe_hash = static_cast<std::uint32_t>(ssrc ^ (static_cast<std::uint32_t>(sequence) * 0x9e37U));
      return (probe_hash & 0x3fU) == 0 ? IpEcn::ect_0 : IpEcn::not_ect;
    }
    return IpEcn::not_ect;
  }

  std::size_t NativeUdpSocket::sent_ecn_bucket(
    const std::uint32_t ssrc,
    const std::uint16_t sequence
  ) noexcept {
    auto mixed = ssrc ^ (static_cast<std::uint32_t>(sequence) * 0x9e37'79b9U);
    mixed ^= mixed >> 16U;
    return static_cast<std::size_t>(mixed) & (ecn_index_bucket_count - 1U);
  }

  void NativeUdpSocket::erase_sent_ecn_index(PeerEcnState &state, const std::size_t slot) noexcept {
    if (slot >= state.sent.size()) {
      return;
    }
    const auto &record = state.sent[slot];
    if (record.ssrc == 0 || record.sent_microseconds == 0) {
      return;
    }
    const auto base = sent_ecn_bucket(record.ssrc, record.sequence) * ecn_index_ways;
    for (std::size_t way = 0; way < ecn_index_ways; ++way) {
      auto &entry = state.index[base + way];
      if (entry.slot_plus_one == slot + 1U) {
        entry = {};
        return;
      }
    }
  }

  void NativeUdpSocket::insert_sent_ecn_index(PeerEcnState &state, const std::size_t slot) noexcept {
    if (slot >= state.sent.size()) {
      return;
    }
    const auto &record = state.sent[slot];
    const auto base = sent_ecn_bucket(record.ssrc, record.sequence) * ecn_index_ways;
    auto replacement = base;
    auto oldest = std::numeric_limits<std::uint64_t>::max();
    for (std::size_t way = 0; way < ecn_index_ways; ++way) {
      const auto index = base + way;
      const auto &entry = state.index[index];
      if (entry.slot_plus_one == 0 || entry.slot_plus_one > state.sent.size()) {
        replacement = index;
        oldest = 0;
        break;
      }
      const auto &indexed = state.sent[entry.slot_plus_one - 1U];
      if (indexed.sent_microseconds == 0 ||
          sent_ecn_bucket(indexed.ssrc, indexed.sequence) !=
            sent_ecn_bucket(record.ssrc, record.sequence)) {
        replacement = index;
        oldest = 0;
        break;
      }
      if (indexed.sent_microseconds < oldest) {
        oldest = indexed.sent_microseconds;
        replacement = index;
      }
    }
    state.index[replacement] = {
      .slot_plus_one = static_cast<std::uint16_t>(slot + 1U),
    };
  }

  NativeUdpSocket::SentEcnRecord *NativeUdpSocket::find_sent_ecn_record(
    PeerEcnState &state,
    const std::uint32_t ssrc,
    const std::uint16_t sequence
  ) noexcept {
    const auto base = sent_ecn_bucket(ssrc, sequence) * ecn_index_ways;
    for (std::size_t way = 0; way < ecn_index_ways; ++way) {
      const auto &entry = state.index[base + way];
      if (entry.slot_plus_one == 0 || entry.slot_plus_one > state.sent.size()) {
        continue;
      }
      auto &record = state.sent[entry.slot_plus_one - 1U];
      if (record.ssrc == ssrc && record.sequence == sequence && record.sent_microseconds != 0) {
        return &record;
      }
    }
    return nullptr;
  }

  void NativeUdpSocket::record_sent_ecn(
    const PeerEndpoint &peer,
    const std::uint32_t ssrc,
    const std::uint16_t sequence,
    const IpEcn mark,
    const std::uint64_t sent_microseconds
  ) noexcept {
    if (ssrc == 0) {
      return;
    }
    std::scoped_lock lock(ecn_mutex_);
    const auto count = peer_count_.load(std::memory_order_acquire);
    for (std::size_t index = 0; index < count; ++index) {
      if (peers_[index] == peer) {
        auto &state = peer_ecn_[index];
        const auto slot = state.next_sent++ % state.sent.size();
        erase_sent_ecn_index(state, slot);
        state.sent[slot] = {
          .ssrc = ssrc,
          .sequence = sequence,
          .mark = mark,
          .sent_microseconds = sent_microseconds,
        };
        insert_sent_ecn_index(state, slot);
        return;
      }
    }
  }

  void NativeUdpSocket::disable_ecn_family(const IpAddressFamily family) noexcept {
    const auto changed = family == IpAddressFamily::ipv4 ?
                           ipv4_ecn_available_.exchange(false, std::memory_order_acq_rel) :
                           ipv6_ecn_available_.exchange(false, std::memory_order_acq_rel);
    if (!changed) {
      return;
    }
    ecn_fallbacks_.fetch_add(1, std::memory_order_relaxed);
    std::scoped_lock lock(ecn_mutex_);
    const auto count = peer_count_.load(std::memory_order_acquire);
    for (std::size_t index = 0; index < count; ++index) {
      if (peers_[index].family == family) {
        peer_ecn_[index].validated = false;
        peer_ecn_[index].proof_count = 0;
      }
    }
  }

  NativeUdpSocket::~NativeUdpSocket() {
    close();
  }

  bool NativeUdpSocket::bind(const std::uint16_t port) noexcept {
    std::scoped_lock lifecycle_lock(lifecycle_mutex_);
    if (closing_ || handle_ != invalid_handle || !initialize_winsock()) {
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

#ifdef __APPLE__
    int dual_stack = 1;
#else
    int dual_stack = 0;
#endif
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

#ifdef __APPLE__
    const auto ipv4_native = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ipv4_native < 0 || !configure_ipv4_no_fragment(ipv4_native) || !set_nonblocking(ipv4_native)) {
      if (ipv4_native >= 0) {
        close_socket(ipv4_native);
      }
      close_socket(native);
      return false;
    }
    sockaddr_in ipv4_address {};
    ipv4_address.sin_family = AF_INET;
    ipv4_address.sin_addr.s_addr = htonl(INADDR_ANY);
    ipv4_address.sin_port = actual.sin6_port;
    if (::bind(ipv4_native, reinterpret_cast<const sockaddr *>(&ipv4_address), sizeof(ipv4_address)) != 0) {
      close_socket(ipv4_native);
      close_socket(native);
      return false;
    }
#endif

    handle_ = static_cast<NativeHandle>(native);
#ifdef __APPLE__
    ipv4_handle_ = ipv4_native;
#endif
    bound_port_ = ntohs(actual.sin6_port);
    peer_count_ = 0;
    next_peer_replacement_ = 0;
    auto ecn = configure_ecn(native, receive_message_, send_message_);
    auto packet_info = configure_packet_info(native);
#ifdef __APPLE__
    std::uintptr_t ipv4_receive_message = 0;
    std::uintptr_t ipv4_send_message = 0;
    const auto ipv4_ecn = configure_ecn(ipv4_native, ipv4_receive_message, ipv4_send_message);
    ecn.ipv4 = ipv4_ecn.ipv4;
    const auto ipv4_packet_info = configure_packet_info(ipv4_native);
    packet_info.ipv4 = ipv4_packet_info.ipv4;
#endif
    ipv4_ecn_available_.store(ecn.ipv4, std::memory_order_release);
    ipv6_ecn_available_.store(ecn.ipv6, std::memory_order_release);
    ipv4_packet_info_available_.store(packet_info.ipv4, std::memory_order_release);
    ipv6_packet_info_available_.store(packet_info.ipv6, std::memory_order_release);
    return bound_port_ != 0;
  }

  void NativeUdpSocket::close() noexcept {
    std::unique_lock lifecycle_lock(lifecycle_mutex_);
    if (handle_ == invalid_handle) {
      return;
    }
    closing_ = true;
    lifecycle_condition_.wait(lifecycle_lock, [this]() {
      return active_operations_ == 0;
    });
#ifdef _WIN32
    close_socket(static_cast<SOCKET>(handle_));
#else
    close_socket(handle_);
  #ifdef __APPLE__
    if (ipv4_handle_ != invalid_handle) {
      close_socket(ipv4_handle_);
    }
  #endif
#endif
    handle_ = invalid_handle;
    ipv4_handle_ = invalid_handle;
    bound_port_ = 0;
    receive_message_ = 0;
    send_message_ = 0;
    ipv4_ecn_available_.store(false, std::memory_order_release);
    ipv6_ecn_available_.store(false, std::memory_order_release);
    ipv4_packet_info_available_.store(false, std::memory_order_release);
    ipv6_packet_info_available_.store(false, std::memory_order_release);
    {
      std::scoped_lock ecn_lock(ecn_mutex_);
      for (std::size_t index = 0; index < peer_count_; ++index) {
        peers_[index] = {};
      }
      peer_count_ = 0;
      next_peer_replacement_ = 0;
      for (auto &state : peer_ecn_) {
        state = {};
      }
    }
    closing_ = false;
    lifecycle_condition_.notify_all();
  }

  bool NativeUdpSocket::wait_readable(const std::uint32_t timeout_milliseconds) noexcept {
    OperationLease operation {*this};
    if (!operation) {
      return true;
    }
#ifdef _WIN32
    WSAPOLLFD descriptor {
      .fd = static_cast<SOCKET>(operation.handle()),
      .events = POLLRDNORM,
    };
    const auto bounded = timeout_milliseconds > static_cast<std::uint32_t>(std::numeric_limits<int>::max()) ?
                           std::numeric_limits<int>::max() :
                           static_cast<int>(timeout_milliseconds);
    return WSAPoll(&descriptor, 1, bounded) != 0;
#else
    const auto bounded = timeout_milliseconds > static_cast<std::uint32_t>(std::numeric_limits<int>::max()) ?
                           std::numeric_limits<int>::max() :
                           static_cast<int>(timeout_milliseconds);
  #ifdef __APPLE__
    std::array<pollfd, 2> descriptors {{
      {.fd = operation.handle(), .events = POLLIN},
      {.fd = operation.ipv4_handle(), .events = POLLIN},
    }};
    return poll(descriptors.data(), descriptors.size(), bounded) != 0;
  #else
    pollfd descriptor {
      .fd = operation.handle(),
      .events = POLLIN,
    };
    return poll(&descriptor, 1, bounded) != 0;
  #endif
#endif
  }

  ReceiveBatchResult NativeUdpSocket::receive_batch(
    const std::size_t maximum_datagrams,
    const std::function<void(const ReceivedDatagram &)> &callback
  ) noexcept {
    OperationLease operation {*this};
    if (!operation) {
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
      auto received_ecn = DatagramEcn::unavailable;
      CanonicalPeerAddress received_local;
      std::uint32_t received_interface = 0;
#ifdef _WIN32
      int size = SOCKET_ERROR;
      if ((ipv4_ecn_available_.load(std::memory_order_acquire) ||
           ipv6_ecn_available_.load(std::memory_order_acquire) ||
           ipv4_packet_info_available_.load(std::memory_order_acquire) ||
           ipv6_packet_info_available_.load(std::memory_order_acquire)) &&
          receive_message_ != 0) {
        WSABUF buffer {
          .len = static_cast<ULONG>(storage.size()),
          .buf = reinterpret_cast<char *>(storage.data()),
        };
        alignas(WSACMSGHDR) std::array<char, 256> control {};
        WSAMSG message {
          .name = reinterpret_cast<sockaddr *>(&remote),
          .namelen = remote_size,
          .lpBuffers = &buffer,
          .dwBufferCount = 1,
          .Control = {.len = static_cast<ULONG>(control.size()), .buf = control.data()},
        };
        DWORD bytes = 0;
        const auto receive_function = reinterpret_cast<LPFN_WSARECVMSG>(receive_message_);
        if (receive_function(static_cast<SOCKET>(operation.handle()), &message, &bytes, nullptr, nullptr) == 0) {
          size = static_cast<int>(bytes);
          remote_size = message.namelen;
          for (auto *header = WSA_CMSG_FIRSTHDR(&message); header != nullptr; header = WSA_CMSG_NXTHDR(&message, header)) {
            if ((header->cmsg_level == IPPROTO_IP && header->cmsg_type == IP_TOS) ||
                (header->cmsg_level == IPPROTO_IPV6 && header->cmsg_type == IPV6_TCLASS)) {
              received_ecn = static_cast<DatagramEcn>(*reinterpret_cast<const DWORD *>(WSA_CMSG_DATA(header)) & 0x03U);
            } else if (header->cmsg_level == IPPROTO_IP && header->cmsg_type == IP_PKTINFO) {
              const auto &info = *reinterpret_cast<const IN_PKTINFO *>(WSA_CMSG_DATA(header));
              std::memcpy(received_local.address.data(), &info.ipi_addr, sizeof(info.ipi_addr));
              received_local.valid = true;
              received_interface = info.ipi_ifindex;
            } else if (header->cmsg_level == IPPROTO_IPV6 && header->cmsg_type == IPV6_PKTINFO) {
              const auto &info = *reinterpret_cast<const IN6_PKTINFO *>(WSA_CMSG_DATA(header));
              if (IN6_IS_ADDR_V4MAPPED(&info.ipi6_addr)) {
                std::memcpy(received_local.address.data(), &info.ipi6_addr.u.Byte[12], sizeof(in_addr));
              } else {
                std::memcpy(received_local.address.data(), &info.ipi6_addr, sizeof(info.ipi6_addr));
              }
              received_local.scope_id = info.ipi6_ifindex;
              received_local.valid = true;
              received_interface = info.ipi6_ifindex;
            }
          }
        }
      } else {
        size = recvfrom(
          static_cast<SOCKET>(operation.handle()),
          reinterpret_cast<char *>(storage.data()),
          static_cast<int>(storage.size()),
          0,
          reinterpret_cast<sockaddr *>(&remote),
          &remote_size
        );
      }
      if (size == SOCKET_ERROR) {
#else
      const auto receive_from = [&](const NativeHandle receive_handle, const bool ancillary) {
        remote = {};
        remote_size = sizeof(remote);
        received_ecn = DatagramEcn::unavailable;
        received_local = {};
        received_interface = 0;
        if (!ancillary) {
          return recvfrom(
            receive_handle,
            storage.data(),
            storage.size(),
            0,
            reinterpret_cast<sockaddr *>(&remote),
            &remote_size
          );
        }
        iovec buffer {.iov_base = storage.data(), .iov_len = storage.size()};
        alignas(cmsghdr) std::array<std::uint8_t, 256> control {};
        msghdr message {
          .msg_name = &remote,
          .msg_namelen = remote_size,
          .msg_iov = &buffer,
          .msg_iovlen = 1,
          .msg_control = control.data(),
          .msg_controllen = control.size(),
        };
        const auto result = recvmsg(receive_handle, &message, 0);
        remote_size = message.msg_namelen;
        if (result >= 0) {
          for (auto *header = CMSG_FIRSTHDR(&message); header != nullptr; header = CMSG_NXTHDR(&message, header)) {
            if ((header->cmsg_level == IPPROTO_IP && header->cmsg_type == IP_TOS) ||
                (header->cmsg_level == IPPROTO_IPV6 && header->cmsg_type == IPV6_TCLASS)) {
              received_ecn = static_cast<DatagramEcn>(*reinterpret_cast<const int *>(CMSG_DATA(header)) & 0x03U);
  #if defined(IP_PKTINFO)
            } else if (header->cmsg_level == IPPROTO_IP && header->cmsg_type == IP_PKTINFO) {
              const auto &info = *reinterpret_cast<const in_pktinfo *>(CMSG_DATA(header));
              std::memcpy(received_local.address.data(), &info.ipi_addr, sizeof(info.ipi_addr));
              received_local.valid = true;
              received_interface = static_cast<std::uint32_t>(info.ipi_ifindex);
  #elif defined(IP_RECVDSTADDR)
            } else if (header->cmsg_level == IPPROTO_IP && header->cmsg_type == IP_RECVDSTADDR) {
              const auto &address = *reinterpret_cast<const in_addr *>(CMSG_DATA(header));
              std::memcpy(received_local.address.data(), &address, sizeof(address));
              received_local.valid = true;
  #endif
            } else if (header->cmsg_level == IPPROTO_IPV6 && header->cmsg_type == IPV6_PKTINFO) {
              const auto &info = *reinterpret_cast<const in6_pktinfo *>(CMSG_DATA(header));
              if (IN6_IS_ADDR_V4MAPPED(&info.ipi6_addr)) {
                std::memcpy(received_local.address.data(), &info.ipi6_addr.s6_addr[12], sizeof(in_addr));
              } else {
                std::memcpy(received_local.address.data(), &info.ipi6_addr, sizeof(info.ipi6_addr));
              }
              received_local.scope_id = info.ipi6_ifindex;
              received_local.valid = true;
              received_interface = info.ipi6_ifindex;
            }
          }
        }
        return result;
      };
      auto size = receive_from(
        operation.handle(),
        ipv6_ecn_available_.load(std::memory_order_acquire) ||
          ipv6_packet_info_available_.load(std::memory_order_acquire)
      );
  #ifdef __APPLE__
      if (size < 0 && would_block_error() && operation.ipv4_handle() != invalid_handle) {
        size = receive_from(
          operation.ipv4_handle(),
          ipv4_ecn_available_.load(std::memory_order_acquire) ||
            ipv4_packet_info_available_.load(std::memory_order_acquire)
        );
      }
  #endif
      if (size < 0) {
#endif
        if (would_block_error()) {
          return received == 0 ? ReceiveBatchResult::would_block : ReceiveBatchResult::drained;
        }
        return ReceiveBatchResult::fatal;
      }

      const auto family = address_family(remote);
      if ((family == IpAddressFamily::ipv4 && !ipv4_ecn_available_.load(std::memory_order_acquire)) ||
          (family == IpAddressFamily::ipv6 && !ipv6_ecn_available_.load(std::memory_order_acquire))) {
        received_ecn = DatagramEcn::unavailable;
      }
      const auto remote_port = numeric_port(remote);
      const auto canonical = canonical_address(remote);
      const PeerEndpoint *peer = nullptr;
      {
        std::scoped_lock ecn_lock(ecn_mutex_);
        for (std::size_t index = 0; index < peer_count_; ++index) {
          const auto &candidate = peers_[index];
          if (candidate.family == family && candidate.remote_port == remote_port &&
              candidate.canonical_remote == canonical && candidate.canonical_local == received_local &&
              candidate.interface_index == received_interface) {
            peer = &candidate;
            break;
          }
        }
        if (peer == nullptr && canonical.valid && remote_port != 0) {
          const auto remote_address = numeric_address(remote);
          const auto local_address = numeric_address(received_local, family);
          if (!remote_address.empty() && !local_address.empty()) {
            const auto slot = peer_count_ < peers_.size() ? peer_count_++ : next_peer_replacement_++ % peers_.size();
            auto &inserted = peers_[slot];
            inserted = {
              .family = family,
              .local_address = local_address,
              .local_port = bound_port_,
              .canonical_local = received_local,
              .interface_index = received_interface,
              .remote_address = remote_address,
              .remote_port = remote_port,
              .canonical_remote = canonical,
            };
            peer_ecn_[slot] = {};
            peer = &inserted;
          }
        }
      }
      if (peer != nullptr) {
        switch (received_ecn) {
          case DatagramEcn::ect_0:
            received_ect0_.fetch_add(1, std::memory_order_relaxed);
            break;
          case DatagramEcn::ect_1:
            received_ect1_.fetch_add(1, std::memory_order_relaxed);
            break;
          case DatagramEcn::congestion_experienced:
            received_ce_.fetch_add(1, std::memory_order_relaxed);
            break;
          case DatagramEcn::not_ect:
          case DatagramEcn::unavailable:
            break;
        }
        callback(ReceivedDatagram {
          .peer = *peer,
          .payload = std::span<std::uint8_t> {storage.data(), static_cast<std::size_t>(size)},
          .received_at_microseconds = monotonic_microseconds(),
          .ecn = received_ecn,
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
    OperationLease operation {*this};
    if (!operation || !peer.valid() || peer.local_port != bound_port_ || datagram.empty() ||
        datagram.size() > maximum_runtime_datagram_size) {
      return UdpSendResult::fatal;
    }

    sockaddr_storage remote {};
    SocketLength remote_size = 0;
#ifdef __APPLE__
    const auto separate_ipv4 = peer.family == IpAddressFamily::ipv4;
    const auto native_send_handle = separate_ipv4 ? operation.ipv4_handle() : operation.handle();
#else
    constexpr bool separate_ipv4 = false;
    const auto native_send_handle = operation.handle();
#endif
    if (native_send_handle == invalid_handle || !encode_destination(peer, remote, remote_size, separate_ipv4)) {
      return UdpSendResult::fatal;
    }
    const auto now = monotonic_microseconds();
    std::uint32_t rtp_ssrc = 0;
    std::uint16_t rtp_sequence = 0;
    auto actual_mark = select_send_ecn(peer, datagram, now, rtp_ssrc, rtp_sequence);
#ifdef _WIN32
    int sent = SOCKET_ERROR;
    auto error = 0;
    if ((actual_mark == IpEcn::ect_0 || peer.canonical_local.valid) && send_message_ != 0) {
      WSABUF buffer {
        .len = static_cast<ULONG>(datagram.size()),
        .buf = reinterpret_cast<char *>(const_cast<std::uint8_t *>(datagram.data())),
      };
      alignas(WSACMSGHDR) std::array<char, 256> control {};
      WSAMSG message {
        .name = reinterpret_cast<sockaddr *>(&remote),
        .namelen = remote_size,
        .lpBuffers = &buffer,
        .dwBufferCount = 1,
        .Control = {.len = 0, .buf = control.data()},
      };
      auto append_control = [&](const int level, const int type, const void *data, const std::size_t size) {
        const auto offset = static_cast<std::size_t>(message.Control.len);
        const auto required = WSA_CMSG_SPACE(static_cast<ULONG>(size));
        if (required > control.size() - offset) {
          return false;
        }
        auto *header = reinterpret_cast<WSACMSGHDR *>(control.data() + offset);
        header->cmsg_level = level;
        header->cmsg_type = type;
        header->cmsg_len = WSA_CMSG_LEN(static_cast<ULONG>(size));
        std::memcpy(WSA_CMSG_DATA(header), data, size);
        message.Control.len += static_cast<ULONG>(required);
        return true;
      };
      bool control_valid = true;
      if (peer.canonical_local.valid && peer.family == IpAddressFamily::ipv4) {
        IN_PKTINFO info {};
        std::memcpy(&info.ipi_addr, peer.canonical_local.address.data(), sizeof(info.ipi_addr));
        info.ipi_ifindex = peer.interface_index;
        control_valid = append_control(IPPROTO_IP, IP_PKTINFO, &info, sizeof(info));
      } else if (peer.canonical_local.valid) {
        IN6_PKTINFO info {};
        std::memcpy(&info.ipi6_addr, peer.canonical_local.address.data(), sizeof(info.ipi6_addr));
        info.ipi6_ifindex = peer.interface_index;
        control_valid = append_control(IPPROTO_IPV6, IPV6_PKTINFO, &info, sizeof(info));
      }
      if (control_valid && actual_mark == IpEcn::ect_0) {
        const DWORD mark = static_cast<DWORD>(IpEcn::ect_0);
        control_valid = append_control(
          peer.family == IpAddressFamily::ipv4 ? IPPROTO_IP : IPPROTO_IPV6,
          peer.family == IpAddressFamily::ipv4 ? IP_TOS : IPV6_TCLASS,
          &mark,
          sizeof(mark)
        );
      }
      DWORD bytes = 0;
      const auto send_function = reinterpret_cast<LPFN_WSASENDMSG>(send_message_);
      if (control_valid && send_function(static_cast<SOCKET>(native_send_handle), &message, 0, &bytes, nullptr, nullptr) == 0) {
        sent = static_cast<int>(bytes);
      } else {
        error = WSAGetLastError();
        if ((error == WSAEINVAL || error == WSAEOPNOTSUPP) && !peer.canonical_local.valid) {
          disable_ecn_family(peer.family);
          actual_mark = IpEcn::not_ect;
          sent = sendto(
            static_cast<SOCKET>(native_send_handle),
            reinterpret_cast<const char *>(datagram.data()),
            static_cast<int>(datagram.size()),
            0,
            reinterpret_cast<const sockaddr *>(&remote),
            remote_size
          );
          if (sent == SOCKET_ERROR) {
            error = WSAGetLastError();
          }
        }
      }
    } else {
      actual_mark = IpEcn::not_ect;
      sent = sendto(
        static_cast<SOCKET>(native_send_handle),
        reinterpret_cast<const char *>(datagram.data()),
        static_cast<int>(datagram.size()),
        0,
        reinterpret_cast<const sockaddr *>(&remote),
        remote_size
      );
      if (sent == SOCKET_ERROR) {
        error = WSAGetLastError();
      }
    }
    if (sent != SOCKET_ERROR && static_cast<std::size_t>(sent) == datagram.size()) {
      if (actual_mark == IpEcn::ect_0) {
        sent_ect0_.fetch_add(1, std::memory_order_relaxed);
      }
      record_sent_ecn(peer, rtp_ssrc, rtp_sequence, actual_mark, now);
      return UdpSendResult::sent;
    }
    if (error == WSAEMSGSIZE) {
      reset_peer_ecn_validation(peer);
      return UdpSendResult::message_too_large;
    }
    return error == WSAEWOULDBLOCK || error == WSAENOBUFS ? UdpSendResult::would_block : UdpSendResult::fatal;
#else
    ssize_t sent = -1;
    auto error = 0;
    if (actual_mark == IpEcn::ect_0 || peer.canonical_local.valid) {
      iovec buffer {.iov_base = const_cast<std::uint8_t *>(datagram.data()), .iov_len = datagram.size()};
      alignas(cmsghdr) std::array<std::uint8_t, 256> control {};
      msghdr message {
        .msg_name = &remote,
        .msg_namelen = remote_size,
        .msg_iov = &buffer,
        .msg_iovlen = 1,
        .msg_control = control.data(),
        .msg_controllen = 0,
      };
      auto append_control = [&](const int level, const int type, const void *data, const std::size_t size) {
        const auto offset = message.msg_controllen;
        const auto required = CMSG_SPACE(size);
        if (required > control.size() - offset) {
          return false;
        }
        auto *header = reinterpret_cast<cmsghdr *>(control.data() + offset);
        header->cmsg_level = level;
        header->cmsg_type = type;
        header->cmsg_len = CMSG_LEN(size);
        std::memcpy(CMSG_DATA(header), data, size);
        message.msg_controllen += required;
        return true;
      };
      bool control_valid = true;
      if (peer.canonical_local.valid && peer.family == IpAddressFamily::ipv4) {
  #if defined(IP_PKTINFO)
        in_pktinfo info {};
        std::memcpy(&info.ipi_spec_dst, peer.canonical_local.address.data(), sizeof(info.ipi_spec_dst));
        info.ipi_ifindex = static_cast<int>(peer.interface_index);
        control_valid = append_control(IPPROTO_IP, IP_PKTINFO, &info, sizeof(info));
  #elif defined(IP_SENDSRCADDR)
        in_addr address {};
        std::memcpy(&address, peer.canonical_local.address.data(), sizeof(address));
        control_valid = append_control(IPPROTO_IP, IP_SENDSRCADDR, &address, sizeof(address));
  #endif
      } else if (peer.canonical_local.valid) {
        in6_pktinfo info {};
        std::memcpy(&info.ipi6_addr, peer.canonical_local.address.data(), sizeof(info.ipi6_addr));
        info.ipi6_ifindex = peer.interface_index;
        control_valid = append_control(IPPROTO_IPV6, IPV6_PKTINFO, &info, sizeof(info));
      }
      if (control_valid && actual_mark == IpEcn::ect_0) {
        const int mark = static_cast<int>(IpEcn::ect_0);
        control_valid = append_control(
          peer.family == IpAddressFamily::ipv4 ? IPPROTO_IP : IPPROTO_IPV6,
          peer.family == IpAddressFamily::ipv4 ? IP_TOS : IPV6_TCLASS,
          &mark,
          sizeof(mark)
        );
      }
      sent = control_valid ? sendmsg(native_send_handle, &message, 0) : -1;
      if (sent < 0) {
        error = errno;
      }
      if (sent < 0 && (error == EINVAL || error == ENOPROTOOPT || error == EOPNOTSUPP) &&
          !peer.canonical_local.valid) {
        disable_ecn_family(peer.family);
        actual_mark = IpEcn::not_ect;
        sent = sendto(
          native_send_handle,
          datagram.data(),
          datagram.size(),
          0,
          reinterpret_cast<const sockaddr *>(&remote),
          remote_size
        );
        if (sent < 0) {
          error = errno;
        }
      }
    } else {
      actual_mark = IpEcn::not_ect;
      sent = sendto(
        native_send_handle,
        datagram.data(),
        datagram.size(),
        0,
        reinterpret_cast<const sockaddr *>(&remote),
        remote_size
      );
      if (sent < 0) {
        error = errno;
      }
    }
    if (sent >= 0 && static_cast<std::size_t>(sent) == datagram.size()) {
      if (actual_mark == IpEcn::ect_0) {
        sent_ect0_.fetch_add(1, std::memory_order_relaxed);
      }
      record_sent_ecn(peer, rtp_ssrc, rtp_sequence, actual_mark, now);
      return UdpSendResult::sent;
    }
    if (error == EMSGSIZE) {
      reset_peer_ecn_validation(peer);
      return UdpSendResult::message_too_large;
    }
    return error == EAGAIN || error == EWOULDBLOCK || error == ENOBUFS ?
             UdpSendResult::would_block :
             UdpSendResult::fatal;
#endif
  }

  std::uint16_t NativeUdpSocket::bound_port() const noexcept {
    std::scoped_lock lock(lifecycle_mutex_);
    return bound_port_;
  }

  bool NativeUdpSocket::open() const noexcept {
    std::scoped_lock lock(lifecycle_mutex_);
    return handle_ != invalid_handle;
  }

  bool NativeUdpSocket::ecn_available() const noexcept {
    return ipv4_ecn_available_.load(std::memory_order_relaxed) ||
           ipv6_ecn_available_.load(std::memory_order_relaxed);
  }

  bool NativeUdpSocket::peer_ecn_validated(const PeerEndpoint &peer) const noexcept {
    std::scoped_lock lock(ecn_mutex_);
    const auto count = peer_count_.load(std::memory_order_acquire);
    for (std::size_t index = 0; index < count; ++index) {
      if (peers_[index] == peer) {
        return peer_ecn_[index].validated;
      }
    }
    return false;
  }

  bool NativeUdpSocket::observe_authenticated_ecn_feedback(
    const PeerEndpoint &peer,
    const transport::congestion_feedback_packet_view &feedback,
    const std::uint64_t now_microseconds
  ) noexcept {
    return process_authenticated_ecn_feedback(peer, feedback, now_microseconds, true);
  }

  bool NativeUdpSocket::validate_authenticated_ecn_feedback(
    const PeerEndpoint &peer,
    const transport::congestion_feedback_packet_view &feedback,
    const std::uint64_t now_microseconds
  ) noexcept {
    return process_authenticated_ecn_feedback(peer, feedback, now_microseconds, false);
  }

  std::optional<EcnFeedbackPreview> NativeUdpSocket::preview_authenticated_ecn_feedback(
    const PeerEndpoint &peer,
    const transport::congestion_feedback_packet_view &feedback,
    const std::uint64_t now_microseconds
  ) noexcept {
    return validate_authenticated_ecn_feedback(peer, feedback, now_microseconds) ?
             std::optional<EcnFeedbackPreview> {{peer, feedback, now_microseconds}} :
             std::nullopt;
  }

  bool NativeUdpSocket::commit_authenticated_ecn_feedback(
    const EcnFeedbackPreview &preview
  ) noexcept {
    return observe_authenticated_ecn_feedback(preview.peer, preview.packet, preview.now_microseconds);
  }

  bool NativeUdpSocket::process_authenticated_ecn_feedback(
    const PeerEndpoint &peer,
    const transport::congestion_feedback_packet_view &feedback,
    const std::uint64_t now_microseconds,
    const bool commit
  ) noexcept {
    if (!feedback || !peer.valid()) {
      return false;
    }
    std::scoped_lock lock(ecn_mutex_);
    const auto count = peer_count_.load(std::memory_order_acquire);
    std::size_t peer_index = count;
    for (std::size_t index = 0; index < count; ++index) {
      if (peers_[index] == peer) {
        peer_index = index;
        break;
      }
    }
    if (peer_index == count) {
      return false;
    }

    auto &state = peer_ecn_[peer_index];
    bool matched = false;
    bool contradiction = false;
    bool lost_ect_probe = false;
    for (std::size_t block_index = 0; block_index < feedback.block_count; ++block_index) {
      const auto &block = feedback.blocks[block_index];
      for (std::size_t metric_index = 0; metric_index < block.report_count; ++metric_index) {
        const auto metric = static_cast<std::uint16_t>(
          (static_cast<std::uint16_t>(block.metrics[metric_index * 2U]) << 8U) |
          block.metrics[metric_index * 2U + 1U]
        );
        const auto received = (metric & 0x8000U) != 0;
        const auto sequence = static_cast<std::uint16_t>(block.begin_sequence + metric_index);
        auto *record = find_sent_ecn_record(state, block.media_ssrc, sequence);
        if (record == nullptr || record->sent_microseconds > now_microseconds ||
            now_microseconds - record->sent_microseconds > 5'000'000U) {
          continue;
        }
        matched = true;
        if (!received) {
          lost_ect_probe = lost_ect_probe || record->mark == IpEcn::ect_0;
          continue;
        }
        const auto echoed = static_cast<IpEcn>((metric >> 13U) & 0x03U);
        if ((record->mark == IpEcn::ect_0 && echoed != IpEcn::ect_0 &&
             echoed != IpEcn::congestion_experienced) ||
            (record->mark == IpEcn::not_ect && echoed != IpEcn::not_ect)) {
          contradiction = true;
          continue;
        }
        if (commit && !record->reflected && record->mark == IpEcn::ect_0) {
          record->reflected = true;
          if (state.proof_count != std::numeric_limits<std::uint8_t>::max()) {
            ++state.proof_count;
          }
        }
      }
    }
    if (!commit) {
      return !contradiction;
    }
    if (lost_ect_probe) {
      state.validated = false;
      state.proof_count = 0;
      ++ecn_black_hole_resets_;
    }
    if (contradiction) {
      state.validated = false;
      state.proof_count = 0;
      ecn_fallbacks_.fetch_add(1, std::memory_order_relaxed);
      return false;
    }
    if (matched) {
      state.last_feedback_microseconds = now_microseconds;
      state.validated = !lost_ect_probe && state.proof_count >= 3U;
    }
    return true;
  }

  void NativeUdpSocket::reset_peer_ecn_validation(const PeerEndpoint &peer) noexcept {
    std::scoped_lock lock(ecn_mutex_);
    const auto count = peer_count_.load(std::memory_order_acquire);
    for (std::size_t index = 0; index < count; ++index) {
      if (peers_[index] == peer) {
        if (peer_ecn_[index].validated || peer_ecn_[index].proof_count != 0) {
          ecn_fallbacks_.fetch_add(1, std::memory_order_relaxed);
        }
        peer_ecn_[index] = {};
        return;
      }
    }
  }

  NativeUdpSocketSnapshot NativeUdpSocket::snapshot() const noexcept {
    std::size_t validated_peers = 0;
    {
      std::scoped_lock lock(ecn_mutex_);
      const auto count = peer_count_.load(std::memory_order_acquire);
      for (std::size_t index = 0; index < count; ++index) {
        validated_peers += peer_ecn_[index].validated ? 1U : 0U;
      }
    }
    const auto ipv4 = ipv4_ecn_available_.load(std::memory_order_relaxed);
    const auto ipv6 = ipv6_ecn_available_.load(std::memory_order_relaxed);
    return {
      .received_ect0 = received_ect0_.load(std::memory_order_relaxed),
      .received_ect1 = received_ect1_.load(std::memory_order_relaxed),
      .received_ce = received_ce_.load(std::memory_order_relaxed),
      .sent_ect0 = sent_ect0_.load(std::memory_order_relaxed),
      .ecn_fallbacks = ecn_fallbacks_.load(std::memory_order_relaxed),
      .ecn_black_hole_resets = ecn_black_hole_resets_.load(std::memory_order_relaxed),
      .cached_peers = peer_count_.load(std::memory_order_relaxed),
      .ecn_validated_peers = validated_peers,
      .ipv4_ecn_available = ipv4,
      .ipv6_ecn_available = ipv6,
      .ecn_available = ipv4 || ipv6,
    };
  }

  std::uint64_t monotonic_microseconds() noexcept {
    const auto elapsed = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count());
  }
}  // namespace lumen::lsp::runtime
