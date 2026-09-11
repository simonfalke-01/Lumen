/**
 * @file src/protocol_lsp/service.cpp
 * @brief Socket-facing single-port host service abstraction for LSP.
 */

#include "service.h"

namespace lumen::lsp {
  namespace {
    DatagramResult provider_result(const ProviderDatagramResult result) noexcept {
      switch (result) {
        case ProviderDatagramResult::accepted:
          return DatagramResult::accepted;
        case ProviderDatagramResult::dropped:
          return DatagramResult::provider_drop;
        case ProviderDatagramResult::fatal:
          return DatagramResult::provider_fatal;
      }
      return DatagramResult::provider_fatal;
    }
  }  // namespace

  HostService::HostService(
    HostConfig config,
    SinglePortUdpSocket &socket,
    DtlsServerProvider *dtls_provider,
    SrtpProvider *srtp_provider
  ) noexcept:
      config_ {config},
      socket_ {socket},
      dtls_provider_ {dtls_provider},
      srtp_provider_ {srtp_provider} {
  }

  HostService::~HostService() {
    stop();
  }

  ServiceStartResult HostService::start() noexcept {
    if (active_.load(std::memory_order_acquire)) {
      return ServiceStartResult::already_started;
    }
    if (!config_.valid()) {
      return ServiceStartResult::invalid_configuration;
    }
    if (!config_.enabled) {
      return ServiceStartResult::disabled;
    }
    if (dtls_provider_ == nullptr) {
      return ServiceStartResult::missing_dtls_provider;
    }
    if (srtp_provider_ == nullptr) {
      return ServiceStartResult::missing_srtp_provider;
    }
    if (!dtls_provider_->ready(DtlsRequirements {})) {
      return ServiceStartResult::dtls_provider_not_ready;
    }
    if (!srtp_provider_->ready(SrtpRequirements {})) {
      return ServiceStartResult::srtp_provider_not_ready;
    }
    if (!socket_.bind(config_.port)) {
      return ServiceStartResult::socket_bind_failed;
    }
    {
      std::scoped_lock lock(admission_mutex_);
      socket_bound_ = true;
      active_.store(true, std::memory_order_release);
    }
    return ServiceStartResult::started;
  }

  void HostService::stop() noexcept {
    stop_admission();
    {
      std::scoped_lock lock(admission_mutex_);
      if (!socket_bound_) {
        return;
      }
      socket_bound_ = false;
    }
    socket_.close();
  }

  void HostService::stop_admission() noexcept {
    std::unique_lock lock(admission_mutex_);
    active_.store(false, std::memory_order_release);
    admission_condition_.wait(lock, [this]() {
      return in_flight_receives_ == 0;
    });
  }

  DatagramResult HostService::receive(
    const PeerEndpoint &peer,
    const std::span<std::uint8_t> datagram,
    const std::uint64_t received_at_microseconds,
    const IpEcn ecn
  ) noexcept {
    {
      std::scoped_lock lock(admission_mutex_);
      if (!active_.load(std::memory_order_acquire)) {
        return DatagramResult::inactive;
      }
      ++in_flight_receives_;
    }
    auto result = DatagramResult::invalid_drop;
    if (!peer.valid() || peer.local_port != config_.port) {
      result = DatagramResult::malformed_peer;
    } else {
      switch (classify_packet(datagram)) {
        case PacketClass::stun:
        case PacketClass::zrtp:
        case PacketClass::turn_channel:
          result = DatagramResult::reserved_drop;
          break;
        case PacketClass::invalid:
          result = DatagramResult::invalid_drop;
          break;
        case PacketClass::dtls:
          result = provider_result(dtls_provider_->receive_dtls(peer, datagram));
          break;
        case PacketClass::rtp_or_rtcp:
          {
            const auto packet_class = classify_secure_packet(datagram);
            result = packet_class == SecurePacketClass::invalid ?
                       DatagramResult::invalid_drop :
                       provider_result(
                         srtp_provider_->receive_secure_packet(peer, packet_class, datagram, received_at_microseconds, ecn)
                       );
            break;
          }
      }
    }
    {
      std::scoped_lock lock(admission_mutex_);
      --in_flight_receives_;
      if (in_flight_receives_ == 0) {
        admission_condition_.notify_all();
      }
    }
    return result;
  }

  bool HostService::active() const noexcept {
    return active_.load(std::memory_order_acquire);
  }

  const HostConfig &HostService::config() const noexcept {
    return config_;
  }
}  // namespace lumen::lsp
