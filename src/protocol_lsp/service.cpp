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
    if (active_) {
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
    active_ = true;
    return ServiceStartResult::started;
  }

  void HostService::stop() noexcept {
    if (!active_) {
      return;
    }
    active_ = false;
    socket_.close();
  }

  DatagramResult HostService::receive(
    const PeerEndpoint &peer,
    const std::span<std::uint8_t> datagram
  ) noexcept {
    if (!active_) {
      return DatagramResult::inactive;
    }
    if (!peer.valid() || peer.local_port != config_.port) {
      return DatagramResult::malformed_peer;
    }

    switch (classify_packet(datagram)) {
      case PacketClass::stun:
      case PacketClass::zrtp:
      case PacketClass::turn_channel:
        return DatagramResult::reserved_drop;
      case PacketClass::invalid:
        return DatagramResult::invalid_drop;
      case PacketClass::dtls:
        return provider_result(dtls_provider_->receive_dtls(peer, datagram));
      case PacketClass::rtp_or_rtcp: {
        const auto packet_class = classify_secure_packet(datagram);
        if (packet_class == SecurePacketClass::invalid) {
          return DatagramResult::invalid_drop;
        }
        return provider_result(srtp_provider_->receive_secure_packet(peer, packet_class, datagram));
      }
    }
    return DatagramResult::invalid_drop;
  }

  bool HostService::active() const noexcept {
    return active_;
  }

  const HostConfig &HostService::config() const noexcept {
    return config_;
  }
}  // namespace lumen::lsp
