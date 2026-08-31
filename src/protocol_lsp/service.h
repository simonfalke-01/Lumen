/**
 * @file src/protocol_lsp/service.h
 * @brief Socket-facing single-port host service abstraction for LSP.
 */

#pragma once

#include "packet_classifier.h"
#include "security_provider.h"
#include "types.h"

#include <cstdint>
#include <span>

namespace lumen::lsp {
  /**
   * @brief Minimal socket ownership boundary used by the LSP service.
   *
   * Implementations may own separate IPv4 and IPv6 native sockets only when
   * required by the operating system; both must bind the single supplied port.
   */
  class SinglePortUdpSocket {
  public:
    virtual ~SinglePortUdpSocket() = default;

    /**
     * @brief Bind the LSP application listener.
     *
     * @param port One nonzero numeric port used by every application flow.
     * @return True when all required native sockets bind the same port.
     */
    virtual bool bind(std::uint16_t port) noexcept = 0;

    /**
     * @brief Close all native sockets owned by this listener.
     */
    virtual void close() noexcept = 0;
  };

  /**
   * @brief LSP service activation result.
   */
  enum class ServiceStartResult : std::uint8_t {
    started,  ///< Listener bound and both security providers are ready.
    disabled,  ///< Configuration explicitly disables LSP.
    invalid_configuration,  ///< Configuration violates an LSP invariant.
    missing_dtls_provider,  ///< No DTLS provider was injected.
    missing_srtp_provider,  ///< No SRTP provider was injected.
    dtls_provider_not_ready,  ///< DTLS provider cannot enforce the LSP policy.
    srtp_provider_not_ready,  ///< SRTP provider cannot enforce the LSP policy.
    socket_bind_failed,  ///< The single UDP application port could not be bound.
    already_started,  ///< The service is already active.
  };

  /**
   * @brief Disposition of one received UDP datagram.
   */
  enum class DatagramResult : std::uint8_t {
    inactive,  ///< Service is not active and no provider was called.
    malformed_peer,  ///< Source endpoint was incomplete.
    reserved_drop,  ///< LSP/1 reserved packet class was silently dropped.
    invalid_drop,  ///< Invalid or incomplete packet was silently dropped.
    accepted,  ///< Security provider accepted the datagram.
    provider_drop,  ///< Security provider silently rejected the datagram.
    provider_fatal,  ///< Security provider reported a local association failure.
  };

  /**
   * @brief Fail-closed host dispatcher for the single LSP UDP port.
   */
  class HostService {
  public:
    /**
     * @brief Construct an inactive LSP host service.
     *
     * Provider pointers may be null to make an unavailable crypto dependency
     * explicit; in that case start fails before the socket binds.
     *
     * @param config Host configuration.
     * @param socket Socket binding implementation.
     * @param dtls_provider Production DTLS provider, or null.
     * @param srtp_provider Production SRTP provider, or null.
     */
    HostService(
      HostConfig config,
      SinglePortUdpSocket &socket,
      DtlsServerProvider *dtls_provider,
      SrtpProvider *srtp_provider
    ) noexcept;

    HostService(const HostService &) = delete;
    HostService &operator=(const HostService &) = delete;

    /**
     * @brief Close the socket if the service is active.
     */
    ~HostService();

    /**
     * @brief Validate dependencies and bind the single configured UDP port.
     *
     * @return Exact activation result.
     */
    ServiceStartResult start() noexcept;

    /**
     * @brief Stop dispatch and close the listener.
     */
    void stop() noexcept;

    /**
     * @brief Classify and dispatch one complete received UDP datagram.
     *
     * @param peer Source endpoint supplied by the socket layer.
     * @param datagram Complete UDP payload.
     * @return Datagram disposition.
     */
    DatagramResult receive(
      const PeerEndpoint &peer,
      std::span<const std::uint8_t> datagram
    ) noexcept;

    /**
     * @brief Return whether the listener is active.
     *
     * @return True after successful start and before stop.
     */
    [[nodiscard]] bool active() const noexcept;

    /**
     * @brief Return the immutable service configuration.
     *
     * @return Host configuration used by this instance.
     */
    [[nodiscard]] const HostConfig &config() const noexcept;

  private:
    HostConfig config_;
    SinglePortUdpSocket &socket_;
    DtlsServerProvider *dtls_provider_ {};
    SrtpProvider *srtp_provider_ {};
    bool active_ {};
  };
}  // namespace lumen::lsp
