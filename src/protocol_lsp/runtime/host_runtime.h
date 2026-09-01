/**
 * @file src/protocol_lsp/runtime/host_runtime.h
 * @brief Production LSP host runtime factory and lifecycle.
 */

#pragma once

#include "../service.h"
#include "control_server.h"

#include <array>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace lumen::lsp::runtime {
  /**
   * @brief Exact active-listener DNS-SD descriptor independent of platform publication APIs.
   */
  struct DiscoveryDescriptor {
    std::string type;  ///< Exact `_lumen-stream._udp` service type.
    std::uint16_t port {};  ///< Active bound UDP port.
    std::vector<std::pair<std::string, std::string>> txt;  ///< Canonical version, host ID, and capability fields.
  };

  /** @brief Web-safe trusted-client administration record. */
  struct TrustedClientSummary {
    Identifier128 client_id {};  ///< Stable client identifier.
    PermissionSet permissions {};  ///< Current effective permissions.
    std::uint32_t revocation_generation {};  ///< Current trust generation.
    bool enabled {};  ///< Whether new authentication is allowed.
  };

  /** @brief Terminal state of the most recent reconnect or planned-rekey attempt. */
  enum class ReconnectOutcome : std::uint8_t {
    none,  ///< No ATTACH attempt has been observed.
    rejected,  ///< ATTACH failed before authority or token commit.
    committed,  ///< Authority committed and the replacement readiness barrier is pending.
    ready,  ///< Input and every negotiated media lane reached the replacement readiness barrier.
    failed,  ///< A post-commit association or required-lane failure ended the handoff.
  };

  /** @brief Secret-free aggregate ATTACH lifecycle telemetry for administration surfaces. */
  struct ReconnectTelemetrySnapshot {
    std::uint64_t attempts {};  ///< Distinct semantic ATTACH attempts.
    std::uint64_t committed {};  ///< Attempts that atomically rotated authority and the attach token.
    std::uint64_t completed {};  ///< Committed attempts that reached the full readiness barrier.
    std::uint64_t rejected {};  ///< Attempts rejected before commit while prior authority remained unchanged.
    std::uint64_t failed {};  ///< Committed attempts that failed before the full readiness barrier.
    std::uint32_t latest_connection_generation {};  ///< Latest attempted nonzero replacement generation.
    ReconnectOutcome latest_outcome {ReconnectOutcome::none};  ///< Latest terminal or intermediate outcome.
    std::uint64_t latest_request_to_commit_microseconds {};  ///< Latest request-to-authority-commit duration.
    std::uint64_t latest_commit_to_ready_microseconds {};  ///< Latest commit-to-full-readiness duration.
    std::uint64_t latest_total_microseconds {};  ///< Latest request-to-terminal-outcome duration.
  };

  /** @brief Web-safe runtime status without key, PIN, SPAKE, or exporter material. */
  struct RuntimeAdministrationSnapshot {
    bool active {};  ///< Whether the real UDP listener is active.
    NetworkProfile profile {NetworkProfile::adaptive_low_latency};  ///< Configured network profile.
    std::uint16_t port {};  ///< Configured LSP port.
    std::size_t pending_pairings {};  ///< Nonexpired PIN sessions awaiting approval or completion.
    ReconnectTelemetrySnapshot reconnect {};  ///< Secret-free reconnect/rekey timings and outcomes.
  };

  /**
   * @brief Product inputs needed to construct the LSP host runtime.
   */
  struct HostRuntimeConfig {
    HostConfig host;  ///< Validated listener and permission configuration.
    std::filesystem::path identity_file;  ///< Exact LSP-only identity path.
    std::filesystem::path state_file;  ///< Shared state file containing only the `lsp` trust subtree for this runtime.
  };

  /**
   * @brief Runtime construction outcome before any socket bind.
   */
  enum class RuntimeCreateStatus : std::uint8_t {
    ready,  ///< Concrete socket, wolfSSL, libSRTP, identity, and control owners were created.
    provider_unavailable,  ///< Build does not contain both production security providers.
    invalid_configuration,  ///< Required path, hostname, or host configuration is invalid.
    identity_failed,  ///< Fresh LSP identity loading/generation/persistence failed.
    crypto_failed,  ///< wolfCrypt application identity initialization failed.
    srtp_failed,  ///< libSRTP process/provider initialization failed.
    dtls_failed,  ///< wolfSSL exact-policy provider initialization failed.
    control_failed,  ///< Control owner or PIN pairing worker could not be initialized.
    allocation_failed,  ///< A bounded product owner could not be allocated.
  };

  /**
   * @brief Production runtime lifecycle interface returned only by the real provider factory.
   */
  class HostRuntime {
  public:
    virtual ~HostRuntime() = default;

    /**
     * @brief Bind the configured port and start the bounded receive/timer worker.
     *
     * @return Exact host-service activation result.
     */
    virtual ServiceStartResult start() noexcept = 0;

    /** @brief Close the socket, stop the worker, and join it. */
    virtual void stop() noexcept = 0;

    /** @brief Return whether the listener and worker are active. */
    [[nodiscard]] virtual bool active() const noexcept = 0;

    /**
     * @brief Return discovery only while the real listener is active.
     *
     * @return Canonical descriptor or no value while inactive.
     */
    [[nodiscard]] virtual std::optional<DiscoveryDescriptor> discovery() const = 0;

    /** @brief Return the web-safe runtime status and pending PIN-session count. */
    [[nodiscard]] virtual RuntimeAdministrationSnapshot administration_snapshot() const = 0;

    /** @brief Return secret-free pending PIN pairing sessions. */
    [[nodiscard]] virtual std::vector<PendingPairingSummary> pending_pairings() noexcept = 0;

    /**
     * @brief Queue one six-digit PIN for asynchronous SPAKE derivation.
     *
     * @param pairing_session_id Non-secret selected pending session.
     * @param pin_digits Exact six ASCII decimal digits.
     * @return Number of pending sessions admitted to worker processing.
     */
    virtual std::size_t submit_pairing_pin(
      const Identifier128 &pairing_session_id,
      const std::array<std::uint8_t, 6> &pin_digits
    ) noexcept = 0;

    /** @brief Cancel every pending LSP PIN pairing session. */
    virtual void cancel_pairings() noexcept = 0;

    /** @brief Return every persisted LSP trusted client without public keys or secrets. */
    [[nodiscard]] virtual std::vector<TrustedClientSummary> trusted_clients() noexcept = 0;

    /**
     * @brief Replace one trusted client's permissions and advance its revocation generation.
     *
     * @param client_id Stable client identifier.
     * @param permissions New exact permission set.
     * @return True only after persistence; live associations are then disconnected.
     */
    virtual bool update_trusted_client(
      const Identifier128 &client_id,
      PermissionSet permissions,
      bool enabled
    ) noexcept = 0;

    /**
     * @brief Revoke one trusted client and disconnect its live associations.
     *
     * @param client_id Stable client identifier.
     * @return True only after persistent removal.
     */
    virtual bool revoke_trusted_client(const Identifier128 &client_id) noexcept = 0;
  };

  /**
   * @brief Result of the compile-time-gated production runtime factory.
   */
  struct HostRuntimeCreateResult {
    std::unique_ptr<HostRuntime> runtime;  ///< Real runtime only when status is `ready`.
    RuntimeCreateStatus status {RuntimeCreateStatus::provider_unavailable};  ///< Exact factory outcome.
  };

  /**
   * @brief Create the real LSP runtime only when wolfSSL and libSRTP are linked.
   *
   * No unavailable socket or provider object is created in unsupported builds.
   *
   * @param config Complete product runtime configuration.
   * @return Real runtime and ready status, or a null runtime and exact failure.
   */
  [[nodiscard]] HostRuntimeCreateResult create_host_runtime(HostRuntimeConfig config) noexcept;

  /** @brief Return the process runtime's current web-safe administration snapshot. */
  [[nodiscard]] std::optional<RuntimeAdministrationSnapshot> administration_snapshot();

  /** @brief Return the process runtime's persisted trusted clients. */
  [[nodiscard]] std::vector<TrustedClientSummary> administration_trusted_clients();

  /** @brief Return the process runtime's secret-free pending PIN sessions. */
  [[nodiscard]] std::vector<PendingPairingSummary> administration_pending_pairings();

  /** @brief Queue a six-digit PIN for the process runtime's pending sessions. */
  std::size_t administration_submit_pairing_pin(
    const Identifier128 &pairing_session_id,
    const std::array<std::uint8_t, 6> &pin_digits
  );

  /** @brief Cancel every process-runtime pending PIN session. */
  void administration_cancel_pairings();

  /** @brief Update one process-runtime trusted client. */
  bool administration_update_trusted_client(const Identifier128 &client_id, PermissionSet permissions, bool enabled);

  /** @brief Revoke one process-runtime trusted client. */
  bool administration_revoke_trusted_client(const Identifier128 &client_id);

  /**
   * @brief Return compile-time production-provider availability.
   *
   * @return True only when both wolfSSL and libSRTP runtime targets are linked.
   */
  [[nodiscard]] constexpr bool providers_available() noexcept {
#ifndef LUMEN_LSP_RUNTIME_AVAILABLE
    return false;
#else
    return LUMEN_LSP_RUNTIME_AVAILABLE != 0;
#endif
  }
}  // namespace lumen::lsp::runtime
