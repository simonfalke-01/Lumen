/**
 * @file src/protocol_v3/host_identity_store.h
 * @brief Protected protocol-v3 host identity persistence.
 */
#pragma once

#include "control_session.h"

#include <expected>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace lumen::protocol_v3::runtime {
  namespace control = lumen::protocol_v3::control_session;

  enum class HostPrincipal {
    local_system,
    elevated_administrator,
    supported_posix,
    unsupported,
  };

  enum class HostIdentityError : std::uint8_t {
    unsupported_principal,
    io_failure,
    corrupt_blob,
    protection_failure,
    security_failure,
    identity_mismatch,
    injected_interruption,
  };

  enum class HostIdentityStage : std::uint8_t {
    journal_started = 1,
    temporary_written = 2,
    temporary_verified = 3,
    identity_replaced = 4,
    journal_committed = 5,
  };

  struct HostIdentityPaths {
    std::filesystem::path identity;
    std::filesystem::path temporary;
    std::filesystem::path journal;
  };

  struct HostIdentityLoad {
    control::Bytes32 seed {};
    bool retire_legacy_seed {};
  };

  /** @brief Injectable OS protection, ACL, and atomic-file boundary. */
  class HostIdentityPlatform {
  public:
    virtual ~HostIdentityPlatform() = default;
    [[nodiscard]] virtual HostPrincipal principal() const noexcept = 0;
    virtual std::expected<std::vector<std::uint8_t>, HostIdentityError> protect(
      std::span<const std::uint8_t> plaintext
    ) = 0;
    virtual std::expected<std::vector<std::uint8_t>, HostIdentityError> unprotect(
      std::span<const std::uint8_t> protected_bytes
    ) = 0;
    virtual bool write_private(
      const std::filesystem::path &path,
      std::span<const std::uint8_t> bytes
    ) = 0;
    virtual bool read_private(
      const std::filesystem::path &path,
      std::vector<std::uint8_t> &bytes
    ) const = 0;
    [[nodiscard]] virtual bool exists(const std::filesystem::path &path) const = 0;
    [[nodiscard]] virtual bool verify_private(const std::filesystem::path &path) const = 0;
    virtual bool replace_private(
      const std::filesystem::path &source,
      const std::filesystem::path &destination
    ) = 0;
    virtual bool remove_private(const std::filesystem::path &path) = 0;
  };

  std::unique_ptr<HostIdentityPlatform> make_native_host_identity_platform();
  HostIdentityPaths host_identity_paths_for_state_file(const std::filesystem::path &state_file);

  /** @brief Transactional versioned host identity blob and migration journal. */
  class HostIdentityStore {
  public:
    using InterruptionHook = std::function<bool(HostIdentityStage)>;

    HostIdentityStore(
      HostIdentityPaths paths,
      std::unique_ptr<HostIdentityPlatform> platform,
      bool persistent,
      InterruptionHook interruption = {}
    );

    std::expected<HostIdentityLoad, HostIdentityError> load_or_create(
      const std::optional<control::Bytes32> &legacy_seed,
      control::Random &random
    );

    [[nodiscard]] const HostIdentityPaths &paths() const noexcept;

  private:
    HostIdentityPaths paths_;
    std::unique_ptr<HostIdentityPlatform> platform_;
    bool persistent_ {};
    InterruptionHook interruption_;
  };

  /** @brief Apply/verify the native private-file contract for TLS key material. */
  bool secure_private_key_file(const std::filesystem::path &path);
  bool verify_private_key_file(const std::filesystem::path &path);
}  // namespace lumen::protocol_v3::runtime
