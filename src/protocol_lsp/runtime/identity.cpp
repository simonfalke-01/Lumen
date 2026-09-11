/**
 * @file src/protocol_lsp/runtime/identity.cpp
 * @brief Fresh LSP-only host identity generation and atomic persistence.
 */

#include "identity.h"

#include "../core/wire.h"

#ifndef LUMEN_LSP_WOLFSSL_AVAILABLE
  #define LUMEN_LSP_WOLFSSL_AVAILABLE 0
#endif

#if LUMEN_LSP_WOLFSSL_AVAILABLE
  #include "../security/wolfssl_process.h"

  #include <wolfssl/options.h>
  #include <wolfssl/wolfcrypt/asn_public.h>
  #include <wolfssl/wolfcrypt/ed25519.h>
  #include <wolfssl/wolfcrypt/random.h>
#endif

#ifdef _WIN32
  #include <windows.h>
#else
  #include <fcntl.h>
  #include <sys/stat.h>
  #include <unistd.h>
#endif

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <limits>
#include <system_error>

namespace lumen::lsp::runtime {
  namespace {
    constexpr std::array<std::uint8_t, 8> identity_magic {'L', 'S', 'P', 'I', 'D', '0', '0', '1'};
    constexpr std::uint16_t identity_format_version = 1;
    constexpr std::size_t fixed_identity_bytes = 8 + 2 + 2 + 16 + 32 + 32 + 32 + 4 + 4;
    constexpr std::size_t maximum_der_bytes = 16U * 1024U;
    constexpr std::size_t maximum_identity_bytes = fixed_identity_bytes + 2U * maximum_der_bytes;

    void clear_secret(const std::span<std::uint8_t> bytes) noexcept {
      volatile std::uint8_t *cursor = bytes.data();
      for (std::size_t index = 0; index < bytes.size(); ++index) {
        cursor[index] = 0;
      }
    }

    void clear_identity_secrets(HostIdentity &identity) noexcept {
      clear_secret(identity.application_private_key);
      clear_secret(identity.cookie_secret);
      clear_secret(identity.private_key_der);
    }

    bool contains_nonzero(const std::span<const std::uint8_t> bytes) noexcept {
      std::uint8_t aggregate = 0;
      for (const auto byte : bytes) {
        aggregate = static_cast<std::uint8_t>(aggregate | byte);
      }
      return aggregate != 0;
    }

    bool flush_file(const std::filesystem::path &path) noexcept {
#ifdef _WIN32
      const auto handle = CreateFileW(
        path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
      );
      if (handle == INVALID_HANDLE_VALUE) {
        return false;
      }
      const auto flushed = FlushFileBuffers(handle) != 0;
      CloseHandle(handle);
      return flushed;
#else
      const auto descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
      if (descriptor < 0) {
        return false;
      }
      const auto flushed = fsync(descriptor) == 0;
      ::close(descriptor);
      return flushed;
#endif
    }

    bool set_private_permissions(const std::filesystem::path &path) noexcept {
      std::error_code error;
      std::filesystem::permissions(
        path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace,
        error
      );
      return !error;
    }

    bool replace_file_atomic(
      const std::filesystem::path &pending,
      const std::filesystem::path &destination
    ) noexcept {
#ifdef _WIN32
      if (std::filesystem::exists(destination)) {
        return ReplaceFileW(destination.c_str(), pending.c_str(), nullptr, REPLACEFILE_WRITE_THROUGH, nullptr, nullptr) != 0;
      }
      return MoveFileExW(pending.c_str(), destination.c_str(), MOVEFILE_WRITE_THROUGH) != 0;
#else
      std::error_code error;
      std::filesystem::rename(pending, destination, error);
      return !error;
#endif
    }

    std::expected<std::vector<std::uint8_t>, IdentityError> read_identity_file(
      const std::filesystem::path &path
    ) noexcept {
      try {
        std::error_code error;
        const auto size = std::filesystem::file_size(path, error);
        if (error || size < fixed_identity_bytes || size > maximum_identity_bytes) {
          return std::unexpected(IdentityError::malformed_storage);
        }
        std::ifstream input {path, std::ios::binary};
        if (!input) {
          return std::unexpected(IdentityError::io_failed);
        }
        std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
        input.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!input || input.gcount() != static_cast<std::streamsize>(bytes.size())) {
          clear_secret(bytes);
          return std::unexpected(IdentityError::io_failed);
        }
        return bytes;
      } catch (...) {
        return std::unexpected(IdentityError::io_failed);
      }
    }

    bool write_identity_file(
      const std::filesystem::path &path,
      const std::span<const std::uint8_t> bytes
    ) noexcept {
      try {
        std::ofstream output {path, std::ios::binary | std::ios::trunc};
        if (!output) {
          return false;
        }
        output.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        output.flush();
        if (!output) {
          return false;
        }
        output.close();
        return set_private_permissions(path) && flush_file(path);
      } catch (...) {
        return false;
      }
    }

#if LUMEN_LSP_WOLFSSL_AVAILABLE
    class RngOwner {
    public:
      RngOwner() noexcept:
          initialized_ {wc_InitRng(&value_) == 0} {
      }

      ~RngOwner() {
        if (initialized_) {
          wc_FreeRng(&value_);
        }
      }

      [[nodiscard]] explicit operator bool() const noexcept {
        return initialized_;
      }

      [[nodiscard]] WC_RNG *get() noexcept {
        return &value_;
      }

    private:
      WC_RNG value_ {};  ///< Owned wolfCrypt random generator.
      bool initialized_ {};  ///< Whether destruction must free the generator.
    };

    class Ed25519Owner {
    public:
      Ed25519Owner() noexcept:
          initialized_ {wc_ed25519_init(&value_) == 0} {
      }

      ~Ed25519Owner() {
        if (initialized_) {
          wc_ed25519_free(&value_);
        }
      }

      [[nodiscard]] explicit operator bool() const noexcept {
        return initialized_;
      }

      [[nodiscard]] ed25519_key *get() noexcept {
        return &value_;
      }

    private:
      ed25519_key value_ {};  ///< Owned Ed25519 key.
      bool initialized_ {};  ///< Whether destruction must free the key.
    };

    bool copy_name(char *destination, const std::size_t capacity, const std::string_view value) noexcept {
      if (value.size() + 1 > capacity) {
        return false;
      }
      std::memcpy(destination, value.data(), value.size());
      destination[value.size()] = '\0';
      return true;
    }
#endif
  }  // namespace

  bool HostIdentity::valid() const noexcept {
    return !is_zero(host_id) && !is_zero(application_public_key) &&
           contains_nonzero(application_private_key) && !is_zero(cookie_secret) &&
           !certificate_der.empty() && certificate_der.size() <= maximum_der_bytes &&
           !private_key_der.empty() && private_key_der.size() <= maximum_der_bytes;
  }

  HostIdentity::HostIdentity(HostIdentity &&other) noexcept:
      host_id {other.host_id},
      application_public_key {other.application_public_key},
      application_private_key {other.application_private_key},
      cookie_secret {other.cookie_secret},
      certificate_der {std::move(other.certificate_der)},
      private_key_der {std::move(other.private_key_der)} {
    clear_identity_secrets(other);
    other.host_id = {};
    other.application_public_key = {};
  }

  HostIdentity &HostIdentity::operator=(HostIdentity &&other) noexcept {
    if (this != &other) {
      clear_identity_secrets(*this);
      host_id = other.host_id;
      application_public_key = other.application_public_key;
      application_private_key = other.application_private_key;
      cookie_secret = other.cookie_secret;
      certificate_der = std::move(other.certificate_der);
      private_key_der = std::move(other.private_key_der);
      clear_identity_secrets(other);
      other.host_id = {};
      other.application_public_key = {};
    }
    return *this;
  }

  HostIdentity::~HostIdentity() {
    clear_identity_secrets(*this);
  }

  std::expected<std::vector<std::uint8_t>, IdentityError> encode_identity(
    const HostIdentity &identity
  ) {
    if (!identity.valid()) {
      return std::unexpected(IdentityError::invalid_identity);
    }
    try {
      std::vector<std::uint8_t> bytes(fixed_identity_bytes + identity.certificate_der.size() + identity.private_key_der.size());
      std::size_t offset = 0;
      std::copy(identity_magic.begin(), identity_magic.end(), bytes.begin());
      offset += identity_magic.size();
      wire::write_be<std::uint16_t>(std::span<std::uint8_t> {bytes}.subspan(offset, 2), identity_format_version);
      offset += 2;
      wire::write_be<std::uint16_t>(std::span<std::uint8_t> {bytes}.subspan(offset, 2), 0);
      offset += 2;
      auto append = [&](const auto &value) {
        std::copy(value.begin(), value.end(), bytes.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += value.size();
      };
      append(identity.host_id);
      append(identity.application_public_key);
      append(identity.application_private_key);
      append(identity.cookie_secret);
      wire::write_be<std::uint32_t>(
        std::span<std::uint8_t> {bytes}.subspan(offset, 4),
        static_cast<std::uint32_t>(identity.certificate_der.size())
      );
      offset += 4;
      wire::write_be<std::uint32_t>(
        std::span<std::uint8_t> {bytes}.subspan(offset, 4),
        static_cast<std::uint32_t>(identity.private_key_der.size())
      );
      offset += 4;
      append(identity.certificate_der);
      append(identity.private_key_der);
      return bytes;
    } catch (...) {
      return std::unexpected(IdentityError::io_failed);
    }
  }

  std::expected<HostIdentity, IdentityError> decode_identity(
    const std::span<const std::uint8_t> bytes
  ) {
    if (bytes.size() < fixed_identity_bytes || bytes.size() > maximum_identity_bytes ||
        !std::equal(identity_magic.begin(), identity_magic.end(), bytes.begin())) {
      return std::unexpected(IdentityError::malformed_storage);
    }
    std::size_t offset = identity_magic.size();
    if (wire::read_be<std::uint16_t>(bytes.subspan(offset, 2)) != identity_format_version ||
        wire::read_be<std::uint16_t>(bytes.subspan(offset + 2, 2)) != 0) {
      return std::unexpected(IdentityError::malformed_storage);
    }
    offset += 4;

    HostIdentity identity;
    auto read_fixed = [&](auto &value) {
      std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset), value.size(), value.begin());
      offset += value.size();
    };
    read_fixed(identity.host_id);
    read_fixed(identity.application_public_key);
    read_fixed(identity.application_private_key);
    read_fixed(identity.cookie_secret);
    const auto certificate_size = wire::read_be<std::uint32_t>(bytes.subspan(offset, 4));
    offset += 4;
    const auto private_key_size = wire::read_be<std::uint32_t>(bytes.subspan(offset, 4));
    offset += 4;
    if (certificate_size == 0 || private_key_size == 0 || certificate_size > maximum_der_bytes ||
        private_key_size > maximum_der_bytes || certificate_size + private_key_size != bytes.size() - offset) {
      clear_identity_secrets(identity);
      return std::unexpected(IdentityError::malformed_storage);
    }
    identity.certificate_der.assign(
      bytes.begin() + static_cast<std::ptrdiff_t>(offset),
      bytes.begin() + static_cast<std::ptrdiff_t>(offset + certificate_size)
    );
    offset += certificate_size;
    identity.private_key_der.assign(
      bytes.begin() + static_cast<std::ptrdiff_t>(offset),
      bytes.end()
    );
    if (!identity.valid()) {
      clear_identity_secrets(identity);
      return std::unexpected(IdentityError::malformed_storage);
    }
    return identity;
  }

  std::expected<HostIdentity, IdentityError> generate_identity() noexcept {
#if !LUMEN_LSP_WOLFSSL_AVAILABLE
    return std::unexpected(IdentityError::provider_unavailable);
#else
    RngOwner random;
    Ed25519Owner application_key;
    Ed25519Owner dtls_key;
    if (!random) {
      return std::unexpected(IdentityError::random_failed);
    }
    if (!application_key || !dtls_key ||
        wc_ed25519_make_key(random.get(), ED25519_KEY_SIZE, application_key.get()) != 0 ||
        wc_ed25519_make_key(random.get(), ED25519_KEY_SIZE, dtls_key.get()) != 0) {
      return std::unexpected(IdentityError::key_generation_failed);
    }

    HostIdentity identity;
    if (wc_RNG_GenerateBlock(random.get(), identity.host_id.data(), static_cast<word32>(identity.host_id.size())) != 0 ||
        wc_RNG_GenerateBlock(random.get(), identity.cookie_secret.data(), static_cast<word32>(identity.cookie_secret.size())) != 0) {
      clear_identity_secrets(identity);
      return std::unexpected(IdentityError::random_failed);
    }
    word32 public_size = identity.application_public_key.size();
    word32 private_size = identity.application_private_key.size();
    if (wc_ed25519_export_public(application_key.get(), identity.application_public_key.data(), &public_size) != 0 ||
        public_size != identity.application_public_key.size() ||
        wc_ed25519_export_private_only(application_key.get(), identity.application_private_key.data(), &private_size) != 0 ||
        private_size != identity.application_private_key.size()) {
      clear_identity_secrets(identity);
      return std::unexpected(IdentityError::key_generation_failed);
    }

    Cert certificate {};
    if (wc_InitCert(&certificate) != 0 ||
        !copy_name(certificate.subject.commonName, sizeof(certificate.subject.commonName), "Lumen LSP Host") ||
        !copy_name(certificate.subject.org, sizeof(certificate.subject.org), "Lumen") ||
        !copy_name(certificate.issuer.commonName, sizeof(certificate.issuer.commonName), "Lumen LSP Host") ||
        !copy_name(certificate.issuer.org, sizeof(certificate.issuer.org), "Lumen")) {
      clear_identity_secrets(identity);
      return std::unexpected(IdentityError::certificate_generation_failed);
    }
    certificate.daysValid = 3'650;
    certificate.selfSigned = 1;
    certificate.isCA = 0;
    certificate.sigType = CTC_ED25519;

    std::array<std::uint8_t, 4'096> certificate_buffer {};
    const auto body_size = wc_MakeCert_ex(
      &certificate,
      certificate_buffer.data(),
      static_cast<word32>(certificate_buffer.size()),
      ED25519_TYPE,
      dtls_key.get(),
      random.get()
    );
    const auto certificate_size = body_size > 0 ? wc_SignCert_ex(
                                                    certificate.bodySz,
                                                    certificate.sigType,
                                                    certificate_buffer.data(),
                                                    static_cast<word32>(certificate_buffer.size()),
                                                    ED25519_TYPE,
                                                    dtls_key.get(),
                                                    random.get()
                                                  ) :
                                                  body_size;
    if (certificate_size <= 0) {
      clear_identity_secrets(identity);
      return std::unexpected(IdentityError::certificate_generation_failed);
    }
    identity.certificate_der.assign(certificate_buffer.begin(), certificate_buffer.begin() + certificate_size);
    clear_secret(certificate_buffer);

    std::array<std::uint8_t, 1'024> private_key_buffer {};
    const auto dtls_private_size = wc_Ed25519PrivateKeyToDer(
      dtls_key.get(),
      private_key_buffer.data(),
      static_cast<word32>(private_key_buffer.size())
    );
    if (dtls_private_size <= 0) {
      clear_secret(private_key_buffer);
      clear_identity_secrets(identity);
      return std::unexpected(IdentityError::key_generation_failed);
    }
    identity.private_key_der.assign(private_key_buffer.begin(), private_key_buffer.begin() + dtls_private_size);
    clear_secret(private_key_buffer);
    if (!identity.valid()) {
      clear_identity_secrets(identity);
      return std::unexpected(IdentityError::invalid_identity);
    }
    return identity;
#endif
  }

  std::expected<HostIdentity, IdentityError> generate_rotated_identity(
    const HostIdentity &current
  ) noexcept {
    if (!current.valid()) {
      return std::unexpected(IdentityError::invalid_identity);
    }
    auto generated = generate_identity();
    if (!generated) {
      return std::unexpected(generated.error());
    }
    generated->host_id = current.host_id;
    generated->application_public_key = current.application_public_key;
    generated->application_private_key = current.application_private_key;
    generated->cookie_secret = current.cookie_secret;
    return generated;
  }

  std::expected<void, IdentityError> persist_identity_atomic(
    const std::filesystem::path &path,
    const HostIdentity &identity
  ) noexcept {
    auto encoded = encode_identity(identity);
    if (!encoded) {
      return std::unexpected(encoded.error());
    }
    try {
      std::error_code error;
      std::filesystem::create_directories(path.parent_path(), error);
      if (error) {
        clear_secret(*encoded);
        return std::unexpected(IdentityError::io_failed);
      }
      auto pending = path;
      pending += ".rotation.pending";
      std::filesystem::remove(pending, error);
      error.clear();
      if (!write_identity_file(pending, *encoded)) {
        clear_secret(*encoded);
        std::filesystem::remove(pending, error);
        return std::unexpected(IdentityError::io_failed);
      }
      const auto replaced = replace_file_atomic(pending, path);
      clear_secret(*encoded);
      if (!replaced) {
        std::filesystem::remove(pending, error);
        return std::unexpected(IdentityError::io_failed);
      }
      return {};
    } catch (...) {
      clear_secret(*encoded);
      return std::unexpected(IdentityError::io_failed);
    }
  }

  std::expected<HostIdentity, IdentityError> load_or_create_identity(
    const std::filesystem::path &path
  ) noexcept {
#if LUMEN_LSP_WOLFSSL_AVAILABLE
    if (!initialize_wolfssl_process()) {
      return std::unexpected(IdentityError::random_failed);
    }
#endif

    try {
      std::error_code error;
      if (std::filesystem::exists(path, error)) {
        if (error || !std::filesystem::is_regular_file(path, error) || error) {
          return std::unexpected(IdentityError::io_failed);
        }
        auto bytes = read_identity_file(path);
        if (!bytes) {
          return std::unexpected(bytes.error());
        }
        auto identity = decode_identity(*bytes);
        clear_secret(*bytes);
        return identity;
      }
      if (error) {
        return std::unexpected(IdentityError::io_failed);
      }

      auto identity = generate_identity();
      if (!identity) {
        return std::unexpected(identity.error());
      }
      auto encoded = encode_identity(*identity);
      if (!encoded) {
        clear_identity_secrets(*identity);
        return std::unexpected(encoded.error());
      }
      std::filesystem::create_directories(path.parent_path(), error);
      if (error) {
        clear_secret(*encoded);
        clear_identity_secrets(*identity);
        return std::unexpected(IdentityError::io_failed);
      }
      auto pending = path;
      pending += ".pending";
      std::filesystem::remove(pending, error);
      error.clear();
      if (!write_identity_file(pending, *encoded)) {
        clear_secret(*encoded);
        clear_identity_secrets(*identity);
        std::filesystem::remove(pending, error);
        return std::unexpected(IdentityError::io_failed);
      }
      std::filesystem::rename(pending, path, error);
      clear_secret(*encoded);
      if (error) {
        clear_identity_secrets(*identity);
        std::filesystem::remove(pending, error);
        return std::unexpected(IdentityError::io_failed);
      }
      return identity;
    } catch (...) {
      return std::unexpected(IdentityError::io_failed);
    }
  }
}  // namespace lumen::lsp::runtime
