/**
 * @file src/protocol_v3/host_identity_store.cpp
 * @brief Protected protocol-v3 host identity persistence.
 */
#include "host_identity_store.h"

#include "../protocol_common/crypto.h"

#include <algorithm>
#include <array>
#include <fstream>
#include <openssl/crypto.h>
#include <system_error>

#ifdef _WIN32
  #include <Windows.h>
  #include <aclapi.h>
  #include <dpapi.h>
  #include <sddl.h>
#else
  #include <sys/stat.h>
  #include <unistd.h>
#endif

namespace lumen::protocol_v3::runtime {
  namespace {
    constexpr std::array<std::uint8_t, 8> identity_magic {'L', 'U', 'M', 'E', 'N', 'I', 'D', '3'};
    constexpr std::array<std::uint8_t, 8> journal_magic {'L', 'U', 'M', 'E', 'N', 'J', '0', '1'};
    constexpr std::uint8_t identity_version = 1;
    constexpr std::size_t maximum_protected_identity_bytes = 16U * 1024U;

    void append_u32(std::vector<std::uint8_t> &output, const std::uint32_t value) {
      output.push_back(static_cast<std::uint8_t>(value >> 24U));
      output.push_back(static_cast<std::uint8_t>(value >> 16U));
      output.push_back(static_cast<std::uint8_t>(value >> 8U));
      output.push_back(static_cast<std::uint8_t>(value));
    }

    std::uint32_t read_u32(const std::span<const std::uint8_t> input, const std::size_t offset) {
      return (static_cast<std::uint32_t>(input[offset]) << 24U) |
             (static_cast<std::uint32_t>(input[offset + 1]) << 16U) |
             (static_cast<std::uint32_t>(input[offset + 2]) << 8U) |
             static_cast<std::uint32_t>(input[offset + 3]);
    }

    std::vector<std::uint8_t> identity_blob(const std::span<const std::uint8_t> protected_seed) {
      std::vector<std::uint8_t> output;
      output.reserve(16 + protected_seed.size());
      output.insert(output.end(), identity_magic.begin(), identity_magic.end());
      output.push_back(identity_version);
      output.insert(output.end(), 3, 0);
      append_u32(output, static_cast<std::uint32_t>(protected_seed.size()));
      output.insert(output.end(), protected_seed.begin(), protected_seed.end());
      return output;
    }

    std::expected<std::span<const std::uint8_t>, HostIdentityError> protected_payload(
      const std::span<const std::uint8_t> blob
    ) {
      if (blob.size() < 16 || !std::equal(identity_magic.begin(), identity_magic.end(), blob.begin()) ||
          blob[8] != identity_version || blob[9] != 0 || blob[10] != 0 || blob[11] != 0) {
        return std::unexpected(HostIdentityError::corrupt_blob);
      }
      const auto size = read_u32(blob, 12);
      if (size == 0 || size > maximum_protected_identity_bytes || blob.size() != 16U + size) {
        return std::unexpected(HostIdentityError::corrupt_blob);
      }
      return blob.subspan(16, size);
    }

    std::vector<std::uint8_t> journal_blob(
      const HostIdentityStage stage,
      const control::Bytes32 &public_key
    ) {
      std::vector<std::uint8_t> output;
      output.reserve(48);
      output.insert(output.end(), journal_magic.begin(), journal_magic.end());
      output.push_back(static_cast<std::uint8_t>(stage));
      output.insert(output.end(), 7, 0);
      output.insert(output.end(), public_key.begin(), public_key.end());
      return output;
    }

    struct JournalRecord {
      HostIdentityStage stage {};
      control::Bytes32 public_key {};
    };

    std::optional<JournalRecord> parse_journal(const std::span<const std::uint8_t> input) {
      if (input.size() != 48 || !std::equal(journal_magic.begin(), journal_magic.end(), input.begin()) ||
          std::ranges::any_of(input.subspan(9, 7), [](const auto value) { return value != 0; })) {
        return std::nullopt;
      }
      const auto raw_stage = input[8];
      if (raw_stage < static_cast<std::uint8_t>(HostIdentityStage::journal_started) ||
          raw_stage > static_cast<std::uint8_t>(HostIdentityStage::journal_committed)) {
        return std::nullopt;
      }
      JournalRecord record {.stage = static_cast<HostIdentityStage>(raw_stage)};
      std::copy_n(input.begin() + 16, record.public_key.size(), record.public_key.begin());
      return record;
    }

    bool same_seed(const control::Bytes32 &left, const control::Bytes32 &right) noexcept {
      return CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0;
    }

    std::optional<control::Bytes32> public_key(const control::Bytes32 &seed) {
      return lumen::protocol_common::crypto::ed25519_public_key(seed);
    }

#ifdef _WIN32
    class NativeHostIdentityPlatform final: public HostIdentityPlatform {
    public:
      HostPrincipal principal() const noexcept override {
        HANDLE token {};
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
          return HostPrincipal::unsupported;
        }
        const auto close_token = std::unique_ptr<void, decltype(&CloseHandle)> {token, CloseHandle};
        DWORD size {};
        GetTokenInformation(token, TokenUser, nullptr, 0, &size);
        if (size == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
          return HostPrincipal::unsupported;
        }
        std::vector<std::uint8_t> buffer(size);
        if (!GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) {
          return HostPrincipal::unsupported;
        }
        std::array<std::uint8_t, SECURITY_MAX_SID_SIZE> system_buffer {};
        DWORD system_size = static_cast<DWORD>(system_buffer.size());
        if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, system_buffer.data(), &system_size)) {
          return HostPrincipal::unsupported;
        }
        const auto *user = reinterpret_cast<const TOKEN_USER *>(buffer.data());
        if (EqualSid(user->User.Sid, system_buffer.data())) {
          return HostPrincipal::local_system;
        }
        std::array<std::uint8_t, SECURITY_MAX_SID_SIZE> admin_buffer {};
        DWORD admin_size = static_cast<DWORD>(admin_buffer.size());
        BOOL administrator {};
        TOKEN_ELEVATION elevation {};
        DWORD returned {};
        if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admin_buffer.data(), &admin_size) ||
            !CheckTokenMembership(nullptr, admin_buffer.data(), &administrator) || !administrator ||
            !GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &returned) ||
            !elevation.TokenIsElevated) {
          return HostPrincipal::unsupported;
        }
        return HostPrincipal::elevated_administrator;
      }

      std::expected<std::vector<std::uint8_t>, HostIdentityError> protect(
        const std::span<const std::uint8_t> plaintext
      ) override {
        DATA_BLOB input {static_cast<DWORD>(plaintext.size()), const_cast<BYTE *>(plaintext.data())};
        auto entropy_bytes = entropy();
        DATA_BLOB extra {static_cast<DWORD>(entropy_bytes.size()), entropy_bytes.data()};
        DATA_BLOB output {};
        if (!CryptProtectData(
              &input,
              L"Lumen protocol v3 machine identity",
              &extra,
              nullptr,
              nullptr,
              CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
              &output
            )) {
          return std::unexpected(HostIdentityError::protection_failure);
        }
        std::vector<std::uint8_t> result(output.pbData, output.pbData + output.cbData);
        SecureZeroMemory(output.pbData, output.cbData);
        LocalFree(output.pbData);
        return result;
      }

      std::expected<std::vector<std::uint8_t>, HostIdentityError> unprotect(
        const std::span<const std::uint8_t> protected_bytes
      ) override {
        DATA_BLOB input {
          static_cast<DWORD>(protected_bytes.size()),
          const_cast<BYTE *>(protected_bytes.data()),
        };
        auto entropy_bytes = entropy();
        DATA_BLOB extra {static_cast<DWORD>(entropy_bytes.size()), entropy_bytes.data()};
        DATA_BLOB output {};
        if (!CryptUnprotectData(&input, nullptr, &extra, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output)) {
          return std::unexpected(HostIdentityError::protection_failure);
        }
        std::vector<std::uint8_t> result(output.pbData, output.pbData + output.cbData);
        SecureZeroMemory(output.pbData, output.cbData);
        LocalFree(output.pbData);
        return result;
      }

      bool write_private(
        const std::filesystem::path &path,
        const std::span<const std::uint8_t> bytes
      ) override {
        if (!prepare_parent(path.parent_path())) {
          return false;
        }
        PSECURITY_DESCRIPTOR descriptor {};
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
              private_sddl,
              SDDL_REVISION_1,
              &descriptor,
              nullptr
            )) {
          return false;
        }
        const auto free_descriptor = std::unique_ptr<void, decltype(&LocalFree)> {descriptor, LocalFree};
        SECURITY_ATTRIBUTES attributes {sizeof(attributes), descriptor, FALSE};
        HANDLE file = CreateFileW(
          path.c_str(),
          GENERIC_WRITE,
          0,
          &attributes,
          CREATE_ALWAYS,
          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OPEN_REPARSE_POINT,
          nullptr
        );
        if (file == INVALID_HANDLE_VALUE) {
          return false;
        }
        DWORD written {};
        const auto ok = bytes.size() <= MAXDWORD &&
                        WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) &&
                        written == bytes.size() && FlushFileBuffers(file);
        CloseHandle(file);
        return ok && apply_private(path) && verify_private(path);
      }

      bool read_private(
        const std::filesystem::path &path,
        std::vector<std::uint8_t> &bytes
      ) const override {
        if (!verify_private(path)) {
          return false;
        }
        std::ifstream input {path, std::ios::binary};
        bytes.assign(std::istreambuf_iterator<char> {input}, std::istreambuf_iterator<char> {});
        return input.good() || input.eof();
      }

      bool exists(const std::filesystem::path &path) const override {
        return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
      }

      bool verify_private(const std::filesystem::path &path) const override {
        const auto attributes = GetFileAttributesW(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
          return false;
        }
        PSID owner {};
        PACL dacl {};
        PSECURITY_DESCRIPTOR descriptor {};
        const auto status = GetNamedSecurityInfoW(
          const_cast<LPWSTR>(path.c_str()),
          SE_FILE_OBJECT,
          OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
          &owner,
          nullptr,
          &dacl,
          nullptr,
          &descriptor
        );
        if (status != ERROR_SUCCESS || !owner || !dacl || !descriptor) {
          return false;
        }
        const auto free_descriptor = std::unique_ptr<void, decltype(&LocalFree)> {descriptor, LocalFree};
        SECURITY_DESCRIPTOR_CONTROL control {};
        DWORD revision {};
        if (!GetSecurityDescriptorControl(descriptor, &control, &revision) ||
            (control & SE_DACL_PROTECTED) == 0) {
          return false;
        }
        std::array<std::uint8_t, SECURITY_MAX_SID_SIZE> system_buffer {};
        std::array<std::uint8_t, SECURITY_MAX_SID_SIZE> admin_buffer {};
        DWORD system_size = static_cast<DWORD>(system_buffer.size());
        DWORD admin_size = static_cast<DWORD>(admin_buffer.size());
        if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, system_buffer.data(), &system_size) ||
            !CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admin_buffer.data(), &admin_size) ||
            !EqualSid(owner, system_buffer.data()) || dacl->AceCount != 2) {
          return false;
        }
        bool system_allowed {};
        bool admin_allowed {};
        for (DWORD index = 0; index < dacl->AceCount; ++index) {
          void *raw {};
          if (!GetAce(dacl, index, &raw)) {
            return false;
          }
          const auto *ace = static_cast<const ACCESS_ALLOWED_ACE *>(raw);
          if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
              (ace->Header.AceFlags & INHERITED_ACE) != 0 ||
              (ace->Mask & FILE_ALL_ACCESS) != FILE_ALL_ACCESS) {
            return false;
          }
          auto sid = const_cast<DWORD *>(&ace->SidStart);
          if (EqualSid(sid, system_buffer.data())) {
            system_allowed = true;
          } else if (EqualSid(sid, admin_buffer.data())) {
            admin_allowed = true;
          } else {
            return false;
          }
        }
        return system_allowed && admin_allowed;
      }

      bool replace_private(
        const std::filesystem::path &source,
        const std::filesystem::path &destination
      ) override {
        return MoveFileExW(
                 source.c_str(),
                 destination.c_str(),
                 MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
               ) &&
               apply_private(destination) && verify_private(destination);
      }

      bool remove_private(const std::filesystem::path &path) override {
        return DeleteFileW(path.c_str()) || GetLastError() == ERROR_FILE_NOT_FOUND;
      }

    private:
      static constexpr wchar_t private_sddl[] = L"O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)";

      static std::array<std::uint8_t, 35> entropy() {
        std::array<std::uint8_t, 35> output {};
        constexpr std::string_view value = "Lumen protocol v3 identity entropy v1";
        std::copy(value.begin(), value.end(), output.begin());
        return output;
      }

      static bool apply_private(const std::filesystem::path &path) {
        PSECURITY_DESCRIPTOR descriptor {};
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
              private_sddl,
              SDDL_REVISION_1,
              &descriptor,
              nullptr
            )) {
          return false;
        }
        const auto free_descriptor = std::unique_ptr<void, decltype(&LocalFree)> {descriptor, LocalFree};
        PSID owner {};
        PACL dacl {};
        BOOL owner_defaulted {};
        BOOL dacl_present {};
        BOOL dacl_defaulted {};
        if (!GetSecurityDescriptorOwner(descriptor, &owner, &owner_defaulted) ||
            !GetSecurityDescriptorDacl(descriptor, &dacl_present, &dacl, &dacl_defaulted) || !dacl_present) {
          return false;
        }
        return SetNamedSecurityInfoW(
                 const_cast<LPWSTR>(path.c_str()),
                 SE_FILE_OBJECT,
                 OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                 owner,
                 nullptr,
                 dacl,
                 nullptr
               ) == ERROR_SUCCESS;
      }

      static bool prepare_parent(const std::filesystem::path &parent) {
        std::error_code error;
        std::filesystem::create_directories(parent, error);
        return !error && apply_private(parent);
      }
    };
#else
    class NativeHostIdentityPlatform final: public HostIdentityPlatform {
    public:
      HostPrincipal principal() const noexcept override {
        return HostPrincipal::supported_posix;
      }

      std::expected<std::vector<std::uint8_t>, HostIdentityError> protect(
        const std::span<const std::uint8_t> plaintext
      ) override {
        return std::vector<std::uint8_t> {plaintext.begin(), plaintext.end()};
      }

      std::expected<std::vector<std::uint8_t>, HostIdentityError> unprotect(
        const std::span<const std::uint8_t> protected_bytes
      ) override {
        return std::vector<std::uint8_t> {protected_bytes.begin(), protected_bytes.end()};
      }

      bool write_private(
        const std::filesystem::path &path,
        const std::span<const std::uint8_t> bytes
      ) override {
        std::error_code error;
        std::filesystem::create_directories(path.parent_path(), error);
        if (error) {
          return false;
        }
        std::filesystem::permissions(
          path.parent_path(),
          std::filesystem::perms::owner_all,
          std::filesystem::perm_options::replace,
          error
        );
        if (error) {
          return false;
        }
        std::ofstream output {path, std::ios::binary | std::ios::trunc};
        output.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        output.flush();
        if (!output) {
          return false;
        }
        output.close();
        std::filesystem::permissions(
          path,
          std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
          std::filesystem::perm_options::replace,
          error
        );
        return !error && verify_private(path);
      }

      bool read_private(
        const std::filesystem::path &path,
        std::vector<std::uint8_t> &bytes
      ) const override {
        if (!verify_private(path)) {
          return false;
        }
        std::ifstream input {path, std::ios::binary};
        bytes.assign(std::istreambuf_iterator<char> {input}, std::istreambuf_iterator<char> {});
        return input.good() || input.eof();
      }

      bool exists(const std::filesystem::path &path) const override {
        std::error_code error;
        return std::filesystem::exists(path, error) && !error;
      }

      bool verify_private(const std::filesystem::path &path) const override {
        std::error_code error;
        const auto status = std::filesystem::symlink_status(path, error);
        if (error || !std::filesystem::is_regular_file(status) || std::filesystem::is_symlink(status)) {
          return false;
        }
        const auto permissions = status.permissions();
        if ((permissions & (std::filesystem::perms::group_all | std::filesystem::perms::others_all)) !=
            std::filesystem::perms::none) {
          return false;
        }
        struct stat native_status {};
        return ::lstat(path.c_str(), &native_status) == 0 && S_ISREG(native_status.st_mode) &&
               native_status.st_uid == ::geteuid();
      }

      bool replace_private(
        const std::filesystem::path &source,
        const std::filesystem::path &destination
      ) override {
        std::error_code error;
        std::filesystem::rename(source, destination, error);
        return !error && verify_private(destination);
      }

      bool remove_private(const std::filesystem::path &path) override {
        std::error_code error;
        return !std::filesystem::exists(path, error) || (!error && std::filesystem::remove(path, error) && !error);
      }
    };
#endif

    std::expected<control::Bytes32, HostIdentityError> read_seed(
      HostIdentityPlatform &platform,
      const std::filesystem::path &path
    ) {
      std::vector<std::uint8_t> blob;
      if (!platform.read_private(path, blob)) {
        return std::unexpected(HostIdentityError::security_failure);
      }
      const auto payload = protected_payload(blob);
      if (!payload) {
        return std::unexpected(payload.error());
      }
      auto plaintext = platform.unprotect(*payload);
      if (!plaintext || plaintext->size() != control::Bytes32 {}.size()) {
        if (plaintext) {
          OPENSSL_cleanse(plaintext->data(), plaintext->size());
        }
        return std::unexpected(HostIdentityError::protection_failure);
      }
      control::Bytes32 seed {};
      std::copy(plaintext->begin(), plaintext->end(), seed.begin());
      OPENSSL_cleanse(plaintext->data(), plaintext->size());
      if (!public_key(seed)) {
        OPENSSL_cleanse(seed.data(), seed.size());
        return std::unexpected(HostIdentityError::corrupt_blob);
      }
      return seed;
    }
  }  // namespace

  std::unique_ptr<HostIdentityPlatform> make_native_host_identity_platform() {
    return std::make_unique<NativeHostIdentityPlatform>();
  }

  HostIdentityPaths host_identity_paths_for_state_file(const std::filesystem::path &state_file) {
    const auto credentials = state_file.parent_path() / "credentials";
    return {
      .identity = credentials / "protocol_v3_identity.bin",
      .temporary = credentials / "protocol_v3_identity.bin.pending",
      .journal = credentials / "protocol_v3_identity.journal",
    };
  }

  HostIdentityStore::HostIdentityStore(
    HostIdentityPaths paths,
    std::unique_ptr<HostIdentityPlatform> platform,
    const bool persistent,
    InterruptionHook interruption
  ):
      paths_ {std::move(paths)},
      platform_ {std::move(platform)},
      persistent_ {persistent},
      interruption_ {std::move(interruption)} {
  }

  std::expected<HostIdentityLoad, HostIdentityError> HostIdentityStore::load_or_create(
    const std::optional<control::Bytes32> &legacy_seed,
    control::Random &random
  ) {
    if (!platform_ || platform_->principal() == HostPrincipal::unsupported) {
      return std::unexpected(HostIdentityError::unsupported_principal);
    }
    if (!persistent_) {
      control::Bytes32 seed {};
      if (!random.fill(seed) || !public_key(seed)) {
        return std::unexpected(HostIdentityError::protection_failure);
      }
      return HostIdentityLoad {.seed = seed};
    }

    std::optional<JournalRecord> journal;
    if (platform_->exists(paths_.journal)) {
      std::vector<std::uint8_t> bytes;
      if (!platform_->read_private(paths_.journal, bytes)) {
        return std::unexpected(HostIdentityError::security_failure);
      }
      journal = parse_journal(bytes);
      if (!journal) {
        return std::unexpected(HostIdentityError::corrupt_blob);
      }
    }

    if (platform_->exists(paths_.identity)) {
      auto seed = read_seed(*platform_, paths_.identity);
      if (!seed) {
        return std::unexpected(seed.error());
      }
      const auto derived = public_key(*seed);
      if (!derived || (journal && !same_seed(*derived, journal->public_key)) ||
          (legacy_seed && !same_seed(*legacy_seed, *seed))) {
        OPENSSL_cleanse(seed->data(), seed->size());
        return std::unexpected(HostIdentityError::identity_mismatch);
      }
      if (platform_->exists(paths_.temporary) && !platform_->remove_private(paths_.temporary)) {
        OPENSSL_cleanse(seed->data(), seed->size());
        return std::unexpected(HostIdentityError::io_failure);
      }
      if (!journal || journal->stage != HostIdentityStage::journal_committed) {
        const auto committed = journal_blob(HostIdentityStage::journal_committed, *derived);
        if (!platform_->write_private(paths_.journal, committed)) {
          OPENSSL_cleanse(seed->data(), seed->size());
          return std::unexpected(HostIdentityError::security_failure);
        }
      }
      return HostIdentityLoad {.seed = *seed, .retire_legacy_seed = legacy_seed.has_value()};
    }

    if (platform_->exists(paths_.temporary)) {
      if (!journal) {
        return std::unexpected(HostIdentityError::corrupt_blob);
      }
      auto seed = read_seed(*platform_, paths_.temporary);
      if (!seed) {
        return std::unexpected(seed.error());
      }
      const auto derived = public_key(*seed);
      if (!derived || !same_seed(*derived, journal->public_key) ||
          (legacy_seed && !same_seed(*legacy_seed, *seed)) ||
          !platform_->replace_private(paths_.temporary, paths_.identity)) {
        OPENSSL_cleanse(seed->data(), seed->size());
        return std::unexpected(HostIdentityError::identity_mismatch);
      }
      const auto committed = journal_blob(HostIdentityStage::journal_committed, *derived);
      if (!platform_->write_private(paths_.journal, committed)) {
        OPENSSL_cleanse(seed->data(), seed->size());
        return std::unexpected(HostIdentityError::security_failure);
      }
      return HostIdentityLoad {.seed = *seed, .retire_legacy_seed = legacy_seed.has_value()};
    }

    if (journal && journal->stage == HostIdentityStage::journal_committed) {
      return std::unexpected(HostIdentityError::corrupt_blob);
    }

    control::Bytes32 seed {};
    if (legacy_seed) {
      seed = *legacy_seed;
    } else if (!random.fill(seed)) {
      return std::unexpected(HostIdentityError::protection_failure);
    }
    const auto derived = public_key(seed);
    if (!derived) {
      OPENSSL_cleanse(seed.data(), seed.size());
      return std::unexpected(HostIdentityError::corrupt_blob);
    }
    const auto started = journal_blob(HostIdentityStage::journal_started, *derived);
    if (!platform_->write_private(paths_.journal, started)) {
      OPENSSL_cleanse(seed.data(), seed.size());
      return std::unexpected(HostIdentityError::security_failure);
    }
    if (interruption_ && interruption_(HostIdentityStage::journal_started)) {
      OPENSSL_cleanse(seed.data(), seed.size());
      return std::unexpected(HostIdentityError::injected_interruption);
    }
    auto protected_seed = platform_->protect(seed);
    if (!protected_seed) {
      OPENSSL_cleanse(seed.data(), seed.size());
      return std::unexpected(protected_seed.error());
    }
    const auto blob = identity_blob(*protected_seed);
    OPENSSL_cleanse(protected_seed->data(), protected_seed->size());
    if (!platform_->write_private(paths_.temporary, blob)) {
      OPENSSL_cleanse(seed.data(), seed.size());
      return std::unexpected(HostIdentityError::security_failure);
    }
    if (interruption_ && interruption_(HostIdentityStage::temporary_written)) {
      OPENSSL_cleanse(seed.data(), seed.size());
      return std::unexpected(HostIdentityError::injected_interruption);
    }
    auto verified = read_seed(*platform_, paths_.temporary);
    if (!verified || !same_seed(seed, *verified)) {
      if (verified) {
        OPENSSL_cleanse(verified->data(), verified->size());
      }
      OPENSSL_cleanse(seed.data(), seed.size());
      return std::unexpected(HostIdentityError::identity_mismatch);
    }
    OPENSSL_cleanse(verified->data(), verified->size());
    if (interruption_ && interruption_(HostIdentityStage::temporary_verified)) {
      OPENSSL_cleanse(seed.data(), seed.size());
      return std::unexpected(HostIdentityError::injected_interruption);
    }
    if (!platform_->replace_private(paths_.temporary, paths_.identity)) {
      OPENSSL_cleanse(seed.data(), seed.size());
      return std::unexpected(HostIdentityError::io_failure);
    }
    if (interruption_ && interruption_(HostIdentityStage::identity_replaced)) {
      OPENSSL_cleanse(seed.data(), seed.size());
      return std::unexpected(HostIdentityError::injected_interruption);
    }
    const auto committed = journal_blob(HostIdentityStage::journal_committed, *derived);
    if (!platform_->write_private(paths_.journal, committed)) {
      OPENSSL_cleanse(seed.data(), seed.size());
      return std::unexpected(HostIdentityError::security_failure);
    }
    if (interruption_ && interruption_(HostIdentityStage::journal_committed)) {
      OPENSSL_cleanse(seed.data(), seed.size());
      return std::unexpected(HostIdentityError::injected_interruption);
    }
    return HostIdentityLoad {.seed = seed, .retire_legacy_seed = legacy_seed.has_value()};
  }

  const HostIdentityPaths &HostIdentityStore::paths() const noexcept {
    return paths_;
  }

  bool secure_private_key_file(const std::filesystem::path &path) {
    auto platform = make_native_host_identity_platform();
    std::vector<std::uint8_t> bytes;
    if (!platform || platform->principal() == HostPrincipal::unsupported) {
      return false;
    }
    std::ifstream input {path, std::ios::binary};
    bytes.assign(std::istreambuf_iterator<char> {input}, std::istreambuf_iterator<char> {});
    return (input.good() || input.eof()) && !bytes.empty() && platform->write_private(path, bytes);
  }

  bool verify_private_key_file(const std::filesystem::path &path) {
    const auto platform = make_native_host_identity_platform();
    return platform && platform->principal() != HostPrincipal::unsupported && platform->verify_private(path);
  }
}  // namespace lumen::protocol_v3::runtime
