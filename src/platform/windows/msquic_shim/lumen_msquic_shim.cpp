/**
 * @file src/platform/windows/msquic_shim/lumen_msquic_shim.cpp
 * @brief MSVC-only implementation of the stable Lumen MsQuic shim ABI.
 */

#define LUMEN_MSQUIC_SHIM_BUILD 1
#include "lumen_msquic_shim.h"
#include "cng_key_journal.h"

#include <algorithm>
#include <array>
#include <windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <map>
#include <memory>
#include <msquic.h>
#include <mutex>
#include <ncrypt.h>
#include <new>
#include <optional>
#include <string>
#include <utility>
#include <vector>
#include <wincrypt.h>

namespace {
  lumen_msquic_status status(const QUIC_STATUS value) noexcept {
    if (value == QUIC_STATUS_PENDING) {
      return LUMEN_MSQUIC_PENDING;
    }
    if (QUIC_SUCCEEDED(value)) {
      return LUMEN_MSQUIC_SUCCESS;
    }
    if (value == QUIC_STATUS_OUT_OF_MEMORY) {
      return LUMEN_MSQUIC_OUT_OF_MEMORY;
    }
    if (value == QUIC_STATUS_INVALID_STATE || value == QUIC_STATUS_INVALID_PARAMETER) {
      return LUMEN_MSQUIC_INVALID_STATE;
    }
    if (value == QUIC_STATUS_NOT_SUPPORTED) {
      return LUMEN_MSQUIC_NOT_SUPPORTED;
    }
    if (value == QUIC_STATUS_ABORTED) {
      return LUMEN_MSQUIC_ABORTED;
    }
    return LUMEN_MSQUIC_TRANSPORT_ERROR;
  }

  HQUIC native(const lumen_msquic_handle value) noexcept {
    return reinterpret_cast<HQUIC>(value);
  }

  lumen_msquic_handle portable(const HQUIC value) noexcept {
    return reinterpret_cast<lumen_msquic_handle>(value);
  }

  bool leaf_spki_sha256(const PCCERT_CONTEXT certificate, std::array<uint8_t, 32> &output) {
    if (certificate == nullptr || certificate->pCertInfo == nullptr) {
      return false;
    }
    DWORD encoded_bytes = 0;
    if (!CryptEncodeObjectEx(
          X509_ASN_ENCODING,
          X509_PUBLIC_KEY_INFO,
          &certificate->pCertInfo->SubjectPublicKeyInfo,
          0,
          nullptr,
          nullptr,
          &encoded_bytes
        ) ||
        encoded_bytes == 0) {
      return false;
    }
    std::vector<uint8_t> encoded(encoded_bytes);
    if (!CryptEncodeObjectEx(
          X509_ASN_ENCODING,
          X509_PUBLIC_KEY_INFO,
          &certificate->pCertInfo->SubjectPublicKeyInfo,
          0,
          nullptr,
          encoded.data(),
          &encoded_bytes
        )) {
      return false;
    }
    DWORD hash_bytes = static_cast<DWORD>(output.size());
    return CryptHashCertificate2(
             BCRYPT_SHA256_ALGORITHM,
             0,
             nullptr,
             encoded.data(),
             encoded_bytes,
             output.data(),
             &hash_bytes
           ) != FALSE &&
           hash_bytes == output.size() &&
           !std::ranges::all_of(output, [](const uint8_t byte) {
             return byte == 0;
           });
  }

  struct ListenerContext: std::enable_shared_from_this<ListenerContext> {
    lumen_msquic_listener_callback callback {};
    void *context {};
  };

  /** @brief Emit a bounded service-log diagnostic for one failed key rollback. */
  void report_cleanup_failure(const SECURITY_STATUS status) noexcept {
    std::fprintf(
      stderr,
      "Lumen MsQuic temporary CNG key cleanup failed with status 0x%08lx\n",
      static_cast<unsigned long>(status)
    );
  }

  std::u16string portable_string(const std::wstring &value) {
    static_assert(sizeof(wchar_t) == sizeof(char16_t));
    return {
      reinterpret_cast<const char16_t *>(value.data()),
      reinterpret_cast<const char16_t *>(value.data() + value.size()),
    };
  }

  std::wstring native_string(const std::u16string &value) {
    static_assert(sizeof(wchar_t) == sizeof(char16_t));
    return {
      reinterpret_cast<const wchar_t *>(value.data()),
      reinterpret_cast<const wchar_t *>(value.data() + value.size()),
    };
  }

  /** @brief Crash-safe Windows file storage for the bounded owned-key journal. */
  class WindowsCngJournalStore final: public lumen::msquic::cng::JournalStore {
  public:
    explicit WindowsCngJournalStore(std::wstring path):
        path_ {std::move(path)} {
    }

    bool read(std::vector<lumen::msquic::cng::KeyIdentity> &entries) noexcept override {
      try {
        const auto temporary_path = path_ + L".tmp";
        std::vector<std::uint8_t> bytes;
        if (read_bytes(temporary_path, bytes)) {
          std::vector<lumen::msquic::cng::KeyIdentity> recovered;
          if (lumen::msquic::cng::deserialize(bytes, recovered) &&
              MoveFileExW(
                temporary_path.c_str(),
                path_.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
              )) {
            entries = std::move(recovered);
            return true;
          }
          DeleteFileW(temporary_path.c_str());
        }
        bytes.clear();
        if (!read_bytes(path_, bytes)) {
          if (GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND) {
            entries.clear();
            return true;
          }
          return false;
        }
        return lumen::msquic::cng::deserialize(bytes, entries);
      } catch (...) {
        return false;
      }
    }

    bool write(const std::vector<lumen::msquic::cng::KeyIdentity> &entries) noexcept override {
      try {
        std::vector<std::uint8_t> bytes;
        if (!lumen::msquic::cng::serialize(entries, bytes)) {
          return false;
        }
        const auto temporary_path = path_ + L".tmp";
        DeleteFileW(temporary_path.c_str());
        const auto file = CreateFileW(
          temporary_path.c_str(),
          GENERIC_WRITE,
          0,
          nullptr,
          CREATE_NEW,
          FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_WRITE_THROUGH,
          nullptr
        );
        if (file == INVALID_HANDLE_VALUE) {
          return false;
        }
        DWORD written {};
        const auto write_ok = WriteFile(
                                file,
                                bytes.data(),
                                static_cast<DWORD>(bytes.size()),
                                &written,
                                nullptr
                              ) &&
                              written == bytes.size() && FlushFileBuffers(file);
        const auto close_ok = CloseHandle(file) != FALSE;
        if (!write_ok || !close_ok ||
            !MoveFileExW(
              temporary_path.c_str(),
              path_.c_str(),
              MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
            )) {
          DeleteFileW(temporary_path.c_str());
          return false;
        }
        return true;
      } catch (...) {
        return false;
      }
    }

  private:
    static bool read_bytes(const std::wstring &path, std::vector<std::uint8_t> &bytes) {
      const auto file = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
      );
      if (file == INVALID_HANDLE_VALUE) {
        return false;
      }
      LARGE_INTEGER size {};
      if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
          size.QuadPart > static_cast<LONGLONG>(lumen::msquic::cng::maximum_serialized_bytes)) {
        CloseHandle(file);
        SetLastError(ERROR_INVALID_DATA);
        return false;
      }
      bytes.resize(static_cast<std::size_t>(size.QuadPart));
      DWORD read {};
      const auto read_ok = ReadFile(
                             file,
                             bytes.data(),
                             static_cast<DWORD>(bytes.size()),
                             &read,
                             nullptr
                           ) &&
                           read == bytes.size();
      const auto close_ok = CloseHandle(file) != FALSE;
      if (!read_ok || !close_ok) {
        SetLastError(ERROR_READ_FAULT);
        return false;
      }
      return true;
    }

    std::wstring path_;
  };

  /**
   * @brief Read one nonempty null-terminated CNG string property.
   * @param key Live CNG key handle.
   * @param property Property name.
   * @param output Destination string.
   * @return True when the property was read without truncation.
   */
  bool read_ncrypt_string_property(
    const NCRYPT_KEY_HANDLE key,
    const wchar_t *const property,
    std::wstring &output
  ) {
    DWORD byte_count {};
    if (NCryptGetProperty(key, property, nullptr, 0, &byte_count, 0) != ERROR_SUCCESS ||
        byte_count < sizeof(wchar_t) || byte_count % sizeof(wchar_t) != 0) {
      return false;
    }
    std::vector<wchar_t> value(byte_count / sizeof(wchar_t));
    if (NCryptGetProperty(
          key,
          property,
          reinterpret_cast<PBYTE>(value.data()),
          byte_count,
          &byte_count,
          0
        ) != ERROR_SUCCESS) {
      return false;
    }
    const auto terminator = std::ranges::find(value, L'\0');
    if (terminator == value.end() || terminator == value.begin()) {
      return false;
    }
    output.assign(value.begin(), terminator);
    return true;
  }

  /** @brief Exact provider/container CNG operations used by the portable reaper. */
  class WindowsCngKeyBackend final: public lumen::msquic::cng::KeyBackend {
  public:
    OpenResult open(const lumen::msquic::cng::KeyIdentity &identity) noexcept override {
      try {
        const auto provider_name = native_string(identity.provider);
        const auto container_name = native_string(identity.container);
        NCRYPT_PROV_HANDLE provider {};
        if (NCryptOpenStorageProvider(&provider, provider_name.c_str(), 0) != ERROR_SUCCESS) {
          return {};
        }
        NCRYPT_KEY_HANDLE key {};
        const auto open_status = NCryptOpenKey(
          provider,
          &key,
          container_name.c_str(),
          0,
          NCRYPT_SILENT_FLAG | (identity.machine_key ? NCRYPT_MACHINE_KEY_FLAG : 0)
        );
        NCryptFreeObject(provider);
        if (open_status == NTE_BAD_KEYSET) {
          return {.status = OpenStatus::missing};
        }
        if (open_status != ERROR_SUCCESS || !key) {
          return {};
        }
        std::wstring unique_name;
        if (!read_ncrypt_string_property(key, NCRYPT_UNIQUE_NAME_PROPERTY, unique_name)) {
          NCryptFreeObject(key);
          return {};
        }
        return {
          .status = OpenStatus::opened,
          .handle = static_cast<Handle>(key),
          .unique_name = portable_string(unique_name),
        };
      } catch (...) {
        return {};
      }
    }

    bool delete_key(const Handle handle) noexcept override {
      last_status_ = NCryptDeleteKey(static_cast<NCRYPT_KEY_HANDLE>(handle), 0);
      return last_status_ == ERROR_SUCCESS;
    }

    void free_key(const Handle handle) noexcept override {
      if (handle) {
        NCryptFreeObject(static_cast<NCRYPT_HANDLE>(handle));
      }
    }

    SECURITY_STATUS last_status() const noexcept {
      return last_status_;
    }

  private:
    SECURITY_STATUS last_status_ {ERROR_SUCCESS};
  };

  /** @brief Move-only owner for one exact journal-authorized persisted CNG key. */
  class PersistedCngKey {
  public:
    PersistedCngKey() = default;

    PersistedCngKey(
      const NCRYPT_KEY_HANDLE handle,
      lumen::msquic::cng::KeyIdentity identity,
      std::shared_ptr<lumen::msquic::cng::OwnedKeyJournal> journal
    ) noexcept:
        identity_ {std::move(identity)},
        journal_ {std::move(journal)},
        handle_ {handle} {
    }

    PersistedCngKey(const PersistedCngKey &) = delete;
    PersistedCngKey &operator=(const PersistedCngKey &) = delete;

    PersistedCngKey(PersistedCngKey &&other) noexcept:
        identity_ {std::move(other.identity_)},
        journal_ {std::move(other.journal_)},
        handle_ {std::exchange(other.handle_, 0)} {
    }

    PersistedCngKey &operator=(PersistedCngKey &&other) noexcept {
      if (this != &other) {
        static_cast<void>(cleanup_with_report());
        identity_ = std::move(other.identity_);
        journal_ = std::move(other.journal_);
        handle_ = std::exchange(other.handle_, 0);
      }
      return *this;
    }

    ~PersistedCngKey() {
      static_cast<void>(cleanup_with_report());
    }

    bool cleanup() noexcept {
      if (!handle_) {
        return true;
      }
      WindowsCngKeyBackend backend;
      const auto cleanup = journal_ ?
                             journal_->release_owned(identity_, static_cast<std::uintptr_t>(handle_), backend) :
                             lumen::msquic::cng::Result {
                               .status = lumen::msquic::cng::Status::not_owned,
                             };
      if (!journal_) {
        backend.free_key(static_cast<std::uintptr_t>(handle_));
      }
      handle_ = 0;
      last_cleanup_status_ = backend.last_status();
      if (cleanup.status != lumen::msquic::cng::Status::success &&
          last_cleanup_status_ == ERROR_SUCCESS) {
        last_cleanup_status_ = NTE_INTERNAL_ERROR;
      }
      return cleanup.status == lumen::msquic::cng::Status::success;
    }

    bool cleanup_with_report() noexcept {
      const auto cleaned = cleanup();
      if (!cleaned) {
        report_cleanup_failure(last_cleanup_status_);
      }
      return cleaned;
    }

  private:
    lumen::msquic::cng::KeyIdentity identity_;
    std::shared_ptr<lumen::msquic::cng::OwnedKeyJournal> journal_;
    NCRYPT_KEY_HANDLE handle_ {};
    SECURITY_STATUS last_cleanup_status_ {ERROR_SUCCESS};
  };

  /** @brief Result of inspecting one imported certificate for a private key. */
  struct PersistedCngKeyAcquisition {
    bool private_key_present {};  ///< The certificate carried a provider-backed private key.
    bool rollback_complete {true};  ///< Any partially acquired key was deleted.
    std::optional<PersistedCngKey> key;  ///< Exact cleanup owner on success.
  };

  /**
   * @brief Acquire cleanup ownership for one imported certificate private key.
   * @param certificate Imported certificate context.
   * @return Key presence, rollback status, and move-only key owner.
   */
  PersistedCngKeyAcquisition acquire_persisted_cng_key(
    const PCCERT_CONTEXT certificate,
    const std::shared_ptr<lumen::msquic::cng::OwnedKeyJournal> &journal
  ) noexcept {
    DWORD property_bytes {};
    if (!CertGetCertificateContextProperty(
          certificate,
          CERT_KEY_PROV_INFO_PROP_ID,
          nullptr,
          &property_bytes
        )) {
      return {};
    }
    PersistedCngKeyAcquisition result {
      .private_key_present = true,
    };
    std::array<std::uint8_t, 4'096> property {};
    if (property_bytes < sizeof(CRYPT_KEY_PROV_INFO) || property_bytes > property.size()) {
      result.rollback_complete = false;
      return result;
    }
    if (!CertGetCertificateContextProperty(
          certificate,
          CERT_KEY_PROV_INFO_PROP_ID,
          property.data(),
          &property_bytes
        )) {
      result.rollback_complete = false;
      return result;
    }
    const auto *const provider_info = reinterpret_cast<const CRYPT_KEY_PROV_INFO *>(property.data());
    if (!provider_info->pwszProvName || !provider_info->pwszContainerName ||
        *provider_info->pwszProvName == L'\0' || *provider_info->pwszContainerName == L'\0' ||
        provider_info->dwProvType != 0) {
      result.rollback_complete = false;
      return result;
    }

    const auto reopen_key = [&]() noexcept {
      NCRYPT_PROV_HANDLE storage_provider {};
      if (NCryptOpenStorageProvider(&storage_provider, provider_info->pwszProvName, 0) != ERROR_SUCCESS) {
        return NCRYPT_KEY_HANDLE {};
      }
      NCRYPT_KEY_HANDLE reopened_key {};
      auto open_flags = (provider_info->dwFlags & CRYPT_MACHINE_KEYSET) != 0 ?
                          static_cast<DWORD>(NCRYPT_MACHINE_KEY_FLAG) :
                          DWORD {};
      const auto open_status = NCryptOpenKey(
        storage_provider,
        &reopened_key,
        provider_info->pwszContainerName,
        0,
        NCRYPT_SILENT_FLAG | open_flags
      );
      NCryptFreeObject(storage_provider);
      return open_status == ERROR_SUCCESS ? reopened_key : NCRYPT_KEY_HANDLE {};
    };

    const auto delete_unjournaled = [](const NCRYPT_KEY_HANDLE key) noexcept {
      WindowsCngKeyBackend backend;
      if (backend.delete_key(static_cast<std::uintptr_t>(key))) {
        return true;
      }
      backend.free_key(static_cast<std::uintptr_t>(key));
      report_cleanup_failure(backend.last_status());
      return false;
    };

    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key {};
    DWORD key_spec {};
    BOOL caller_frees {};
    if (CryptAcquireCertificatePrivateKey(
          certificate,
          CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
          nullptr,
          &key,
          &key_spec,
          &caller_frees
        )) {
      if (key_spec != CERT_NCRYPT_KEY_SPEC) {
        if (caller_frees) {
          CryptReleaseContext(key, 0);
        }
        result.rollback_complete = false;
        return result;
      }
      if (caller_frees) {
        NCryptFreeObject(key);
      }
    }

    const auto reopened_key = reopen_key();
    if (!reopened_key) {
      result.rollback_complete = false;
      return result;
    }
    try {
      std::wstring unique_name;
      if (!read_ncrypt_string_property(
            reopened_key,
            NCRYPT_UNIQUE_NAME_PROPERTY,
            unique_name
          )) {
        result.rollback_complete = delete_unjournaled(reopened_key);
        return result;
      }
      lumen::msquic::cng::KeyIdentity identity {
        .provider = portable_string(provider_info->pwszProvName),
        .container = portable_string(provider_info->pwszContainerName),
        .unique_name = portable_string(unique_name),
        .machine_key = (provider_info->dwFlags & CRYPT_MACHINE_KEYSET) != 0,
      };
      if (!journal) {
        result.rollback_complete = delete_unjournaled(reopened_key);
        return result;
      }
      const auto record_status = journal->record_before_escape(identity);
      if (record_status != lumen::msquic::cng::Status::success) {
        if (record_status == lumen::msquic::cng::Status::already_owned) {
          NCryptFreeObject(reopened_key);
          result.rollback_complete = false;
        } else {
          result.rollback_complete = delete_unjournaled(reopened_key);
        }
        return result;
      }
      result.key.emplace(reopened_key, std::move(identity), journal);
    } catch (...) {
      result.rollback_complete = delete_unjournaled(reopened_key);
    }
    return result;
  }

  /** @brief Cursor that frees the current store-owned enumerated certificate on every exit. */
  class CertificateEnumeration {
  public:
    /** @brief Begin a certificate-store enumeration. */
    explicit CertificateEnumeration(const HCERTSTORE store) noexcept:
        store_ {store} {
    }

    CertificateEnumeration(const CertificateEnumeration &) = delete;
    CertificateEnumeration &operator=(const CertificateEnumeration &) = delete;

    ~CertificateEnumeration() {
      if (current_) {
        CertFreeCertificateContext(current_);
      }
    }

    /** @brief Advance while transferring the previous context back to Crypt32. */
    PCCERT_CONTEXT next() noexcept {
      const auto previous = std::exchange(current_, nullptr);
      current_ = CertEnumCertificatesInStore(store_, previous);
      return current_;
    }

  private:
    HCERTSTORE store_ {};  ///< Store being enumerated.
    PCCERT_CONTEXT current_ {};  ///< Current store-owned context.
  };

  struct CredentialContext {
    HCERTSTORE store {};  ///< In-memory certificate store returned by PFXImportCertStore.
    PCCERT_CONTEXT certificate {};  ///< Leaf context retained for the Schannel credential.
    std::array<uint8_t, 32> spki {};  ///< Exact DER-SPKI SHA-256 for invitation pinning.
    std::vector<PersistedCngKey> persisted_keys;  ///< Every imported private key, each with exact cleanup ownership.

    ~CredentialContext() {
      static_cast<void>(release());
    }

    /**
     * @brief Release certificate references before deleting every imported key.
     * @return True when every temporary CNG key was deleted.
     */
    bool release() noexcept {
      if (certificate) {
        CertFreeCertificateContext(certificate);
        certificate = nullptr;
      }
      if (store) {
        CertCloseStore(store, 0);
        store = nullptr;
      }
      bool cleaned = true;
      for (auto &key : persisted_keys) {
        if (!key.cleanup_with_report()) {
          cleaned = false;
        }
      }
      persisted_keys.clear();
      return cleaned;
    }
  };

  std::wstring wide(const char *value) {
    if (!value) {
      return {};
    }
    const auto required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, -1, nullptr, 0);
    if (required <= 1) {
      return {};
    }
    std::wstring output(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, -1, output.data(), required) != required) {
      return {};
    }
    output.pop_back();
    return output;
  }

  struct SecureWide {
    std::wstring value;
    ~SecureWide() {
      if (!value.empty()) {
        SecureZeroMemory(value.data(), value.size() * sizeof(wchar_t));
      }
    }
  };

  struct SendContext {
    static constexpr size_t maximum_buffers = 4;
    std::array<QUIC_BUFFER, maximum_buffers> buffers {};
    uint32_t buffer_count {};
    uint64_t token {};
    bool active {};
  };

  struct SendRegistry {
    static constexpr size_t maximum_sends = 260;
    std::mutex mutex;
    std::array<SendContext, maximum_sends> slots {};
    size_t next {};

    SendContext *acquire() noexcept {
      std::lock_guard lock {mutex};
      for (size_t offset = 0; offset < slots.size(); ++offset) {
        const auto index = (next + offset) % slots.size();
        auto &slot = slots[index];
        if (slot.active) {
          continue;
        }
        slot = {};
        slot.active = true;
        next = (index + 1) % slots.size();
        return &slot;
      }
      return nullptr;
    }

    void release(SendContext *send) noexcept {
      std::lock_guard lock {mutex};
      const auto address = reinterpret_cast<uintptr_t>(send);
      const auto first = reinterpret_cast<uintptr_t>(slots.data());
      const auto last = first + sizeof(slots);
      if (address >= first && address < last && (address - first) % sizeof(SendContext) == 0) {
        send->active = false;
      }
    }
  };

  struct ConnectionContext: std::enable_shared_from_this<ConnectionContext> {
    lumen_msquic_shim *shim {};
    const QUIC_API_TABLE *api {};
    lumen_msquic_connection_callback callback {};
    void *context {};
    std::shared_ptr<SendRegistry> sends;
  };

  struct StreamContext: std::enable_shared_from_this<StreamContext> {
    lumen_msquic_stream_callback callback {};
    void *context {};
    std::shared_ptr<SendRegistry> sends;
  };

  std::optional<uint64_t> complete_send(
    SendRegistry *registry,
    void *key
  ) {
    std::lock_guard lock {registry->mutex};
    auto *const send = static_cast<SendContext *>(key);
    const auto address = reinterpret_cast<uintptr_t>(send);
    const auto first = reinterpret_cast<uintptr_t>(registry->slots.data());
    const auto last = first + sizeof(registry->slots);
    if (address < first || address >= last || (address - first) % sizeof(SendContext) != 0 || !send->active) {
      return std::nullopt;
    }
    const auto token = send->token;
    send->active = false;
    return token;
  }

  void associate_stream_send_registry(
    lumen_msquic_shim *shim,
    HQUIC stream,
    const std::shared_ptr<SendRegistry> &registry
  );

  QUIC_STATUS QUIC_API listener_callback(HQUIC, void *raw, QUIC_LISTENER_EVENT *event) {
    auto retained = static_cast<ListenerContext *>(raw)->shared_from_this();
    lumen_msquic_listener_event output {};
    if (event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION) {
      output.kind = LUMEN_MSQUIC_LISTENER_NEW_CONNECTION;
      output.connection = portable(event->NEW_CONNECTION.Connection);
      const auto *remote = event->NEW_CONNECTION.Info->RemoteAddress;
      output.remote_address_family = QuicAddrGetFamily(remote);
      if (output.remote_address_family == QUIC_ADDRESS_FAMILY_INET) {
        std::copy_n(
          reinterpret_cast<const uint8_t *>(&remote->Ipv4.sin_addr),
          4,
          output.remote_address
        );
      } else if (output.remote_address_family == QUIC_ADDRESS_FAMILY_INET6) {
        std::copy_n(
          reinterpret_cast<const uint8_t *>(&remote->Ipv6.sin6_addr),
          16,
          output.remote_address
        );
      }
    } else if (event->Type == QUIC_LISTENER_EVENT_STOP_COMPLETE) {
      output.kind = LUMEN_MSQUIC_LISTENER_STOP_COMPLETE;
    } else {
      return QUIC_STATUS_SUCCESS;
    }
    return retained->callback(retained->context, &output) == LUMEN_MSQUIC_SUCCESS ?
             QUIC_STATUS_SUCCESS :
             QUIC_STATUS_ABORTED;
  }

  QUIC_STATUS QUIC_API connection_callback(HQUIC, void *raw, QUIC_CONNECTION_EVENT *event) {
    auto retained = static_cast<ConnectionContext *>(raw)->shared_from_this();
    lumen_msquic_connection_event output {};
    switch (event->Type) {
      case QUIC_CONNECTION_EVENT_CONNECTED:
        output.kind = LUMEN_MSQUIC_CONNECTION_CONNECTED;
        output.resumed = event->CONNECTED.SessionResumed != FALSE;
        break;
      case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
        output.kind = LUMEN_MSQUIC_CONNECTION_DATAGRAM_STATE;
        output.datagram_enabled = event->DATAGRAM_STATE_CHANGED.SendEnabled != FALSE;
        output.maximum_datagram_bytes = event->DATAGRAM_STATE_CHANGED.MaxSendLength;
        break;
      case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
        output.kind = LUMEN_MSQUIC_CONNECTION_DATAGRAM_RECEIVED;
        output.bytes = event->DATAGRAM_RECEIVED.Buffer->Buffer;
        output.byte_count = event->DATAGRAM_RECEIVED.Buffer->Length;
        break;
      case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
        if (!QUIC_DATAGRAM_SEND_STATE_IS_FINAL(event->DATAGRAM_SEND_STATE_CHANGED.State)) {
          return QUIC_STATUS_SUCCESS;
        }
        output.kind = LUMEN_MSQUIC_CONNECTION_DATAGRAM_SEND_COMPLETE;
        {
          const auto token = complete_send(
            retained->sends.get(),
            event->DATAGRAM_SEND_STATE_CHANGED.ClientContext
          );
          if (!token) {
            return QUIC_STATUS_ABORTED;
          }
          output.send_token = *token;
        }
        output.canceled = event->DATAGRAM_SEND_STATE_CHANGED.State == QUIC_DATAGRAM_SEND_CANCELED;
        break;
      case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        output.kind = LUMEN_MSQUIC_CONNECTION_PEER_STREAM;
        output.stream = portable(event->PEER_STREAM_STARTED.Stream);
        output.peer_stream_unidirectional =
          (event->PEER_STREAM_STARTED.Flags & QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL) != 0;
        associate_stream_send_registry(retained->shim, event->PEER_STREAM_STARTED.Stream, retained->sends);
        {
          uint32_t length = sizeof(output.stream_id);
          if (QUIC_FAILED(retained->api->GetParam(
                event->PEER_STREAM_STARTED.Stream,
                QUIC_PARAM_STREAM_ID,
                &length,
                &output.stream_id
              ))) {
            return QUIC_STATUS_ABORTED;
          }
        }
        break;
      case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        output.kind = LUMEN_MSQUIC_CONNECTION_SHUTDOWN_TRANSPORT;
        output.error = static_cast<uint64_t>(event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        break;
      case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        output.kind = LUMEN_MSQUIC_CONNECTION_SHUTDOWN_PEER;
        output.error = event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode;
        break;
      case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        output.kind = LUMEN_MSQUIC_CONNECTION_SHUTDOWN_COMPLETE;
        break;
      default:
        return QUIC_STATUS_SUCCESS;
    }
    return retained->callback(retained->context, &output) == LUMEN_MSQUIC_SUCCESS ?
             QUIC_STATUS_SUCCESS :
             QUIC_STATUS_ABORTED;
  }

  QUIC_STATUS QUIC_API stream_callback(HQUIC, void *raw, QUIC_STREAM_EVENT *event) {
    auto retained = static_cast<StreamContext *>(raw)->shared_from_this();
    lumen_msquic_stream_event output {};
    std::vector<lumen_msquic_buffer> buffers;
    switch (event->Type) {
      case QUIC_STREAM_EVENT_RECEIVE:
        output.kind = LUMEN_MSQUIC_STREAM_RECEIVE;
        buffers.reserve(event->RECEIVE.BufferCount);
        for (uint32_t index = 0; index < event->RECEIVE.BufferCount; ++index) {
          buffers.push_back({event->RECEIVE.Buffers[index].Buffer, event->RECEIVE.Buffers[index].Length});
        }
        output.buffers = buffers.data();
        output.buffer_count = buffers.size();
        output.total_buffer_bytes = event->RECEIVE.TotalBufferLength;
        break;
      case QUIC_STREAM_EVENT_SEND_COMPLETE:
        output.kind = LUMEN_MSQUIC_STREAM_SEND_COMPLETE;
        {
          const auto token = complete_send(retained->sends.get(), event->SEND_COMPLETE.ClientContext);
          if (!token) {
            return QUIC_STATUS_ABORTED;
          }
          output.send_token = *token;
        }
        output.canceled = event->SEND_COMPLETE.Canceled != FALSE;
        break;
      case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:
        output.kind = LUMEN_MSQUIC_STREAM_WRITABLE;
        break;
      case QUIC_STREAM_EVENT_START_COMPLETE:
        output.kind = LUMEN_MSQUIC_STREAM_START_COMPLETE;
        output.error = static_cast<uint64_t>(event->START_COMPLETE.Status);
        output.canceled = QUIC_FAILED(event->START_COMPLETE.Status);
        break;
      case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        output.kind = LUMEN_MSQUIC_STREAM_PEER_SEND_SHUTDOWN;
        break;
      case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        output.kind = LUMEN_MSQUIC_STREAM_PEER_SEND_ABORTED;
        output.error = event->PEER_SEND_ABORTED.ErrorCode;
        break;
      case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        output.kind = LUMEN_MSQUIC_STREAM_PEER_RECEIVE_ABORTED;
        output.error = event->PEER_RECEIVE_ABORTED.ErrorCode;
        break;
      case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
        output.kind = LUMEN_MSQUIC_STREAM_SEND_SHUTDOWN_COMPLETE;
        break;
      case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        output.kind = LUMEN_MSQUIC_STREAM_SHUTDOWN_COMPLETE;
        break;
      default:
        return QUIC_STATUS_SUCCESS;
    }
    return retained->callback(retained->context, &output) == LUMEN_MSQUIC_SUCCESS ?
             QUIC_STATUS_SUCCESS :
             QUIC_STATUS_ABORTED;
  }
}  // namespace

struct lumen_msquic_shim {
  const QUIC_API_TABLE *api {};
  std::mutex mutex;
  std::map<HQUIC, std::shared_ptr<ListenerContext>> listeners;
  std::map<HQUIC, std::shared_ptr<ConnectionContext>> connections;
  std::map<HQUIC, std::shared_ptr<StreamContext>> streams;
  std::map<HQUIC, std::weak_ptr<SendRegistry>> stream_send_registries;
  std::map<HQUIC, std::shared_ptr<CredentialContext>> configuration_credentials;
  std::shared_ptr<lumen::msquic::cng::OwnedKeyJournal> cng_journal;
};

namespace {
  void associate_stream_send_registry(
    lumen_msquic_shim *shim,
    HQUIC stream,
    const std::shared_ptr<SendRegistry> &registry
  ) {
    std::lock_guard lock {shim->mutex};
    shim->stream_send_registries[stream] = registry;
  }
}  // namespace

extern "C" {
  lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_open(
    const uint32_t requested_abi,
    lumen_msquic_shim **output
  ) {
    if (requested_abi != LUMEN_MSQUIC_SHIM_ABI_VERSION || output == nullptr) {
      return LUMEN_MSQUIC_INVALID_STATE;
    }
    std::unique_ptr<lumen_msquic_shim> shim;
    try {
      shim = std::make_unique<lumen_msquic_shim>();
    } catch (...) {
      return LUMEN_MSQUIC_OUT_OF_MEMORY;
    }
    const auto result = MsQuicOpenVersion(QUIC_API_VERSION_2, reinterpret_cast<const void **>(&shim->api));
    if (QUIC_FAILED(result)) {
      return status(result);
    }
    *output = shim.release();
    return LUMEN_MSQUIC_SUCCESS;
  }

  lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_close(lumen_msquic_shim *shim) {
    if (shim == nullptr) {
      return LUMEN_MSQUIC_SUCCESS;
    }
    if (shim->api != nullptr) {
      MsQuicClose(shim->api);
    }
    auto cleanup_status = LUMEN_MSQUIC_SUCCESS;
    for (auto &[configuration, credential] : shim->configuration_credentials) {
      static_cast<void>(configuration);
      if (credential && !credential->release()) {
        cleanup_status = LUMEN_MSQUIC_CLEANUP_ERROR;
      }
    }
    shim->configuration_credentials.clear();
    delete shim;
    return cleanup_status;
  }

  int LUMEN_MSQUIC_CALL lumen_msquic_is_schannel(lumen_msquic_shim *shim) {
    if (shim == nullptr || shim->api == nullptr) {
      return 0;
    }
    QUIC_TLS_PROVIDER provider {};
    uint32_t length = sizeof(provider);
    return QUIC_SUCCEEDED(shim->api->GetParam(nullptr, QUIC_PARAM_GLOBAL_TLS_PROVIDER, &length, &provider)) &&
           provider == QUIC_TLS_PROVIDER_SCHANNEL;
  }

  lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_set_cng_journal_path(
    lumen_msquic_shim *shim,
    const char *journal_path
  ) {
    if (!shim || !journal_path) {
      return LUMEN_MSQUIC_INVALID_STATE;
    }
    try {
      auto path = wide(journal_path);
      if (path.empty()) {
        return LUMEN_MSQUIC_INVALID_STATE;
      }
      auto store = std::make_shared<WindowsCngJournalStore>(std::move(path));
      auto journal = std::make_shared<lumen::msquic::cng::OwnedKeyJournal>(std::move(store));
      WindowsCngKeyBackend backend;
      std::lock_guard lock {shim->mutex};
      if (!shim->configuration_credentials.empty()) {
        return LUMEN_MSQUIC_INVALID_STATE;
      }
      const auto reaped = journal->reap(backend);
      shim->cng_journal = std::move(journal);
      return reaped.status == lumen::msquic::cng::Status::success ?
               LUMEN_MSQUIC_SUCCESS :
               LUMEN_MSQUIC_CLEANUP_ERROR;
    } catch (...) {
      return LUMEN_MSQUIC_OUT_OF_MEMORY;
    }
  }

  lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_registration_open(
    lumen_msquic_shim *shim,
    const char *name,
    lumen_msquic_handle *output
  ) {
    if (!shim || !name || !output) {
      return LUMEN_MSQUIC_INVALID_STATE;
    }
    QUIC_REGISTRATION_CONFIG config {name, QUIC_EXECUTION_PROFILE_LOW_LATENCY};
    HQUIC handle {};
    const auto result = status(shim->api->RegistrationOpen(&config, &handle));
    if (result == LUMEN_MSQUIC_SUCCESS || result == LUMEN_MSQUIC_PENDING) {
      *output = portable(handle);
    }
    return result;
  }

  void LUMEN_MSQUIC_CALL lumen_msquic_registration_close(lumen_msquic_shim *s, lumen_msquic_handle h) {
    s->api->RegistrationClose(native(h));
  }

  lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_configuration_open(
    lumen_msquic_shim *s,
    lumen_msquic_handle r,
    const uint8_t *alpn,
    size_t alpn_length,
    uint16_t bidi,
    uint16_t unidi,
    uint64_t handshake_timeout_ms,
    uint64_t initial_idle_timeout_ms,
    lumen_msquic_handle *output
  ) {
    if (!s || !alpn || alpn_length == 0 || alpn_length > UINT32_MAX ||
        handshake_timeout_ms == 0 || initial_idle_timeout_ms == 0 || !output) {
      return LUMEN_MSQUIC_INVALID_STATE;
    }
    QUIC_SETTINGS settings {};
    settings.IsSet.PeerBidiStreamCount = TRUE;
    settings.PeerBidiStreamCount = bidi;
    settings.IsSet.PeerUnidiStreamCount = TRUE;
    settings.PeerUnidiStreamCount = unidi;
    settings.IsSet.DatagramReceiveEnabled = TRUE;
    settings.DatagramReceiveEnabled = TRUE;
    settings.IsSet.ServerResumptionLevel = TRUE;
    settings.ServerResumptionLevel = QUIC_SERVER_NO_RESUME;
    settings.IsSet.HandshakeIdleTimeoutMs = TRUE;
    settings.HandshakeIdleTimeoutMs = handshake_timeout_ms;
    settings.IsSet.IdleTimeoutMs = TRUE;
    settings.IdleTimeoutMs = initial_idle_timeout_ms;
    settings.IsSet.SendBufferingEnabled = TRUE;
    settings.SendBufferingEnabled = FALSE;
    settings.IsSet.PacingEnabled = TRUE;
    settings.PacingEnabled = TRUE;
    QUIC_BUFFER buffer {static_cast<uint32_t>(alpn_length), const_cast<uint8_t *>(alpn)};
    HQUIC handle {};
    const auto result = status(s->api->ConfigurationOpen(native(r), &buffer, 1, &settings, sizeof(settings), nullptr, &handle));
    if (result == LUMEN_MSQUIC_SUCCESS || result == LUMEN_MSQUIC_PENDING) {
      *output = portable(handle);
    }
    return result;
  }

  lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_configuration_load_pkcs12(
    lumen_msquic_shim *s,
    lumen_msquic_handle h,
    const uint8_t *pkcs12,
    size_t pkcs12_size,
    const char *password
  ) {
    if (!s || !pkcs12 || pkcs12_size == 0 || pkcs12_size > UINT32_MAX || !password) {
      return LUMEN_MSQUIC_INVALID_STATE;
    }
    std::shared_ptr<lumen::msquic::cng::OwnedKeyJournal> journal;
    {
      std::lock_guard lock {s->mutex};
      journal = s->cng_journal;
    }
    if (!journal) {
      return LUMEN_MSQUIC_INVALID_STATE;
    }
    std::shared_ptr<CredentialContext> credential;
    bool rollback_complete = true;
    const auto fail = [&](const lumen_msquic_status status) {
      const auto cleaned = !credential || credential->release();
      return rollback_complete && cleaned ? status : LUMEN_MSQUIC_CLEANUP_ERROR;
    };
    try {
      SecureWide import_password {wide(password)};
      if (import_password.value.empty()) {
        return LUMEN_MSQUIC_INVALID_STATE;
      }
      CRYPT_DATA_BLOB blob {
        static_cast<DWORD>(pkcs12_size),
        const_cast<BYTE *>(pkcs12),
      };
      credential = std::make_shared<CredentialContext>();
      DWORD import_flags = CRYPT_USER_KEYSET;
#ifdef PKCS12_ALWAYS_CNG_KSP
      import_flags |= PKCS12_ALWAYS_CNG_KSP;
#endif
      credential->store = PFXImportCertStore(
        &blob,
        import_password.value.c_str(),
        import_flags
      );
      if (!credential->store) {
        return LUMEN_MSQUIC_TRANSPORT_ERROR;
      }
      std::size_t private_key_certificates = 0;
      bool discovery_failed = false;
      {
        CertificateEnumeration certificates {credential->store};
        while (const auto candidate = certificates.next()) {
          auto acquisition = acquire_persisted_cng_key(candidate, journal);
          if (!acquisition.private_key_present) {
            continue;
          }
          ++private_key_certificates;
          rollback_complete = rollback_complete && acquisition.rollback_complete;
          if (!acquisition.key) {
            discovery_failed = true;
            continue;
          }
          if (private_key_certificates == 1) {
            credential->certificate = CertDuplicateCertificateContext(candidate);
            if (!credential->certificate) {
              discovery_failed = true;
            }
          }
          try {
            credential->persisted_keys.push_back(std::move(*acquisition.key));
          } catch (...) {
            rollback_complete = acquisition.key->cleanup() && rollback_complete;
            discovery_failed = true;
          }
        }
      }
      if (discovery_failed || private_key_certificates != 1 ||
          credential->persisted_keys.size() != 1 || !credential->certificate ||
          !leaf_spki_sha256(credential->certificate, credential->spki)) {
        return fail(LUMEN_MSQUIC_TRANSPORT_ERROR);
      }
      QUIC_CREDENTIAL_CONFIG config {};
      config.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT;
      config.CertificateContext = reinterpret_cast<QUIC_CERTIFICATE *>(
        const_cast<CERT_CONTEXT *>(credential->certificate)
      );
      const auto result = status(s->api->ConfigurationLoadCredential(native(h), &config));
      if (result == LUMEN_MSQUIC_SUCCESS || result == LUMEN_MSQUIC_PENDING) {
        std::lock_guard lock {s->mutex};
        s->configuration_credentials[native(h)] = std::move(credential);
        return result;
      }
      return fail(result);
    } catch (...) {
      return fail(LUMEN_MSQUIC_OUT_OF_MEMORY);
    }
  }

  lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_configuration_leaf_spki_sha256(
    lumen_msquic_shim *s,
    lumen_msquic_handle h,
    uint8_t output[32]
  ) {
    if (!s || !output) {
      return LUMEN_MSQUIC_INVALID_STATE;
    }
    std::lock_guard lock {s->mutex};
    const auto found = s->configuration_credentials.find(native(h));
    if (found == s->configuration_credentials.end()) {
      return LUMEN_MSQUIC_INVALID_STATE;
    }
    std::copy(found->second->spki.begin(), found->second->spki.end(), output);
    return LUMEN_MSQUIC_SUCCESS;
  }

  void LUMEN_MSQUIC_CALL lumen_msquic_configuration_close(lumen_msquic_shim *s, lumen_msquic_handle h) {
    if (!s) {
      return;
    }
    const auto handle = native(h);
    s->api->ConfigurationClose(handle);
    std::shared_ptr<CredentialContext> credential;
    {
      std::lock_guard lock {s->mutex};
      auto owned = s->configuration_credentials.extract(handle);
      if (!owned.empty()) {
        credential = std::move(owned.mapped());
      }
    }
    if (credential) {
      static_cast<void>(credential->release());
    }
  }

  lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_listener_open(
    lumen_msquic_shim *s,
    lumen_msquic_handle r,
    lumen_msquic_listener_callback cb,
    void *ctx,
    lumen_msquic_handle *output
  ) {
    if (!s || !cb || !output) {
      return LUMEN_MSQUIC_INVALID_STATE;
    }
    auto holder = std::make_shared<ListenerContext>();
    holder->callback = cb;
    holder->context = ctx;
    HQUIC handle {};
    const auto result = status(s->api->ListenerOpen(native(r), &listener_callback, holder.get(), &handle));
    if (result == LUMEN_MSQUIC_SUCCESS || result == LUMEN_MSQUIC_PENDING) {
      std::lock_guard lock {s->mutex};
      s->listeners.emplace(handle, std::move(holder));
      *output = portable(handle);
    }
    return result;
  }

  lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_listener_start(
    lumen_msquic_shim *s,
    lumen_msquic_handle h,
    const uint8_t *alpn,
    size_t length,
    uint16_t port
  ) {
    if (!s || !alpn || length == 0 || length > UINT32_MAX) {
      return LUMEN_MSQUIC_INVALID_STATE;
    }
    QUIC_BUFFER buffer {static_cast<uint32_t>(length), const_cast<uint8_t *>(alpn)};
    QUIC_ADDR address {};
    QuicAddrSetFamily(&address, QUIC_ADDRESS_FAMILY_UNSPEC);
    QuicAddrSetPort(&address, port);
    return status(s->api->ListenerStart(native(h), &buffer, 1, &address));
  }

  void LUMEN_MSQUIC_CALL lumen_msquic_listener_stop(lumen_msquic_shim *s, lumen_msquic_handle h) {
    s->api->ListenerStop(native(h));
  }

  void LUMEN_MSQUIC_CALL lumen_msquic_listener_close(lumen_msquic_shim *s, lumen_msquic_handle h) {
    const auto n = native(h);
    s->api->ListenerClose(n);
    std::lock_guard lock {s->mutex};
    s->listeners.erase(n);
  }

  lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_connection_set_callback(
    lumen_msquic_shim *s,
    lumen_msquic_handle h,
    lumen_msquic_connection_callback cb,
    void *ctx
  ) {
    if (!s || !cb) {
      return LUMEN_MSQUIC_INVALID_STATE;
    }
    try {
      auto holder = std::make_shared<ConnectionContext>();
      holder->shim = s;
      holder->api = s->api;
      holder->callback = cb;
      holder->context = ctx;
      holder->sends = std::make_shared<SendRegistry>();
      s->api->SetCallbackHandler(native(h), reinterpret_cast<void *>(&connection_callback), holder.get());
      std::lock_guard lock {s->mutex};
      s->connections[native(h)] = std::move(holder);
      return LUMEN_MSQUIC_SUCCESS;
    } catch (...) {
      return LUMEN_MSQUIC_OUT_OF_MEMORY;
    }
  }

  lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_connection_set_configuration(
    lumen_msquic_shim *s,
    lumen_msquic_handle c,
    lumen_msquic_handle config
  ) {
    return status(s->api->ConnectionSetConfiguration(native(c), native(config)));
  }

  lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_connection_set_idle_timeout(
    lumen_msquic_shim *s,
    lumen_msquic_handle connection,
    uint64_t timeout_ms
  ) {
    if (!s) {
      return LUMEN_MSQUIC_INVALID_STATE;
    }
    QUIC_SETTINGS settings {};
    settings.IsSet.IdleTimeoutMs = TRUE;
    settings.IdleTimeoutMs = timeout_ms;
    return status(s->api->SetParam(
      native(connection),
      QUIC_PARAM_CONN_SETTINGS,
      sizeof(settings),
      &settings
    ));
  }

  void LUMEN_MSQUIC_CALL lumen_msquic_connection_shutdown(lumen_msquic_shim *s, lumen_msquic_handle h, uint64_t e) {
    s->api->ConnectionShutdown(native(h), QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, e);
  }

  void LUMEN_MSQUIC_CALL lumen_msquic_connection_close(lumen_msquic_shim *s, lumen_msquic_handle h) {
    const auto n = native(h);
    s->api->ConnectionClose(n);
    std::lock_guard lock {s->mutex};
    s->connections.erase(n);
  }

  lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_stream_open_unidirectional(
    lumen_msquic_shim *s,
    lumen_msquic_handle connection,
    lumen_msquic_stream_callback cb,
    void *ctx,
    lumen_msquic_handle *output
  ) {
    if (!s || !cb || !output) {
      return LUMEN_MSQUIC_INVALID_STATE;
    }
    try {
      std::shared_ptr<SendRegistry> sends;
      {
        std::lock_guard lock {s->mutex};
        const auto connection_context = s->connections.find(native(connection));
        if (connection_context == s->connections.end()) {
          return LUMEN_MSQUIC_INVALID_STATE;
        }
        sends = connection_context->second->sends;
      }
      auto holder = std::make_shared<StreamContext>();
      holder->callback = cb;
      holder->context = ctx;
      holder->sends = sends;
      HQUIC stream {};
      const auto result = status(s->api->StreamOpen(
        native(connection),
        QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
        &stream_callback,
        holder.get(),
        &stream
      ));
      if (result != LUMEN_MSQUIC_SUCCESS && result != LUMEN_MSQUIC_PENDING) {
        return result;
      }
      {
        std::lock_guard lock {s->mutex};
        s->streams[stream] = std::move(holder);
        s->stream_send_registries[stream] = sends;
      }
      *output = portable(stream);
      return result;
    } catch (...) {
      return LUMEN_MSQUIC_OUT_OF_MEMORY;
    }
  }

  lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_stream_start(
    lumen_msquic_shim *s,
    lumen_msquic_handle h
  ) {
    if (!s || h == 0) {
      return LUMEN_MSQUIC_INVALID_STATE;
    }
    const auto flags = static_cast<QUIC_STREAM_START_FLAGS>(
      QUIC_STREAM_START_FLAG_FAIL_BLOCKED |
      QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL |
      QUIC_STREAM_START_FLAG_INDICATE_PEER_ACCEPT
    );
    return status(s->api->StreamStart(native(h), flags));
  }

  lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_stream_set_callback(
    lumen_msquic_shim *s,
    lumen_msquic_handle h,
    lumen_msquic_stream_callback cb,
    void *ctx
  ) {
    if (!s || !cb) {
      return LUMEN_MSQUIC_INVALID_STATE;
    }
    std::shared_ptr<SendRegistry> sends;
    {
      std::lock_guard lock {s->mutex};
      const auto found = s->stream_send_registries.find(native(h));
      if (found == s->stream_send_registries.end()) {
        return LUMEN_MSQUIC_INVALID_STATE;
      }
      sends = found->second.lock();
      if (!sends) {
        return LUMEN_MSQUIC_INVALID_STATE;
      }
    }
    auto holder = std::make_shared<StreamContext>();
    holder->callback = cb;
    holder->context = ctx;
    holder->sends = sends;
    s->api->SetCallbackHandler(native(h), reinterpret_cast<void *>(&stream_callback), holder.get());
    std::lock_guard lock {s->mutex};
    s->streams[native(h)] = std::move(holder);
    return LUMEN_MSQUIC_SUCCESS;
  }

  lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_stream_send(
    lumen_msquic_shim *s,
    lumen_msquic_handle h,
    const lumen_msquic_buffer *buffers,
    size_t count,
    uint64_t token,
    uint8_t urgent,
    uint8_t fin
  ) {
    if (!s || !buffers || count == 0 || count > SendContext::maximum_buffers) {
      return LUMEN_MSQUIC_INVALID_STATE;
    }
    for (size_t i = 0; i < count; ++i) {
      if (buffers[i].size > UINT32_MAX) {
        return LUMEN_MSQUIC_INVALID_STATE;
      }
    }
    StreamContext *stream {};
    {
      std::lock_guard lock {s->mutex};
      const auto found = s->streams.find(native(h));
      if (found == s->streams.end()) {
        return LUMEN_MSQUIC_INVALID_STATE;
      }
      stream = found->second.get();
    }
    auto *const send = stream->sends->acquire();
    if (send == nullptr) {
      return LUMEN_MSQUIC_OUT_OF_MEMORY;
    }
    send->buffer_count = static_cast<uint32_t>(count);
    send->token = token;
    for (size_t i = 0; i < count; ++i) {
      send->buffers[i] = {static_cast<uint32_t>(buffers[i].size), const_cast<uint8_t *>(buffers[i].data)};
    }
    auto flags = urgent ? QUIC_SEND_FLAG_PRIORITY_WORK : QUIC_SEND_FLAG_NONE;
    if (fin) {
      flags = static_cast<QUIC_SEND_FLAGS>(flags | QUIC_SEND_FLAG_FIN);
    }
    const auto result = status(s->api->StreamSend(native(h), send->buffers.data(), send->buffer_count, flags, send));
    if (result != LUMEN_MSQUIC_SUCCESS && result != LUMEN_MSQUIC_PENDING) {
      stream->sends->release(send);
    }
    return result;
  }

  lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_stream_set_priority(
    lumen_msquic_shim *s,
    lumen_msquic_handle h,
    uint16_t priority
  ) {
    return status(s->api->SetParam(native(h), QUIC_PARAM_STREAM_PRIORITY, sizeof(priority), &priority));
  }

  void LUMEN_MSQUIC_CALL lumen_msquic_stream_receive_complete(lumen_msquic_shim *s, lumen_msquic_handle h, uint64_t bytes) {
    s->api->StreamReceiveComplete(native(h), bytes);
  }

  void LUMEN_MSQUIC_CALL lumen_msquic_stream_shutdown(lumen_msquic_shim *s, lumen_msquic_handle h, uint64_t e) {
    s->api->StreamShutdown(native(h), static_cast<QUIC_STREAM_SHUTDOWN_FLAGS>(QUIC_STREAM_SHUTDOWN_FLAG_ABORT | QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE), e);
  }

  void LUMEN_MSQUIC_CALL lumen_msquic_stream_close(lumen_msquic_shim *s, lumen_msquic_handle h) {
    const auto n = native(h);
    s->api->StreamClose(n);
    std::lock_guard lock {s->mutex};
    s->streams.erase(n);
    s->stream_send_registries.erase(n);
  }

  lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_datagram_send(
    lumen_msquic_shim *s,
    lumen_msquic_handle h,
    const lumen_msquic_buffer *buffers,
    size_t count,
    uint64_t token,
    uint8_t urgent,
    uint8_t cancel
  ) {
    if (!s || !buffers || count == 0 || count > SendContext::maximum_buffers) {
      return LUMEN_MSQUIC_INVALID_STATE;
    }
    for (size_t i = 0; i < count; ++i) {
      if (buffers[i].size > UINT32_MAX) {
        return LUMEN_MSQUIC_INVALID_STATE;
      }
    }
    ConnectionContext *connection {};
    {
      std::lock_guard lock {s->mutex};
      const auto found = s->connections.find(native(h));
      if (found == s->connections.end()) {
        return LUMEN_MSQUIC_INVALID_STATE;
      }
      connection = found->second.get();
    }
    auto *const send = connection->sends->acquire();
    if (send == nullptr) {
      return LUMEN_MSQUIC_OUT_OF_MEMORY;
    }
    send->buffer_count = static_cast<uint32_t>(count);
    send->token = token;
    for (size_t i = 0; i < count; ++i) {
      send->buffers[i] = {static_cast<uint32_t>(buffers[i].size), const_cast<uint8_t *>(buffers[i].data)};
    }
    auto flags = QUIC_SEND_FLAG_NONE;
    if (urgent) {
      flags = static_cast<QUIC_SEND_FLAGS>(flags | QUIC_SEND_FLAG_DGRAM_PRIORITY);
    }
    if (cancel) {
      flags = static_cast<QUIC_SEND_FLAGS>(flags | QUIC_SEND_FLAG_CANCEL_ON_BLOCKED);
    }
    const auto result = status(s->api->DatagramSend(native(h), send->buffers.data(), send->buffer_count, flags, send));
    if (result != LUMEN_MSQUIC_SUCCESS && result != LUMEN_MSQUIC_PENDING) {
      connection->sends->release(send);
    }
    return result;
  }

  lumen_msquic_status LUMEN_MSQUIC_CALL lumen_msquic_connection_statistics(
    lumen_msquic_shim *s,
    lumen_msquic_handle h,
    lumen_msquic_statistics *output
  ) {
    if (!s || !output) {
      return LUMEN_MSQUIC_INVALID_STATE;
    }
    QUIC_STATISTICS_V2 statistics {};
    uint32_t length = QUIC_STATISTICS_V2_SIZE_4;
    const auto result = status(s->api->GetParam(
      native(h),
      QUIC_PARAM_CONN_STATISTICS_V2,
      &length,
      &statistics
    ));
    if (result != LUMEN_MSQUIC_SUCCESS) {
      return result;
    }
    output->smoothed_rtt_microseconds = statistics.Rtt;
    output->minimum_rtt_microseconds = statistics.MinRtt;
    output->congestion_window_bytes = statistics.SendCongestionWindow;
    output->bytes_in_flight = 0;  // Not exposed by stable QUIC_STATISTICS_V2.
    output->packets_lost = statistics.SendSuspectedLostPackets -
                           std::min(statistics.SendSuspectedLostPackets, statistics.SendSpuriousLostPackets);
    output->valid_fields = LUMEN_MSQUIC_STAT_VALID_RTT |
                           LUMEN_MSQUIC_STAT_VALID_CONGESTION_WINDOW |
                           LUMEN_MSQUIC_STAT_VALID_PACKETS_LOST;
    return LUMEN_MSQUIC_SUCCESS;
  }
}
