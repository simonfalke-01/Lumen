/**
 * @file src/platform/windows/msquic_shim/lumen_msquic_shim.cpp
 * @brief MSVC-only implementation of the stable Lumen MsQuic shim ABI.
 */

#define LUMEN_MSQUIC_SHIM_BUILD 1
#include "lumen_msquic_shim.h"

#include <algorithm>
#include <array>
#include <windows.h>
#include <bcrypt.h>
#include <map>
#include <memory>
#include <msquic.h>
#include <mutex>
#include <ncrypt.h>
#include <new>
#include <optional>
#include <string>
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

  struct CredentialContext {
    HCERTSTORE store {};
    PCCERT_CONTEXT certificate {};
    std::array<uint8_t, 32> spki {};

    ~CredentialContext() {
      if (certificate) {
        CertFreeCertificateContext(certificate);
      }
      if (store) {
        CertCloseStore(store, 0);
      }
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

  bool has_private_key(const PCCERT_CONTEXT certificate) {
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key {};
    DWORD key_spec {};
    BOOL caller_frees {};
    if (!CryptAcquireCertificatePrivateKey(
          certificate,
          CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
          nullptr,
          &key,
          &key_spec,
          &caller_frees
        )) {
      return false;
    }
    if (caller_frees) {
      if (key_spec == CERT_NCRYPT_KEY_SPEC) {
        NCryptFreeObject(key);
      } else {
        CryptReleaseContext(key, 0);
      }
    }
    return true;
  }

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

  void LUMEN_MSQUIC_CALL lumen_msquic_close(lumen_msquic_shim *shim) {
    if (shim == nullptr) {
      return;
    }
    if (shim->api != nullptr) {
      MsQuicClose(shim->api);
    }
    delete shim;
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
    try {
    SecureWide import_password {wide(password)};
    if (import_password.value.empty()) {
      return LUMEN_MSQUIC_INVALID_STATE;
    }
    CRYPT_DATA_BLOB blob {
      static_cast<DWORD>(pkcs12_size),
      const_cast<BYTE *>(pkcs12),
    };
    auto credential = std::make_shared<CredentialContext>();
    DWORD import_flags = PKCS12_NO_PERSIST_KEY | CRYPT_USER_KEYSET;
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
    PCCERT_CONTEXT candidate {};
    while ((candidate = CertEnumCertificatesInStore(credential->store, candidate)) != nullptr) {
      if (has_private_key(candidate)) {
        credential->certificate = CertDuplicateCertificateContext(candidate);
        break;
      }
    }
    if (!credential->certificate || !leaf_spki_sha256(credential->certificate, credential->spki)) {
      return LUMEN_MSQUIC_TRANSPORT_ERROR;
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
    }
    return result;
    } catch (...) {
      return LUMEN_MSQUIC_OUT_OF_MEMORY;
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
    const auto handle = native(h);
    s->api->ConfigurationClose(handle);
    std::lock_guard lock {s->mutex};
    s->configuration_credentials.erase(handle);
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
