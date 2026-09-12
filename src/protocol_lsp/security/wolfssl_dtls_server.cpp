/**
 * @file src/protocol_lsp/security/wolfssl_dtls_server.cpp
 * @brief wolfSSL 5.9.2 DTLS 1.3 server provider for LSP.
 */

#include "wolfssl_dtls_server.h"

#include "secure_zero.h"
#include "wolfssl_process.h"

// clang-format off
#include <wolfssl/options.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfio.h>
// clang-format on

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <limits>
#include <mutex>
#include <new>
#include <optional>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace lumen::lsp {
  namespace {
    constexpr std::string_view wolfssl_cipher_name = "TLS13-AES128-GCM-SHA256";
    constexpr std::string_view wolfssl_cipher_iana_name = "TLS_AES_128_GCM_SHA256";
    constexpr std::string_view required_group = "X25519";
    constexpr std::string_view required_srtp_profile = "SRTP_AEAD_AES_128_GCM";
    constexpr std::uint8_t empty_exporter_context = 0;  ///< Nonnull sentinel for an explicit empty TLS exporter context.
    constexpr std::size_t cookie_secret_size = 32;
    constexpr std::size_t maximum_dtls_application_record = 16U * 1024U;
    constexpr std::size_t maximum_records_per_datagram = 32;

    /**
     * @brief Parsed strict-DER tag, content, and complete encoded range.
     */
    struct DerElement {
      std::uint8_t tag {};  ///< DER tag octet.
      std::span<const std::uint8_t> encoded;  ///< Complete tag-length-value bytes.
      std::span<const std::uint8_t> content;  ///< Value bytes only.
    };

    /**
     * @brief Return whether a byte span contains at least one nonzero byte.
     *
     * @param bytes Bytes to inspect.
     * @return True when the aggregate is nonzero.
     */
    [[nodiscard]] bool contains_nonzero(const std::span<const std::uint8_t> bytes) noexcept {
      std::uint8_t aggregate = 0;
      for (const auto byte : bytes) {
        aggregate = static_cast<std::uint8_t>(aggregate | byte);
      }
      return aggregate != 0;
    }

    /**
     * @brief Parse one canonical definite-length DER element.
     *
     * @param input DER container bytes.
     * @param offset In/out cursor within the container.
     * @return Parsed element, or no value for truncation or non-canonical length encoding.
     */
    [[nodiscard]] std::optional<DerElement> parse_der_element(
      const std::span<const std::uint8_t> input,
      std::size_t &offset
    ) noexcept {
      const auto begin = offset;
      if (offset + 2 > input.size()) {
        return std::nullopt;
      }

      const auto tag = input[offset++];
      const auto first_length = input[offset++];
      std::size_t content_size = 0;
      if ((first_length & 0x80U) == 0) {
        content_size = first_length;
      } else {
        const auto length_octets = static_cast<std::size_t>(first_length & 0x7fU);
        if (length_octets == 0 || length_octets > sizeof(std::size_t) || offset + length_octets > input.size() ||
            input[offset] == 0) {
          return std::nullopt;
        }
        for (std::size_t index = 0; index < length_octets; ++index) {
          if (content_size > (std::numeric_limits<std::size_t>::max() >> 8U)) {
            return std::nullopt;
          }
          content_size = (content_size << 8U) | input[offset++];
        }
        if (content_size < 128) {
          return std::nullopt;
        }
      }

      if (content_size > input.size() - offset) {
        return std::nullopt;
      }
      const auto content_begin = offset;
      offset += content_size;
      return DerElement {
        .tag = tag,
        .encoded = input.subspan(begin, offset - begin),
        .content = input.subspan(content_begin, content_size),
      };
    }

    /**
     * @brief Locate the complete DER SubjectPublicKeyInfo inside an X.509 certificate.
     *
     * @param certificate_der Complete strict-DER certificate.
     * @return Complete encoded SubjectPublicKeyInfo sequence, or no value for malformed input.
     */
    [[nodiscard]] std::optional<std::span<const std::uint8_t>> extract_spki(
      const std::span<const std::uint8_t> certificate_der
    ) noexcept {
      std::size_t certificate_offset = 0;
      const auto certificate = parse_der_element(certificate_der, certificate_offset);
      if (!certificate || certificate->tag != 0x30U || certificate_offset != certificate_der.size()) {
        return std::nullopt;
      }

      std::size_t certificate_content_offset = 0;
      const auto tbs = parse_der_element(certificate->content, certificate_content_offset);
      if (!tbs || tbs->tag != 0x30U) {
        return std::nullopt;
      }

      std::size_t tbs_offset = 0;
      auto field = parse_der_element(tbs->content, tbs_offset);
      if (!field) {
        return std::nullopt;
      }
      if (field->tag == 0xa0U) {
        field = parse_der_element(tbs->content, tbs_offset);
        if (!field) {
          return std::nullopt;
        }
      }

      for (std::size_t field_index = 0; field_index < 4; ++field_index) {
        field = parse_der_element(tbs->content, tbs_offset);
        if (!field) {
          return std::nullopt;
        }
      }

      const auto spki = parse_der_element(tbs->content, tbs_offset);
      if (!spki || spki->tag != 0x30U) {
        return std::nullopt;
      }
      return spki->encoded;
    }

    /**
     * @brief Derive the PIN-discovery-compatible SHA-256 SPKI digest.
     *
     * @param certificate_der Complete strict-DER certificate.
     * @return SPKI digest, or no value for parse or hash failure.
     */
    [[nodiscard]] std::optional<Digest256> derive_spki_sha256(
      const std::span<const std::uint8_t> certificate_der
    ) noexcept {
      const auto spki = extract_spki(certificate_der);
      if (!spki || spki->size() > std::numeric_limits<word32>::max()) {
        return std::nullopt;
      }
      Digest256 digest;
      if (wc_Sha256Hash(spki->data(), static_cast<word32>(spki->size()), digest.data()) != 0) {
        return std::nullopt;
      }
      return digest;
    }

    /**
     * @brief Build wolfSSL's peer-address blob for cookie binding.
     *
     * @param peer Valid LSP peer endpoint.
     * @param storage Output socket-address storage.
     * @param size Output encoded address size.
     * @return True when the numeric remote address parsed for its declared family.
     */
    [[nodiscard]] bool encode_remote_address(
      const PeerEndpoint &peer,
      sockaddr_storage &storage,
      unsigned int &size
    ) noexcept {
      std::memset(&storage, 0, sizeof(storage));
      if (peer.family == IpAddressFamily::ipv4) {
        auto *address = reinterpret_cast<sockaddr_in *>(&storage);
        address->sin_family = AF_INET;
        address->sin_port = htons(peer.remote_port);
        if (inet_pton(AF_INET, peer.remote_address.c_str(), &address->sin_addr) != 1) {
          return false;
        }
        size = sizeof(*address);
        return true;
      }
      if (peer.family == IpAddressFamily::ipv6) {
        auto *address = reinterpret_cast<sockaddr_in6 *>(&storage);
        address->sin6_family = AF_INET6;
        address->sin6_port = htons(peer.remote_port);
        if (inet_pton(AF_INET6, peer.remote_address.c_str(), &address->sin6_addr) != 1) {
          return false;
        }
        size = sizeof(*address);
        return true;
      }
      return false;
    }

    /**
     * @brief Split the RFC 5764 exporter in its specified key/salt order.
     *
     * @param exporter Exact 56-byte exporter.
     * @return Directional SRTP key material.
     */
    [[nodiscard]] DtlsSrtpKeyMaterial split_exporter(
      const std::span<const std::uint8_t, dtls_srtp_exporter_size> exporter
    ) noexcept {
      DtlsSrtpKeyMaterial result;
      std::size_t offset = 0;
      std::copy_n(exporter.data() + offset, result.client_write_key.size(), result.client_write_key.begin());
      offset += result.client_write_key.size();
      std::copy_n(exporter.data() + offset, result.server_write_key.size(), result.server_write_key.begin());
      offset += result.server_write_key.size();
      std::copy_n(exporter.data() + offset, result.client_write_salt.size(), result.client_write_salt.begin());
      offset += result.client_write_salt.size();
      std::copy_n(exporter.data() + offset, result.server_write_salt.size(), result.server_write_salt.begin());
      return result;
    }

    /**
     * @brief Compare a nullable C string with an exact protocol token.
     *
     * @param actual wolfSSL result.
     * @param expected Exact expected token.
     * @return True only for a byte-identical non-null string.
     */
    [[nodiscard]] bool exact_string(const char *actual, const std::string_view expected) noexcept {
      return actual != nullptr && std::string_view {actual} == expected;
    }

  }  // namespace

  class WolfsslDtlsServerProvider::Impl {
  public:
    /**
     * @brief wolfSSL context deleter.
     */
    struct ContextDeleter {
      /**
       * @brief Destroy a wolfSSL context.
       *
       * @param context Context to destroy.
       */
      void operator()(WOLFSSL_CTX *context) const noexcept {
        if (context != nullptr) {
          wolfSSL_CTX_free(context);
        }
      }
    };

    /**
     * @brief wolfSSL association deleter.
     */
    struct SessionDeleter {
      /**
       * @brief Destroy one wolfSSL association and its traffic secrets.
       *
       * @param session Session to destroy.
       */
      void operator()(WOLFSSL *session) const noexcept {
        if (session != nullptr) {
          wolfSSL_free(session);
        }
      }
    };

    using Context = std::unique_ptr<WOLFSSL_CTX, ContextDeleter>;  ///< Owning wolfSSL server context.
    using Session = std::unique_ptr<WOLFSSL, SessionDeleter>;  ///< Owning wolfSSL association.

    /** @brief Allocation-free canonical five-tuple used by cross-thread queues. */
    struct FixedPeerIdentity {
      IpAddressFamily family {IpAddressFamily::ipv4};  ///< Declared address family.
      std::array<std::uint8_t, 16> local_address {};  ///< IPv4 leading four bytes or full IPv6 bytes.
      std::uint16_t local_port {};  ///< Local application port.
      std::uint32_t local_scope_id {};  ///< Local IPv6 scope identifier, zero otherwise.
      std::uint32_t interface_index {};  ///< Receiving interface used for same-source replies.
      std::array<std::uint8_t, 16> remote_address {};  ///< IPv4 leading four bytes or full IPv6 bytes.
      std::uint16_t remote_port {};  ///< Remote source port.
      std::uint32_t remote_scope_id {};  ///< Remote IPv6 scope identifier, zero otherwise.

      bool operator==(const FixedPeerIdentity &) const = default;
    };

    /**
     * @brief Per-call complete-datagram wolfSSL I/O adapter.
     */
    struct IoContext {
      const WolfsslDtlsServerCallbacks *callbacks {};  ///< Stable callback table.
      const PeerEndpoint *peer {};  ///< Stable peer for this synchronous operation.
      std::span<const std::uint8_t> input;  ///< One complete DTLS UDP datagram.
      bool consumed {};  ///< Whether wolfSSL already received the input datagram.
      bool output_failed {};  ///< Whether the socket callback rejected an output datagram.
      std::size_t datagrams_sent {};  ///< Complete datagrams accepted by the output callback.
    };

    /**
     * @brief Durable association retained only after stateless-cookie validation.
     */
    struct Association {
      PeerEndpoint peer;  ///< Bound LSP five-tuple.
      FixedPeerIdentity identity {};  ///< Allocation-free exact lookup identity.
      Session session;  ///< Stateful wolfSSL DTLS association.
      std::uint32_t context_generation {};  ///< Exact server context that created this session.
      bool established {};  ///< Whether exact policy validation and exporter installation completed.
      bool pending_close {};  ///< Deferred close applied only after the outermost wolfSSL call unwinds.
    };

    /** @brief Retired server context retained only while its associations remain live. */
    struct RetiredContext {
      std::uint32_t generation {};  ///< Context incarnation named by live associations.
      Context context;  ///< Old credential context.
    };

    /** @brief Bounded copied application record awaiting socket-owner protection. */
    struct PendingSend {
      FixedPeerIdentity peer {};  ///< Destination association without string allocation.
      std::array<std::uint8_t, maximum_dtls_application_record> plaintext {};  ///< Copied record bytes.
      std::size_t size {};  ///< Active leading record bytes.
    };

    /** @brief Restore the prior wolfSSL I/O contexts at lexical-scope exit. */
    class ScopedIoContext {
    public:
      /** @brief Attach one per-call I/O adapter while preserving prior contexts. */
      ScopedIoContext(WOLFSSL *session, IoContext &context) noexcept:
          session_ {session},
          previous_read_ {wolfSSL_GetIOReadCtx(session)},
          previous_write_ {wolfSSL_GetIOWriteCtx(session)} {
        wolfSSL_SetIOReadCtx(session_, &context);
        wolfSSL_SetIOWriteCtx(session_, &context);
      }

      ScopedIoContext(const ScopedIoContext &) = delete;
      ScopedIoContext &operator=(const ScopedIoContext &) = delete;

      /** @brief Restore both prior contexts before association mutation. */
      ~ScopedIoContext() {
        wolfSSL_SetIOReadCtx(session_, previous_read_);
        wolfSSL_SetIOWriteCtx(session_, previous_write_);
      }

    private:
      WOLFSSL *session_ {};  ///< Temporarily attached association.
      void *previous_read_ {};  ///< Prior read context.
      void *previous_write_ {};  ///< Prior write context.
    };

    /** @brief Track one outer or direct socket-owner provider operation. */
    class OperationScope {
    public:
      /** @brief Enter only when the current thread owns association mutation. */
      explicit OperationScope(Impl &owner) noexcept:
          owner_ {owner},
          active_ {owner_.enter_operation()} {
      }

      OperationScope(const OperationScope &) = delete;
      OperationScope &operator=(const OperationScope &) = delete;

      /** @brief Unwind and drain deferred operations at depth zero. */
      ~OperationScope() {
        if (active_) {
          owner_.leave_operation();
        }
      }

      /** @brief Return whether owner-thread entry succeeded. */
      [[nodiscard]] bool active() const noexcept {
        return active_;
      }

    private:
      Impl &owner_;  ///< Provider implementation owner.
      bool active_ {};  ///< Successful owner-thread entry.
    };

    /**
     * @brief Construct an empty implementation owner.
     */
    Impl() = default;

    Impl(const Impl &) = delete;
    Impl &operator=(const Impl &) = delete;

    /**
     * @brief Clear secrets before member storage is released.
     */
    ~Impl() {
      disable_callbacks();
      associations_.clear();
      context_.reset();
      secure_zero(private_key_der_);
      secure_zero(cookie_secret_);
    }

    /** @brief Build one exact-policy server context from a matching DER credential pair. */
    static Context make_server_context(
      const std::span<const std::uint8_t> certificate_der,
      const std::span<const std::uint8_t> private_key_der
    ) noexcept {
      Context context {wolfSSL_CTX_new(wolfDTLSv1_3_server_method())};
      if (!context || wolfSSL_CTX_set_cipher_list(context.get(), wolfssl_cipher_name.data()) != WOLFSSL_SUCCESS) {
        return {};
      }
      (void) wolfSSL_CTX_set_session_cache_mode(context.get(), WOLFSSL_SESS_CACHE_OFF);
      int group = WOLFSSL_ECC_X25519;
      if (wolfSSL_CTX_set_groups(context.get(), &group, 1) != WOLFSSL_SUCCESS ||
          wolfSSL_CTX_set_tlsext_use_srtp(context.get(), required_srtp_profile.data()) != 0 ||
          wolfSSL_CTX_no_ticket_TLSv13(context.get()) != 0 ||
          certificate_der.size() > std::numeric_limits<long>::max() ||
          private_key_der.size() > std::numeric_limits<long>::max() ||
          wolfSSL_CTX_use_certificate_buffer(
            context.get(),
            certificate_der.data(),
            static_cast<long>(certificate_der.size()),
            WOLFSSL_FILETYPE_ASN1
          ) != WOLFSSL_SUCCESS ||
          wolfSSL_CTX_use_PrivateKey_buffer(
            context.get(),
            private_key_der.data(),
            static_cast<long>(private_key_der.size()),
            WOLFSSL_FILETYPE_ASN1
          ) != WOLFSSL_SUCCESS ||
          wolfSSL_CTX_check_private_key(context.get()) != WOLFSSL_SUCCESS) {
        return {};
      }
      wolfSSL_CTX_set_verify(context.get(), WOLFSSL_VERIFY_NONE, nullptr);
      wolfSSL_CTX_SetIORecv(context.get(), receive_callback);
      wolfSSL_CTX_SetIOSend(context.get(), send_callback);
      return context;
    }

    /**
     * @brief Copy and configure the exact pinned wolfSSL provider policy.
     *
     * @param config Provider configuration.
     * @return Fail-closed initialization result.
     */
    WolfsslDtlsInitializationStatus initialize(const WolfsslDtlsServerConfig &config) noexcept {
      if (config.certificate_der.empty() || config.private_key_der.empty() ||
          config.cookie_secret.size() != cookie_secret_size || !contains_nonzero(config.cookie_secret) ||
          config.maximum_associations == 0 || config.maximum_associations > 64 ||
          config.callbacks.send_datagram == nullptr || config.callbacks.application_data == nullptr ||
          config.callbacks.association_ready == nullptr || config.callbacks.server_certificate == nullptr) {
        return WolfsslDtlsInitializationStatus::invalid_configuration;
      }

      try {
        certificate_der_.assign(config.certificate_der.begin(), config.certificate_der.end());
        private_key_der_.assign(config.private_key_der.begin(), config.private_key_der.end());
        cookie_secret_.assign(config.cookie_secret.begin(), config.cookie_secret.end());
        associations_.reserve(config.maximum_associations);
        retired_contexts_.reserve(8);
      } catch (...) {
        return WolfsslDtlsInitializationStatus::invalid_configuration;
      }
      maximum_associations_ = config.maximum_associations;
      callbacks_ = config.callbacks;
      callbacks_enabled_ = true;

      const auto spki = derive_spki_sha256(certificate_der_);
      if (!spki) {
        return WolfsslDtlsInitializationStatus::certificate_parse_failed;
      }
      server_spki_sha256_ = *spki;
      if (!callbacks_.server_certificate(callbacks_.context, certificate_der_, server_spki_sha256_)) {
        return WolfsslDtlsInitializationStatus::certificate_rejected;
      }

      if (!initialize_wolfssl_process()) {
        return WolfsslDtlsInitializationStatus::wolfssl_initialization_failed;
      }
      context_ = make_server_context(certificate_der_, private_key_der_);
      if (!context_) {
        return WolfsslDtlsInitializationStatus::wolfssl_initialization_failed;
      }
      return WolfsslDtlsInitializationStatus::ready;
    }

    /**
     * @brief Return whether the exact LSP security policy is initialized.
     *
     * @param requirements Policy requested by the generic host service.
     * @return True only for the locked LSP/1 policy.
     */
    [[nodiscard]] bool ready(const DtlsRequirements &requirements) const noexcept {
      return context_ && requirements.alpn_protocol == alpn &&
             requirements.cipher_suite == wolfssl_cipher_iana_name && requirements.key_agreement == required_group &&
             requirements.require_dtls_1_3 && requirements.require_stateless_cookie && !requirements.allow_early_data &&
             !requirements.allow_resumption;
    }

    /**
     * @brief Process one complete incoming DTLS datagram.
     *
     * @param peer Source five-tuple.
     * @param datagram Complete DTLS UDP payload.
     * @return Generic provider disposition.
     */
    ProviderDatagramResult receive(
      const PeerEndpoint &peer,
      const std::span<const std::uint8_t> datagram
    ) noexcept {
      OperationScope operation {*this};
      if (!operation.active()) {
        return ProviderDatagramResult::fatal;
      }
      if (!context_ || !peer.valid() || datagram.empty() || datagram.size() > std::numeric_limits<int>::max()) {
        return ProviderDatagramResult::dropped;
      }

      const auto fixed_peer = fixed_peer_identity(peer);
      if (!fixed_peer) {
        return ProviderDatagramResult::dropped;
      }

      if (const auto index = find_association(*fixed_peer); index != associations_.size()) {
        return receive_known(index, datagram);
      }
      if (datagram.front() != 22U || associations_.size() >= maximum_associations_) {
        return ProviderDatagramResult::dropped;
      }

      auto session = create_session(peer);
      if (!session) {
        return ProviderDatagramResult::fatal;
      }
      IoContext io {
        .callbacks = &callbacks_,
        .peer = &peer,
        .input = datagram,
      };
      int accept_result = WOLFSSL_FAILURE;
      {
        ScopedIoContext io_scope {session.get(), io};
        accept_result = wolfSSL_accept(session.get());
      }
      if (io.output_failed) {
        return ProviderDatagramResult::fatal;
      }

      const auto stateful = wolfSSL_is_stateful(session.get()) != 0;
      if (!stateful) {
        return acceptable_wolfssl_result(session.get(), accept_result) && io.datagrams_sent != 0 ? ProviderDatagramResult::accepted : ProviderDatagramResult::dropped;
      }

      try {
        associations_.push_back(Association {
          .peer = peer,
          .identity = *fixed_peer,
          .session = std::move(session),
          .context_generation = current_context_generation_,
        });
        association_count_snapshot_.store(associations_.size(), std::memory_order_release);
      } catch (...) {
        return ProviderDatagramResult::fatal;
      }
      const auto index = associations_.size() - 1;
      if (accept_result == WOLFSSL_SUCCESS) {
        if (!complete_association(index)) {
          associations_[index].pending_close = true;
          return ProviderDatagramResult::dropped;
        }
      } else if (!acceptable_wolfssl_result(associations_[index].session.get(), accept_result)) {
        associations_[index].pending_close = true;
        return ProviderDatagramResult::dropped;
      }
      return ProviderDatagramResult::accepted;
    }

    /**
     * @brief Send one authenticated application record.
     *
     * @param peer Association five-tuple.
     * @param plaintext Complete LSPC record.
     * @return Exact operation disposition.
     */
    WolfsslDtlsOperationResult send_application_data(
      const PeerEndpoint &peer,
      const std::span<const std::uint8_t> plaintext
    ) noexcept {
      if (plaintext.empty() || plaintext.size() > maximum_dtls_application_record ||
          plaintext.size() > std::numeric_limits<int>::max() || !peer.valid()) {
        return WolfsslDtlsOperationResult::rejected;
      }
      const auto fixed_peer = fixed_peer_identity(peer);
      if (!fixed_peer) {
        return WolfsslDtlsOperationResult::rejected;
      }
      if (!is_owner_thread() || operation_depth_ != 0) {
        return queue_send(*fixed_peer, plaintext) ?
                 WolfsslDtlsOperationResult::accepted :
                 WolfsslDtlsOperationResult::rejected;
      }
      OperationScope operation {*this};
      return operation.active() ?
               perform_send(*fixed_peer, plaintext) :
               WolfsslDtlsOperationResult::rejected;
    }

    /**
     * @brief Process one expired DTLS retransmission timeout.
     *
     * @param peer Association five-tuple.
     * @return Exact operation disposition.
     */
    WolfsslDtlsOperationResult handle_timeout(const PeerEndpoint &peer) noexcept {
      OperationScope operation {*this};
      if (!operation.active()) {
        return WolfsslDtlsOperationResult::rejected;
      }
      const auto fixed_peer = fixed_peer_identity(peer);
      if (!fixed_peer) {
        return WolfsslDtlsOperationResult::rejected;
      }
      const auto index = find_association(*fixed_peer);
      if (index == associations_.size()) {
        return WolfsslDtlsOperationResult::not_found;
      }
      auto &association = associations_[index];
      if (association.established) {
        return WolfsslDtlsOperationResult::accepted;
      }
      IoContext io {
        .callbacks = &callbacks_,
        .peer = &association.peer,
      };
      int result = WOLFSSL_FAILURE;
      {
        ScopedIoContext io_scope {association.session.get(), io};
        result = wolfSSL_dtls_got_timeout(association.session.get());
      }
      if (result == WOLFSSL_SUCCESS && !io.output_failed) {
        return WolfsslDtlsOperationResult::accepted;
      }
      association.pending_close = true;
      return WolfsslDtlsOperationResult::fatal;
    }

    /**
     * @brief Return the handshake retransmission timeout in whole seconds.
     *
     * @param peer Association five-tuple.
     * @return Positive seconds while handshaking, or zero once established/absent.
     */
    [[nodiscard]] std::uint32_t timeout_seconds(const PeerEndpoint &peer) const noexcept {
      if (!is_owner_thread()) {
        return 0;
      }
      const auto fixed_peer = fixed_peer_identity(peer);
      if (!fixed_peer) {
        return 0;
      }
      const auto index = find_association(*fixed_peer);
      if (index == associations_.size() || associations_[index].established) {
        return 0;
      }
      const auto timeout = wolfSSL_dtls_get_current_timeout(associations_[index].session.get());
      return timeout > 0 ? static_cast<std::uint32_t>(timeout) : 0;
    }

    /**
     * @brief Remove one association.
     *
     * @param peer Association five-tuple.
     * @return True when removed.
     */
    bool close_association(const PeerEndpoint &peer) noexcept {
      if (!is_owner_thread()) {
        return request_close(peer);
      }
      const auto fixed_peer = fixed_peer_identity(peer);
      if (!fixed_peer) {
        return false;
      }
      const auto index = find_association(*fixed_peer);
      if (index == associations_.size()) {
        return false;
      }
      associations_[index].pending_close = true;
      if (operation_depth_ == 0) {
        flush_pending_closes();
      }
      return true;
    }

    /** @brief Queue a close without mutating association state. */
    bool request_close(const PeerEndpoint &peer) noexcept {
      const auto fixed_peer = fixed_peer_identity(peer);
      if (!fixed_peer) {
        return false;
      }
      std::scoped_lock lock(pending_mutex_);
      for (std::size_t index = 0; index < pending_close_count_; ++index) {
        if (pending_closes_[(pending_close_head_ + index) % pending_closes_.size()] == *fixed_peer) {
          return true;
        }
      }
      if (pending_close_count_ == pending_closes_.size()) {
        return false;
      }
      pending_closes_[pending_close_tail_] = *fixed_peer;
      pending_close_tail_ = (pending_close_tail_ + 1) % pending_closes_.size();
      ++pending_close_count_;
      return true;
    }

    /** @brief Drain copied sends and close requests on the owner thread. */
    bool process_pending() noexcept {
      if (!is_owner_thread()) {
        OperationScope bind_owner {*this};
        return bind_owner.active();
      }
      if (operation_depth_ != 0 || draining_pending_) {
        return false;
      }
      process_pending_owner();
      return true;
    }

    /** @brief Permit a joined receive worker to hand final provider draining to shutdown. */
    bool release_owner_thread() noexcept {
      std::scoped_lock lock(pending_mutex_);
      if (owner_thread_ != std::this_thread::get_id() || operation_depth_ != 0 || draining_pending_) {
        return false;
      }
      owner_thread_ = {};
      return true;
    }

    /** @brief Close and notify every association exactly once on the owner thread. */
    std::size_t drain_all() noexcept {
      if (!is_owner_thread() || operation_depth_ != 0) {
        return 0;
      }
      process_pending_owner();
      const auto drained = associations_.size();
      while (!associations_.empty()) {
        erase_association(associations_.size() - 1);
      }
      clear_pending_queues();
      return drained;
    }

    /** @brief Permanently clear non-owning callbacks after owner shutdown. */
    void disable_callbacks() noexcept {
      std::scoped_lock lock(pending_mutex_);
      callbacks_ = {};
      callbacks_enabled_ = false;
      for (auto &pending : pending_sends_) {
        secure_zero(pending.plaintext);
        pending = {};
      }
      pending_send_count_ = 0;
      pending_send_head_ = 0;
      pending_send_tail_ = 0;
      pending_close_count_ = 0;
      pending_close_head_ = 0;
      pending_close_tail_ = 0;
    }

    /**
     * @brief Return the configured server SPKI digest.
     *
     * @return SHA-256 SPKI digest.
     */
    [[nodiscard]] Digest256 server_spki_sha256() const noexcept {
      return server_spki_sha256_;
    }

    bool rotate_identity(
      const std::span<const std::uint8_t> certificate_der,
      const std::span<const std::uint8_t> private_key_der,
      const std::span<const std::uint8_t> cookie_secret
    ) noexcept {
      OperationScope operation {*this};
      if (!operation.active()) {
        return false;
      }
      reclaim_retired_contexts();
      if (certificate_der.empty() || private_key_der.empty() ||
          cookie_secret.size() != cookie_secret_size || !contains_nonzero(cookie_secret) ||
          retired_contexts_.size() >= 8U ||
          current_context_generation_ == std::numeric_limits<std::uint32_t>::max()) {
        return false;
      }
      const auto spki = derive_spki_sha256(certificate_der);
      if (!spki || *spki == server_spki_sha256_ ||
          !callbacks_.server_certificate(callbacks_.context, certificate_der, *spki)) {
        return false;
      }
      auto replacement = make_server_context(certificate_der, private_key_der);
      if (!replacement) {
        return false;
      }
      std::vector<std::uint8_t> certificate_copy;
      std::vector<std::uint8_t> private_key_copy;
      std::vector<std::uint8_t> cookie_copy;
      try {
        certificate_copy.assign(certificate_der.begin(), certificate_der.end());
        private_key_copy.assign(private_key_der.begin(), private_key_der.end());
        cookie_copy.assign(cookie_secret.begin(), cookie_secret.end());
        retired_contexts_.push_back({current_context_generation_, std::move(context_)});
      } catch (...) {
        if (!context_ && !retired_contexts_.empty()) {
          context_ = std::move(retired_contexts_.back().context);
          retired_contexts_.pop_back();
        }
        secure_zero(private_key_copy);
        secure_zero(cookie_copy);
        return false;
      }
      certificate_der_.swap(certificate_copy);
      secure_zero(private_key_der_);
      private_key_der_.swap(private_key_copy);
      secure_zero(cookie_secret_);
      cookie_secret_.swap(cookie_copy);
      secure_zero(private_key_copy);
      secure_zero(cookie_copy);
      context_ = std::move(replacement);
      ++current_context_generation_;
      server_spki_sha256_ = *spki;
      reclaim_retired_contexts();
      return true;
    }

    /**
     * @brief Return retained durable association count.
     *
     * @return Association count.
     */
    [[nodiscard]] std::size_t association_count() const noexcept {
      return association_count_snapshot_.load(std::memory_order_acquire);
    }

  private:
    /**
     * @brief Parse one endpoint into allocation-free canonical queue identity.
     *
     * @param peer Valid numeric endpoint supplied by the socket owner.
     * @return Fixed five-tuple identity, or no value when either numeric address is invalid.
     */
    [[nodiscard]] static std::optional<FixedPeerIdentity> fixed_peer_identity(
      const PeerEndpoint &peer
    ) noexcept {
      if (!peer.valid()) {
        return std::nullopt;
      }
      FixedPeerIdentity identity {
        .family = peer.family,
        .local_port = peer.local_port,
        .interface_index = peer.interface_index,
        .remote_port = peer.remote_port,
      };
      const auto address_family = peer.family == IpAddressFamily::ipv4 ? AF_INET : AF_INET6;
      const auto address_size = peer.family == IpAddressFamily::ipv4 ? 4U : 16U;
      if (peer.canonical_local.valid) {
        std::copy_n(peer.canonical_local.address.begin(), address_size, identity.local_address.begin());
        identity.local_scope_id = peer.family == IpAddressFamily::ipv6 ? peer.canonical_local.scope_id : 0;
      } else if (inet_pton(address_family, peer.local_address.c_str(), identity.local_address.data()) != 1) {
        return std::nullopt;
      }
      if (peer.canonical_remote.valid) {
        std::copy_n(peer.canonical_remote.address.begin(), address_size, identity.remote_address.begin());
        identity.remote_scope_id = peer.family == IpAddressFamily::ipv6 ? peer.canonical_remote.scope_id : 0;
      } else if (inet_pton(address_family, peer.remote_address.c_str(), identity.remote_address.data()) != 1) {
        return std::nullopt;
      }
      return identity;
    }

    /** @brief Return whether the current thread owns all association mutation. */
    [[nodiscard]] bool is_owner_thread() const noexcept {
      std::scoped_lock lock(pending_mutex_);
      return owner_thread_ != std::thread::id {} && owner_thread_ == std::this_thread::get_id();
    }

    /** @brief Bind or re-enter the socket-owner mutation scope. */
    bool enter_operation() noexcept {
      {
        std::scoped_lock lock(pending_mutex_);
        if (owner_thread_ == std::thread::id {}) {
          owner_thread_ = std::this_thread::get_id();
        }
        if (owner_thread_ != std::this_thread::get_id() || !callbacks_enabled_) {
          return false;
        }
      }
      ++operation_depth_;
      return true;
    }

    /** @brief Leave one owner scope and apply deferred work only at depth zero. */
    void leave_operation() noexcept {
      if (operation_depth_ == 0) {
        return;
      }
      --operation_depth_;
      if (operation_depth_ == 0 && !draining_pending_) {
        process_pending_owner();
      }
    }

    /** @brief Copy one deferred application record into the bounded concurrent queue. */
    bool queue_send(const FixedPeerIdentity &peer, const std::span<const std::uint8_t> plaintext) noexcept {
      std::scoped_lock lock(pending_mutex_);
      if (!callbacks_enabled_ || pending_send_count_ == pending_sends_.size()) {
        return false;
      }
      auto &pending = pending_sends_[pending_send_tail_];
      pending.peer = peer;
      std::copy(plaintext.begin(), plaintext.end(), pending.plaintext.begin());
      pending.size = plaintext.size();
      pending_send_tail_ = (pending_send_tail_ + 1) % pending_sends_.size();
      ++pending_send_count_;
      return true;
    }

    /** @brief Protect one record directly while already executing on the owner. */
    WolfsslDtlsOperationResult perform_send(
      const FixedPeerIdentity &peer,
      const std::span<const std::uint8_t> plaintext
    ) noexcept {
      const auto index = find_association(peer);
      if (index == associations_.size()) {
        return WolfsslDtlsOperationResult::not_found;
      }
      auto &association = associations_[index];
      if (!association.established || association.pending_close) {
        return WolfsslDtlsOperationResult::not_established;
      }
      IoContext io {
        .callbacks = &callbacks_,
        .peer = &association.peer,
      };
      int written = WOLFSSL_FAILURE;
      {
        ScopedIoContext io_scope {association.session.get(), io};
        written = wolfSSL_write(
          association.session.get(),
          plaintext.data(),
          static_cast<int>(plaintext.size())
        );
      }
      if (written == static_cast<int>(plaintext.size()) && !io.output_failed) {
        return WolfsslDtlsOperationResult::accepted;
      }
      if (io.output_failed) {
        association.pending_close = true;
        return WolfsslDtlsOperationResult::fatal;
      }
      const auto error = wolfSSL_get_error(association.session.get(), written);
      if (error == WOLFSSL_ERROR_WANT_READ || error == WOLFSSL_ERROR_WANT_WRITE) {
        return WolfsslDtlsOperationResult::rejected;
      }
      association.pending_close = true;
      return WolfsslDtlsOperationResult::fatal;
    }

    /** @brief Apply all association-local close flags after no wolfSSL frame is active. */
    void flush_pending_closes() noexcept {
      for (std::size_t index = associations_.size(); index > 0; --index) {
        if (associations_[index - 1].pending_close) {
          erase_association(index - 1);
        }
      }
    }

    /** @brief Apply every copied send before queued closes on the owner thread. */
    void process_pending_owner() noexcept {
      if (draining_pending_ || operation_depth_ != 0) {
        return;
      }
      draining_pending_ = true;
      for (;;) {
        PendingSend pending_send;
        FixedPeerIdentity pending_close;
        bool have_send = false;
        bool have_close = false;
        {
          std::scoped_lock lock(pending_mutex_);
          if (pending_send_count_ != 0) {
            auto &source = pending_sends_[pending_send_head_];
            pending_send = std::move(source);
            secure_zero(source.plaintext);
            source = {};
            pending_send_head_ = (pending_send_head_ + 1) % pending_sends_.size();
            --pending_send_count_;
            have_send = true;
          } else if (pending_close_count_ != 0) {
            pending_close = std::move(pending_closes_[pending_close_head_]);
            pending_closes_[pending_close_head_] = {};
            pending_close_head_ = (pending_close_head_ + 1) % pending_closes_.size();
            --pending_close_count_;
            have_close = true;
          }
        }
        if (have_send) {
          ++operation_depth_;
          (void) perform_send(
            pending_send.peer,
            std::span<const std::uint8_t> {pending_send.plaintext.data(), pending_send.size}
          );
          --operation_depth_;
          secure_zero(pending_send.plaintext);
          flush_pending_closes();
          continue;
        }
        if (have_close) {
          const auto index = find_association(pending_close);
          if (index != associations_.size()) {
            associations_[index].pending_close = true;
          }
          flush_pending_closes();
          continue;
        }
        break;
      }
      flush_pending_closes();
      draining_pending_ = false;
    }

    /** @brief Clear queued plaintext and peer requests without callbacks. */
    void clear_pending_queues() noexcept {
      std::scoped_lock lock(pending_mutex_);
      for (auto &pending : pending_sends_) {
        secure_zero(pending.plaintext);
        pending = {};
      }
      pending_send_head_ = 0;
      pending_send_tail_ = 0;
      pending_send_count_ = 0;
      pending_close_head_ = 0;
      pending_close_tail_ = 0;
      pending_close_count_ = 0;
    }

    /**
     * @brief Serve one complete datagram to wolfSSL exactly once.
     *
     * @param session wolfSSL association.
     * @param buffer wolfSSL destination.
     * @param size Destination capacity.
     * @param opaque Per-call I/O context.
     * @return Bytes copied or wolfSSL nonblocking I/O status.
     */
    static int receive_callback(WOLFSSL *session, char *buffer, int size, void *opaque) noexcept {
      (void) session;
      auto *io = static_cast<IoContext *>(opaque);
      if (io == nullptr || buffer == nullptr || size < 0) {
        return WOLFSSL_CBIO_ERR_GENERAL;
      }
      if (io->consumed || io->input.empty()) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
      }
      if (io->input.size() > static_cast<std::size_t>(size)) {
        return WOLFSSL_CBIO_ERR_GENERAL;
      }
      std::memcpy(buffer, io->input.data(), io->input.size());
      io->consumed = true;
      return static_cast<int>(io->input.size());
    }

    /**
     * @brief Emit one complete DTLS datagram through the socket owner.
     *
     * @param session wolfSSL association.
     * @param buffer Complete DTLS datagram bytes.
     * @param size Datagram size.
     * @param opaque Per-call I/O context.
     * @return Bytes accepted or a fatal wolfSSL I/O status.
     */
    static int send_callback(WOLFSSL *session, char *buffer, int size, void *opaque) noexcept {
      (void) session;
      auto *io = static_cast<IoContext *>(opaque);
      if (io == nullptr || io->callbacks == nullptr || io->callbacks->send_datagram == nullptr ||
          io->peer == nullptr || buffer == nullptr || size <= 0) {
        return WOLFSSL_CBIO_ERR_GENERAL;
      }
      const auto datagram = std::span<const std::uint8_t> {
        reinterpret_cast<const std::uint8_t *>(buffer),
        static_cast<std::size_t>(size),
      };
      if (!io->callbacks->send_datagram(io->callbacks->context, *io->peer, datagram)) {
        io->output_failed = true;
        return WOLFSSL_CBIO_ERR_GENERAL;
      }
      ++io->datagrams_sent;
      return size;
    }

    /**
     * @brief Create an exact-policy wolfSSL association for one peer.
     *
     * @param peer Candidate five-tuple.
     * @return Configured association or null on any policy/API failure.
     */
    [[nodiscard]] Session create_session(const PeerEndpoint &peer) const noexcept {
      Session session {wolfSSL_new(context_.get())};
      if (!session) {
        return {};
      }

      int group = WOLFSSL_ECC_X25519;
      char alpn_name[] = "lumen-stream/1";
      sockaddr_storage remote_address;
      unsigned int remote_address_size = 0;
      if (!encode_remote_address(peer, remote_address, remote_address_size) ||
          wolfSSL_set_groups(session.get(), &group, 1) != WOLFSSL_SUCCESS ||
          wolfSSL_UseALPN(
            session.get(),
            alpn_name,
            static_cast<unsigned int>(sizeof(alpn_name) - 1),
            WOLFSSL_ALPN_FAILED_ON_MISMATCH
          ) != WOLFSSL_SUCCESS ||
          wolfSSL_set_tlsext_use_srtp(session.get(), required_srtp_profile.data()) != 0 ||
          wolfSSL_send_hrr_cookie(
            session.get(),
            cookie_secret_.data(),
            static_cast<unsigned int>(cookie_secret_.size())
          ) != WOLFSSL_SUCCESS ||
          wolfSSL_dtls_set_peer(session.get(), &remote_address, remote_address_size) != WOLFSSL_SUCCESS) {
        return {};
      }
      wolfSSL_dtls_set_using_nonblock(session.get(), 1);
      wolfSSL_KeepArrays(session.get());
      return session;
    }

    /**
     * @brief Return whether a wolfSSL operation is a successful nonblocking wait.
     *
     * @param session wolfSSL association.
     * @param result wolfSSL operation result.
     * @return True for success, WANT_READ, or WANT_WRITE only.
     */
    [[nodiscard]] static bool acceptable_wolfssl_result(WOLFSSL *session, const int result) noexcept {
      if (result == WOLFSSL_SUCCESS) {
        return true;
      }
      const auto error = wolfSSL_get_error(session, result);
      return error == WOLFSSL_ERROR_WANT_READ || error == WOLFSSL_ERROR_WANT_WRITE;
    }

    /**
     * @brief Process a datagram for one already stateful association.
     *
     * @param index Association index.
     * @param datagram Complete DTLS UDP payload.
     * @return Provider disposition.
     */
    ProviderDatagramResult receive_known(
      const std::size_t index,
      const std::span<const std::uint8_t> datagram
    ) noexcept {
      auto &association = associations_[index];
      IoContext io {
        .callbacks = &callbacks_,
        .peer = &association.peer,
        .input = datagram,
      };
      ProviderDatagramResult result = ProviderDatagramResult::accepted;
      {
        ScopedIoContext io_scope {association.session.get(), io};
        if (!association.established) {
          const auto accepted = wolfSSL_accept(association.session.get());
          if (accepted == WOLFSSL_SUCCESS) {
            if (!complete_association(index)) {
              result = ProviderDatagramResult::dropped;
            }
          } else if (!acceptable_wolfssl_result(association.session.get(), accepted)) {
            result = ProviderDatagramResult::dropped;
          }
        } else {
          result = read_application_records(association);
        }
      }

      if (io.output_failed) {
        result = ProviderDatagramResult::fatal;
      }
      if (result != ProviderDatagramResult::accepted) {
        association.pending_close = true;
      }
      return result;
    }

    /**
     * @brief Validate exact negotiated policy and publish the 56-byte exporter.
     *
     * @param index Association index.
     * @return True only when all policy checks and product admission succeed.
     */
    bool complete_association(const std::size_t index) noexcept {
      auto &association = associations_[index];
      auto *session = association.session.get();
      char *selected_alpn = nullptr;
      unsigned short selected_alpn_size = 0;
      const auto *srtp_profile = wolfSSL_get_selected_srtp_profile(session);
      const auto alpn_result = wolfSSL_ALPN_GetProtocol(session, &selected_alpn, &selected_alpn_size);

      if (!exact_string(wolfSSL_get_version(session), "DTLSv1.3") ||
          (!exact_string(wolfSSL_get_cipher_name(session), wolfssl_cipher_name) &&
           !exact_string(wolfSSL_get_cipher_name(session), wolfssl_cipher_iana_name)) ||
          !exact_string(wolfSSL_get_curve_name(session), required_group) || srtp_profile == nullptr ||
          srtp_profile->id != SRTP_AEAD_AES_128_GCM ||
          std::string_view {srtp_profile->name} != required_srtp_profile ||
          alpn_result != WOLFSSL_SUCCESS ||
          selected_alpn == nullptr || std::string_view {selected_alpn, selected_alpn_size} != alpn) {
        return false;
      }

      std::array<std::uint8_t, dtls_srtp_exporter_size> exporter;
      std::size_t exporter_size = 0;
      const auto length_result = wolfSSL_export_dtls_srtp_keying_material(session, nullptr, &exporter_size);
      if (length_result != LENGTH_ONLY_E || exporter_size != exporter.size()) {
        return false;
      }
      exporter_size = exporter.size();
      const auto exporter_result = wolfSSL_export_dtls_srtp_keying_material(session, exporter.data(), &exporter_size);
      if (exporter_result != WOLFSSL_SUCCESS ||
          exporter_size != exporter.size()) {
        secure_zero(exporter);
        return false;
      }
      PairingExporter pairing_exporter;
      if (wolfSSL_export_keying_material(
            session,
            pairing_exporter.data(),
            pairing_exporter.size(),
            pairing_exporter_label.data(),
            pairing_exporter_label.size(),
            &empty_exporter_context,
            0,
            1
          ) != WOLFSSL_SUCCESS) {
        secure_zero(exporter);
        secure_zero(pairing_exporter);
        return false;
      }
      wolfSSL_FreeArrays(session);

      DtlsAssociationSecurity security {
        .server_spki_sha256 = server_spki_sha256_,
        .srtp = split_exporter(exporter),
        .pairing_exporter = pairing_exporter,
      };
      secure_zero(exporter);
      secure_zero(pairing_exporter);
      const auto admitted = callbacks_enabled_ && callbacks_.association_ready != nullptr &&
                            callbacks_.association_ready(callbacks_.context, association.peer, security);
      secure_zero(security.srtp.client_write_key);
      secure_zero(security.srtp.server_write_key);
      secure_zero(security.srtp.client_write_salt);
      secure_zero(security.srtp.server_write_salt);
      secure_zero(security.pairing_exporter);
      if (!admitted) {
        return false;
      }
      association.established = true;
      return true;
    }

    /**
     * @brief Drain authenticated application records already buffered by wolfSSL.
     *
     * @param association Established association.
     * @return Provider disposition.
     */
    ProviderDatagramResult read_application_records(Association &association) noexcept {
      std::array<std::uint8_t, maximum_dtls_application_record> plaintext;
      for (std::size_t record_index = 0; record_index < maximum_records_per_datagram; ++record_index) {
        const auto size = wolfSSL_read(
          association.session.get(),
          plaintext.data(),
          static_cast<int>(plaintext.size())
        );
        if (size > 0) {
          if (!callbacks_enabled_ || callbacks_.application_data == nullptr ||
              !callbacks_.application_data(
                callbacks_.context,
                association.peer,
                std::span<const std::uint8_t> {plaintext.data(), static_cast<std::size_t>(size)}
              )) {
            secure_zero(plaintext);
            return ProviderDatagramResult::fatal;
          }
          secure_zero(std::span<std::uint8_t> {plaintext.data(), static_cast<std::size_t>(size)});
          continue;
        }

        secure_zero(plaintext);
        const auto error = wolfSSL_get_error(association.session.get(), size);
        if (error == WOLFSSL_ERROR_WANT_READ || error == WOLFSSL_ERROR_WANT_WRITE) {
          return ProviderDatagramResult::accepted;
        }
        return ProviderDatagramResult::dropped;
      }
      secure_zero(plaintext);
      return ProviderDatagramResult::fatal;
    }

    /**
     * @brief Find an association by its complete five-tuple.
     *
     * @param peer Five-tuple to find.
     * @return Index, or `associations_.size()` when absent.
     */
    [[nodiscard]] std::size_t find_association(const FixedPeerIdentity &peer) const noexcept {
      const auto iterator = std::find_if(associations_.begin(), associations_.end(), [&peer](const Association &candidate) {
        return candidate.identity == peer;
      });
      return static_cast<std::size_t>(std::distance(associations_.begin(), iterator));
    }

    /**
     * @brief Notify product state and erase one association.
     *
     * @param index Valid association index.
     */
    void erase_association(const std::size_t index) noexcept {
      ++operation_depth_;
      notify_closed(associations_[index].peer);
      --operation_depth_;
      associations_.erase(associations_.begin() + static_cast<std::ptrdiff_t>(index));
      association_count_snapshot_.store(associations_.size(), std::memory_order_release);
      reclaim_retired_contexts();
    }

    /** @brief Destroy retired contexts after their final association closes. */
    void reclaim_retired_contexts() noexcept {
      for (std::size_t index = 0; index < retired_contexts_.size();) {
        const auto generation = retired_contexts_[index].generation;
        const auto referenced = std::ranges::any_of(associations_, [generation](const Association &association) {
          return association.context_generation == generation;
        });
        if (referenced) {
          ++index;
        } else {
          retired_contexts_.erase(retired_contexts_.begin() + static_cast<std::ptrdiff_t>(index));
        }
      }
    }

    /**
     * @brief Invoke the optional non-reentrant teardown notification.
     *
     * @param peer Association five-tuple.
     */
    void notify_closed(const PeerEndpoint &peer) const noexcept {
      if (callbacks_enabled_ && callbacks_.association_closed != nullptr) {
        callbacks_.association_closed(callbacks_.context, peer);
      }
    }

    Context context_;  ///< Exact DTLS 1.3 wolfSSL server context.
    std::vector<RetiredContext> retired_contexts_;  ///< Old contexts retained for live pre-rotation sessions.
    std::vector<std::uint8_t> certificate_der_;  ///< Canonical DER leaf certificate.
    std::vector<std::uint8_t> private_key_der_;  ///< Secret DER private key.
    std::vector<std::uint8_t> cookie_secret_;  ///< Shared address-bound HRR HMAC secret.
    Digest256 server_spki_sha256_ {};  ///< PIN-discovery-compatible server SPKI digest.
    WolfsslDtlsServerCallbacks callbacks_;  ///< Product/socket callbacks.
    std::vector<Association> associations_;  ///< Durable post-cookie associations.
    std::size_t maximum_associations_ {};  ///< Durable association bound.
    std::uint32_t current_context_generation_ {1};  ///< Active new-association credential incarnation.
    std::array<PendingSend, 64> pending_sends_ {};  ///< Bounded copied application records.
    std::array<FixedPeerIdentity, 64> pending_closes_ {};  ///< Bounded administrator/callback close requests.
    mutable std::mutex pending_mutex_;  ///< Synchronizes only cross-thread queue and owner identity state.
    std::thread::id owner_thread_ {};  ///< Sole association and WOLFSSL mutation thread.
    std::size_t pending_send_head_ {};  ///< Next copied send to drain.
    std::size_t pending_send_tail_ {};  ///< Next copied send insertion slot.
    std::size_t pending_send_count_ {};  ///< Live copied send count.
    std::size_t pending_close_head_ {};  ///< Next close request to drain.
    std::size_t pending_close_tail_ {};  ///< Next close insertion slot.
    std::size_t pending_close_count_ {};  ///< Live close request count.
    std::size_t operation_depth_ {};  ///< Owner-thread wolfSSL/callback nesting depth.
    bool draining_pending_ {};  ///< Prevent recursive pending-queue drains.
    bool callbacks_enabled_ {};  ///< Product callback lifetime gate.
    std::atomic<std::size_t> association_count_snapshot_ {};  ///< Cross-thread administration snapshot.
  };

  WolfsslDtlsServerProvider::WolfsslDtlsServerProvider(const WolfsslDtlsServerConfig &config) noexcept:
      impl_ {new (std::nothrow) Impl} {
    if (!impl_) {
      status_ = WolfsslDtlsInitializationStatus::invalid_configuration;
      return;
    }
    status_ = impl_->initialize(config);
  }

  WolfsslDtlsServerProvider::~WolfsslDtlsServerProvider() = default;

  bool WolfsslDtlsServerProvider::ready(const DtlsRequirements &requirements) const noexcept {
    return status_ == WolfsslDtlsInitializationStatus::ready && impl_ && impl_->ready(requirements);
  }

  ProviderDatagramResult WolfsslDtlsServerProvider::receive_dtls(
    const PeerEndpoint &peer,
    const std::span<const std::uint8_t> datagram
  ) noexcept {
    if (status_ != WolfsslDtlsInitializationStatus::ready || !impl_) {
      return ProviderDatagramResult::fatal;
    }
    return impl_->receive(peer, datagram);
  }

  WolfsslDtlsOperationResult WolfsslDtlsServerProvider::send_application_data(
    const PeerEndpoint &peer,
    const std::span<const std::uint8_t> plaintext
  ) noexcept {
    if (status_ != WolfsslDtlsInitializationStatus::ready || !impl_) {
      return WolfsslDtlsOperationResult::fatal;
    }
    return impl_->send_application_data(peer, plaintext);
  }

  WolfsslDtlsOperationResult WolfsslDtlsServerProvider::handle_timeout(const PeerEndpoint &peer) noexcept {
    if (status_ != WolfsslDtlsInitializationStatus::ready || !impl_) {
      return WolfsslDtlsOperationResult::fatal;
    }
    return impl_->handle_timeout(peer);
  }

  std::uint32_t WolfsslDtlsServerProvider::timeout_seconds(const PeerEndpoint &peer) const noexcept {
    return impl_ ? impl_->timeout_seconds(peer) : 0;
  }

  bool WolfsslDtlsServerProvider::close_association(const PeerEndpoint &peer) noexcept {
    return impl_ && impl_->close_association(peer);
  }

  bool WolfsslDtlsServerProvider::request_close(const PeerEndpoint &peer) noexcept {
    return impl_ && impl_->request_close(peer);
  }

  bool WolfsslDtlsServerProvider::process_pending() noexcept {
    return impl_ && impl_->process_pending();
  }

  bool WolfsslDtlsServerProvider::release_owner_thread() noexcept {
    return impl_ && impl_->release_owner_thread();
  }

  std::size_t WolfsslDtlsServerProvider::drain_all() noexcept {
    return impl_ ? impl_->drain_all() : 0;
  }

  void WolfsslDtlsServerProvider::disable_callbacks() noexcept {
    if (impl_) {
      impl_->disable_callbacks();
    }
  }

  WolfsslDtlsInitializationStatus WolfsslDtlsServerProvider::initialization_status() const noexcept {
    return status_;
  }

  Digest256 WolfsslDtlsServerProvider::server_spki_sha256() const noexcept {
    return impl_ ? impl_->server_spki_sha256() : Digest256 {};
  }

  bool WolfsslDtlsServerProvider::rotate_identity(
    const std::span<const std::uint8_t> certificate_der,
    const std::span<const std::uint8_t> private_key_der,
    const std::span<const std::uint8_t> cookie_secret
  ) noexcept {
    return impl_ && impl_->rotate_identity(certificate_der, private_key_der, cookie_secret);
  }

  std::size_t WolfsslDtlsServerProvider::association_count() const noexcept {
    return impl_ ? impl_->association_count() : 0;
  }
}  // namespace lumen::lsp
