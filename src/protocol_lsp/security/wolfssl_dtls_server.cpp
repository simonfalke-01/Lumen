/**
 * @file src/protocol_lsp/security/wolfssl_dtls_server.cpp
 * @brief wolfSSL 5.9.2 DTLS 1.3 server provider for LSP.
 */

#include "wolfssl_dtls_server.h"

#include "secure_zero.h"

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
#include <cstring>
#include <limits>
#include <mutex>
#include <new>
#include <optional>
#include <string_view>
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

    /**
     * @brief Initialize wolfSSL once for the process without provider-local cleanup races.
     *
     * wolfSSL global cleanup is intentionally left to process termination.
     * Multiple DTLS providers and libSRTP's wolfCrypt backend can coexist, so
     * one provider must never tear global state down while another still uses
     * it.
     *
     * @return True when process-scoped initialization succeeded.
     */
    [[nodiscard]] bool initialize_wolfssl_process() noexcept {
      static std::once_flag initialization_once;
      static bool initialized = false;
      try {
        std::call_once(initialization_once, []() noexcept {
          initialized = wolfSSL_Init() == WOLFSSL_SUCCESS;
        });
      } catch (...) {
        return false;
      }
      return initialized;
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
      Session session;  ///< Stateful wolfSSL DTLS association.
      bool established {};  ///< Whether exact policy validation and exporter installation completed.
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
      for (const auto &association : associations_) {
        notify_closed(association.peer);
      }
      associations_.clear();
      context_.reset();
      secure_zero(private_key_der_);
      secure_zero(cookie_secret_);
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
      } catch (...) {
        return WolfsslDtlsInitializationStatus::invalid_configuration;
      }
      maximum_associations_ = config.maximum_associations;
      callbacks_ = config.callbacks;

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
      context_.reset(wolfSSL_CTX_new(wolfDTLSv1_3_server_method()));
      if (!context_ || wolfSSL_CTX_set_cipher_list(context_.get(), wolfssl_cipher_name.data()) != WOLFSSL_SUCCESS) {
        return WolfsslDtlsInitializationStatus::wolfssl_initialization_failed;
      }
      (void) wolfSSL_CTX_set_session_cache_mode(context_.get(), WOLFSSL_SESS_CACHE_OFF);

      int group = WOLFSSL_ECC_X25519;
      if (wolfSSL_CTX_set_groups(context_.get(), &group, 1) != WOLFSSL_SUCCESS ||
          wolfSSL_CTX_set_tlsext_use_srtp(context_.get(), required_srtp_profile.data()) != 0 ||
          wolfSSL_CTX_no_ticket_TLSv13(context_.get()) != 0 ||
          certificate_der_.size() > std::numeric_limits<long>::max() ||
          private_key_der_.size() > std::numeric_limits<long>::max() ||
          wolfSSL_CTX_use_certificate_buffer(
            context_.get(),
            certificate_der_.data(),
            static_cast<long>(certificate_der_.size()),
            WOLFSSL_FILETYPE_ASN1
          ) != WOLFSSL_SUCCESS ||
          wolfSSL_CTX_use_PrivateKey_buffer(
            context_.get(),
            private_key_der_.data(),
            static_cast<long>(private_key_der_.size()),
            WOLFSSL_FILETYPE_ASN1
          ) != WOLFSSL_SUCCESS ||
          wolfSSL_CTX_check_private_key(context_.get()) != WOLFSSL_SUCCESS) {
        context_.reset();
        return WolfsslDtlsInitializationStatus::wolfssl_initialization_failed;
      }

      wolfSSL_CTX_set_verify(context_.get(), WOLFSSL_VERIFY_NONE, nullptr);
      wolfSSL_CTX_SetIORecv(context_.get(), receive_callback);
      wolfSSL_CTX_SetIOSend(context_.get(), send_callback);
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
      if (!context_ || !peer.valid() || datagram.empty() || datagram.size() > std::numeric_limits<int>::max()) {
        return ProviderDatagramResult::dropped;
      }

      if (const auto index = find_association(peer); index != associations_.size()) {
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
      attach_io(session.get(), io);
      const auto accept_result = wolfSSL_accept(session.get());
      detach_io(session.get());
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
          .session = std::move(session),
        });
      } catch (...) {
        return ProviderDatagramResult::fatal;
      }
      const auto index = associations_.size() - 1;
      if (accept_result == WOLFSSL_SUCCESS) {
        if (!complete_association(index)) {
          erase_association(index);
          return ProviderDatagramResult::dropped;
        }
      } else if (!acceptable_wolfssl_result(associations_[index].session.get(), accept_result)) {
        erase_association(index);
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
      const auto index = find_association(peer);
      if (index == associations_.size()) {
        return WolfsslDtlsOperationResult::not_found;
      }
      auto &association = associations_[index];
      if (!association.established) {
        return WolfsslDtlsOperationResult::not_established;
      }
      if (plaintext.empty() || plaintext.size() > maximum_dtls_application_record ||
          plaintext.size() > std::numeric_limits<int>::max()) {
        return WolfsslDtlsOperationResult::rejected;
      }

      IoContext io {
        .callbacks = &callbacks_,
        .peer = &association.peer,
      };
      attach_io(association.session.get(), io);
      const auto written = wolfSSL_write(
        association.session.get(),
        plaintext.data(),
        static_cast<int>(plaintext.size())
      );
      detach_io(association.session.get());
      if (written == static_cast<int>(plaintext.size()) && !io.output_failed) {
        return WolfsslDtlsOperationResult::accepted;
      }
      if (io.output_failed) {
        erase_association(index);
        return WolfsslDtlsOperationResult::fatal;
      }
      const auto error = wolfSSL_get_error(association.session.get(), written);
      if (error == WOLFSSL_ERROR_WANT_READ || error == WOLFSSL_ERROR_WANT_WRITE) {
        return WolfsslDtlsOperationResult::rejected;
      }
      erase_association(index);
      return WolfsslDtlsOperationResult::fatal;
    }

    /**
     * @brief Process one expired DTLS retransmission timeout.
     *
     * @param peer Association five-tuple.
     * @return Exact operation disposition.
     */
    WolfsslDtlsOperationResult handle_timeout(const PeerEndpoint &peer) noexcept {
      const auto index = find_association(peer);
      if (index == associations_.size()) {
        return WolfsslDtlsOperationResult::not_found;
      }
      auto &association = associations_[index];
      IoContext io {
        .callbacks = &callbacks_,
        .peer = &association.peer,
      };
      attach_io(association.session.get(), io);
      const auto result = wolfSSL_dtls_got_timeout(association.session.get());
      detach_io(association.session.get());
      if (result == WOLFSSL_SUCCESS && !io.output_failed) {
        return WolfsslDtlsOperationResult::accepted;
      }
      erase_association(index);
      return WolfsslDtlsOperationResult::fatal;
    }

    /**
     * @brief Return the current timeout in whole seconds.
     *
     * @param peer Association five-tuple.
     * @return Positive seconds, or zero when absent or unavailable.
     */
    [[nodiscard]] std::uint32_t timeout_seconds(const PeerEndpoint &peer) const noexcept {
      const auto index = find_association(peer);
      if (index == associations_.size()) {
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
      const auto index = find_association(peer);
      if (index == associations_.size()) {
        return false;
      }
      erase_association(index);
      return true;
    }

    /**
     * @brief Return the configured server SPKI digest.
     *
     * @return SHA-256 SPKI digest.
     */
    [[nodiscard]] Digest256 server_spki_sha256() const noexcept {
      return server_spki_sha256_;
    }

    /**
     * @brief Return retained durable association count.
     *
     * @return Association count.
     */
    [[nodiscard]] std::size_t association_count() const noexcept {
      return associations_.size();
    }

  private:
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
      if (io == nullptr || io->callbacks == nullptr || io->peer == nullptr || buffer == nullptr || size <= 0) {
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
     * @brief Attach one stack I/O context for a synchronous wolfSSL call.
     *
     * @param session wolfSSL association.
     * @param io Live per-call I/O context.
     */
    static void attach_io(WOLFSSL *session, IoContext &io) noexcept {
      wolfSSL_SetIOReadCtx(session, &io);
      wolfSSL_SetIOWriteCtx(session, &io);
    }

    /**
     * @brief Remove stack I/O pointers after a synchronous wolfSSL call.
     *
     * @param session wolfSSL association.
     */
    static void detach_io(WOLFSSL *session) noexcept {
      wolfSSL_SetIOReadCtx(session, nullptr);
      wolfSSL_SetIOWriteCtx(session, nullptr);
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
      attach_io(association.session.get(), io);

      ProviderDatagramResult result = ProviderDatagramResult::accepted;
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
      detach_io(association.session.get());

      if (io.output_failed) {
        result = ProviderDatagramResult::fatal;
      }
      if (result != ProviderDatagramResult::accepted) {
        erase_association(index);
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
      const auto admitted = callbacks_.association_ready(callbacks_.context, association.peer, security);
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
          if (!callbacks_.application_data(
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
    [[nodiscard]] std::size_t find_association(const PeerEndpoint &peer) const noexcept {
      const auto iterator = std::find_if(associations_.begin(), associations_.end(), [&peer](const Association &candidate) {
        return candidate.peer == peer;
      });
      return static_cast<std::size_t>(std::distance(associations_.begin(), iterator));
    }

    /**
     * @brief Notify product state and erase one association.
     *
     * @param index Valid association index.
     */
    void erase_association(const std::size_t index) noexcept {
      notify_closed(associations_[index].peer);
      associations_.erase(associations_.begin() + static_cast<std::ptrdiff_t>(index));
    }

    /**
     * @brief Invoke the optional non-reentrant teardown notification.
     *
     * @param peer Association five-tuple.
     */
    void notify_closed(const PeerEndpoint &peer) const noexcept {
      if (callbacks_.association_closed != nullptr) {
        callbacks_.association_closed(callbacks_.context, peer);
      }
    }

    Context context_;  ///< Exact DTLS 1.3 wolfSSL server context.
    std::vector<std::uint8_t> certificate_der_;  ///< Canonical DER leaf certificate.
    std::vector<std::uint8_t> private_key_der_;  ///< Secret DER private key.
    std::vector<std::uint8_t> cookie_secret_;  ///< Shared address-bound HRR HMAC secret.
    Digest256 server_spki_sha256_ {};  ///< PIN-discovery-compatible server SPKI digest.
    WolfsslDtlsServerCallbacks callbacks_;  ///< Product/socket callbacks.
    std::vector<Association> associations_;  ///< Durable post-cookie associations.
    std::size_t maximum_associations_ {};  ///< Durable association bound.
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

  WolfsslDtlsInitializationStatus WolfsslDtlsServerProvider::initialization_status() const noexcept {
    return status_;
  }

  Digest256 WolfsslDtlsServerProvider::server_spki_sha256() const noexcept {
    return impl_ ? impl_->server_spki_sha256() : Digest256 {};
  }

  std::size_t WolfsslDtlsServerProvider::association_count() const noexcept {
    return impl_ ? impl_->association_count() : 0;
  }
}  // namespace lumen::lsp
