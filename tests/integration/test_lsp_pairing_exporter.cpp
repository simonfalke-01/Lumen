/**
 * @file tests/integration/test_lsp_pairing_exporter.cpp
 * @brief Product-provider equality test for the dedicated LSP pairing TLS exporter.
 */

#include "src/protocol_lsp/security/wolfssl_dtls_server.h"

#include <gtest/gtest.h>

#if LUMEN_LSP_WOLFSSL_AVAILABLE

  #define USE_CERT_BUFFERS_2048
  #include <algorithm>
  #include <array>
  #include <cstdint>
  #include <cstring>
  #include <deque>
  #include <thread>
  #include <utility>
  #include <vector>
// clang-format off
  #include <wolfssl/options.h>
  #include <wolfssl/certs_test.h>
  #include <wolfssl/error-ssl.h>
  #include <wolfssl/ssl.h>
  #include <wolfssl/wolfio.h>
// clang-format on

namespace {
  namespace lsp = lumen::lsp;

  /** @brief In-memory datagram queues and product callback observations. */
  struct PairingExporterHarness {
    std::deque<std::vector<std::uint8_t>> client_to_server;  ///< Client-emitted DTLS datagrams.
    std::deque<std::vector<std::uint8_t>> server_to_client;  ///< Product-server-emitted DTLS datagrams.
    lsp::PairingExporter server_pairing_exporter {};  ///< Product callback exporter.
    lsp::WolfsslDtlsServerProvider *provider {};  ///< Product provider used for nested callback operations.
    std::array<std::uint8_t, 32> reply {};  ///< Nested application response bytes.
    std::size_t reply_size {};  ///< Active nested response bytes.
    std::size_t application_calls {};  ///< Authenticated application callback count.
    std::size_t closed_calls {};  ///< Exactly-once association close notifications.
    bool close_during_application {};  ///< Request a reentrant close after queuing the response.
    bool accept_application {true};  ///< Malformed-LSP simulation gate.
    bool certificate_seen {};  ///< Product certificate callback observation.
    bool association_ready {};  ///< Product association callback observation.
  };

  /** @brief Capture one product-server DTLS datagram. */
  bool server_send(
    void *context,
    const lsp::PeerEndpoint &,
    const std::span<const std::uint8_t> datagram
  ) noexcept {
    auto &harness = *static_cast<PairingExporterHarness *>(context);
    harness.server_to_client.emplace_back(datagram.begin(), datagram.end());
    return true;
  }

  /** @brief Accept no application data during the handshake-only test. */
  bool server_application_data(
    void *context,
    const lsp::PeerEndpoint &peer,
    std::span<const std::uint8_t>
  ) noexcept {
    auto &harness = *static_cast<PairingExporterHarness *>(context);
    ++harness.application_calls;
    if (harness.provider != nullptr && harness.reply_size != 0) {
      if (harness.provider->send_application_data(
            peer,
            std::span<const std::uint8_t> {harness.reply.data(), harness.reply_size}
          ) != lsp::WolfsslDtlsOperationResult::accepted) {
        return false;
      }
    }
    if (harness.provider != nullptr && harness.close_during_application) {
      (void) harness.provider->close_association(peer);
    }
    return harness.accept_application;
  }

  /** @brief Capture the product provider's dedicated exporter. */
  bool server_ready(
    void *context,
    const lsp::PeerEndpoint &,
    const lsp::DtlsAssociationSecurity &security
  ) noexcept {
    auto &harness = *static_cast<PairingExporterHarness *>(context);
    harness.server_pairing_exporter = security.pairing_exporter;
    harness.association_ready = true;
    return true;
  }

  /** @brief Accept the canonical test certificate/SPKI pair. */
  bool server_certificate(
    void *context,
    const std::span<const std::uint8_t> certificate,
    const lsp::Digest256 &spki
  ) noexcept {
    auto &harness = *static_cast<PairingExporterHarness *>(context);
    harness.certificate_seen = !certificate.empty() && !lsp::is_zero(spki);
    return harness.certificate_seen;
  }

  /** @brief Count product association teardown notifications. */
  void server_closed(void *context, const lsp::PeerEndpoint &) noexcept {
    ++static_cast<PairingExporterHarness *>(context)->closed_calls;
  }

  /** @brief Queue one client DTLS datagram. */
  int client_send(WOLFSSL *, char *buffer, const int size, void *context) {
    auto &harness = *static_cast<PairingExporterHarness *>(context);
    harness.client_to_server.emplace_back(
      reinterpret_cast<std::uint8_t *>(buffer),
      reinterpret_cast<std::uint8_t *>(buffer) + size
    );
    return size;
  }

  /** @brief Deliver one complete product-server DTLS datagram to wolfSSL. */
  int client_receive(WOLFSSL *, char *buffer, const int size, void *context) {
    auto &harness = *static_cast<PairingExporterHarness *>(context);
    if (harness.server_to_client.empty()) {
      return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    auto datagram = std::move(harness.server_to_client.front());
    harness.server_to_client.pop_front();
    if (datagram.size() > static_cast<std::size_t>(size)) {
      return WOLFSSL_CBIO_ERR_GENERAL;
    }
    std::memcpy(buffer, datagram.data(), datagram.size());
    return static_cast<int>(datagram.size());
  }
}  // namespace

TEST(LspPairingExporter, ProductServerMatchesExplicitEmptyContextPeer) {
  PairingExporterHarness harness;
  std::array<std::uint8_t, 32> cookie_secret;
  cookie_secret.fill(0x5a);
  lsp::WolfsslDtlsServerProvider server({
    .certificate_der = std::span {server_cert_der_2048},
    .private_key_der = std::span {server_key_der_2048},
    .cookie_secret = cookie_secret,
    .callbacks = {
      .context = &harness,
      .send_datagram = server_send,
      .application_data = server_application_data,
      .association_ready = server_ready,
      .server_certificate = server_certificate,
      .association_closed = server_closed,
    },
  });
  harness.provider = &server;
  ASSERT_EQ(server.initialization_status(), lsp::WolfsslDtlsInitializationStatus::ready);
  ASSERT_TRUE(server.ready(lsp::DtlsRequirements {}));
  ASSERT_TRUE(harness.certificate_seen);

  const lsp::PeerEndpoint peer {
    .family = lsp::IpAddressFamily::ipv4,
    .local_address = "127.0.0.1",
    .local_port = lsp::default_udp_port,
    .remote_address = "127.0.0.1",
    .remote_port = 50'000,
  };

  WOLFSSL_CTX *client_context = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());
  ASSERT_NE(client_context, nullptr);
  ASSERT_EQ(wolfSSL_CTX_set_cipher_list(client_context, "TLS13-AES128-GCM-SHA256"), WOLFSSL_SUCCESS);
  int group = WOLFSSL_ECC_X25519;
  ASSERT_EQ(wolfSSL_CTX_set_groups(client_context, &group, 1), WOLFSSL_SUCCESS);
  ASSERT_EQ(wolfSSL_CTX_set_tlsext_use_srtp(client_context, "SRTP_AEAD_AES_128_GCM"), 0);
  wolfSSL_CTX_set_verify(client_context, WOLFSSL_VERIFY_NONE, nullptr);
  wolfSSL_CTX_SetIORecv(client_context, client_receive);
  wolfSSL_CTX_SetIOSend(client_context, client_send);

  WOLFSSL *client = wolfSSL_new(client_context);
  ASSERT_NE(client, nullptr);
  char selected_alpn[] = "lumen-stream/1";
  ASSERT_EQ(
    wolfSSL_UseALPN(
      client,
      selected_alpn,
      static_cast<unsigned int>(sizeof(selected_alpn) - 1),
      WOLFSSL_ALPN_FAILED_ON_MISMATCH
    ),
    WOLFSSL_SUCCESS
  );
  wolfSSL_dtls_set_using_nonblock(client, 1);
  wolfSSL_SetIOReadCtx(client, &harness);
  wolfSSL_SetIOWriteCtx(client, &harness);
  wolfSSL_KeepArrays(client);

  bool client_connected = false;
  for (std::size_t iteration = 0; iteration < 100 && (!client_connected || !harness.association_ready); ++iteration) {
    const auto connect_result = wolfSSL_connect(client);
    if (connect_result == WOLFSSL_SUCCESS) {
      client_connected = true;
    } else {
      const auto error = wolfSSL_get_error(client, connect_result);
      ASSERT_TRUE(error == WOLFSSL_ERROR_WANT_READ || error == WOLFSSL_ERROR_WANT_WRITE);
    }
    while (!harness.client_to_server.empty()) {
      auto datagram = std::move(harness.client_to_server.front());
      harness.client_to_server.pop_front();
      ASSERT_EQ(server.receive_dtls(peer, datagram), lsp::ProviderDatagramResult::accepted);
    }
  }
  ASSERT_TRUE(client_connected);
  ASSERT_TRUE(harness.association_ready);

  lsp::PairingExporter client_pairing_exporter {};
  static constexpr std::uint8_t empty_context = 0;
  ASSERT_EQ(
    wolfSSL_export_keying_material(
      client,
      client_pairing_exporter.data(),
      client_pairing_exporter.size(),
      lsp::pairing_exporter_label.data(),
      lsp::pairing_exporter_label.size(),
      &empty_context,
      0,
      1
    ),
    WOLFSSL_SUCCESS
  );
  EXPECT_EQ(client_pairing_exporter, harness.server_pairing_exporter);

  // A completed association must never consume handshake retransmission
  // attempts. Previously these stale timer callbacks closed live streams
  // after the exponential handshake backoff exhausted its maximum.
  EXPECT_EQ(server.timeout_seconds(peer), 0U);
  for (std::size_t attempt = 0; attempt < 10; ++attempt) {
    EXPECT_EQ(server.handle_timeout(peer), lsp::WolfsslDtlsOperationResult::accepted);
  }
  EXPECT_EQ(server.association_count(), 1U);
  EXPECT_EQ(harness.closed_calls, 0U);

  constexpr std::array<std::uint8_t, 5> nested_reply {'r', 'e', 'p', 'l', 'y'};
  std::copy(nested_reply.begin(), nested_reply.end(), harness.reply.begin());
  harness.reply_size = nested_reply.size();
  constexpr std::array<std::uint8_t, 7> request {'r', 'e', 'q', 'u', 'e', 's', 't'};
  ASSERT_EQ(wolfSSL_write(client, request.data(), static_cast<int>(request.size())), static_cast<int>(request.size()));
  while (!harness.client_to_server.empty()) {
    auto datagram = std::move(harness.client_to_server.front());
    harness.client_to_server.pop_front();
    ASSERT_EQ(server.receive_dtls(peer, datagram), lsp::ProviderDatagramResult::accepted);
  }
  EXPECT_EQ(harness.application_calls, 1U);
  EXPECT_EQ(server.association_count(), 1U);
  std::array<std::uint8_t, 32> received_reply {};
  ASSERT_EQ(
    wolfSSL_read(client, received_reply.data(), static_cast<int>(received_reply.size())),
    static_cast<int>(nested_reply.size())
  );
  EXPECT_TRUE(std::ranges::equal(std::span {received_reply}.first(nested_reply.size()), nested_reply));

  ASSERT_TRUE(server.rotate_identity(
    std::span {client_cert_der_2048},
    std::span {client_key_der_2048},
    cookie_secret
  ));
  ASSERT_EQ(wolfSSL_write(client, request.data(), static_cast<int>(request.size())), static_cast<int>(request.size()));
  while (!harness.client_to_server.empty()) {
    auto datagram = std::move(harness.client_to_server.front());
    harness.client_to_server.pop_front();
    ASSERT_EQ(server.receive_dtls(peer, datagram), lsp::ProviderDatagramResult::accepted);
  }
  EXPECT_EQ(harness.application_calls, 2U);
  ASSERT_EQ(
    wolfSSL_read(client, received_reply.data(), static_cast<int>(received_reply.size())),
    static_cast<int>(nested_reply.size())
  );

  harness.reply_size = 0;
  harness.close_during_application = true;
  harness.accept_application = false;
  bool admin_close_queued = false;
  std::thread admin_close([&]() {
    admin_close_queued = server.request_close(peer);
  });
  admin_close.join();
  constexpr std::array<std::uint8_t, 3> malformed {'b', 'a', 'd'};
  ASSERT_EQ(
    wolfSSL_write(client, malformed.data(), static_cast<int>(malformed.size())),
    static_cast<int>(malformed.size())
  );
  ASSERT_FALSE(harness.client_to_server.empty());
  auto malformed_datagram = std::move(harness.client_to_server.front());
  harness.client_to_server.pop_front();
  EXPECT_EQ(server.receive_dtls(peer, malformed_datagram), lsp::ProviderDatagramResult::fatal);
  EXPECT_TRUE(admin_close_queued);
  EXPECT_EQ(harness.closed_calls, 1U);
  EXPECT_EQ(server.association_count(), 0U);
  ASSERT_TRUE(server.rotate_identity(
    std::span {server_cert_der_2048},
    std::span {server_key_der_2048},
    cookie_secret
  ));

  wolfSSL_FreeArrays(client);
  wolfSSL_free(client);

  harness.accept_application = true;
  harness.close_during_application = false;
  harness.association_ready = false;
  harness.client_to_server.clear();
  harness.server_to_client.clear();
  client = wolfSSL_new(client_context);
  ASSERT_NE(client, nullptr);
  ASSERT_EQ(
    wolfSSL_UseALPN(
      client,
      selected_alpn,
      static_cast<unsigned int>(sizeof(selected_alpn) - 1),
      WOLFSSL_ALPN_FAILED_ON_MISMATCH
    ),
    WOLFSSL_SUCCESS
  );
  wolfSSL_dtls_set_using_nonblock(client, 1);
  wolfSSL_SetIOReadCtx(client, &harness);
  wolfSSL_SetIOWriteCtx(client, &harness);
  wolfSSL_KeepArrays(client);
  client_connected = false;
  for (std::size_t iteration = 0; iteration < 100 && (!client_connected || !harness.association_ready); ++iteration) {
    const auto connect_result = wolfSSL_connect(client);
    if (connect_result == WOLFSSL_SUCCESS) {
      client_connected = true;
    } else {
      const auto error = wolfSSL_get_error(client, connect_result);
      ASSERT_TRUE(error == WOLFSSL_ERROR_WANT_READ || error == WOLFSSL_ERROR_WANT_WRITE);
    }
    while (!harness.client_to_server.empty()) {
      auto datagram = std::move(harness.client_to_server.front());
      harness.client_to_server.pop_front();
      ASSERT_EQ(server.receive_dtls(peer, datagram), lsp::ProviderDatagramResult::accepted);
    }
  }
  ASSERT_TRUE(client_connected);
  ASSERT_TRUE(harness.association_ready);
  EXPECT_EQ(server.drain_all(), 1U);
  EXPECT_EQ(harness.closed_calls, 2U);
  server.disable_callbacks();
  wolfSSL_FreeArrays(client);
  wolfSSL_free(client);
  wolfSSL_CTX_free(client_context);
}

#endif
