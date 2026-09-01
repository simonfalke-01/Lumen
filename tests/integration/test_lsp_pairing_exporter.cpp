/**
 * @file tests/integration/test_lsp_pairing_exporter.cpp
 * @brief Product-provider equality test for the dedicated LSP pairing TLS exporter.
 */

#include "src/protocol_lsp/security/wolfssl_dtls_server.h"

#include <gtest/gtest.h>

#if LUMEN_LSP_WOLFSSL_AVAILABLE

  #define USE_CERT_BUFFERS_2048
  #include <array>
  #include <cstdint>
  #include <cstring>
  #include <deque>
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
    void *,
    const lsp::PeerEndpoint &,
    std::span<const std::uint8_t>
  ) noexcept {
    return true;
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
    harness.certificate_seen = certificate.size() == sizeof_server_cert_der_2048 && !lsp::is_zero(spki);
    return harness.certificate_seen;
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
    },
  });
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

  wolfSSL_FreeArrays(client);
  wolfSSL_free(client);
  wolfSSL_CTX_free(client_context);
}

#endif
