/**
 * @file tests/unit/test_libsrtp_provider.cpp
 * @brief Focused lifecycle and replay tests for the concrete libSRTP provider.
 */

#include "src/protocol_lsp/runtime/libsrtp_provider.h"

#ifndef LUMEN_LSP_LIBSRTP_AVAILABLE
  #define LUMEN_LSP_LIBSRTP_AVAILABLE 0
#endif

#if LUMEN_LSP_LIBSRTP_AVAILABLE
  #if __has_include(<srtp2/srtp.h>)
    #include <srtp2/srtp.h>
  #else
    #include <srtp.h>
  #endif

  #include <algorithm>
  #include <array>
  #include <cstddef>
  #include <cstdint>
  #include <gtest/gtest.h>
  #include <span>

namespace {
  namespace lsp = lumen::lsp;
  namespace runtime = lumen::lsp::runtime;

  /** @brief Captured callback state for one authenticated packet. */
  struct PlaintextCapture {
    runtime::LibsrtpServerProvider *provider {};  ///< Provider re-entered by the callback.
    std::array<std::uint8_t, 64> plaintext {};  ///< Bounded copied plaintext.
    std::size_t plaintext_bytes {};  ///< Captured plaintext length.
    std::size_t protected_bytes {};  ///< Captured protected datagram length.
    std::size_t association_count {};  ///< Association count queried during callback re-entry.
    unsigned calls {};  ///< Callback invocation count.
  };

  /**
   * @brief Capture authenticated plaintext while re-entering a lock-taking provider method.
   *
   * @param context PlaintextCapture callback state.
   * @param peer Authenticated peer endpoint.
   * @param packet_class Authenticated packet class.
   * @param plaintext Complete decrypted RTP packet.
   * @param protected_bytes Complete protected datagram size.
   * @return True when the bounded capture accepted the packet.
   */
  bool capture_plaintext(
    void *context,
    const lsp::PeerEndpoint &peer,
    const lsp::SecurePacketClass packet_class,
    const std::span<const std::uint8_t> plaintext,
    const std::size_t protected_bytes
  ) noexcept {
    auto &capture = *static_cast<PlaintextCapture *>(context);
    if (capture.provider == nullptr || !peer.valid() || packet_class != lsp::SecurePacketClass::rtp ||
        plaintext.empty() || plaintext.size() > capture.plaintext.size()) {
      return false;
    }
    ++capture.calls;
    capture.plaintext_bytes = plaintext.size();
    capture.protected_bytes = protected_bytes;
    capture.association_count = capture.provider->association_count();
    std::copy(plaintext.begin(), plaintext.end(), capture.plaintext.begin());
    return true;
  }

  /**
   * @brief Return one valid loopback peer identity.
   *
   * @return Exact peer used for the provider association.
   */
  lsp::PeerEndpoint test_peer() {
    return {
      .family = lsp::IpAddressFamily::ipv4,
      .local_address = "127.0.0.1",
      .local_port = 48'030,
      .remote_address = "127.0.0.2",
      .remote_port = 50'000,
    };
  }

  /**
   * @brief Return deterministic directional key material for one test association.
   *
   * @return Nonzero client and server SRTP keys and salts.
   */
  lsp::DtlsSrtpKeyMaterial test_key_material() {
    lsp::DtlsSrtpKeyMaterial material;
    for (std::size_t index = 0; index < material.client_write_key.size(); ++index) {
      material.client_write_key[index] = static_cast<std::uint8_t>(0x10U + index);
      material.server_write_key[index] = static_cast<std::uint8_t>(0x30U + index);
    }
    for (std::size_t index = 0; index < material.client_write_salt.size(); ++index) {
      material.client_write_salt[index] = static_cast<std::uint8_t>(0x50U + index);
      material.server_write_salt[index] = static_cast<std::uint8_t>(0x70U + index);
    }
    return material;
  }
}  // namespace

TEST(LibsrtpServerProvider, PlaintextCallbackReentersWithoutBlockingAndReplayIsDropped) {
  PlaintextCapture capture;
  runtime::LibsrtpServerProvider provider {
    {
      .context = &capture,
      .plaintext_packet = capture_plaintext,
    },
    1,
  };
  capture.provider = &provider;

  ASSERT_TRUE(provider.ready(lsp::SrtpRequirements {}));
  const auto peer = test_peer();
  const auto key_material = test_key_material();
  ASSERT_TRUE(provider.install_association(peer, key_material));

  constexpr std::size_t master_material_size = lsp::srtp_aes_128_key_size + lsp::srtp_aead_salt_size;
  std::array<std::uint8_t, master_material_size> client_material {};
  std::copy(key_material.client_write_key.begin(), key_material.client_write_key.end(), client_material.begin());
  std::copy(
    key_material.client_write_salt.begin(),
    key_material.client_write_salt.end(),
    client_material.begin() + lsp::srtp_aes_128_key_size
  );

  srtp_policy_t client_policy {};
  srtp_crypto_policy_set_aes_gcm_128_16_auth(&client_policy.rtp);
  srtp_crypto_policy_set_aes_gcm_128_16_auth(&client_policy.rtcp);
  client_policy.ssrc.type = ssrc_any_outbound;
  client_policy.key = client_material.data();
  client_policy.window_size = 128;
  client_policy.allow_repeat_tx = 0;

  srtp_t client {};
  ASSERT_EQ(srtp_create(&client, &client_policy), srtp_err_status_ok);

  constexpr std::array<std::uint8_t, 16> plaintext_packet {
    0x80,
    96,
    0,
    1,
    0,
    0,
    0,
    1,
    0x12,
    0x34,
    0x56,
    0x78,
    0xde,
    0xad,
    0xbe,
    0xef,
  };
  std::array<std::uint8_t, 64> packet {};
  std::copy(plaintext_packet.begin(), plaintext_packet.end(), packet.begin());
  constexpr std::size_t plaintext_bytes = plaintext_packet.size();
  auto protected_bytes = static_cast<int>(plaintext_bytes);
  ASSERT_EQ(srtp_protect(client, packet.data(), &protected_bytes), srtp_err_status_ok);
  ASSERT_EQ(srtp_dealloc(client), srtp_err_status_ok);

  const auto protected_packet = std::span<const std::uint8_t> {
    packet.data(),
    static_cast<std::size_t>(protected_bytes),
  };
  EXPECT_EQ(
    provider.receive_secure_packet(peer, lsp::SecurePacketClass::rtp, protected_packet),
    lsp::ProviderDatagramResult::accepted
  );
  EXPECT_EQ(capture.calls, 1U);
  EXPECT_EQ(capture.association_count, 1U);
  EXPECT_EQ(capture.plaintext_bytes, plaintext_bytes);
  EXPECT_EQ(capture.protected_bytes, protected_packet.size());
  EXPECT_TRUE(std::ranges::equal(std::span<const std::uint8_t> {capture.plaintext.data(), capture.plaintext_bytes}, plaintext_packet));

  EXPECT_EQ(
    provider.receive_secure_packet(peer, lsp::SecurePacketClass::rtp, protected_packet),
    lsp::ProviderDatagramResult::dropped
  );
  EXPECT_EQ(capture.calls, 1U);
  EXPECT_TRUE(provider.remove_association(peer));
}
#endif
