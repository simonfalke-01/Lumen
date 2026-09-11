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
  #include <atomic>
  #include <chrono>
  #include <cstddef>
  #include <cstdint>
  #include <gtest/gtest.h>
  #include <span>
  #include <thread>

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
    std::uint64_t received_at_microseconds {};  ///< Preserved socket timestamp.
    lsp::IpEcn ecn {lsp::IpEcn::unavailable};  ///< Preserved authenticated IP ECN observation.
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
    const std::size_t protected_bytes,
    const std::uint64_t received_at_microseconds,
    const lsp::IpEcn ecn
  ) noexcept {
    auto &capture = *static_cast<PlaintextCapture *>(context);
    if (capture.provider == nullptr || !peer.valid() || packet_class != lsp::SecurePacketClass::rtp ||
        plaintext.empty() || plaintext.size() > capture.plaintext.size()) {
      return false;
    }
    ++capture.calls;
    capture.plaintext_bytes = plaintext.size();
    capture.protected_bytes = protected_bytes;
    capture.received_at_microseconds = received_at_microseconds;
    capture.ecn = ecn;
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
  constexpr std::uint32_t input_ssrc = 0x12345678U;
  ASSERT_TRUE(provider.install_stream(peer, lsp::MediaDirection::client_to_host, input_ssrc));

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
  client_policy.ssrc.type = ssrc_specific;
  client_policy.ssrc.value = input_ssrc;
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

  std::array<std::uint8_t, 64> replay_packet = packet;
  const auto protected_packet_bytes = static_cast<std::size_t>(protected_bytes);
  constexpr std::uint64_t received_at_microseconds = 123'456'789U;
  EXPECT_EQ(
    provider.receive_secure_packet(
      peer,
      lsp::SecurePacketClass::rtp,
      std::span<std::uint8_t> {packet}.first(protected_packet_bytes),
      received_at_microseconds,
      lsp::IpEcn::congestion_experienced
    ),
    lsp::ProviderDatagramResult::accepted
  );
  EXPECT_EQ(capture.calls, 1U);
  EXPECT_EQ(capture.association_count, 1U);
  EXPECT_EQ(capture.plaintext_bytes, plaintext_bytes);
  EXPECT_EQ(capture.protected_bytes, protected_packet_bytes);
  EXPECT_EQ(capture.received_at_microseconds, received_at_microseconds);
  EXPECT_EQ(capture.ecn, lsp::IpEcn::congestion_experienced);
  EXPECT_TRUE(std::ranges::equal(std::span<const std::uint8_t> {capture.plaintext.data(), capture.plaintext_bytes}, plaintext_packet));

  EXPECT_EQ(
    provider.receive_secure_packet(
      peer,
      lsp::SecurePacketClass::rtp,
      std::span<std::uint8_t> {replay_packet}.first(protected_packet_bytes),
      received_at_microseconds + 1,
      lsp::IpEcn::not_ect
    ),
    lsp::ProviderDatagramResult::dropped
  );
  EXPECT_EQ(capture.calls, 1U);
  EXPECT_TRUE(provider.remove_association(peer));
}

TEST(LibsrtpServerProvider, RejectsPrevisibleSsrcAndSeparatesConcurrentDirections) {
  PlaintextCapture capture;
  runtime::LibsrtpServerProvider provider {
    {
      .context = &capture,
      .plaintext_packet = capture_plaintext,
    },
    1,
  };
  capture.provider = &provider;
  const auto peer = test_peer();
  const auto key_material = test_key_material();
  ASSERT_TRUE(provider.install_association(peer, key_material));
  constexpr std::uint32_t input_ssrc = 0x12345678U;
  constexpr std::uint32_t output_ssrc = 0x87654321U;

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
  client_policy.ssrc.type = ssrc_specific;
  client_policy.ssrc.value = input_ssrc;
  client_policy.key = client_material.data();
  client_policy.window_size = 128;
  srtp_t client {};
  ASSERT_EQ(srtp_create(&client, &client_policy), srtp_err_status_ok);

  const auto make_input_packet = [&](const std::uint16_t sequence) {
    std::array<std::uint8_t, 64> packet {
      0x80,
      96,
      static_cast<std::uint8_t>(sequence >> 8U),
      static_cast<std::uint8_t>(sequence),
      0,
      0,
      0,
      static_cast<std::uint8_t>(sequence),
      0x12,
      0x34,
      0x56,
      0x78,
      0xde,
      0xad,
      0xbe,
      0xef,
    };
    auto size = 16;
    EXPECT_EQ(srtp_protect(client, packet.data(), &size), srtp_err_status_ok);
    return std::pair {packet, static_cast<std::size_t>(size)};
  };

  auto [invisible_packet, invisible_size] = make_input_packet(1);
  EXPECT_EQ(
    provider.receive_secure_packet(
      peer,
      lsp::SecurePacketClass::rtp,
      std::span<std::uint8_t> {invisible_packet}.first(invisible_size),
      10,
      lsp::IpEcn::not_ect
    ),
    lsp::ProviderDatagramResult::dropped
  );
  EXPECT_EQ(capture.calls, 0U);

  ASSERT_TRUE(provider.install_stream(peer, lsp::MediaDirection::client_to_host, input_ssrc));
  ASSERT_TRUE(provider.install_stream(peer, lsp::MediaDirection::host_to_client, output_ssrc));
  std::atomic<bool> inbound_ok {true};
  std::atomic<bool> outbound_ok {true};
  std::thread inbound([&]() {
    for (std::uint16_t sequence = 2; sequence < 102; ++sequence) {
      auto [packet, size] = make_input_packet(sequence);
      if (provider.receive_secure_packet(
            peer,
            lsp::SecurePacketClass::rtp,
            std::span<std::uint8_t> {packet}.first(size),
            1'000U + sequence,
            lsp::IpEcn::ect_0
          ) != lsp::ProviderDatagramResult::accepted) {
        inbound_ok.store(false, std::memory_order_release);
        return;
      }
    }
  });
  std::thread outbound([&]() {
    for (std::uint16_t sequence = 1; sequence < 101; ++sequence) {
      std::array<std::uint8_t, 64> packet {
        0x80,
        97,
        static_cast<std::uint8_t>(sequence >> 8U),
        static_cast<std::uint8_t>(sequence),
        0,
        0,
        0,
        static_cast<std::uint8_t>(sequence),
        0x87,
        0x65,
        0x43,
        0x21,
        1,
        2,
        3,
        4,
      };
      std::size_t protected_size = 0;
      if (!provider.protect_in_place(
            peer,
            lsp::SecurePacketClass::rtp,
            packet,
            16,
            protected_size
          ) ||
          protected_size <= 16) {
        outbound_ok.store(false, std::memory_order_release);
        return;
      }
    }
  });
  inbound.join();
  outbound.join();
  EXPECT_TRUE(inbound_ok.load(std::memory_order_acquire));
  EXPECT_TRUE(outbound_ok.load(std::memory_order_acquire));
  EXPECT_EQ(capture.calls, 100U);
  EXPECT_EQ(srtp_dealloc(client), srtp_err_status_ok);
  EXPECT_TRUE(provider.remove_association(peer));
}

TEST(LibsrtpServerProvider, ThreadCacheKeysTheEndpointValueRatherThanTheCallerAddress) {
  PlaintextCapture capture;
  runtime::LibsrtpServerProvider provider {
    {
      .context = &capture,
      .plaintext_packet = capture_plaintext,
    },
    2,
  };
  capture.provider = &provider;

  const auto first_peer = test_peer();
  auto second_peer = first_peer;
  second_peer.remote_port = static_cast<std::uint16_t>(first_peer.remote_port + 1U);
  const auto key_material = test_key_material();
  ASSERT_TRUE(provider.install_association(first_peer, key_material));
  ASSERT_TRUE(provider.install_association(second_peer, key_material));
  constexpr std::uint32_t first_ssrc = 0x12345678U;
  constexpr std::uint32_t second_ssrc = 0x87654321U;
  ASSERT_TRUE(provider.install_stream(first_peer, lsp::MediaDirection::host_to_client, first_ssrc));
  ASSERT_TRUE(provider.install_stream(second_peer, lsp::MediaDirection::host_to_client, second_ssrc));

  lsp::PeerEndpoint selected_peer = first_peer;
  std::array<std::uint8_t, 64> first_packet {
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
  };
  std::size_t protected_bytes = 0;
  ASSERT_TRUE(provider.protect_in_place(selected_peer, lsp::SecurePacketClass::rtp, first_packet, 12, protected_bytes));

  selected_peer = second_peer;
  std::array<std::uint8_t, 64> second_packet {
    0x80,
    96,
    0,
    1,
    0,
    0,
    0,
    1,
    0x87,
    0x65,
    0x43,
    0x21,
  };
  ASSERT_TRUE(provider.protect_in_place(selected_peer, lsp::SecurePacketClass::rtp, second_packet, 12, protected_bytes));
  EXPECT_TRUE(provider.remove_association(first_peer));
  EXPECT_TRUE(provider.remove_association(second_peer));

  std::array<std::uint8_t, 64> retired_packet {
    0x80,
    96,
    0,
    2,
    0,
    0,
    0,
    2,
    0x87,
    0x65,
    0x43,
    0x21,
  };
  EXPECT_FALSE(provider.protect_in_place(selected_peer, lsp::SecurePacketClass::rtp, retired_packet, 12, protected_bytes));
  EXPECT_EQ(protected_bytes, 0U);

  ASSERT_TRUE(provider.install_association(second_peer, key_material));
  ASSERT_TRUE(provider.install_stream(second_peer, lsp::MediaDirection::host_to_client, second_ssrc));
  std::array<std::uint8_t, 64> replacement_packet {
    0x80,
    96,
    0,
    1,
    0,
    0,
    0,
    1,
    0x87,
    0x65,
    0x43,
    0x21,
  };
  EXPECT_TRUE(provider.protect_in_place(
    selected_peer,
    lsp::SecurePacketClass::rtp,
    replacement_packet,
    12,
    protected_bytes
  ));
  EXPECT_TRUE(provider.remove_association(second_peer));
}

TEST(LibsrtpServerProvider, RemovalQuiescesConcurrentCryptoAndRejectsLaterProtection) {
  PlaintextCapture capture;
  runtime::LibsrtpServerProvider provider {
    {
      .context = &capture,
      .plaintext_packet = capture_plaintext,
    },
    1,
  };
  capture.provider = &provider;
  const auto peer = test_peer();
  ASSERT_TRUE(provider.install_association(peer, test_key_material()));
  constexpr std::uint32_t output_ssrc = 0x87654321U;
  ASSERT_TRUE(provider.install_stream(peer, lsp::MediaDirection::host_to_client, output_ssrc));

  std::atomic_uint attempts {};
  std::atomic_bool stop_requested {};
  std::thread protector([&]() {
    for (std::uint32_t ordinal = 1; !stop_requested.load(std::memory_order_acquire); ++ordinal) {
      const auto sequence = static_cast<std::uint16_t>(ordinal);
      std::array<std::uint8_t, 64> packet {
        0x80,
        97,
        static_cast<std::uint8_t>(sequence >> 8U),
        static_cast<std::uint8_t>(sequence),
        0,
        0,
        0,
        static_cast<std::uint8_t>(sequence),
        0x87,
        0x65,
        0x43,
        0x21,
      };
      std::size_t protected_bytes = 0;
      const auto protected_packet = provider.protect_in_place(
        peer,
        lsp::SecurePacketClass::rtp,
        packet,
        12,
        protected_bytes
      );
      attempts.fetch_add(1, std::memory_order_release);
      if (!protected_packet) {
        return;
      }
    }
  });
  const auto wait_deadline = std::chrono::steady_clock::now() + std::chrono::seconds {1};
  while (attempts.load(std::memory_order_acquire) < 32U &&
         std::chrono::steady_clock::now() < wait_deadline) {
    std::this_thread::yield();
  }
  EXPECT_GE(attempts.load(std::memory_order_acquire), 32U);
  const auto removed_association = provider.remove_association(peer);
  stop_requested.store(true, std::memory_order_release);
  protector.join();

  EXPECT_TRUE(removed_association);
  EXPECT_EQ(provider.association_count(), 0U);
  std::array<std::uint8_t, 64> retired_packet {
    0x80,
    97,
    0,
    1,
    0,
    0,
    0,
    1,
    0x87,
    0x65,
    0x43,
    0x21,
  };
  std::size_t protected_bytes = 0;
  EXPECT_FALSE(provider.protect_in_place(peer, lsp::SecurePacketClass::rtp, retired_packet, 12, protected_bytes));
}
#endif
