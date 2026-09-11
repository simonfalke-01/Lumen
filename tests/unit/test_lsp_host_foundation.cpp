/**
 * @file tests/unit/test_lsp_host_foundation.cpp
 * @brief Concrete invariant tests for the host-side LSP foundation.
 */

#include "src/protocol_lsp/core/wire.h"
#include "src/protocol_lsp/packet_classifier.h"
#include "src/protocol_lsp/runtime/host_runtime.h"
#include "src/protocol_lsp/runtime/input_owner.h"
#include "src/protocol_lsp/runtime/microphone_receiver.h"
#include "src/protocol_lsp/runtime/udp_socket.h"
#include "src/protocol_lsp/runtime/video_sender.h"
#include "src/protocol_lsp/service.h"
#include "src/protocol_lsp/session_authority.h"
#include "src/protocol_lsp/ssrc_registry.h"
#include "src/protocol_lsp/types.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <future>
#include <gtest/gtest.h>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace {
  namespace lsp = lumen::lsp;

  template<std::size_t Size>
  std::array<std::uint8_t, Size> filled(const std::uint8_t value) {
    std::array<std::uint8_t, Size> output {};
    output.fill(value);
    return output;
  }

  lsp::PermissionSet permissions(const std::uint32_t mask = lsp::PermissionSet::default_pairing_mask) {
    return *lsp::PermissionSet::from_mask(mask);
  }

  lsp::AuthenticatedClient client(const std::uint32_t connection_generation = 10) {
    return {
      .client_id = filled<16>(7),
      .connection_generation = connection_generation,
      .revocation_generation = 1,
      .permissions = permissions(),
    };
  }

  lsp::StartAuthority start_authority() {
    return {
      .session_id = filled<16>(8),
      .attach_token = filled<32>(9),
      .generations = {
        .connection = 10,
        .stream = 20,
        .video = 30,
        .audio = 40,
        .microphone = 50,
        .input = 60,
      },
    };
  }

  class FakeSocket final: public lsp::SinglePortUdpSocket {
  public:
    bool bind(const std::uint16_t port) noexcept override {
      ++bind_calls;
      bound_port = port;
      return bind_result;
    }

    void close() noexcept override {
      ++close_calls;
    }

    bool bind_result {true};
    unsigned bind_calls {};
    unsigned close_calls {};
    std::uint16_t bound_port {};
  };

  class FakeDtls final: public lsp::DtlsServerProvider {
  public:
    bool ready(const lsp::DtlsRequirements &requirements) const noexcept override {
      observed_exact_policy = requirements.require_dtls_1_3 && requirements.require_stateless_cookie &&
                              requirements.alpn_protocol == lsp::alpn && !requirements.allow_early_data &&
                              !requirements.allow_resumption;
      return ready_result;
    }

    lsp::ProviderDatagramResult receive_dtls(
      const lsp::PeerEndpoint &,
      const std::span<const std::uint8_t>
    ) noexcept override {
      ++receive_calls;
      return receive_result;
    }

    bool ready_result {true};
    lsp::ProviderDatagramResult receive_result {lsp::ProviderDatagramResult::accepted};
    mutable bool observed_exact_policy {};
    std::atomic<unsigned> receive_calls {};
  };

  class BlockingDtls final: public lsp::DtlsServerProvider {
  public:
    bool ready(const lsp::DtlsRequirements &) const noexcept override {
      return true;
    }

    lsp::ProviderDatagramResult receive_dtls(
      const lsp::PeerEndpoint &,
      std::span<const std::uint8_t>
    ) noexcept override {
      std::unique_lock lock(mutex);
      entered = true;
      changed.notify_all();
      changed.wait(lock, [this]() {
        return released;
      });
      return lsp::ProviderDatagramResult::accepted;
    }

    std::mutex mutex;  ///< Synchronizes the deliberately in-flight provider call.
    std::condition_variable changed;  ///< Wakes test and provider at exact state transitions.
    bool entered {};  ///< Whether the provider callback owns its stack frame.
    bool released {};  ///< Whether the test permits the provider callback to return.
  };

  class FakeSrtp final: public lsp::SrtpProvider {
  public:
    bool ready(const lsp::SrtpRequirements &requirements) const noexcept override {
      observed_exact_policy = requirements.protection_profile == "SRTP_AEAD_AES_128_GCM" &&
                              requirements.require_replay_protection && requirements.require_encrypted_extensions &&
                              !requirements.allow_mki;
      return ready_result;
    }

    lsp::ProviderDatagramResult receive_secure_packet(
      const lsp::PeerEndpoint &,
      const lsp::SecurePacketClass packet_class,
      const std::span<std::uint8_t>,
      const std::uint64_t received_at_microseconds,
      const lsp::IpEcn ecn
    ) noexcept override {
      ++receive_calls;
      last_class = packet_class;
      last_received_at_microseconds = received_at_microseconds;
      last_ecn = ecn;
      return receive_result;
    }

    bool ready_result {true};
    lsp::ProviderDatagramResult receive_result {lsp::ProviderDatagramResult::accepted};
    mutable bool observed_exact_policy {};
    unsigned receive_calls {};
    lsp::SecurePacketClass last_class {lsp::SecurePacketClass::invalid};
    std::uint64_t last_received_at_microseconds {};
    lsp::IpEcn last_ecn {lsp::IpEcn::unavailable};
  };

  class FakeNeutralizer final: public lsp::InputNeutralizer {
  public:
    bool neutralize(const lsp::NeutralizationRequest &request) noexcept override {
      ++calls;
      last_request = request;
      return result;
    }

    bool result {true};
    unsigned calls {};
    lsp::NeutralizationRequest last_request;
  };

  class FakeTokenVerifier final: public lsp::AttachTokenVerifier {
  public:
    bool matches(
      const lsp::Secret256 &presented,
      const lsp::Secret256 &expected
    ) const noexcept override {
      ++calls;
      return presented == expected;
    }

    mutable unsigned calls {};
  };

  lsp::SsrcAssignment video_primary() {
    return {
      .ssrc = 100,
      .payload_type = 96,
      .lane = lsp::MediaLane::video_primary,
      .direction = lsp::MediaDirection::host_to_client,
      .format = lsp::PayloadFormat::h264,
      .clock_rate = 90'000,
      .generation = 1,
    };
  }
}  // namespace

TEST(LspPacketClassifier, CoversEveryRfc7983BoundaryAndRtpRtcpMux) {
  const auto classify = [](const std::uint8_t first) {
    return lsp::classify_packet(std::array {first});
  };
  EXPECT_EQ(lsp::classify_packet({}), lsp::PacketClass::invalid);
  EXPECT_EQ(classify(0), lsp::PacketClass::stun);
  EXPECT_EQ(classify(3), lsp::PacketClass::stun);
  EXPECT_EQ(classify(4), lsp::PacketClass::invalid);
  EXPECT_EQ(classify(16), lsp::PacketClass::zrtp);
  EXPECT_EQ(classify(19), lsp::PacketClass::zrtp);
  EXPECT_EQ(classify(20), lsp::PacketClass::dtls);
  EXPECT_EQ(classify(63), lsp::PacketClass::dtls);
  EXPECT_EQ(classify(64), lsp::PacketClass::turn_channel);
  EXPECT_EQ(classify(79), lsp::PacketClass::turn_channel);
  EXPECT_EQ(classify(80), lsp::PacketClass::invalid);
  EXPECT_EQ(classify(128), lsp::PacketClass::rtp_or_rtcp);
  EXPECT_EQ(classify(191), lsp::PacketClass::rtp_or_rtcp);
  EXPECT_EQ(classify(192), lsp::PacketClass::invalid);

  EXPECT_EQ(lsp::classify_secure_packet(std::array<std::uint8_t, 1> {0x80}), lsp::SecurePacketClass::invalid);
  EXPECT_EQ(lsp::classify_secure_packet(std::array<std::uint8_t, 2> {0x80, 96}), lsp::SecurePacketClass::rtp);
  EXPECT_EQ(lsp::classify_secure_packet(std::array<std::uint8_t, 2> {0x80, 192}), lsp::SecurePacketClass::rtcp);
  EXPECT_EQ(lsp::classify_secure_packet(std::array<std::uint8_t, 2> {0x80, 223}), lsp::SecurePacketClass::rtcp);
  EXPECT_EQ(lsp::classify_secure_packet(std::array<std::uint8_t, 2> {0x80, 224}), lsp::SecurePacketClass::rtp);
}

TEST(LspHostService, FailsClosedBeforeBindingWithoutReadyCryptoProviders) {
  lsp::HostConfig config;
  config.enabled = true;
  FakeSocket socket;
  FakeSrtp srtp;
  lsp::HostService missing_dtls {config, socket, nullptr, &srtp};
  EXPECT_EQ(missing_dtls.start(), lsp::ServiceStartResult::missing_dtls_provider);
  EXPECT_EQ(socket.bind_calls, 0U);

  FakeDtls dtls;
  dtls.ready_result = false;
  lsp::HostService unready_dtls {config, socket, &dtls, &srtp};
  EXPECT_EQ(unready_dtls.start(), lsp::ServiceStartResult::dtls_provider_not_ready);
  EXPECT_EQ(socket.bind_calls, 0U);

  config.profile = lsp::NetworkProfile::competition;
  config.competition_capacity_mbps = 0;
  lsp::HostService unsafe_competition {config, socket, &dtls, &srtp};
  EXPECT_EQ(unsafe_competition.start(), lsp::ServiceStartResult::invalid_configuration);
  EXPECT_EQ(socket.bind_calls, 0U);

  config.profile = lsp::NetworkProfile::adaptive_low_latency;
  config.enabled = false;
  lsp::HostService disabled {config, socket, &dtls, &srtp};
  EXPECT_EQ(disabled.start(), lsp::ServiceStartResult::disabled);

  config.enabled = true;
  lsp::HostService missing_srtp {config, socket, &dtls, nullptr};
  EXPECT_EQ(missing_srtp.start(), lsp::ServiceStartResult::missing_srtp_provider);

  dtls.ready_result = true;
  srtp.ready_result = false;
  lsp::HostService unready_srtp {config, socket, &dtls, &srtp};
  EXPECT_EQ(unready_srtp.start(), lsp::ServiceStartResult::srtp_provider_not_ready);

  srtp.ready_result = true;
  socket.bind_result = false;
  lsp::HostService bind_failure {config, socket, &dtls, &srtp};
  EXPECT_EQ(bind_failure.start(), lsp::ServiceStartResult::socket_bind_failed);
}

TEST(LspHostService, BindsOnePortAndDispatchesOnlyDefinedPacketClasses) {
  lsp::HostConfig config;
  config.enabled = true;
  FakeSocket socket;
  FakeDtls dtls;
  FakeSrtp srtp;
  lsp::HostService service {config, socket, &dtls, &srtp};
  ASSERT_EQ(service.start(), lsp::ServiceStartResult::started);
  EXPECT_EQ(service.start(), lsp::ServiceStartResult::already_started);
  EXPECT_TRUE(service.active());
  EXPECT_EQ(service.config().port, lsp::default_udp_port);
  EXPECT_EQ(socket.bind_calls, 1U);
  EXPECT_EQ(socket.bound_port, lsp::default_udp_port);
  EXPECT_TRUE(dtls.observed_exact_policy);
  EXPECT_TRUE(srtp.observed_exact_policy);

  const lsp::PeerEndpoint peer {
    .family = lsp::IpAddressFamily::ipv4,
    .local_address = "192.0.2.1",
    .local_port = lsp::default_udp_port,
    .remote_address = "192.0.2.10",
    .remote_port = 50'000,
  };
  std::array<std::uint8_t, 1> dtls_datagram {22};
  std::array<std::uint8_t, 2> rtp_datagram {0x80, 96};
  std::array<std::uint8_t, 2> rtcp_datagram {0x80, 200};
  std::array<std::uint8_t, 1> reserved_datagram {0};
  std::array<std::uint8_t, 1> invalid_datagram {80};
  std::array<std::uint8_t, 1> short_rtp_datagram {0x80};
  EXPECT_EQ(service.receive(peer, dtls_datagram), lsp::DatagramResult::accepted);
  EXPECT_EQ(dtls.receive_calls, 1U);
  constexpr std::uint64_t received_at_microseconds = 987'654'321U;
  EXPECT_EQ(
    service.receive(peer, rtp_datagram, received_at_microseconds, lsp::IpEcn::congestion_experienced),
    lsp::DatagramResult::accepted
  );
  EXPECT_EQ(srtp.last_class, lsp::SecurePacketClass::rtp);
  EXPECT_EQ(srtp.last_received_at_microseconds, received_at_microseconds);
  EXPECT_EQ(srtp.last_ecn, lsp::IpEcn::congestion_experienced);
  EXPECT_EQ(service.receive(peer, rtcp_datagram), lsp::DatagramResult::accepted);
  EXPECT_EQ(srtp.last_class, lsp::SecurePacketClass::rtcp);
  EXPECT_EQ(service.receive(peer, reserved_datagram), lsp::DatagramResult::reserved_drop);
  EXPECT_EQ(service.receive(peer, invalid_datagram), lsp::DatagramResult::invalid_drop);
  auto wrong_local_port = peer;
  wrong_local_port.local_port = 1;
  EXPECT_EQ(service.receive(wrong_local_port, dtls_datagram), lsp::DatagramResult::malformed_peer);
  EXPECT_EQ(service.receive(peer, short_rtp_datagram), lsp::DatagramResult::invalid_drop);

  dtls.receive_result = lsp::ProviderDatagramResult::dropped;
  EXPECT_EQ(service.receive(peer, dtls_datagram), lsp::DatagramResult::provider_drop);
  EXPECT_FALSE(lsp::datagram_result_requires_association_close(lsp::DatagramResult::provider_drop));
  srtp.receive_result = lsp::ProviderDatagramResult::fatal;
  EXPECT_EQ(service.receive(peer, rtp_datagram), lsp::DatagramResult::provider_fatal);
  EXPECT_TRUE(lsp::datagram_result_requires_association_close(lsp::DatagramResult::provider_fatal));
  EXPECT_EQ(dtls.receive_calls, 2U);
  EXPECT_EQ(srtp.receive_calls, 3U);

  service.stop();
  EXPECT_FALSE(service.active());
  EXPECT_EQ(socket.close_calls, 1U);
  EXPECT_EQ(service.receive(peer, dtls_datagram), lsp::DatagramResult::inactive);
}

TEST(LspHostService, ConcurrentStopClosesAdmissionBeforeFurtherHandshakeDispatch) {
  lsp::HostConfig config;
  config.enabled = true;
  FakeSocket socket;
  FakeDtls dtls;
  FakeSrtp srtp;
  lsp::HostService service {config, socket, &dtls, &srtp};
  ASSERT_EQ(service.start(), lsp::ServiceStartResult::started);
  const lsp::PeerEndpoint peer {
    .local_address = "127.0.0.1",
    .local_port = lsp::default_udp_port,
    .remote_address = "127.0.0.1",
    .remote_port = 50'000,
  };
  std::atomic<bool> running {true};
  std::jthread receiver {[&]() {
    std::array<std::uint8_t, 2> datagram {22, 0};
    while (running.load(std::memory_order_acquire)) {
      (void) service.receive(peer, datagram);
    }
  }};
  service.stop();
  running.store(false, std::memory_order_release);
  receiver.join();
  const auto calls_after_stop = dtls.receive_calls.load(std::memory_order_acquire);
  std::array<std::uint8_t, 2> datagram {22, 0};
  EXPECT_EQ(service.receive(peer, datagram), lsp::DatagramResult::inactive);
  EXPECT_EQ(dtls.receive_calls.load(std::memory_order_acquire), calls_after_stop);
}

TEST(LspHostService, StopAdmissionWaitsForInFlightHandshakeWithoutClosingSocket) {
  using namespace std::chrono_literals;
  lsp::HostConfig config;
  config.enabled = true;
  FakeSocket socket;
  BlockingDtls dtls;
  FakeSrtp srtp;
  lsp::HostService service {config, socket, &dtls, &srtp};
  ASSERT_EQ(service.start(), lsp::ServiceStartResult::started);
  const lsp::PeerEndpoint peer {
    .local_address = "127.0.0.1",
    .local_port = lsp::default_udp_port,
    .remote_address = "127.0.0.1",
    .remote_port = 50'000,
  };
  std::jthread receiver {[&]() {
    std::array<std::uint8_t, 2> datagram {22, 0};
    EXPECT_EQ(service.receive(peer, datagram), lsp::DatagramResult::accepted);
  }};
  {
    std::unique_lock lock(dtls.mutex);
    ASSERT_TRUE(dtls.changed.wait_for(lock, 1s, [&]() {
      return dtls.entered;
    }));
  }
  auto stopping = std::async(std::launch::async, [&]() {
    service.stop_admission();
  });
  EXPECT_EQ(stopping.wait_for(20ms), std::future_status::timeout);
  EXPECT_EQ(socket.close_calls, 0U);
  {
    std::scoped_lock lock(dtls.mutex);
    dtls.released = true;
  }
  dtls.changed.notify_all();
  EXPECT_EQ(stopping.wait_for(1s), std::future_status::ready);
  receiver.join();
  EXPECT_FALSE(service.active());
  EXPECT_EQ(socket.close_calls, 0U);
  service.stop();
  EXPECT_EQ(socket.close_calls, 1U);
}

TEST(LspNativeUdpSocket, BindsNoFragmentDualStackAndPreservesMappedIpv4Peers) {
  lsp::runtime::NativeUdpSocket socket;
  ASSERT_TRUE(socket.bind(0));
  ASSERT_NE(socket.bound_port(), 0U);
  const lsp::PeerEndpoint loopback {
    .family = lsp::IpAddressFamily::ipv4,
    .local_address = "0.0.0.0",
    .local_port = socket.bound_port(),
    .remote_address = "127.0.0.1",
    .remote_port = socket.bound_port(),
  };
  constexpr std::array<std::uint8_t, 4> payload {1, 2, 3, 4};
  ASSERT_EQ(socket.send_datagram_result(loopback, payload), lsp::runtime::UdpSendResult::sent);
  ASSERT_TRUE(socket.wait_readable(100));
  bool received = false;
  lsp::PeerEndpoint cached_peer;
  EXPECT_EQ(
    socket.receive_batch(1, [&](const lsp::runtime::ReceivedDatagram &datagram) {
      cached_peer = datagram.peer;
      received = datagram.peer.family == lsp::IpAddressFamily::ipv4 &&
                 datagram.peer.remote_address == "127.0.0.1" &&
                 datagram.peer.canonical_remote.valid &&
                 (datagram.ecn == lsp::runtime::DatagramEcn::not_ect ||
                  datagram.ecn == lsp::runtime::DatagramEcn::unavailable) &&
                 std::ranges::equal(datagram.payload, payload);
    }),
    lsp::runtime::ReceiveBatchResult::drained
  );
  EXPECT_TRUE(received);
  socket.close();
}

TEST(LspNativeUdpSocket, EnablesEctOnlyAfterAuthenticatedProbeReflectionAndNeverMarksRtcp) {
  lsp::runtime::NativeUdpSocket socket;
  ASSERT_TRUE(socket.bind(0));
  const lsp::PeerEndpoint loopback {
    .family = lsp::IpAddressFamily::ipv4,
    .local_address = "0.0.0.0",
    .local_port = socket.bound_port(),
    .remote_address = "127.0.0.1",
    .remote_port = socket.bound_port(),
  };
  constexpr std::array<std::uint8_t, 2> handshake {22, 0};
  ASSERT_EQ(socket.send_datagram_result(loopback, handshake), lsp::runtime::UdpSendResult::sent);
  ASSERT_TRUE(socket.wait_readable(100));
  lsp::PeerEndpoint peer;
  ASSERT_EQ(
    socket.receive_batch(1, [&](const lsp::runtime::ReceivedDatagram &datagram) {
      peer = datagram.peer;
      EXPECT_TRUE(datagram.ecn == lsp::IpEcn::not_ect || datagram.ecn == lsp::IpEcn::unavailable);
    }),
    lsp::runtime::ReceiveBatchResult::drained
  );
  ASSERT_TRUE(peer.valid());
  if (!socket.snapshot().ipv4_ecn_available) {
    GTEST_SKIP() << "IPv4 ancillary ECN unavailable on this runner";
  }

  constexpr std::uint32_t ssrc = 0x12345678U;
  auto probe_sequence = [](std::uint16_t start) {
    while (((ssrc ^ (static_cast<std::uint32_t>(start) * 0x9e37U)) & 0x3fU) != 0U) {
      ++start;
    }
    return start;
  };
  auto sequence = probe_sequence(1);
  for (std::size_t proof = 0; proof < 3; ++proof) {
    std::array<std::uint8_t, 12> rtp {0x80U, 96U};
    lumen::lsp::wire::write_be<std::uint16_t>(std::span<std::uint8_t> {rtp}.subspan<2, 2>(), sequence);
    lumen::lsp::wire::write_be<std::uint32_t>(std::span<std::uint8_t> {rtp}.subspan<8, 4>(), ssrc);
    ASSERT_EQ(socket.send_datagram_result(peer, rtp), lsp::runtime::UdpSendResult::sent);
    ASSERT_TRUE(socket.wait_readable(100));
    ASSERT_EQ(
      socket.receive_batch(1, [&](const lsp::runtime::ReceivedDatagram &datagram) {
        EXPECT_TRUE(datagram.ecn == lsp::IpEcn::ect_0 || datagram.ecn == lsp::IpEcn::congestion_experienced || datagram.ecn == lsp::IpEcn::unavailable);
      }),
      lsp::runtime::ReceiveBatchResult::drained
    );
    std::array<std::uint8_t, 2> metric {0xc0U, 0U};
    lsp::transport::congestion_feedback_packet_view feedback;
    feedback.blocks[0] = {
      .media_ssrc = ssrc,
      .begin_sequence = sequence,
      .report_count = 1,
      .metrics = metric,
    };
    feedback.block_count = 1;
    EXPECT_TRUE(socket.observe_authenticated_ecn_feedback(peer, feedback, lsp::runtime::monotonic_microseconds()));
    sequence = probe_sequence(static_cast<std::uint16_t>(sequence + 1U));
  }
  EXPECT_TRUE(socket.peer_ecn_validated(peer));

  std::uint16_t indexed_sequence = 1'000;
  for (std::size_t packet_index = 0; packet_index < 300U; ++packet_index, ++indexed_sequence) {
    std::array<std::uint8_t, 12> rtp {0x80U, 96U};
    lumen::lsp::wire::write_be<std::uint16_t>(
      std::span<std::uint8_t> {rtp}.subspan<2, 2>(),
      indexed_sequence
    );
    lumen::lsp::wire::write_be<std::uint32_t>(std::span<std::uint8_t> {rtp}.subspan<8, 4>(), ssrc);
    ASSERT_EQ(socket.send_datagram_result(peer, rtp), lsp::runtime::UdpSendResult::sent);
    ASSERT_TRUE(socket.wait_readable(100));
    ASSERT_EQ(
      socket.receive_batch(1, [](const lsp::runtime::ReceivedDatagram &) {
      }),
      lsp::runtime::ReceiveBatchResult::drained
    );
  }
  --indexed_sequence;
  std::array<std::uint8_t, 2> indexed_metric {0xc0U, 0U};
  lsp::transport::congestion_feedback_packet_view indexed_feedback;
  indexed_feedback.blocks[0] = {
    .media_ssrc = ssrc,
    .begin_sequence = indexed_sequence,
    .report_count = 1,
    .metrics = indexed_metric,
  };
  indexed_feedback.block_count = 1;
  EXPECT_TRUE(
    socket.observe_authenticated_ecn_feedback(
      peer,
      indexed_feedback,
      lsp::runtime::monotonic_microseconds()
    )
  );
  EXPECT_TRUE(socket.peer_ecn_validated(peer));

  std::array<std::uint8_t, 8> rtcp {0x80U, lsp::transport::rtcp_receiver_report_type, 0, 1};
  lumen::lsp::wire::write_be<std::uint32_t>(std::span<std::uint8_t> {rtcp}.subspan<4, 4>(), ssrc);
  ASSERT_EQ(socket.send_datagram_result(peer, rtcp), lsp::runtime::UdpSendResult::sent);
  ASSERT_TRUE(socket.wait_readable(100));
  ASSERT_EQ(
    socket.receive_batch(1, [&](const lsp::runtime::ReceivedDatagram &datagram) {
      EXPECT_TRUE(datagram.ecn == lsp::IpEcn::not_ect || datagram.ecn == lsp::IpEcn::unavailable);
    }),
    lsp::runtime::ReceiveBatchResult::drained
  );
  socket.close();
}

TEST(LspNativeUdpSocket, CloseWaitsForInFlightReceiveCallbackBeforeDescriptorReuse) {
  using namespace std::chrono_literals;
  lsp::runtime::NativeUdpSocket socket;
  ASSERT_TRUE(socket.bind(0));
  const auto first_port = socket.bound_port();
  const lsp::PeerEndpoint loopback {
    .family = lsp::IpAddressFamily::ipv4,
    .local_address = "0.0.0.0",
    .local_port = first_port,
    .remote_address = "127.0.0.1",
    .remote_port = first_port,
  };
  constexpr std::array<std::uint8_t, 1> payload {7};
  ASSERT_EQ(socket.send_datagram_result(loopback, payload), lsp::runtime::UdpSendResult::sent);
  ASSERT_TRUE(socket.wait_readable(100));

  std::mutex callback_mutex;
  std::condition_variable callback_changed;
  bool callback_entered = false;
  bool callback_released = false;
  std::jthread receiver {[&]() {
    EXPECT_EQ(
      socket.receive_batch(1, [&](const lsp::runtime::ReceivedDatagram &) {
        std::unique_lock lock(callback_mutex);
        callback_entered = true;
        callback_changed.notify_all();
        callback_changed.wait(lock, [&]() {
          return callback_released;
        });
      }),
      lsp::runtime::ReceiveBatchResult::drained
    );
  }};
  {
    std::unique_lock lock(callback_mutex);
    ASSERT_TRUE(callback_changed.wait_for(lock, 1s, [&]() {
      return callback_entered;
    }));
  }
  auto closing = std::async(std::launch::async, [&]() {
    socket.close();
  });
  EXPECT_EQ(closing.wait_for(20ms), std::future_status::timeout);
  {
    std::scoped_lock lock(callback_mutex);
    callback_released = true;
  }
  callback_changed.notify_all();
  EXPECT_EQ(closing.wait_for(1s), std::future_status::ready);
  receiver.join();
  EXPECT_FALSE(socket.open());
  EXPECT_TRUE(socket.bind(0));
  EXPECT_NE(socket.bound_port(), 0U);
  socket.close();
}

TEST(LspMicrophoneFeedbackWire, WritesRegularCompoundAndReducedCongestionReports) {
  std::array<std::uint8_t, 128> compound {};
  const auto compound_bytes = lsp::runtime::write_microphone_compound_report(compound, 77);
  ASSERT_NE(compound_bytes, 0U);
  const auto compound_packet = std::span<const std::uint8_t> {compound}.first(compound_bytes);
  const auto summary = lsp::transport::parse_rtcp_datagram(
    compound_packet,
    lsp::transport::rtcp_datagram_form::compound
  );
  ASSERT_TRUE(summary);
  EXPECT_EQ(summary.packet_count, 2U);
  const auto authority = lsp::transport::validate_compound_rtcp_authority(compound_packet, 77);
  ASSERT_TRUE(authority);
  EXPECT_EQ(authority.first_report.packet_type, lsp::transport::rtcp_receiver_report_type);
  EXPECT_EQ(authority.first_report.count, 1U);
  EXPECT_EQ(authority.cname.size(), 16U);
  auto missing_cname = std::vector<std::uint8_t>(compound_packet.begin(), compound_packet.end());
  missing_cname[authority.first_report.packet.size() + 8U] = 2U;
  EXPECT_FALSE(lsp::transport::validate_compound_rtcp_authority(missing_cname, 77));

  std::array<std::uint8_t, 24> congestion {};
  ASSERT_EQ(
    lsp::runtime::write_microphone_congestion_report(congestion, 77, 88, 0xfffe, 0x12345678),
    congestion.size()
  );
  const auto parsed = lsp::runtime::parse_congestion_feedback_packet(congestion, 77);
  ASSERT_TRUE(parsed);
  ASSERT_EQ(parsed->block_count, 1U);
  EXPECT_EQ(parsed->blocks[0].media_ssrc, 88U);
  EXPECT_EQ(parsed->blocks[0].begin_sequence, 0xfffeU);
  EXPECT_EQ(parsed->blocks[0].report_count, 1U);
  EXPECT_EQ(parsed->report_timestamp, 0x12345678U);
}

TEST(LspInputFeedbackWire, WritesAcknowledgementRegularCompoundWithoutMicrophoneAuthority) {
  lsp::RtcpCname cname;
  constexpr std::array<std::uint8_t, 12> cname_bytes {'l', 's', 'p', '-', 'i', 'n', 'p', 'u', 't', '-', 'a', 'c'};
  std::copy(cname_bytes.begin(), cname_bytes.end(), cname.bytes.begin());
  cname.size = static_cast<std::uint8_t>(cname_bytes.size());
  std::array<std::uint8_t, 96> compound {};
  const auto written = lsp::runtime::write_input_feedback_compound_report(compound, 91, cname);
  ASSERT_NE(written, 0U);
  const auto authority = lsp::transport::validate_compound_rtcp_authority(
    std::span<const std::uint8_t> {compound}.first(written),
    91
  );
  ASSERT_TRUE(authority);
  EXPECT_EQ(authority.first_report.packet_type, lsp::transport::rtcp_receiver_report_type);
  EXPECT_TRUE(std::ranges::equal(authority.cname, cname.view()));
}

TEST(LspInputFeedbackWire, DefersReducedFeedbackThroughWouldBlockUntilCompoundIsSent) {
  lsp::runtime::InputFeedbackCompoundGate gate;
  gate.reset(7, 11);
  const auto token = gate.token();
  ASSERT_NE(token, 0U);
  EXPECT_FALSE(gate.reduced_size_allowed(token));
  ASSERT_TRUE(gate.begin_submission(token));

  // A local would-block retry is not terminal completion and must retain the exact protected compound.
  EXPECT_TRUE(gate.submission_pending());
  EXPECT_FALSE(gate.begin_submission(token));
  EXPECT_FALSE(gate.reduced_size_allowed(token));

  gate.complete(token, true);
  EXPECT_FALSE(gate.submission_pending());
  EXPECT_TRUE(gate.reduced_size_allowed(token));

  EXPECT_FALSE(gate.begin_submission(token + 1U));
  gate.reset(8, 12);
  gate.complete(token, true);
  EXPECT_FALSE(gate.reduced_size_allowed(gate.token()));
}

TEST(LspFeedbackWorker, BoundsCopiesAndRejectsRetiredMediaGenerations) {
  EXPECT_EQ(lsp::runtime::next_host_feedback_work_class(1, 32), lsp::runtime::HostFeedbackWorkClass::repair);
  EXPECT_EQ(lsp::runtime::next_host_feedback_work_class(0, 32), lsp::runtime::HostFeedbackWorkClass::congestion);
  EXPECT_TRUE(lsp::runtime::host_feedback_work_is_current(lsp::runtime::maximum_host_feedback_work_bytes, 7, 11, 13, 17, 7, 11, 13, 17));
  EXPECT_FALSE(lsp::runtime::host_feedback_work_is_current(1'473, 7, 11, 13, 17, 7, 11, 13, 17));
  EXPECT_FALSE(lsp::runtime::host_feedback_work_is_current(1'200, 7, 11, 13, 17, 8, 11, 13, 17));
  EXPECT_FALSE(lsp::runtime::host_feedback_work_is_current(1'200, 7, 11, 13, 17, 7, 11, 14, 17));
  EXPECT_FALSE(lsp::runtime::host_feedback_work_is_current(1'200, 7, 11, 13, 17, 7, 11, 13, 18));
}

TEST(LspMicrophoneFeedbackWire, PreservesGapsReorderAtoAndDuplicateCeUntilExplicitCommit) {
  lsp::transport::reordering_congestion_feedback_window<512> window;
  window.reset(88, 1'000);
  EXPECT_EQ(
    window.record({
      .media_ssrc = 88,
      .extended_sequence_number = 100,
      .arrival_microseconds = 1'500,
      .received_bytes = 100,
      .ecn = lsp::transport::ecn_mark::not_ect,
    }),
    lsp::transport::reordering_congestion_report_result::accepted
  );
  EXPECT_EQ(
    window.record({
      .media_ssrc = 88,
      .extended_sequence_number = 103,
      .arrival_microseconds = 1'600,
      .received_bytes = 100,
      .ecn = lsp::transport::ecn_mark::ect0,
    }),
    lsp::transport::reordering_congestion_report_result::accepted
  );
  EXPECT_EQ(
    window.record({
      .media_ssrc = 88,
      .extended_sequence_number = 102,
      .arrival_microseconds = 1'700,
      .received_bytes = 100,
      .ecn = lsp::transport::ecn_mark::ect1,
    }),
    lsp::transport::reordering_congestion_report_result::accepted
  );
  EXPECT_EQ(
    window.record({
      .media_ssrc = 88,
      .extended_sequence_number = 103,
      .arrival_microseconds = 1'800,
      .received_bytes = 100,
      .ecn = lsp::transport::ecn_mark::congestion_experienced,
    }),
    lsp::transport::reordering_congestion_report_result::duplicate
  );

  const auto batch = window.pending_report(4'000);
  ASSERT_EQ(batch.size(), 4U);
  std::array<std::uint8_t, 1'200> packet {};
  const auto written = lsp::runtime::write_microphone_congestion_report(packet, 77, batch, 0x12345678U);
  ASSERT_EQ(written, 28U);
  const auto feedback = lsp::transport::validate_congestion_feedback_packet(
    std::span<const std::uint8_t> {packet}.first(written),
    77
  );
  ASSERT_TRUE(feedback);
  ASSERT_EQ(feedback.block_count, 1U);
  const auto &block = feedback.blocks[0];
  EXPECT_EQ(block.begin_sequence, 100U);
  ASSERT_EQ(block.report_count, 4U);
  const auto metric = [&](const std::size_t index) {
    return lumen::lsp::wire::read_be<std::uint16_t>(block.metrics.subspan(index * 2U, 2));
  };
  EXPECT_NE(metric(0) & 0x8000U, 0U);
  EXPECT_EQ(metric(1), 0U);
  EXPECT_EQ((metric(2) >> 13U) & 0x03U, static_cast<std::uint16_t>(lsp::transport::ecn_mark::ect1));
  EXPECT_EQ(
    (metric(3) >> 13U) & 0x03U,
    static_cast<std::uint16_t>(lsp::transport::ecn_mark::congestion_experienced)
  );
  EXPECT_EQ(feedback.report_timestamp, 0x12345678U);

  ASSERT_EQ(
    window.record({
      .media_ssrc = 88,
      .extended_sequence_number = 104,
      .arrival_microseconds = 4'100,
      .received_bytes = 100,
      .ecn = lsp::transport::ecn_mark::not_ect,
    }),
    lsp::transport::reordering_congestion_report_result::accepted
  );
  EXPECT_TRUE(window.commit_report(batch.begin_extended_sequence, batch.size(), 4'200));
  EXPECT_EQ(window.size(), 1U);
}

TEST(LspMicrophoneFeedbackWire, RetainsExpectedOriginAndEmitsLateOverlapCorrection) {
  lsp::transport::reordering_congestion_feedback_window<512> window;
  window.reset(88, 1'000);
  ASSERT_EQ(
    window.record({
      .media_ssrc = 88,
      .extended_sequence_number = 100,
      .arrival_microseconds = 1'500,
      .received_bytes = 100,
    }),
    lsp::transport::reordering_congestion_report_result::accepted
  );
  auto batch = window.pending_report(4'000);
  ASSERT_EQ(batch.begin_extended_sequence, 100U);
  ASSERT_TRUE(window.commit_report(batch.begin_extended_sequence, batch.size(), 4'100));
  ASSERT_EQ(
    window.record({
      .media_ssrc = 88,
      .extended_sequence_number = 102,
      .arrival_microseconds = 4'200,
      .received_bytes = 100,
    }),
    lsp::transport::reordering_congestion_report_result::accepted
  );
  batch = window.pending_report(6'200);
  ASSERT_EQ(batch.begin_extended_sequence, 101U);
  ASSERT_EQ(batch.size(), 2U);
  EXPECT_FALSE(batch.first[0].received);
  EXPECT_TRUE(batch.first[1].received);
  ASSERT_TRUE(window.commit_report(batch.begin_extended_sequence, batch.size(), 6'300));

  EXPECT_EQ(
    window.record({
      .media_ssrc = 88,
      .extended_sequence_number = 101,
      .arrival_microseconds = 6'400,
      .received_bytes = 100,
      .ecn = lsp::transport::ecn_mark::congestion_experienced,
    }),
    lsp::transport::reordering_congestion_report_result::accepted
  );
  const auto correction = window.pending_report(6'900);
  ASSERT_TRUE(correction.correction);
  ASSERT_EQ(correction.begin_extended_sequence, 101U);
  ASSERT_EQ(correction.size(), 1U);
  EXPECT_TRUE(correction.first[0].received);
  EXPECT_EQ(correction.first[0].ecn, lsp::transport::ecn_mark::congestion_experienced);
}

TEST(LspMicrophoneFeedbackWire, UsesExactEcnCodepointsAndAtoSentinels) {
  EXPECT_EQ(static_cast<std::uint8_t>(lsp::transport::ecn_mark::ect1), 1U);
  EXPECT_EQ(static_cast<std::uint8_t>(lsp::transport::ecn_mark::ect0), 2U);
  EXPECT_EQ(lsp::transport::encode_congestion_ato(0, 1'000), lsp::transport::congestion_ato_unavailable);
  EXPECT_EQ(lsp::transport::encode_congestion_ato(2'000, 1'000), lsp::transport::congestion_ato_unavailable);
  EXPECT_EQ(lsp::transport::encode_congestion_ato(1'000, 1'000), 0U);
  EXPECT_EQ(lsp::transport::encode_congestion_ato(500'000, 1'000'000), 512U);
  EXPECT_EQ(
    lsp::transport::encode_congestion_ato(1, 9'000'000),
    lsp::transport::congestion_ato_over_range
  );
}

TEST(LspSsrcRegistry, AcceptsExactLaneMappingsAndRejectsAmbiguity) {
  const auto primary = video_primary();
  const lsp::SsrcAssignment repair {
    .ssrc = 101,
    .payload_type = 97,
    .lane = lsp::MediaLane::video_repair,
    .direction = lsp::MediaDirection::host_to_client,
    .format = lsp::PayloadFormat::flexfec,
    .clock_rate = 90'000,
    .generation = 1,
    .associated_primary_ssrc = primary.ssrc,
  };
  const lsp::SsrcAssignment input {
    .ssrc = 200,
    .payload_type = 98,
    .lane = lsp::MediaLane::input,
    .direction = lsp::MediaDirection::client_to_host,
    .format = lsp::PayloadFormat::lsp_input,
    .clock_rate = 1'000'000,
    .generation = 3,
  };
  const std::array valid {primary, repair, input};
  const auto registry = lsp::SsrcRegistry::create(valid);
  ASSERT_TRUE(registry);
  EXPECT_EQ(registry->assignments().size(), valid.size());
  ASSERT_NE(registry->find(200), nullptr);
  EXPECT_EQ(registry->find(200)->lane, lsp::MediaLane::input);
  EXPECT_EQ(registry->find(999), nullptr);

  auto duplicate = input;
  duplicate.ssrc = primary.ssrc;
  const std::array duplicate_ssrc {primary, duplicate};
  EXPECT_EQ(lsp::SsrcRegistry::create(duplicate_ssrc).error(), lsp::SsrcRegistryError::duplicate_ssrc);

  auto wrong_association = repair;
  wrong_association.associated_primary_ssrc = 999;
  const std::array invalid_repair {primary, wrong_association};
  EXPECT_EQ(lsp::SsrcRegistry::create(invalid_repair).error(), lsp::SsrcRegistryError::invalid_repair_association);

  auto conflict = input;
  conflict.payload_type = primary.payload_type;
  const std::array conflicting_payload {primary, conflict};
  EXPECT_EQ(lsp::SsrcRegistry::create(conflicting_payload).error(), lsp::SsrcRegistryError::conflicting_payload_type);
}

TEST(LspSsrcRegistry, RejectsEachPerAssignmentInvariant) {
  const auto expect_error = [](const lsp::SsrcAssignment &assignment, const lsp::SsrcRegistryError error) {
    EXPECT_EQ(lsp::SsrcRegistry::create(std::span {&assignment, 1}).error(), error);
  };
  EXPECT_EQ(lsp::SsrcRegistry::create({}).error(), lsp::SsrcRegistryError::empty);
  std::vector<lsp::SsrcAssignment> excessive(lsp::SsrcRegistry::maximum_entries + 1, video_primary());
  EXPECT_EQ(lsp::SsrcRegistry::create(excessive).error(), lsp::SsrcRegistryError::too_many_entries);

  auto assignment = video_primary();
  assignment.ssrc = 0;
  expect_error(assignment, lsp::SsrcRegistryError::zero_ssrc);
  assignment = video_primary();
  assignment.payload_type = 95;
  expect_error(assignment, lsp::SsrcRegistryError::invalid_payload_type);
  assignment = video_primary();
  assignment.generation = 0;
  expect_error(assignment, lsp::SsrcRegistryError::zero_generation);
  assignment = video_primary();
  assignment.direction = lsp::MediaDirection::client_to_host;
  expect_error(assignment, lsp::SsrcRegistryError::invalid_direction);
  assignment = video_primary();
  assignment.format = lsp::PayloadFormat::opus;
  expect_error(assignment, lsp::SsrcRegistryError::invalid_format);
  assignment = video_primary();
  assignment.clock_rate = 48'000;
  expect_error(assignment, lsp::SsrcRegistryError::invalid_clock_rate);
  assignment = video_primary();
  assignment.associated_primary_ssrc = 999;
  expect_error(assignment, lsp::SsrcRegistryError::invalid_repair_association);

  auto duplicate_lane = video_primary();
  duplicate_lane.ssrc = 101;
  duplicate_lane.payload_type = 97;
  const std::array duplicate_lanes {video_primary(), duplicate_lane};
  EXPECT_EQ(lsp::SsrcRegistry::create(duplicate_lanes).error(), lsp::SsrcRegistryError::duplicate_lane);
}

TEST(LspSessionAuthority, NeutralizesBeforeAttachAndRequiresFreshBaseline) {
  FakeNeutralizer neutralizer;
  FakeTokenVerifier token_verifier;
  lsp::SessionAuthority authority {neutralizer, &token_verifier};
  auto owner = client();
  const auto start = start_authority();
  ASSERT_EQ(authority.start(owner, start), lsp::AuthorityResult::accepted);
  EXPECT_EQ(authority.authorize_input(owner.client_id, 10, 20, 60), lsp::AuthorityResult::baseline_required);
  ASSERT_EQ(authority.commit_input_baseline(owner, 20, 60), lsp::AuthorityResult::accepted);
  EXPECT_EQ(authority.authorize_input(owner.client_id, 10, 20, 60), lsp::AuthorityResult::accepted);

  ASSERT_EQ(authority.transport_lost(10), lsp::AuthorityResult::accepted);
  EXPECT_EQ(neutralizer.calls, 1U);
  EXPECT_EQ(neutralizer.last_request.reason, lsp::NeutralizationReason::transport_loss);
  EXPECT_EQ(authority.snapshot().state, lsp::SessionState::detached);

  auto fresh_owner = owner;
  fresh_owner.connection_generation = 11;
  const auto successor = filled<32>(11);
  EXPECT_EQ(authority.attach(fresh_owner, start.session_id, filled<32>(10), successor), lsp::AuthorityResult::token_mismatch);
  ASSERT_EQ(authority.attach(fresh_owner, start.session_id, start.attach_token, successor), lsp::AuthorityResult::accepted);
  EXPECT_EQ(token_verifier.calls, 2U);
  EXPECT_EQ(authority.snapshot().generations.connection, 11U);
  EXPECT_EQ(authority.snapshot().generations.input, 61U);
  EXPECT_EQ(authority.snapshot().generations.video, 31U);
  EXPECT_EQ(authority.authorize_input(owner.client_id, 10, 20, 60), lsp::AuthorityResult::stale_generation);
  EXPECT_EQ(authority.authorize_input(owner.client_id, 11, 20, 61), lsp::AuthorityResult::baseline_required);
}

TEST(LspSessionAuthority, AttachPreflightIsReadOnlyAndSuccessfulRekeyRotatesToken) {
  FakeNeutralizer neutralizer;
  FakeTokenVerifier token_verifier;
  lsp::SessionAuthority authority {neutralizer, &token_verifier};
  auto owner = client();
  const auto start = start_authority();
  ASSERT_EQ(authority.start(owner, start), lsp::AuthorityResult::accepted);
  ASSERT_EQ(authority.commit_input_baseline(owner, 20, 60), lsp::AuthorityResult::accepted);

  auto fresh_owner = owner;
  fresh_owner.connection_generation = 15;
  const auto replacement = filled<32>(11);
  EXPECT_EQ(
    authority.prepare_attach(fresh_owner, start.session_id, filled<32>(10), replacement),
    lsp::AuthorityResult::token_mismatch
  );
  EXPECT_EQ(neutralizer.calls, 0U);
  EXPECT_EQ(authority.authorize_input(owner.client_id, 10, 20, 60), lsp::AuthorityResult::accepted);

  EXPECT_EQ(
    authority.prepare_attach(fresh_owner, start.session_id, start.attach_token, start.attach_token),
    lsp::AuthorityResult::malformed
  );
  EXPECT_EQ(neutralizer.calls, 0U);

  EXPECT_EQ(
    authority.prepare_attach(fresh_owner, start.session_id, start.attach_token, replacement),
    lsp::AuthorityResult::accepted
  );
  EXPECT_EQ(neutralizer.calls, 0U);
  EXPECT_EQ(authority.authorize_input(owner.client_id, 10, 20, 60), lsp::AuthorityResult::accepted);
  ASSERT_EQ(
    authority.attach(fresh_owner, start.session_id, start.attach_token, replacement),
    lsp::AuthorityResult::accepted
  );
  EXPECT_EQ(neutralizer.calls, 1U);
  EXPECT_EQ(authority.snapshot().generations.connection, 15U);
  EXPECT_EQ(authority.snapshot().generations.input, 61U);
  EXPECT_EQ(authority.snapshot().generations.video, 31U);

  ASSERT_EQ(authority.transport_lost(15), lsp::AuthorityResult::accepted);
  fresh_owner.connection_generation = 16;
  EXPECT_EQ(
    authority.prepare_attach(fresh_owner, start.session_id, start.attach_token, filled<32>(12)),
    lsp::AuthorityResult::token_mismatch
  );
  EXPECT_EQ(
    authority.prepare_attach(fresh_owner, start.session_id, replacement, filled<32>(12)),
    lsp::AuthorityResult::accepted
  );
}

TEST(LspSessionAuthority, RevocationNeutralizesBeforeInputRemainsDenied) {
  FakeNeutralizer neutralizer;
  FakeTokenVerifier token_verifier;
  lsp::SessionAuthority authority {neutralizer, &token_verifier};
  auto owner = client();
  const auto start = start_authority();
  ASSERT_EQ(authority.start(owner, start), lsp::AuthorityResult::accepted);
  ASSERT_EQ(authority.commit_input_baseline(owner, 20, 60), lsp::AuthorityResult::accepted);

  owner.revocation_generation = 2;
  const auto input_permission = permissions(static_cast<std::uint32_t>(lsp::Permission::input));
  ASSERT_EQ(authority.revoke_permissions(owner, input_permission), lsp::AuthorityResult::accepted);
  EXPECT_EQ(neutralizer.calls, 1U);
  EXPECT_EQ(neutralizer.last_request.reason, lsp::NeutralizationReason::permission_revoked);
  EXPECT_EQ(authority.authorize_input(owner.client_id, 10, 20, 60), lsp::AuthorityResult::permission_denied);
}

TEST(LspSessionAuthority, NeutralizationFailurePreventsAuthorityTransfer) {
  FakeNeutralizer neutralizer;
  neutralizer.result = false;
  FakeTokenVerifier token_verifier;
  lsp::SessionAuthority authority {neutralizer, &token_verifier};
  auto owner = client();
  const auto start = start_authority();
  ASSERT_EQ(authority.start(owner, start), lsp::AuthorityResult::accepted);
  ASSERT_EQ(authority.commit_input_baseline(owner, 20, 60), lsp::AuthorityResult::accepted);
  EXPECT_EQ(authority.transport_lost(10), lsp::AuthorityResult::neutralization_failed);
  EXPECT_EQ(authority.snapshot().state, lsp::SessionState::faulted);

  owner.connection_generation = 11;
  EXPECT_EQ(authority.attach(owner, start.session_id, start.attach_token, filled<32>(11)), lsp::AuthorityResult::invalid_state);
}

TEST(LspSessionAuthority, AttachFailsClosedWithoutTokenVerifier) {
  FakeNeutralizer neutralizer;
  lsp::SessionAuthority authority {neutralizer, nullptr};
  auto owner = client();
  const auto start = start_authority();
  ASSERT_EQ(authority.start(owner, start), lsp::AuthorityResult::accepted);
  ASSERT_EQ(authority.transport_lost(10), lsp::AuthorityResult::accepted);
  owner.connection_generation = 11;
  EXPECT_EQ(
    authority.attach(owner, start.session_id, start.attach_token, filled<32>(11)),
    lsp::AuthorityResult::security_provider_unavailable
  );
  EXPECT_EQ(authority.snapshot().state, lsp::SessionState::detached);
}

TEST(LspSessionAuthority, RejectsInvalidStartAndStopAuthority) {
  FakeNeutralizer neutralizer;
  FakeTokenVerifier token_verifier;
  lsp::SessionAuthority authority {neutralizer, &token_verifier};
  auto owner = client();
  auto start = start_authority();
  start.session_id = {};
  EXPECT_EQ(authority.start(owner, start), lsp::AuthorityResult::malformed);

  start = start_authority();
  owner.permissions = permissions(static_cast<std::uint32_t>(lsp::Permission::input));
  EXPECT_EQ(authority.start(owner, start), lsp::AuthorityResult::permission_denied);

  owner = client();
  start.generations.connection = 11;
  EXPECT_EQ(authority.start(owner, start), lsp::AuthorityResult::stale_generation);

  start = start_authority();
  ASSERT_EQ(authority.start(owner, start), lsp::AuthorityResult::accepted);
  EXPECT_EQ(authority.start(owner, start), lsp::AuthorityResult::invalid_state);
  EXPECT_EQ(authority.transport_lost(11), lsp::AuthorityResult::stale_generation);

  auto stranger = owner;
  stranger.client_id = filled<16>(99);
  EXPECT_EQ(authority.stop_owned(stranger, start.session_id), lsp::AuthorityResult::not_owner);

  ASSERT_EQ(authority.stop_owned(owner, start.session_id), lsp::AuthorityResult::accepted);
  EXPECT_EQ(authority.snapshot().state, lsp::SessionState::ready);
  EXPECT_EQ(authority.stop_from_host(lsp::NeutralizationReason::service_shutdown), lsp::AuthorityResult::invalid_state);
}

TEST(LspTypes, ValidatesPermissionsProfilesEndpointsAndGenerations) {
  EXPECT_FALSE(lsp::PermissionSet::from_mask(lsp::PermissionSet::known_mask + 1));
  EXPECT_TRUE(lsp::PermissionSet::default_pairing().contains(lsp::Permission::controller_output));

  lsp::HostConfig config;
  config.profile = lsp::NetworkProfile::competition;
  EXPECT_FALSE(config.valid());
  config.competition_capacity_mbps = 1'000;
  EXPECT_TRUE(config.valid());
  config.port = 0;
  EXPECT_FALSE(config.valid());
  config.port = lsp::default_udp_port;
  config.profile = static_cast<lsp::NetworkProfile>(255);
  EXPECT_FALSE(config.valid());

  lsp::PeerEndpoint endpoint {
    .family = lsp::IpAddressFamily::ipv6,
    .local_address = "2001:db8::1",
    .local_port = lsp::default_udp_port,
    .remote_address = "2001:db8::2",
    .remote_port = 50'000,
  };
  EXPECT_TRUE(endpoint.valid());
  endpoint.family = static_cast<lsp::IpAddressFamily>(255);
  EXPECT_FALSE(endpoint.valid());

  auto generations = start_authority().generations;
  EXPECT_TRUE(generations.valid());
  generations.input = 0;
  EXPECT_FALSE(generations.valid());
}
