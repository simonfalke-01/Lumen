/**
 * @file tests/unit/test_lsp_host_foundation.cpp
 * @brief Concrete invariant tests for the host-side LSP foundation.
 */

#include "src/protocol_lsp/invitation.h"
#include "src/protocol_lsp/packet_classifier.h"
#include "src/protocol_lsp/service.h"
#include "src/protocol_lsp/session_authority.h"
#include "src/protocol_lsp/ssrc_registry.h"
#include "src/protocol_lsp/types.h"

#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <span>
#include <string>
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

  lsp::PairingInvitation invitation() {
    return {
      .version = lsp::wire_version,
      .host_id = filled<16>(1),
      .host_identity_key = filled<32>(2),
      .dtls_spki_sha256 = filled<32>(3),
      .port = lsp::default_udp_port,
      .host = "lumen-host.local",
      .invitation_id = filled<16>(4),
      .invitation_secret = filled<32>(5),
      .expires_at_utc_seconds = 1'900'000'000,
      .offered_permissions = permissions(),
    };
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
    unsigned receive_calls {};
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
      const std::span<const std::uint8_t>
    ) noexcept override {
      ++receive_calls;
      last_class = packet_class;
      return receive_result;
    }

    bool ready_result {true};
    lsp::ProviderDatagramResult receive_result {lsp::ProviderDatagramResult::accepted};
    mutable bool observed_exact_policy {};
    unsigned receive_calls {};
    lsp::SecurePacketClass last_class {lsp::SecurePacketClass::invalid};
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
  EXPECT_EQ(service.receive(peer, std::array<std::uint8_t, 1> {22}), lsp::DatagramResult::accepted);
  EXPECT_EQ(dtls.receive_calls, 1U);
  EXPECT_EQ(service.receive(peer, std::array<std::uint8_t, 2> {0x80, 96}), lsp::DatagramResult::accepted);
  EXPECT_EQ(srtp.last_class, lsp::SecurePacketClass::rtp);
  EXPECT_EQ(service.receive(peer, std::array<std::uint8_t, 2> {0x80, 200}), lsp::DatagramResult::accepted);
  EXPECT_EQ(srtp.last_class, lsp::SecurePacketClass::rtcp);
  EXPECT_EQ(service.receive(peer, std::array<std::uint8_t, 1> {0}), lsp::DatagramResult::reserved_drop);
  EXPECT_EQ(service.receive(peer, std::array<std::uint8_t, 1> {80}), lsp::DatagramResult::invalid_drop);
  auto wrong_local_port = peer;
  wrong_local_port.local_port = 1;
  EXPECT_EQ(
    service.receive(wrong_local_port, std::array<std::uint8_t, 1> {22}),
    lsp::DatagramResult::malformed_peer
  );
  EXPECT_EQ(service.receive(peer, std::array<std::uint8_t, 1> {0x80}), lsp::DatagramResult::invalid_drop);

  dtls.receive_result = lsp::ProviderDatagramResult::dropped;
  EXPECT_EQ(service.receive(peer, std::array<std::uint8_t, 1> {22}), lsp::DatagramResult::provider_drop);
  srtp.receive_result = lsp::ProviderDatagramResult::fatal;
  EXPECT_EQ(
    service.receive(peer, std::array<std::uint8_t, 2> {0x80, 96}),
    lsp::DatagramResult::provider_fatal
  );
  EXPECT_EQ(dtls.receive_calls, 2U);
  EXPECT_EQ(srtp.receive_calls, 3U);

  service.stop();
  EXPECT_FALSE(service.active());
  EXPECT_EQ(socket.close_calls, 1U);
  EXPECT_EQ(service.receive(peer, std::array<std::uint8_t, 1> {22}), lsp::DatagramResult::inactive);
}

TEST(LspInvitation, RoundTripsExactDeterministicFragmentUri) {
  const auto model = invitation();
  const auto first = lsp::encode_invitation_uri(model);
  ASSERT_TRUE(first);
  ASSERT_TRUE(first->starts_with(lsp::invitation_uri_prefix));
  EXPECT_EQ(first->find('='), std::string::npos);
  const auto decoded = lsp::decode_invitation_uri(*first);
  ASSERT_TRUE(decoded);
  EXPECT_EQ(*decoded, model);
  EXPECT_EQ(lsp::encode_invitation_uri(*decoded), first);
  EXPECT_FALSE(decoded->expired(decoded->expires_at_utc_seconds - 1));
  EXPECT_TRUE(decoded->expired(decoded->expires_at_utc_seconds));

  EXPECT_EQ(lsp::decode_invitation_uri(*first + "=").error(), lsp::InvitationError::invalid_base64url);
  EXPECT_EQ(lsp::decode_invitation_uri("https://pair/lsp1#abc").error(), lsp::InvitationError::invalid_uri);
  EXPECT_EQ(lsp::decode_invitation_uri("umbra://pair/lsp1#_w").error(), lsp::InvitationError::invalid_cbor);
  auto zero_secret = model;
  zero_secret.invitation_secret = {};
  EXPECT_EQ(lsp::encode_invitation_uri(zero_secret).error(), lsp::InvitationError::invalid_model);
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
  EXPECT_EQ(authority.attach(fresh_owner, start.session_id, filled<32>(10)), lsp::AuthorityResult::token_mismatch);
  ASSERT_EQ(authority.attach(fresh_owner, start.session_id, start.attach_token), lsp::AuthorityResult::accepted);
  EXPECT_EQ(token_verifier.calls, 2U);
  EXPECT_EQ(authority.snapshot().generations.connection, 11U);
  EXPECT_EQ(authority.snapshot().generations.input, 61U);
  EXPECT_EQ(authority.authorize_input(owner.client_id, 10, 20, 60), lsp::AuthorityResult::stale_generation);
  EXPECT_EQ(authority.authorize_input(owner.client_id, 11, 20, 61), lsp::AuthorityResult::baseline_required);
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
  EXPECT_EQ(authority.attach(owner, start.session_id, start.attach_token), lsp::AuthorityResult::invalid_state);
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
    authority.attach(owner, start.session_id, start.attach_token),
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
