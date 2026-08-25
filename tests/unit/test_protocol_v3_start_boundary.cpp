/**
 * @file tests/unit/test_protocol_v3_start_boundary.cpp
 * @brief Encoded START coverage at the real authenticated ControlSession boundary.
 */

#include "src/protocol_common/status.h"
#include "src/protocol_v3/control_session.h"
#include "src/protocol_v3/quic_server.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <expected>
#include <gtest/gtest.h>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {
  namespace control = lumen::protocol_v3::control_session;
  namespace quic = lumen::protocol_v3::quic_server;
  using Status = lumen::protocol_common::Status;

  class FixedRandom final: public control::Random {
  public:
    bool fill(const std::span<std::uint8_t> output) noexcept override {
      std::ranges::fill(output, 0x5a);
      return true;
    }
  };

  class UnusedAuthorization final: public control::AuthorizationStore {
  public:
    std::optional<control::ClientRecord> paired_client(const control::Identifier &) override {
      return std::nullopt;
    }

    std::expected<control::ClientRecord, std::uint8_t> consume_invitation(
      const control::PairingClaim &
    ) override {
      return std::unexpected(std::uint8_t {1});
    }
  };

  class UnusedNonceRegistry final: public control::NonceRegistry {
  public:
    bool claim(
      const quic::RemoteSourcePrefix &,
      const control::Identifier &,
      const control::Bytes32 &,
      quic::MonotonicClock::time_point
    ) noexcept override {
      return true;
    }
  };

  class UnusedPairingAdmission final: public control::PairingAdmission {
  public:
    bool admit_hello(
      const quic::RemoteSourcePrefix &,
      const control::Identifier &,
      quic::MonotonicClock::time_point
    ) noexcept override {
      return true;
    }

    bool admit(
      const quic::RemoteSourcePrefix &,
      const control::Identifier &,
      quic::MonotonicClock::time_point
    ) noexcept override {
      return true;
    }
  };

  class CapturingBackend final: public control::SessionBackend {
  public:
    std::expected<control::StartResult, std::uint8_t> start(
      const control::ClientRecord &,
      const control::cbor::Value::Map &request_fields,
      std::uint64_t,
      std::uint16_t
    ) override {
      ++start_calls;
      last_start_fields = request_fields;
      return std::unexpected(static_cast<std::uint8_t>(Status::unsupported_media));
    }

    std::expected<control::ControlResult, std::uint8_t> control(
      const control::ClientRecord &,
      control::AuthenticatedControl,
      const control::cbor::Value::Map &,
      std::uint64_t,
      std::uint64_t,
      std::uint64_t
    ) override {
      return std::unexpected(std::uint8_t {1});
    }

    std::optional<control::Identifier> owned_session(const control::ClientRecord &) override {
      return std::nullopt;
    }

    bool acknowledge_configuration(
      const control::ClientRecord &,
      control::ConfigurationAcknowledgement,
      const control::Identifier &,
      std::uint32_t,
      std::optional<std::uint32_t>
    ) override {
      return false;
    }

    bool start_media(const control::ClientRecord &, const control::Identifier &) override {
      return false;
    }

    void datagram(const control::ClientRecord &, const quic::DatagramRecord &) override {
    }

    void revoke_connection(std::uint64_t) noexcept override {
    }

    void disconnect(const std::optional<control::Identifier> &, std::uint64_t) noexcept override {
    }

    int start_calls {};
    control::cbor::Value::Map last_start_fields;
  };

  void append_be(std::vector<std::uint8_t> &output, const std::uint64_t value, std::size_t bytes) {
    while (bytes-- != 0) {
      output.push_back(static_cast<std::uint8_t>(value >> (bytes * 8U)));
    }
  }

  control::cbor::Value::Map start_fields(
    const std::uint64_t refresh_numerator = 60'000,
    const std::uint64_t refresh_denominator = 1'001,
    const bool host_audio = false
  ) {
    using Value = control::cbor::Value;
    return {
      {1, Value::Bytes(16, 0x11)},
      {2, 1U},
      {3, 2U},
      {4, 1920U},
      {5, 1080U},
      {6, refresh_numerator},
      {7, refresh_denominator},
      {8, 100'000U},
      {9, Value::Array {Value::Map {
            {1, 1U},
            {2, 1U},
            {3, 8U},
            {4, 1U},
            {5, 1U},
            {6, 1U},
            {7, 1U},
            {8, 0U},
            {9, 0U},
            {10, 1U},
          }}},
      {10, Value::Array {Value::Map {}}},
      {11, Value {control::cbor::Null {}}},
      {12, static_cast<std::uint64_t>(quic::maximum_semantic_datagram_bytes)},
      {13, Value::Bytes(16, 0x22)},
      {14, Value::Array {}},
      {15, Value::Array {Value::Map {}}},
      {16, Value {false}},
      {17, Value::Map {}},
      {18, Value {host_audio}},
    };
  }

  std::vector<std::uint8_t> encoded_start(const control::cbor::Value::Map &fields) {
    const auto payload = control::cbor::encode(control::cbor::Value {fields});
    EXPECT_TRUE(payload);
    std::vector<std::uint8_t> output {'U', 'L', 'C', '3', 3, 0};
    append_be(output, 0x0100, 2);
    append_be(output, 1, 8);
    append_be(output, payload.bytes.size(), 4);
    append_be(output, 0, 4);
    output.insert(output.end(), payload.bytes.begin(), payload.bytes.end());
    return output;
  }

  bool traverses_control_session(const control::cbor::Value::Map &fields, CapturingBackend &backend) {
    FixedRandom random;
    control::Bytes32 seed {};
    seed.fill(0x41);
    control::SeedHostIdentity identity {seed};
    UnusedAuthorization authorization;
    UnusedNonceRegistry nonces;
    UnusedPairingAdmission pairing;
    control::ConnectionAuthorities authorities;
    quic::ConnectionContext connection {
      .connection_id = 42,
      .local_udp_port = 48'021,
      .maximum_datagram_bytes = quic::maximum_semantic_datagram_bytes,
      .profile = quic::Profile::quality,
      .connected_at = quic::MonotonicClock::now(),
    };
    connection.leaf_spki_sha256.fill(0x33);
    control::ControlSession session {
      connection,
      {},
      random,
      identity,
      authorization,
      nonces,
      pairing,
      authorities,
      backend,
    };
    control::ClientRecord client {
      .permissions = control::start_permission,
      .generation = 1,
    };
    client.client_id.fill(0x51);
    if (!session.install_authenticated_client_for_test(client)) {
      return false;
    }
    const auto bytes = encoded_start(fields);
    const auto parsed = quic::parse_control_frame(bytes);
    if (!parsed) {
      return false;
    }
    static_cast<void>(session.control(*parsed));
    return true;
  }
}  // namespace

TEST(ProtocolV3StartBoundary, EncodedKey18AndExactRefreshReachTheProductionBackend) {
  for (const auto [numerator, denominator] : std::array {
         std::pair {10ULL, 1ULL},
         std::pair {120ULL, 1ULL},
         std::pair {60'000ULL, 1'001ULL},
         std::pair {480ULL, 1ULL},
       }) {
    for (const bool host_audio : {false, true}) {
      CapturingBackend backend;
      ASSERT_TRUE(traverses_control_session(start_fields(numerator, denominator, host_audio), backend));
      ASSERT_EQ(backend.start_calls, 1);
      const auto host_audio_field = std::ranges::find_if(backend.last_start_fields, [](const auto &entry) {
        return entry.first == 18;
      });
      ASSERT_NE(host_audio_field, backend.last_start_fields.end());
      ASSERT_NE(std::get_if<bool>(&host_audio_field->second.storage), nullptr);
      EXPECT_EQ(*std::get_if<bool>(&host_audio_field->second.storage), host_audio);
    }
  }
}

TEST(ProtocolV3StartBoundary, HostileKey18ShapesFailBeforeTheProductionBackend) {
  std::vector<control::cbor::Value::Map> hostile;
  auto missing = start_fields();
  missing.pop_back();
  hostile.push_back(std::move(missing));
  for (control::cbor::Value value : {
         control::cbor::Value {control::cbor::Null {}},
         control::cbor::Value {0U},
         control::cbor::Value {std::string {"false"}},
       }) {
    auto fields = start_fields();
    fields.back().second = std::move(value);
    hostile.push_back(std::move(fields));
  }
  auto extra = start_fields();
  extra.emplace_back(19, control::cbor::Value {false});
  hostile.push_back(std::move(extra));

  for (const auto &fields : hostile) {
    CapturingBackend backend;
    EXPECT_THROW(static_cast<void>(traverses_control_session(fields, backend)), std::runtime_error);
    EXPECT_EQ(backend.start_calls, 0);
  }
}

TEST(ProtocolV3StartBoundary, InvalidExactRationalsFailBeforeTheProductionBackend) {
  for (const auto [numerator, denominator] : std::array {
         std::pair {9'999ULL, 1'000ULL},
         std::pair {480'001ULL, 1'000ULL},
         std::pair {0ULL, 1ULL},
         std::pair {60ULL, 0ULL},
         std::pair {4'294'967'296ULL, 1ULL},
         std::pair {60'000ULL, 1'000ULL},
         std::pair {60'000'000ULL, 1'001'000ULL},
       }) {
    CapturingBackend backend;
    EXPECT_THROW(
      static_cast<void>(traverses_control_session(start_fields(numerator, denominator), backend)),
      std::runtime_error
    );
    EXPECT_EQ(backend.start_calls, 0);
  }
}
