/**
 * @file tests/unit/test_protocol_v3_quic_server.cpp
 * @brief Pure protocol-v3 wire, credential, and bounded-security tests.
 */

#include "src/protocol_v3/control_session.h"
#include "src/protocol_v3/quic_server.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <gtest/gtest.h>
#include <map>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {
  namespace control = lumen::protocol_v3::control_session;
  namespace quic = lumen::protocol_v3::quic_server;

  void append_be(std::vector<std::uint8_t> &out, std::uint64_t value, std::size_t count) {
    while (count-- > 0) {
      out.push_back(static_cast<std::uint8_t>(value >> (count * 8U)));
    }
  }

  std::array<std::uint8_t, 16> session_id() {
    std::array<std::uint8_t, 16> id {};
    for (std::size_t index = 0; index < id.size(); ++index) {
      id[index] = static_cast<std::uint8_t>(0xc0 + index);
    }
    return id;
  }

  std::vector<std::uint8_t> control_frame(std::uint16_t type, std::uint64_t request) {
    std::vector<std::uint8_t> out {'U', 'L', 'C', '3', 3, 0};
    append_be(out, type, 2);
    append_be(out, request, 8);
    append_be(out, 1, 4);
    append_be(out, 0, 4);
    out.push_back(0xa0);
    return out;
  }

  std::vector<std::uint8_t> datagram(std::uint8_t channel, std::uint8_t kind, std::uint8_t flags = 0) {
    std::vector<std::uint8_t> out {'U', 'L', 'M', '3', 3, channel, kind, flags};
    append_be(out, 44, 2);
    append_be(out, 1, 2);
    const auto id = session_id();
    out.insert(out.end(), id.begin(), id.end());
    append_be(out, 42, 8);
    append_be(out, 77, 8);
    out.push_back(0x42);
    return out;
  }

  constexpr std::string_view test_certificate = R"PEM(-----BEGIN CERTIFICATE-----
MIIDPDCCAiSgAwIBAgIUcL5OD62bCLR4l3gjBLxRUBSfg+8wDQYJKoZIhvcNAQEL
BQAwHDEaMBgGA1UEAwwRbHVtZW4tdjItbG9vcGJhY2swHhcNMjYwODI0MDAyNjQ2
WhcNMzYwODIxMDAyNjQ2WjAcMRowGAYDVQQDDBFsdW1lbi12Mi1sb29wYmFjazCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALW78ceVc2E6nkHxjE+4gUBE
PLJ35OlBGRW+FeYmTxK7vBu3Yq42NtcDDopRbaaG9VyYD3gYZPgE1Bi8NyZg5y65
ST8TLypQXCwJ6j3hpyv3C7YCwMeceRojreRxL2gtjoAUlGAkvqII98eZBOL7qWtf
uLLmeVNYUZfS1Yb8t0NWtVw8VbSFsMtUADr/41WqmX4GEJfTt61oF5GIn97Tqke/
AkXSCdyh7U7oT7m7WJxMsEgvvgwLqM0DLSVkXQRHEKbk3TZmXUiR/SSz99AJMBnx
2rIPZc5gCACdQOCWWW6J4vtq+P0wXb1Ux/YkDmHOG2QvJi4Ljw2xsTZBQnQDcAUC
AwEAAaN2MHQwHQYDVR0OBBYEFO1KvYMNWGz89kpdOndGBAYor0CqMB8GA1UdIwQY
MBaAFO1KvYMNWGz89kpdOndGBAYor0CqMA8GA1UdEwEB/wQFMAMBAf8wIQYDVR0R
BBowGIcEfwAAAYcQAAAAAAAAAAAAAAAAAAAAATANBgkqhkiG9w0BAQsFAAOCAQEA
Pwwh1wjVU8r4LfsXRuycUoGW+cZb2crrIbmxNiVibRztslBVX5bPAa+5gZS6kHmb
q8BZPsTCqVG8GNdP4YswrtRJXF7M1iFF4WZ86JSPLM7l4xG7zW3qN6/+jt3+k+8r
Oa8L7/sowTTi2LdHDW3FQjPal0LY/Z6OMDHHb4QlZWVmpm40mVihfN4piQUeg6J2
3YuqTs5wRfx/w+JXCEt+pTaf1RAiKb/UnsJKuCGbUU2MXhdsInfnUIHoH1+Lxpz+
vT1gnf7vat//Iw86VySv6+RouYiqFzZOIV1OMJ6RTm3mIxrmzMDFmQ8qtvSp8dVG
3pjXFp2G8R0hgizhRoW1MQ==
-----END CERTIFICATE-----
)PEM";

  constexpr std::string_view test_private_key = R"PEM(-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC1u/HHlXNhOp5B
8YxPuIFARDyyd+TpQRkVvhXmJk8Su7wbt2KuNjbXAw6KUW2mhvVcmA94GGT4BNQY
vDcmYOcuuUk/Ey8qUFwsCeo94acr9wu2AsDHnHkaI63kcS9oLY6AFJRgJL6iCPfH
mQTi+6lrX7iy5nlTWFGX0tWG/LdDVrVcPFW0hbDLVAA6/+NVqpl+BhCX07etaBeR
iJ/e06pHvwJF0gncoe1O6E+5u1icTLBIL74MC6jNAy0lZF0ERxCm5N02Zl1Ikf0k
s/fQCTAZ8dqyD2XOYAgAnUDgllluieL7avj9MF29VMf2JA5hzhtkLyYuC48NsbE2
QUJ0A3AFAgMBAAECggEAF/3z8XFdhhyDABmveGbXSXC4wqbpZZHeiexKX9P25HY8
YzxWnsExhDk3FjOh0jZG9i5s/GHcEpIwngNbFIn+e0Ci1tzlgSSSxo2YiwrbUwaO
WT0Lzk5t/nFvZ5U5uPsqsOYGoJq5QBMHAybEamLm/vHoJFYg9kvWmcCPx/5dA1qa
J7rRTdngrk+updUGiXvAiXTvjq4foA9pxFTPEcar26gX/Ae+mZoHlsR1vNpYrVL+
QA5JKYn72N7g9/l1OQRyldTByXRuL2T8IrQ0Yrh1LdJMV6gkePlgBiRGn4yTxl3E
NnmWVBkAlwaHVdBdVa3ySFHlPqg8sHqp3K82bzKEAQKBgQDcegtYWLgLF2uFPF6P
+ne4mLxx1kGjeteAUTaAowDvwXc9NnMSncdcl+PDLDWkfBlovhUgl2XhURBcB2Mi
guKSh7kHUoAaaxxExOVcPPlYLIL/bCDSX7tz6b8P+l0rbciMr/JnhBZ6hVGVMJOx
+3644/FLu+D1DDL2b5lCPUWKwQKBgQDTA+S9MN1ui01KMByjw0hb8ryDEpftqvWc
d2XJWbcajyiI7raWoPNiajRZYo6nPCRC1VyAlRoUkQ2g+yMK2pUHlPP70QP6jk40
Lo/J4fqpOn8+ZWZYsgzRpdSzNl9tlyNCDJJYfq7+UjHg3Ev6OT0KfyvRMq9LwKf3
RjXQrrmKRQKBgQCdDj9YrtJj7EoGfkuqarSwBfVvbj4R06cB3Fhj6Dn5kKp9K3Vr
lIN4vSZdWPfZdSGwkH+CWPcVO2bY99YxtmTqFs7CnY1txFE917i/LRw+KG8kvoTe
950T5DXbjvChyDGtroSSIvDUVHYaPaFojwvlb1LrLSoBxa/kBvl4yybnwQKBgA34
fQV1ncN635Qg2VSSUlEcIhT/fyWSIw7H7OpG0VOl1MY0H8ybPWHvrCWa290Ao1n1
bFlrBb4E2IUm+2v1itZkqz6p2PyWvWDBEG4KUyEvKUuFRSBsMWMT+qAe4nSMBB6U
XIAVaxqVcI31p+YaMgtm3gzMsURvre82K8v0NX6NAoGBAKgV/PL0IbXtLOQcftnF
OGnRHsIdoF4fCHXfTQQV+rnz1+hFIRN9BkhY6lhiwKT9fTZ5vAkhj1NUNAp4/OT1
nmYOVibPoPW6Sb0v2UubDY6TT2+1SCD9smKkBcgzRc++61a8V0A8xaaZYZkWMMRc
i2j7w5vhA66Ep18oU6mfswVI
-----END PRIVATE KEY-----
)PEM";

  class TestSession final: public quic::ControlSessionV3 {
  public:
    explicit TestSession(const bool active): active_ {active} {
    }

    std::vector<std::shared_ptr<const std::vector<std::uint8_t>>> control(
      const quic::ControlFrame &
    ) override {
      return {};
    }

    void datagram(const quic::DatagramRecord &) override {
    }

    std::optional<std::array<std::uint8_t, 16>> active_session_id() const noexcept override {
      return active_ ? std::optional {session_id()} : std::nullopt;
    }

    bool authenticated() const noexcept override {
      return true;
    }

    std::uint64_t idle_timeout_ms() const noexcept override {
      return 0;
    }

    void datagram_maximum_changed(std::uint16_t) override {
    }

    std::vector<quic::BulkTransfer> take_bulk_transfers() override {
      return {};
    }

    void disconnect() noexcept override {
    }

  private:
    bool active_;
  };

  class TestSessionFactory final: public quic::SessionFactory {
  public:
    explicit TestSessionFactory(const bool active = true): active_ {active} {
    }

    std::unique_ptr<quic::ControlSessionV3> create(const quic::ConnectionContext &) override {
      return std::make_unique<TestSession>(active_);
    }

  private:
    bool active_;
  };

  class TestMsQuicApi final: public quic::MsQuicApi {
  public:
    struct DatagramSend {
      std::vector<std::uint8_t> bytes;
      std::uint64_t token {};
      bool urgent {};
    };

    bool is_schannel() const noexcept override {
      return true;
    }

    quic::ApiStatus registration_open(std::string_view, quic::Handle &registration) override {
      registration = 1;
      return quic::ApiStatus::success;
    }

    void registration_close(quic::Handle) noexcept override {
    }

    quic::ApiStatus configuration_open(
      quic::Handle,
      std::string_view,
      std::uint16_t,
      std::uint16_t,
      std::uint64_t,
      std::uint64_t,
      quic::Handle &configuration
    ) override {
      configuration = 2;
      return quic::ApiStatus::success;
    }

    quic::ApiStatus configuration_load_pkcs12(
      quic::Handle,
      std::span<const std::uint8_t>,
      std::string_view
    ) override {
      return configuration_load_status;
    }

    quic::ApiStatus configuration_leaf_spki_sha256(
      quic::Handle,
      const std::span<std::uint8_t, 32> output
    ) override {
      std::ranges::fill(output, 0xA5);
      return quic::ApiStatus::success;
    }

    void configuration_close(quic::Handle) noexcept override {
    }

    quic::ApiStatus listener_open(
      quic::Handle,
      ListenerCallback callback,
      quic::Handle &listener
    ) override {
      listener_callback = std::move(callback);
      listener = 3;
      return quic::ApiStatus::success;
    }

    quic::ApiStatus listener_start(quic::Handle, std::string_view, std::uint16_t) override {
      return quic::ApiStatus::success;
    }

    void listener_stop(quic::Handle) noexcept override {
      const auto call = listener_stop_calls.fetch_add(1) + 1;
      if (block_first_listener_stop && call == 1) {
        std::unique_lock lock {listener_stop_mutex};
        first_listener_stop_entered = true;
        listener_stop_condition.notify_all();
        listener_stop_condition.wait(lock, [&] {
          return release_first_listener_stop;
        });
      }
      if (complete_listener_stop_synchronously) {
        static_cast<void>(listener_callback({.kind = quic::ListenerEvent::Kind::stop_complete}));
      }
    }

    void listener_close(quic::Handle) noexcept override {
    }

    quic::ApiStatus connection_set_callback(
      quic::Handle,
      ConnectionCallback callback
    ) override {
      connection_callback = std::move(callback);
      return quic::ApiStatus::success;
    }

    quic::ApiStatus connection_set_configuration(quic::Handle, quic::Handle) override {
      return quic::ApiStatus::success;
    }

    quic::ApiStatus connection_set_idle_timeout(quic::Handle, std::uint64_t) override {
      return quic::ApiStatus::success;
    }

    void connection_shutdown(const quic::Handle connection, const std::uint64_t error) noexcept override {
      connection_shutdowns.emplace_back(connection, error);
    }

    void connection_close(quic::Handle) noexcept override {
    }

    quic::ApiStatus stream_open_unidirectional(
      quic::Handle,
      StreamCallback callback,
      quic::Handle &stream
    ) override {
      stream = next_stream++;
      stream_callbacks.emplace(stream, std::move(callback));
      return quic::ApiStatus::success;
    }

    quic::ApiStatus stream_start(quic::Handle) override {
      return quic::ApiStatus::success;
    }

    quic::ApiStatus stream_set_callback(const quic::Handle stream, StreamCallback callback) override {
      stream_callbacks.insert_or_assign(stream, std::move(callback));
      return quic::ApiStatus::success;
    }

    quic::ApiStatus stream_send(
      quic::Handle,
      std::span<const quic::Buffer>,
      std::uint64_t,
      bool,
      bool
    ) override {
      return quic::ApiStatus::success;
    }

    quic::ApiStatus stream_set_priority(quic::Handle, std::uint16_t) override {
      return quic::ApiStatus::success;
    }

    void stream_receive_complete(quic::Handle, std::uint64_t) noexcept override {
    }

    void stream_shutdown(const quic::Handle stream, const std::uint64_t error) noexcept override {
      stream_shutdowns.emplace_back(stream, error);
    }

    void stream_close(quic::Handle) noexcept override {
    }

    quic::ApiStatus datagram_send(
      quic::Handle,
      const std::span<const quic::Buffer> buffers,
      const std::uint64_t token,
      const bool urgent,
      bool
    ) override {
      DatagramSend send {.token = token, .urgent = urgent};
      for (const auto &buffer : buffers) {
        send.bytes.insert(send.bytes.end(), buffer.data, buffer.data + buffer.size);
      }
      datagram_sends.push_back(std::move(send));
      return quic::ApiStatus::success;
    }

    std::optional<quic::CongestionSample> congestion_sample(quic::Handle) noexcept override {
      return congestion;
    }

    quic::ApiStatus accept_connection(const quic::Handle connection = 10) {
      return listener_callback({
        .kind = quic::ListenerEvent::Kind::new_connection,
        .connection = connection,
        .remote_source = quic::RemoteSourcePrefix {
          quic::RemoteSourcePrefix::Family::ipv4,
          {192, 0, 2, 1},
        },
      });
    }

    quic::ApiStatus connection_event(const quic::ConnectionEvent &event) {
      return connection_callback(event);
    }

    quic::ApiStatus stream_event(const quic::Handle stream, const quic::StreamEvent &event) {
      return stream_callbacks.at(stream)(event);
    }

    void wait_for_first_listener_stop() {
      std::unique_lock lock {listener_stop_mutex};
      listener_stop_condition.wait(lock, [&] {
        return first_listener_stop_entered;
      });
    }

    void release_listener_stop() {
      std::lock_guard lock {listener_stop_mutex};
      release_first_listener_stop = true;
      listener_stop_condition.notify_all();
    }

    ListenerCallback listener_callback;
    ConnectionCallback connection_callback;
    std::map<quic::Handle, StreamCallback> stream_callbacks;
    std::vector<std::pair<quic::Handle, std::uint64_t>> connection_shutdowns;
    std::vector<std::pair<quic::Handle, std::uint64_t>> stream_shutdowns;
    std::vector<DatagramSend> datagram_sends;
    std::optional<quic::CongestionSample> congestion;
    quic::Handle next_stream {100};
    std::atomic_size_t listener_stop_calls {};
    bool complete_listener_stop_synchronously {};
    quic::ApiStatus configuration_load_status {quic::ApiStatus::success};
    std::mutex listener_stop_mutex;
    std::condition_variable listener_stop_condition;
    bool block_first_listener_stop {};
    bool first_listener_stop_entered {};
    bool release_first_listener_stop {};
  };

  quic::Config test_config() {
    quic::Config config;
    config.certificate = quic::make_certificate_credential_from_pem(test_certificate, test_private_key);
    return config;
  }

  void connect_test_server(TestMsQuicApi &api, quic::QuicServer &server) {
    ASSERT_EQ(server.start(), quic::ApiStatus::success);
    ASSERT_EQ(api.accept_connection(), quic::ApiStatus::success);
    ASSERT_EQ(
      api.connection_event({.kind = quic::ConnectionEvent::Kind::connected}),
      quic::ApiStatus::success
    );
  }

  void authenticate_test_server(TestMsQuicApi &api) {
    constexpr quic::Handle control_stream = 20;
    ASSERT_EQ(
      api.connection_event({
        .kind = quic::ConnectionEvent::Kind::peer_stream_started,
        .stream = control_stream,
        .stream_id = 0,
      }),
      quic::ApiStatus::success
    );
    const auto hello = control_frame(0x0001, 1);
    const quic::Buffer buffer {hello.data(), hello.size()};
    ASSERT_EQ(
      api.stream_event(control_stream, {
        .kind = quic::StreamEvent::Kind::receive,
        .buffers = std::span {&buffer, 1},
        .total_buffer_bytes = hello.size(),
      }),
      quic::ApiStatus::success
    );
  }

  TEST(ProtocolV3Wire, ParsersRejectWrongNamespaceDirectionAndFlags) {
    const auto frame = control_frame(0x10, 2);
    const auto parsed = quic::parse_control_frame(frame);
    ASSERT_TRUE(parsed);
    EXPECT_EQ(parsed->message_type, 0x10);
    auto bad = frame;
    bad[0] = 'X';
    EXPECT_EQ(quic::parse_control_frame(bad).error(), quic::ParseError::magic_or_version);
    const auto id = session_id();
    const auto record = datagram(1, 1);
    ASSERT_TRUE(quic::parse_datagram_record(record, quic::Direction::client_to_host, id, 1152));
    EXPECT_EQ(
      quic::parse_datagram_record(record, quic::Direction::host_to_client, id, 1152).error(),
      quic::ParseError::reserved_route
    );
    const auto controller_feedback = datagram(1, 4);
    ASSERT_TRUE(quic::parse_datagram_record(
      controller_feedback,
      quic::Direction::host_to_client,
      id,
      1152
    ));
    EXPECT_EQ(
      quic::parse_datagram_record(
        controller_feedback,
        quic::Direction::client_to_host,
        id,
        1152
      ).error(),
      quic::ParseError::reserved_route
    );
    const auto rtt_telemetry = datagram(5, 1);
    ASSERT_TRUE(quic::parse_datagram_record(
      rtt_telemetry,
      quic::Direction::host_to_client,
      id,
      1152
    ));
    EXPECT_EQ(
      quic::parse_datagram_record(
        rtt_telemetry,
        quic::Direction::client_to_host,
        id,
        1152
      ).error(),
      quic::ParseError::reserved_route
    );
    bad = record;
    bad[7] = 0x40;
    EXPECT_EQ(
      quic::parse_datagram_record(bad, quic::Direction::client_to_host, id, 1152).error(),
      quic::ParseError::reserved_flags
    );
  }

  TEST(ProtocolV3Wire, SourceNormalizationCollapsesMappedIpv4AndBoundsIpv6To64) {
    const std::array<std::uint8_t, 16> mapped {
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1,
    };
    EXPECT_EQ(
      quic::normalize_remote_source(23, mapped),
      quic::normalize_remote_source(2, std::span {mapped}.last(4))
    );
    const std::array<std::uint8_t, 16> first {
      0x20, 1, 0x0d, 0xb8, 1, 2, 3, 4, 0, 1, 2, 3, 4, 5, 6, 7,
    };
    auto same_prefix = first;
    std::fill(same_prefix.begin() + 8, same_prefix.end(), 0xff);
    EXPECT_EQ(quic::normalize_remote_source(23, first), quic::normalize_remote_source(23, same_prefix));
  }

  TEST(ProtocolV3Security, ConcreteServicesEnforceNonceAdmissionAndAuthorityBounds) {
    control::SecureRandom random;
    control::Bytes32 random_bytes {};
    EXPECT_TRUE(random.fill(random_bytes));
    control::Bytes32 seed {};
    for (std::size_t index = 0; index < seed.size(); ++index) {
      seed[index] = static_cast<std::uint8_t>(index + 32);
    }
    control::SeedHostIdentity identity {seed};
    EXPECT_TRUE(identity.sign(random_bytes).has_value());
    control::Identifier attempt {};
    attempt[0] = 1;
    const auto now = quic::MonotonicClock::now();
    const quic::RemoteSourcePrefix source {quic::RemoteSourcePrefix::Family::ipv4, {192, 0, 2, 1}};
    control::BoundedNonceRegistry nonces;
    EXPECT_TRUE(nonces.claim(source, attempt, random_bytes, now));
    EXPECT_FALSE(nonces.claim(source, attempt, random_bytes, now));
    for (std::uint8_t index = 1; index < 64; ++index) {
      control::Identifier unique_attempt {};
      control::Bytes32 unique_nonce {};
      unique_attempt[0] = static_cast<std::uint8_t>(index + 1);
      unique_nonce[0] = index;
      EXPECT_TRUE(nonces.claim(source, unique_attempt, unique_nonce, now));
    }
    control::Identifier excess_attempt {};
    control::Bytes32 excess_nonce {};
    excess_attempt[0] = 65;
    excess_nonce[0] = 64;
    EXPECT_FALSE(nonces.claim(source, excess_attempt, excess_nonce, now));

    control::BoundedNonceRegistry fair_nonces;
    for (std::uint8_t source_index = 0; source_index < 64; ++source_index) {
      const quic::RemoteSourcePrefix bucket {
        quic::RemoteSourcePrefix::Family::ipv4,
        {198, 51, 100, source_index},
      };
      for (std::uint8_t nonce_index = 0; nonce_index < 64; ++nonce_index) {
        control::Identifier unique_attempt {};
        control::Bytes32 unique_nonce {};
        unique_attempt[0] = source_index;
        unique_attempt[1] = nonce_index;
        unique_attempt[2] = 1;
        unique_nonce[0] = source_index;
        unique_nonce[1] = nonce_index;
        unique_nonce[2] = 2;
        ASSERT_TRUE(fair_nonces.claim(bucket, unique_attempt, unique_nonce, now));
      }
    }
    const quic::RemoteSourcePrefix new_source {
      quic::RemoteSourcePrefix::Family::ipv4,
      {203, 0, 113, 1},
    };
    EXPECT_TRUE(fair_nonces.claim(new_source, excess_attempt, excess_nonce, now));

    control::BoundedPairingAdmission admission;
    for (std::size_t count = 0; count < 32; ++count) {
      EXPECT_TRUE(admission.admit(source, attempt, now));
    }
    EXPECT_FALSE(admission.admit(source, attempt, now));
    control::ConnectionAuthorities authorities;
    const auto first = authorities.claim(attempt, 10, false);
    ASSERT_TRUE(first);
    EXPECT_FALSE(authorities.claim(attempt, 11, false));
    const auto replacement = authorities.claim(attempt, 11, true);
    ASSERT_TRUE(replacement);
    EXPECT_EQ(replacement->replaced_connection_id, 10U);
    auto lease = authorities.lease(attempt, 11, replacement->generation);
    ASSERT_TRUE(lease);
    EXPECT_FALSE(authorities.claim(attempt, 12, true));
    lease.reset();
    EXPECT_TRUE(authorities.claim(attempt, 12, true));
  }

  TEST(ProtocolV3Security, PemCredentialConvertsToBoundedInMemoryPkcs12) {
    const auto certificate = std::string {test_certificate};
    const auto private_key = std::string {test_private_key};
    const auto credential = quic::make_certificate_credential_from_pem(certificate, private_key);
    ASSERT_TRUE(credential);
    EXPECT_FALSE(credential->pkcs12.empty());
    EXPECT_LE(credential->pkcs12.size(), 1'048'576U);
    EXPECT_EQ(credential->password.size(), 64U);
    EXPECT_FALSE(quic::make_certificate_credential_from_pem(certificate, certificate));
  }

  TEST(ProtocolV3Security, ApplicationCloseCodesMatchTheVersionThreeWireContract) {
    EXPECT_EQ(static_cast<std::uint64_t>(quic::ApplicationCloseCode::malformed), 0x100U);
    EXPECT_EQ(static_cast<std::uint64_t>(quic::ApplicationCloseCode::connection_replaced), 0x105U);
    EXPECT_EQ(static_cast<std::uint64_t>(quic::ApplicationCloseCode::abuse_limit), 0x106U);
    EXPECT_EQ(static_cast<std::uint64_t>(quic::ApplicationCloseCode::internal_failure), 0x109U);
    EXPECT_EQ(static_cast<std::uint64_t>(quic::ApplicationCloseCode::normal_shutdown), 0x10AU);
  }

  TEST(ProtocolV3Security, SynchronousListenerStopCompletionDoesNotReenterTheServerLock) {
    TestMsQuicApi api;
    api.complete_listener_stop_synchronously = true;
    TestSessionFactory factory;
    quic::QuicServer server {api, test_config(), factory};
    ASSERT_EQ(server.start(), quic::ApiStatus::success);

    server.stop();

    EXPECT_EQ(api.listener_stop_calls.load(), 1U);
    EXPECT_FALSE(server.running());
  }

  TEST(ProtocolV3Security, ConcurrentStopCallersSubmitListenerStopExactlyOnce) {
    TestMsQuicApi api;
    api.block_first_listener_stop = true;
    api.complete_listener_stop_synchronously = true;
    TestSessionFactory factory;
    quic::QuicServer server {api, test_config(), factory};
    ASSERT_EQ(server.start(), quic::ApiStatus::success);

    std::jthread first {[&] {
      server.stop();
    }};
    api.wait_for_first_listener_stop();
    server.stop();
    EXPECT_EQ(api.listener_stop_calls.load(), 1U);
    api.release_listener_stop();
    first.join();
  }

  TEST(ProtocolV3Security, StartupFailureReportsTheExactTransportStage) {
    TestMsQuicApi api;
    api.configuration_load_status = quic::ApiStatus::transport_error;
    TestSessionFactory factory;
    quic::QuicServer server {api, test_config(), factory};

    EXPECT_EQ(server.start(), quic::ApiStatus::transport_error);
    EXPECT_EQ(server.startup_stage(), quic::StartupStage::credential);
    EXPECT_EQ(quic::startup_stage_name(server.startup_stage()), "credential");
  }

  TEST(ProtocolV3Security, PreAuthDatagramAndBulkStreamCloseTheConnectionImmediately) {
    {
      TestMsQuicApi api;
      TestSessionFactory factory;
      quic::QuicServer server {api, test_config(), factory};
      connect_test_server(api, server);
      const auto record = datagram(1, 1);
      EXPECT_EQ(
        api.connection_event({
          .kind = quic::ConnectionEvent::Kind::datagram_received,
          .received_bytes = record,
        }),
        quic::ApiStatus::aborted
      );
      ASSERT_EQ(api.connection_shutdowns.size(), 1U);
      EXPECT_EQ(
        api.connection_shutdowns.front().second,
        static_cast<std::uint64_t>(quic::ApplicationCloseCode::malformed)
      );
    }
    {
      TestMsQuicApi api;
      TestSessionFactory factory;
      quic::QuicServer server {api, test_config(), factory};
      connect_test_server(api, server);
      EXPECT_EQ(
        api.connection_event({
          .kind = quic::ConnectionEvent::Kind::peer_stream_started,
          .stream = 24,
          .stream_id = 4,
        }),
        quic::ApiStatus::aborted
      );
      ASSERT_EQ(api.connection_shutdowns.size(), 1U);
      EXPECT_EQ(
        api.connection_shutdowns.front().second,
        static_cast<std::uint64_t>(quic::ApplicationCloseCode::malformed)
      );
    }
  }

  TEST(ProtocolV3Security, AuthenticatedSessionlessDatagramClosesImmediately) {
    TestMsQuicApi api;
    TestSessionFactory factory {false};
    quic::QuicServer server {api, test_config(), factory};
    connect_test_server(api, server);
    authenticate_test_server(api);
    const auto record = datagram(1, 1);
    EXPECT_EQ(
      api.connection_event({
        .kind = quic::ConnectionEvent::Kind::datagram_received,
        .received_bytes = record,
      }),
      quic::ApiStatus::aborted
    );
    ASSERT_EQ(api.connection_shutdowns.size(), 1U);
    EXPECT_EQ(
      api.connection_shutdowns.front().second,
      static_cast<std::uint64_t>(quic::ApplicationCloseCode::malformed)
    );
  }

  TEST(ProtocolV3Security, AuthenticatedSessionlessBulkStreamClosesImmediately) {
    TestMsQuicApi api;
    TestSessionFactory factory {false};
    quic::QuicServer server {api, test_config(), factory};
    connect_test_server(api, server);
    authenticate_test_server(api);
    EXPECT_EQ(
      api.connection_event({
        .kind = quic::ConnectionEvent::Kind::peer_stream_started,
        .stream = 24,
        .stream_id = 4,
      }),
      quic::ApiStatus::aborted
    );
    ASSERT_EQ(api.connection_shutdowns.size(), 1U);
    EXPECT_EQ(
      api.connection_shutdowns.front().second,
      static_cast<std::uint64_t>(quic::ApplicationCloseCode::malformed)
    );
  }

  TEST(ProtocolV3Security, AuthenticatedMalformedDatagramsCloseAtAbuseThreshold) {
    TestMsQuicApi api;
    TestSessionFactory factory;
    quic::QuicServer server {api, test_config(), factory};
    connect_test_server(api, server);
    authenticate_test_server(api);
    const std::array<std::uint8_t, 1> malformed {0};
    for (std::size_t count = 1; count < quic::AbuseTracker::malformed_record_limit; ++count) {
      EXPECT_EQ(
        api.connection_event({
          .kind = quic::ConnectionEvent::Kind::datagram_received,
          .received_bytes = malformed,
        }),
        quic::ApiStatus::success
      );
    }
    EXPECT_TRUE(api.connection_shutdowns.empty());
    EXPECT_EQ(
      api.connection_event({
        .kind = quic::ConnectionEvent::Kind::datagram_received,
        .received_bytes = malformed,
      }),
      quic::ApiStatus::aborted
    );
    ASSERT_EQ(api.connection_shutdowns.size(), 1U);
    EXPECT_EQ(
      api.connection_shutdowns.front().second,
      static_cast<std::uint64_t>(quic::ApplicationCloseCode::abuse_limit)
    );
  }

  TEST(ProtocolV3Security, AuthenticatedMalformedBulkStreamsShareTheAbuseThreshold) {
    TestMsQuicApi api;
    TestSessionFactory factory;
    quic::QuicServer server {api, test_config(), factory};
    connect_test_server(api, server);
    authenticate_test_server(api);
    for (std::size_t count = 1; count < quic::AbuseTracker::malformed_record_limit; ++count) {
      EXPECT_EQ(
        api.connection_event({
          .kind = quic::ConnectionEvent::Kind::peer_stream_started,
          .stream = 24 + count,
          .stream_id = 4 * count,
        }),
        quic::ApiStatus::aborted
      );
    }
    EXPECT_TRUE(api.connection_shutdowns.empty());
    EXPECT_EQ(
      api.connection_event({
        .kind = quic::ConnectionEvent::Kind::peer_stream_started,
        .stream = 24 + quic::AbuseTracker::malformed_record_limit,
        .stream_id = 4 * quic::AbuseTracker::malformed_record_limit,
      }),
      quic::ApiStatus::aborted
    );
    ASSERT_EQ(api.connection_shutdowns.size(), 1U);
    EXPECT_EQ(
      api.connection_shutdowns.front().second,
      static_cast<std::uint64_t>(quic::ApplicationCloseCode::abuse_limit)
    );
  }

  TEST(ProtocolV3Security, AuthenticatedMalformedRecordsCloseAtTheRollingTenSecondLimit) {
    quic::AbuseTracker tracker;
    const auto start = quic::MonotonicClock::time_point {};
    for (std::size_t index = 0; index < quic::AbuseTracker::malformed_record_limit - 1; ++index) {
      EXPECT_FALSE(tracker.observe_malformed_record(start + std::chrono::milliseconds {index * 300}));
    }
    EXPECT_TRUE(tracker.observe_malformed_record(start + std::chrono::milliseconds {9'300}));

    quic::AbuseTracker expired;
    for (std::size_t index = 0; index < quic::AbuseTracker::malformed_record_limit - 1; ++index) {
      EXPECT_FALSE(expired.observe_malformed_record(start));
    }
    const auto next_window = start + quic::AbuseTracker::malformed_record_window;
    EXPECT_FALSE(expired.observe_malformed_record(next_window));
    for (std::size_t index = 1; index < quic::AbuseTracker::malformed_record_limit - 1; ++index) {
      EXPECT_FALSE(expired.observe_malformed_record(next_window));
    }
    EXPECT_TRUE(expired.observe_malformed_record(next_window));
  }

  TEST(ProtocolV3Security, InvalidDatagramRateRequiresThreeConsecutiveExcessSeconds) {
    const auto start = quic::MonotonicClock::time_point {};
    const auto fill_excess_second = [](quic::AbuseTracker &tracker, const auto timestamp) {
      bool close = false;
      for (std::uint32_t count = 0; count <= quic::AbuseTracker::invalid_datagram_rate_limit; ++count) {
        close = tracker.observe_invalid_datagram(timestamp);
      }
      return close;
    };

    quic::AbuseTracker consecutive;
    EXPECT_FALSE(fill_excess_second(consecutive, start));
    EXPECT_FALSE(fill_excess_second(consecutive, start + std::chrono::seconds {1}));
    EXPECT_TRUE(fill_excess_second(consecutive, start + std::chrono::seconds {2}));

    quic::AbuseTracker interrupted;
    EXPECT_FALSE(fill_excess_second(interrupted, start));
    EXPECT_FALSE(fill_excess_second(interrupted, start + std::chrono::seconds {1}));
    EXPECT_FALSE(fill_excess_second(interrupted, start + std::chrono::seconds {3}));
    EXPECT_FALSE(fill_excess_second(interrupted, start + std::chrono::seconds {4}));
    EXPECT_TRUE(fill_excess_second(interrupted, start + std::chrono::seconds {5}));
  }

  TEST(ProtocolV3Wire, LatencyBudgetTracksRttBitrateAndUrgentReserve) {
    EXPECT_EQ(quic::latency_video_send_budget({32, 4, 1152, 100'000, 1'000, {}, {}}), 11U);
    EXPECT_EQ(quic::latency_video_send_budget({32, 4, 1152, 100'000, 4'000, {}, {}}), 28U);
    EXPECT_EQ(quic::latency_video_send_budget({32, 4, 1152, 20'000, 1'000, {}, {}}), 3U);
    EXPECT_EQ(quic::latency_video_send_budget({32, 4, 1152, 100'000, 4'000, 8'000, 4'544}), 3U);
  }

  TEST(ProtocolV3Transport, RealCongestionSampleEmitsBoundedAuthenticatedRttTelemetry) {
    TestMsQuicApi api;
    api.congestion = quic::CongestionSample {
      .valid_fields = quic::CongestionSample::valid_rtt,
      .smoothed_rtt_microseconds = 4'000,
      .minimum_rtt_microseconds = 3'000,
    };
    TestSessionFactory factory;
    quic::QuicServer server {api, test_config(), factory};
    connect_test_server(api, server);
    authenticate_test_server(api);
    ASSERT_EQ(
      api.connection_event({
        .kind = quic::ConnectionEvent::Kind::datagram_state_changed,
        .maximum_datagram_bytes = 1'152,
        .datagram_send_enabled = true,
      }),
      quic::ApiStatus::success
    );

    auto video = std::make_shared<const std::vector<std::uint8_t>>(datagram(2, 1));
    ASSERT_EQ(
      server.enqueue(1, {
        .lane = quic::Lane::delta_video,
        .bytes = video,
        .deadline = {},
        .replaceable = true,
      }),
      quic::EnqueueResult::queued
    );
    ASSERT_EQ(api.datagram_sends.size(), 1U);
    const auto video_token = api.datagram_sends.front().token;
    ASSERT_EQ(
      api.connection_event({
        .kind = quic::ConnectionEvent::Kind::datagram_send_complete,
        .send_token = video_token,
      }),
      quic::ApiStatus::success
    );

    ASSERT_EQ(api.datagram_sends.size(), 2U);
    const auto &telemetry = api.datagram_sends.back();
    EXPECT_FALSE(telemetry.urgent);
    const auto active_session = session_id();
    const auto parsed = quic::parse_datagram_record(
      telemetry.bytes,
      quic::Direction::host_to_client,
      active_session,
      1'152
    );
    ASSERT_TRUE(parsed);
    EXPECT_EQ(parsed->channel, 5);
    EXPECT_EQ(parsed->kind, 1);
    EXPECT_EQ(parsed->sequence, 1U);
    EXPECT_EQ(parsed->object_id, 1U);
    ASSERT_EQ(parsed->payload.size(), 24U);
    EXPECT_EQ(parsed->payload[7], 1);
    EXPECT_EQ(parsed->payload[8], 0);
    EXPECT_EQ(parsed->payload[9], 0);
    EXPECT_EQ(parsed->payload[10], 0x0f);
    EXPECT_EQ(parsed->payload[11], 0xa0);
    EXPECT_EQ(parsed->payload[12], 0);
    EXPECT_EQ(parsed->payload[13], 0);
    EXPECT_EQ(parsed->payload[14], 0x0b);
    EXPECT_EQ(parsed->payload[15], 0xb8);
    EXPECT_EQ(parsed->payload[16], 0);
    EXPECT_EQ(parsed->payload[17], 0);
    EXPECT_EQ(parsed->payload[18], 0x03);
    EXPECT_EQ(parsed->payload[19], 0xe8);
    EXPECT_TRUE(std::ranges::all_of(parsed->payload.begin() + 20, parsed->payload.end(), [](const auto byte) {
      return byte == 0;
    }));
    EXPECT_EQ(
      api.connection_event({
        .kind = quic::ConnectionEvent::Kind::datagram_send_complete,
        .send_token = telemetry.token,
      }),
      quic::ApiStatus::success
    );
  }

  TEST(ProtocolV3Transport, SendSlotPoolIsBoundedReusableAndRejectsStaleCompletions) {
    quic::SendSlotPool slots {2};
    EXPECT_EQ(slots.capacity(), 2U);
    EXPECT_EQ(slots.active(), 0U);

    const auto first = slots.acquire();
    const auto second = slots.acquire();
    ASSERT_TRUE(first);
    ASSERT_TRUE(second);
    EXPECT_NE(first->index, second->index);
    EXPECT_EQ(slots.active(), 2U);
    EXPECT_FALSE(slots.acquire());

    EXPECT_EQ(slots.index(first->token), first->index);
    EXPECT_TRUE(slots.release(first->token));
    EXPECT_FALSE(slots.release(first->token));
    const auto reused = slots.acquire();
    ASSERT_TRUE(reused);
    EXPECT_EQ(reused->index, first->index);
    EXPECT_NE(reused->token, first->token);
    EXPECT_FALSE(slots.index(first->token));

    slots.clear();
    EXPECT_EQ(slots.active(), 0U);
    EXPECT_FALSE(slots.occupied(reused->index));
    EXPECT_FALSE(slots.release(reused->token));
  }

  TEST(ProtocolV3Transport, SendSlotPoolClampsCapacityWithoutDynamicGrowth) {
    quic::SendSlotPool slots {quic::SendSlotPool::maximum_capacity + 1};
    EXPECT_EQ(slots.capacity(), quic::SendSlotPool::maximum_capacity);
    for (std::size_t index = 0; index < quic::SendSlotPool::maximum_capacity; ++index) {
      ASSERT_TRUE(slots.acquire());
    }
    EXPECT_FALSE(slots.acquire());
  }
}  // namespace
