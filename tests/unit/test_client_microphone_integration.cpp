/**
 * @file tests/unit/test_client_microphone_integration.cpp
 * @brief Verify RTSP negotiation and replay seams for client microphone integration.
 */

// standard includes
#include <algorithm>
#include <array>
#include <memory>
#include <ranges>
#include <span>
#include <string_view>
#include <unordered_map>
#include <vector>

// lib includes
#include <gtest/gtest.h>

// local includes
#include <src/client_microphone.h>
#include <src/client_microphone_protocol.h>
#include <src/crypto.h>
#include <src/rtsp.h>
#include <src/stream.h>

using namespace std::literals;

namespace {
  /** Decoder seam used by the authenticated integration test. */
  class integration_decoder_t final: public client_microphone::decoder_t {
  public:
    int reset() override {
      return 0;
    }

    int decode(std::span<const std::uint8_t>, bool, std::span<std::int16_t> output) override {
      std::ranges::fill(output, 1);
      return static_cast<int>(client_microphone::SAMPLES_PER_FRAME);
    }

    int conceal(std::span<std::int16_t> output) override {
      std::ranges::fill(output, 0);
      return static_cast<int>(client_microphone::SAMPLES_PER_FRAME);
    }
  };

  /** Sink seam recording PCM frames delivered by the authenticated integration test. */
  class integration_sink_t final: public client_microphone::sink_t {
  public:
    bool begin(std::uint64_t generation, std::uint32_t, std::uint8_t) override {
      active_generation = generation;
      return true;
    }

    bool write(std::uint64_t generation, std::span<const std::int16_t> samples) override {
      if (generation != active_generation) {
        return false;
      }
      frames.emplace_back(samples.begin(), samples.end());
      return true;
    }

    void end(std::uint64_t generation) override {
      if (generation == active_generation) {
        active_generation = 0;
      }
    }

    std::uint64_t active_generation {};  ///< Generation currently accepted by the fake sink.
    std::vector<std::vector<std::int16_t>> frames;  ///< Complete PCM frames written by the receiver.
  };
}  // namespace

TEST(ClientMicrophoneIntegrationTest, AdvertisesTheExactVersionOneCapability) {
  EXPECT_EQ(
    rtsp_stream::CLIENT_MICROPHONE_DESCRIBE_ATTRIBUTES,
    "a=x-lumen-mic.version:1\r\n"
    "a=x-lumen-mic.codec:opus\r\n"
    "a=x-lumen-mic.sampleRate:48000\r\n"
    "a=x-lumen-mic.channels:1\r\n"
    "a=x-lumen-mic.packetDurationMs:20\r\n"
    "a=x-lumen-mic.crypto:aes-256-gcm\r\n"
    "a=x-lumen-mic.fec:opus-inband\r\n"sv
  );
}

TEST(ClientMicrophoneIntegrationTest, RecognizesOnlyTheVersionOneSetupTarget) {
  EXPECT_TRUE(rtsp_stream::is_client_microphone_setup_target("rtsp://host/streamid=lumen-mic/1/0"));
  EXPECT_TRUE(rtsp_stream::is_client_microphone_setup_target("streamid=lumen-mic/1/0"));
  EXPECT_FALSE(rtsp_stream::is_client_microphone_setup_target("streamid=lumen-mic/2/0"));
  EXPECT_FALSE(rtsp_stream::is_client_microphone_setup_target("streamid=audio/0/0"));
  EXPECT_FALSE(rtsp_stream::is_client_microphone_setup_target("prefixstreamid=lumen-mic/1/0"));
}

TEST(ClientMicrophoneIntegrationTest, EncodesSetupCredentialsInForwardLowercaseHex) {
  const std::array<std::uint8_t, 16> bytes {
    0x00,
    0x0F,
    0x10,
    0x2A,
    0x3B,
    0x4C,
    0x5D,
    0x6E,
    0x7F,
    0x80,
    0x91,
    0xA2,
    0xB3,
    0xC4,
    0xD5,
    0xFF,
  };

  EXPECT_EQ(rtsp_stream::encode_client_microphone_hex(bytes), "000f102a3b4c5d6e7f8091a2b3c4d5ff");
}

TEST(ClientMicrophoneIntegrationTest, RequiresEveryExactAnnounceAttribute) {
  std::unordered_map<std::string_view, std::string_view> attributes {
    {"x-lumen-mic.enabled", "1"},
    {"x-lumen-mic.version", "1"},
    {"x-lumen-mic.codec", "opus"},
    {"x-lumen-mic.sampleRate", "48000"},
    {"x-lumen-mic.channels", "1"},
    {"x-lumen-mic.packetDurationMs", "20"},
    {"x-lumen-mic.fec", "opus-inband"},
  };

  EXPECT_TRUE(rtsp_stream::validate_client_microphone_announce(attributes));

  auto extended = attributes;
  extended.emplace("x-lumen-mic.unsupported", "1");
  EXPECT_FALSE(rtsp_stream::validate_client_microphone_announce(extended));

  for (const auto &[name, value] : attributes) {
    auto incomplete = attributes;
    incomplete.erase(name);
    EXPECT_FALSE(rtsp_stream::validate_client_microphone_announce(incomplete)) << name;

    auto changed = attributes;
    changed[name] = "unsupported";
    EXPECT_FALSE(rtsp_stream::validate_client_microphone_announce(changed)) << name;
  }
}

TEST(ClientMicrophoneIntegrationTest, ReplayWindowCommitsOnlyExplicitlyAuthenticatedSequences) {
  stream::microphone_replay_window_t replay;

  EXPECT_TRUE(replay.may_accept(10));
  EXPECT_TRUE(replay.may_accept(10));

  replay.commit(10);
  EXPECT_FALSE(replay.may_accept(10));
  EXPECT_TRUE(replay.may_accept(9));
  EXPECT_TRUE(replay.may_accept(11));
  EXPECT_FALSE(replay.would_advance(9));
  EXPECT_FALSE(replay.would_advance(10));
  EXPECT_TRUE(replay.would_advance(11));
}

TEST(ClientMicrophoneIntegrationTest, ReplayWindowSupportsReorderingAndRejectsOldPackets) {
  stream::microphone_replay_window_t replay;
  replay.commit(200);
  replay.commit(198);

  EXPECT_FALSE(replay.may_accept(200));
  EXPECT_FALSE(replay.may_accept(198));
  EXPECT_TRUE(replay.may_accept(199));
  EXPECT_TRUE(replay.may_accept(73));
  EXPECT_FALSE(replay.may_accept(72));

  replay.commit(400);
  EXPECT_FALSE(replay.may_accept(272));
  EXPECT_TRUE(replay.may_accept(400 + 1));

  replay.reset();
  EXPECT_TRUE(replay.may_accept(200));
}

TEST(ClientMicrophoneIntegrationTest, AuthenticatedHelloClaimsAndAuthenticatedTrafficRebinds) {
  stream::microphone_endpoint_tracker_t endpoints;
  const boost::asio::ip::udp::endpoint first {
    boost::asio::ip::make_address("192.0.2.10"),
    45000
  };
  const boost::asio::ip::udp::endpoint rebound {
    boost::asio::ip::make_address("192.0.2.10"),
    46000
  };

  // The caller invokes this seam only after successful authentication. A media
  // packet cannot claim an endpoint even when it otherwise has valid framing.
  EXPECT_FALSE(endpoints.accept_authenticated(first, false));
  EXPECT_FALSE(endpoints.claimed());

  EXPECT_TRUE(endpoints.accept_authenticated(first, true));
  EXPECT_TRUE(endpoints.claimed());
  EXPECT_EQ(endpoints.endpoint(), first);

  EXPECT_TRUE(endpoints.accept_authenticated(rebound, false));
  EXPECT_EQ(endpoints.endpoint(), rebound);

  endpoints.reset();
  EXPECT_FALSE(endpoints.claimed());
}

TEST(ClientMicrophoneIntegrationTest, RoutesByAllSixteenSessionIdentifierBytes) {
  std::array<std::uint8_t, 16> first {};
  std::array<std::uint8_t, 16> second {};
  first.front() = 0x41;
  second.front() = 0x41;
  first.back() = 0x01;
  second.back() = 0x02;

  const auto first_key = stream::client_microphone_route_key(first);
  const auto second_key = stream::client_microphone_route_key(second);
  EXPECT_EQ(first_key.size(), 16U);
  EXPECT_EQ(second_key.size(), 16U);
  EXPECT_NE(first_key, second_key);
  EXPECT_EQ(first_key[1], '\0');
}

TEST(ClientMicrophoneIntegrationTest, AllowsOnlyOneMicrophoneOwner) {
  constexpr std::uint32_t first_session = 0x1001;
  constexpr std::uint32_t second_session = 0x1002;

  ASSERT_TRUE(stream::session::claim_client_microphone(first_session));
  EXPECT_TRUE(stream::session::claim_client_microphone(first_session));
  EXPECT_FALSE(stream::session::claim_client_microphone(second_session));

  stream::session::release_client_microphone(second_session);
  EXPECT_FALSE(stream::session::claim_client_microphone(second_session));

  stream::session::release_client_microphone(first_session);
  EXPECT_TRUE(stream::session::claim_client_microphone(second_session));
  stream::session::release_client_microphone(second_session);
}

TEST(ClientMicrophoneIntegrationTest, AuthenticatesAndDeliversSilenceThroughTheCompleteMediaCore) {
  const std::array<std::uint8_t, 16> rikey {
    0x00,
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
    0x09,
    0x0A,
    0x0B,
    0x0C,
    0x0D,
    0x0E,
    0x0F,
  };
  const std::array<std::uint8_t, 16> salt {
    0x10,
    0x11,
    0x12,
    0x13,
    0x14,
    0x15,
    0x16,
    0x17,
    0x18,
    0x19,
    0x1A,
    0x1B,
    0x1C,
    0x1D,
    0x1E,
    0x1F,
  };
  const std::array<std::uint8_t, 16> session_id {
    0x20,
    0x21,
    0x22,
    0x23,
    0x24,
    0x25,
    0x26,
    0x27,
    0x28,
    0x29,
    0x2A,
    0x2B,
    0x2C,
    0x2D,
    0x2E,
    0x2F,
  };
  constexpr auto key_info = "lumen/client-microphone/client-to-host/v1"sv;
  const auto derived = crypto::hkdf_sha256(rikey, salt, key_info, crypto::aes_256_gcm_t::key_size + 4);
  ASSERT_TRUE(derived);

  crypto::aes_256_gcm_t::key_t key {};
  std::array<std::uint8_t, 4> nonce_prefix {};
  std::copy_n(derived->begin(), key.size(), key.begin());
  std::copy_n(derived->begin() + key.size(), nonce_prefix.size(), nonce_prefix.begin());
  crypto::aes_256_gcm_t cipher {key};

  auto make_datagram = [&](client_microphone::protocol::packet_type_t type, std::uint8_t flags, std::uint64_t sequence, std::uint32_t timestamp) {
    client_microphone::protocol::packet_t packet;
    packet.type = type;
    packet.flags = flags;
    packet.session_id = session_id;
    packet.packet_sequence = sequence;
    packet.timestamp_48khz = timestamp;

    const auto provisional = client_microphone::protocol::serialize(packet);
    EXPECT_TRUE(provisional);
    const auto framed = client_microphone::protocol::parse(*provisional);
    EXPECT_TRUE(framed);

    crypto::aes_256_gcm_t::nonce_t nonce {};
    std::copy(nonce_prefix.begin(), nonce_prefix.end(), nonce.begin());
    for (std::size_t index = 0; index < sizeof(sequence); ++index) {
      nonce[nonce_prefix.size() + index] = static_cast<std::uint8_t>(sequence >> ((7U - index) * 8U));
    }
    EXPECT_TRUE(cipher.encrypt({}, framed->authenticated_header, nonce, packet.ciphertext, packet.authentication_tag));
    return client_microphone::protocol::serialize(packet);
  };

  stream::microphone_replay_window_t replay;
  stream::microphone_endpoint_tracker_t endpoints;
  integration_sink_t sink;
  client_microphone::receiver_t receiver {std::make_unique<integration_decoder_t>(), sink};
  const auto now = client_microphone::clock_t::now();
  const boost::asio::ip::udp::endpoint peer {boost::asio::ip::make_address("192.0.2.50"), 48000};

  const auto hello_bytes = make_datagram(client_microphone::protocol::packet_type_t::hello, 0, 0, 0);
  ASSERT_TRUE(hello_bytes);
  const auto hello = client_microphone::protocol::parse(*hello_bytes);
  ASSERT_TRUE(hello);
  crypto::aes_t hello_plaintext;
  crypto::aes_256_gcm_t::nonce_t hello_nonce {};
  std::copy(nonce_prefix.begin(), nonce_prefix.end(), hello_nonce.begin());
  ASSERT_TRUE(cipher.decrypt(
    hello->ciphertext,
    hello->authenticated_header,
    hello_nonce,
    hello->authentication_tag,
    hello_plaintext
  ));
  ASSERT_TRUE(replay.may_accept(hello->packet_sequence));
  ASSERT_TRUE(endpoints.accept_authenticated(peer, true));
  replay.commit(hello->packet_sequence);
  ASSERT_TRUE(receiver.reset(1, now));

  const auto silence_bytes = make_datagram(
    client_microphone::protocol::packet_type_t::audio,
    client_microphone::protocol::flag_silence,
    1,
    0
  );
  ASSERT_TRUE(silence_bytes);
  const auto silence = client_microphone::protocol::parse(*silence_bytes);
  ASSERT_TRUE(silence);
  crypto::aes_256_gcm_t::nonce_t silence_nonce {};
  std::copy(nonce_prefix.begin(), nonce_prefix.end(), silence_nonce.begin());
  silence_nonce.back() = 1;
  crypto::aes_t silence_plaintext;
  ASSERT_TRUE(cipher.decrypt(
    silence->ciphertext,
    silence->authenticated_header,
    silence_nonce,
    silence->authentication_tag,
    silence_plaintext
  ));
  replay.commit(silence->packet_sequence);
  EXPECT_EQ(
    receiver.submit(
      {1, silence->packet_sequence, silence->timestamp_48khz, client_microphone::packet_kind_e::silence, {}},
      now
    ),
    client_microphone::submit_result_e::accepted
  );
  EXPECT_EQ(receiver.poll(now + client_microphone::JITTER_WINDOW), 1U);
  ASSERT_EQ(sink.frames.size(), 1U);
  EXPECT_TRUE(std::ranges::all_of(sink.frames.front(), [](std::int16_t sample) {
    return sample == 0;
  }));
}
