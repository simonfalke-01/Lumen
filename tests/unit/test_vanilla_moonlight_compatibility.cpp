/**
 * @file tests/unit/test_vanilla_moonlight_compatibility.cpp
 * @brief Pinned Moonlight Qt/common-c compatibility transcript tests.
 */

#include "../tests_common.h"

#include <array>
#include <atomic>
#include <boost/asio.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <nlohmann/json.hpp>
#include <Simple-Web-Server/client_http.hpp>
#include <Simple-Web-Server/server_http.hpp>
#include <Simple-Web-Server/utility.hpp>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>

extern "C" {
#include <moonlight-common-c/src/Rtsp.h>
}

#include "src/config.h"
#include "src/httpcommon.h"
#include "src/network.h"
#include "src/nvhttp.h"
#include "src/process.h"
#include "src/protocol_v3/control_session.h"
#include "src/rtsp.h"
#include "src/stream_policy.h"
#include "src/utility.h"

using namespace std::literals;

// These are production functions with external linkage that are deliberately
// internal to nvhttp.cpp/rtsp.cpp. Forward declarations keep compatibility
// tests on the exact production paths without adding a production test seam.
namespace nvhttp {
  using args_t = SimpleWeb::CaseInsensitiveMultimap;
  std::shared_ptr<rtsp_stream::launch_session_t> make_launch_session(
    bool host_audio,
    const args_t &args,
    std::string client_certificate
  );
  bool resume_should_prepare_display_after_reservation(int active_sessions);
  bool load_committed_host_audio(const std::atomic_bool &committed_host_audio);
  void commit_host_audio(std::atomic_bool &committed_host_audio, bool candidate);
  bool resolve_resume_host_audio_candidate(
    const std::atomic_bool &committed_host_audio,
    std::optional<bool> requested_host_audio,
    int active_sessions
  );
  void rollback_launch_reservation_transaction(
    const std::shared_ptr<rtsp_stream::launch_session_t> &launch_session,
    const std::function<void()> &process_cleanup,
    const std::function<void()> &display_cleanup
  );
  template<class T>
  void serverinfo(
    std::shared_ptr<typename SimpleWeb::ServerBase<T>::Response> response,
    std::shared_ptr<typename SimpleWeb::ServerBase<T>::Request> request
  );
}  // namespace nvhttp

namespace rtsp_stream {
  void free_msg(PRTSP_MESSAGE msg);
  using msg_t = util::safe_ptr<RTSP_MESSAGE, free_msg>;
  class rtsp_server_t;
  void cmd_option(rtsp_server_t *, boost::asio::ip::tcp::socket &, launch_session_t &, msg_t &&);
  void cmd_describe(rtsp_server_t *, boost::asio::ip::tcp::socket &, launch_session_t &, msg_t &&);
  void cmd_setup(rtsp_server_t *, boost::asio::ip::tcp::socket &, launch_session_t &, msg_t &&);
  void cmd_announce(rtsp_server_t *, boost::asio::ip::tcp::socket &, launch_session_t &, msg_t &&);
  void cmd_play(rtsp_server_t *, boost::asio::ip::tcp::socket &, launch_session_t &, msg_t &&);
  std::string encrypt_rtsp_request_for_tests(
    const crypto::aes_t &key,
    std::uint32_t sequence,
    std::string_view plaintext
  );
  decrypted_rtsp_response_t decrypt_rtsp_response_for_tests(
    const crypto::aes_t &key,
    std::string_view message
  );
  std::vector<std::string> exchange_preannounce_requests_for_tests(
    std::shared_ptr<launch_session_t> launch_session,
    const std::vector<std::string> &requests,
    const std::vector<std::string> &source_addresses = {},
    std::vector<int> *active_counts = nullptr,
    const std::vector<listener_lifecycle_action_e> &actions = {},
    const std::shared_ptr<launch_session_t> &replacement_launch = {},
    std::vector<bool> *action_results = nullptr
  );
}  // namespace rtsp_stream

namespace {
  using boost::asio::ip::tcp;

  const nlohmann::json &official_fixture() {
    static const auto fixture = [] {
      const auto path = std::filesystem::path {SUNSHINE_SOURCE_DIR} /
                        "tests/fixtures/vanilla_moonlight_qt_d2f6990.json";
      std::ifstream input {path};
      if (!input) {
        throw std::runtime_error("Unable to open pinned Moonlight compatibility fixture: " + path.string());
      }
      return nlohmann::json::parse(input);
    }();
    return fixture;
  }

  std::string announce_payload() {
    const auto &rtsp = official_fixture().at("rtsp");
    std::ostringstream payload;
    payload << "v=0\r\n"
            << "o=android 0 " << rtsp.at("clientVersion").get<int>() << " IN IPv4 127.0.0.1\r\n"
            << "s=NVIDIA Streaming Client\r\n";
    for (const auto &[name, value] : rtsp.at("announceAttributes").items()) {
      payload << "a=" << name << ':' << value.get<std::string>() << " \r\n";
    }
    payload << "t=0 0\r\n"
            << "m=video 47998  \r\n";
    return payload.str();
  }

  std::string request_text(
    std::string_view method,
    std::string_view target,
    int cseq,
    std::string_view extra_headers = {},
    std::string_view payload = {}
  ) {
    std::ostringstream request;
    request << method << ' ' << target << " RTSP/1.0\r\n"
            << "CSeq: " << cseq << "\r\n"
            << "X-GS-ClientVersion: 14\r\n"
            << "Host: 127.0.0.1\r\n"
            << extra_headers;
    if (!payload.empty()) {
      request << "Content-type: application/sdp\r\n"
              << "Content-length: " << payload.size() << "\r\n";
    }
    request << "\r\n"
            << payload;
    return request.str();
  }

  rtsp_stream::msg_t parse_request(const std::string &wire) {
    auto request = rtsp_stream::msg_t {new RTSP_MESSAGE {}};
    auto mutable_wire = wire;
    if (parseRtspMessage(request.get(), mutable_wire.data(), static_cast<int>(mutable_wire.size())) != RTSP_ERROR_SUCCESS) {
      return {};
    }
    return request;
  }

  class ConnectedSockets {
  public:
    ConnectedSockets():
        acceptor_(io_, {tcp::v4(), 0}),
        client_(io_),
        server_(io_) {
      client_.connect({boost::asio::ip::address_v4::loopback(), acceptor_.local_endpoint().port()});
      acceptor_.accept(server_);
    }

    tcp::socket &server() {
      return server_;
    }

    std::string read_response() {
      boost::asio::streambuf buffer;
      boost::asio::read_until(client_, buffer, "\r\n\r\n");
      auto response = std::string {boost::asio::buffers_begin(buffer.data()), boost::asio::buffers_end(buffer.data())};
      const auto header_end = response.find("\r\n\r\n");
      const auto length_header = response.find("Content-length: ");
      if (length_header != std::string::npos) {
        const auto length_begin = length_header + std::string_view {"Content-length: "}.size();
        const auto length_end = response.find("\r\n", length_begin);
        const auto content_length = static_cast<std::size_t>(std::stoul(response.substr(length_begin, length_end - length_begin)));
        const auto required_size = header_end + 4U + content_length;
        if (response.size() < required_size) {
          boost::asio::read(client_, buffer, boost::asio::transfer_exactly(required_size - response.size()));
          response = {boost::asio::buffers_begin(buffer.data()), boost::asio::buffers_end(buffer.data())};
        }
      }
      bool read_payload = false;
      for (int attempt = 0; attempt < 100; ++attempt) {
        boost::system::error_code error;
        const auto available = client_.available(error);
        if (error) {
          break;
        }
        if (available == 0) {
          if (read_payload || attempt >= 10) {
            break;
          }
          std::this_thread::sleep_for(std::chrono::milliseconds {1});
          continue;
        }
        std::string payload(available, '\0');
        const auto read = client_.read_some(boost::asio::buffer(payload), error);
        if (error) {
          break;
        }
        payload.resize(read);
        response += payload;
        read_payload = true;
      }
      return response;
    }

  private:
    boost::asio::io_context io_;
    tcp::acceptor acceptor_;
    tcp::socket client_;
    tcp::socket server_;
  };

  rtsp_stream::launch_session_t legacy_session() {
    rtsp_stream::launch_session_t session {};
    session.id = 71;
    session.av_ping_payload = "0011223344556677";
    session.control_connect_data = 305419896;
    return session;
  }

  boost::property_tree::ptree parse_xml(std::string_view xml) {
    boost::property_tree::ptree tree;
    std::istringstream input {std::string {xml}};
    boost::property_tree::read_xml(input, tree);
    return tree;
  }
}  // namespace

TEST(VanillaMoonlightCompatibility, FixturePinsTheApprovedOfficialSources) {
  const auto &provenance = official_fixture().at("provenance");
  EXPECT_EQ(provenance.at("moonlightQtCommit"), "d2f6990be699197385a6458e1231d070da83e665");
  EXPECT_EQ(provenance.at("moonlightCommonCommit"), "874ac9548f1bd6f095ef2b435c42cdde460e7821");
  EXPECT_EQ(provenance.at("generator"), "moonlight-qt-source-derived-v1");
  EXPECT_EQ(provenance.at("lineEndings"), "CRLF");
  const auto &sources = provenance.at("sourceFiles");
  EXPECT_EQ(sources.at("app/backend/identitymanager.cpp"), "81cc5e276635524e65d4cf26887c6052e5e19a2cbb200f68202f2bc26c7e8c52");
  EXPECT_EQ(sources.at("app/backend/nvhttp.cpp"), "3ea8beeee68a38b8f189522275181d2cc9960de55505667c4c0003816ee0ad35");
  EXPECT_EQ(sources.at("app/backend/nvpairingmanager.cpp"), "e0ce6136d0b2133e1fe5282dbe7a262ac7094893572ebe4d9e225c2b9f1de6ae");
  EXPECT_EQ(sources.at("moonlight-common-c/moonlight-common-c/src/RtspConnection.c"), "44cfd110f637c64c1108a10e1c0efbc4dd2c938613979a645a61346d1979e75f");
  EXPECT_EQ(sources.at("moonlight-common-c/moonlight-common-c/src/SdpGenerator.c"), "c0ef395dd701b9f30defc9ae94ba2333c0cf7cdaa7108f7fb1b9300241f1a6aa");
}

TEST(VanillaMoonlightCompatibility, OfficialUniqueIdsRemainValidWithoutARequestId) {
  const auto unique_id = official_fixture().at("http").at("uniqueId").get<std::string>();
  EXPECT_TRUE(nvhttp::is_valid_pairing_unique_id(unique_id));

  nvhttp::pairing_session_manager_t manager;
  nvhttp::pair_session_t session;
  session.client.uniqueID = unique_id;
  session.async_insert_pin.salt = "00112233445566778899aabbccddeeff";
  const auto added = manager.add(std::move(session), "192.0.2.1");
  EXPECT_TRUE(added);
  EXPECT_EQ(added.request_id.size(), nvhttp::PAIRING_REQUEST_ID_HEX_BYTES);
}

TEST(VanillaMoonlightCompatibility, DiscoveryServerInfoRemainsAParseableLegacyResponse) {
  const auto saved_name = config::nvhttp.sunshine_name;
  const auto saved_unique_id = http::unique_id;
  config::nvhttp.sunshine_name = "Lumen Compatibility Host";
  http::unique_id = "00112233-4455-6677-8899-aabbccddeeff";
  auto restore = util::fail_guard([&]() {
    config::nvhttp.sunshine_name = saved_name;
    http::unique_id = saved_unique_id;
  });

  SimpleWeb::Server<SimpleWeb::HTTP> server;
  server.config.port = 0;
  server.config.address = "127.0.0.1";
  server.config.reuse_address = true;
  server.resource["^/serverinfo$"]["GET"] = nvhttp::serverinfo<SimpleWeb::HTTP>;
  std::atomic<unsigned short> port {};
  std::jthread server_thread {[&]() {
    server.start([&](const unsigned short assigned_port) {
      port.store(assigned_port, std::memory_order_release);
    });
  }};
  auto stop_server = util::fail_guard([&]() {
    server.stop();
  });
  for (int attempt = 0; attempt < 100 && port.load(std::memory_order_acquire) == 0; ++attempt) {
    std::this_thread::sleep_for(std::chrono::milliseconds {10});
  }
  ASSERT_NE(port.load(std::memory_order_acquire), 0);

  SimpleWeb::Client<SimpleWeb::HTTP> client {
    "127.0.0.1:" + std::to_string(port.load(std::memory_order_acquire))
  };
  client.config.timeout = 5;
  const auto response = client.request("GET", "/serverinfo?uniqueid=0123456789abcdef");
  ASSERT_EQ(response->status_code, "200 OK");
  const auto body = response->content.string();
  EXPECT_NE(body.find("<hostname>Lumen Compatibility Host</hostname>"), std::string::npos);
  EXPECT_NE(body.find("<appversion>7.1.431.-1</appversion>"), std::string::npos);
  EXPECT_NE(body.find("<GfeVersion>3.23.0.74</GfeVersion>"), std::string::npos);
  EXPECT_NE(body.find("<uniqueid>00112233-4455-6677-8899-aabbccddeeff</uniqueid>"), std::string::npos);
  EXPECT_NE(body.find("<PairStatus>0</PairStatus>"), std::string::npos);
  EXPECT_NE(body.find("<mac>00:00:00:00:00:00</mac>"), std::string::npos);
  EXPECT_EQ(body.find("x-lumen-"), std::string::npos);
  EXPECT_EQ(body.find("lumen/2"), std::string::npos);
}

TEST(VanillaMoonlightCompatibility, OfficialLaunchArgumentsMapToTheLegacySessionExactly) {
  nvhttp::args_t args;
  for (const auto &[name, value] : official_fixture().at("http").at("launchArguments").items()) {
    args.emplace(name, value.get<std::string>());
  }

  const auto session = nvhttp::make_launch_session(false, args, "client-certificate-a");
  ASSERT_TRUE(session);
  EXPECT_EQ(session->unique_id, "0123456789ABCDEF");
  EXPECT_EQ(session->appid, 881);
  EXPECT_EQ(session->width, 2560);
  EXPECT_EQ(session->height, 1440);
  EXPECT_EQ(session->fps, 120);
  EXPECT_EQ(session->gcmap, 5);
  EXPECT_EQ(session->surround_info, 196610);
  EXPECT_FALSE(session->host_audio);
  EXPECT_TRUE(session->enable_hdr);
  EXPECT_TRUE(session->enable_sops);
  EXPECT_TRUE(session->rtsp_cipher.has_value());
  EXPECT_EQ(session->rtsp_url_scheme, "rtspenc://");
  EXPECT_EQ(session->client_cert, "client-certificate-a");
  ASSERT_EQ(session->gcm_key.size(), 16U);
  for (std::size_t index = 0; index < session->gcm_key.size(); ++index) {
    EXPECT_EQ(session->gcm_key[index], index);
  }
  ASSERT_EQ(session->iv.size(), 16U);
  EXPECT_EQ(std::vector<std::uint8_t>(session->iv.begin(), session->iv.begin() + 4), (std::vector<std::uint8_t> {1, 2, 3, 4}));
}

TEST(VanillaMoonlightCompatibility, InterleavedTlsConnectionsKeepExactLaunchOwners) {
  boost::asio::io_context io;
  boost::asio::ssl::context tls_context {boost::asio::ssl::context::tls_client};
  nvhttp::SunshineHTTPS first_connection {io, tls_context};
  nvhttp::SunshineHTTPS second_connection {io, tls_context};
  first_connection.bind_verified_client_certificate("certificate-a");
  second_connection.bind_verified_client_certificate("certificate-b");

  nvhttp::args_t args;
  for (const auto &[name, value] : official_fixture().at("http").at("launchArguments").items()) {
    args.emplace(name, value.get<std::string>());
  }
  const auto first = nvhttp::make_launch_session(false, args, first_connection.verified_client_certificate());
  const auto second = nvhttp::make_launch_session(false, args, second_connection.verified_client_certificate());
  const auto first_again = nvhttp::make_launch_session(false, args, first_connection.verified_client_certificate());
  ASSERT_TRUE(first);
  ASSERT_TRUE(second);
  ASSERT_TRUE(first_again);
  EXPECT_EQ(first->client_cert, "certificate-a");
  EXPECT_EQ(second->client_cert, "certificate-b");
  EXPECT_EQ(first_again->client_cert, "certificate-a");
}

TEST(VanillaMoonlightCompatibility, OwnerScopedCancelCannotClearAnotherPendingLaunch) {
  auto pending = std::make_shared<rtsp_stream::launch_session_t>();
  pending->id = 0xCA11;
  pending->client_cert = "certificate-a";
  rtsp_stream::launch_session_raise(pending);

  EXPECT_EQ(rtsp_stream::terminate_sessions_by_cert("certificate-b"), 0U);
  EXPECT_EQ(rtsp_stream::terminate_sessions_by_cert("certificate-a"), 1U);
  EXPECT_EQ(rtsp_stream::terminate_sessions_by_cert(""), 0U);
}

TEST(VanillaMoonlightCompatibility, IdleOwnerCancelClearsStaleDesktopAndServerInfoState) {
  constexpr auto owner_certificate = "certificate-a"sv;
  constexpr auto other_certificate = "certificate-b"sv;
  static_cast<void>(rtsp_stream::terminate_sessions_by_cert(owner_certificate));
  static_cast<void>(rtsp_stream::terminate_sessions_by_cert(other_certificate));
  proc::proc.terminate();
  auto saved_process = std::move(proc::proc);
  auto restore = util::fail_guard([&]() {
    static_cast<void>(rtsp_stream::terminate_sessions_by_cert(owner_certificate));
    static_cast<void>(rtsp_stream::terminate_sessions_by_cert(other_certificate));
    proc::proc.terminate();
    proc::proc = std::move(saved_process);
  });

  boost::process::v1::environment env {boost::this_process::environment()};
  proc::ctx_t desktop {};
  desktop.name = "Desktop";
  desktop.id = "881";
  desktop.exit_timeout = std::chrono::seconds {0};
  std::vector<proc::ctx_t> apps;
  apps.emplace_back(std::move(desktop));
  proc::proc = proc::proc_t {std::move(env), std::move(apps)};

  auto launch = std::make_shared<rtsp_stream::launch_session_t>();
  launch->client_cert = owner_certificate;
  ASSERT_EQ(proc::proc.execute(881, launch), 0);
  auto state = parse_xml(nvhttp::legacy_server_state_xml_for_tests());
  EXPECT_EQ(state.get<int>("root.currentgame"), 881);
  EXPECT_EQ(state.get<std::string>("root.state"), "SUNSHINE_SERVER_BUSY");

  EXPECT_FALSE(nvhttp::cancel_process_for_client_if_idle(other_certificate));
  EXPECT_EQ(proc::proc.running(), 881);

  auto pending = std::make_shared<rtsp_stream::launch_session_t>();
  pending->id = 0xCA12;
  pending->client_cert = other_certificate;
  rtsp_stream::launch_session_raise(pending);
  EXPECT_FALSE(nvhttp::cancel_process_for_client_if_idle(owner_certificate));
  EXPECT_EQ(proc::proc.running(), 881);
  EXPECT_EQ(rtsp_stream::terminate_sessions_by_cert(other_certificate), 1U);

  EXPECT_TRUE(nvhttp::cancel_process_for_client_if_idle(owner_certificate));
  state = parse_xml(nvhttp::legacy_server_state_xml_for_tests());
  EXPECT_EQ(state.get<int>("root.currentgame"), 0);
  EXPECT_EQ(state.get<std::string>("root.state"), "SUNSHINE_SERVER_FREE");
}

TEST(VanillaMoonlightCompatibility, PendingLaunchTimeoutPreservesOtherClientAndReleasesOwnerDesktop) {
  constexpr auto owner_certificate = "certificate-a"sv;
  constexpr auto other_certificate = "certificate-b"sv;
  rtsp_stream::terminate_sessions();
  proc::proc.terminate();
  auto saved_process = std::move(proc::proc);
  auto restore = util::fail_guard([&]() {
    rtsp_stream::terminate_sessions();
    rtsp_stream::reset_idle_display_revert_count_for_tests();
    proc::proc.terminate();
    proc::proc = std::move(saved_process);
  });

  boost::process::v1::environment env {boost::this_process::environment()};
  proc::ctx_t desktop {};
  desktop.name = "Desktop";
  desktop.id = "881";
  desktop.exit_timeout = std::chrono::seconds {0};
  std::vector<proc::ctx_t> apps;
  apps.emplace_back(std::move(desktop));
  proc::proc = proc::proc_t {std::move(env), std::move(apps)};
  rtsp_stream::reset_idle_display_revert_count_for_tests();

  auto launch = std::make_shared<rtsp_stream::launch_session_t>();
  launch->client_cert = owner_certificate;
  ASSERT_EQ(proc::proc.execute(881, launch), 0);

  auto other_pending = std::make_shared<rtsp_stream::launch_session_t>();
  other_pending->id = 0xCA14;
  other_pending->client_cert = other_certificate;
  other_pending->process_generation = launch->process_generation;
  rtsp_stream::launch_session_raise(other_pending);
  EXPECT_TRUE(rtsp_stream::expire_pending_launch_for_tests());
  EXPECT_EQ(proc::proc.running(), 881);
  EXPECT_FALSE(rtsp_stream::has_session_or_pending_launch());
  EXPECT_EQ(rtsp_stream::idle_display_revert_count_for_tests(), 0U);

  auto owner_pending = std::make_shared<rtsp_stream::launch_session_t>();
  owner_pending->id = 0xCA15;
  owner_pending->client_cert = owner_certificate;
  owner_pending->process_generation = launch->process_generation;
  rtsp_stream::launch_session_raise(owner_pending);
  EXPECT_TRUE(rtsp_stream::expire_pending_launch_for_tests());
  EXPECT_EQ(proc::proc.running(), 0);
  EXPECT_FALSE(rtsp_stream::has_session_or_pending_launch());
  EXPECT_EQ(rtsp_stream::idle_display_revert_count_for_tests(), 1U);

  auto no_process_pending = std::make_shared<rtsp_stream::launch_session_t>();
  no_process_pending->id = 0xCA16;
  no_process_pending->client_cert = owner_certificate;
  no_process_pending->process_generation = proc::proc.generation();
  rtsp_stream::launch_session_raise(no_process_pending);
  EXPECT_TRUE(rtsp_stream::expire_pending_launch_for_tests());
  EXPECT_EQ(rtsp_stream::idle_display_revert_count_for_tests(), 2U);
  EXPECT_FALSE(rtsp_stream::expire_pending_launch_for_tests());

  const auto state = parse_xml(nvhttp::legacy_server_state_xml_for_tests());
  EXPECT_EQ(state.get<int>("root.currentgame"), 0);
  EXPECT_EQ(state.get<std::string>("root.state"), "SUNSHINE_SERVER_FREE");
}

TEST(VanillaMoonlightCompatibility, ClaimedHandshakeCannotPublishAfterOwnerCancel) {
  constexpr auto owner_certificate = "certificate-a"sv;
  rtsp_stream::terminate_sessions();
  auto restore = util::fail_guard([&]() {
    rtsp_stream::terminate_sessions();
    rtsp_stream::reset_idle_display_revert_count_for_tests();
  });
  ASSERT_EQ(proc::proc.running(), 0);
  rtsp_stream::reset_idle_display_revert_count_for_tests();

  auto pending = std::make_shared<rtsp_stream::launch_session_t>();
  pending->id = 0xCA17;
  pending->client_cert = owner_certificate;
  pending->process_generation = proc::proc.generation();
  rtsp_stream::launch_session_raise(pending);
  const auto claimed = rtsp_stream::claim_pending_launch_for_tests();
  ASSERT_EQ(claimed, pending);
  ASSERT_TRUE(rtsp_stream::claimed_launch_publishable_for_tests(claimed));

  EXPECT_EQ(nvhttp::cancel_sessions_and_process_for_client(owner_certificate), 1U);
  EXPECT_FALSE(rtsp_stream::claimed_launch_publishable_for_tests(claimed));
  EXPECT_FALSE(rtsp_stream::has_session_or_pending_launch());
  EXPECT_EQ(rtsp_stream::idle_display_revert_count_for_tests(), 1U);
}

TEST(VanillaMoonlightCompatibility, StaleTimeoutCannotRemoveReplacementPendingLaunch) {
  rtsp_stream::terminate_sessions();
  auto restore = util::fail_guard([&]() {
    rtsp_stream::terminate_sessions();
  });

  auto first = std::make_shared<rtsp_stream::launch_session_t>();
  first->id = 0xCA18;
  first->client_cert = "certificate-a";
  first->process_generation = proc::proc.generation();
  rtsp_stream::launch_session_raise(first);
  const auto stale_generation = rtsp_stream::pending_launch_generation_for_tests();
  ASSERT_NE(stale_generation, 0U);
  EXPECT_EQ(rtsp_stream::terminate_sessions_by_cert("certificate-a"), 1U);

  auto replacement = std::make_shared<rtsp_stream::launch_session_t>();
  replacement->id = first->id;
  replacement->client_cert = "certificate-b";
  replacement->process_generation = proc::proc.generation();
  rtsp_stream::launch_session_raise(replacement);
  const auto replacement_generation = rtsp_stream::pending_launch_generation_for_tests();
  ASSERT_GT(replacement_generation, stale_generation);

  rtsp_stream::launch_session_clear(first->id, stale_generation);
  EXPECT_EQ(rtsp_stream::pending_launch_generation_for_tests(), replacement_generation);
  EXPECT_FALSE(rtsp_stream::expire_pending_launch_generation_for_tests(stale_generation));
  EXPECT_EQ(rtsp_stream::pending_launch_generation_for_tests(), replacement_generation);
  EXPECT_TRUE(rtsp_stream::has_session_or_pending_launch());
  EXPECT_EQ(rtsp_stream::terminate_sessions_by_cert("certificate-b"), 1U);
}

TEST(VanillaMoonlightCompatibility, PendingLaunchClaimsRemainGenerationQualifiedAfterCancelAndReplacement) {
  constexpr auto first_owner = "repeatable-rtsp-owner-a"sv;
  constexpr auto replacement_owner = "repeatable-rtsp-owner-b"sv;
  rtsp_stream::terminate_sessions();
  auto restore = util::fail_guard([&]() {
    rtsp_stream::terminate_sessions();
  });

  auto first = std::make_shared<rtsp_stream::launch_session_t>();
  first->id = 0xCA19;
  first->client_cert = first_owner;
  first->process_generation = proc::proc.generation();
  rtsp_stream::launch_session_raise(first);

  const auto options_claim = rtsp_stream::claim_pending_launch_for_tests();
  const auto describe_claim = rtsp_stream::claim_pending_launch_for_tests();
  ASSERT_EQ(options_claim, first);
  ASSERT_EQ(describe_claim, first);
  EXPECT_TRUE(rtsp_stream::claimed_launch_publishable_for_tests(options_claim));
  EXPECT_TRUE(rtsp_stream::claimed_launch_publishable_for_tests(describe_claim));

  ASSERT_EQ(rtsp_stream::terminate_sessions_by_cert(first_owner), 1U);
  EXPECT_FALSE(rtsp_stream::claimed_launch_publishable_for_tests(options_claim));
  EXPECT_FALSE(rtsp_stream::claimed_launch_publishable_for_tests(describe_claim));

  auto replacement = std::make_shared<rtsp_stream::launch_session_t>();
  replacement->id = first->id;
  replacement->client_cert = replacement_owner;
  replacement->process_generation = proc::proc.generation();
  rtsp_stream::launch_session_raise(replacement);
  const auto replacement_claim = rtsp_stream::claim_pending_launch_for_tests();
  ASSERT_EQ(replacement_claim, replacement);
  EXPECT_FALSE(rtsp_stream::claimed_launch_publishable_for_tests(options_claim));
  EXPECT_FALSE(rtsp_stream::claimed_launch_publishable_for_tests(describe_claim));
  EXPECT_TRUE(rtsp_stream::claimed_launch_publishable_for_tests(replacement_claim));
  EXPECT_EQ(rtsp_stream::terminate_sessions_by_cert(replacement_owner), 1U);
}

TEST(VanillaMoonlightCompatibility, HttpLaunchResumeReservationConflictIsSideEffectFreeAndRollbackExact) {
  rtsp_stream::terminate_sessions();
  auto restore = util::fail_guard([&]() {
    rtsp_stream::terminate_sessions();
    rtsp_stream::reset_idle_display_revert_count_for_tests();
  });
  const auto process_generation = proc::proc.generation();
  const auto running_app = proc::proc.running();
  rtsp_stream::reset_idle_display_revert_count_for_tests();

  auto launch = std::make_shared<rtsp_stream::launch_session_t>();
  launch->id = 0xCA1A;
  launch->client_cert = "certificate-a";
  launch->source_address = "127.0.0.1";
  launch->process_generation = process_generation;
  ASSERT_TRUE(rtsp_stream::launch_session_reserve(launch));
  ASSERT_NE(launch->pending_launch_generation, 0U);
  EXPECT_FALSE(rtsp_stream::claimed_launch_publishable_for_tests(launch));
  EXPECT_FALSE(rtsp_stream::expire_pending_launch_for_tests());

  auto conflicting_resume = std::make_shared<rtsp_stream::launch_session_t>();
  conflicting_resume->id = 0xCA1B;
  conflicting_resume->client_cert = "certificate-b";
  conflicting_resume->source_address = "127.0.0.2";
  conflicting_resume->process_generation = process_generation;
  EXPECT_FALSE(rtsp_stream::launch_session_reserve(conflicting_resume));
  EXPECT_EQ(conflicting_resume->pending_launch_generation, 0U);
  EXPECT_EQ(proc::proc.generation(), process_generation);
  EXPECT_EQ(proc::proc.running(), running_app);
  EXPECT_EQ(rtsp_stream::idle_display_revert_count_for_tests(), 0U);

  EXPECT_TRUE(rtsp_stream::launch_session_rollback(launch));
  EXPECT_FALSE(rtsp_stream::has_session_or_pending_launch());
  EXPECT_FALSE(rtsp_stream::launch_session_commit(launch));
  EXPECT_EQ(rtsp_stream::idle_display_revert_count_for_tests(), 0U);
}

TEST(VanillaMoonlightCompatibility, CancelledReservationBlocksReplacementUntilExactHttpRollback) {
  constexpr auto owner = "reservation-owner-a"sv;
  constexpr auto replacement_owner = "reservation-owner-b"sv;
  rtsp_stream::terminate_sessions();
  auto restore = util::fail_guard([&]() {
    rtsp_stream::terminate_sessions();
    rtsp_stream::reset_idle_display_revert_count_for_tests();
  });
  const auto process_generation = proc::proc.generation();
  const auto running_app = proc::proc.running();
  rtsp_stream::reset_idle_display_revert_count_for_tests();

  auto launch = std::make_shared<rtsp_stream::launch_session_t>();
  launch->id = 0xCA1C;
  launch->client_cert = owner;
  launch->source_address = "127.0.0.1";
  launch->process_generation = process_generation;
  ASSERT_TRUE(rtsp_stream::launch_session_reserve(launch));
  const auto cancelled_generation = launch->pending_launch_generation;

  EXPECT_EQ(rtsp_stream::cancel_sessions_and_process_by_cert(owner), 1U);
  EXPECT_EQ(rtsp_stream::cancel_sessions_and_process_by_cert(owner), 0U);
  EXPECT_FALSE(rtsp_stream::claimed_launch_publishable_for_tests(launch));

  auto replacement = std::make_shared<rtsp_stream::launch_session_t>();
  replacement->id = 0xCA1D;
  replacement->client_cert = replacement_owner;
  replacement->source_address = "192.0.2.2";
  replacement->process_generation = process_generation;
  EXPECT_FALSE(rtsp_stream::launch_session_reserve(replacement));
  EXPECT_EQ(replacement->pending_launch_generation, 0U);
  EXPECT_EQ(proc::proc.generation(), process_generation);
  EXPECT_EQ(proc::proc.running(), running_app);
  EXPECT_EQ(rtsp_stream::idle_display_revert_count_for_tests(), 0U);

  EXPECT_FALSE(rtsp_stream::launch_session_commit(launch));
  EXPECT_EQ(launch->pending_launch_generation, cancelled_generation);
  EXPECT_TRUE(rtsp_stream::launch_session_rollback(launch));
  ASSERT_TRUE(rtsp_stream::launch_session_reserve(replacement));
  EXPECT_GT(replacement->pending_launch_generation, cancelled_generation);
  EXPECT_TRUE(rtsp_stream::launch_session_commit(replacement));
  EXPECT_TRUE(rtsp_stream::launch_session_rollback(replacement));
  EXPECT_FALSE(rtsp_stream::has_session_or_pending_launch());
  EXPECT_EQ(proc::proc.generation(), process_generation);
  EXPECT_EQ(proc::proc.running(), running_app);
  EXPECT_EQ(rtsp_stream::idle_display_revert_count_for_tests(), 0U);
}

TEST(VanillaMoonlightCompatibility, CancelledResumeReservationTerminatesOwnedProcessWhileRetainingFence) {
  constexpr auto owner = "cancelled-resume-owner"sv;
  rtsp_stream::terminate_sessions();
  proc::proc.terminate();
  auto saved_process = std::move(proc::proc);
  auto restore = util::fail_guard([&]() {
    rtsp_stream::terminate_sessions();
    rtsp_stream::reset_idle_display_revert_count_for_tests();
    proc::proc.terminate();
    proc::proc = std::move(saved_process);
  });

  boost::process::v1::environment env {boost::this_process::environment()};
  proc::ctx_t desktop {};
  desktop.name = "Desktop";
  desktop.id = "881";
  desktop.exit_timeout = std::chrono::seconds {0};
  std::vector<proc::ctx_t> apps;
  apps.emplace_back(std::move(desktop));
  proc::proc = proc::proc_t {std::move(env), std::move(apps)};
  rtsp_stream::reset_idle_display_revert_count_for_tests();

  auto process_launch = std::make_shared<rtsp_stream::launch_session_t>();
  process_launch->client_cert = owner;
  ASSERT_EQ(proc::proc.execute(881, process_launch), 0);
  ASSERT_EQ(proc::proc.running(), 881);

  auto resume = std::make_shared<rtsp_stream::launch_session_t>();
  resume->id = 0xCA20;
  resume->client_cert = owner;
  resume->source_address = "127.0.0.1";
  resume->process_generation = proc::proc.generation();
  ASSERT_TRUE(rtsp_stream::launch_session_reserve(resume));

  EXPECT_EQ(rtsp_stream::cancel_sessions_and_process_by_cert(owner), 1U);
  EXPECT_EQ(proc::proc.running(), 0);
  EXPECT_TRUE(rtsp_stream::has_session_or_pending_launch());
  EXPECT_EQ(rtsp_stream::idle_display_revert_count_for_tests(), 1U);
  EXPECT_EQ(rtsp_stream::cancel_sessions_and_process_by_cert(owner), 0U);
  EXPECT_EQ(proc::proc.running(), 0);
  EXPECT_EQ(rtsp_stream::idle_display_revert_count_for_tests(), 1U);

  EXPECT_TRUE(rtsp_stream::launch_session_rollback(resume));
  EXPECT_FALSE(rtsp_stream::has_session_or_pending_launch());
  EXPECT_EQ(proc::proc.running(), 0);
}

TEST(VanillaMoonlightCompatibility, ResumeRechecksActiveSessionsAfterReservationBeforeDisplayPreparation) {
  const bool no_active_sessions_at_request = true;
  ASSERT_TRUE(no_active_sessions_at_request);
  EXPECT_FALSE(nvhttp::resume_should_prepare_display_after_reservation(1));
  EXPECT_FALSE(nvhttp::resume_should_prepare_display_after_reservation(2));
  EXPECT_TRUE(nvhttp::resume_should_prepare_display_after_reservation(0));

  std::atomic_bool committed_host_audio {false};
  EXPECT_FALSE(nvhttp::resolve_resume_host_audio_candidate(committed_host_audio, true, 1));
  EXPECT_TRUE(nvhttp::resolve_resume_host_audio_candidate(committed_host_audio, true, 0));
  nvhttp::commit_host_audio(committed_host_audio, true);
  EXPECT_TRUE(nvhttp::resolve_resume_host_audio_candidate(committed_host_audio, false, 1));
  EXPECT_FALSE(nvhttp::resolve_resume_host_audio_candidate(committed_host_audio, false, 0));
}

TEST(VanillaMoonlightCompatibility, RejectedHostAudioCandidateDoesNotMutateCommittedBaseline) {
  rtsp_stream::terminate_sessions();
  auto restore = util::fail_guard([&]() {
    rtsp_stream::terminate_sessions();
  });
  std::atomic_bool committed_host_audio {false};

  auto blocker = std::make_shared<rtsp_stream::launch_session_t>();
  blocker->id = 0xCA30;
  blocker->source_address = "127.0.0.1";
  ASSERT_TRUE(rtsp_stream::launch_session_reserve(blocker));

  auto rejected = std::make_shared<rtsp_stream::launch_session_t>();
  rejected->id = 0xCA31;
  rejected->source_address = "192.0.2.4";
  constexpr bool rejected_candidate = true;
  rejected->host_audio = rejected_candidate;
  EXPECT_FALSE(rtsp_stream::launch_session_reserve(rejected));
  EXPECT_FALSE(nvhttp::load_committed_host_audio(committed_host_audio));

  ASSERT_TRUE(rtsp_stream::launch_session_rollback(blocker));
  ASSERT_TRUE(rtsp_stream::launch_session_reserve(rejected));
  ASSERT_TRUE(rtsp_stream::launch_session_commit(rejected));
  nvhttp::commit_host_audio(committed_host_audio, rejected_candidate);
  EXPECT_TRUE(nvhttp::load_committed_host_audio(committed_host_audio));
  EXPECT_TRUE(rtsp_stream::launch_session_rollback(rejected));
}

TEST(VanillaMoonlightCompatibility, CommittedHostAudioBaselineIsAtomicUnderConcurrentAccess) {
  std::atomic_bool committed_host_audio {false};
  constexpr int iterations = 1000;
  std::array<std::future<void>, 6> tasks;
  for (std::size_t task = 0; task < tasks.size(); ++task) {
    tasks[task] = std::async(std::launch::async, [&, task]() {
      for (int iteration = 0; iteration < iterations; ++iteration) {
        if ((task & 1U) == 0) {
          nvhttp::commit_host_audio(committed_host_audio, (iteration & 1) != 0);
        } else {
          static_cast<void>(nvhttp::load_committed_host_audio(committed_host_audio));
          static_cast<void>(nvhttp::resolve_resume_host_audio_candidate(
            committed_host_audio,
            (iteration & 1) != 0,
            iteration & 1
          ));
        }
      }
    });
  }
  for (auto &task : tasks) {
    EXPECT_NO_THROW(task.get());
  }
  nvhttp::commit_host_audio(committed_host_audio, true);
  EXPECT_TRUE(nvhttp::load_committed_host_audio(committed_host_audio));
}

TEST(VanillaMoonlightCompatibility, ReservationRollbackRetainsSlotThroughProcessAndDisplayCleanup) {
  constexpr auto owner = "rollback-owner-a"sv;
  rtsp_stream::terminate_sessions();
  auto restore = util::fail_guard([&]() {
    rtsp_stream::terminate_sessions();
  });

  auto launch = std::make_shared<rtsp_stream::launch_session_t>();
  launch->id = 0xCA1E;
  launch->client_cert = owner;
  launch->source_address = "127.0.0.1";
  launch->process_generation = proc::proc.generation();
  ASSERT_TRUE(rtsp_stream::launch_session_reserve(launch));
  ASSERT_EQ(rtsp_stream::cancel_sessions_and_process_by_cert(owner), 1U);
  ASSERT_FALSE(rtsp_stream::launch_session_commit(launch));

  auto replacement = std::make_shared<rtsp_stream::launch_session_t>();
  replacement->id = 0xCA1F;
  replacement->client_cert = "rollback-owner-b";
  replacement->source_address = "192.0.2.3";
  replacement->process_generation = proc::proc.generation();
  std::vector<std::string> events;
  nvhttp::rollback_launch_reservation_transaction(
    launch,
    [&]() {
      events.emplace_back("process");
      EXPECT_FALSE(rtsp_stream::launch_session_reserve(replacement));
    },
    [&]() {
      events.emplace_back("display");
      EXPECT_FALSE(rtsp_stream::launch_session_reserve(replacement));
    }
  );

  EXPECT_EQ(events, (std::vector<std::string> {"process", "display"}));
  ASSERT_TRUE(rtsp_stream::launch_session_reserve(replacement));
  EXPECT_TRUE(rtsp_stream::launch_session_rollback(replacement));
}

TEST(VanillaMoonlightCompatibility, StaleLegacyTimeoutCannotTearDownReplacementProtocolV3ProcessOrDisplay) {
  constexpr auto owner_certificate = "certificate-a"sv;
  rtsp_stream::terminate_sessions();
  proc::proc.terminate();
  auto saved_process = std::move(proc::proc);
  auto restore = util::fail_guard([&]() {
    rtsp_stream::terminate_sessions();
    rtsp_stream::reset_idle_display_revert_count_for_tests();
    proc::proc.terminate();
    proc::proc = std::move(saved_process);
  });

  boost::process::v1::environment env {boost::this_process::environment()};
  proc::ctx_t desktop {};
  desktop.name = "Desktop";
  desktop.id = "881";
  desktop.exit_timeout = std::chrono::seconds {0};
  std::vector<proc::ctx_t> apps;
  apps.emplace_back(std::move(desktop));
  proc::proc = proc::proc_t {std::move(env), std::move(apps)};

  auto legacy = std::make_shared<rtsp_stream::launch_session_t>();
  legacy->client_cert = owner_certificate;
  ASSERT_EQ(proc::proc.execute(881, legacy), 0);
  auto stale_pending = std::make_shared<rtsp_stream::launch_session_t>();
  stale_pending->id = 0xCA20;
  stale_pending->client_cert = owner_certificate;
  stale_pending->process_generation = legacy->process_generation;
  rtsp_stream::launch_session_raise(stale_pending);

  auto protocol_v3 = std::make_shared<rtsp_stream::launch_session_t>();
  ASSERT_EQ(proc::proc.execute(881, protocol_v3), 0);
  ASSERT_GT(protocol_v3->process_generation, legacy->process_generation);
  rtsp_stream::reset_idle_display_revert_count_for_tests();

  EXPECT_TRUE(rtsp_stream::expire_pending_launch_for_tests());
  EXPECT_EQ(proc::proc.running(), 881);
  EXPECT_EQ(rtsp_stream::idle_display_revert_count_for_tests(), 0U);
  EXPECT_FALSE(proc::proc.terminate_if_owned_by_certificate(owner_certificate));
}

TEST(VanillaMoonlightCompatibility, LegacyPairingSourcePolicyAllowsPrivateAndRejectsPublicAddresses) {
  for (const auto address : {"127.0.0.1", "192.168.1.20", "10.0.0.8", "172.16.5.4", "169.254.4.2", "::1", "fd00::1", "fe80::1"}) {
    EXPECT_TRUE(nvhttp::is_trusted_pairing_source(boost::asio::ip::make_address(address))) << address;
  }
  for (const auto address : {"1.1.1.1", "8.8.8.8", "100.64.1.2", "203.0.113.9", "2001:4860:4860::8888"}) {
    const auto parsed_address = boost::asio::ip::make_address(address);
    EXPECT_FALSE(nvhttp::is_trusted_pairing_source(parsed_address)) << address;
    const auto response = parse_xml(nvhttp::legacy_pairing_source_xml_for_tests(parsed_address));
    EXPECT_EQ(response.get<int>("root.<xmlattr>.status_code"), 403);
    EXPECT_EQ(response.get<int>("root.paired"), 0);
    EXPECT_EQ(
      response.get<std::string>("root.<xmlattr>.status_message"),
      "Pairing is restricted to local and trusted private networks"
    );
  }
}

TEST(VanillaMoonlightCompatibility, WanEncryptionDefaultsMandatoryAndAllowsExplicitCompatibilityDowngrade) {
  const auto saved_stream = config::stream;
  const auto saved_modified = config::modified_config_settings;
  auto restore = util::fail_guard([&]() {
    config::stream = saved_stream;
    config::modified_config_settings = saved_modified;
  });

  EXPECT_EQ(config::stream.wan_encryption_mode, config::ENCRYPTION_MODE_MANDATORY);
  EXPECT_EQ(
    net::encryption_mode_for_address(boost::asio::ip::make_address("8.8.8.8")),
    config::ENCRYPTION_MODE_MANDATORY
  );
  config::apply_config_for_test("wan_encryption_mode = 1\n");
  EXPECT_EQ(config::stream.wan_encryption_mode, config::ENCRYPTION_MODE_OPPORTUNISTIC);
  EXPECT_EQ(
    net::encryption_mode_for_address(boost::asio::ip::make_address("8.8.8.8")),
    config::ENCRYPTION_MODE_OPPORTUNISTIC
  );
  EXPECT_EQ(config::modified_config_settings.at("wan_encryption_mode"), "1");
}

TEST(VanillaMoonlightCompatibility, MixedCaseMediaKeysAreAlwaysRedactedFromLogs) {
  constexpr auto secret = "00112233445566778899aabbccddeeff"sv;
  for (const auto name : {"rikey"sv, "RiKeY"sv, "RIKEYID"sv, "rIkEyId"sv}) {
    const auto logged = nvhttp::legacy_query_log_value_for_tests(name, secret);
    EXPECT_EQ(logged, "[redacted]");
    EXPECT_EQ(logged.find(secret), std::string::npos);
  }
  EXPECT_EQ(nvhttp::legacy_query_log_value_for_tests("appid", "881"), "881");
}

TEST(VanillaMoonlightCompatibility, PairedClientRegistrySerializesVerifyPairDisableUnpairAndList) {
  const auto saved_state_file = config::nvhttp.file_state;
  const auto test_directory = std::filesystem::temp_directory_path() / "lumen-paired-client-registry-stress";
  std::filesystem::create_directories(test_directory);
  config::nvhttp.file_state = (test_directory / "state.json").string();
  auto restore = util::fail_guard([&]() {
    nvhttp::reset_paired_clients_for_tests();
    config::nvhttp.file_state = saved_state_file;
    std::filesystem::remove_all(test_directory);
  });
  nvhttp::reset_paired_clients_for_tests();

  constexpr int iterations = 250;
  std::array<std::future<void>, 5> tasks {
    std::async(std::launch::async, [] {
      for (int index = 0; index < iterations; ++index) {
        nvhttp::upsert_paired_client_for_tests("Moonlight", "client-a", "certificate-a", true);
      }
    }),
    std::async(std::launch::async, [] {
      for (int index = 0; index < iterations; ++index) {
        static_cast<void>(nvhttp::set_client_enabled("client-a", (index & 1) == 0));
      }
    }),
    std::async(std::launch::async, [] {
      for (int index = 0; index < iterations; ++index) {
        static_cast<void>(nvhttp::unpair_client("client-a"));
      }
    }),
    std::async(std::launch::async, [] {
      for (int index = 0; index < iterations; ++index) {
        static_cast<void>(nvhttp::get_all_clients());
      }
    }),
    std::async(std::launch::async, [] {
      for (int index = 0; index < iterations; ++index) {
        static_cast<void>(nvhttp::paired_client_enabled_for_tests("certificate-a"));
      }
    }),
  };
  for (auto &task : tasks) {
    EXPECT_NO_THROW(task.get());
  }

  nvhttp::upsert_paired_client_for_tests("Moonlight", "client-a", "certificate-a", true);
  EXPECT_TRUE(nvhttp::paired_client_enabled_for_tests("certificate-a"));
  EXPECT_EQ(nvhttp::get_all_clients().size(), 1U);
}

TEST(VanillaMoonlightCompatibility, RevokingOneClientReturnsExactOwnerAndPreservesTheOther) {
  const auto saved_state_file = config::nvhttp.file_state;
  const auto test_directory = std::filesystem::temp_directory_path() / "lumen-paired-client-revoke";
  std::filesystem::create_directories(test_directory);
  config::nvhttp.file_state = (test_directory / "state.json").string();
  auto restore = util::fail_guard([&]() {
    nvhttp::reset_paired_clients_for_tests();
    config::nvhttp.file_state = saved_state_file;
    std::filesystem::remove_all(test_directory);
  });
  nvhttp::reset_paired_clients_for_tests();
  nvhttp::upsert_paired_client_for_tests("First", "client-a", "certificate-a", true);
  nvhttp::upsert_paired_client_for_tests("Second", "client-b", "certificate-b", true);

  boost::asio::io_context io;
  boost::asio::ssl::context tls_context {boost::asio::ssl::context::tls_client};
  nvhttp::SunshineHTTPS first_connection {io, tls_context};
  nvhttp::SunshineHTTPS second_connection {io, tls_context};
  first_connection.bind_verified_client_certificate("certificate-a");
  second_connection.bind_verified_client_certificate("certificate-b");
  EXPECT_EQ(nvhttp::verified_transport_certificate_for_tests(first_connection), "certificate-a");
  EXPECT_EQ(nvhttp::verified_transport_certificate_for_tests(second_connection), "certificate-b");

  auto pending = std::make_shared<rtsp_stream::launch_session_t>();
  pending->id = 0xCA12;
  pending->client_cert = "certificate-a";
  rtsp_stream::launch_session_raise(pending);

  const auto revoked = nvhttp::revoke_client("client-a");
  ASSERT_TRUE(revoked);
  EXPECT_EQ(*revoked, "certificate-a");
  EXPECT_EQ(rtsp_stream::terminate_sessions_by_cert(*revoked), 1U);
  EXPECT_FALSE(nvhttp::paired_client_enabled_for_tests("certificate-a"));
  EXPECT_TRUE(nvhttp::paired_client_enabled_for_tests("certificate-b"));
  EXPECT_TRUE(nvhttp::verified_transport_certificate_for_tests(first_connection).empty());
  EXPECT_EQ(nvhttp::verified_transport_certificate_for_tests(second_connection), "certificate-b");
  EXPECT_EQ(nvhttp::get_all_clients().size(), 1U);
}

TEST(VanillaMoonlightCompatibility, RegistryMutationsPublishOnlyAfterPersistenceCommit) {
  enum class Mutation { add, disable, revoke, erase };
  const auto saved_state_file = config::nvhttp.file_state;
  const auto saved_fresh_state = config::sunshine.flags[config::flag::FRESH_STATE];
  const auto test_directory = std::filesystem::temp_directory_path() / "lumen-paired-client-persist-failure";
  std::filesystem::create_directories(test_directory);
  config::nvhttp.file_state = (test_directory / "missing" / "state.json").string();
  auto restore = util::fail_guard([&]() {
    config::sunshine.flags[config::flag::FRESH_STATE] = true;
    nvhttp::reset_paired_clients_for_tests();
    config::sunshine.flags[config::flag::FRESH_STATE] = saved_fresh_state;
    config::nvhttp.file_state = saved_state_file;
    std::filesystem::remove_all(test_directory);
  });

  for (const auto mutation : {Mutation::add, Mutation::disable, Mutation::revoke, Mutation::erase}) {
    config::sunshine.flags[config::flag::FRESH_STATE] = true;
    nvhttp::reset_paired_clients_for_tests();
    ASSERT_TRUE(nvhttp::upsert_paired_client_for_tests("First", "client-a", "certificate-a", true));
    config::sunshine.flags[config::flag::FRESH_STATE] = false;

    switch (mutation) {
      case Mutation::add:
        EXPECT_FALSE(nvhttp::upsert_paired_client_for_tests("Second", "client-b", "certificate-b", true));
        break;
      case Mutation::disable:
        EXPECT_FALSE(nvhttp::set_client_enabled_with_certificate("client-a", false));
        break;
      case Mutation::revoke:
        EXPECT_FALSE(nvhttp::revoke_client("client-a"));
        break;
      case Mutation::erase:
        EXPECT_FALSE(nvhttp::erase_all_clients());
        break;
    }

    EXPECT_TRUE(nvhttp::paired_client_enabled_for_tests("certificate-a"));
    EXPECT_FALSE(nvhttp::paired_client_enabled_for_tests("certificate-b"));
    EXPECT_EQ(nvhttp::get_all_clients().size(), 1U);
  }
}

TEST(VanillaMoonlightCompatibility, RevokingOneClientPreservesAnotherClientsPendingLaunch) {
  const auto saved_state_file = config::nvhttp.file_state;
  const auto saved_fresh_state = config::sunshine.flags[config::flag::FRESH_STATE];
  config::sunshine.flags[config::flag::FRESH_STATE] = true;
  auto restore = util::fail_guard([&]() {
    static_cast<void>(rtsp_stream::terminate_sessions_by_cert("certificate-b"));
    nvhttp::reset_paired_clients_for_tests();
    config::sunshine.flags[config::flag::FRESH_STATE] = saved_fresh_state;
    config::nvhttp.file_state = saved_state_file;
  });
  nvhttp::reset_paired_clients_for_tests();
  ASSERT_TRUE(nvhttp::upsert_paired_client_for_tests("First", "client-a", "certificate-a", true));
  ASSERT_TRUE(nvhttp::upsert_paired_client_for_tests("Second", "client-b", "certificate-b", true));

  auto pending = std::make_shared<rtsp_stream::launch_session_t>();
  pending->id = 0xCA13;
  pending->client_cert = "certificate-b";
  rtsp_stream::launch_session_raise(pending);
  const auto revoked = nvhttp::revoke_client("client-a");
  ASSERT_TRUE(revoked);
  EXPECT_EQ(rtsp_stream::terminate_sessions_by_cert(*revoked), 0U);
  EXPECT_TRUE(rtsp_stream::has_session_or_pending_launch());
  EXPECT_EQ(rtsp_stream::terminate_sessions_by_cert("certificate-b"), 1U);
}

TEST(VanillaMoonlightCompatibility, PairChallengeAndApplicationListBuildersRetainLegacyXml) {
  const auto pair = parse_xml(nvhttp::legacy_pair_challenge_xml_for_tests());
  EXPECT_EQ(pair.get<int>("root.<xmlattr>.status_code"), 200);
  EXPECT_EQ(pair.get<int>("root.paired"), 1);

  const auto apps = parse_xml(nvhttp::legacy_applist_xml_for_tests(
    {{"Desktop", "881"}, {"Steam Big Picture", "882"}},
    true
  ));
  EXPECT_EQ(apps.get<int>("root.<xmlattr>.status_code"), 200);
  const auto application_nodes = apps.get_child("root").equal_range("App");
  ASSERT_EQ(std::distance(application_nodes.first, application_nodes.second), 2);
  auto application = application_nodes.first;
  EXPECT_EQ(application->second.get<std::string>("AppTitle"), "Desktop");
  EXPECT_EQ(application->second.get<std::string>("ID"), "881");
  EXPECT_EQ(application->second.get<int>("IsHdrSupported"), 1);
  ++application;
  EXPECT_EQ(application->second.get<std::string>("AppTitle"), "Steam Big Picture");
  EXPECT_EQ(application->second.get<std::string>("ID"), "882");
}

TEST(VanillaMoonlightCompatibility, LaunchResumeCancelAndAssetBuildersRetainLegacyContract) {
  constexpr auto session_url = "rtspenc://192.0.2.10:48010"sv;
  const auto launch = parse_xml(nvhttp::legacy_launch_xml_for_tests(session_url));
  EXPECT_EQ(launch.get<int>("root.<xmlattr>.status_code"), 200);
  EXPECT_EQ(launch.get<std::string>("root.sessionUrl0"), session_url);
  EXPECT_EQ(launch.get<int>("root.gamesession"), 1);

  const auto resume = parse_xml(nvhttp::legacy_resume_xml_for_tests(session_url));
  EXPECT_EQ(resume.get<int>("root.<xmlattr>.status_code"), 200);
  EXPECT_EQ(resume.get<std::string>("root.sessionUrl0"), session_url);
  EXPECT_EQ(resume.get<int>("root.resume"), 1);

  const auto cancel = parse_xml(nvhttp::legacy_cancel_xml_for_tests());
  EXPECT_EQ(cancel.get<int>("root.<xmlattr>.status_code"), 200);
  EXPECT_EQ(cancel.get<int>("root.cancel"), 1);
  EXPECT_EQ(nvhttp::legacy_appasset_content_type_for_tests(), "image/png");
}

TEST(VanillaMoonlightCompatibility, PinnedRtspMethodsAndTargetsParseUnmodified) {
  const auto &rtsp = official_fixture().at("rtsp");
  const auto target = rtsp.at("target").get<std::string>();
  const std::array transactions {
    std::pair {"OPTIONS"s, target},
    std::pair {"DESCRIBE"s, target},
    std::pair {"SETUP"s, rtsp.at("setupTargets").at(0).get<std::string>()},
    std::pair {"SETUP"s, rtsp.at("setupTargets").at(1).get<std::string>()},
    std::pair {"SETUP"s, rtsp.at("setupTargets").at(2).get<std::string>()},
    std::pair {"ANNOUNCE"s, rtsp.at("announceTarget").get<std::string>()},
    std::pair {"PLAY"s, rtsp.at("playTarget").get<std::string>()},
  };

  int cseq = 1;
  for (const auto &[method, request_target] : transactions) {
    const auto payload = method == "ANNOUNCE" ? announce_payload() : std::string {};
    auto request = parse_request(request_text(method, request_target, cseq, {}, payload));
    ASSERT_TRUE(request) << method;
    EXPECT_STREQ(request->message.request.command, method.c_str());
    EXPECT_STREQ(request->message.request.target, request_target.c_str());
    EXPECT_EQ(request->sequenceNumber, cseq);
    ++cseq;
  }
}

TEST(VanillaMoonlightCompatibility, LegacyOptionsAndDescribeHandlersReturnMoonlightPayloads) {
  const auto &rtsp = official_fixture().at("rtsp");
  auto session = legacy_session();

  auto options = parse_request(request_text("OPTIONS", rtsp.at("target").get<std::string>(), 10));
  ASSERT_TRUE(options);
  ConnectedSockets option_sockets;
  rtsp_stream::cmd_option(nullptr, option_sockets.server(), session, std::move(options));
  const auto option_response = option_sockets.read_response();
  EXPECT_NE(option_response.find("RTSP/1.0 200 OK\r\n"), std::string::npos);
  EXPECT_NE(option_response.find("CSeq: 10\r\n"), std::string::npos);

  const auto saved_microphone = config::audio.client_microphone;
  config::audio.client_microphone = false;
  auto restore = util::fail_guard([&]() {
    config::audio.client_microphone = saved_microphone;
  });
  auto describe = parse_request(request_text(
    "DESCRIBE",
    rtsp.at("target").get<std::string>(),
    11,
    "Accept: application/sdp\r\nIf-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\n"
  ));
  ASSERT_TRUE(describe);
  ConnectedSockets describe_sockets;
  rtsp_stream::cmd_describe(nullptr, describe_sockets.server(), session, std::move(describe));
  const auto describe_response = describe_sockets.read_response();
  EXPECT_NE(describe_response.find("RTSP/1.0 200 OK\r\n"), std::string::npos);
  EXPECT_NE(describe_response.find("a=x-ss-general.featureFlags:"), std::string::npos);
  EXPECT_NE(describe_response.find("a=x-ss-general.encryptionSupported:"), std::string::npos);
  EXPECT_NE(describe_response.find("a=x-ss-general.encryptionRequested:"), std::string::npos);
  EXPECT_EQ(describe_response.find("x-lumen-"), std::string::npos);
}

TEST(VanillaMoonlightCompatibility, ProductionRtspListenerReusesPendingLaunchAcrossPreAnnounceConnections) {
  const auto &rtsp = official_fixture().at("rtsp");
  const auto target = rtsp.at("target").get<std::string>();
  auto pending = std::make_shared<rtsp_stream::launch_session_t>();
  pending->id = 0xCA21;
  pending->source_address = "127.0.0.1";

  const auto saved_microphone = config::audio.client_microphone;
  config::audio.client_microphone = false;
  auto restore = util::fail_guard([&]() {
    config::audio.client_microphone = saved_microphone;
  });

  const std::vector requests {
    request_text("OPTIONS", target, 10),
    request_text(
      "DESCRIBE",
      target,
      11,
      "Accept: application/sdp\r\nIf-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\n"
    ),
  };
  const auto responses = rtsp_stream::exchange_preannounce_requests_for_tests(pending, requests);

  ASSERT_EQ(responses.size(), 2U);
  EXPECT_NE(responses[0].find("RTSP/1.0 200 OK\r\n"), std::string::npos);
  EXPECT_NE(responses[0].find("CSeq: 10\r\n"), std::string::npos);
  EXPECT_NE(responses[1].find("RTSP/1.0 200 OK\r\n"), std::string::npos);
  EXPECT_NE(responses[1].find("CSeq: 11\r\n"), std::string::npos);
  EXPECT_NE(responses[1].find("a=x-ss-general.featureFlags:"), std::string::npos);
}

TEST(VanillaMoonlightCompatibility, ProductionRtspListenerRejectsWrongSourceBeforeDispatch) {
  const auto target = official_fixture().at("rtsp").at("target").get<std::string>();
  auto pending = std::make_shared<rtsp_stream::launch_session_t>();
  pending->id = 0xCA22;
  pending->source_address = "192.0.2.1";

  const auto responses = rtsp_stream::exchange_preannounce_requests_for_tests(
    pending,
    {request_text("OPTIONS", target, 12)}
  );

  ASSERT_EQ(responses.size(), 1U);
  EXPECT_TRUE(responses[0].empty());
}

TEST(VanillaMoonlightCompatibility, LegacySetupAndPlayHandlersReturnMoonlightHeaders) {
  const auto &rtsp = official_fixture().at("rtsp");
  auto session = legacy_session();

  int cseq = 20;
  for (const auto &target_node : rtsp.at("setupTargets")) {
    const auto target = target_node.get<std::string>();
    auto request = parse_request(request_text(
      "SETUP",
      target,
      cseq,
      "Transport: unicast;X-GS-ClientPort=50000-50001\r\n"
      "If-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\n"
    ));
    ASSERT_TRUE(request);
    ConnectedSockets sockets;
    rtsp_stream::cmd_setup(nullptr, sockets.server(), session, std::move(request));
    const auto response = sockets.read_response();
    EXPECT_NE(response.find("RTSP/1.0 200 OK\r\n"), std::string::npos);
    EXPECT_NE(response.find("CSeq: " + std::to_string(cseq) + "\r\n"), std::string::npos);
    EXPECT_NE(response.find("Session: DEADBEEFCAFE;timeout = 90\r\n"), std::string::npos);
    EXPECT_NE(response.find("Transport: server_port="), std::string::npos);
    ++cseq;
  }

  auto play = parse_request(request_text("PLAY", rtsp.at("playTarget").get<std::string>(), cseq, "Session: DEADBEEFCAFE\r\n"));
  ASSERT_TRUE(play);
  ConnectedSockets sockets;
  rtsp_stream::cmd_play(nullptr, sockets.server(), session, std::move(play));
  const auto response = sockets.read_response();
  EXPECT_NE(response.find("RTSP/1.0 403 Forbidden\r\n"), std::string::npos);
  EXPECT_NE(response.find("CSeq: " + std::to_string(cseq) + "\r\n"), std::string::npos);
}

TEST(VanillaMoonlightCompatibility, ProductionRtspListenerAcceptsFreshPostAnnouncePlayTransactions) {
  const auto &rtsp = official_fixture().at("rtsp");
  nvhttp::args_t args;
  for (const auto &[name, value] : official_fixture().at("http").at("launchArguments").items()) {
    args.emplace(name, value.get<std::string>());
  }
  auto launch = nvhttp::make_launch_session(false, args, "certificate-a");
  launch->rtsp_cipher.reset();
  launch->source_address = "127.0.0.1";

  const auto saved_lan_mode = config::stream.lan_encryption_mode;
  const auto saved_microphone = config::audio.client_microphone;
  config::stream.lan_encryption_mode = config::ENCRYPTION_MODE_OPPORTUNISTIC;
  config::audio.client_microphone = false;
  auto restore = util::fail_guard([&]() {
    config::stream.lan_encryption_mode = saved_lan_mode;
    config::audio.client_microphone = saved_microphone;
  });

  const std::vector requests {
    request_text(
      "ANNOUNCE",
      rtsp.at("announceTarget").get<std::string>(),
      30,
      "Session: DEADBEEFCAFE\r\n",
      announce_payload()
    ),
    request_text("PLAY", rtsp.at("playTarget").get<std::string>(), 32, "Session: DEADBEEFCAFE\r\n"),
    request_text("PLAY", rtsp.at("target").get<std::string>(), 33, "Session: DEADBEEFCAFE\r\n"),
    request_text(
      "ANNOUNCE",
      rtsp.at("announceTarget").get<std::string>(),
      34,
      "Session: DEADBEEFCAFE\r\n",
      announce_payload()
    ),
  };
  std::vector<int> active_counts;
  auto replacement = std::make_shared<rtsp_stream::launch_session_t>();
  replacement->id = launch->id + 1;
  replacement->source_address = launch->source_address;
  const std::vector actions {
    rtsp_stream::listener_lifecycle_action_e::attempt_same_address_replacement,
  };
  std::vector<bool> action_results;
  const auto responses = rtsp_stream::exchange_preannounce_requests_for_tests(
    launch,
    requests,
    {},
    &active_counts,
    actions,
    replacement,
    &action_results
  );

  ASSERT_EQ(responses.size(), requests.size());
  ASSERT_EQ(active_counts.size(), requests.size());
  ASSERT_EQ(action_results.size(), requests.size());
  EXPECT_FALSE(action_results[0]);
  for (std::size_t index = 0; index < responses.size(); ++index) {
    EXPECT_NE(responses[index].find("RTSP/1.0 200 OK\r\n"), std::string::npos) << index;
    EXPECT_EQ(active_counts[index], 1) << index;
  }
}

TEST(VanillaMoonlightCompatibility, ProductionRtspListenerRejectsPlayAfterClearCancelAndReplacement) {
  const auto &rtsp = official_fixture().at("rtsp");
  nvhttp::args_t args;
  for (const auto &[name, value] : official_fixture().at("http").at("launchArguments").items()) {
    args.emplace(name, value.get<std::string>());
  }
  auto launch = nvhttp::make_launch_session(false, args, "certificate-a");
  launch->rtsp_cipher.reset();
  launch->source_address = "127.0.0.1";
  auto replacement = nvhttp::make_launch_session(false, args, "certificate-b");
  replacement->rtsp_cipher.reset();
  replacement->source_address = launch->source_address;

  const auto saved_lan_mode = config::stream.lan_encryption_mode;
  const auto saved_microphone = config::audio.client_microphone;
  config::stream.lan_encryption_mode = config::ENCRYPTION_MODE_OPPORTUNISTIC;
  config::audio.client_microphone = false;
  auto restore = util::fail_guard([&]() {
    config::stream.lan_encryption_mode = saved_lan_mode;
    config::audio.client_microphone = saved_microphone;
  });

  const std::vector requests {
    request_text(
      "ANNOUNCE",
      rtsp.at("announceTarget").get<std::string>(),
      40,
      "Session: DEADBEEFCAFE\r\n",
      announce_payload()
    ),
    request_text("PLAY", rtsp.at("playTarget").get<std::string>(), 41, "Session: DEADBEEFCAFE\r\n"),
    request_text("PLAY", rtsp.at("playTarget").get<std::string>(), 42, "Session: DEADBEEFCAFE\r\n"),
    request_text("OPTIONS", rtsp.at("target").get<std::string>(), 43),
  };
  const std::vector actions {
    rtsp_stream::listener_lifecycle_action_e::clear_announced,
    rtsp_stream::listener_lifecycle_action_e::cancel_replace_and_stale_clear,
  };
  std::vector<int> active_counts;
  std::vector<bool> action_results;
  const auto responses = rtsp_stream::exchange_preannounce_requests_for_tests(
    launch,
    requests,
    {},
    &active_counts,
    actions,
    replacement,
    &action_results
  );

  ASSERT_EQ(responses.size(), requests.size());
  ASSERT_EQ(active_counts.size(), requests.size());
  ASSERT_EQ(action_results.size(), requests.size());
  EXPECT_NE(responses[0].find("RTSP/1.0 200 OK\r\n"), std::string::npos);
  EXPECT_TRUE(responses[1].empty());
  EXPECT_NE(responses[2].find("RTSP/1.0 403 Forbidden\r\n"), std::string::npos);
  EXPECT_NE(responses[3].find("RTSP/1.0 200 OK\r\n"), std::string::npos);
  EXPECT_EQ(active_counts, (std::vector<int> {1, 0, 0, 0}));
  EXPECT_TRUE(action_results[0]);
  EXPECT_TRUE(action_results[1]);
}

TEST(VanillaMoonlightCompatibility, EncryptedFreshSocketAnnouncePlayPreservesSharedIvContinuity) {
  const auto &rtsp = official_fixture().at("rtsp");
  nvhttp::args_t args;
  for (const auto &[name, value] : official_fixture().at("http").at("launchArguments").items()) {
    args.emplace(name, value.get<std::string>());
  }
  auto launch = nvhttp::make_launch_session(false, args, "certificate-a");
  launch->source_address = "127.0.0.1";
  const auto key = launch->gcm_key;

  const auto saved_lan_mode = config::stream.lan_encryption_mode;
  const auto saved_microphone = config::audio.client_microphone;
  config::stream.lan_encryption_mode = config::ENCRYPTION_MODE_OPPORTUNISTIC;
  config::audio.client_microphone = false;
  auto restore = util::fail_guard([&]() {
    config::stream.lan_encryption_mode = saved_lan_mode;
    config::audio.client_microphone = saved_microphone;
  });

  const std::vector requests {
    rtsp_stream::encrypt_rtsp_request_for_tests(
      key,
      1,
      request_text(
        "ANNOUNCE",
        rtsp.at("announceTarget").get<std::string>(),
        50,
        "Session: DEADBEEFCAFE\r\n",
        announce_payload()
      )
    ),
    rtsp_stream::encrypt_rtsp_request_for_tests(
      key,
      2,
      request_text("PLAY", rtsp.at("playTarget").get<std::string>(), 51, "Session: DEADBEEFCAFE\r\n")
    ),
  };
  const auto responses = rtsp_stream::exchange_preannounce_requests_for_tests(launch, requests);

  ASSERT_EQ(responses.size(), requests.size());
  const auto announce = rtsp_stream::decrypt_rtsp_response_for_tests(key, responses[0]);
  const auto play = rtsp_stream::decrypt_rtsp_response_for_tests(key, responses[1]);
  EXPECT_NE(announce.plaintext.find("RTSP/1.0 200 OK\r\n"), std::string::npos);
  EXPECT_NE(play.plaintext.find("RTSP/1.0 200 OK\r\n"), std::string::npos);
  EXPECT_EQ(announce.sequence, 1U);
  EXPECT_EQ(play.sequence, 2U);
}

TEST(VanillaMoonlightCompatibility, DistinctAddressAnnouncedAndPendingRoutesCoexistThroughTimeout) {
  const auto &rtsp = official_fixture().at("rtsp");
  nvhttp::args_t args;
  for (const auto &[name, value] : official_fixture().at("http").at("launchArguments").items()) {
    args.emplace(name, value.get<std::string>());
  }
  auto launch = nvhttp::make_launch_session(false, args, "certificate-a");
  launch->rtsp_cipher.reset();
  launch->source_address = "127.0.0.1";
  auto distinct_pending = nvhttp::make_launch_session(false, args, "certificate-b");
  distinct_pending->rtsp_cipher.reset();
  distinct_pending->source_address = "192.0.2.2";

  const auto saved_lan_mode = config::stream.lan_encryption_mode;
  const auto saved_microphone = config::audio.client_microphone;
  config::stream.lan_encryption_mode = config::ENCRYPTION_MODE_OPPORTUNISTIC;
  config::audio.client_microphone = false;
  auto restore = util::fail_guard([&]() {
    config::stream.lan_encryption_mode = saved_lan_mode;
    config::audio.client_microphone = saved_microphone;
  });

  const std::vector requests {
    request_text(
      "ANNOUNCE",
      rtsp.at("announceTarget").get<std::string>(),
      60,
      "Session: DEADBEEFCAFE\r\n",
      announce_payload()
    ),
    request_text("PLAY", rtsp.at("playTarget").get<std::string>(), 61, "Session: DEADBEEFCAFE\r\n"),
    request_text("PLAY", rtsp.at("playTarget").get<std::string>(), 62, "Session: DEADBEEFCAFE\r\n"),
  };
  const std::vector actions {
    rtsp_stream::listener_lifecycle_action_e::attempt_distinct_address_pending,
    rtsp_stream::listener_lifecycle_action_e::expire_replacement_pending,
  };
  std::vector<int> active_counts;
  std::vector<bool> action_results;
  const auto responses = rtsp_stream::exchange_preannounce_requests_for_tests(
    launch,
    requests,
    {},
    &active_counts,
    actions,
    distinct_pending,
    &action_results
  );

  ASSERT_EQ(responses.size(), requests.size());
  for (const auto &response : responses) {
    EXPECT_NE(response.find("RTSP/1.0 200 OK\r\n"), std::string::npos);
  }
  EXPECT_EQ(active_counts, (std::vector<int> {1, 1, 1}));
  ASSERT_GE(action_results.size(), 2U);
  EXPECT_TRUE(action_results[0]);
  EXPECT_TRUE(action_results[1]);
}

TEST(VanillaMoonlightCompatibility, ControlAttachClearAndStopEraseAnnouncedPlayRoute) {
  const auto &rtsp = official_fixture().at("rtsp");
  nvhttp::args_t args;
  for (const auto &[name, value] : official_fixture().at("http").at("launchArguments").items()) {
    args.emplace(name, value.get<std::string>());
  }
  auto launch = nvhttp::make_launch_session(false, args, "certificate-a");
  launch->rtsp_cipher.reset();
  launch->source_address = "127.0.0.1";

  const auto saved_lan_mode = config::stream.lan_encryption_mode;
  const auto saved_microphone = config::audio.client_microphone;
  config::stream.lan_encryption_mode = config::ENCRYPTION_MODE_OPPORTUNISTIC;
  config::audio.client_microphone = false;
  auto restore = util::fail_guard([&]() {
    config::stream.lan_encryption_mode = saved_lan_mode;
    config::audio.client_microphone = saved_microphone;
  });

  const std::vector requests {
    request_text(
      "ANNOUNCE",
      rtsp.at("announceTarget").get<std::string>(),
      70,
      "Session: DEADBEEFCAFE\r\n",
      announce_payload()
    ),
    request_text("PLAY", rtsp.at("playTarget").get<std::string>(), 71, "Session: DEADBEEFCAFE\r\n"),
    request_text("PLAY", rtsp.at("playTarget").get<std::string>(), 72, "Session: DEADBEEFCAFE\r\n"),
  };
  const std::vector actions {
    rtsp_stream::listener_lifecycle_action_e::clear_announced,
    rtsp_stream::listener_lifecycle_action_e::stop_all,
  };
  std::vector<int> active_counts;
  const auto responses = rtsp_stream::exchange_preannounce_requests_for_tests(
    launch,
    requests,
    {},
    &active_counts,
    actions
  );

  ASSERT_EQ(responses.size(), requests.size());
  EXPECT_NE(responses[0].find("RTSP/1.0 200 OK\r\n"), std::string::npos);
  EXPECT_TRUE(responses[1].empty());
  EXPECT_TRUE(responses[2].empty());
  EXPECT_EQ(active_counts, (std::vector<int> {1, 0, 0}));
}

TEST(VanillaMoonlightCompatibility, VanillaAnnounceReachesTheFinalPolicyGateWithoutExtensions) {
  const auto payload = announce_payload();
  EXPECT_EQ(payload.find("x-lumen-"), std::string::npos);
  EXPECT_EQ(payload.find("lumen/2"), std::string::npos);
  EXPECT_EQ(
    stream_policy::parse_rtsp_announce_optimization_mode(payload).status,
    stream_policy::ParsedOptimizationMode::Status::absent
  );
  EXPECT_EQ(
    stream_policy::parse_rtsp_announce_client_protocol(payload).protocol,
    stream_policy::ClientProtocol::vanilla
  );

  const auto saved_lan_mode = config::stream.lan_encryption_mode;
  config::stream.lan_encryption_mode = config::ENCRYPTION_MODE_MANDATORY;
  auto restore = util::fail_guard([&]() {
    config::stream.lan_encryption_mode = saved_lan_mode;
  });

  auto request = parse_request(request_text(
    "ANNOUNCE",
    official_fixture().at("rtsp").at("announceTarget").get<std::string>(),
    40,
    "Session: DEADBEEFCAFE\r\n",
    payload
  ));
  ASSERT_TRUE(request);
  auto session = legacy_session();
  ConnectedSockets sockets;
  rtsp_stream::cmd_announce(nullptr, sockets.server(), session, std::move(request));
  const auto response = sockets.read_response();

  // 400 would mean the vanilla SDP failed parsing or validation. Reaching the
  // mandatory-encryption 403 proves the complete legacy parse path succeeded,
  // while stopping before VDD, capture, encoder, or stream startup.
  EXPECT_NE(response.find("RTSP/1.0 403 Forbidden\r\n"), std::string::npos);
}

TEST(VanillaMoonlightCompatibility, UnknownSdpAttributeDoesNotBreakVanillaAnnounce) {
  auto payload = announce_payload();
  payload += "a=x-umbra-unknown-future-attribute:1\r\n";
  const auto saved_lan_mode = config::stream.lan_encryption_mode;
  config::stream.lan_encryption_mode = config::ENCRYPTION_MODE_MANDATORY;
  auto restore = util::fail_guard([&]() {
    config::stream.lan_encryption_mode = saved_lan_mode;
  });
  auto request = parse_request(request_text(
    "ANNOUNCE",
    official_fixture().at("rtsp").at("announceTarget").get<std::string>(),
    41,
    "Session: DEADBEEFCAFE\r\n",
    payload
  ));
  ASSERT_TRUE(request);
  auto session = legacy_session();
  ConnectedSockets sockets;
  rtsp_stream::cmd_announce(nullptr, sockets.server(), session, std::move(request));
  EXPECT_NE(sockets.read_response().find("RTSP/1.0 403 Forbidden\r\n"), std::string::npos);
}

TEST(VanillaMoonlightCompatibility, V3StartupFailurePreservesConfiguredLegacyListeners) {
  auto settings = config::protocol_v3;
  settings.legacy_compatibility = true;
  auto policy = config::listener_startup_policy(settings);
  EXPECT_TRUE(policy.start_legacy);
  EXPECT_FALSE(policy.v3_failure_is_fatal);

  settings.legacy_compatibility = false;
  policy = config::listener_startup_policy(settings);
  EXPECT_FALSE(policy.start_legacy);
  EXPECT_TRUE(policy.v3_failure_is_fatal);
}

TEST(VanillaMoonlightCompatibility, UndefinedV3PairingPermissionBitsAreMigratedOutOfConfig) {
  const auto saved = config::protocol_v3;
  auto restore = util::fail_guard([&]() {
    config::protocol_v3 = saved;
  });

  config::apply_config_for_test("protocol_v3_pairing_permissions = 255\n");
  EXPECT_EQ(lumen::protocol_v3::control_session::defined_permission_mask, 0x3fU);
  EXPECT_EQ(
    config::protocol_v3.pairing_permissions,
    lumen::protocol_v3::control_session::defined_permission_mask
  );
}

TEST(VanillaMoonlightCompatibility, BuildsWithoutV3NormalizeMigratedV3OnlyConfiguration) {
  const auto saved = config::protocol_v3;
  auto restore = util::fail_guard([&]() {
    config::protocol_v3 = saved;
  });

  config::apply_config_for_test("protocol_v3_enabled = true\nlegacy_compatibility = false\n");
#if LUMEN_PROTOCOL_V3_DEFAULT_ENABLED
  EXPECT_TRUE(config::protocol_v3.enabled);
  EXPECT_FALSE(config::protocol_v3.legacy_compatibility);
#else
  EXPECT_FALSE(config::protocol_v3.enabled);
  EXPECT_TRUE(config::protocol_v3.legacy_compatibility);
#endif
}
