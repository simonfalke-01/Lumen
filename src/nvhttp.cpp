/**
 * @file src/nvhttp.cpp
 * @brief Definitions for the nvhttp (GameStream) server.
 */
// macros
#define BOOST_BIND_GLOBAL_PLACEHOLDERS

// standard includes
#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <format>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

// lib includes
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/context_base.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <Simple-Web-Server/server_http.hpp>

// local includes
#include "config.h"
#include "display_device.h"
#include "file_handler.h"
#include "globals.h"
#include "httpcommon.h"
#include "logging.h"
#include "network.h"
#include "nvhttp.h"
#include "platform/common.h"
#include "process.h"
#include "rtsp.h"
#include "stream_policy.h"
#include "system_tray.h"
#include "utility.h"
#include "uuid.h"
#include "video.h"

using namespace std::literals;

namespace nvhttp {

  constexpr std::uint32_t SCM_LUMEN_H264_LOSSLESS = 0x00800000;  ///< Runtime NVENC H.264 lossless proof.
  constexpr std::uint32_t SCM_LUMEN_HEVC_LOSSLESS = 0x01000000;  ///< Runtime NVENC HEVC lossless proof.
  constexpr std::uint32_t SCM_LUMEN_AV1_LOSSLESS = 0x02000000;  ///< Runtime NVENC AV1 lossless proof.

  static constexpr std::string_view EMPTY_PROPERTY_TREE_ERROR_MSG = "Property tree is empty. Probably, control flow got interrupted by an unexpected C++ exception. This is a bug in Lumen. Moonlight-qt will report Malformed XML (missing root element)."sv;

  namespace fs = std::filesystem;
  namespace pt = boost::property_tree;

  /**
   * @brief HTTPS server backend that adds Sunshine's client-certificate verification.
   */
  class SunshineHTTPSServer: public SimpleWeb::ServerBase<SunshineHTTPS> {
  public:
    /**
     * @brief Initialize the HTTPS server with Sunshine's certificate and key files.
     *
     * @param certification_file Path to the server certificate file.
     * @param private_key_file Path to the matching private key file.
     */
    SunshineHTTPSServer(const std::string &certification_file, const std::string &private_key_file):
        ServerBase<SunshineHTTPS>::ServerBase(443),
        context(boost::asio::ssl::context::tls_server) {
      // Disabling TLS 1.0 and 1.1 (see RFC 8996)
      context.set_options(boost::asio::ssl::context::no_tlsv1);
      context.set_options(boost::asio::ssl::context::no_tlsv1_1);
      context.use_certificate_chain_file(certification_file);
      context.use_private_key_file(private_key_file, boost::asio::ssl::context::pem);
    }

    std::function<std::optional<std::string>(SSL *)> verify;  ///< Returns the exact verified peer certificate for this connection.
    std::function<void(std::shared_ptr<Response>, std::shared_ptr<Request>)> on_verify_failed;  ///< Handler used to return the pairing challenge when client verification fails.

  protected:
    boost::asio::ssl::context context;  ///< TLS server context configured with Sunshine's certificate and protocol policy.

    /**
     * @brief Enable client-certificate verification after the listening socket is bound.
     */
    void after_bind() override {
      if (verify) {
        context.set_verify_mode(boost::asio::ssl::verify_peer | boost::asio::ssl::verify_fail_if_no_peer_cert | boost::asio::ssl::verify_client_once);
        context.set_verify_callback([](int verified, boost::asio::ssl::verify_context &ctx) {
          // To respond with an error message, a connection must be established
          return 1;
        });
      }
    }

    // This is Server<HTTPS>::accept() with SSL validation support added
    /**
     * @brief Accept a pending connection and arm the server for the next client.
     */
    void accept() override {
      auto connection = create_connection(*io_service, context);

      acceptor->async_accept(connection->socket->lowest_layer(), [this, connection](const SimpleWeb::error_code &ec) {
        auto lock = connection->handler_runner->continue_lock();
        if (!lock) {
          return;
        }

        if (ec != SimpleWeb::error::operation_aborted) {
          this->accept();
        }

        auto session = std::make_shared<Session>(config.max_request_streambuf_size, connection);

        if (!ec) {
          boost::asio::ip::tcp::no_delay option(true);
          SimpleWeb::error_code ec;
          session->connection->socket->lowest_layer().set_option(option, ec);

          session->connection->set_timeout(config.timeout_request);
          session->connection->socket->async_handshake(boost::asio::ssl::stream_base::server, [this, session](const SimpleWeb::error_code &ec) {
            session->connection->cancel_timeout();
            auto lock = session->connection->handler_runner->continue_lock();
            if (!lock) {
              return;
            }
            if (!ec) {
              if (verify) {
                auto certificate = verify(session->connection->socket->native_handle());
                if (!certificate) {
                  this->write(session, on_verify_failed);
                  return;
                }
                session->connection->socket->bind_verified_client_certificate(std::move(*certificate));
              }
              this->read(session);
            } else if (this->on_error) {
              this->on_error(session->request, ec);
            }
          });
        } else if (this->on_error) {
          this->on_error(session->request, ec);
        }
      });
    }
  };

  /**
   * @brief HTTPS server type used for GameStream endpoints requiring TLS.
   */
  using https_server_t = SunshineHTTPSServer;
  /**
   * @brief Plain HTTP server type used for GameStream endpoints without TLS.
   */
  using http_server_t = SimpleWeb::Server<SimpleWeb::HTTP>;

  /**
   * @brief Internal HTTPS credential paths for the configuration server.
   */
  struct conf_intern_t {
    std::string servercert;  ///< Server certificate PEM string.
    std::string pkey;  ///< Private key PEM string or path.
  } conf_intern;  ///< TLS credential paths loaded from Sunshine's runtime configuration.

  /**
   * @brief Certificate entry associated with a client name and UUID.
   */
  struct named_cert_t {
    std::string name;  ///< Human-readable name for this item.
    std::string uuid;  ///< Persistent Moonlight client UUID associated with the certificate.
    std::string cert;  ///< Certificate PEM string or path.
    bool enabled = true;  ///< Whether this persisted client entry may connect.
  };

  /**
   * @brief Persisted pairing data for one Moonlight client.
   */
  struct client_t {
    std::vector<named_cert_t> named_devices;  ///< Persisted Moonlight clients allowed to pair or reconnect.
  };

  struct paired_client_registry_t {
    std::recursive_mutex mutex;
    client_t clients;
  };

  pairing_session_manager_t pairing_sessions;  ///< Synchronized owner for temporary pairing state.
  paired_client_registry_t paired_clients;  ///< Synchronized paired-client authorization and persistence registry.
  std::atomic<uint32_t> session_id_counter;  ///< Monotonic counter used to allocate GameStream session IDs.

  /**
   * @brief Case-insensitive map used for HTTP headers and query parameters.
   */
  using args_t = SimpleWeb::CaseInsensitiveMultimap;
  /**
   * @brief Shared HTTPS response object passed to GameStream handlers.
   */
  using resp_https_t = std::shared_ptr<typename SimpleWeb::ServerBase<SunshineHTTPS>::Response>;
  /**
   * @brief Shared HTTPS request object received by GameStream handlers.
   */
  using req_https_t = std::shared_ptr<typename SimpleWeb::ServerBase<SunshineHTTPS>::Request>;
  /**
   * @brief Shared HTTP response object passed to redirect and discovery handlers.
   */
  using resp_http_t = std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTP>::Response>;
  /**
   * @brief Shared HTTP request object received by redirect and discovery handlers.
   */
  using req_http_t = std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTP>::Request>;

  namespace {
    constexpr std::string_view LEGACY_APP_ASSET_CONTENT_TYPE = "image/png"sv;
    constexpr std::array SENSITIVE_QUERY_FIELDS {
      "clientcert"sv,
      "salt"sv,
      "clientchallenge"sv,
      "serverchallengeresp"sv,
      "clientpairingsecret"sv,
      "rikey"sv,
      "rikeyid"sv,
    };

    bool is_sensitive_query_field(std::string_view name) {
      return std::ranges::any_of(SENSITIVE_QUERY_FIELDS, [&](std::string_view field) {
        return name.size() == field.size() && std::equal(name.begin(), name.end(), field.begin(), [](char left, char right) {
          return std::tolower(static_cast<unsigned char>(left)) == std::tolower(static_cast<unsigned char>(right));
        });
      });
    }

    bool registry_allows_certificate(std::string_view certificate) {
      std::lock_guard lock {paired_clients.mutex};
      const auto &clients = paired_clients.clients.named_devices;
      const auto existing = std::ranges::find(clients, certificate, &named_cert_t::cert);
      return existing != clients.end() && existing->enabled;
    }

#ifdef SUNSHINE_TESTS
    std::string query_log_value(std::string_view name, std::string_view value) {
      return is_sensitive_query_field(name) ? "[redacted]" : std::string {value};
    }
#endif

    std::string verified_client_certificate(const req_https_t &request) {
      const auto transport = request ? request->connection_socket() : nullptr;
      if (!transport || !registry_allows_certificate(transport->verified_client_certificate())) {
        return {};
      }
      return transport->verified_client_certificate();
    }

#ifdef SUNSHINE_TESTS
    std::string serialize_legacy_xml(const pt::ptree &tree) {
      std::ostringstream data;
      pt::write_xml(data, tree);
      return data.str();
    }
#endif

    pt::ptree build_pair_challenge_tree() {
      pt::ptree tree;
      tree.put("root.paired", 1);
      tree.put("root.<xmlattr>.status_code", 200);
      return tree;
    }

    pt::ptree build_untrusted_pairing_source_tree() {
      pt::ptree tree;
      tree.put("root.paired", 0);
      tree.put("root.<xmlattr>.status_code", 403);
      tree.put("root.<xmlattr>.status_message", "Pairing is restricted to local and trusted private networks");
      return tree;
    }

    pt::ptree build_applist_tree(
      const std::vector<std::pair<std::string, std::string>> &apps,
      bool hdr_supported
    ) {
      pt::ptree tree;
      auto &root = tree.add_child("root", pt::ptree {});
      root.put("<xmlattr>.status_code", 200);
      for (const auto &[name, id] : apps) {
        pt::ptree app;
        app.put("IsHdrSupported", hdr_supported ? 1 : 0);
        app.put("AppTitle", name);
        app.put("ID", id);
        root.push_back(std::make_pair("App", std::move(app)));
      }
      return tree;
    }

    pt::ptree build_launch_tree(std::string_view session_url) {
      pt::ptree tree;
      tree.put("root.<xmlattr>.status_code", 200);
      tree.put("root.sessionUrl0", session_url);
      tree.put("root.gamesession", 1);
      return tree;
    }

    pt::ptree build_resume_tree(std::string_view session_url) {
      pt::ptree tree;
      tree.put("root.<xmlattr>.status_code", 200);
      tree.put("root.sessionUrl0", session_url);
      tree.put("root.resume", 1);
      return tree;
    }

    pt::ptree build_cancel_tree() {
      pt::ptree tree;
      tree.put("root.cancel", 1);
      tree.put("root.<xmlattr>.status_code", 200);
      return tree;
    }

    bool has_held_pairing_response(const pair_session_t &session) {
      const auto &response = session.async_insert_pin.response;
      return response.has_left() || response.has_right();
    }

    bool write_held_pairing_response(pair_session_t &session, const pt::ptree &tree) {
      std::ostringstream data;
      pt::write_xml(data, tree);

      auto &response = session.async_insert_pin.response;
      std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTP>::Response> http_response;
      std::shared_ptr<typename SimpleWeb::ServerBase<SunshineHTTPS>::Response> https_response;
      if (response.has_left()) {
        http_response = std::move(response.left());
      } else if (response.has_right()) {
        https_response = std::move(response.right());
      }
      response = {};

      if (http_response) {
        http_response->write(data.str());
        http_response->close_connection_after_response = true;
        return true;
      }
      if (https_response) {
        https_response->write(data.str());
        https_response->close_connection_after_response = true;
        return true;
      }
      return false;
    }

    void reject_held_pairing_response(pair_session_t &session, int status_code, std::string_view message) {
      pt::ptree tree;
      tree.put("root.paired", 0);
      tree.put("root.<xmlattr>.status_code", status_code);
      tree.put("root.<xmlattr>.status_message", message);
      write_held_pairing_response(session, tree);
    }

    std::string random_pairing_request_id() {
      std::array<std::uint8_t, 16> bytes {};
      if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        return {};
      }
      return util::hex_vec(bytes, true);
    }

    std::string short_client_fingerprint(std::string_view certificate) {
      auto fingerprint = util::hex_vec(crypto::hash(certificate), true);
      if (fingerprint.size() > 12) {
        fingerprint.resize(12);
      }
      return fingerprint;
    }
  }  // namespace

  bool is_valid_pairing_unique_id(std::string_view value) {
    return !value.empty() && value.size() <= PAIRING_UNIQUE_ID_MAX_BYTES && std::all_of(value.begin(), value.end(), [](unsigned char character) {
      return character >= 0x21 && character <= 0x7E;
    });
  }

  bool is_valid_pairing_hex(std::string_view value, std::size_t minimum_bytes, std::size_t maximum_bytes) {
    return value.size() >= minimum_bytes && value.size() <= maximum_bytes && value.size() % 2 == 0 &&
           std::all_of(value.begin(), value.end(), [](unsigned char character) {
             return std::isxdigit(character) != 0;
           });
  }

  bool is_trusted_pairing_source(const boost::asio::ip::address &address) {
    const auto normalized = net::normalize_address(address);
    if (normalized.is_v4()) {
      const auto value = normalized.to_v4().to_uint();
      return (value & 0xFF000000U) == 0x7F000000U ||
             (value & 0xFF000000U) == 0x0A000000U ||
             (value & 0xFFF00000U) == 0xAC100000U ||
             (value & 0xFFFF0000U) == 0xC0A80000U ||
             (value & 0xFFFF0000U) == 0xA9FE0000U;
    }
    static const auto unique_local = boost::asio::ip::make_network_v6("fc00::/7"sv);
    static const auto link_local = boost::asio::ip::make_network_v6("fe80::/10"sv);
    const auto value = normalized.to_v6();
    return value.is_loopback() ||
           unique_local.hosts().find(value) != unique_local.hosts().end() ||
           link_local.hosts().find(value) != link_local.hosts().end();
  }

  pairing_session_manager_t::locked_session_t::locked_session_t(
    std::unique_lock<std::recursive_mutex> lock,
    std::shared_ptr<pair_session_t> session,
    std::string unique_id,
    std::string request_id,
    std::string source
  ):
      lock_ {std::move(lock)},
      session_ {std::move(session)},
      unique_id_ {std::move(unique_id)},
      request_id_ {std::move(request_id)},
      source_ {std::move(source)} {
  }

  pairing_session_manager_t::locked_session_t::operator bool() const noexcept {
    return static_cast<bool>(session_);
  }

  pair_session_t &pairing_session_manager_t::locked_session_t::session() const {
    return *session_;
  }

  const std::string &pairing_session_manager_t::locked_session_t::unique_id() const noexcept {
    return unique_id_;
  }

  const std::string &pairing_session_manager_t::locked_session_t::request_id() const noexcept {
    return request_id_;
  }

  const std::string &pairing_session_manager_t::locked_session_t::source() const noexcept {
    return source_;
  }

  pairing_session_manager_t::add_result_t pairing_session_manager_t::add(
    pair_session_t session,
    std::string source,
    std::string request_id,
    time_point_t now
  ) {
    std::lock_guard lock {mutex_};
    cleanup_expired_locked(now);
    cleanup_pin_submissions_locked(now);

    if (!accepting_) {
      return {add_status_e::CLOSED, {}};
    }

    if (!is_valid_pairing_unique_id(session.client.uniqueID) ||
        session.client.cert.size() > PAIRING_CLIENT_CERT_MAX_BYTES ||
        session.async_insert_pin.salt.size() > PAIRING_SALT_HEX_BYTES) {
      return {add_status_e::INVALID_FIELDS, {}};
    }

    const auto unique_id = session.client.uniqueID;
    if (auto existing = sessions_.find(unique_id); existing != sessions_.end()) {
      const auto identical_retry = existing->second.source == source &&
                                   existing->second.session->last_phase == PAIR_PHASE::NONE &&
                                   has_held_pairing_response(*existing->second.session) &&
                                   existing->second.session->client.cert == session.client.cert &&
                                   existing->second.session->async_insert_pin.salt == session.async_insert_pin.salt;
      if (identical_retry) {
        reject_held_pairing_response(*existing->second.session, 409, "Pairing request superseded by an identical retry");
        existing->second.session = std::make_shared<pair_session_t>(std::move(session));
        return {add_status_e::REPLACED, existing->second.request_id};
      }
      return {add_status_e::DUPLICATE_UNIQUE_ID, {}};
    }
    if (sessions_.size() >= MAX_GLOBAL_SESSIONS) {
      return {add_status_e::GLOBAL_LIMIT, {}};
    }
    if (const auto submissions = pin_submissions_by_source_.find(source);
        submissions != pin_submissions_by_source_.end() && submissions->second.size() >= MAX_PIN_ATTEMPTS) {
      return {add_status_e::SOURCE_LIMIT, {}};
    }
    const auto source_sessions = static_cast<std::size_t>(std::count_if(sessions_.begin(), sessions_.end(), [&](const auto &item) {
      return item.second.source == source;
    }));
    if (source_sessions >= MAX_SESSIONS_PER_SOURCE) {
      return {add_status_e::SOURCE_LIMIT, {}};
    }

    if (request_id.empty()) {
      for (int attempt = 0; attempt < 4 && request_id.empty(); ++attempt) {
        auto candidate = random_pairing_request_id();
        if (!candidate.empty() && !request_to_unique_id_.contains(candidate)) {
          request_id = std::move(candidate);
        }
      }
      if (request_id.empty()) {
        return {add_status_e::RANDOM_FAILURE, {}};
      }
    } else if (request_to_unique_id_.contains(request_id)) {
      return {add_status_e::DUPLICATE_REQUEST_ID, {}};
    }

    auto stored_session = std::make_shared<pair_session_t>(std::move(session));
    auto fingerprint = short_client_fingerprint(stored_session->client.cert);
    sessions_.emplace(
      unique_id,
      entry_t {
        .session = std::move(stored_session),
        .source = std::move(source),
        .request_id = request_id,
        .created_at = now,
        .client_fingerprint = std::move(fingerprint)
      }
    );
    request_to_unique_id_.emplace(request_id, unique_id);
    return {add_status_e::ADDED, std::move(request_id)};
  }

  pairing_session_manager_t::locked_session_t pairing_session_manager_t::find_by_unique_id(std::string_view unique_id, std::string_view source, time_point_t now) {
    std::unique_lock lock {mutex_};
    cleanup_expired_locked(now);
    auto entry = sessions_.find(std::string {unique_id});
    if (entry == sessions_.end() || entry->second.source != source) {
      return {};
    }
    return {std::move(lock), entry->second.session, entry->first, entry->second.request_id, entry->second.source};
  }

  pairing_session_manager_t::locked_session_t pairing_session_manager_t::find_pending_by_request_id(std::string_view request_id, time_point_t now) {
    std::unique_lock lock {mutex_};
    cleanup_expired_locked(now);
    auto request = request_to_unique_id_.find(std::string {request_id});
    if (request == request_to_unique_id_.end()) {
      return {};
    }
    auto entry = sessions_.find(request->second);
    if (entry == sessions_.end() || entry->second.session->last_phase != PAIR_PHASE::NONE || !has_held_pairing_response(*entry->second.session)) {
      return {};
    }
    return {std::move(lock), entry->second.session, entry->first, entry->second.request_id, entry->second.source};
  }

  pairing_session_manager_t::locked_session_t pairing_session_manager_t::find_single_pending(time_point_t now) {
    std::unique_lock lock {mutex_};
    cleanup_expired_locked(now);

    auto match = sessions_.end();
    for (auto entry = sessions_.begin(); entry != sessions_.end(); ++entry) {
      if (entry->second.session->last_phase != PAIR_PHASE::NONE || !has_held_pairing_response(*entry->second.session)) {
        continue;
      }
      if (match != sessions_.end()) {
        return {};
      }
      match = entry;
    }
    if (match == sessions_.end()) {
      return {};
    }
    return {std::move(lock), match->second.session, match->first, match->second.request_id, match->second.source};
  }

  pairing_session_manager_t::pin_attempt_status_e pairing_session_manager_t::record_pin_attempt(locked_session_t &session, time_point_t now) {
    std::lock_guard lock {mutex_};
    cleanup_pin_submissions_locked(now);
    auto entry = sessions_.find(session.unique_id());
    if (entry == sessions_.end() || entry->second.session != session.session_) {
      return pin_attempt_status_e::MISSING_SESSION;
    }

    auto &source_submissions = pin_submissions_by_source_[entry->second.source];
    if (source_submissions.size() >= MAX_PIN_ATTEMPTS) {
      return pin_attempt_status_e::SOURCE_RATE_LIMITED;
    }
    source_submissions.push_back(now);

    if (entry->second.pin_attempts >= MAX_PIN_ATTEMPTS) {
      return pin_attempt_status_e::SESSION_EXHAUSTED;
    }
    ++entry->second.pin_attempts;
    return entry->second.pin_attempts < MAX_PIN_ATTEMPTS ? pin_attempt_status_e::ACCEPTED : pin_attempt_status_e::SESSION_EXHAUSTED;
  }

  void pairing_session_manager_t::erase(std::string_view unique_id) {
    std::lock_guard lock {mutex_};
    auto entry = sessions_.find(std::string {unique_id});
    if (entry != sessions_.end()) {
      erase_locked(entry);
    }
  }

  std::size_t pairing_session_manager_t::cleanup_expired(time_point_t now) {
    std::lock_guard lock {mutex_};
    return cleanup_expired_locked(now);
  }

  bool pairing_session_manager_t::cancel_by_request_id(std::string_view request_id) {
    std::lock_guard lock {mutex_};
    auto request = request_to_unique_id_.find(std::string {request_id});
    if (request == request_to_unique_id_.end()) {
      return false;
    }
    auto entry = sessions_.find(request->second);
    if (entry == sessions_.end()) {
      request_to_unique_id_.erase(request);
      return false;
    }
    reject_held_pairing_response(*entry->second.session, 400, "Pairing request cancelled");
    erase_locked(entry);
    return true;
  }

  void pairing_session_manager_t::cancel_all() {
    std::lock_guard lock {mutex_};
    accepting_ = false;
    for (auto &[_, entry] : sessions_) {
      reject_held_pairing_response(*entry.session, 400, "Pairing request cancelled");
    }
    sessions_.clear();
    request_to_unique_id_.clear();
  }

  void pairing_session_manager_t::open() {
    std::lock_guard lock {mutex_};
    accepting_ = true;
  }

  void pairing_session_manager_t::close() {
    cancel_all();
  }

  bool pairing_session_manager_t::accepting() {
    std::lock_guard lock {mutex_};
    return accepting_;
  }

  std::size_t pairing_session_manager_t::size(time_point_t now) {
    std::lock_guard lock {mutex_};
    cleanup_expired_locked(now);
    return sessions_.size();
  }

  std::vector<pairing_session_manager_t::pending_request_t> pairing_session_manager_t::pending_requests(time_point_t now) {
    std::lock_guard lock {mutex_};
    cleanup_expired_locked(now);
    std::vector<pending_request_t> result;
    result.reserve(sessions_.size());
    for (const auto &[_, entry] : sessions_) {
      if (entry.session->last_phase == PAIR_PHASE::NONE && has_held_pairing_response(*entry.session)) {
        const auto age = now > entry.created_at ? std::chrono::duration_cast<std::chrono::seconds>(now - entry.created_at).count() : 0;
        result.push_back({.request_id = entry.request_id, .source = entry.source, .age_seconds = static_cast<std::uint64_t>(age), .client_fingerprint = entry.client_fingerprint});
      }
    }
    std::sort(result.begin(), result.end(), [](const auto &left, const auto &right) {
      return left.request_id < right.request_id;
    });
    return result;
  }

  std::size_t pairing_session_manager_t::cleanup_expired_locked(time_point_t now) {
    std::size_t removed = 0;
    for (auto entry = sessions_.begin(); entry != sessions_.end();) {
      if (now - entry->second.created_at < SESSION_TTL) {
        ++entry;
        continue;
      }
      reject_held_pairing_response(*entry->second.session, 408, "Pairing request timed out");
      request_to_unique_id_.erase(entry->second.request_id);
      entry = sessions_.erase(entry);
      ++removed;
    }
    return removed;
  }

  void pairing_session_manager_t::cleanup_pin_submissions_locked(time_point_t now) {
    for (auto source = pin_submissions_by_source_.begin(); source != pin_submissions_by_source_.end();) {
      auto &submissions = source->second;
      while (!submissions.empty() && now - submissions.front() >= SESSION_TTL) {
        submissions.pop_front();
      }
      if (submissions.empty()) {
        source = pin_submissions_by_source_.erase(source);
      } else {
        ++source;
      }
    }
  }

  void pairing_session_manager_t::erase_locked(std::unordered_map<std::string, entry_t>::iterator entry) {
    request_to_unique_id_.erase(entry->second.request_id);
    sessions_.erase(entry);
  }

  /**
   * @brief Certificate operations supported by the pairing API.
   */
  enum class op_e {
    ADD,  ///< Add certificate
    REMOVE  ///< Remove certificate
  };

  /**
   * @brief Read a named query argument from the HTTP request map.
   *
   * @param args Parsed query-string argument map.
   * @param name Query parameter name to read.
   * @param default_value Value returned when the parameter is absent.
   * @return Query parameter value, default value, or an empty string.
   */
  std::string get_arg(const args_t &args, const char *name, const char *default_value = nullptr) {
    auto it = args.find(name);
    if (it == std::end(args)) {
      if (default_value != nullptr) {
        return std::string(default_value);
      }

      throw std::out_of_range(name);
    }
    return it->second;
  }

  /**
   * @brief Persist the current state to its backing store.
   */
  bool persist_client_state(const client_t &client) {
    if (!http::update_state_file(config::nvhttp.file_state, [&](pt::ptree &root) {
          root.erase("root"s);
          root.put("root.uniqueid", http::unique_id);
          pt::ptree named_cert_nodes;
          for (const auto &named_cert : client.named_devices) {
            pt::ptree named_cert_node;
            named_cert_node.put("name"s, named_cert.name);
            named_cert_node.put("cert"s, named_cert.cert);
            named_cert_node.put("uuid"s, named_cert.uuid);
            named_cert_node.put("enabled"s, named_cert.enabled);
            named_cert_nodes.push_back(std::make_pair(""s, named_cert_node));
          }
          root.add_child("root.named_devices"s, named_cert_nodes);
        })) {
      BOOST_LOG(error) << "Couldn't atomically persist paired-client state to "sv << config::nvhttp.file_state;
      return false;
    }
    return true;
  }

  bool commit_client_state(client_t candidate) {
    if (!config::sunshine.flags[config::flag::FRESH_STATE] && !persist_client_state(candidate)) {
      return false;
    }
    paired_clients.clients = std::move(candidate);
    return true;
  }

  /**
   * @brief Load state from its backing store.
   */
  void load_state() {
    std::lock_guard lock {paired_clients.mutex};
    if (!fs::exists(config::nvhttp.file_state)) {
      BOOST_LOG(info) << "File "sv << config::nvhttp.file_state << " doesn't exist"sv;
      http::unique_id = uuid_util::uuid_t::generate().string();
      return;
    }

    pt::ptree tree;
    if (!http::read_state_file(config::nvhttp.file_state, tree)) {
      return;
    }

    auto unique_id_p = tree.get_optional<std::string>("root.uniqueid");
    if (!unique_id_p) {
      // This file doesn't contain moonlight credentials
      http::unique_id = uuid_util::uuid_t::generate().string();
      return;
    }
    http::unique_id = std::move(*unique_id_p);

    auto root = tree.get_child("root");
    client_t client;

    // Import from old format
    if (root.get_child_optional("devices")) {
      auto device_nodes = root.get_child("devices");
      for (auto &[_, device_node] : device_nodes) {
        auto uniqID = device_node.get<std::string>("uniqueid");

        if (device_node.count("certs")) {
          for (auto &[_, el] : device_node.get_child("certs")) {
            named_cert_t named_cert;
            named_cert.name = ""s;
            named_cert.cert = el.get_value<std::string>();
            named_cert.uuid = uuid_util::uuid_t::generate().string();
            client.named_devices.emplace_back(named_cert);
          }
        }
      }
    }

    if (root.count("named_devices")) {
      for (auto &[_, el] : root.get_child("named_devices")) {
        named_cert_t named_cert;
        named_cert.name = el.get_child("name").get_value<std::string>();
        named_cert.cert = el.get_child("cert").get_value<std::string>();
        named_cert.uuid = el.get_child("uuid").get_value<std::string>();
        named_cert.enabled = el.get<bool>("enabled", true);
        client.named_devices.emplace_back(named_cert);
      }
    }

    paired_clients.clients = std::move(client);
  }

  /**
   * @brief Add authorized client data.
   *
   * @param name Human-readable name to assign.
   * @param cert Certificate data or object used by the operation.
   */
  bool add_authorized_client(const std::string &name, std::string &&cert) {
    std::lock_guard lock {paired_clients.mutex};
    auto candidate = paired_clients.clients;
    named_cert_t named_cert;
    named_cert.name = name;
    named_cert.cert = std::move(cert);
    named_cert.uuid = uuid_util::uuid_t::generate().string();
    candidate.named_devices.emplace_back(std::move(named_cert));
    return commit_client_state(std::move(candidate));
  }

  /**
   * @brief Create launch session.
   *
   * @param host_audio Host audio.
   * @param args Arguments forwarded to the callable or parser.
   * @return Constructed launch session object.
   */
  std::shared_ptr<rtsp_stream::launch_session_t> make_launch_session(
    bool host_audio,
    const args_t &args,
    std::string client_certificate
  ) {
    auto launch_session = std::make_shared<rtsp_stream::launch_session_t>();

    launch_session->id = ++session_id_counter;

    auto rikey = util::from_hex_vec(get_arg(args, "rikey"), true);
    std::copy(rikey.cbegin(), rikey.cend(), std::back_inserter(launch_session->gcm_key));

    launch_session->host_audio = host_audio;
    std::stringstream mode = std::stringstream(get_arg(args, "mode", "0x0x0"));
    // Split mode by the char "x", to populate width/height/fps
    int x = 0;
    std::string segment;
    while (std::getline(mode, segment, 'x')) {
      if (x == 0) {
        launch_session->width = atoi(segment.c_str());
      }
      if (x == 1) {
        launch_session->height = atoi(segment.c_str());
      }
      if (x == 2) {
        launch_session->fps = atoi(segment.c_str());
      }
      x++;
    }
    launch_session->unique_id = (get_arg(args, "uniqueid", "unknown"));
    launch_session->appid = (int) util::from_view(get_arg(args, "appid", "unknown"));
    launch_session->enable_sops = util::from_view(get_arg(args, "sops", "0"));
    launch_session->surround_info = (int) util::from_view(get_arg(args, "surroundAudioInfo", "196610"));
    launch_session->surround_params = (get_arg(args, "surroundParams", ""));
    launch_session->continuous_audio = util::from_view(get_arg(args, "continuousAudio", "0"));
    launch_session->gcmap = (int) util::from_view(get_arg(args, "gcmap", "0"));
    launch_session->enable_hdr = util::from_view(get_arg(args, "hdrMode", "0"));

    // Encrypted RTSP is enabled with client reported corever >= 1
    auto corever = util::from_view(get_arg(args, "corever", "0"));
    if (corever >= 1) {
      launch_session->rtsp_cipher = crypto::cipher::gcm_t {
        launch_session->gcm_key,
        false
      };
      launch_session->rtsp_iv_counter = 0;
    }
    launch_session->rtsp_url_scheme = launch_session->rtsp_cipher ? "rtspenc://"s : "rtsp://"s;
    launch_session->client_cert = std::move(client_certificate);

    // Generate the unique identifiers for this connection that we will send later during RTSP handshake
    unsigned char raw_payload[8];
    RAND_bytes(raw_payload, sizeof(raw_payload));
    launch_session->av_ping_payload = util::hex_vec(raw_payload);
    RAND_bytes((unsigned char *) &launch_session->control_connect_data, sizeof(launch_session->control_connect_data));

    launch_session->iv.resize(16);
    uint32_t prepend_iv = util::endian::big<uint32_t>((int) util::from_view(get_arg(args, "rikeyid")));
    auto prepend_iv_p = (uint8_t *) &prepend_iv;
    std::copy(prepend_iv_p, prepend_iv_p + sizeof(prepend_iv), std::begin(launch_session->iv));
    return launch_session;
  }

  void remove_session(const pair_session_t &sess) {
    pairing_sessions.erase(sess.client.uniqueID);
  }

  /**
   * @brief Return the GameStream pairing failure response.
   *
   * @param sess Pairing session that owns the request state.
   * @param tree XML property tree used for the response body.
   * @param status_msg Status msg.
   */
  void fail_pair(pair_session_t &sess, pt::ptree &tree, const std::string status_msg) {
    tree.put("root.paired", 0);
    tree.put("root.<xmlattr>.status_code", 400);
    tree.put("root.<xmlattr>.status_message", status_msg);
    remove_session(sess);  // Security measure, delete the session when something went wrong and force a re-pair
  }

  /**
   * @brief Return the server certificate text for pairing responses.
   *
   * @param sess Pairing session that owns the request state.
   * @param tree XML property tree used for the response body.
   * @param pin PIN supplied by the client during pairing.
   */
  void getservercert(pair_session_t &sess, pt::ptree &tree, const std::string &pin) {
    if (sess.last_phase != PAIR_PHASE::NONE) {
      fail_pair(sess, tree, "Out of order call to getservercert");
      return;
    }
    sess.last_phase = PAIR_PHASE::GETSERVERCERT;

    if (sess.async_insert_pin.salt.size() < 32) {
      fail_pair(sess, tree, "Salt too short");
      return;
    }

    std::string_view salt_view {sess.async_insert_pin.salt.data(), 32};

    auto salt = util::from_hex<std::array<uint8_t, 16>>(salt_view, true);

    auto key = crypto::gen_aes_key(salt, pin);
    sess.cipher_key = std::make_unique<crypto::aes_t>(key);

    tree.put("root.paired", 1);
    tree.put("root.plaincert", util::hex_vec(conf_intern.servercert, true));
    tree.put("root.<xmlattr>.status_code", 200);
  }

  /**
   * @brief Handle the client-challenge phase of GameStream pairing.
   *
   * @param sess Pairing session that owns the request state.
   * @param tree XML property tree used for the response body.
   * @param challenge Client challenge bytes from the pairing request.
   */
  void clientchallenge(pair_session_t &sess, pt::ptree &tree, const std::string &challenge) {
    if (sess.last_phase != PAIR_PHASE::GETSERVERCERT) {
      fail_pair(sess, tree, "Out of order call to clientchallenge");
      return;
    }
    sess.last_phase = PAIR_PHASE::CLIENTCHALLENGE;

    if (!sess.cipher_key) {
      fail_pair(sess, tree, "Cipher key not set");
      return;
    }
    crypto::cipher::ecb_t cipher(*sess.cipher_key, false);

    std::vector<uint8_t> decrypted;
    cipher.decrypt(challenge, decrypted);

    auto x509 = crypto::x509(conf_intern.servercert);
    auto sign = crypto::signature(x509);
    auto serversecret = crypto::rand(16);

    decrypted.insert(std::end(decrypted), std::begin(sign), std::end(sign));
    decrypted.insert(std::end(decrypted), std::begin(serversecret), std::end(serversecret));

    auto hash = crypto::hash({(char *) decrypted.data(), decrypted.size()});
    auto serverchallenge = crypto::rand(16);

    std::string plaintext;
    plaintext.reserve(hash.size() + serverchallenge.size());

    plaintext.insert(std::end(plaintext), std::begin(hash), std::end(hash));
    plaintext.insert(std::end(plaintext), std::begin(serverchallenge), std::end(serverchallenge));

    std::vector<uint8_t> encrypted;
    cipher.encrypt(plaintext, encrypted);

    sess.serversecret = std::move(serversecret);
    sess.serverchallenge = std::move(serverchallenge);

    tree.put("root.paired", 1);
    tree.put("root.challengeresponse", util::hex_vec(encrypted, true));
    tree.put("root.<xmlattr>.status_code", 200);
  }

  /**
   * @brief Handle the server-challenge response phase of GameStream pairing.
   *
   * @param sess Pairing session that owns the request state.
   * @param tree XML property tree used for the response body.
   * @param encrypted_response Encrypted response.
   */
  void serverchallengeresp(pair_session_t &sess, pt::ptree &tree, const std::string &encrypted_response) {
    if (sess.last_phase != PAIR_PHASE::CLIENTCHALLENGE) {
      fail_pair(sess, tree, "Out of order call to serverchallengeresp");
      return;
    }
    sess.last_phase = PAIR_PHASE::SERVERCHALLENGERESP;

    if (!sess.cipher_key || sess.serversecret.empty()) {
      fail_pair(sess, tree, "Cipher key or serversecret not set");
      return;
    }

    std::vector<uint8_t> decrypted;
    crypto::cipher::ecb_t cipher(*sess.cipher_key, false);

    cipher.decrypt(encrypted_response, decrypted);

    sess.clienthash = std::move(decrypted);

    auto serversecret = sess.serversecret;
    auto sign = crypto::sign256(crypto::pkey(conf_intern.pkey), serversecret);

    serversecret.insert(std::end(serversecret), std::begin(sign), std::end(sign));

    tree.put("root.pairingsecret", util::hex_vec(serversecret, true));
    tree.put("root.paired", 1);
    tree.put("root.<xmlattr>.status_code", 200);
  }

  /**
   * @brief Handle the client pairing-secret phase of GameStream pairing.
   *
   * @param sess Pairing session that owns the request state.
   * @param add_cert Add cert.
   * @param tree XML property tree used for the response body.
   * @param client_pairing_secret Client pairing secret.
   */
  void clientpairingsecret(pair_session_t &sess, std::shared_ptr<safe::queue_t<crypto::x509_t>> &add_cert, pt::ptree &tree, const std::string &client_pairing_secret) {
    if (sess.last_phase != PAIR_PHASE::SERVERCHALLENGERESP) {
      fail_pair(sess, tree, "Out of order call to clientpairingsecret");
      return;
    }
    sess.last_phase = PAIR_PHASE::CLIENTPAIRINGSECRET;

    auto &client = sess.client;

    if (client_pairing_secret.size() <= 16) {
      fail_pair(sess, tree, "Client pairing secret too short");
      return;
    }

    std::string_view secret {client_pairing_secret.data(), 16};
    std::string_view sign {client_pairing_secret.data() + secret.size(), client_pairing_secret.size() - secret.size()};

    auto x509 = crypto::x509(client.cert);
    if (!x509) {
      fail_pair(sess, tree, "Invalid client certificate");
      return;
    }
    auto x509_sign = crypto::signature(x509);

    std::string data;
    data.reserve(sess.serverchallenge.size() + x509_sign.size() + secret.size());

    data.insert(std::end(data), std::begin(sess.serverchallenge), std::end(sess.serverchallenge));
    data.insert(std::end(data), std::begin(x509_sign), std::end(x509_sign));
    data.insert(std::end(data), std::begin(secret), std::end(secret));

    auto hash = crypto::hash(data);

    // if hash not correct, probably MITM
    bool same_hash = hash.size() == sess.clienthash.size() && std::equal(hash.begin(), hash.end(), sess.clienthash.begin());
    auto verify = crypto::verify256(crypto::x509(client.cert), secret, sign);
    const auto paired_certificate = client.cert;
    if (same_hash && verify && add_authorized_client(client.name, std::move(client.cert))) {
      tree.put("root.paired", 1);
      // Retain the legacy handoff shape for consumers that observe pairing completion.
      // Authorization itself is owned by the synchronized paired-client registry.
      add_cert->raise(crypto::x509(paired_certificate));
    } else {
      tree.put("root.paired", 0);
    }

    remove_session(sess);
    tree.put("root.<xmlattr>.status_code", 200);
  }

  template<class T>
  struct tunnel;

  /**
   * @brief HTTPS tunnel session used for encrypted client requests.
   */
  template<>
  struct tunnel<SunshineHTTPS> {
    static auto constexpr to_string = "HTTPS"sv;  ///< To string.
  };

  /**
   * @brief Plain HTTP server wrapper used for non-TLS endpoints.
   */
  template<>
  struct tunnel<SimpleWeb::HTTP> {
    static auto constexpr to_string = "NONE"sv;  ///< To string.
  };

  /**
   * @brief Write req details to the log.
   *
   * @param request HTTP request data from the client.
   */
  template<class T>
  void print_req(std::shared_ptr<typename SimpleWeb::ServerBase<T>::Request> request) {
    static constexpr std::size_t MAX_LOGGED_FIELD_BYTES = 256;
    const auto log_field = [](std::string_view name, std::string_view value, bool sensitive) {
      if (sensitive) {
        BOOST_LOG(debug) << name << " -- [redacted]"sv;
        return;
      }
      const auto displayed = value.substr(0, MAX_LOGGED_FIELD_BYTES);
      BOOST_LOG(debug) << name << " -- " << displayed << (displayed.size() < value.size() ? " [truncated]"sv : ""sv);
    };

    BOOST_LOG(debug) << "TUNNEL :: "sv << tunnel<T>::to_string;

    BOOST_LOG(debug) << "METHOD :: "sv << request->method;
    BOOST_LOG(debug) << "DESTINATION :: "sv << request->path;

    for (auto &[name, val] : request->header) {
      const auto sensitive = SimpleWeb::case_insensitive_equal(name, "authorization") || SimpleWeb::case_insensitive_equal(name, "cookie");
      log_field(name, val, sensitive);
    }

    BOOST_LOG(debug) << " [--] "sv;

    for (auto &[name, val] : request->parse_query_string()) {
      log_field(name, val, is_sensitive_query_field(name));
    }

    BOOST_LOG(debug) << " [--] "sv;
  }

  /**
   * @brief Return a GameStream HTTP not-found response.
   *
   * @param response HTTP response object to populate.
   * @param request HTTP request data from the client.
   */
  template<class T>
  void not_found(std::shared_ptr<typename SimpleWeb::ServerBase<T>::Response> response, std::shared_ptr<typename SimpleWeb::ServerBase<T>::Request> request) {
    print_req<T>(request);

    pt::ptree tree;
    tree.put("root.<xmlattr>.status_code", 404);

    std::ostringstream data;

    pt::write_xml(data, tree);
    response->write(data.str());

    *response
      << "HTTP/1.1 404 NOT FOUND\r\n"
      << data.str();

    response->close_connection_after_response = true;
  }

  /**
   * @brief Dispatch the top-level GameStream pairing request by phase.
   *
   * @param add_cert Add cert.
   * @param response HTTP response object to populate.
   * @param request HTTP request data from the client.
   */
  template<class T>
  void pair(std::shared_ptr<safe::queue_t<crypto::x509_t>> &add_cert, std::shared_ptr<typename SimpleWeb::ServerBase<T>::Response> response, std::shared_ptr<typename SimpleWeb::ServerBase<T>::Request> request) {
    print_req<T>(request);

    pt::ptree tree;

    auto fg = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_xml(data, tree);
      response->write(data.str());
      response->close_connection_after_response = true;
    });

    if (!is_trusted_pairing_source(request->remote_endpoint().address())) {
      tree = build_untrusted_pairing_source_tree();
      return;
    }

    auto args = request->parse_query_string();
    if (args.find("uniqueid"s) == std::end(args)) {
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "Missing uniqueid parameter");

      return;
    }

    auto uniqID {get_arg(args, "uniqueid")};
    if (!is_valid_pairing_unique_id(uniqID)) {
      tree.put("root.paired", 0);
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "Invalid uniqueid");
      return;
    }

    args_t::const_iterator it;
    if (it = args.find("phrase"); it != std::end(args)) {
      if (it->second.size() > 32) {
        tree.put("root.paired", 0);
        tree.put("root.<xmlattr>.status_code", 400);
        tree.put("root.<xmlattr>.status_message", "Invalid pairing phrase");
        return;
      }
      if (it->second == "getservercert"sv) {
        pair_session_t sess;

        const auto client_cert_hex = get_arg(args, "clientcert", "");
        const auto salt = get_arg(args, "salt", "");
        if (!is_valid_pairing_hex(client_cert_hex, 2, PAIRING_CLIENT_CERT_HEX_MAX_BYTES) ||
            !is_valid_pairing_hex(salt, PAIRING_SALT_HEX_BYTES, PAIRING_SALT_HEX_BYTES)) {
          tree.put("root.paired", 0);
          tree.put("root.<xmlattr>.status_code", 400);
          tree.put("root.<xmlattr>.status_message", "Invalid pairing certificate or salt");
          return;
        }

        sess.client.uniqueID = uniqID;
        sess.client.cert = util::from_hex_vec(client_cert_hex, true);
        if (sess.client.cert.size() > PAIRING_CLIENT_CERT_MAX_BYTES || !crypto::x509(sess.client.cert)) {
          tree.put("root.paired", 0);
          tree.put("root.<xmlattr>.status_code", 400);
          tree.put("root.<xmlattr>.status_message", "Invalid client certificate");
          return;
        }
        sess.async_insert_pin.salt = salt;
        if (!config::sunshine.flags[config::flag::PIN_STDIN]) {
          sess.async_insert_pin.response = response;
        }

        const auto source = net::addr_to_normalized_string(request->remote_endpoint().address());
        auto added = pairing_sessions.add(std::move(sess), source);
        if (!added) {
          tree.put("root.paired", 0);
          switch (added.status) {
            case pairing_session_manager_t::add_status_e::DUPLICATE_UNIQUE_ID:
            case pairing_session_manager_t::add_status_e::DUPLICATE_REQUEST_ID:
              tree.put("root.<xmlattr>.status_code", 409);
              tree.put("root.<xmlattr>.status_message", "A pairing request for this client is already pending");
              break;
            case pairing_session_manager_t::add_status_e::GLOBAL_LIMIT:
            case pairing_session_manager_t::add_status_e::SOURCE_LIMIT:
              tree.put("root.<xmlattr>.status_code", 429);
              tree.put("root.<xmlattr>.status_message", "Too many pending pairing requests");
              break;
            case pairing_session_manager_t::add_status_e::RANDOM_FAILURE:
              tree.put("root.<xmlattr>.status_code", 500);
              tree.put("root.<xmlattr>.status_message", "Unable to create a secure pairing request ID");
              break;
            case pairing_session_manager_t::add_status_e::CLOSED:
              tree.put("root.<xmlattr>.status_code", 503);
              tree.put("root.<xmlattr>.status_message", "Pairing service is shutting down");
              break;
            case pairing_session_manager_t::add_status_e::INVALID_FIELDS:
              tree.put("root.<xmlattr>.status_code", 400);
              tree.put("root.<xmlattr>.status_message", "Invalid pairing request fields");
              break;
            case pairing_session_manager_t::add_status_e::REPLACED:
            case pairing_session_manager_t::add_status_e::ADDED:
              break;
          }
          return;
        }

        if (config::sunshine.flags[config::flag::PIN_STDIN]) {
          std::string pin;

          std::cout << "Please insert pin: "sv;
          std::getline(std::cin, pin);

          auto stored = pairing_sessions.find_by_unique_id(uniqID, source);
          if (!stored) {
            tree.put("root.paired", 0);
            tree.put("root.<xmlattr>.status_code", 408);
            tree.put("root.<xmlattr>.status_message", "Pairing request timed out");
            return;
          }
          const auto attempt_status = pairing_sessions.record_pin_attempt(stored);
          if (attempt_status == pairing_session_manager_t::pin_attempt_status_e::SOURCE_RATE_LIMITED ||
              attempt_status == pairing_session_manager_t::pin_attempt_status_e::MISSING_SESSION) {
            tree.put("root.paired", 0);
            tree.put("root.<xmlattr>.status_code", 429);
            tree.put("root.<xmlattr>.status_message", "Too many PIN submissions from this source");
            pairing_sessions.erase(stored.unique_id());
            return;
          }
          getservercert(stored.session(), tree, pin);
          return;
        } else {
#if defined SUNSHINE_TRAY && SUNSHINE_TRAY >= 1
          system_tray::update_tray_require_pin();
#endif
          fg.disable();
          return;
        }
      } else if (it->second == "pairchallenge"sv) {
        tree = build_pair_challenge_tree();
        return;
      }
    }

    const auto source = net::addr_to_normalized_string(request->remote_endpoint().address());
    auto stored = pairing_sessions.find_by_unique_id(uniqID, source);
    if (!stored) {
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "Invalid uniqueid");

      return;
    }

    if (it = args.find("clientchallenge"); it != std::end(args)) {
      if (!is_valid_pairing_hex(it->second, PAIRING_CLIENT_CHALLENGE_HEX_BYTES, PAIRING_CLIENT_CHALLENGE_HEX_BYTES)) {
        fail_pair(stored.session(), tree, "Invalid client challenge");
        return;
      }
      auto challenge = util::from_hex_vec(it->second, true);
      clientchallenge(stored.session(), tree, challenge);
    } else if (it = args.find("serverchallengeresp"); it != std::end(args)) {
      if (!is_valid_pairing_hex(it->second, PAIRING_SERVER_CHALLENGE_RESPONSE_HEX_BYTES, PAIRING_SERVER_CHALLENGE_RESPONSE_HEX_BYTES)) {
        fail_pair(stored.session(), tree, "Invalid server challenge response");
        return;
      }
      auto encrypted_response = util::from_hex_vec(it->second, true);
      serverchallengeresp(stored.session(), tree, encrypted_response);
    } else if (it = args.find("clientpairingsecret"); it != std::end(args)) {
      if (!is_valid_pairing_hex(it->second, 34, PAIRING_CLIENT_SECRET_HEX_MAX_BYTES)) {
        fail_pair(stored.session(), tree, "Invalid client pairing secret");
        return;
      }
      auto pairingsecret = util::from_hex_vec(it->second, true);
      clientpairingsecret(stored.session(), add_cert, tree, pairingsecret);
    } else {
      tree.put("root.<xmlattr>.status_code", 404);
      tree.put("root.<xmlattr>.status_message", "Invalid pairing request");
    }
  }

  bool pin(std::string pin, std::string name) {
    return nvhttp::pin(std::move(pin), std::move(name), {});
  }

  bool pin(std::string pin, std::string name, std::string_view request_id) {
    pt::ptree tree;
    if (!request_id.empty() && !is_valid_pairing_hex(request_id, PAIRING_REQUEST_ID_HEX_BYTES, PAIRING_REQUEST_ID_HEX_BYTES)) {
      return false;
    }
    auto stored = request_id.empty() ? pairing_sessions.find_single_pending() : pairing_sessions.find_pending_by_request_id(request_id);
    if (!stored) {
      return false;
    }

    const auto attempt_status = pairing_sessions.record_pin_attempt(stored);
    if (attempt_status == pairing_session_manager_t::pin_attempt_status_e::SOURCE_RATE_LIMITED ||
        attempt_status == pairing_session_manager_t::pin_attempt_status_e::MISSING_SESSION) {
      tree.put("root.paired", 0);
      tree.put("root.<xmlattr>.status_code", 429);
      tree.put("root.<xmlattr>.status_message", "Too many PIN submissions from this source");
      write_held_pairing_response(stored.session(), tree);
      pairing_sessions.erase(stored.unique_id());
      return false;
    }
    const auto session_exhausted = attempt_status == pairing_session_manager_t::pin_attempt_status_e::SESSION_EXHAUSTED;

    if (name.size() > PAIRING_CLIENT_NAME_MAX_BYTES) {
      tree.put("root.paired", 0);
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "Client name is too long");
      if (session_exhausted) {
        write_held_pairing_response(stored.session(), tree);
        pairing_sessions.erase(stored.unique_id());
      }
      return false;
    }

    // ensure pin is 4 digits
    if (pin.size() != 4) {
      tree.put("root.paired", 0);
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put(
        "root.<xmlattr>.status_message",
        std::format("Pin must be 4 digits, {} provided", pin.size())
      );
      if (session_exhausted) {
        write_held_pairing_response(stored.session(), tree);
        pairing_sessions.erase(stored.unique_id());
      }
      return false;
    }

    // ensure all pin characters are numeric
    if (!std::all_of(pin.begin(), pin.end(), [](unsigned char character) {
          return std::isdigit(character) != 0;
        })) {
      tree.put("root.paired", 0);
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "Pin must be numeric");
      if (session_exhausted) {
        write_held_pairing_response(stored.session(), tree);
        pairing_sessions.erase(stored.unique_id());
      }
      return false;
    }

    auto &sess = stored.session();
    getservercert(sess, tree, pin);
    sess.client.name = name;

    // response to the request for pin
    if (!write_held_pairing_response(sess, tree)) {
      pairing_sessions.erase(stored.unique_id());
      return false;
    }

    // response to the current request
    return true;
  }

  std::vector<pairing_session_manager_t::pending_request_t> pending_pairing_requests() {
    return pairing_sessions.pending_requests();
  }

  bool cancel_pairing_request(std::string_view request_id) {
    if (!is_valid_pairing_hex(request_id, PAIRING_REQUEST_ID_HEX_BYTES, PAIRING_REQUEST_ID_HEX_BYTES)) {
      return false;
    }
    return pairing_sessions.cancel_by_request_id(request_id);
  }

#ifdef SUNSHINE_TESTS
  pairing_session_manager_t &pairing_sessions_for_tests() {
    return pairing_sessions;
  }

  std::string legacy_pair_challenge_xml_for_tests() {
    return serialize_legacy_xml(build_pair_challenge_tree());
  }

  std::string legacy_applist_xml_for_tests(
    const std::vector<std::pair<std::string, std::string>> &apps,
    bool hdr_supported
  ) {
    return serialize_legacy_xml(build_applist_tree(apps, hdr_supported));
  }

  std::string legacy_launch_xml_for_tests(std::string_view session_url) {
    return serialize_legacy_xml(build_launch_tree(session_url));
  }

  std::string legacy_resume_xml_for_tests(std::string_view session_url) {
    return serialize_legacy_xml(build_resume_tree(session_url));
  }

  std::string legacy_cancel_xml_for_tests() {
    return serialize_legacy_xml(build_cancel_tree());
  }

  std::string_view legacy_appasset_content_type_for_tests() {
    return LEGACY_APP_ASSET_CONTENT_TYPE;
  }

  std::string legacy_query_log_value_for_tests(std::string_view name, std::string_view value) {
    return query_log_value(name, value);
  }

  void reset_paired_clients_for_tests() {
    std::lock_guard lock {paired_clients.mutex};
    paired_clients.clients = {};
  }

  bool upsert_paired_client_for_tests(
    std::string name,
    std::string uuid,
    std::string certificate,
    bool enabled
  ) {
    std::lock_guard lock {paired_clients.mutex};
    auto candidate = paired_clients.clients;
    auto &clients = candidate.named_devices;
    auto existing = std::ranges::find(clients, uuid, &named_cert_t::uuid);
    if (existing == clients.end()) {
      clients.push_back({std::move(name), std::move(uuid), std::move(certificate), enabled});
    } else {
      existing->name = std::move(name);
      existing->cert = std::move(certificate);
      existing->enabled = enabled;
    }
    return commit_client_state(std::move(candidate));
  }

  bool paired_client_enabled_for_tests(std::string_view certificate) {
    std::lock_guard lock {paired_clients.mutex};
    const auto &clients = paired_clients.clients.named_devices;
    const auto existing = std::ranges::find(clients, certificate, &named_cert_t::cert);
    return existing != clients.end() && existing->enabled;
  }

  std::string legacy_pairing_source_xml_for_tests(const boost::asio::ip::address &address) {
    return is_trusted_pairing_source(address) ? std::string {} : serialize_legacy_xml(build_untrusted_pairing_source_tree());
  }

  std::string verified_transport_certificate_for_tests(const SunshineHTTPS &transport) {
    return registry_allows_certificate(transport.verified_client_certificate()) ? transport.verified_client_certificate() : std::string {};
  }
#endif

  /**
   * @brief Get codec mode flags.
   *
   * @return Moonlight codec capability bitmask for the currently probed encoders.
   */
  uint32_t get_codec_mode_flags() {
    uint32_t codec_mode_flags = SCM_H264;
    if (video::last_encoder_probe_supported_yuv444_for_codec[0]) {
      codec_mode_flags |= SCM_H264_HIGH8_444;
    }
    if (video::active_hevc_mode >= 2) {
      codec_mode_flags |= SCM_HEVC;
      if (video::last_encoder_probe_supported_yuv444_for_codec[1]) {
        codec_mode_flags |= SCM_HEVC_REXT8_444;
      }
    }
    if (video::active_hevc_mode == 3 || video::active_hevc_mode == 5) {
      codec_mode_flags |= SCM_HEVC_MAIN10;
    }
    if ((video::active_hevc_mode == 4 || video::active_hevc_mode == 5) && video::last_encoder_probe_supported_yuv444_for_codec[1]) {
      codec_mode_flags |= SCM_HEVC_REXT10_444;
    }

    if (video::active_av1_mode >= 2) {
      codec_mode_flags |= SCM_AV1_MAIN8;
      if (video::last_encoder_probe_supported_yuv444_for_codec[2]) {
        codec_mode_flags |= SCM_AV1_HIGH8_444;
      }
    }
    if (video::active_av1_mode == 3 || video::active_av1_mode == 5) {
      codec_mode_flags |= SCM_AV1_MAIN10;
    }
    if ((video::active_av1_mode == 4 || video::active_av1_mode == 5) && video::last_encoder_probe_supported_yuv444_for_codec[2]) {
      codec_mode_flags |= SCM_AV1_HIGH10_444;
    }
    if (video::current_nvenc_lossless_capability(0)) {
      codec_mode_flags |= SCM_LUMEN_H264_LOSSLESS;
    }
    if (video::current_nvenc_lossless_capability(1)) {
      codec_mode_flags |= SCM_LUMEN_HEVC_LOSSLESS;
    }
    if (video::current_nvenc_lossless_capability(2)) {
      codec_mode_flags |= SCM_LUMEN_AV1_LOSSLESS;
    }
    return codec_mode_flags;
  }

  /**
   * @brief Build the GameStream server-info response.
   *
   * @param response HTTP response object to populate.
   * @param request HTTP request data from the client.
   */
  template<class T>
  void serverinfo(std::shared_ptr<typename SimpleWeb::ServerBase<T>::Response> response, std::shared_ptr<typename SimpleWeb::ServerBase<T>::Request> request) {
    print_req<T>(request);

    int pair_status = 0;
    if constexpr (std::is_same_v<SunshineHTTPS, T>) {
      auto args = request->parse_query_string();
      auto clientID = args.find("uniqueid"s);

      if (clientID != std::end(args)) {
        pair_status = 1;
      }
    }

    auto local_endpoint = request->local_endpoint();

    pt::ptree tree;

    tree.put("root.<xmlattr>.status_code", 200);
    tree.put("root.hostname", config::nvhttp.sunshine_name);

    tree.put("root.appversion", VERSION);
    tree.put("root.GfeVersion", GFE_VERSION);
    tree.put("root.uniqueid", http::unique_id);
    tree.put("root.HttpsPort", net::map_port(PORT_HTTPS));
    tree.put("root.ExternalPort", net::map_port(PORT_HTTP));
    tree.put("root.MaxLumaPixelsHEVC", video::active_hevc_mode > 1 ? "1869449984" : "0");

    // Only include the MAC address for requests sent from paired clients over HTTPS.
    // For HTTP requests, use a placeholder MAC address that Moonlight knows to ignore.
    if constexpr (std::is_same_v<SunshineHTTPS, T>) {
      tree.put("root.mac", platf::get_mac_address(net::addr_to_normalized_string(local_endpoint.address())));
    } else {
      tree.put("root.mac", "00:00:00:00:00:00");
    }

    // Moonlight clients track LAN IPv6 addresses separately from LocalIP which is expected to
    // always be an IPv4 address. If we return that same IPv6 address here, it will clobber the
    // stored LAN IPv4 address. To avoid this, we need to return an IPv4 address in this field
    // when we get a request over IPv6.
    //
    // HACK: We should return the IPv4 address of local interface here, but we don't currently
    // have that implemented. For now, we will emulate the behavior of GFE+GS-IPv6-Forwarder,
    // which returns 127.0.0.1 as LocalIP for IPv6 connections. Moonlight clients with IPv6
    // support know to ignore this bogus address.
    if (local_endpoint.address().is_v6() && !local_endpoint.address().to_v6().is_v4_mapped()) {
      tree.put("root.LocalIP", "127.0.0.1");
    } else {
      tree.put("root.LocalIP", net::addr_to_normalized_string(local_endpoint.address()));
    }

    const uint32_t codec_mode_flags = get_codec_mode_flags();
    tree.put("root.ServerCodecModeSupport", codec_mode_flags);

    if (!config::nvhttp.external_ip.empty()) {
      tree.put("root.ExternalIP", config::nvhttp.external_ip);
    }

    auto current_appid = proc::proc.running();
    tree.put("root.PairStatus", pair_status);
    tree.put("root.currentgame", current_appid);
    tree.put("root.state", current_appid > 0 ? "SUNSHINE_SERVER_BUSY" : "SUNSHINE_SERVER_FREE");

    std::ostringstream data;

    pt::write_xml(data, tree);
    response->write(data.str());
    response->close_connection_after_response = true;
  }

  nlohmann::json get_all_clients() {
    std::lock_guard lock {paired_clients.mutex};
    nlohmann::json named_cert_nodes = nlohmann::json::array();
    const client_t &client = paired_clients.clients;
    for (const auto &named_cert : client.named_devices) {
      nlohmann::json named_cert_node;
      named_cert_node["name"] = named_cert.name;
      named_cert_node["uuid"] = named_cert.uuid;
      named_cert_node["enabled"] = named_cert.enabled;
      named_cert_nodes.push_back(named_cert_node);
    }

    return named_cert_nodes;
  }

  /**
   * @brief Build the GameStream application list response.
   *
   * @param response HTTP response object to populate.
   * @param request HTTP request data from the client.
   */
  void applist(resp_https_t response, req_https_t request) {
    print_req<SunshineHTTPS>(request);

    pt::ptree tree;

    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_xml(data, tree);
      response->write(data.str());
      response->close_connection_after_response = true;
    });

    std::vector<std::pair<std::string, std::string>> app_entries;
    for (const auto &app : proc::proc.get_apps()) {
      app_entries.emplace_back(app.name, app.id);
    }
    tree = build_applist_tree(app_entries, video::active_hevc_mode >= 3);
  }

  /**
   * @brief Launch the requested application for a GameStream session.
   *
   * @param host_audio Host audio.
   * @param response HTTP response object to populate.
   * @param request HTTP request data from the client.
   */
  void launch(bool &host_audio, resp_https_t response, req_https_t request) {
    print_req<SunshineHTTPS>(request);

    pt::ptree tree;
    bool revert_display_configuration {false};
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      if (tree.empty()) {
        BOOST_LOG(error) << EMPTY_PROPERTY_TREE_ERROR_MSG;
      }

      pt::write_xml(data, tree);
      response->write(data.str());
      response->close_connection_after_response = true;

      if (revert_display_configuration) {
        display_device::revert_configuration();
      }
    });

    auto args = request->parse_query_string();
    if (
      args.find("rikey"s) == std::end(args) ||
      args.find("rikeyid"s) == std::end(args) ||
      args.find("localAudioPlayMode"s) == std::end(args) ||
      args.find("appid"s) == std::end(args)
    ) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "Missing a required launch parameter");

      return;
    }

    auto appid = util::from_view(get_arg(args, "appid"));

    auto current_appid = proc::proc.running();
    if (current_appid > 0) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "An app is already running on this host");

      return;
    }

    host_audio = util::from_view(get_arg(args, "localAudioPlayMode"));
    const auto client_certificate = verified_client_certificate(request);
    if (client_certificate.empty()) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 401);
      tree.put("root.<xmlattr>.status_message", "Missing authenticated client identity");
      return;
    }
    auto launch_session = make_launch_session(host_audio, args, client_certificate);

    if (rtsp_stream::session_count() == 0) {
      // The display should be restored in case something fails as there are no other sessions.
      revert_display_configuration = true;

      // We want to prepare display only if there are no active sessions at
      // the moment. This should be done before probing encoders as it could
      // change the active displays.
      display_device::configure_display(config::video, *launch_session);

      // Probe encoders again before streaming to ensure our chosen
      // encoder matches the active GPU (which could have changed
      // due to hotplugging, driver crash, primary monitor change,
      // or any number of other factors).
      if (video::probe_encoders()) {
        tree.put("root.<xmlattr>.status_code", 503);
        tree.put("root.<xmlattr>.status_message", "Failed to initialize video capture/encoding. Is a display connected and turned on?");
        tree.put("root.gamesession", 0);

        return;
      }
    }

    auto encryption_mode = net::encryption_mode_for_address(request->remote_endpoint().address());
    if (!launch_session->rtsp_cipher && encryption_mode == config::ENCRYPTION_MODE_MANDATORY) {
      BOOST_LOG(error) << "Rejecting client that cannot comply with mandatory encryption requirement"sv;

      tree.put("root.<xmlattr>.status_code", 403);
      tree.put("root.<xmlattr>.status_message", "Encryption is mandatory for this host but unsupported by the client");
      tree.put("root.gamesession", 0);

      return;
    }

    if (appid > 0) {
      auto err = proc::proc.execute((int) appid, launch_session);
      if (err) {
        tree.put("root.<xmlattr>.status_code", err);
        tree.put("root.<xmlattr>.status_message", "Failed to start the specified application");
        tree.put("root.gamesession", 0);

        return;
      }
    }

    tree = build_launch_tree(
      std::format(
        "{}{}:{}",
        launch_session->rtsp_url_scheme,
        net::addr_to_url_escaped_string(request->local_endpoint().address()),
        static_cast<int>(net::map_port(rtsp_stream::RTSP_SETUP_PORT))
      )
    );

    rtsp_stream::launch_session_raise(launch_session);

    // Stream was started successfully, we will revert the config when the app or session terminates
    revert_display_configuration = false;
  }

  /**
   * @brief Resume an existing GameStream session.
   *
   * @param host_audio Host audio.
   * @param response HTTP response object to populate.
   * @param request HTTP request data from the client.
   */
  void resume(bool &host_audio, resp_https_t response, req_https_t request) {
    print_req<SunshineHTTPS>(request);

    pt::ptree tree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      if (tree.empty()) {
        BOOST_LOG(error) << EMPTY_PROPERTY_TREE_ERROR_MSG;
      }

      pt::write_xml(data, tree);
      response->write(data.str());
      response->close_connection_after_response = true;
    });

    auto current_appid = proc::proc.running();
    if (current_appid == 0) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 503);
      tree.put("root.<xmlattr>.status_message", "No running app to resume");

      return;
    }

    auto args = request->parse_query_string();
    if (
      args.find("rikey"s) == std::end(args) ||
      args.find("rikeyid"s) == std::end(args)
    ) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "Missing a required resume parameter");

      return;
    }

    // Newer Moonlight clients send localAudioPlayMode on /resume too,
    // so we should use it if it's present in the args and there are
    // no active sessions we could be interfering with.
    const bool no_active_sessions {rtsp_stream::session_count() == 0};
    if (no_active_sessions && args.find("localAudioPlayMode"s) != std::end(args)) {
      host_audio = util::from_view(get_arg(args, "localAudioPlayMode"));
    }
    const auto client_certificate = verified_client_certificate(request);
    if (client_certificate.empty()) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 401);
      tree.put("root.<xmlattr>.status_message", "Missing authenticated client identity");
      return;
    }
    const auto launch_session = make_launch_session(host_audio, args, client_certificate);

    if (no_active_sessions) {
      // We want to prepare display only if there are no active sessions at
      // the moment. This should be done before probing encoders as it could
      // change the active displays.
      display_device::configure_display(config::video, *launch_session);

      // Probe encoders again before streaming to ensure our chosen
      // encoder matches the active GPU (which could have changed
      // due to hotplugging, driver crash, primary monitor change,
      // or any number of other factors).
      if (video::probe_encoders()) {
        tree.put("root.resume", 0);
        tree.put("root.<xmlattr>.status_code", 503);
        tree.put("root.<xmlattr>.status_message", "Failed to initialize video capture/encoding. Is a display connected and turned on?");

        return;
      }
    }

    auto encryption_mode = net::encryption_mode_for_address(request->remote_endpoint().address());
    if (!launch_session->rtsp_cipher && encryption_mode == config::ENCRYPTION_MODE_MANDATORY) {
      BOOST_LOG(error) << "Rejecting client that cannot comply with mandatory encryption requirement"sv;

      tree.put("root.<xmlattr>.status_code", 403);
      tree.put("root.<xmlattr>.status_message", "Encryption is mandatory for this host but unsupported by the client");
      tree.put("root.gamesession", 0);

      return;
    }

    tree = build_resume_tree(
      std::format(
        "{}{}:{}",
        launch_session->rtsp_url_scheme,
        net::addr_to_url_escaped_string(request->local_endpoint().address()),
        static_cast<int>(net::map_port(rtsp_stream::RTSP_SETUP_PORT))
      )
    );

    rtsp_stream::launch_session_raise(launch_session);
  }

  /**
   * @brief Check whether cel.
   *
   * @param response HTTP response object to populate.
   * @param request HTTP request data from the client.
   */
  void cancel(resp_https_t response, req_https_t request) {
    print_req<SunshineHTTPS>(request);

    pt::ptree tree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_xml(data, tree);
      response->write(data.str());
      response->close_connection_after_response = true;
    });

    const auto client_certificate = verified_client_certificate(request);
    if (client_certificate.empty()) {
      tree.put("root.cancel", 0);
      tree.put("root.<xmlattr>.status_code", 401);
      tree.put("root.<xmlattr>.status_message", "Missing authenticated client identity");
      return;
    }

    tree = build_cancel_tree();
    const auto terminated = rtsp_stream::terminate_sessions_by_cert(client_certificate);
    if (terminated > 0 && !rtsp_stream::has_session_or_pending_launch()) {
      if (proc::proc.running() > 0) {
        proc::proc.terminate();
      }
      display_device::revert_configuration();
    }
  }

  /**
   * @brief Return an application asset requested by the client.
   *
   * @param response HTTP response object to populate.
   * @param request HTTP request data from the client.
   */
  void appasset(resp_https_t response, req_https_t request) {
    print_req<SunshineHTTPS>(request);

    auto args = request->parse_query_string();
    auto app_image = proc::proc.get_app_image((int) util::from_view(get_arg(args, "appid")));

    std::ifstream in(app_image, std::ios::binary);
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", LEGACY_APP_ASSET_CONTENT_TYPE);
    response->write(SimpleWeb::StatusCode::success_ok, in, headers);
    response->close_connection_after_response = true;
  }

  void setup(const std::string &pkey, const std::string &cert) {
    conf_intern.pkey = pkey;
    conf_intern.servercert = cert;
  }

  /**
   * @brief Check whether a paired client certificate is allowed to connect.
   *
   * @param cert_pem PEM-encoded client certificate to look up.
   * @return True when the client certificate belongs to an enabled device.
   */
  bool is_client_enabled(const std::string_view cert_pem);

  void start() {
    platf::set_thread_name("nvhttp");
    pairing_sessions.open();
    auto shutdown_event = mail::man->event<bool>(mail::shutdown);

    auto port_http = net::map_port(PORT_HTTP);
    auto port_https = net::map_port(PORT_HTTPS);
    auto address_family = net::af_from_enum_string(config::sunshine.address_family);

    bool clean_slate = config::sunshine.flags[config::flag::FRESH_STATE];

    if (!clean_slate) {
      load_state();
    }

    auto pkey = file_handler::read_file(config::nvhttp.pkey.c_str());
    auto cert = file_handler::read_file(config::nvhttp.cert.c_str());
    setup(pkey, cert);

    auto add_cert = std::make_shared<safe::queue_t<crypto::x509_t>>(30);

    // resume doesn't always get the parameter "localAudioPlayMode"
    // launch will store it in host_audio
    bool host_audio {};

    https_server_t https_server {config::nvhttp.cert, config::nvhttp.pkey};
    http_server_t http_server;

    // Verify certificates after establishing connection
    https_server.verify = [add_cert](SSL *ssl) -> std::optional<std::string> {
      crypto::x509_t x509 {
#if OPENSSL_VERSION_MAJOR >= 3
        SSL_get1_peer_certificate(ssl)
#else
        SSL_get_peer_certificate(ssl)
#endif
      };
      if (!x509) {
        BOOST_LOG(info) << "unknown -- denied"sv;
        return std::nullopt;
      }

      bool verified = false;

      auto fg = util::fail_guard([&]() {
        char subject_name[256];

        X509_NAME_oneline(X509_get_subject_name(x509.get()), subject_name, sizeof(subject_name));

        BOOST_LOG(debug) << subject_name << " -- "sv << (verified ? "verified"sv : "denied"sv);
      });

      while (add_cert->peek()) {
        char subject_name[256];

        auto cert = add_cert->pop();
        X509_NAME_oneline(X509_get_subject_name(cert.get()), subject_name, sizeof(subject_name));

        BOOST_LOG(debug) << "Added cert ["sv << subject_name << ']';
        // The synchronized registry already owns the exact paired certificate.
        // Drain this legacy handoff queue so repeated pairings remain bounded.
      }

      // Check if this client is enabled
      auto pem = crypto::pem(x509);
      if (!is_client_enabled(pem)) {
        BOOST_LOG(info) << "Client is disabled -- denied"sv;
        return std::nullopt;
      }

      verified = true;
      return pem;
    };

    https_server.on_verify_failed = [](resp_https_t resp, req_https_t req) {
      pt::ptree tree;
      auto g = util::fail_guard([&]() {
        std::ostringstream data;

        pt::write_xml(data, tree);
        resp->write(data.str());
        resp->close_connection_after_response = true;
      });

      tree.put("root.<xmlattr>.status_code"s, 401);
      tree.put("root.<xmlattr>.query"s, req->path);
      tree.put("root.<xmlattr>.status_message"s, "The client is not authorized. Certificate verification failed."s);
    };

    https_server.default_resource["GET"] = not_found<SunshineHTTPS>;
    https_server.resource["^/serverinfo$"]["GET"] = serverinfo<SunshineHTTPS>;
    https_server.resource["^/pair$"]["GET"] = [&add_cert](auto resp, auto req) {
      pair<SunshineHTTPS>(add_cert, resp, req);
    };
    https_server.resource["^/applist$"]["GET"] = applist;
    https_server.resource["^/appasset$"]["GET"] = appasset;
    https_server.resource["^/launch$"]["GET"] = [&host_audio](auto resp, auto req) {
      launch(host_audio, resp, req);
    };
    https_server.resource["^/resume$"]["GET"] = [&host_audio](auto resp, auto req) {
      resume(host_audio, resp, req);
    };
    https_server.resource["^/cancel$"]["GET"] = cancel;

    https_server.config.reuse_address = true;
    https_server.config.address = net::get_bind_address(address_family);
    https_server.config.port = port_https;
    https_server.config.max_request_streambuf_size = PAIRING_REQUEST_BUFFER_LIMIT;

    http_server.default_resource["GET"] = not_found<SimpleWeb::HTTP>;
    http_server.resource["^/serverinfo$"]["GET"] = serverinfo<SimpleWeb::HTTP>;
    http_server.resource["^/pair$"]["GET"] = [&add_cert](auto resp, auto req) {
      pair<SimpleWeb::HTTP>(add_cert, resp, req);
    };

    http_server.config.reuse_address = true;
    http_server.config.address = net::get_bind_address(address_family);
    http_server.config.port = port_http;
    http_server.config.max_request_streambuf_size = PAIRING_REQUEST_BUFFER_LIMIT;

    auto accept_and_run = [&](auto *http_server) {
      try {
        std::string name = "nvhttp::" + std::to_string(http_server->config.port);
        platf::set_thread_name(name);
        http_server->start();
      } catch (boost::system::system_error &err) {
        // It's possible the exception gets thrown after calling http_server->stop() from a different thread
        if (shutdown_event->peek()) {
          return;
        }

        BOOST_LOG(fatal) << "Couldn't start http server on ports ["sv << port_https << ", "sv << port_https << "]: "sv << err.what();
        shutdown_event->raise(true);
        return;
      }
    };
    std::jthread ssl {accept_and_run, &https_server};
    std::jthread tcp {accept_and_run, &http_server};
    std::jthread pairing_reaper {[](std::stop_token stop_token) {
      while (!stop_token.stop_requested()) {
        for (int interval = 0; interval < 10 && !stop_token.stop_requested(); ++interval) {
          std::this_thread::sleep_for(100ms);
        }
        if (!stop_token.stop_requested()) {
          pairing_sessions.cleanup_expired();
        }
      }
    }};

    // Wait for any event
    shutdown_event->view();

    pairing_reaper.request_stop();
    pairing_sessions.close();
    https_server.stop();
    http_server.stop();

    pairing_reaper.join();
    ssl.join();
    tcp.join();
  }

  bool erase_all_clients() {
    std::lock_guard lock {paired_clients.mutex};
    return commit_client_state(client_t {});
  }

  bool unpair_client(const std::string_view uuid) {
    return revoke_client(uuid).has_value();
  }

  std::optional<std::string> revoke_client(const std::string_view uuid) {
    std::lock_guard lock {paired_clients.mutex};
    client_t &client = paired_clients.clients;
    const auto existing = std::ranges::find(client.named_devices, uuid, &named_cert_t::uuid);
    if (existing == client.named_devices.end()) {
      return std::nullopt;
    }
    auto certificate = existing->cert;
    auto candidate = client;
    const auto candidate_existing = std::ranges::find(candidate.named_devices, uuid, &named_cert_t::uuid);
    candidate.named_devices.erase(candidate_existing);
    if (!commit_client_state(std::move(candidate))) {
      return std::nullopt;
    }
    return certificate;
  }

  bool set_client_enabled(const std::string_view uuid, bool enabled) {
    return set_client_enabled_with_certificate(uuid, enabled).has_value();
  }

  std::optional<std::string> set_client_enabled_with_certificate(const std::string_view uuid, bool enabled) {
    std::lock_guard lock {paired_clients.mutex};
    const client_t &client = paired_clients.clients;
    for (const auto &named_cert : client.named_devices) {
      if (named_cert.uuid == uuid) {
        auto certificate = named_cert.cert;
        auto candidate = client;
        const auto candidate_existing = std::ranges::find(candidate.named_devices, uuid, &named_cert_t::uuid);
        candidate_existing->enabled = enabled;
        if (!commit_client_state(std::move(candidate))) {
          return std::nullopt;
        }
        return certificate;
      }
    }
    return std::nullopt;
  }

  /**
   * @brief Get cert by UUID.
   */
  std::string get_cert_by_uuid(const std::string_view uuid) {
    std::lock_guard lock {paired_clients.mutex};
    for (const auto &named_cert : paired_clients.clients.named_devices) {
      if (named_cert.uuid == uuid) {
        return named_cert.cert;
      }
    }
    return {};
  }

  /**
   * @brief Check whether a paired client certificate is allowed to connect.
   */
  bool is_client_enabled(const std::string_view cert_pem) {
    return registry_allows_certificate(cert_pem);
  }
}  // namespace nvhttp
