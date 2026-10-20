/**
 * @file src/confighttp.cpp
 * @brief Lumen's administration server: the web panel and the `/api/v1` API it uses.
 *
 * One API covers both streaming protocols. Lumen devices and GameStream devices appear in one
 * device list, pairing requests from either protocol are answered in one place, and settings are
 * read and written as typed values rather than as a raw configuration file.
 *
 * Every API request must carry `X-Lumen-Request: 1`. Browsers cannot attach a custom header to a
 * cross-site request without a CORS preflight, which this server never approves, so the header
 * stops cross-site request forgery without per-form tokens. Sessions are HttpOnly cookies.
 */
#define BOOST_BIND_GLOBAL_PLACEHOLDERS

// standard includes
#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <limits>
#include <map>
#include <mutex>
#include <random>
#include <ranges>
#include <set>
#include <string_view>
#include <thread>

// lib includes
#include <boost/algorithm/string.hpp>
#include <boost/asio/buffers_iterator.hpp>
#include <boost/asio/streambuf.hpp>
#include <nlohmann/json.hpp>
#include <Simple-Web-Server/crypto.hpp>
#include <Simple-Web-Server/server_https.hpp>

// local includes
#include "config.h"
#include "confighttp.h"
#include "crypto.h"
#include "file_handler.h"
#include "globals.h"
#include "httpcommon.h"
#include "logging.h"
#include "network.h"
#include "nvhttp.h"
#include "platform/common.h"
#include "process.h"
#include "protocol_lsp/runtime/host_runtime.h"
#include "protocol_lsp/security/secure_zero.h"
#include "rtsp.h"
#include "utility.h"

using namespace std::literals;

namespace confighttp {
  namespace fs = std::filesystem;
  using json = nlohmann::json;
  using status_t = SimpleWeb::StatusCode;
  using headers_t = SimpleWeb::CaseInsensitiveMultimap;
  using https_handler_t = std::function<void(resp_https_t, req_https_t)>;

  login_throttle_t login_throttle;  ///< Failed sign-in budgets by source. NOSONAR(cpp:S5421) - intentionally mutable global

  login_throttle_t::login_throttle_t(
    const std::size_t maximum_sources,
    const std::size_t maximum_failures,
    const clock_t::duration failure_window
  ):
      maximum_sources_(maximum_sources),
      maximum_failures_(maximum_failures),
      failure_window_(failure_window) {
  }

  std::string login_throttle_t::source_key(boost::asio::ip::address address) {
    address = net::normalize_address(address);
    if (address.is_v4()) {
      return "v4:"s + address.to_string();
    }

    auto bytes = address.to_v6().to_bytes();
    std::fill(bytes.begin() + 8, bytes.end(), 0);
    return "v6:"s + boost::asio::ip::address_v6(bytes).to_string() + "/64"s;
  }

  void login_throttle_t::prune_expired(const clock_t::time_point now) {
    std::erase_if(sources_, [now](const auto &entry) {
      return entry.second.expiration <= now;
    });
  }

  bool login_throttle_t::is_blocked(const boost::asio::ip::address address, const clock_t::time_point now) {
    std::scoped_lock lock(mutex_);
    prune_expired(now);
    const auto source = sources_.find(source_key(address));
    return source != sources_.end() && source->second.failures >= maximum_failures_;
  }

  void login_throttle_t::record_failure(const boost::asio::ip::address address, const clock_t::time_point now) {
    std::scoped_lock lock(mutex_);
    prune_expired(now);

    const auto key = source_key(address);
    if (auto source = sources_.find(key); source != sources_.end()) {
      ++source->second.failures;
      return;
    }

    if (maximum_sources_ == 0) {
      return;
    }
    if (sources_.size() >= maximum_sources_) {
      const auto earliest = std::ranges::min_element(sources_, {}, [](const auto &entry) {
        return entry.second.expiration;
      });
      sources_.erase(earliest);
    }
    sources_.emplace(key, source_state_t {1, now + failure_window_});
  }

  void login_throttle_t::record_success(const boost::asio::ip::address address) {
    std::scoped_lock lock(mutex_);
    sources_.erase(source_key(address));
  }

  bool bootstrap_allowed(boost::asio::ip::address address) {
    return net::normalize_address(address).is_loopback();
  }

  namespace {
    using resp_t = resp_https_t;
    using req_t = req_https_t;

    // ---------------------------------------------------------------------------------------------
    // Responses

    /** @brief Headers every response carries. */
    headers_t base_headers(const std::string_view content_type) {
      return {
        {"Content-Type", std::string {content_type}},
        {"Cache-Control", "no-store"},
        {"X-Content-Type-Options", "nosniff"},
        {"X-Frame-Options", "DENY"},
        {"Referrer-Policy", "no-referrer"},
      };
    }

    void send_json(const resp_t &response, const status_t status, const json &body, headers_t extra = {}) {
      auto headers = base_headers("application/json");
      for (auto &[name, value] : extra) {
        headers.emplace(name, value);
      }
      response->write(status, body.dump(), headers);
    }

    void send_ok(const resp_t &response, const json &body) {
      send_json(response, status_t::success_ok, body);
    }

    void send_no_content(const resp_t &response, headers_t extra = {}) {
      auto headers = base_headers("text/plain");
      for (auto &[name, value] : extra) {
        headers.emplace(name, value);
      }
      response->write(status_t::success_no_content, headers);
    }

    /** @brief Send an error whose message the panel shows as is, so it must read as plain English. */
    void send_error(const resp_t &response, const status_t status, const std::string_view message) {
      send_json(response, status, {{"error", message}});
    }

    std::string body_of(const req_t &request) {
      return request->content.string();
    }

    /** @brief Parse a JSON object body; send 400 and return no value when it is not one. */
    std::optional<json> json_body(const resp_t &response, const req_t &request) {
      const auto content_type = request->header.find("Content-Type");
      if (content_type == request->header.end() || !boost::istarts_with(content_type->second, "application/json")) {
        send_error(response, status_t::client_error_unsupported_media_type, "Send JSON.");
        return std::nullopt;
      }
      auto body = json::parse(body_of(request), nullptr, false);
      if (!body.is_object()) {
        send_error(response, status_t::client_error_bad_request, "The request isn’t valid JSON.");
        return std::nullopt;
      }
      return body;
    }

    std::string remote_address(const req_t &request) {
      return net::addr_to_normalized_string(request->remote_endpoint().address());
    }

    // ---------------------------------------------------------------------------------------------
    // Sessions

    constexpr auto session_cookie = "lumen_session"sv;
    constexpr auto session_idle_lifetime = std::chrono::hours(12);
    constexpr std::size_t maximum_sessions = 32;

    struct session_t {
      std::string username;
      std::chrono::steady_clock::time_point expires;
    };

    std::mutex sessions_mutex;
    std::map<std::string, session_t, std::less<>> sessions;  ///< Session token to session.

    std::string cookie_header(const std::string_view token, const std::chrono::seconds max_age) {
      return std::format("{}={}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Strict", session_cookie, token, max_age.count());
    }

    std::string create_session(const std::string &username) {
      constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
      auto token = crypto::rand_alphabet(43, alphabet);
      std::scoped_lock lock(sessions_mutex);
      const auto now = std::chrono::steady_clock::now();
      std::erase_if(sessions, [now](const auto &entry) {
        return entry.second.expires <= now;
      });
      if (sessions.size() >= maximum_sessions) {
        sessions.erase(std::ranges::min_element(sessions, {}, [](const auto &entry) {
          return entry.second.expires;
        }));
      }
      sessions.emplace(token, session_t {username, now + session_idle_lifetime});
      return token;
    }

    std::optional<std::string> session_token(const req_t &request) {
      const auto cookie = request->header.find("Cookie");
      if (cookie == request->header.end()) {
        return std::nullopt;
      }
      for (const auto part : std::views::split(std::string_view {cookie->second}, ';')) {
        auto pair = std::string_view {part.begin(), part.end()};
        while (!pair.empty() && pair.front() == ' ') {
          pair.remove_prefix(1);
        }
        if (pair.starts_with(session_cookie) && pair.size() > session_cookie.size() && pair[session_cookie.size()] == '=') {
          return std::string {pair.substr(session_cookie.size() + 1)};
        }
      }
      return std::nullopt;
    }

    /** @brief Return the signed-in username, extending the session, or no value. */
    std::optional<std::string> session_user(const req_t &request) {
      const auto token = session_token(request);
      if (!token) {
        return std::nullopt;
      }
      std::scoped_lock lock(sessions_mutex);
      const auto session = sessions.find(*token);
      const auto now = std::chrono::steady_clock::now();
      if (session == sessions.end() || session->second.expires <= now) {
        return std::nullopt;
      }
      session->second.expires = now + session_idle_lifetime;
      return session->second.username;
    }

    void end_session(const req_t &request) {
      if (const auto token = session_token(request)) {
        std::scoped_lock lock(sessions_mutex);
        sessions.erase(*token);
      }
    }

    void end_all_sessions() {
      std::scoped_lock lock(sessions_mutex);
      sessions.clear();
    }

    // ---------------------------------------------------------------------------------------------
    // Admission

    /** @brief Reject sources outside the configured network scope. */
    bool admit_source(const resp_t &response, const req_t &request) {
      const auto address = remote_address(request);
      if (net::from_address(address) > http::origin_web_ui_allowed) {
        BOOST_LOG(info) << "Admin: ["sv << address << "] denied by origin_web_ui_allowed"sv;
        send_error(response, status_t::client_error_forbidden, "This PC doesn’t allow administration from your network.");
        return false;
      }
      return true;
    }

    /** @brief Admit an API request: allowed source and the anti-forgery header. */
    bool admit_api(const resp_t &response, const req_t &request) {
      if (!admit_source(response, request)) {
        return false;
      }
      const auto marker = request->header.find("X-Lumen-Request");
      if (marker == request->header.end() || marker->second != "1") {
        send_error(response, status_t::client_error_forbidden, "Missing X-Lumen-Request header.");
        return false;
      }
      return true;
    }

    /** @brief Admit an API request that needs a signed-in administrator. */
    bool admit_signed_in(const resp_t &response, const req_t &request) {
      if (!admit_api(response, request)) {
        return false;
      }
      if (!session_user(request)) {
        send_error(response, status_t::client_error_unauthorized, "Sign in to continue.");
        return false;
      }
      return true;
    }

    using handler_t = void (*)(const resp_t &, const req_t &);

    void run_handler(const handler_t handler, const resp_t &response, const req_t &request) {
      try {
        handler(response, request);
      } catch (const std::exception &failure) {
        BOOST_LOG(error) << "Admin: "sv << request->method << ' ' << request->path << " failed: "sv << failure.what();
        send_error(response, status_t::server_error_internal_server_error, "Lumen couldn’t complete that request.");
      }
    }

    /** @brief Wrap a handler so it runs only for signed-in requests and never throws into the server. */
    https_handler_t signed_in(const handler_t handler) {
      return [handler](const resp_t &response, const req_t &request) {
        if (admit_signed_in(response, request)) {
          run_handler(handler, response, request);
        }
      };
    }

    /** @brief Like signed_in, for reads the browser makes without the request header. */
    https_handler_t signed_in_read(const handler_t handler) {
      return [handler](const resp_t &response, const req_t &request) {
        if (!admit_source(response, request)) {
          return;
        }
        if (!session_user(request)) {
          send_error(response, status_t::client_error_unauthorized, "Sign in to continue.");
          return;
        }
        run_handler(handler, response, request);
      };
    }

    // ---------------------------------------------------------------------------------------------
    // Account

    bool credentials_match(const std::string &username, const std::string &password) {
      if (!boost::iequals(username, config::general.username)) {
        return false;
      }
      return http::verify_user_password(password, config::general.password, config::general.salt) !=
             http::password_verification_e::INVALID;
    }

    bool save_credentials(const std::string &username, const std::string &password) {
      http::user_credentials_t saved;
      if (http::save_user_creds(config::general.credentials_file, username, password, false, &saved) != 0) {
        return false;
      }
      config::general.username = std::move(saved.username);
      config::general.password = std::move(saved.password);
      config::general.salt = std::move(saved.salt);
      return true;
    }

    void sign_in_response(const resp_t &response, const std::string &username, const status_t status = status_t::success_ok) {
      const auto token = create_session(username);
      send_json(
        response,
        status,
        {{"username", username}},
        {{"Set-Cookie", cookie_header(token, std::chrono::duration_cast<std::chrono::seconds>(session_idle_lifetime))}}
      );
    }

    void get_setup(const resp_t &response, const req_t &request) {
      if (!admit_api(response, request)) {
        return;
      }
      send_ok(response, {{"required", config::general.username.empty()}});
    }

    void post_setup(const resp_t &response, const req_t &request) {
      if (!admit_api(response, request)) {
        return;
      }
      if (!config::general.username.empty()) {
        send_error(response, status_t::client_error_conflict, "Lumen already has an administrator.");
        return;
      }
      if (!bootstrap_allowed(request->remote_endpoint().address())) {
        send_error(response, status_t::client_error_forbidden, "Set up Lumen from a browser on this PC.");
        return;
      }
      const auto body = json_body(response, request);
      if (!body) {
        return;
      }
      const auto username = body->value("username", ""s);
      const auto password = body->value("password", ""s);
      if (username.empty() || password.empty()) {
        send_error(response, status_t::client_error_bad_request, "Enter a username and password.");
        return;
      }
      if (!save_credentials(username, password)) {
        send_error(response, status_t::server_error_internal_server_error, "The account wasn’t saved.");
        return;
      }
      BOOST_LOG(info) << "Admin: created administrator account"sv;
      sign_in_response(response, config::general.username, status_t::success_created);
    }

    void get_session(const resp_t &response, const req_t &request) {
      if (!admit_api(response, request)) {
        return;
      }
      const auto username = session_user(request);
      if (!username) {
        send_error(response, status_t::client_error_unauthorized, "Sign in to continue.");
        return;
      }
      send_ok(response, {{"username", *username}});
    }

    void post_session(const resp_t &response, const req_t &request) {
      if (!admit_api(response, request)) {
        return;
      }
      if (config::general.username.empty()) {
        send_error(response, status_t::client_error_conflict, "Create an administrator account first.");
        return;
      }
      const auto address = request->remote_endpoint().address();
      if (login_throttle.is_blocked(address)) {
        send_error(response, status_t::client_error_too_many_requests, "Too many attempts. Try again in a few minutes.");
        return;
      }
      const auto body = json_body(response, request);
      if (!body) {
        return;
      }
      const auto username = body->value("username", ""s);
      const auto password = body->value("password", ""s);
      const auto result = http::verify_user_password(password, config::general.password, config::general.salt);
      if (!boost::iequals(username, config::general.username) || result == http::password_verification_e::INVALID) {
        login_throttle.record_failure(address);
        BOOST_LOG(info) << "Admin: ["sv << remote_address(request) << "] sign-in failed"sv;
        send_error(response, status_t::client_error_unauthorized, "The username or password is incorrect.");
        return;
      }
      login_throttle.record_success(address);
      if (result == http::password_verification_e::LEGACY) {
        save_credentials(config::general.username, password);
      }
      sign_in_response(response, config::general.username);
    }

    void delete_session(const resp_t &response, const req_t &request) {
      if (!admit_api(response, request)) {
        return;
      }
      end_session(request);
      send_no_content(response, {{"Set-Cookie", cookie_header("", 0s)}});
    }

    void put_account(const resp_t &response, const req_t &request) {
      const auto body = json_body(response, request);
      if (!body) {
        return;
      }
      const auto current_password = body->value("currentPassword", ""s);
      const auto username = body->value("username", ""s);
      const auto password = body->value("password", ""s);
      if (!credentials_match(config::general.username, current_password)) {
        send_error(response, status_t::client_error_forbidden, "The current password is incorrect.");
        return;
      }
      if (username.empty() || password.empty()) {
        send_error(response, status_t::client_error_bad_request, "Enter a username and password.");
        return;
      }
      if (!save_credentials(username, password)) {
        send_error(response, status_t::server_error_internal_server_error, "The account wasn’t saved.");
        return;
      }
      // Other browsers signed in with the old credentials must sign in again.
      end_all_sessions();
      sign_in_response(response, config::general.username);
    }

    // ---------------------------------------------------------------------------------------------
    // Permissions and identifiers

    struct permission_name_t {
      lumen::lsp::Permission permission;
      std::string_view name;
    };

    constexpr std::array permission_names {
      permission_name_t {lumen::lsp::Permission::browse_applications, "browse"sv},
      permission_name_t {lumen::lsp::Permission::start_attach, "start"sv},
      permission_name_t {lumen::lsp::Permission::input, "input"sv},
      permission_name_t {lumen::lsp::Permission::microphone, "microphone"sv},
      permission_name_t {lumen::lsp::Permission::stop_own_stream, "stop"sv},
      permission_name_t {lumen::lsp::Permission::quit_application, "quit"sv},
      permission_name_t {lumen::lsp::Permission::controller_output, "controller-output"sv},
      permission_name_t {lumen::lsp::Permission::clipboard, "clipboard"sv},
    };

    json permission_list(const lumen::lsp::PermissionSet permissions) {
      auto list = json::array();
      for (const auto &[permission, name] : permission_names) {
        if ((permissions.mask() & static_cast<std::uint32_t>(permission)) != 0) {
          list.push_back(name);
        }
      }
      return list;
    }

    std::optional<lumen::lsp::PermissionSet> permissions_from(const json &list) {
      if (!list.is_array()) {
        return std::nullopt;
      }
      std::uint32_t mask = 0;
      for (const auto &entry : list) {
        if (!entry.is_string()) {
          return std::nullopt;
        }
        const auto match = std::ranges::find(permission_names, entry.get<std::string>(), &permission_name_t::name);
        if (match == permission_names.end()) {
          return std::nullopt;
        }
        mask |= static_cast<std::uint32_t>(match->permission);
      }
      return lumen::lsp::PermissionSet::from_mask(mask);
    }

    template<std::size_t Size>
    std::string to_hex(const std::array<std::uint8_t, Size> &bytes) {
      constexpr std::string_view digits = "0123456789abcdef";
      std::string encoded(bytes.size() * 2, '0');
      for (std::size_t index = 0; index < bytes.size(); ++index) {
        encoded[index * 2] = digits[bytes[index] >> 4U];
        encoded[index * 2 + 1] = digits[bytes[index] & 0x0fU];
      }
      return encoded;
    }

    std::optional<lumen::lsp::Identifier128> identifier_from_hex(const std::string_view encoded) {
      lumen::lsp::Identifier128 identifier {};
      if (encoded.size() != identifier.size() * 2) {
        return std::nullopt;
      }
      const auto nibble = [](const char value) -> int {
        if (value >= '0' && value <= '9') {
          return value - '0';
        }
        if (value >= 'a' && value <= 'f') {
          return value - 'a' + 10;
        }
        return -1;
      };
      for (std::size_t index = 0; index < identifier.size(); ++index) {
        const auto high = nibble(encoded[index * 2]);
        const auto low = nibble(encoded[index * 2 + 1]);
        if (high < 0 || low < 0) {
          return std::nullopt;
        }
        identifier[index] = static_cast<std::uint8_t>((high << 4) | low);
      }
      return lumen::lsp::is_zero(identifier) ? std::nullopt : std::optional {identifier};
    }

    std::uint64_t unix_seconds(const std::chrono::system_clock::time_point time) {
      return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(time.time_since_epoch()).count());
    }

    // ---------------------------------------------------------------------------------------------
    // Status

    std::atomic<bool> restart_required {false};  ///< Settings changed since this process started.

    void get_status(const resp_t &response, const req_t &) {
      const auto snapshot = lumen::lsp::runtime::administration_snapshot();
      json stream = nullptr;
      if (const auto running = proc::proc.running(); running > 0) {
        const auto &apps = proc::proc.get_apps();
        const auto app = std::ranges::find(apps, std::to_string(running), &proc::ctx_t::id);
        const auto started = proc::proc.started_at();
        stream = {
          {"appName", app == apps.end() ? proc::proc.get_last_run_app_name() : app->name},
          {"startedAt", started ? json(unix_seconds(*started)) : json(nullptr)},
        };
      }
      send_ok(response, {
                          {"hostName", config::nvhttp.host_name},
                          {"version", PROJECT_VERSION},
                          {"lsp",
                           {
                             {"enabled", config::lsp.enabled},
                             {"listening", snapshot && snapshot->active},
                             {"port", snapshot ? snapshot->port : config::lsp.port},
                           }},
                          {"stream", stream},
                          {"restartRequired", restart_required.load()},
                        });
    }

    void post_stream_stop(const resp_t &response, const req_t &) {
      proc::proc.terminate();
      send_no_content(response);
    }

    void post_restart(const resp_t &response, const req_t &) {
      send_no_content(response);
      // Give the response time to leave before the process restarts.
      std::thread([] {
        std::this_thread::sleep_for(300ms);
        platf::restart();
      }).detach();
    }

    // ---------------------------------------------------------------------------------------------
    // Pairing

    std::string_view pairing_state(const lumen::lsp::runtime::PairingAdministrationState state) {
      using lumen::lsp::runtime::PairingAdministrationState;
      switch (state) {
        case PairingAdministrationState::awaiting_pin:
          return "awaiting-pin"sv;
        case PairingAdministrationState::deriving:
          return "verifying"sv;
        case PairingAdministrationState::challenge_ready:
          return "ready"sv;
        case PairingAdministrationState::cooldown:
          return "cooldown"sv;
      }
      return "awaiting-pin"sv;
    }

    void get_pairing(const resp_t &response, const req_t &) {
      auto requests = json::array();
      for (const auto &pairing : lumen::lsp::runtime::administration_pending_pairings()) {
        requests.push_back({
          {"id", to_hex(pairing.pairing_session_id)},
          {"deviceName", pairing.client_name},
          {"nameVerified", pairing.client_name_verified},
          {"fingerprint", to_hex(pairing.identity_key_fingerprint)},
          {"permissions", permission_list(pairing.effective_permissions)},
          {"expiresAt", pairing.expires_at_utc_seconds},
          {"state", pairing_state(pairing.state)},
        });
      }
      send_ok(response, {{"requests", std::move(requests)}});
    }

    /** @brief Wipe the request buffer that carried a PIN, on every exit path. */
    class pin_body_guard_t {
    public:
      explicit pin_body_guard_t(req_t request) noexcept:
          request_ {std::move(request)} {
      }

      pin_body_guard_t(const pin_body_guard_t &) = delete;
      pin_body_guard_t &operator=(const pin_body_guard_t &) = delete;

      ~pin_body_guard_t() {
        auto *buffer = dynamic_cast<boost::asio::streambuf *>(request_->content.rdbuf());
        if (buffer == nullptr) {
          return;
        }
        const auto data = buffer->data();
        for (auto iterator = boost::asio::buffers_begin(data); iterator != boost::asio::buffers_end(data); ++iterator) {
          const_cast<char &>(*iterator) = 0;
        }
        buffer->consume(buffer->size());
      }

    private:
      req_t request_;
    };

    void post_pairing_pin(const resp_t &response, const req_t &request) {
      pin_body_guard_t guard {request};
      const auto session_id = identifier_from_hex(request->path_match[1].str());
      if (!session_id) {
        send_error(response, status_t::client_error_not_found, "That pairing request has ended.");
        return;
      }
      std::array<std::uint8_t, 6> digits {};
      auto wipe = util::fail_guard([&digits] {
        lumen::lsp::secure_zero(digits);
      });
      {
        auto *buffer = dynamic_cast<boost::asio::streambuf *>(request->content.rdbuf());
        if (buffer == nullptr || buffer->size() != digits.size()) {
          send_error(response, status_t::client_error_bad_request, "Enter the six-digit PIN.");
          return;
        }
        const auto data = buffer->data();
        auto iterator = boost::asio::buffers_begin(data);
        for (auto &digit : digits) {
          const auto character = *iterator++;
          if (character < '0' || character > '9') {
            send_error(response, status_t::client_error_bad_request, "Enter the six-digit PIN.");
            return;
          }
          digit = static_cast<std::uint8_t>(character);
        }
      }
      if (lumen::lsp::runtime::administration_submit_pairing_pin(*session_id, digits) == 0) {
        send_error(response, status_t::client_error_conflict, "That pairing request has ended or isn’t ready for a PIN.");
        return;
      }
      send_no_content(response);
    }

    void delete_pairing(const resp_t &response, const req_t &request) {
      const auto session_id = identifier_from_hex(request->path_match[1].str());
      if (!session_id || !lumen::lsp::runtime::administration_cancel_pairing(*session_id)) {
        send_error(response, status_t::client_error_not_found, "That pairing request has already ended.");
        return;
      }
      send_no_content(response);
    }

    void post_pairing_gamestream(const resp_t &response, const req_t &request) {
      const auto body = json_body(response, request);
      if (!body) {
        return;
      }
      auto pin = body->value("pin", ""s);
      auto name = body->value("name", ""s);
      auto wipe = util::fail_guard([&pin] {
        lumen::lsp::secure_zero(std::span<char> {pin.data(), pin.size()});
      });
      if (pin.size() != 4 || !std::ranges::all_of(pin, [](const char c) {
            return c >= '0' && c <= '9';
          })) {
        send_error(response, status_t::client_error_bad_request, "Enter the four-digit PIN shown on the device.");
        return;
      }
      if (name.empty()) {
        name = "GameStream device";
      }
      if (!nvhttp::pin(pin, name)) {
        send_error(response, status_t::client_error_conflict, "No GameStream device is waiting to pair. Start pairing on the device, then try again.");
        return;
      }
      send_no_content(response);
    }

    // ---------------------------------------------------------------------------------------------
    // Devices

    json lsp_device(const lumen::lsp::runtime::TrustedClientSummary &client) {
      return {
        {"id", to_hex(client.client_id)},
        {"protocol", "lsp"},
        {"name", client.name.empty() ? "Unnamed device"s : client.name},
        {"enabled", client.enabled},
        {"permissions", permission_list(client.permissions)},
      };
    }

    std::optional<lumen::lsp::runtime::TrustedClientSummary> find_lsp_device(const lumen::lsp::Identifier128 &id) {
      for (auto &client : lumen::lsp::runtime::administration_trusted_clients()) {
        if (client.client_id == id) {
          return client;
        }
      }
      return std::nullopt;
    }

    std::optional<json> find_gamestream_device(const std::string_view uuid) {
      for (const auto &client : nvhttp::get_all_clients()) {
        if (client.value("uuid", ""s) == uuid) {
          return json {
            {"id", client.value("uuid", ""s)},
            {"protocol", "gamestream"},
            {"name", client.value("name", ""s)},
            {"enabled", client.value("enabled", true)},
            {"permissions", nullptr},
          };
        }
      }
      return std::nullopt;
    }

    void get_devices(const resp_t &response, const req_t &) {
      auto devices = json::array();
      for (const auto &client : lumen::lsp::runtime::administration_trusted_clients()) {
        devices.push_back(lsp_device(client));
      }
      for (const auto &client : nvhttp::get_all_clients()) {
        if (auto device = find_gamestream_device(client.value("uuid", ""s))) {
          devices.push_back(std::move(*device));
        }
      }
      send_ok(response, {{"devices", std::move(devices)}});
    }

    /** @brief End a GameStream device's sessions after its access was removed or disabled. */
    void end_gamestream_sessions(const std::string &certificate) {
      rtsp_stream::terminate_sessions_by_cert(certificate);
      if (!rtsp_stream::has_session_or_pending_launch() && proc::proc.running() > 0) {
        proc::proc.terminate_if_owned_by_certificate(certificate);
      }
    }

    void patch_device(const resp_t &response, const req_t &request) {
      const auto protocol = request->path_match[1].str();
      const auto id = request->path_match[2].str();
      const auto body = json_body(response, request);
      if (!body) {
        return;
      }
      const auto name = body->contains("name") && (*body)["name"].is_string() ? std::optional {(*body)["name"].get<std::string>()} : std::nullopt;
      const auto enabled = body->contains("enabled") && (*body)["enabled"].is_boolean() ? std::optional {(*body)["enabled"].get<bool>()} : std::nullopt;
      if (name && (name->empty() || name->size() > 64)) {
        send_error(response, status_t::client_error_bad_request, "Names must be 1 to 64 characters.");
        return;
      }

      if (protocol == "lsp") {
        const auto client_id = identifier_from_hex(id);
        const auto current = client_id ? find_lsp_device(*client_id) : std::nullopt;
        if (!current) {
          send_error(response, status_t::client_error_not_found, "That device is no longer paired.");
          return;
        }
        auto permissions = current->permissions;
        if (body->contains("permissions")) {
          const auto requested = permissions_from((*body)["permissions"]);
          if (!requested) {
            send_error(response, status_t::client_error_bad_request, "A device needs at least one permission.");
            return;
          }
          permissions = *requested;
        }
        const bool access_changed = permissions != current->permissions || (enabled && *enabled != current->enabled);
        if (access_changed &&
            !lumen::lsp::runtime::administration_update_trusted_client(*client_id, permissions, enabled.value_or(current->enabled))) {
          send_error(response, status_t::server_error_internal_server_error, "The change wasn’t saved.");
          return;
        }
        if (name && !lumen::lsp::runtime::administration_rename_trusted_client(*client_id, *name)) {
          send_error(response, status_t::server_error_internal_server_error, "The name wasn’t saved.");
          return;
        }
        send_ok(response, lsp_device(*find_lsp_device(*client_id)));
        return;
      }

      if (!find_gamestream_device(id)) {
        send_error(response, status_t::client_error_not_found, "That device is no longer paired.");
        return;
      }
      if (enabled) {
        const auto certificate = nvhttp::set_client_enabled_with_certificate(id, *enabled);
        if (!certificate) {
          send_error(response, status_t::server_error_internal_server_error, "The change wasn’t saved.");
          return;
        }
        if (!*enabled) {
          end_gamestream_sessions(*certificate);
        }
      }
      if (name && !nvhttp::rename_client(id, *name)) {
        send_error(response, status_t::server_error_internal_server_error, "The name wasn’t saved.");
        return;
      }
      send_ok(response, *find_gamestream_device(id));
    }

    void delete_device(const resp_t &response, const req_t &request) {
      const auto protocol = request->path_match[1].str();
      const auto id = request->path_match[2].str();
      if (protocol == "lsp") {
        const auto client_id = identifier_from_hex(id);
        if (!client_id || !lumen::lsp::runtime::administration_revoke_trusted_client(*client_id)) {
          send_error(response, status_t::client_error_not_found, "That device is no longer paired.");
          return;
        }
        send_no_content(response);
        return;
      }
      const auto certificate = nvhttp::revoke_client(id);
      if (!certificate) {
        send_error(response, status_t::client_error_not_found, "That device is no longer paired.");
        return;
      }
      end_gamestream_sessions(*certificate);
      send_no_content(response);
    }

    // ---------------------------------------------------------------------------------------------
    // Apps
    //
    // Apps live in apps.json. Each entry stores a stable numeric "id" so renaming an app or
    // changing its image doesn't change the ID clients cached. Files written before IDs were
    // stored get the IDs clients already know, the ones Lumen derived when it loaded them.

    std::mutex apps_mutex;  ///< Serializes read-modify-write of apps.json.

    json read_apps_file() {
      auto file = json::parse(file_handler::read_file(config::stream.file_apps.c_str()), nullptr, false);
      if (!file.is_object()) {
        file = json::object();
      }
      if (!file.contains("apps") || !file["apps"].is_array()) {
        file["apps"] = json::array();
      }
      if (!file.contains("env") || !file["env"].is_object()) {
        file["env"] = json::object();
      }
      return file;
    }

    void write_apps_file(const json &file) {
      if (file_handler::write_file(config::stream.file_apps.c_str(), file.dump(2)) != 0) {
        throw std::runtime_error("couldn't write apps.json");
      }
      proc::refresh(config::stream.file_apps);
    }

    std::string new_app_id(const json &apps) {
      std::set<std::string> used;
      for (const auto &app : apps) {
        used.insert(app.value("id", ""s));
      }
      std::random_device device;
      std::uniform_int_distribution<std::int32_t> distribution {1, std::numeric_limits<std::int32_t>::max()};
      for (;;) {
        if (auto id = std::to_string(distribution(device)); !used.contains(id)) {
          return id;
        }
      }
    }

    /** @brief Load apps.json and persist an ID for any app that lacks one. */
    json load_apps() {
      auto file = read_apps_file();
      auto &apps = file["apps"];
      const auto &loaded = proc::proc.get_apps();
      bool changed = false;
      for (std::size_t index = 0; index < apps.size(); ++index) {
        auto &app = apps[index];
        if (app.contains("id") && app["id"].is_string() && proc::is_valid_app_id(app["id"].get<std::string>())) {
          continue;
        }
        app["id"] = loaded.size() == apps.size() ? loaded[index].id : new_app_id(apps);
        changed = true;
      }
      if (changed) {
        write_apps_file(file);
      }
      return file;
    }

    json app_json(const json &stored) {
      const auto id = stored.value("id", ""s);
      const auto &loaded = proc::proc.get_apps();
      const auto app = std::ranges::find(loaded, id, &proc::ctx_t::id);
      auto kind = "app"sv;
      bool has_image = false;
      if (app != loaded.end()) {
        switch (proc::app_kind(*app)) {
          case proc::app_kind_e::desktop:
            kind = "desktop"sv;
            break;
          case proc::app_kind_e::steam:
            kind = "steam"sv;
            break;
          case proc::app_kind_e::app:
            break;
        }
        has_image = proc::custom_image_path(*app).has_value();
      }
      auto prep = json::array();
      for (const auto &command : stored.value("prep-cmd", json::array())) {
        prep.push_back({
          {"do", command.value("do", ""s)},
          {"undo", command.value("undo", ""s)},
          {"elevated", command.value("elevated", false)},
        });
      }
      return {
        {"id", id},
        {"name", stored.value("name", ""s)},
        {"kind", kind},
        {"command", stored.value("cmd", ""s)},
        {"workingDirectory", stored.value("working-dir", ""s)},
        {"hasImage", has_image},
        {"prepCommands", std::move(prep)},
        {"detachedCommands", stored.value("detached", json::array())},
        {"elevated", stored.value("elevated", false)},
        {"autoDetach", stored.value("auto-detach", true)},
        {"waitAll", stored.value("wait-all", true)},
        {"exitTimeoutSeconds", stored.value("exit-timeout", 5)},
        {"excludeGlobalPrepCommands", stored.value("exclude-global-prep-cmd", false)},
        {"running", proc::proc.running() > 0 && std::to_string(proc::proc.running()) == id},
      };
    }

    /** @brief Copy an API app into its stored form, keeping stored keys the API doesn't manage. */
    std::optional<std::string> apply_app_input(const json &input, json &stored) {
      const auto string_field = [&](const char *name) -> std::optional<std::string> {
        return input.contains(name) && input[name].is_string() ? std::optional {input[name].get<std::string>()} : std::nullopt;
      };
      const auto name = string_field("name");
      if (!name || boost::trim_copy(*name).empty()) {
        return "Enter a name."s;
      }
      stored["name"] = boost::trim_copy(*name);
      stored["cmd"] = string_field("command").value_or("");
      stored["working-dir"] = string_field("workingDirectory").value_or("");
      auto prep = json::array();
      for (const auto &command : input.value("prepCommands", json::array())) {
        if (!command.is_object()) {
          return "A preparation command isn’t valid."s;
        }
        prep.push_back({
          {"do", command.value("do", ""s)},
          {"undo", command.value("undo", ""s)},
          {"elevated", command.value("elevated", false)},
        });
      }
      stored["prep-cmd"] = std::move(prep);
      auto detached = json::array();
      for (const auto &command : input.value("detachedCommands", json::array())) {
        if (!command.is_string()) {
          return "A background command isn’t valid."s;
        }
        if (!command.get<std::string>().empty()) {
          detached.push_back(command);
        }
      }
      stored["detached"] = std::move(detached);
      stored["elevated"] = input.value("elevated", false);
      stored["auto-detach"] = input.value("autoDetach", true);
      stored["wait-all"] = input.value("waitAll", true);
      const auto timeout = input.value("exitTimeoutSeconds", 5);
      if (timeout < 0 || timeout > 3600) {
        return "The exit timeout must be 0 to 3600 seconds."s;
      }
      stored["exit-timeout"] = timeout;
      stored["exclude-global-prep-cmd"] = input.value("excludeGlobalPrepCommands", false);
      return std::nullopt;
    }

    json *find_stored_app(json &file, const std::string &id) {
      for (auto &app : file["apps"]) {
        if (app.value("id", ""s) == id) {
          return &app;
        }
      }
      return nullptr;
    }

    void get_apps(const resp_t &response, const req_t &) {
      std::scoped_lock lock(apps_mutex);
      const auto file = load_apps();
      auto apps = json::array();
      for (const auto &app : file["apps"]) {
        apps.push_back(app_json(app));
      }
      send_ok(response, {{"apps", std::move(apps)}});
    }

    void post_app(const resp_t &response, const req_t &request) {
      const auto body = json_body(response, request);
      if (!body) {
        return;
      }
      std::scoped_lock lock(apps_mutex);
      auto file = load_apps();
      json stored = json::object();
      if (const auto problem = apply_app_input(*body, stored)) {
        send_error(response, status_t::client_error_bad_request, *problem);
        return;
      }
      stored["id"] = new_app_id(file["apps"]);
      file["apps"].push_back(stored);
      write_apps_file(file);
      send_json(response, status_t::success_created, app_json(stored));
    }

    void put_app(const resp_t &response, const req_t &request) {
      const auto body = json_body(response, request);
      if (!body) {
        return;
      }
      std::scoped_lock lock(apps_mutex);
      auto file = load_apps();
      auto *stored = find_stored_app(file, request->path_match[1].str());
      if (stored == nullptr) {
        send_error(response, status_t::client_error_not_found, "That app was removed.");
        return;
      }
      if (const auto problem = apply_app_input(*body, *stored)) {
        send_error(response, status_t::client_error_bad_request, *problem);
        return;
      }
      const auto updated = *stored;
      write_apps_file(file);
      send_ok(response, app_json(updated));
    }

    fs::path covers_directory() {
      return platf::appdata() / "covers";
    }

    /** @brief Delete an image file only if Lumen created it for an app. */
    void remove_owned_image(const std::string &image_path) {
      if (image_path.empty()) {
        return;
      }
      std::error_code error;
      const auto image = fs::weakly_canonical(image_path, error);
      if (!error && image.parent_path() == fs::weakly_canonical(covers_directory(), error) && !error) {
        fs::remove(image, error);
      }
    }

    void delete_app(const resp_t &response, const req_t &request) {
      std::scoped_lock lock(apps_mutex);
      auto file = load_apps();
      auto &apps = file["apps"];
      const auto id = request->path_match[1].str();
      const auto app = std::ranges::find_if(apps, [&id](const json &candidate) {
        return candidate.value("id", ""s) == id;
      });
      if (app == apps.end()) {
        send_error(response, status_t::client_error_not_found, "That app was already removed.");
        return;
      }
      const auto image = app->value("image-path", ""s);
      apps.erase(app);
      write_apps_file(file);
      remove_owned_image(image);
      send_no_content(response);
    }

    void get_app_image(const resp_t &response, const req_t &request) {
      const auto id = request->path_match[1].str();
      const auto &loaded = proc::proc.get_apps();
      const auto app = std::ranges::find(loaded, id, &proc::ctx_t::id);
      const auto image = app == loaded.end() ? std::nullopt : proc::custom_image_path(*app);
      std::ifstream file;
      if (image) {
        file.open(*image, std::ios::binary);
      }
      if (!file) {
        send_error(response, status_t::client_error_not_found, "This app has no image.");
        return;
      }
      auto headers = base_headers("image/png");
      headers.erase("Cache-Control");
      headers.emplace("Cache-Control", "no-cache");
      response->write(status_t::success_ok, file, headers);
    }

    void put_app_image(const resp_t &response, const req_t &request) {
      const auto content_type = request->header.find("Content-Type");
      if (content_type == request->header.end() || !boost::iequals(content_type->second, "image/png")) {
        send_error(response, status_t::client_error_unsupported_media_type, "Choose a PNG image.");
        return;
      }
      const auto bytes = body_of(request);
      constexpr std::string_view png_signature = "\x89PNG\r\n\x1a\n";
      if (!bytes.starts_with(png_signature)) {
        send_error(response, status_t::client_error_bad_request, "Choose a PNG image.");
        return;
      }
      std::scoped_lock lock(apps_mutex);
      auto file = load_apps();
      const auto id = request->path_match[1].str();
      auto *stored = find_stored_app(file, id);
      if (stored == nullptr) {
        send_error(response, status_t::client_error_not_found, "That app was removed.");
        return;
      }
      std::error_code error;
      fs::create_directories(covers_directory(), error);
      const auto path = covers_directory() / ("app-" + id + ".png");
      {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        if (!out) {
          send_error(response, status_t::server_error_internal_server_error, "The image wasn’t saved.");
          return;
        }
      }
      const auto previous = stored->value("image-path", ""s);
      (*stored)["image-path"] = path.string();
      write_apps_file(file);
      if (previous != path.string()) {
        remove_owned_image(previous);
      }
      send_no_content(response);
    }

    void delete_app_image(const resp_t &response, const req_t &request) {
      std::scoped_lock lock(apps_mutex);
      auto file = load_apps();
      auto *stored = find_stored_app(file, request->path_match[1].str());
      if (stored == nullptr) {
        send_error(response, status_t::client_error_not_found, "That app was removed.");
        return;
      }
      const auto previous = stored->value("image-path", ""s);
      stored->erase("image-path");
      write_apps_file(file);
      remove_owned_image(previous);
      send_no_content(response);
    }

    // ---------------------------------------------------------------------------------------------
    // Settings
    //
    // Values are the configuration file's entries, typed by the matching default: a key whose
    // default is a boolean reads as a boolean. Writing null removes the entry, restoring the default.

    /** @brief Built-in values of the settings the panel presents; keys absent here are shown as text. */
    json setting_defaults() {
      return {
        {"host_name", platf::get_host_name()},
        {"system_tray", true},
        {"min_log_level", "info"},
        {"lsp_enabled", LUMEN_LSP_DEFAULT_ENABLED != 0},
        {"lsp_port", 48030},
        {"lsp_profile", "adaptive-low-latency"},
        {"lsp_competition_capacity_mbps", 0},
        {"port", 47989},
        {"address_family", "ipv4"},
        {"bind_address", ""},
        {"upnp", false},
        {"external_ip", ""},
        {"origin_web_ui_allowed", "lan"},
        {"encoder", ""},
        {"adapter_name", ""},
        {"output_name", ""},
        {"max_bitrate", 0},
        {"minimum_fps_target", 0},
        {"lumen_vdd_policy", "optional"},
        {"dd_configuration_option", "disabled"},
        {"dd_resolution_option", "auto"},
        {"dd_refresh_rate_option", "auto"},
        {"dd_hdr_option", "auto"},
        {"nvenc_preset", 1},
        {"nvenc_twopass", "quarter_res"},
        {"nvenc_spatial_aq", false},
        {"nvenc_latency_over_power", true},
        {"stream_audio", true},
        {"audio_sink", ""},
        {"virtual_sink", ""},
        {"client_microphone", false},
        {"client_microphone_sink", "steam"},
        {"keyboard", true},
        {"mouse", true},
        {"controller", true},
        {"gamepad_backend", "auto"},
        {"high_resolution_scrolling", true},
        {"native_pen_touch", true},
        {"key_rightalt_to_key_win", false},
      };
    }

    /** @brief Keys that hold credentials, key material, or file locations and are never exposed. */
    bool hidden_setting(const std::string_view key) {
      constexpr std::array hidden {
        "pkey"sv,
        "cert"sv,
        "file_state"sv,
        "credentials_file"sv,
        "file_apps"sv,
        "log_path"sv,
        "lsp_pairing_permissions"sv,
      };
      return std::ranges::find(hidden, key) != hidden.end();
    }

    json typed_value(const std::string &value, const json &default_value) {
      if (default_value.is_boolean()) {
        const auto lower = boost::to_lower_copy(value);
        return lower == "true" || lower == "yes" || lower == "enable" || lower == "enabled" || lower == "on" || lower == "1";
      }
      if (default_value.is_number()) {
        try {
          std::size_t used = 0;
          const auto number = std::stod(value, &used);
          if (used == value.size()) {
            return number == std::floor(number) ? json(static_cast<std::int64_t>(number)) : json(number);
          }
        } catch (const std::exception &) {
        }
      }
      return value;
    }

    std::map<std::string, std::string> read_settings_file() {
      std::map<std::string, std::string> settings;
      for (auto &[key, value] : config::parse_config(file_handler::read_file(config::general.config_file.c_str()))) {
        settings.emplace(key, std::move(value));
      }
      // Older files name the host "sunshine_name".
      if (const auto legacy = settings.find("sunshine_name"); legacy != settings.end()) {
        settings.try_emplace("host_name", legacy->second);
        settings.erase(legacy);
      }
      return settings;
    }

    json settings_json() {
      const auto defaults = setting_defaults();
      auto values = json::object();
      for (const auto &[key, value] : read_settings_file()) {
        if (!hidden_setting(key)) {
          values[key] = typed_value(value, defaults.contains(key) ? defaults[key] : json(""));
        }
      }
      return {{"values", std::move(values)}, {"defaults", defaults}};
    }

    void get_settings(const resp_t &response, const req_t &) {
      send_ok(response, settings_json());
    }

    void patch_settings(const resp_t &response, const req_t &request) {
      const auto body = json_body(response, request);
      if (!body) {
        return;
      }
      auto settings = read_settings_file();
      for (const auto &[key, value] : body->items()) {
        const bool valid_key = !key.empty() && key.size() <= 64 && std::ranges::all_of(key, [](const char c) {
          return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
        });
        if (!valid_key || hidden_setting(key)) {
          send_error(response, status_t::client_error_bad_request, std::format("“{}” can’t be changed here.", key));
          return;
        }
        if (value.is_null()) {
          settings.erase(key);
          continue;
        }
        std::string text;
        if (value.is_boolean()) {
          text = value.get<bool>() ? "enabled" : "disabled";
        } else if (value.is_number()) {
          text = value.dump();
        } else if (value.is_string()) {
          text = value.get<std::string>();
        } else {
          send_error(response, status_t::client_error_bad_request, std::format("“{}” needs a text, number, or on/off value.", key));
          return;
        }
        if (text.find_first_of("\r\n") != std::string::npos) {
          send_error(response, status_t::client_error_bad_request, std::format("“{}” must be on one line.", key));
          return;
        }
        if (text.empty()) {
          settings.erase(key);
        } else {
          settings[key] = std::move(text);
        }
      }
      std::string contents;
      for (const auto &[key, value] : settings) {
        contents += std::format("{} = {}\n", key, value);
      }
      if (file_handler::write_file(config::general.config_file.c_str(), contents) != 0) {
        send_error(response, status_t::server_error_internal_server_error, "The settings weren’t saved.");
        return;
      }
      restart_required = true;
      send_ok(response, settings_json());
    }

    void post_identity_rotate(const resp_t &response, const req_t &) {
      using lumen::lsp::runtime::IdentityRotationResult;
      const auto result = lumen::lsp::runtime::administration_rotate_identity();
      if (result == IdentityRotationResult::success) {
        send_no_content(response);
        return;
      }
      send_error(
        response,
        result == IdentityRotationResult::inactive ? status_t::client_error_conflict : status_t::server_error_internal_server_error,
        result == IdentityRotationResult::inactive ?
          "Lumen streaming is off, so there’s no certificate to replace." :
          "The certificate wasn’t replaced. The current one is still in use."
      );
    }

    // ---------------------------------------------------------------------------------------------
    // Logs

    constexpr std::uintmax_t maximum_log_chunk = 512 * 1024;

    void get_logs(const resp_t &response, const req_t &request) {
      const auto query = request->parse_query_string();
      std::uintmax_t after = 0;
      if (const auto parameter = query.find("after"); parameter != query.end()) {
        try {
          after = std::stoull(parameter->second);
        } catch (const std::exception &) {
          send_error(response, status_t::client_error_bad_request, "“after” must be a byte offset.");
          return;
        }
      }
      std::error_code error;
      const auto size = fs::file_size(config::general.log_file, error);
      if (error) {
        send_ok(response, {{"text", ""}, {"next", 0}});
        return;
      }
      // A smaller file means the log was replaced; start over. A first read starts near the end.
      if (after > size) {
        after = 0;
      }
      std::uintmax_t start = after;
      if (size - start > maximum_log_chunk) {
        start = size - maximum_log_chunk;
      }
      std::ifstream file(config::general.log_file, std::ios::binary);
      file.seekg(static_cast<std::streamoff>(start));
      std::string text(static_cast<std::size_t>(size - start), '\0');
      file.read(text.data(), static_cast<std::streamsize>(text.size()));
      text.resize(static_cast<std::size_t>(file.gcount()));
      if (start != after) {
        // Skipped ahead: drop the partial first line.
        if (const auto newline = text.find('\n'); newline != std::string::npos) {
          text.erase(0, newline + 1);
        }
      }
      send_ok(response, {{"text", text}, {"next", start + static_cast<std::uintmax_t>(file.gcount())}});
    }

    void get_logs_download(const resp_t &response, const req_t &) {
      std::ifstream file(config::general.log_file, std::ios::binary);
      if (!file) {
        send_error(response, status_t::client_error_not_found, "There’s no log yet.");
        return;
      }
      auto headers = base_headers("text/plain; charset=utf-8");
      headers.emplace("Content-Disposition", "attachment; filename=\"lumen.log\"");
      response->write(status_t::success_ok, file, headers);
    }

    // ---------------------------------------------------------------------------------------------
    // Panel files

    std::string_view content_type_for(const fs::path &path) {
      static const std::map<std::string, std::string_view, std::less<>> types {
        {".css", "text/css; charset=utf-8"},
        {".html", "text/html; charset=utf-8"},
        {".ico", "image/x-icon"},
        {".js", "text/javascript; charset=utf-8"},
        {".json", "application/json"},
        {".png", "image/png"},
        {".svg", "image/svg+xml"},
        {".woff2", "font/woff2"},
      };
      const auto type = types.find(boost::to_lower_copy(path.extension().string()));
      return type == types.end() ? "application/octet-stream"sv : type->second;
    }

    constexpr auto panel_security_policy =
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; "
      "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"sv;

    void send_file(const resp_t &response, const fs::path &path, const bool immutable) {
      std::ifstream file(path, std::ios::binary);
      if (!file) {
        send_error(response, status_t::client_error_not_found, "Not found.");
        return;
      }
      auto headers = base_headers(content_type_for(path));
      headers.erase("Cache-Control");
      headers.emplace("Cache-Control", immutable ? "public, max-age=31536000, immutable" : "no-cache");
      headers.emplace("Content-Security-Policy", std::string {panel_security_policy});
      response->write(status_t::success_ok, file, headers);
    }

    /** @brief Serve the panel; every panel route loads the same page, which routes in the browser. */
    void get_panel(const resp_t &response, const req_t &request) {
      if (!admit_source(response, request)) {
        return;
      }
      send_file(response, fs::path {WEB_DIR} / "index.html", false);
    }

    /** @brief Serve a built panel asset. File names carry content hashes, so they never change. */
    void get_panel_asset(const resp_t &response, const req_t &request) {
      if (!admit_source(response, request)) {
        return;
      }
      std::error_code error;
      const auto root = fs::weakly_canonical(fs::path {WEB_DIR} / "assets", error);
      const auto path = fs::weakly_canonical(fs::path {WEB_DIR} / fs::path {request->path}.relative_path(), error);
      const auto relative = fs::relative(path, root, error);
      if (error || relative.empty() || *relative.begin() == "..") {
        send_error(response, status_t::client_error_not_found, "Not found.");
        return;
      }
      send_file(response, path, true);
    }
  }  // namespace

  void start() {
    platf::set_thread_name("confighttp");
    const auto shutdown_event = mail::man->event<bool>(mail::shutdown);

    const auto port_https = net::map_port(PORT_HTTPS);
    const auto address_family = net::af_from_enum_string(config::general.address_family);

    https_server_t server {config::nvhttp.cert, config::nvhttp.pkey};

    const https_handler_t not_found = [](const resp_https_t &response, const req_https_t &) {
      send_error(response, status_t::client_error_not_found, "Not found.");
    };
    for (const auto method : {"GET", "POST", "PUT", "PATCH", "DELETE"}) {
      server.default_resource[method] = not_found;
    }

    auto &routes = server.resource;
    routes["^/api/v1/setup$"]["GET"] = get_setup;
    routes["^/api/v1/setup$"]["POST"] = post_setup;
    routes["^/api/v1/session$"]["GET"] = get_session;
    routes["^/api/v1/session$"]["POST"] = post_session;
    routes["^/api/v1/session$"]["DELETE"] = delete_session;
    routes["^/api/v1/account$"]["PUT"] = signed_in(put_account);

    routes["^/api/v1/status$"]["GET"] = signed_in(get_status);
    routes["^/api/v1/stream/stop$"]["POST"] = signed_in(post_stream_stop);
    routes["^/api/v1/restart$"]["POST"] = signed_in(post_restart);

    routes["^/api/v1/pairing$"]["GET"] = signed_in(get_pairing);
    routes["^/api/v1/pairing/gamestream$"]["POST"] = signed_in(post_pairing_gamestream);
    routes["^/api/v1/pairing/([0-9a-f]{32})/pin$"]["POST"] = signed_in(post_pairing_pin);
    routes["^/api/v1/pairing/([0-9a-f]{32})$"]["DELETE"] = signed_in(delete_pairing);

    routes["^/api/v1/devices$"]["GET"] = signed_in(get_devices);
    routes["^/api/v1/devices/(lsp|gamestream)/([0-9A-Za-z-]{1,64})$"]["PATCH"] = signed_in(patch_device);
    routes["^/api/v1/devices/(lsp|gamestream)/([0-9A-Za-z-]{1,64})$"]["DELETE"] = signed_in(delete_device);

    routes["^/api/v1/apps$"]["GET"] = signed_in(get_apps);
    routes["^/api/v1/apps$"]["POST"] = signed_in(post_app);
    routes["^/api/v1/apps/([0-9]{1,10})$"]["PUT"] = signed_in(put_app);
    routes["^/api/v1/apps/([0-9]{1,10})$"]["DELETE"] = signed_in(delete_app);
    // Images and the log download are loaded by <img> and links, which can't send the request
    // header. Both only read, so a session cookie is enough.
    routes["^/api/v1/apps/([0-9]{1,10})/image$"]["GET"] = signed_in_read(get_app_image);
    routes["^/api/v1/apps/([0-9]{1,10})/image$"]["PUT"] = signed_in(put_app_image);
    routes["^/api/v1/apps/([0-9]{1,10})/image$"]["DELETE"] = signed_in(delete_app_image);

    routes["^/api/v1/settings$"]["GET"] = signed_in(get_settings);
    routes["^/api/v1/settings$"]["PATCH"] = signed_in(patch_settings);
    routes["^/api/v1/identity/rotate$"]["POST"] = signed_in(post_identity_rotate);

    routes["^/api/v1/logs$"]["GET"] = signed_in(get_logs);
    routes["^/api/v1/logs/download$"]["GET"] = signed_in_read(get_logs_download);

    routes["^/(devices|apps|logs|settings(/[a-z]+)?)?/?$"]["GET"] = get_panel;
    routes["^/assets/.+$"]["GET"] = get_panel_asset;

    server.config.reuse_address = true;
    server.config.timeout_request = REQUEST_HEADER_TIMEOUT_SECONDS;
    server.config.timeout_content = REQUEST_BODY_TIMEOUT_SECONDS;
    server.config.max_request_streambuf_size = MAX_REQUEST_BODY_SIZE;
    server.config.reject_transfer_encoding = true;
    server.config.max_active_connections = MAX_ACTIVE_CONNECTIONS;
    server.config.max_active_connections_per_source = MAX_ACTIVE_CONNECTIONS_PER_SOURCE;
    server.config.address = net::get_bind_address(address_family);
    server.config.port = port_https;

    const auto display_address = config::general.bind_address.empty() ? "localhost"s : server.config.address;

    std::jthread tcp {[&] {
      try {
        platf::set_thread_name("confighttp::tcp");
        server.start([&display_address](const unsigned short port) {
          BOOST_LOG(info) << "Admin panel available at [https://"sv << display_address << ':' << port << ']';
        });
      } catch (const boost::system::system_error &failure) {
        // Stopping the server from another thread can surface here.
        if (shutdown_event->peek()) {
          return;
        }
        BOOST_LOG(fatal) << "Couldn't start the admin panel on port ["sv << port_https << "]: "sv << failure.what();
        shutdown_event->raise(true);
      }
    }};

    shutdown_event->view();
    server.stop();
  }
}  // namespace confighttp
