/**
 * @file src/confighttp.cpp
 * @brief Definitions for the Web UI Config HTTP server.
 *
 * @todo Authentication, better handling of routes common to nvhttp, cleanup
 */
#define BOOST_BIND_GLOBAL_PLACEHOLDERS

// standard includes
#include <algorithm>
#include <array>
#include <filesystem>
#include <format>
#include <fstream>
#include <limits>
#include <string_view>

// lib includes
#include <boost/algorithm/string.hpp>
#include <boost/asio/buffers_iterator.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/filesystem.hpp>
#include <nlohmann/json.hpp>
#include <Simple-Web-Server/crypto.hpp>
#include <Simple-Web-Server/server_https.hpp>

#ifdef _WIN32
  #include "platform/windows/misc.h"
  #include "platform/windows/virtual_display_status.h"

  #include <vector>
  #include <Windows.h>
#endif

// local includes
#include "config.h"
#include "confighttp.h"
#include "crypto.h"
#include "display_device.h"
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
#include "uuid.h"

using namespace std::literals;

namespace confighttp {
  namespace fs = std::filesystem;

  /**
   * @brief HTTPS server type used for Sunshine's configuration UI.
   */
  using https_server_t = SimpleWeb::Server<SimpleWeb::HTTPS>;

  /**
   * @brief Case-insensitive map used for HTTP headers and query parameters.
   */
  using args_t = SimpleWeb::CaseInsensitiveMultimap;
  /**
   * @brief Shared HTTPS response object passed to configuration handlers.
   */
  using resp_https_t = std::shared_ptr<SimpleWeb::ServerBase<SimpleWeb::HTTPS>::Response>;
  /**
   * @brief Shared HTTPS request object received by configuration handlers.
   */
  using req_https_t = std::shared_ptr<SimpleWeb::ServerBase<SimpleWeb::HTTPS>::Request>;
  /**
   * @brief Handler signature for configuration UI HTTPS routes.
   */
  using https_handler_t = std::function<void(resp_https_t, req_https_t)>;

  /**
   * @brief Client certificate operations accepted by the configuration API.
   */
  enum class op_e {
    ADD,  ///< Add client
    REMOVE  ///< Remove client
  };

  // CSRF token management
  /**
   * @brief CSRF token value and its expiration deadline.
   */
  struct csrf_token_t {
    std::string token;  ///< Random token value that must be echoed by the client.
    std::chrono::steady_clock::time_point expiration;  ///< Monotonic deadline after which the token is rejected.
  };

  std::map<std::string, csrf_token_t, std::less<>> csrf_tokens;  ///< CSRF tokens by client identifier. NOSONAR(cpp:S5421) - intentionally mutable global
  std::mutex csrf_tokens_mutex;  ///< Mutex protecting CSRF token storage. NOSONAR(cpp:S5421) - intentionally mutable global

  // CSRF token configuration
  /**
   * @brief Number of random bytes used when generating a CSRF token.
   */
  constexpr auto CSRF_TOKEN_SIZE = 32;  // 32 bytes = 256 bits
  /**
   * @brief Amount of time a generated CSRF token remains valid.
   */
  constexpr auto CSRF_TOKEN_LIFETIME = std::chrono::hours(1);  // Tokens valid for 1 hour

  login_throttle_t login_throttle;  ///< Process-local Web UI failed-login budgets. NOSONAR(cpp:S5421) - intentionally mutable global

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

  std::string_view request_log_value(const std::string_view name, const std::string_view value) {
    constexpr std::array sensitive_fields {
      "Authorization"sv,
      "Proxy-Authorization"sv,
      "Cookie"sv,
      "X-CSRF-Token"sv,
      "csrf_token"sv,
    };
    const bool sensitive = std::ranges::any_of(sensitive_fields, [name](const std::string_view candidate) {
      return boost::iequals(name, candidate);
    });
    return sensitive ? "[redacted]"sv : value;
  }

#ifdef SUNSHINE_TESTS
  void reset_login_throttle_for_tests() {
    login_throttle.record_success(boost::asio::ip::make_address("127.0.0.1"));
    login_throttle.record_success(boost::asio::ip::make_address("::1"));
  }
#endif

  /**
   * @brief Log the request details.
   * @param request The HTTP request object.
   */
  void print_req(const req_https_t &request) {
    BOOST_LOG(debug) << "METHOD :: "sv << request->method;
    BOOST_LOG(debug) << "DESTINATION :: "sv << request->path;

    for (auto &[name, val] : request->header) {
      BOOST_LOG(debug) << name << " -- " << request_log_value(name, val);
    }

    BOOST_LOG(debug) << " [--] "sv;

    for (auto &[name, val] : request->parse_query_string()) {
      BOOST_LOG(debug) << name << " -- " << request_log_value(name, val);
    }

    BOOST_LOG(debug) << " [--] "sv;
  }

  /**
   * @brief Send a response.
   * @param response The HTTP response object.
   * @param output_tree The JSON tree to send.
   */
  void send_response(const resp_https_t &response, const nlohmann::json &output_tree) {
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "application/json");
    headers.emplace("X-Frame-Options", "DENY");
    headers.emplace("Content-Security-Policy", "frame-ancestors 'none';");
    response->write(output_tree.dump(), headers);
  }

  /**
   * @brief Send a 401 Unauthorized response.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   */
  void send_unauthorized(const resp_https_t &response, const req_https_t &request) {
    auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
    BOOST_LOG(info) << "Web UI: ["sv << address << "] -- not authorized"sv;

    constexpr auto code = SimpleWeb::StatusCode::client_error_unauthorized;

    nlohmann::json tree;
    tree["status_code"] = code;
    tree["status"] = false;
    tree["error"] = "Unauthorized";

    const SimpleWeb::CaseInsensitiveMultimap headers {
      {"Content-Type", "application/json"},
      {"WWW-Authenticate", R"(Basic realm="Lumen GameStream Host", charset="UTF-8")"},
      {"X-Frame-Options", "DENY"},
      {"Content-Security-Policy", "frame-ancestors 'none';"}
    };

    response->write(code, tree.dump(), headers);
  }

  /**
   * @brief Send a redirect response.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * @param path The path to redirect to.
   */
  void send_redirect(const resp_https_t &response, const req_https_t &request, const char *path) {
    auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
    BOOST_LOG(info) << "Web UI: ["sv << address << "] -- not authorized"sv;
    const SimpleWeb::CaseInsensitiveMultimap headers {
      {"Location", path},
      {"X-Frame-Options", "DENY"},
      {"Content-Security-Policy", "frame-ancestors 'none';"}
    };
    response->write(SimpleWeb::StatusCode::redirection_temporary_redirect, headers);
  }

  /**
   * @brief Authenticate the user.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * @return True if the user is authenticated, false otherwise.
   */
  bool authenticate(const resp_https_t &response, const req_https_t &request) {
    const auto remote_address = request->remote_endpoint().address();
    const auto address = net::addr_to_normalized_string(remote_address);

    if (const auto ip_type = net::from_address(address); ip_type > http::origin_web_ui_allowed) {
      BOOST_LOG(info) << "Web UI: ["sv << address << "] -- denied"sv;
      response->write(SimpleWeb::StatusCode::client_error_forbidden);
      return false;
    }

    // If credentials are shown, redirect the user to a /welcome page
    if (config::sunshine.username.empty()) {
      send_redirect(response, request, "/welcome");
      return false;
    }

    if (login_throttle.is_blocked(remote_address)) {
      send_unauthorized(response, request);
      return false;
    }

    auto fg = util::fail_guard([&]() {
      send_unauthorized(response, request);
    });

    const auto auth = request->header.find("authorization");
    if (auth == request->header.end()) {
      return false;
    }

    std::string auth_data;
    try {
      const auto &raw_auth = auth->second;
      if (!raw_auth.starts_with("Basic "sv)) {
        login_throttle.record_failure(remote_address);
        return false;
      }
      auth_data = SimpleWeb::Crypto::Base64::decode(raw_auth.substr("Basic "sv.length()));
    } catch (const std::exception &) {
      login_throttle.record_failure(remote_address);
      return false;
    }

    const auto separator = auth_data.find(':');
    if (separator == std::string::npos || separator == 0 || separator + 1 >= auth_data.size()) {
      login_throttle.record_failure(remote_address);
      return false;
    }

    const auto username = auth_data.substr(0, separator);
    const auto password = auth_data.substr(separator + 1);
    const auto password_result = http::verify_user_password(password, config::sunshine.password, config::sunshine.salt);

    if (!boost::iequals(username, config::sunshine.username) || password_result == http::password_verification_e::INVALID) {
      login_throttle.record_failure(remote_address);
      return false;
    }

    login_throttle.record_success(remote_address);
    if (password_result == http::password_verification_e::LEGACY) {
      http::user_credentials_t migrated;
      if (http::save_user_creds(config::sunshine.credentials_file, config::sunshine.username, password, false, &migrated) == 0) {
        config::sunshine.username = std::move(migrated.username);
        config::sunshine.password = std::move(migrated.password);
        config::sunshine.salt = std::move(migrated.salt);
      }
    }

    fg.disable();
    return true;
  }

  /**
   * @brief Send a 404 Not Found response.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * @param error_message The error message to include in the response.
   */
  void not_found(const resp_https_t &response, [[maybe_unused]] const req_https_t &request, const std::string &error_message) {
    constexpr auto code = SimpleWeb::StatusCode::client_error_not_found;

    nlohmann::json tree;
    tree["status_code"] = code;
    tree["error"] = error_message;

    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "application/json");
    headers.emplace("X-Frame-Options", "DENY");
    headers.emplace("Content-Security-Policy", "frame-ancestors 'none';");

    response->write(code, tree.dump(), headers);
  }

  /**
   * @brief Send a 400 Bad Request response.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * @param error_message The error message to include in the response.
   */
  void bad_request(const resp_https_t &response, [[maybe_unused]] const req_https_t &request, const std::string &error_message) {
    constexpr auto code = SimpleWeb::StatusCode::client_error_bad_request;

    nlohmann::json tree;
    tree["status_code"] = code;
    tree["status"] = false;
    tree["error"] = error_message;

    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "application/json");
    headers.emplace("X-Frame-Options", "DENY");
    headers.emplace("Content-Security-Policy", "frame-ancestors 'none';");

    response->write(code, tree.dump(), headers);
  }

  /**
   * @brief Validate the request content type and send a bad request when mismatched.
   */
  bool check_content_type(const resp_https_t &response, const req_https_t &request, const std::string_view &contentType) {
    const auto requestContentType = request->header.find("content-type");
    if (requestContentType == request->header.end()) {
      bad_request(response, request, "Content type not provided");
      return false;
    }
    // Extract the media type part before any parameters (e.g., charset)
    std::string actualContentType = requestContentType->second;
    if (const size_t semicolonPos = actualContentType.find(';'); semicolonPos != std::string::npos) {
      actualContentType = actualContentType.substr(0, semicolonPos);
    }

    // Trim whitespace and convert to lowercase for case-insensitive comparison
    boost::algorithm::trim(actualContentType);
    boost::algorithm::to_lower(actualContentType);

    std::string expectedContentType(contentType);
    boost::algorithm::to_lower(expectedContentType);

    if (actualContentType != expectedContentType) {
      bad_request(response, request, "Content type mismatch");
      return false;
    }
    return true;
  }

  /**
   * @brief Get a unique client identifier for CSRF token management.
   * @param request The HTTP request object.
   * @return A unique identifier based on username or IP address.
   */
  std::string get_client_id(const req_https_t &request) {
    // Try to use the authenticated username as client ID
    if (const auto auth = request->header.find("authorization"); !config::sunshine.username.empty() && auth != request->header.end()) {
      if (const auto &rawAuth = auth->second; rawAuth.rfind("Basic "sv, 0) == 0) {
        auto authData = SimpleWeb::Crypto::Base64::decode(rawAuth.substr("Basic "sv.length()));
        if (const auto index = static_cast<int>(authData.find(':')); index < authData.size() - 1) {
          return authData.substr(0, index);  // Return username
        }
      }
    }

    // Fall back to IP address if no username
    return net::addr_to_normalized_string(request->remote_endpoint().address());
  }

  /**
   * @brief Generate a new CSRF token for a client.
   * @param client_id A unique identifier for the client (e.g., session ID or username).
   * @return The generated CSRF token.
   */
  std::string generate_csrf_token(const std::string &client_id) {
    // Generate a cryptographically secure random token
    std::string token = crypto::rand_alphabet(CSRF_TOKEN_SIZE);

    std::scoped_lock lock(csrf_tokens_mutex);

    // Clean up expired tokens first
    const auto now = std::chrono::steady_clock::now();
    std::erase_if(csrf_tokens, [&now](const auto &entry) {
      return entry.second.expiration < now;
    });

    // Store the token with expiration
    csrf_tokens[client_id] = csrf_token_t {
      token,
      now + CSRF_TOKEN_LIFETIME
    };

    return token;
  }

  /**
   * @brief Validate a stored CSRF token for a client against a provided token string.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * @param client_id A unique identifier for the client.
   * @param provided_token The token string to validate.
   * @return True if the token is valid, false otherwise.
   */
  bool validate_stored_csrf_token(const resp_https_t &response, const req_https_t &request, const std::string_view client_id, const std::string_view provided_token) {
    std::scoped_lock lock(csrf_tokens_mutex);
    const auto token_it = csrf_tokens.find(client_id);

    if (token_it == csrf_tokens.end()) {
      auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
      BOOST_LOG(error) << "Web UI: ["sv << address << "] -- CSRF token validation failed: no token found for client"sv;
      bad_request(response, request, "Invalid CSRF token");
      return false;
    }

    if (const auto now = std::chrono::steady_clock::now(); token_it->second.expiration < now) {
      csrf_tokens.erase(token_it);
      auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
      BOOST_LOG(error) << "Web UI: ["sv << address << "] -- CSRF token validation failed: token expired"sv;
      bad_request(response, request, "CSRF token expired");
      return false;
    }

    if (token_it->second.token != provided_token) {
      auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
      BOOST_LOG(error) << "Web UI: ["sv << address << "] -- CSRF token validation failed: token mismatch"sv;
      bad_request(response, request, "Invalid CSRF token");
      return false;
    }

    return true;
  }

  /**
   * @brief Validate CSRF token.
   */
  bool validate_csrf_token(const resp_https_t &response, const req_https_t &request, const std::string &client_id) {
    // Helper function to check if a URL starts with any allowed origin
    auto is_allowed_origin = [](const std::string_view url) {
      return std::ranges::any_of(config::sunshine.csrf_allowed_origins, [&url](const std::string &allowed_origin) {
        // Ensure exact prefix match (with ":" or "/" after to prevent malicious.com matching allowed.com)
        if (url.rfind(allowed_origin, 0) != 0) {  // rfind with pos=0 checks if the url starts with allowed_origin
          return false;
        }
        // Check that it's followed by ":" (port) or "/" (path) or is an exact match
        const size_t len = allowed_origin.length();
        return url.length() == len || url[len] == ':' || url[len] == '/';
      });
    };

    // Check if the request is from the same origin (Origin or Referer header matches configured allowed origins)
    const auto origin_it = request->header.find("Origin");
    if (origin_it != request->header.end() && is_allowed_origin(origin_it->second)) {
      // Same origin request - allow without CSRF token
      return true;
    }

    // If we have a Referer header, check if it's same-origin
    const auto referer_it = request->header.find("Referer");
    if (referer_it != request->header.end() && is_allowed_origin(referer_it->second)) {
      // Same origin request - allow without CSRF token
      return true;
    }

    // If neither Origin nor Referer is present, this cannot be a browser-initiated CSRF attack.
    // Non-browser clients (e.g. curl, scripts) never send these headers, and a malicious web page
    // cannot cause a non-browser client to make requests on a user's behalf.
    if (origin_it == request->header.end() && referer_it == request->header.end()) {
      return true;
    }

    // A browser-like request arrived with an Origin/Referer that doesn't match an allowed origin.
    // Require a CSRF token.
    const std::string_view blocked_origin = (origin_it != request->header.end()) ? origin_it->second : referer_it->second;
    // Extract token from X-CSRF-Token header
    const auto header_it = request->header.find("X-CSRF-Token");
    if (header_it == request->header.end()) {
      // Also check query parameters as fallback
      auto query_params = request->parse_query_string();
      const auto query_it = query_params.find("csrf_token");
      if (query_it == query_params.end()) {
        auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
        BOOST_LOG(error) << "Web UI: ["sv << address << "] -- CSRF protection blocked request from origin: "sv << blocked_origin;
        BOOST_LOG(error) << "Web UI: To allow this origin, add it to the 'csrf_allowed_origins' option in your Lumen configuration"sv;
        bad_request(response, request, "Missing CSRF token");
        return false;
      }

      return validate_stored_csrf_token(response, request, client_id, query_it->second);
    }

    // Validate token from header
    return validate_stored_csrf_token(response, request, client_id, header_it->second);
  }

  /**
   * @brief Validates the application index and sends an error response if invalid.
   */
  bool check_app_index(const resp_https_t &response, const req_https_t &request, int index) {
    std::string file = file_handler::read_file(config::stream.file_apps.c_str());
    nlohmann::json file_tree = nlohmann::json::parse(file);
    if (const auto &apps = file_tree["apps"]; index < 0 || index >= static_cast<int>(apps.size())) {
      std::string error;
      if (const int max_index = static_cast<int>(apps.size()) - 1; max_index < 0) {
        error = "No applications found";
      } else {
        error = std::format("'index' {} out of range, max index is {}", index, max_index);
      }
      bad_request(response, request, error);
      return false;
    }
    return true;
  }

  /**
   * @brief Get an HTML page.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * @param html_file The HTML file to serve (relative to WEB_DIR).
   * @param require_auth Whether to require authentication (default: true).
   * @param redirect_if_username If true, redirect to "/" when the username is set (for welcome page).
   */
  void getPage(const resp_https_t &response, const req_https_t &request, const char *html_file, const bool require_auth, const bool redirect_if_username) {
    // Special handling for welcome page: redirect if the username is already set
    if (redirect_if_username && !config::sunshine.username.empty()) {
      send_redirect(response, request, "/");
      return;
    }

    if (require_auth && !authenticate(response, request)) {
      return;
    }

    print_req(request);

    const std::string content = file_handler::read_file((std::string(WEB_DIR) + html_file).c_str());
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");

    // prevent click jacking
    headers.emplace("X-Frame-Options", "DENY");
    headers.emplace("Content-Security-Policy", "frame-ancestors 'none';");

    response->write(content, headers);
  }

  /**
   * @brief Get the favicon image.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * @todo combine function with getSunshineLogoImage and possibly getNodeModules
   * @todo use mime_types map
   */
  void getFaviconImage(const resp_https_t &response, const req_https_t &request) {
    print_req(request);

    std::ifstream in(WEB_DIR "images/sunshine.ico", std::ios::binary);
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "image/x-icon");
    headers.emplace("X-Frame-Options", "DENY");
    headers.emplace("Content-Security-Policy", "frame-ancestors 'none';");
    response->write(SimpleWeb::StatusCode::success_ok, in, headers);
  }

  /**
   * @brief Get the Sunshine logo image.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * @todo combine function with getFaviconImage and possibly getNodeModules
   * @todo use mime_types map
   */
  void getSunshineLogoImage(const resp_https_t &response, const req_https_t &request) {
    print_req(request);

    std::ifstream in(WEB_DIR "images/logo-sunshine-45.png", std::ios::binary);
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "image/png");
    headers.emplace("X-Frame-Options", "DENY");
    headers.emplace("Content-Security-Policy", "frame-ancestors 'none';");
    response->write(SimpleWeb::StatusCode::success_ok, in, headers);
  }

  /**
   * @brief Check if a path is a child of another path.
   * @param base The base path.
   * @param query The path to check.
   * @return True if the path is a child of the base path, false otherwise.
   */
  bool isChildPath(fs::path const &base, fs::path const &query) {
    auto relPath = fs::relative(base, query);
    return *(relPath.begin()) != fs::path("..");
  }

  /**
   * @brief Get an asset.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   */
  void getAsset(const resp_https_t &response, const req_https_t &request) {
    print_req(request);
    fs::path webDirPath(WEB_DIR);
    fs::path nodeModulesPath(webDirPath / "assets");

    // .relative_path is needed to shed any leading slash that might exist in the request path
    auto filePath = fs::weakly_canonical(webDirPath / fs::path(request->path).relative_path());

    // Don't do anything if the file does not exist or is outside the assets directory
    if (!isChildPath(filePath, nodeModulesPath)) {
      BOOST_LOG(warning) << "Someone requested a path " << filePath << " that is outside the assets folder";
      bad_request(response, request);
      return;
    }
    if (!fs::exists(filePath)) {
      not_found(response, request);
      return;
    }

    auto relPath = fs::relative(filePath, webDirPath);
    // get the mime type from the file extension mime_types map
    // remove the leading period from the extension
    auto mimeType = mime_types.find(relPath.extension().string().substr(1));
    // check if the extension is in the map at the x position
    if (mimeType == mime_types.end()) {
      bad_request(response, request);
      return;
    }

    // if it is, set the content type to the mime type
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", mimeType->second);
    headers.emplace("X-Frame-Options", "DENY");
    headers.emplace("Content-Security-Policy", "frame-ancestors 'none';");
    std::ifstream in(filePath.string(), std::ios::binary);
    response->write(SimpleWeb::StatusCode::success_ok, in, headers);
  }

  /**
   * @brief Get a CSRF token for the authenticated user.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/csrf-token| GET| null}
   */
  void getCSRFToken(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    print_req(request);

    std::string client_id = get_client_id(request);
    std::string token = generate_csrf_token(client_id);

    nlohmann::json output_tree;
    output_tree["csrf_token"] = token;
    send_response(response, output_tree);
  }

  /**
   * @brief Get the list of available applications.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/apps| GET| null}
   */
  void getApps(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    print_req(request);

    try {
      std::string content = file_handler::read_file(config::stream.file_apps.c_str());
      nlohmann::json file_tree = nlohmann::json::parse(content);

      // Legacy versions of Sunshine used strings for boolean and integers, let's convert them
      // List of keys to convert to boolean
      const std::vector<std::string> boolean_keys = {
        "exclude-global-prep-cmd",
        "elevated",
        "auto-detach",
        "wait-all"
      };

      // List of keys to convert to integers
      std::vector<std::string> integer_keys = {
        "exit-timeout"
      };

      // Walk fileTree and convert true/false strings to boolean or integer values
      for (auto &app : file_tree["apps"]) {
        for (const auto &key : boolean_keys) {
          if (app.contains(key) && app[key].is_string()) {
            app[key] = app[key] == "true";
          }
        }
        for (const auto &key : integer_keys) {
          if (app.contains(key) && app[key].is_string()) {
            app[key] = std::stoi(app[key].get<std::string>());
          }
        }
        if (app.contains("prep-cmd")) {
          for (auto &prep : app["prep-cmd"]) {
            if (prep.contains("elevated") && prep["elevated"].is_string()) {
              prep["elevated"] = prep["elevated"] == "true";
            }
          }
        }
      }

      send_response(response, file_tree);
    } catch (std::exception &e) {
      BOOST_LOG(warning) << "GetApps: "sv << e.what();
      bad_request(response, request, e.what());
    }
  }

  /**
   * @brief Save an application. To save a new application, the index must be `-1`. To update an existing application, you must provide the current index of the application.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * The body for the post request should be JSON serialized in the following format:
   * @code{.json}
   * {
   *   "name": "Application Name",
   *   "output": "Log Output Path",
   *   "cmd": "Command to run the application",
   *   "index": -1,
   *   "exclude-global-prep-cmd": false,
   *   "elevated": false,
   *   "auto-detach": true,
   *   "wait-all": true,
   *   "exit-timeout": 5,
   *   "prep-cmd": [
   *     {
   *       "do": "Command to prepare",
   *       "undo": "Command to undo preparation",
   *       "elevated": false
   *     }
   *   ],
   *   "detached": [
   *     "Detached command"
   *   ],
   *   "image-path": "Full path to the application image. Must be a png file."
   * }
   * @endcode
   *
   * @api_examples{/api/apps| POST| {"name":"Hello, World!","index":-1}}
   */
  void saveApp(const resp_https_t &response, const req_https_t &request) {
    if (!check_content_type(response, request, "application/json")) {
      return;
    }
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    std::stringstream ss;
    ss << request->content.rdbuf();
    try {
      // TODO: Input Validation
      nlohmann::json output_tree;
      nlohmann::json input_tree = nlohmann::json::parse(ss);
      std::string file = file_handler::read_file(config::stream.file_apps.c_str());
      nlohmann::json file_tree = nlohmann::json::parse(file);

      if (input_tree["prep-cmd"].empty()) {
        input_tree.erase("prep-cmd");
      }

      if (input_tree["detached"].empty()) {
        input_tree.erase("detached");
      }

      auto &apps_node = file_tree["apps"];
      int index = input_tree["index"].get<int>();  // this will intentionally cause an exception if the provided value is the wrong type

      input_tree.erase("index");

      if (index == -1) {
        apps_node.push_back(input_tree);
      } else {
        nlohmann::json newApps = nlohmann::json::array();
        for (size_t i = 0; i < apps_node.size(); ++i) {
          if (i == index) {
            newApps.push_back(input_tree);
          } else {
            newApps.push_back(apps_node[i]);
          }
        }
        file_tree["apps"] = newApps;
      }

      // Sort the apps array by name
      std::sort(apps_node.begin(), apps_node.end(), [](const nlohmann::json &a, const nlohmann::json &b) {
        return a["name"].get<std::string>() < b["name"].get<std::string>();
      });

      file_handler::write_file(config::stream.file_apps.c_str(), file_tree.dump(4));
      proc::refresh(config::stream.file_apps);

      output_tree["status"] = true;
      send_response(response, output_tree);
    } catch (std::exception &e) {
      BOOST_LOG(warning) << "SaveApp: "sv << e.what();
      bad_request(response, request, e.what());
    }
  }

  /**
   * @brief Close the currently running application.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/apps/close| POST| null}
   */
  void closeApp(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    proc::proc.terminate();

    nlohmann::json output_tree;
    output_tree["status"] = true;
    send_response(response, output_tree);
  }

  /**
   * @brief Delete an application.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/apps/9999| DELETE| null}
   */
  void deleteApp(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    try {
      nlohmann::json output_tree;
      nlohmann::json new_apps = nlohmann::json::array();
      const int index = std::stoi(request->path_match[1]);

      if (!check_app_index(response, request, index)) {
        return;
      }

      std::string file = file_handler::read_file(config::stream.file_apps.c_str());
      nlohmann::json file_tree = nlohmann::json::parse(file);
      auto &apps = file_tree["apps"];

      for (size_t i = 0; i < apps.size(); ++i) {
        if (i != index) {
          new_apps.push_back(apps[i]);
        }
      }
      file_tree["apps"] = new_apps;

      file_handler::write_file(config::stream.file_apps.c_str(), file_tree.dump(4));
      proc::refresh(config::stream.file_apps);

      output_tree["status"] = true;
      output_tree["result"] = std::format("application {} deleted", index);
      send_response(response, output_tree);
    } catch (std::exception &e) {
      BOOST_LOG(warning) << "DeleteApp: "sv << e.what();
      bad_request(response, request, e.what());
    }
  }

  /**
   * @brief Get the list of paired clients.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/clients/list| GET| null}
   */
  void getClients(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    print_req(request);

    const nlohmann::json named_certs = nvhttp::get_all_clients();

    nlohmann::json output_tree;
    output_tree["named_certs"] = named_certs;
    output_tree["status"] = true;
    send_response(response, output_tree);
  }

  /**
   * @brief Enable or disable a client.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * The body for the POST request should be JSON serialized in the following format:
   * @code{.json}
   * {
   *   "uuid": "<uuid>",
   *   "enabled": true
   * }
   * @endcode
   *
   * @api_examples{/api/clients/update| POST| {"uuid":"<uuid>","enabled":true}}
   */
  void updateClient(resp_https_t response, req_https_t request) {
    if (!check_content_type(response, request, "application/json")) {
      return;
    }
    if (!authenticate(response, request)) {
      return;
    }
    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    std::stringstream ss;
    ss << request->content.rdbuf();
    try {
      nlohmann::json input_tree = nlohmann::json::parse(ss.str());
      nlohmann::json output_tree;
      std::string uuid = input_tree.value("uuid", "");
      bool enabled = input_tree.value("enabled", true);
      const auto updated_certificate = nvhttp::set_client_enabled_with_certificate(uuid, enabled);
      output_tree["status"] = updated_certificate.has_value();

      if (!enabled && updated_certificate) {
        rtsp_stream::terminate_sessions_by_cert(*updated_certificate);

        if (!rtsp_stream::has_session_or_pending_launch() && proc::proc.running() > 0) {
          proc::proc.terminate();
        }
      }

      send_response(response, output_tree);
    } catch (nlohmann::json::exception &e) {
      BOOST_LOG(warning) << "Update Client: "sv << e.what();
      bad_request(response, request, e.what());
    }
  }

  /**
   * @brief Unpair a client.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * The body for the POST request should be JSON serialized in the following format:
   * @code{.json}
   * {
   *  "uuid": "<uuid>"
   * }
   * @endcode
   *
   * @api_examples{/api/unpair| POST| {"uuid":"1234"}}
   */
  void unpair(const resp_https_t &response, const req_https_t &request) {
    if (!check_content_type(response, request, "application/json")) {
      return;
    }
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    std::stringstream ss;
    ss << request->content.rdbuf();

    try {
      // TODO: Input Validation
      nlohmann::json output_tree;
      const nlohmann::json input_tree = nlohmann::json::parse(ss);
      const std::string uuid = input_tree.value("uuid", "");
      const auto removed_certificate = nvhttp::revoke_client(uuid);
      output_tree["status"] = removed_certificate.has_value();

      if (removed_certificate) {
        rtsp_stream::terminate_sessions_by_cert(*removed_certificate);
        if (nvhttp::get_all_clients().empty()) {
          proc::proc.terminate();
        }
      }

      send_response(response, output_tree);
    } catch (std::exception &e) {
      BOOST_LOG(warning) << "Unpair: "sv << e.what();
      bad_request(response, request, e.what());
    }
  }

  /**
   * @brief Unpair all clients.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/clients/unpair-all| POST| null}
   */
  void unpairAll(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    nlohmann::json output_tree;
    output_tree["status"] = nvhttp::erase_all_clients();
    if (output_tree["status"]) {
      proc::proc.terminate();
    }
    send_response(response, output_tree);
  }

  /**
   * @brief Convert one LSP fixed-width identifier to lowercase hexadecimal.
   *
   * @param identifier Identifier bytes to encode.
   * @return Stable 32-character lowercase client identifier.
   */
  std::string encode_lsp_client_id(const lumen::lsp::Identifier128 &identifier) {
    constexpr std::string_view digits = "0123456789abcdef";
    std::string encoded(identifier.size() * 2, '0');
    for (std::size_t index = 0; index < identifier.size(); ++index) {
      encoded[index * 2] = digits[identifier[index] >> 4U];
      encoded[index * 2 + 1] = digits[identifier[index] & 0x0fU];
    }
    return encoded;
  }

  /** @brief Convert one LSP SHA-256 fingerprint to lowercase hexadecimal. */
  std::string encode_lsp_fingerprint(const lumen::lsp::Digest256 &fingerprint) {
    constexpr std::string_view digits = "0123456789abcdef";
    std::string encoded(fingerprint.size() * 2, '0');
    for (std::size_t index = 0; index < fingerprint.size(); ++index) {
      encoded[index * 2] = digits[fingerprint[index] >> 4U];
      encoded[index * 2 + 1] = digits[fingerprint[index] & 0x0fU];
    }
    return encoded;
  }

  /**
   * @brief Decode one canonical LSP client identifier.
   *
   * @param encoded Exact 32-character lowercase hexadecimal identifier.
   * @return Decoded identifier, or no value for malformed input.
   */
  std::optional<lumen::lsp::Identifier128> decode_lsp_client_id(const std::string_view encoded) noexcept {
    constexpr std::size_t encoded_client_id_size = 32;
    if (encoded.size() != encoded_client_id_size) {
      return std::nullopt;
    }

    const auto hex_value = [](const char value) -> std::optional<std::uint8_t> {
      if (value >= '0' && value <= '9') {
        return static_cast<std::uint8_t>(value - '0');
      }
      if (value >= 'a' && value <= 'f') {
        return static_cast<std::uint8_t>(value - 'a' + 10);
      }
      return std::nullopt;
    };

    lumen::lsp::Identifier128 identifier {};
    for (std::size_t index = 0; index < identifier.size(); ++index) {
      const auto high = hex_value(encoded[index * 2]);
      const auto low = hex_value(encoded[index * 2 + 1]);
      if (!high || !low) {
        return std::nullopt;
      }
      identifier[index] = static_cast<std::uint8_t>((*high << 4U) | *low);
    }
    return lumen::lsp::is_zero(identifier) ? std::nullopt : std::optional {identifier};
  }

  /**
   * @brief Return the stable Web API name for one LSP network profile.
   *
   * @param profile Configured LSP profile.
   * @return Public profile name.
   */
  std::string_view lsp_profile_name(const lumen::lsp::NetworkProfile profile) noexcept {
    switch (profile) {
      case lumen::lsp::NetworkProfile::adaptive_low_latency:
        return "adaptive-low-latency"sv;
      case lumen::lsp::NetworkProfile::competition:
        return "competition"sv;
    }
    return "unknown"sv;
  }

  /**
   * @brief Return the stable Web API name for one LSP reconnect outcome.
   *
   * @param outcome Secret-free runtime reconnect outcome.
   * @return Public reconnect outcome name.
   */
  std::string_view lsp_reconnect_outcome_name(const lumen::lsp::runtime::ReconnectOutcome outcome) noexcept {
    using lumen::lsp::runtime::ReconnectOutcome;
    switch (outcome) {
      case ReconnectOutcome::none:
        return "none"sv;
      case ReconnectOutcome::rejected:
        return "rejected"sv;
      case ReconnectOutcome::committed:
        return "committed"sv;
      case ReconnectOutcome::ready:
        return "ready"sv;
      case ReconnectOutcome::failed:
        return "failed"sv;
    }
    return "unknown"sv;
  }

  /** @brief Return one stable secret-free PIN pairing state name. */
  std::string_view lsp_pairing_state_name(const lumen::lsp::runtime::PairingAdministrationState state) noexcept {
    using lumen::lsp::runtime::PairingAdministrationState;
    switch (state) {
      case PairingAdministrationState::awaiting_pin:
        return "awaiting-pin"sv;
      case PairingAdministrationState::deriving:
        return "deriving"sv;
      case PairingAdministrationState::challenge_ready:
        return "challenge-ready"sv;
      case PairingAdministrationState::cooldown:
        return "cooldown"sv;
    }
    return "unknown"sv;
  }

  /** @brief Scope guard that wipes the original LSP PIN request body on every handler exit. */
  class LspPinRequestBodyGuard {
  public:
    /** @brief Retain the request without allocating or reading its body. */
    explicit LspPinRequestBodyGuard(req_https_t request) noexcept:
        request_ {std::move(request)} {
    }

    LspPinRequestBodyGuard(const LspPinRequestBodyGuard &) = delete;
    LspPinRequestBodyGuard &operator=(const LspPinRequestBodyGuard &) = delete;

    /** @brief Wipe and consume the underlying HTTP request buffer. */
    ~LspPinRequestBodyGuard() {
      auto *buffer = dynamic_cast<boost::asio::streambuf *>(request_->content.rdbuf());
      if (buffer == nullptr) {
        return;
      }
      const auto data = buffer->data();
      for (auto iterator = boost::asio::buffers_begin(data); iterator != boost::asio::buffers_end(data); ++iterator) {
        auto &byte = const_cast<char &>(*iterator);
        byte = 0;
      }
      buffer->consume(buffer->size());
    }

  private:
    req_https_t request_;  ///< Request retaining the original buffer through scope exit.
  };

  /** @brief Scope-owned PIN copies for the LSP administration handler. */
  class LspPinSubmissionSecrets {
  public:
    /** @brief Copy the exact bounded request body after its length and session pass preflight. */
    explicit LspPinSubmissionSecrets(const req_https_t &request):
        pin {request->content.string()} {
    }

    LspPinSubmissionSecrets(const LspPinSubmissionSecrets &) = delete;
    LspPinSubmissionSecrets &operator=(const LspPinSubmissionSecrets &) = delete;

    /** @brief Wipe every PIN copy on scope exit. */
    ~LspPinSubmissionSecrets() {
      lumen::lsp::secure_zero(std::span<char> {pin.data(), pin.size()});
      lumen::lsp::secure_zero(digits);
    }

    std::string pin;  ///< Exact six-byte body copy, securely cleared on scope exit.
    std::array<std::uint8_t, 6> digits {};  ///< Validated worker input, securely cleared on scope exit.
  };

  /**
   * @brief Send a non-cacheable LSP administration JSON response.
   *
   * @param response Shared HTTPS response object.
   * @param status HTTP response status.
   * @param output_tree Public administration response body.
   */
  void send_lsp_admin_response(
    const resp_https_t &response,
    const SimpleWeb::StatusCode status,
    const nlohmann::json &output_tree
  ) {
    const SimpleWeb::CaseInsensitiveMultimap headers {
      {"Content-Type", "application/json"},
      {"Cache-Control", "no-store"},
      {"Pragma", "no-cache"},
      {"Referrer-Policy", "no-referrer"},
      {"X-Frame-Options", "DENY"},
      {"Content-Security-Policy", "frame-ancestors 'none';"},
    };
    response->write(status, output_tree.dump(), headers);
  }

  /**
   * @brief Reject an LSP administration request with a stable JSON error.
   *
   * @param response Shared HTTPS response object.
   * @param status HTTP failure status.
   * @param error Public error string without secret material.
   */
  void send_lsp_admin_error(
    const resp_https_t &response,
    const SimpleWeb::StatusCode status,
    const std::string_view error
  ) {
    send_lsp_admin_response(response, status, {
                                                {"status", false},
                                                {"error", error},
                                              });
  }

  /**
   * @brief Enforce authenticated trusted-LAN access and an explicit CSRF token.
   *
   * General Web UI routes retain their existing origin-aware CSRF behavior.
   * LSP PIN and trust administration always requires the token header,
   * including same-origin GET requests.
   *
   * @param response Shared HTTPS response object.
   * @param request Shared HTTPS request object.
   * @return True only for an authenticated PC/LAN source with a valid token.
   */
  bool authorize_lsp_administration(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return false;
    }

    const auto remote_address = net::addr_to_normalized_string(request->remote_endpoint().address());
    if (net::from_address(remote_address) > net::LAN) {
      send_lsp_admin_error(
        response,
        SimpleWeb::StatusCode::client_error_forbidden,
        "LSP administration is restricted to the trusted local network"
      );
      return false;
    }

    const auto token = request->header.find("X-CSRF-Token");
    if (token == request->header.end()) {
      bad_request(response, request, "Missing CSRF token");
      return false;
    }
    return validate_stored_csrf_token(response, request, get_client_id(request), token->second);
  }

  /**
   * @brief Send the current LSP listener administration status.
   *
   * @api_examples{/api/lsp/status| GET| null}
   */
  void getLspStatus(const resp_https_t &response, const req_https_t &request) {
    if (!authorize_lsp_administration(response, request)) {
      return;
    }

    const auto snapshot = lumen::lsp::runtime::administration_snapshot();
    if (!snapshot) {
      send_lsp_admin_error(
        response,
        SimpleWeb::StatusCode::server_error_service_unavailable,
        "LSP runtime is unavailable"
      );
      return;
    }

    const nlohmann::json reconnect {
      {"attempts", snapshot->reconnect.attempts},
      {"committed", snapshot->reconnect.committed},
      {"completed", snapshot->reconnect.completed},
      {"rejected", snapshot->reconnect.rejected},
      {"failed", snapshot->reconnect.failed},
      {"latestConnectionGeneration", snapshot->reconnect.latest_connection_generation},
      {"latestOutcome", lsp_reconnect_outcome_name(snapshot->reconnect.latest_outcome)},
      {"latestRequestToCommitMicroseconds", snapshot->reconnect.latest_request_to_commit_microseconds},
      {"latestCommitToReadyMicroseconds", snapshot->reconnect.latest_commit_to_ready_microseconds},
      {"latestTotalMicroseconds", snapshot->reconnect.latest_total_microseconds},
    };
    const nlohmann::json media {
      {"audioGeneration", snapshot->media.audio_generation},
      {"videoGeneration", snapshot->media.video_generation},
      {"microphoneGeneration", snapshot->media.microphone_generation},
      {"audioSentPackets", snapshot->media.audio_sent_packets},
      {"audioExpiredPackets", snapshot->media.audio_expired_packets},
      {"audioDeliveredBytes", snapshot->media.audio_delivered_bytes},
      {"audioLostBytes", snapshot->media.audio_lost_bytes},
      {"audioEcnCeBytes", snapshot->media.audio_ecn_ce_bytes},
      {"videoSentFrames", snapshot->media.video_sent_frames},
      {"videoAdmittedFrames", snapshot->media.video_admitted_frames},
      {"videoDroppedFrames", snapshot->media.video_dropped_frames},
      {"videoPressureEvents", snapshot->media.video_pressure_events},
      {"videoDecoderCredit", snapshot->media.video_decoder_credit},
      {"videoPacingBitsPerSecond", snapshot->media.video_pacing_bits_per_second},
      {"videoEncoderBitsPerSecond", snapshot->media.video_encoder_bits_per_second},
      {"videoFeedbackReports", snapshot->media.video_feedback_reports},
      {"videoFeedbackRejections", snapshot->media.video_feedback_rejections},
      {"videoRepairFeedbackPackets", snapshot->media.video_repair_feedback_packets},
      {"videoSentPackets", snapshot->media.video_sent_packets},
      {"flexfecSentPackets", snapshot->media.flexfec_sent_packets},
      {"rtxSentPackets", snapshot->media.rtx_sent_packets},
      {"videoLostBytes", snapshot->media.video_lost_bytes},
      {"videoEcnCeBytes", snapshot->media.video_ecn_ce_bytes},
      {"microphoneAcceptedPackets", snapshot->media.microphone_accepted_packets},
      {"microphoneRejectedPackets", snapshot->media.microphone_rejected_packets},
      {"microphoneReceiverReports", snapshot->media.microphone_receiver_reports},
      {"microphoneCongestionReports", snapshot->media.microphone_congestion_reports},
      {"microphoneDecodedFrames", snapshot->media.microphone_decoded_frames},
      {"microphoneFecFrames", snapshot->media.microphone_fec_frames},
      {"microphonePlcFrames", snapshot->media.microphone_plc_frames},
      {"microphoneSilenceFrames", snapshot->media.microphone_silence_frames},
      {"microphoneDecodeErrors", snapshot->media.microphone_decode_errors},
      {"microphoneSinkErrors", snapshot->media.microphone_sink_errors},
      {"microphonePlayoutActive", snapshot->media.microphone_playout_active},
      {"forwardSentBytes", snapshot->media.forward_sent_bytes},
      {"inputFeedbackSentBytes", snapshot->media.input_feedback_sent_bytes},
      {"inputAuthenticatedPackets", snapshot->media.input_authenticated_packets},
      {"inputCongestionReports", snapshot->media.input_congestion_reports},
      {"inputReceiverReports", snapshot->media.input_receiver_reports},
      {"inputFeedbackStorageDrops", snapshot->media.input_feedback_storage_drops},
      {"inputPendingFeedbackPositions", snapshot->media.input_pending_feedback_positions},
      {"appliedInputStateSequence", snapshot->media.applied_input_state_sequence},
      {"appliedInputEdgeId", snapshot->media.applied_input_edge_id},
      {"inputLatencySamples", snapshot->media.input_latency_samples},
      {"latestInputLatencyMicroseconds", snapshot->media.latest_input_latency_microseconds},
      {"maximumInputLatencyMicroseconds", snapshot->media.maximum_input_latency_microseconds},
      {"ecnAvailable", snapshot->media.ecn_available},
      {"receivedEct0Datagrams", snapshot->media.received_ect0_datagrams},
      {"receivedEct1Datagrams", snapshot->media.received_ect1_datagrams},
      {"receivedCeDatagrams", snapshot->media.received_ce_datagrams},
      {"sentEct0Datagrams", snapshot->media.sent_ect0_datagrams},
      {"ecnFallbacks", snapshot->media.ecn_fallbacks},
      {"cachedPeerHandles", snapshot->media.cached_peer_handles},
    };
    send_lsp_admin_response(response, SimpleWeb::StatusCode::success_ok, {
                                                                           {"status", true},
                                                                           {"active", snapshot->active},
                                                                           {"port", snapshot->port},
                                                                           {"profile", lsp_profile_name(snapshot->profile)},
                                                                           {"pendingPairings", snapshot->pending_pairings},
                                                                           {"reconnect", reconnect},
                                                                           {"media", media},
                                                                         });
  }

  /** @brief Return secret-free pending LSP PIN pairing sessions. */
  void getLspPairing(const resp_https_t &response, const req_https_t &request) {
    if (!authorize_lsp_administration(response, request)) {
      return;
    }
    if (!lumen::lsp::runtime::administration_snapshot()) {
      send_lsp_admin_error(
        response,
        SimpleWeb::StatusCode::server_error_service_unavailable,
        "LSP runtime is unavailable"
      );
      return;
    }
    nlohmann::json pending = nlohmann::json::array();
    for (const auto &pairing : lumen::lsp::runtime::administration_pending_pairings()) {
      pending.push_back({
        {"sessionId", encode_lsp_client_id(pairing.pairing_session_id)},
        {"clientId", encode_lsp_client_id(pairing.client_id)},
        {"identityKeyFingerprint", encode_lsp_fingerprint(pairing.identity_key_fingerprint)},
        {"clientName", pairing.client_name},
        {"clientNameVerified", pairing.client_name_verified},
        {"permissions", pairing.effective_permissions.mask()},
        {"expiresAt", pairing.expires_at_utc_seconds},
        {"challengesUsed", pairing.challenges_used},
        {"state", lsp_pairing_state_name(pairing.state)},
      });
    }
    send_lsp_admin_response(response, SimpleWeb::StatusCode::success_ok, {
                                                                           {"status", true},
                                                                           {"pending", std::move(pending)},
                                                                         });
  }

  /**
   * @brief Queue one exact six-digit PIN without logging or echoing it.
   */
  void submitLspPairingPin(const resp_https_t &response, const req_https_t &request) {
    LspPinRequestBodyGuard request_body_guard {request};
    if (!check_content_type(response, request, "text/plain")) {
      return;
    }
    if (!authorize_lsp_administration(response, request)) {
      return;
    }
    const auto content_length = request->header.find("Content-Length");
    if (content_length == request->header.end() || content_length->second != "6") {
      send_lsp_admin_error(response, SimpleWeb::StatusCode::client_error_bad_request, "PIN body must be exactly six bytes");
      return;
    }
    const auto session_header = request->header.find("X-LSP-Pairing-Session");
    const auto pairing_session_id = session_header == request->header.end() ?
                                      std::nullopt :
                                      decode_lsp_client_id(session_header->second);
    if (!pairing_session_id) {
      send_lsp_admin_error(response, SimpleWeb::StatusCode::client_error_bad_request, "A selected pairing session is required");
      return;
    }
    LspPinSubmissionSecrets secrets {request};
    if (secrets.pin.size() != 6 || std::ranges::any_of(secrets.pin, [](const char digit) {
          return digit < '0' || digit > '9';
        })) {
      send_lsp_admin_error(response, SimpleWeb::StatusCode::client_error_bad_request, "PIN must contain exactly six digits");
      return;
    }
    std::ranges::transform(secrets.pin, secrets.digits.begin(), [](const char digit) {
      return static_cast<std::uint8_t>(digit);
    });
    const auto submitted = lumen::lsp::runtime::administration_submit_pairing_pin(*pairing_session_id, secrets.digits);
    if (submitted == 0) {
      send_lsp_admin_error(
        response,
        SimpleWeb::StatusCode::client_error_conflict,
        "No pending LSP client can accept a PIN yet"
      );
      return;
    }
    send_lsp_admin_response(response, SimpleWeb::StatusCode::success_ok, {
                                                                           {"status", true},
                                                                           {"submitted", submitted},
                                                                         });
  }

  /** @brief Cancel every pending LSP PIN pairing session. */
  void cancelLspPairing(const resp_https_t &response, const req_https_t &request) {
    if (!authorize_lsp_administration(response, request)) {
      return;
    }
    if (!lumen::lsp::runtime::administration_snapshot()) {
      send_lsp_admin_error(
        response,
        SimpleWeb::StatusCode::server_error_service_unavailable,
        "LSP runtime is unavailable"
      );
      return;
    }
    lumen::lsp::runtime::administration_cancel_pairings();
    send_lsp_admin_response(response, SimpleWeb::StatusCode::success_ok, {{"status", true}});
  }

  /**
   * @brief Return persisted LSP trusted clients without identity key material.
   *
   * @api_examples{/api/lsp/clients| GET| null}
   */
  void getLspClients(const resp_https_t &response, const req_https_t &request) {
    if (!authorize_lsp_administration(response, request)) {
      return;
    }
    if (!lumen::lsp::runtime::administration_snapshot()) {
      send_lsp_admin_error(
        response,
        SimpleWeb::StatusCode::server_error_service_unavailable,
        "LSP runtime is unavailable"
      );
      return;
    }

    nlohmann::json clients = nlohmann::json::array();
    for (const auto &client : lumen::lsp::runtime::administration_trusted_clients()) {
      clients.push_back({
        {"clientId", encode_lsp_client_id(client.client_id)},
        {"permissions", client.permissions.mask()},
        {"revocationGeneration", client.revocation_generation},
        {"enabled", client.enabled},
      });
    }
    send_lsp_admin_response(response, SimpleWeb::StatusCode::success_ok, {
                                                                           {"status", true},
                                                                           {"clients", std::move(clients)},
                                                                         });
  }

  /**
   * @brief Atomically update one LSP trusted client's permissions and enable state.
   *
   * @api_examples{/api/lsp/clients| PATCH| {"clientId":"00112233445566778899aabbccddeeff","permissions":87,"enabled":true}}
   */
  void updateLspClient(const resp_https_t &response, const req_https_t &request) {
    if (!authorize_lsp_administration(response, request)) {
      return;
    }
    if (!check_content_type(response, request, "application/json")) {
      return;
    }

    try {
      std::stringstream content;
      content << request->content.rdbuf();
      nlohmann::json input_tree = nlohmann::json::parse(content);
      if (!input_tree.is_object() || input_tree.size() != 3 ||
          !input_tree.contains("clientId") || !input_tree["clientId"].is_string() ||
          !input_tree.contains("permissions") || !input_tree["permissions"].is_number_unsigned() ||
          !input_tree.contains("enabled") || !input_tree["enabled"].is_boolean()) {
        bad_request(response, request, "Invalid LSP client update");
        return;
      }

      const auto client_id = decode_lsp_client_id(input_tree["clientId"].get<std::string>());
      const auto raw_permissions = input_tree["permissions"].get<std::uint64_t>();
      if (!client_id || raw_permissions == 0 || raw_permissions > std::numeric_limits<std::uint32_t>::max()) {
        bad_request(response, request, "Invalid LSP client update");
        return;
      }
      const auto permissions = lumen::lsp::PermissionSet::from_mask(static_cast<std::uint32_t>(raw_permissions));
      if (!permissions) {
        bad_request(response, request, "Invalid LSP permission mask");
        return;
      }

      const bool updated = lumen::lsp::runtime::administration_update_trusted_client(
        *client_id,
        *permissions,
        input_tree["enabled"].get<bool>()
      );
      if (!updated) {
        send_lsp_admin_error(
          response,
          SimpleWeb::StatusCode::client_error_not_found,
          "LSP trusted client was not found or could not be saved"
        );
        return;
      }
      send_lsp_admin_response(response, SimpleWeb::StatusCode::success_ok, {{"status", true}});
    } catch (const nlohmann::json::exception &) {
      bad_request(response, request, "Invalid LSP client update");
    }
  }

  /**
   * @brief Revoke one persisted LSP trusted client.
   *
   * @api_examples{/api/lsp/clients| DELETE| {"clientId":"00112233445566778899aabbccddeeff"}}
   */
  void revokeLspClient(const resp_https_t &response, const req_https_t &request) {
    if (!authorize_lsp_administration(response, request)) {
      return;
    }
    if (!check_content_type(response, request, "application/json")) {
      return;
    }

    try {
      std::stringstream content;
      content << request->content.rdbuf();
      nlohmann::json input_tree = nlohmann::json::parse(content);
      if (!input_tree.is_object() || input_tree.size() != 1 ||
          !input_tree.contains("clientId") || !input_tree["clientId"].is_string()) {
        bad_request(response, request, "Invalid LSP client revocation");
        return;
      }
      const auto client_id = decode_lsp_client_id(input_tree["clientId"].get<std::string>());
      if (!client_id) {
        bad_request(response, request, "Invalid LSP client revocation");
        return;
      }

      if (!lumen::lsp::runtime::administration_revoke_trusted_client(*client_id)) {
        send_lsp_admin_error(
          response,
          SimpleWeb::StatusCode::client_error_not_found,
          "LSP trusted client was not found or could not be revoked"
        );
        return;
      }
      send_lsp_admin_response(response, SimpleWeb::StatusCode::success_ok, {{"status", true}});
    } catch (const nlohmann::json::exception &) {
      bad_request(response, request, "Invalid LSP client revocation");
    }
  }

  /** @brief Rotate the LSP DTLS certificate through authenticated client persistence and atomic swap. */
  void rotateLspIdentity(const resp_https_t &response, const req_https_t &request) {
    if (!authorize_lsp_administration(response, request)) {
      return;
    }
    const auto result = lumen::lsp::runtime::administration_rotate_identity();
    if (result != lumen::lsp::runtime::IdentityRotationResult::success) {
      send_lsp_admin_error(
        response,
        result == lumen::lsp::runtime::IdentityRotationResult::inactive ?
          SimpleWeb::StatusCode::client_error_conflict :
          SimpleWeb::StatusCode::server_error_internal_server_error,
        "LSP certificate rotation did not commit; the prior identity remains active"
      );
      return;
    }
    send_lsp_admin_response(response, SimpleWeb::StatusCode::success_ok, {{"status", true}});
  }

  /**
   * @brief Get the configuration settings.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/config| GET| null}
   */
  void getConfig(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    print_req(request);

    nlohmann::json output_tree;
    output_tree["status"] = true;
    output_tree["platform"] = SUNSHINE_PLATFORM;
    output_tree["version"] = PROJECT_VERSION;

    auto vars = config::parse_config(file_handler::read_file(config::sunshine.config_file.c_str()));

    for (auto &[name, value] : vars) {
      output_tree[name] = std::move(value);
    }

    send_response(response, output_tree);
  }

  /**
   * @brief Get the locale setting. This endpoint does not require authentication.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/configLocale| GET| null}
   */
  void getLocale(const resp_https_t &response, const req_https_t &request) {
    // we need to return the locale whether authenticated or not

    print_req(request);

    nlohmann::json output_tree;
    output_tree["status"] = true;
    output_tree["locale"] = config::sunshine.locale;
    send_response(response, output_tree);
  }

  /**
   * @brief Save the configuration settings.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * The body for the POST request should be JSON serialized in the following format:
   * @code{.json}
   * {
   *   "key": "value"
   * }
   * @endcode
   *
   * @attention{It is recommended to ONLY save the config settings that differ from the default behavior.}
   *
   * @api_examples{/api/config| POST| {"key":"value"}}
   */
  void saveConfig(const resp_https_t &response, const req_https_t &request) {
    if (!check_content_type(response, request, "application/json")) {
      return;
    }
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    std::stringstream ss;
    ss << request->content.rdbuf();
    try {
      // TODO: Input Validation
      std::stringstream config_stream;
      nlohmann::json output_tree;
      nlohmann::json input_tree = nlohmann::json::parse(ss);
      for (const auto &[k, v] : input_tree.items()) {
        if (v.is_null() || (v.is_string() && v.get<std::string>().empty())) {
          continue;
        }

        // v.dump() will dump valid json, which we do not want for strings in the config, right now
        // we should migrate the config file to straight JSON and get rid of all this nonsense
        config_stream << k << " = " << (v.is_string() ? v.get<std::string>() : v.dump()) << std::endl;
      }
      file_handler::write_file(config::sunshine.config_file.c_str(), config_stream.str());
      output_tree["status"] = true;
      send_response(response, output_tree);
    } catch (std::exception &e) {
      BOOST_LOG(warning) << "SaveConfig: "sv << e.what();
      bad_request(response, request, e.what());
    }
  }

  /**
   * @brief Get an application's image.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @note{The index in the url path is the application index.}
   *
   * @api_examples{/api/covers/9999 | GET| null}
   */
  void getCover(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    print_req(request);

    try {
      const int index = std::stoi(request->path_match[1]);
      if (!check_app_index(response, request, index)) {
        return;
      }

      std::string file = file_handler::read_file(config::stream.file_apps.c_str());
      nlohmann::json file_tree = nlohmann::json::parse(file);
      auto &apps = file_tree["apps"];

      auto &app = apps[index];

      // Get the image path from the app configuration
      std::string app_image_path;
      if (app.contains("image-path") && !app["image-path"].is_null()) {
        app_image_path = app["image-path"];
      }

      // Use validate_app_image_path to resolve and validate the path
      // This handles extension validation, PNG signature validation, and path resolution
      std::string validated_path = proc::validate_app_image_path(app_image_path);

      // Check if we got the default image path (means validation failed or no image configured)
      if (validated_path == DEFAULT_APP_IMAGE_PATH) {
        BOOST_LOG(debug) << "Application at index " << index << " does not have a valid cover image";
        not_found(response, request, "Cover image not found");
        return;
      }

      // Open and stream the validated file
      std::ifstream in(validated_path, std::ios::binary);
      if (!in) {
        BOOST_LOG(warning) << "Unable to read cover image file: " << validated_path;
        bad_request(response, request, "Unable to read cover image file");
        return;
      }

      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Content-Type", "image/png");
      headers.emplace("X-Frame-Options", "DENY");
      headers.emplace("Content-Security-Policy", "frame-ancestors 'none';");

      response->write(SimpleWeb::StatusCode::success_ok, in, headers);
    } catch (std::exception &e) {
      BOOST_LOG(warning) << "GetCover: "sv << e.what();
      bad_request(response, request, e.what());
    }
  }

  /**
   * @brief Upload a cover image.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * The body for the post request should be JSON serialized in the following format:
   * @code{.json}
   * {
   *   "key": "igdb_<game_id>",
   *   "url": "https://images.igdb.com/igdb/image/upload/t_cover_big_2x/<slug>.png"
   * }
   * @endcode
   *
   * @api_examples{/api/covers/upload| POST| {"key":"igdb_1234","url":"https://images.igdb.com/igdb/image/upload/t_cover_big_2x/abc123.png"}}
   */
  void uploadCover(const resp_https_t &response, const req_https_t &request) {
    if (!check_content_type(response, request, "application/json")) {
      return;
    }
    if (!authenticate(response, request)) {
      return;
    }

    std::stringstream ss;
    ss << request->content.rdbuf();
    try {
      nlohmann::json output_tree;
      nlohmann::json input_tree = nlohmann::json::parse(ss);

      std::string key = input_tree.value("key", "");
      if (key.empty()) {
        bad_request(response, request, "Cover key is required");
        return;
      }
      std::string url = input_tree.value("url", "");

      const std::string coverdir = platf::appdata().string() + "/covers/";
      file_handler::make_directory(coverdir);

      std::basic_string path = coverdir + http::url_escape(key) + ".png";
      if (!url.empty()) {
        if (http::url_get_host(url) != "images.igdb.com") {
          bad_request(response, request, "Only images.igdb.com is allowed");
          return;
        }
        if (!http::download_file(url, path)) {
          bad_request(response, request, "Failed to download cover");
          return;
        }
      } else {
        auto data = SimpleWeb::Crypto::Base64::decode(input_tree.value("data", ""));

        std::ofstream imgfile(path);
        imgfile.write(data.data(), static_cast<int>(data.size()));
      }
      output_tree["status"] = true;
      output_tree["path"] = path;
      send_response(response, output_tree);
    } catch (std::exception &e) {
      BOOST_LOG(warning) << "UploadCover: "sv << e.what();
      bad_request(response, request, e.what());
    }
  }

  /**
   * @brief Get the logs from the log file.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/logs| GET| null}
   */
  void getLogs(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    print_req(request);

    std::string content = file_handler::read_file(config::sunshine.log_file.c_str());
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/plain");
    headers.emplace("X-Frame-Options", "DENY");
    headers.emplace("Content-Security-Policy", "frame-ancestors 'none';");
    response->write(SimpleWeb::StatusCode::success_ok, content, headers);
  }

  /**
   * @brief Update existing credentials.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * The body for the post request should be JSON serialized in the following format:
   * @code{.json}
   * {
   *   "currentUsername": "Current Username",
   *   "currentPassword": "Current Password",
   *   "newUsername": "New Username",
   *   "newPassword": "New Password",
   *   "confirmNewPassword": "Confirm New Password"
   * }
   * @endcode
   *
   * @api_examples{/api/password| POST| {"currentUsername":"admin","currentPassword":"admin","newUsername":"admin","newPassword":"admin","confirmNewPassword":"admin"}}
   */
  void savePassword(const resp_https_t &response, const req_https_t &request) {
    if (!check_content_type(response, request, "application/json")) {
      return;
    }
    if (config::sunshine.username.empty()) {
      if (!bootstrap_allowed(request->remote_endpoint().address())) {
        response->write(SimpleWeb::StatusCode::client_error_forbidden);
        return;
      }
    } else {
      if (!authenticate(response, request)) {
        return;
      }
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    std::vector<std::string> errors = {};
    std::stringstream ss;
    std::stringstream config_stream;
    ss << request->content.rdbuf();
    try {
      // TODO: Input Validation
      nlohmann::json output_tree;
      nlohmann::json input_tree = nlohmann::json::parse(ss);
      std::string username = input_tree.value("currentUsername", "");
      std::string newUsername = input_tree.value("newUsername", "");
      std::string password = input_tree.value("currentPassword", "");
      std::string newPassword = input_tree.value("newPassword", "");
      std::string confirmPassword = input_tree.value("confirmNewPassword", "");
      if (newUsername.empty()) {
        newUsername = username;
      }
      if (newUsername.empty()) {
        errors.emplace_back("Invalid Username");
      } else {
        const auto password_result = http::verify_user_password(password, config::sunshine.password, config::sunshine.salt);
        if (config::sunshine.username.empty() || (boost::iequals(username, config::sunshine.username) && password_result != http::password_verification_e::INVALID)) {
          if (newPassword.empty() || newPassword != confirmPassword) {
            errors.emplace_back("Password Mismatch");
          } else {
            http::user_credentials_t saved;
            if (http::save_user_creds(config::sunshine.credentials_file, newUsername, newPassword, false, &saved) != 0) {
              errors.emplace_back("Failed to save credentials");
            } else {
              config::sunshine.username = std::move(saved.username);
              config::sunshine.password = std::move(saved.password);
              config::sunshine.salt = std::move(saved.salt);
              output_tree["status"] = true;
            }
          }
        } else {
          errors.emplace_back("Invalid Current Credentials");
        }
      }

      if (!errors.empty()) {
        // join the errors array
        std::string error = std::accumulate(errors.begin(), errors.end(), std::string(), [](const std::string &a, const std::string &b) {
          return a.empty() ? b : a + ", " + b;
        });
        bad_request(response, request, error);
        return;
      }

      send_response(response, output_tree);
    } catch (std::exception &e) {
      BOOST_LOG(warning) << "SavePassword: "sv << e.what();
      bad_request(response, request, e.what());
    }
  }

  /**
   * @brief Send a pin code to the host. The pin is generated from the Moonlight client during the pairing process.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * The body for the post request should be JSON serialized in the following format:
   * @code{.json}
   * {
   *   "pin": "<pin>",
   *   "name": "Friendly Client Name",
   *   "requestId": "<pairing request ID>"
   * }
   * @endcode
   *
   * @api_examples{/api/pin| POST| {"pin":"1234","name":"My PC"}}
   */
  void savePin(const resp_https_t &response, const req_https_t &request) {
    if (!check_content_type(response, request, "application/json")) {
      return;
    }
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }
    if (request->content.size() > 1024) {
      bad_request(response, request, "PIN request body is too large");
      return;
    }

    print_req(request);

    std::stringstream ss;
    ss << request->content.rdbuf();
    try {
      nlohmann::json output_tree;
      nlohmann::json input_tree = nlohmann::json::parse(ss);
      const std::string name = input_tree.value("name", "");
      const std::string pin = input_tree.value("pin", "");
      const std::string request_id = input_tree.value("requestId", "");

      output_tree["status"] = request_id.empty() ? nvhttp::pin(pin, name) : nvhttp::pin(pin, name, request_id);
      send_response(response, output_tree);
    } catch (std::exception &e) {
      BOOST_LOG(warning) << "SavePin: "sv << e.what();
      bad_request(response, request, e.what());
    }
  }

  /**
   * @brief List the opaque IDs of pairing requests currently awaiting a PIN.
   */
  void getPendingPairingRequests(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    nlohmann::json output_tree;
    output_tree["requests"] = nlohmann::json::array();
    for (const auto &pending : nvhttp::pending_pairing_requests()) {
      output_tree["requests"].push_back({{"requestId", pending.request_id}, {"source", pending.source}, {"ageSeconds", pending.age_seconds}, {"clientFingerprint", pending.client_fingerprint}});
    }
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "application/json");
    headers.emplace("X-Frame-Options", "DENY");
    headers.emplace("Content-Security-Policy", "frame-ancestors 'none';");
    headers.emplace("Cache-Control", "no-store");
    response->write(output_tree.dump(), headers);
  }

  /**
   * @brief Cancel one pending pairing request by opaque request ID.
   */
  void cancelPendingPairingRequest(const resp_https_t &response, const req_https_t &request) {
    if (!check_content_type(response, request, "application/json")) {
      return;
    }
    if (!authenticate(response, request)) {
      return;
    }

    const std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }
    if (request->content.size() > 256) {
      bad_request(response, request, "Pairing cancellation body is too large");
      return;
    }

    std::stringstream body;
    body << request->content.rdbuf();
    try {
      const auto input_tree = nlohmann::json::parse(body);
      const std::string request_id = input_tree.value("requestId", "");
      nlohmann::json output_tree;
      output_tree["status"] = nvhttp::cancel_pairing_request(request_id);
      send_response(response, output_tree);
    } catch (const std::exception &error) {
      BOOST_LOG(warning) << "CancelPairingRequest: "sv << error.what();
      bad_request(response, request, error.what());
    }
  }

  /**
   * @brief Reset the display device persistence.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/reset-display-device-persistence| POST| null}
   */
  void resetDisplayDevicePersistence(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    nlohmann::json output_tree;
    output_tree["status"] = display_device::reset_persistence();
    send_response(response, output_tree);
  }

  /**
   * @brief Authenticate a Web UI request and restart the Sunshine process.
   *
   * @param response HTTP response used for authentication or CSRF failures.
   * @param request HTTP request carrying the client identity and CSRF token.
   *
   * @api_examples{/api/restart| POST| null}
   */
  void restart(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    // We may not return from this call
    platf::restart();
  }

  /**
   * @brief Get ViGEmBus driver version and installation status.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/vigembus/status| GET| null}
   */
  void getViGEmBusStatus(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    print_req(request);

    nlohmann::json output_tree;

#ifdef _WIN32
    std::string version_str;
    bool installed = false;
    bool version_compatible = false;

    // Check if ViGEmBus driver exists
    std::filesystem::path driver_path = std::filesystem::path(std::getenv("SystemRoot") ? std::getenv("SystemRoot") : "C:\\Windows") / "System32" / "drivers" / "ViGEmBus.sys";

    if (std::filesystem::exists(driver_path)) {
      installed = platf::getFileVersionInfo(driver_path, version_str);
      if (installed) {
        // Parse version string to check compatibility (>= 1.17.0.0)
        std::vector<std::string> version_parts;
        std::stringstream ss(version_str);
        std::string part;
        while (std::getline(ss, part, '.')) {
          version_parts.push_back(part);
        }

        if (version_parts.size() >= 2) {
          int major = std::stoi(version_parts[0]);
          int minor = std::stoi(version_parts[1]);
          version_compatible = (major > 1) || (major == 1 && minor >= 17);
        }
      }
    }

    output_tree["installed"] = installed;
    output_tree["version"] = version_str;
    output_tree["version_compatible"] = version_compatible;
    output_tree["packaged_version"] = VIGEMBUS_PACKAGED_VERSION;
#else
    output_tree["error"] = "ViGEmBus is only available on Windows";
    output_tree["installed"] = false;
    output_tree["version"] = "";
    output_tree["version_compatible"] = false;
    output_tree["packaged_version"] = "";
#endif

    send_response(response, output_tree);
  }

  /**
   * @brief Return read-only Lumen Virtual Display health and active-path status.
   * @param response HTTP response populated after authentication.
   * @param request HTTP request carrying the dashboard credentials.
   *
   * @api_examples{/api/vdd/status| GET| null}
   */
  void getVddStatus(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    print_req(request);

    nlohmann::json output_tree {
      {"installed", false},
      {"compatible", false},
      {"deviceHealthy", false},
      {"problem", nullptr},
      {"active", false},
      {"generation", nullptr},
      {"mode", nullptr},
      {"deliveryPolicy", nullptr},
      {"directFrameBound", false},
      {"quarantined", false},
      {"fallback", false},
      {"captureState", "inactive"},
      {"diagnostic", "Lumen Virtual Display is available only on Windows."},
    };

#ifdef _WIN32
    const auto status = platf::virtual_display::query_system_status();
    output_tree["installed"] = status.installed;
    output_tree["compatible"] = status.compatible;
    output_tree["deviceHealthy"] = status.device_healthy;
    output_tree["problem"] = status.device_problem ?
                               nlohmann::json {*status.device_problem} :
                               nlohmann::json {nullptr};
    output_tree["directFrameBound"] = status.direct_frame_bound;
    output_tree["quarantined"] = status.direct_frame_quarantined;
    output_tree["fallback"] = status.fallback;
    output_tree["captureState"] = std::string {platf::virtual_display::capture_path_status_name(status.capture_path)};
    output_tree["diagnostic"] = status.diagnostic;
    if (status.active) {
      output_tree["active"] = true;
      output_tree["generation"] = status.active->generation;
      output_tree["deliveryPolicy"] =
        status.active->delivery_policy == platf::virtual_display::delivery_policy_e::latency ?
          "latency" :
          "quality";
      output_tree["mode"] = {
        {"width", status.active->mode.width},
        {"height", status.active->mode.height},
        {"refreshNumerator", status.active->mode.refresh.numerator},
        {"refreshDenominator", status.active->mode.refresh.denominator},
        {"hdr", status.active->mode.dynamic_range == platf::virtual_display::dynamic_range_e::hdr10},
        {"bitDepth", status.active->mode.bits_per_channel},
      };
    }
#endif

    send_response(response, output_tree);
  }

  /**
   * @brief Install ViGEmBus driver with elevated permissions.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/vigembus/install| POST| null}
   */
  void installViGEmBus(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    nlohmann::json output_tree;

#ifdef _WIN32
    // Get the path to the packaged ViGEmBus installer.
    const std::filesystem::path installer_path = platf::appdata().parent_path() / "third-party" / "vigembus_installer.exe";

    if (!std::filesystem::exists(installer_path)) {
      output_tree["status"] = false;
      output_tree["error"] = "ViGEmBus installer not found";
      send_response(response, output_tree);
      return;
    }

    // Run the installer with elevated permissions
    std::error_code ec;
    boost::filesystem::path working_dir = boost::filesystem::path(installer_path.string()).parent_path();
    boost::process::v1::environment env = boost::this_process::environment();

    // Run with elevated permissions, non-interactive
    const std::string install_cmd = std::format("{} /quiet", installer_path.string());
    auto child = platf::run_command(true, false, install_cmd, working_dir, env, nullptr, ec, nullptr);

    if (ec) {
      output_tree["status"] = false;
      output_tree["error"] = "Failed to start installer: " + ec.message();
      send_response(response, output_tree);
      return;
    }

    // Wait for the installer to complete
    child.wait(ec);

    if (ec) {
      output_tree["status"] = false;
      output_tree["error"] = "Installer failed: " + ec.message();
    } else {
      int exit_code = child.exit_code();
      output_tree["status"] = (exit_code == 0);
      output_tree["exit_code"] = exit_code;
      if (exit_code != 0) {
        output_tree["error"] = std::format("Installer exited with code {}", exit_code);
      }
    }
#else
    output_tree["status"] = false;
    output_tree["error"] = "ViGEmBus installation is only available on Windows";
#endif

    send_response(response, output_tree);
  }

  /**
   * @brief Checks whether a directory entry qualifies as an executable file.
   * @param entry The directory entry to check.
   * @param status The cached file status for the entry.
   * @return True if the file should be included in an executable-type listing.
   */
  bool is_browsable_executable([[maybe_unused]] const fs::directory_entry &entry, [[maybe_unused]] const fs::file_status &status) {
#ifdef _WIN32
    auto ext = entry.path().extension().string();
    boost::algorithm::to_lower(ext);
    return ext == ".exe" || ext == ".bat" || ext == ".cmd" || ext == ".com" || ext == ".ps1";
#else
    const auto perms = status.permissions();
    return (perms & fs::perms::owner_exec) != fs::perms::none ||
           (perms & fs::perms::group_exec) != fs::perms::none ||
           (perms & fs::perms::others_exec) != fs::perms::none;
#endif
  }

#ifdef _WIN32
  /**
   * @brief Builds a JSON array of available Windows drive letters.
   * @return JSON array of drive-letter entries.
   */
  nlohmann::json get_windows_drives() {
    nlohmann::json entries = nlohmann::json::array();
    const DWORD drives = GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
      if (drives & (1 << i)) {
        const auto drive_letter = static_cast<char>('A' + i);
        const auto drive_path = std::string(1, drive_letter) + ":\\";
        nlohmann::json entry;
        entry["name"] = drive_path;
        entry["type"] = "directory";
        entry["path"] = drive_path;
        entries.push_back(entry);
      }
    }
    return entries;
  }
#endif

  /**
   * @brief Lists, filters, and sorts the entries of a directory for the browse API.
   * @param dir_path The directory to list.
   * @param type_str Filter type: "directory", "executable", "file", or "any".
   * @return Sorted JSON array of entry objects with name/type/path fields.
   */
  nlohmann::json build_browse_entries(const fs::path &dir_path, const std::string &type_str) {
    nlohmann::json entries = nlohmann::json::array();

    std::error_code iter_ec;
    for (auto it = fs::directory_iterator(dir_path, fs::directory_options::skip_permission_denied, iter_ec);
         !iter_ec && it != fs::directory_iterator();
         it.increment(iter_ec)) {
      try {
        const auto status = it->status();
        const bool is_dir = fs::is_directory(status);

        if (const bool is_regular = fs::is_regular_file(status); !is_dir && !is_regular) {
          continue;
        }

        // Apply type filter (directories are always included for navigation)
        if (type_str == "directory" && !is_dir) {
          continue;
        }

        if (type_str == "executable" && !is_dir && !is_browsable_executable(*it, status)) {
          continue;
        }

        nlohmann::json file_entry;
        file_entry["name"] = it->path().filename().string();
        file_entry["path"] = it->path().string();
        file_entry["type"] = is_dir ? "directory" : "file";
        entries.push_back(file_entry);
      } catch (const fs::filesystem_error &e) {
        BOOST_LOG(debug) << "BrowseDirectory: skipping entry due to error: "sv << e.what();
      }
    }

    if (iter_ec) {
      BOOST_LOG(debug) << "BrowseDirectory: directory iteration error: "sv << iter_ec.message();
    }

    // Sort: directories first, then files; both case-insensitively alphabetical
    std::sort(entries.begin(), entries.end(), [](const nlohmann::json &a, const nlohmann::json &b) {
      const bool a_dir = (a["type"] == "directory");
      if (const bool b_dir = (b["type"] == "directory"); a_dir != b_dir) {
        return a_dir && !b_dir;
      }
      auto a_name = a["name"].get<std::string>();
      auto b_name = b["name"].get<std::string>();
      boost::algorithm::to_lower(a_name);
      boost::algorithm::to_lower(b_name);
      return a_name < b_name;
    });

    return entries;
  }

  /**
   * @brief Browse the server filesystem.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * @note On Windows, an empty or root path returns the list of available drive letters.
   * @note On non-Windows, an empty path defaults to the filesystem root ("/").
   *
   * @api_examples{/api/browse?path=/home/user&type=directory| GET| null}
   */
  void browseDirectory(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    print_req(request);

    try {
      const auto query_params = request->parse_query_string();

      std::string path_str;
      if (const auto path_it = query_params.find("path"); path_it != query_params.end()) {
        path_str = path_it->second;
      }

      std::string type_str = "any";
      if (const auto type_it = query_params.find("type"); type_it != query_params.end() && !type_it->second.empty()) {
        type_str = type_it->second;
      }

      nlohmann::json output_tree;

#ifdef _WIN32
      // On Windows with an empty or root path, return the list of available drive letters
      if (path_str.empty() || path_str == "/" || path_str == "\\") {
        output_tree["path"] = "";
        output_tree["parent"] = "";
        output_tree["entries"] = get_windows_drives();
        send_response(response, output_tree);
        return;
      }
#else
      // On non-Windows, default an empty path to the filesystem root
      if (path_str.empty()) {
        path_str = "/";
      }
#endif

      // Normalize the path
      fs::path dir_path = fs::weakly_canonical(fs::path(path_str));

      // If the path points to a file, use its parent directory
      std::error_code ec;
      if (fs::is_regular_file(dir_path, ec)) {
        dir_path = dir_path.parent_path();
      }

      // If the path doesn't exist, try the parent
      if (!fs::exists(dir_path, ec)) {
        dir_path = dir_path.parent_path();
      }

      if (!fs::is_directory(dir_path, ec)) {
        bad_request(response, request, "Path is not a directory");
        return;
      }

      output_tree["path"] = dir_path.string();

      // Determine the parent path for the "Up" navigation
      const fs::path parent = dir_path.parent_path();
#ifdef _WIN32
      // At a drive root (e.g., C:\) the parent equals itself; signal the drive list with an empty string
      output_tree["parent"] = (parent == dir_path) ? "" : parent.string();
#else
      output_tree["parent"] = parent.string();
#endif

      output_tree["entries"] = build_browse_entries(dir_path, type_str);
      send_response(response, output_tree);
    } catch (const fs::filesystem_error &e) {
      BOOST_LOG(warning) << "BrowseDirectory: "sv << e.what();
      bad_request(response, request, e.what());
    }
  }

  /**
   * @brief Start the HTTPS configuration server.
   */
  void start() {
    platf::set_thread_name("confighttp");
    const auto shutdown_event = mail::man->event<bool>(mail::shutdown);

    const auto port_https = net::map_port(PORT_HTTPS);
    const auto address_family = net::af_from_enum_string(config::sunshine.address_family);

    https_server_t server {config::nvhttp.cert, config::nvhttp.pkey};

    // Helper to create page handler lambdas without repeating the signature
    auto page_handler = [](const char *file, bool require_auth = true, bool redirect_if_username = false) {
      return [file, require_auth, redirect_if_username](const resp_https_t &response, const req_https_t &request) {
        getPage(response, request, file, require_auth, redirect_if_username);
      };
    };

    // Default resource handlers
    const https_handler_t bad_request_handler = [](const resp_https_t &response, const req_https_t &request) {
      bad_request(response, request);
    };
    const https_handler_t not_found_handler = [](const resp_https_t &response, const req_https_t &request) {
      not_found(response, request);
    };

    // error by default
    server.default_resource["DELETE"] = bad_request_handler;
    server.default_resource["PATCH"] = bad_request_handler;
    server.default_resource["POST"] = bad_request_handler;
    server.default_resource["PUT"] = bad_request_handler;
    server.default_resource["GET"] = not_found_handler;

    // web pages
    server.resource["^/$"]["GET"] = page_handler("index.html");
    server.resource["^/apps/?$"]["GET"] = page_handler("apps.html");
    server.resource["^/clients/?$"]["GET"] = page_handler("clients.html");
    server.resource["^/config/?$"]["GET"] = page_handler("config.html");
    server.resource["^/featured/?$"]["GET"] = page_handler("featured.html");
    server.resource["^/logout/?$"]["GET"] = page_handler("logout.html", false);
    server.resource["^/password/?$"]["GET"] = page_handler("password.html");
    server.resource["^/pin/?$"]["GET"] = page_handler("pin.html");
    server.resource["^/troubleshooting/?$"]["GET"] = page_handler("troubleshooting.html");
    server.resource["^/welcome/?$"]["GET"] = page_handler("welcome.html", false, true);

    // rest api
    server.resource["^/api/browse$"]["GET"] = browseDirectory;
    server.resource["^/api/apps$"]["GET"] = getApps;
    server.resource["^/api/apps$"]["POST"] = saveApp;
    server.resource["^/api/apps/([0-9]+)$"]["DELETE"] = deleteApp;
    server.resource["^/api/apps/close$"]["POST"] = closeApp;
    server.resource["^/api/clients/list$"]["GET"] = getClients;
    server.resource["^/api/clients/unpair$"]["POST"] = unpair;
    server.resource["^/api/clients/unpair-all$"]["POST"] = unpairAll;
    server.resource["^/api/clients/update$"]["POST"] = updateClient;
    server.resource["^/api/config$"]["GET"] = getConfig;
    server.resource["^/api/config$"]["POST"] = saveConfig;
    server.resource["^/api/configLocale$"]["GET"] = getLocale;
    server.resource["^/api/covers/([0-9]+)$"]["GET"] = getCover;
    server.resource["^/api/covers/upload$"]["POST"] = uploadCover;
    server.resource["^/api/csrf-token$"]["GET"] = getCSRFToken;
    server.resource["^/api/lsp/status$"]["GET"] = getLspStatus;
    server.resource["^/api/lsp/pairing$"]["GET"] = getLspPairing;
    server.resource["^/api/lsp/pairing$"]["DELETE"] = cancelLspPairing;
    server.resource["^/api/lsp/pairing/pin$"]["POST"] = submitLspPairingPin;
    server.resource["^/api/lsp/clients$"]["GET"] = getLspClients;
    server.resource["^/api/lsp/clients$"]["PATCH"] = updateLspClient;
    server.resource["^/api/lsp/clients$"]["DELETE"] = revokeLspClient;
    server.resource["^/api/lsp/identity/rotate$"]["POST"] = rotateLspIdentity;
    server.resource["^/api/password$"]["POST"] = savePassword;
    server.resource["^/api/pin$"]["GET"] = getPendingPairingRequests;
    server.resource["^/api/pin$"]["POST"] = savePin;
    server.resource["^/api/pin/cancel$"]["POST"] = cancelPendingPairingRequest;
    server.resource["^/api/logs$"]["GET"] = getLogs;
    server.resource["^/api/reset-display-device-persistence$"]["POST"] = resetDisplayDevicePersistence;
    server.resource["^/api/restart$"]["POST"] = restart;
    server.resource["^/api/vigembus/status$"]["GET"] = getViGEmBusStatus;
    server.resource["^/api/vigembus/install$"]["POST"] = installViGEmBus;
    server.resource["^/api/vdd/status$"]["GET"] = getVddStatus;

    // static/dynamic resources
    server.resource["^/images/sunshine.ico$"]["GET"] = getFaviconImage;
    server.resource["^/images/logo-sunshine-45.png$"]["GET"] = getSunshineLogoImage;
    server.resource["^/assets\\/.+$"]["GET"] = getAsset;

    server.config.reuse_address = true;
    server.config.timeout_request = REQUEST_HEADER_TIMEOUT_SECONDS;
    server.config.timeout_content = REQUEST_BODY_TIMEOUT_SECONDS;
    server.config.max_request_streambuf_size = MAX_REQUEST_BODY_SIZE;
    server.config.reject_transfer_encoding = true;
    server.config.max_active_connections = MAX_ACTIVE_CONNECTIONS;
    server.config.max_active_connections_per_source = MAX_ACTIVE_CONNECTIONS_PER_SOURCE;
    server.config.address = net::get_bind_address(address_family);
    server.config.port = port_https;

    // Store bind address for logging, use "localhost" as fallback for wildcard addresses
    const auto bind_addr = server.config.address;
    const auto display_addr = config::sunshine.bind_address.empty() ? "localhost"sv : std::string_view {bind_addr};

    auto accept_and_run = [&](auto *server) {
      try {
        platf::set_thread_name("confighttp::tcp");
        server->start([&display_addr](const unsigned short port) {
          BOOST_LOG(info) << "Configuration UI available at [https://"sv << display_addr << ":" << port << "]";
        });
      } catch (boost::system::system_error &err) {
        // It's possible the exception gets thrown after calling server->stop() from a different thread
        if (shutdown_event->peek()) {
          return;
        }

        BOOST_LOG(fatal) << "Couldn't start Configuration HTTPS server on port ["sv << port_https << "]: "sv << err.what();
        shutdown_event->raise(true);
        return;
      }
    };
    std::jthread tcp {accept_and_run, &server};

    // Wait for any event
    shutdown_event->view();

    server.stop();

    tcp.join();
  }
}  // namespace confighttp
