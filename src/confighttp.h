/**
 * @file src/confighttp.h
 * @brief Declarations for the Web UI Config HTTP server.
 */
#pragma once

// standard includes
#include <chrono>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <string>

// lib includes
#include <boost/asio/ip/address.hpp>
#include <nlohmann/json.hpp>
#include <Simple-Web-Server/server_https.hpp>

// local includes
#include "thread_safe.h"

/**
 * @def WEB_DIR
 * @brief Macro for WEB DIR.
 */
#define WEB_DIR SUNSHINE_ASSETS_DIR "/web/"

namespace confighttp {
  constexpr auto PORT_HTTPS = 1;  ///< GameStream port offset for port https.
  constexpr std::size_t MAX_REQUEST_BODY_SIZE = 1024 * 1024;  ///< Maximum buffered Web UI header or body segment size.
  constexpr long REQUEST_HEADER_TIMEOUT_SECONDS = 3;  ///< TLS handshake and request-header deadline.
  constexpr long REQUEST_BODY_TIMEOUT_SECONDS = 15;  ///< Request-body deadline, sufficient for a 1 MiB LAN upload.
  constexpr std::size_t MAX_ACTIVE_CONNECTIONS = 64;  ///< Global Web UI connection ceiling.
  constexpr std::size_t MAX_ACTIVE_CONNECTIONS_PER_SOURCE = 8;  ///< Web UI connection ceiling for one normalized source.

  // Type aliases for HTTPS server components
  using https_server_t = SimpleWeb::Server<SimpleWeb::HTTPS>;
  using resp_https_t = std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTPS>::Response>;
  using req_https_t = std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTPS>::Request>;

  /**
   * @brief Bounded failed-login tracker keyed by normalized network source.
   */
  class login_throttle_t {
  public:
    using clock_t = std::chrono::steady_clock;  ///< Monotonic clock used for expiry.

    /**
     * @brief Construct a failed-login tracker.
     *
     * @param maximum_sources Maximum number of live source records retained.
     * @param maximum_failures Number of failures allowed during one window.
     * @param failure_window Lifetime of a source's failed-login budget.
     */
    explicit login_throttle_t(
      std::size_t maximum_sources = 1024,
      std::size_t maximum_failures = 5,
      clock_t::duration failure_window = std::chrono::minutes(5)
    );

    /**
     * @brief Normalize an address into an IPv4 host or IPv6 /64 source key.
     *
     * @param address Remote network address.
     * @return Stable source key used for throttling.
     */
    [[nodiscard]] static std::string source_key(boost::asio::ip::address address);

    /**
     * @brief Check whether a source has exhausted its failed-login budget.
     *
     * @param address Remote network address.
     * @param now Current monotonic time.
     * @return True when authentication attempts should remain rejected.
     */
    [[nodiscard]] bool is_blocked(boost::asio::ip::address address, clock_t::time_point now = clock_t::now());

    /**
     * @brief Consume one failed-login attempt for a source.
     *
     * @param address Remote network address.
     * @param now Current monotonic time.
     */
    void record_failure(boost::asio::ip::address address, clock_t::time_point now = clock_t::now());

    /**
     * @brief Clear the failed-login budget after successful authentication.
     *
     * @param address Remote network address.
     */
    void record_success(boost::asio::ip::address address);

  private:
    /**
     * @brief Failed-login state for one normalized source.
     */
    struct source_state_t {
      std::size_t failures;  ///< Failures recorded in the current window.
      clock_t::time_point expiration;  ///< Deadline at which the budget resets.
    };

    /**
     * @brief Remove expired source records while holding the tracker lock.
     *
     * @param now Current monotonic time.
     */
    void prune_expired(clock_t::time_point now);

    std::size_t maximum_sources_;  ///< Hard cap on retained source records.
    std::size_t maximum_failures_;  ///< Failures permitted in one window.
    clock_t::duration failure_window_;  ///< Lifetime of one failure window.
    std::map<std::string, source_state_t, std::less<>> sources_;  ///< Live failure state by normalized source.
    std::mutex mutex_;  ///< Protects source failure state.
  };

  /**
   * @brief Check whether initial Web UI credential creation may originate from an address.
   *
   * @param address Remote network address.
   * @return True only for normalized IPv4 or IPv6 loopback addresses.
   */
  [[nodiscard]] bool bootstrap_allowed(boost::asio::ip::address address);

  /**
   * @brief Format a request header or query value for logging without exposing credentials.
   *
   * @param name Request header or query-field name.
   * @param value Request field value.
   * @return Original value for ordinary fields or a redaction marker for sensitive fields.
   */
  [[nodiscard]] std::string_view request_log_value(std::string_view name, std::string_view value);

#ifdef SUNSHINE_TESTS
  /**
   * @brief Clear loopback failed-login state between Web UI tests.
   */
  void reset_login_throttle_for_tests();
#endif

  // Main server start function
  void start();

  void print_req(const req_https_t &request);
  void send_response(const resp_https_t &response, const nlohmann::json &output_tree);
  void send_unauthorized(const resp_https_t &response, const req_https_t &request);
  void send_redirect(const resp_https_t &response, const req_https_t &request, const char *path);
  bool authenticate(const resp_https_t &response, const req_https_t &request);
  void not_found(const resp_https_t &response, const req_https_t &request, const std::string &error_message = "Not Found");
  void bad_request(const resp_https_t &response, const req_https_t &request, const std::string &error_message = "Bad Request");
  /**
   * @brief Check content type.
   *
   * @param response HTTP response object to populate.
   * @param request HTTP request data from the client.
   * @param contentType Expected HTTP content type.
   * @return True when the request passes validation and processing may continue.
   */
  bool check_content_type(const resp_https_t &response, const req_https_t &request, const std::string_view &contentType);
  std::string generate_csrf_token(const std::string &client_id);
  /**
   * @brief Validate CSRF token.
   *
   * @param response HTTP response object to populate.
   * @param request HTTP request data from the client.
   * @param client_id Client identifier used to look up the CSRF token.
   * @return True when the request passes validation and processing may continue.
   */
  bool validate_csrf_token(const resp_https_t &response, const req_https_t &request, const std::string &client_id);
  std::string get_client_id(const req_https_t &request);
  /**
   * @brief Check app index.
   *
   * @param response HTTP response object to populate.
   * @param request HTTP request data from the client.
   * @param index Zero-based index of the item being addressed.
   * @return True when the request passes validation and processing may continue.
   */
  bool check_app_index(const resp_https_t &response, const req_https_t &request, int index);
  void getPage(const resp_https_t &response, const req_https_t &request, const char *html_file, bool require_auth = true, bool redirect_if_username = false);
  void getAsset(const resp_https_t &response, const req_https_t &request);
  void browseDirectory(const resp_https_t &response, const req_https_t &request);
  void getLocale(const resp_https_t &response, const req_https_t &request);
  void getCSRFToken(const resp_https_t &response, const req_https_t &request);
  void savePassword(const resp_https_t &response, const req_https_t &request);
  void unpair(const resp_https_t &response, const req_https_t &request);
  void savePin(const resp_https_t &response, const req_https_t &request);
  void getPendingPairingRequests(const resp_https_t &response, const req_https_t &request);
  void cancelPendingPairingRequest(const resp_https_t &response, const req_https_t &request);

  // Browse helper functions (also exposed for unit testing)
  /**
   * @brief Checks whether a directory entry qualifies as an executable file.
   * @param entry The directory entry to check.
   * @param status The cached file status for the entry.
   * @return True if the file should be included in an executable-type listing.
   */
  bool is_browsable_executable(const std::filesystem::directory_entry &entry, const std::filesystem::file_status &status);

  /**
   * @brief Lists, filters, and sorts the entries of a directory for the browse API.
   * @param dir_path The directory to list.
   * @param type_str Filter type: "directory", "executable", "file", or "any".
   * @return Sorted JSON array of entry objects with name/type/path fields.
   */
  nlohmann::json build_browse_entries(const std::filesystem::path &dir_path, const std::string &type_str);

#ifdef _WIN32
  /**
   * @brief Builds a JSON array of available Windows drive letters.
   * @return JSON array of drive-letter entries.
   */
  nlohmann::json get_windows_drives();
#endif
}  // namespace confighttp

// mime types map
/**
 * @brief File-extension to MIME-type mapping used when serving the Web UI.
 */
const std::map<std::string, std::string> mime_types = {
  {"css", "text/css"},
  {"gif", "image/gif"},
  {"htm", "text/html"},
  {"html", "text/html"},
  {"ico", "image/x-icon"},
  {"jpeg", "image/jpeg"},
  {"jpg", "image/jpeg"},
  {"js", "application/javascript"},
  {"json", "application/json"},
  {"png", "image/png"},
  {"svg", "image/svg+xml"},
  {"ttf", "font/ttf"},
  {"txt", "text/plain"},
  {"woff2", "font/woff2"},
  {"xml", "text/xml"},
};
