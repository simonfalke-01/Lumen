/**
 * @file src/confighttp.h
 * @brief Lumen's administration server: the web panel and its API.
 */
#pragma once

// standard includes
#include <chrono>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

// lib includes
#include <boost/asio/ip/address.hpp>
#include <Simple-Web-Server/server_https.hpp>

/**
 * @def WEB_DIR
 * @brief Directory holding the built admin panel.
 */
#define WEB_DIR LUMEN_ASSETS_DIR "/web/"

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
   * @brief Run the admin server until shutdown.
   */
  void start();
}  // namespace confighttp
