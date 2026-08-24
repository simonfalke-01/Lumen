/**
 * @file src/httpcommon.h
 * @brief Declarations for common HTTP.
 */
#pragma once

// standard includes
#include <functional>
#include <optional>
#include <string_view>

// lib includes
#include <boost/property_tree/ptree.hpp>
#include <curl/curl.h>

// local includes
#include "network.h"
#include "thread_safe.h"

namespace http {

  using state_file_tree_t = boost::property_tree::ptree;  ///< JSON-compatible shared state tree.
  using state_file_mutator_t = std::function<void(state_file_tree_t &)>;  ///< In-lock state mutation callback.

  /**
   * @brief Result of verifying a Web UI password hash.
   */
  enum class password_verification_e {
    INVALID,  ///< The password did not match or the stored format was invalid.
    CURRENT,  ///< The password matched the current versioned KDF format.
    LEGACY  ///< The password matched the legacy SHA-256 format and should be migrated.
  };

  /**
   * @brief Fully derived credentials committed to the shared state file.
   */
  struct user_credentials_t {
    std::string username;  ///< Persisted Web UI username.
    std::string password;  ///< Persisted versioned password hash.
    std::string salt;  ///< Persisted per-credential salt.
  };

  /**
   * @brief Initialize shared HTTP client state.
   *
   * @return 0 when HTTP state initializes successfully; nonzero on failure.
   */
  int init();
  /**
   * @brief Generate HTTPS credential files from the provided key and certificate paths.
   *
   * @param pkey Private key PEM data or private key file path.
   * @param cert Certificate data or object used by the operation.
   * @return Created creds object or status.
   */
  int create_creds(const std::string &pkey, const std::string &cert);

  /**
   * @brief Atomically persist versioned Web UI credentials.
   *
   * @param file Shared state file path.
   * @param username Username to persist.
   * @param password Plaintext password to derive and persist.
   * @param run_our_mouth Whether to emit the existing user-facing status message.
   * @param saved_credentials Optional destination for the committed derived credentials.
   * @return Zero after commit, or nonzero when derivation or persistence fails.
   */
  int save_user_creds(
    const std::string &file,
    const std::string &username,
    const std::string &password,
    bool run_our_mouth = false,
    user_credentials_t *saved_credentials = nullptr
  );

  /**
   * @brief Derive the current versioned Web UI password hash.
   *
   * @param password Plaintext password supplied by the user.
   * @param salt Per-credential salt stored alongside the hash.
   * @return Versioned encoded hash, or no value when OpenSSL rejects the derivation.
   */
  [[nodiscard]] std::optional<std::string> hash_user_password(std::string_view password, std::string_view salt);

  /**
   * @brief Verify a Web UI password against either current or legacy storage.
   *
   * @param password Plaintext password supplied by the user.
   * @param stored_hash Persisted password hash.
   * @param salt Persisted per-credential salt.
   * @return Verification result including whether a successful legacy hash needs migration.
   */
  [[nodiscard]] password_verification_e verify_user_password(std::string_view password, std::string_view stored_hash, std::string_view salt);

  /**
   * @brief Read a shared state file while holding its resolved-path lock.
   *
   * @param file State file path.
   * @param tree Destination tree, replaced only after a complete parse.
   * @return True when the file was read and parsed successfully.
   */
  [[nodiscard]] bool read_state_file(const std::string &file, state_file_tree_t &tree);

  /**
   * @brief Atomically read, mutate, and replace a shared JSON state file.
   *
   * @param file State file path.
   * @param mutator Callback applied while the file's resolved-path lock is held.
   * @return True when the complete transaction was committed.
   */
  [[nodiscard]] bool update_state_file(const std::string &file, const state_file_mutator_t &mutator);

  /**
   * @brief Reload Web UI user credentials from disk.
   *
   * @param file Destination path for the downloaded content.
   * @return 0 when credentials reload successfully; nonzero on failure.
   */
  int reload_user_creds(const std::string &file);
  /**
   * @brief Download a URL to a local file using libcurl.
   *
   * @param url URL used for the HTTP request.
   * @param file Destination path for the downloaded content.
   * @param ssl_version libcurl TLS version selector for the request.
   * @return True when the file is downloaded successfully.
   */
  bool download_file(const std::string &url, const std::string &file, long ssl_version = CURL_SSLVERSION_TLSv1_2);
  /**
   * @brief Percent-encode a string for safe inclusion in a URL.
   *
   * @param url URL used for the HTTP request.
   * @return Percent-encoded URL component.
   */
  std::string url_escape(const std::string &url);
  /**
   * @brief Extract the host component from a URL.
   *
   * @param url URL used for the HTTP request.
   * @return Host name parsed from the URL, or an empty string when none is present.
   */
  std::string url_get_host(const std::string &url);

  extern std::string unique_id;
  extern net::net_e origin_web_ui_allowed;

}  // namespace http
