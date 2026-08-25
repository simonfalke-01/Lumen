/**
 * @file src/httpcommon.cpp
 * @brief Definitions for common HTTP.
 */
#define BOOST_BIND_GLOBAL_PLACEHOLDERS

// standard includes
#include <array>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <utility>

// lib includes
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/context_base.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <curl/curl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <Simple-Web-Server/server_http.hpp>
#include <Simple-Web-Server/server_https.hpp>

#ifdef _WIN32
  #include <Windows.h>
#endif

// local includes
#include "config.h"
#include "crypto.h"
#include "file_handler.h"
#include "httpcommon.h"
#include "protocol_v3/host_identity_store.h"
#include "logging.h"
#include "network.h"
#include "nvhttp.h"
#include "platform/common.h"
#include "process.h"
#include "rtsp.h"
#include "utility.h"
#include "uuid.h"

namespace http {
  using namespace std::literals;
  namespace fs = std::filesystem;
  namespace pt = boost::property_tree;

  namespace {
    constexpr std::uint64_t PASSWORD_SCRYPT_N = 32768;  ///< Scrypt CPU/memory cost parameter.
    constexpr std::uint64_t PASSWORD_SCRYPT_R = 8;  ///< Scrypt block-size parameter.
    constexpr std::uint64_t PASSWORD_SCRYPT_P = 1;  ///< Scrypt parallelization parameter.
    constexpr std::uint64_t PASSWORD_SCRYPT_MAX_MEMORY = 64ULL * 1024ULL * 1024ULL;  ///< OpenSSL memory ceiling for one derivation.
    constexpr std::size_t PASSWORD_HASH_SIZE = 32;  ///< Derived password hash size in bytes.
    constexpr auto PASSWORD_HASH_PREFIX = "$scrypt$v1$32768$8$1$"sv;  ///< Self-identifying current password format.

    std::mutex state_file_locks_mutex;  ///< Protects the resolved-path lock registry. NOSONAR(cpp:S5421) - process-wide transaction owner
    std::map<std::string, std::weak_ptr<std::mutex>, std::less<>> state_file_locks;  ///< Shared state-file locks by resolved path. NOSONAR(cpp:S5421)

    /**
     * @brief Compare equal-length secret representations without early exit.
     *
     * @param left First representation.
     * @param right Second representation.
     * @return True only when both representations are byte-for-byte equal.
     */
    bool secure_equals(const std::string_view left, const std::string_view right) {
      return left.size() == right.size() &&
             (left.empty() || CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0);
    }

    /**
     * @brief Resolve a stable absolute key for a possibly nonexistent state file.
     *
     * @param file State file path.
     * @return Normalized absolute path key.
     */
    std::string state_file_key(const std::string &file) {
      std::error_code error;
      auto path = fs::weakly_canonical(fs::path(file), error);
      if (error) {
        error.clear();
        path = fs::absolute(fs::path(file), error);
      }
      return (error ? fs::path(file) : path).lexically_normal().string();
    }

    /**
     * @brief Acquire the shared mutex object for a state file path.
     *
     * @param file State file path.
     * @return Mutex shared by all transactions for the resolved path.
     */
    std::shared_ptr<std::mutex> state_file_lock(const std::string &file) {
      const auto key = state_file_key(file);
      std::scoped_lock lock(state_file_locks_mutex);
      if (const auto existing = state_file_locks.find(key); existing != state_file_locks.end()) {
        if (auto shared = existing->second.lock()) {
          return shared;
        }
      }

      auto shared = std::make_shared<std::mutex>();
      state_file_locks[key] = shared;
      return shared;
    }

    /**
     * @brief Replace a state file with a fully written sibling temporary file.
     *
     * @param temporary_path Completed temporary file.
     * @param destination_path State file to replace.
     * @return True when the replacement completed atomically.
     */
    bool replace_state_file(const fs::path &temporary_path, const fs::path &destination_path) {
#ifdef _WIN32
      return MoveFileExW(
               temporary_path.c_str(),
               destination_path.c_str(),
               MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
             ) != 0;
#else
      std::error_code error;
      fs::rename(temporary_path, destination_path, error);
      return !error;
#endif
    }
  }  // namespace

  int reload_user_creds(const std::string &file);
  /**
   * @brief Check whether the Web UI credentials file exists and is readable.
   *
   * @param file Path to the credentials file.
   * @return True when the credentials file is present.
   */
  bool user_creds_exist(const std::string &file);

  std::string unique_id;  ///< Unique ID.
  net::net_e origin_web_ui_allowed;  ///< Origin web ui allowed.

  std::optional<std::string> hash_user_password(const std::string_view password, const std::string_view salt) {
    std::array<std::uint8_t, PASSWORD_HASH_SIZE> derived {};
    if (EVP_PBE_scrypt(
          password.data(),
          password.size(),
          reinterpret_cast<const unsigned char *>(salt.data()),
          salt.size(),
          PASSWORD_SCRYPT_N,
          PASSWORD_SCRYPT_R,
          PASSWORD_SCRYPT_P,
          PASSWORD_SCRYPT_MAX_MEMORY,
          derived.data(),
          derived.size()
        ) != 1) {
      return std::nullopt;
    }

    return std::string(PASSWORD_HASH_PREFIX) + util::hex(derived).to_string();
  }

  password_verification_e verify_user_password(const std::string_view password, const std::string_view stored_hash, const std::string_view salt) {
    if (stored_hash.starts_with(PASSWORD_HASH_PREFIX)) {
      const auto candidate = hash_user_password(password, salt);
      return candidate && secure_equals(*candidate, stored_hash) ? password_verification_e::CURRENT : password_verification_e::INVALID;
    }

    const auto legacy_hash = util::hex(crypto::hash(std::string(password) + std::string(salt))).to_string();
    return secure_equals(legacy_hash, stored_hash) ? password_verification_e::LEGACY : password_verification_e::INVALID;
  }

  bool read_state_file(const std::string &file, state_file_tree_t &tree) {
    auto file_lock = state_file_lock(file);
    std::scoped_lock lock(*file_lock);

    state_file_tree_t candidate;
    try {
      pt::read_json(file, candidate);
    } catch (const std::exception &exception) {
      BOOST_LOG(error) << "Couldn't read shared state file "sv << file << ": "sv << exception.what();
      return false;
    }
    tree = std::move(candidate);
    return true;
  }

  bool update_state_file(const std::string &file, const state_file_mutator_t &mutator) {
    auto file_lock = state_file_lock(file);
    std::scoped_lock lock(*file_lock);

    state_file_tree_t tree;
    try {
      if (fs::exists(file)) {
        pt::read_json(file, tree);
      }
      mutator(tree);
    } catch (const std::exception &exception) {
      BOOST_LOG(error) << "Couldn't update shared state file "sv << file << ": "sv << exception.what();
      return false;
    }

    const fs::path destination(file);
    const fs::path temporary = destination.string() + ".tmp-" + crypto::rand_alphabet(16);
    try {
      std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
      if (!output) {
        return false;
      }
      pt::write_json(output, tree);
      output.flush();
      if (!output) {
        output.close();
        std::error_code ignored;
        fs::remove(temporary, ignored);
        return false;
      }
      output.close();
    } catch (const std::exception &exception) {
      std::error_code ignored;
      fs::remove(temporary, ignored);
      BOOST_LOG(error) << "Couldn't stage shared state file "sv << file << ": "sv << exception.what();
      return false;
    }

    if (!replace_state_file(temporary, destination)) {
      std::error_code ignored;
      fs::remove(temporary, ignored);
      BOOST_LOG(error) << "Couldn't replace shared state file "sv << file;
      return false;
    }
    return true;
  }

  /**
   * @brief Load persisted HTTP credentials and initialize shared request state.
   */
  int init() {
    bool clean_slate = config::sunshine.flags[config::flag::FRESH_STATE];
    origin_web_ui_allowed = net::from_enum_string(config::nvhttp.origin_web_ui_allowed);

    if (clean_slate) {
      unique_id = uuid_util::uuid_t::generate().string();
      auto dir = std::filesystem::temp_directory_path() / "Lumen"sv;
      config::nvhttp.cert = (dir / ("cert-"s + unique_id)).string();
      config::nvhttp.pkey = (dir / ("pkey-"s + unique_id)).string();
    }

    if ((!fs::exists(config::nvhttp.pkey) || !fs::exists(config::nvhttp.cert)) && create_creds(config::nvhttp.pkey, config::nvhttp.cert)) {
      return -1;
    }
    if (!user_creds_exist(config::sunshine.credentials_file)) {
      BOOST_LOG(info) << "Open the Web UI to set your new username and password and getting started";
    } else if (reload_user_creds(config::sunshine.credentials_file)) {
      return -1;
    }
    return 0;
  }

  /**
   * @brief Save user creds.
   *
   * @param file Credentials file path.
   * @param username Username to save.
   * @param password Password to save.
   * @param run_our_mouth Whether to log user-facing status messages.
   * @return 0 on success, non-zero on failure.
   */
  int save_user_creds(
    const std::string &file,
    const std::string &username,
    const std::string &password,
    bool run_our_mouth,
    user_credentials_t *saved_credentials
  ) {
    const auto salt = crypto::rand_alphabet(16);
    const auto password_hash = hash_user_password(password, salt);
    if (!password_hash) {
      BOOST_LOG(error) << "OpenSSL failed to derive the Web UI password hash"sv;
      return -1;
    }

    if (!update_state_file(file, [&](state_file_tree_t &tree) {
          tree.put("username", username);
          tree.put("salt", salt);
          tree.put("password", *password_hash);
        })) {
      BOOST_LOG(error) << "Error writing to the credentials file, perhaps try this again as an administrator"sv;
      return -1;
    }

    if (saved_credentials) {
      *saved_credentials = user_credentials_t {username, *password_hash, salt};
    }

    BOOST_LOG(info) << "New credentials have been created"sv;
    return 0;
  }

  /**
   * @brief Check whether the Web UI credentials file exists and is readable.
   */
  bool user_creds_exist(const std::string &file) {
    if (!fs::exists(file)) {
      return false;
    }

    pt::ptree inputTree;
    return read_state_file(file, inputTree) &&
           inputTree.find("username") != inputTree.not_found() &&
           inputTree.find("password") != inputTree.not_found() &&
           inputTree.find("salt") != inputTree.not_found();
  }

  /**
   * @brief Reload the Web UI credentials from disk.
   */
  int reload_user_creds(const std::string &file) {
    pt::ptree inputTree;
    if (!read_state_file(file, inputTree)) {
      return -1;
    }
    try {
      user_credentials_t loaded {
        inputTree.get<std::string>("username"),
        inputTree.get<std::string>("password"),
        inputTree.get<std::string>("salt")
      };
      config::sunshine.username = std::move(loaded.username);
      config::sunshine.password = std::move(loaded.password);
      config::sunshine.salt = std::move(loaded.salt);
    } catch (std::exception &e) {
      BOOST_LOG(error) << "loading user credentials: "sv << e.what();
      return -1;
    }
    return 0;
  }

  /**
   * @brief Generate HTTPS credential files from the provided key and certificate paths.
   */
  int create_creds(const std::string &pkey, const std::string &cert) {
    fs::path pkey_path = pkey;
    fs::path cert_path = cert;

    auto creds = crypto::gen_creds("Lumen GameStream Host"sv, 2048);

    auto pkey_dir = pkey_path;
    auto cert_dir = cert_path;
    pkey_dir.remove_filename();
    cert_dir.remove_filename();

    std::error_code err_code {};
    fs::create_directories(pkey_dir, err_code);
    if (err_code) {
      BOOST_LOG(error) << "Couldn't create directory ["sv << pkey_dir << "] :"sv << err_code.message();
      return -1;
    }

    fs::create_directories(cert_dir, err_code);
    if (err_code) {
      BOOST_LOG(error) << "Couldn't create directory ["sv << cert_dir << "] :"sv << err_code.message();
      return -1;
    }

    if (file_handler::write_file(pkey.c_str(), creds.pkey)) {
      BOOST_LOG(error) << "Couldn't open ["sv << config::nvhttp.pkey << ']';
      return -1;
    }

    if (file_handler::write_file(cert.c_str(), creds.x509)) {
      BOOST_LOG(error) << "Couldn't open ["sv << config::nvhttp.cert << ']';
      return -1;
    }

    if (!lumen::protocol_v3::runtime::secure_private_key_file(pkey_path)) {
      BOOST_LOG(error) << "Couldn't apply and verify private-key security for ["sv << config::nvhttp.pkey << ']';
      return -1;
    }

    fs::permissions(cert_path, fs::perms::owner_read | fs::perms::group_read | fs::perms::others_read | fs::perms::owner_write, fs::perm_options::replace, err_code);

    if (err_code) {
      BOOST_LOG(error) << "Couldn't change permissions of ["sv << config::nvhttp.cert << "] :"sv << err_code.message();
      return -1;
    }

    return 0;
  }

  /**
   * @brief Send a static file response for a Web UI request.
   */
  bool download_file(const std::string &url, const std::string &file, long ssl_version) {
    CURL *curl = curl_easy_init();
    if (!curl) {
      BOOST_LOG(error) << "Couldn't create CURL instance";
      return false;
    }

    if (std::string file_dir = file_handler::get_parent_directory(file); !file_handler::make_directory(file_dir)) {
      BOOST_LOG(error) << "Couldn't create directory ["sv << file_dir << ']';
      curl_easy_cleanup(curl);
      return false;
    }

    FILE *fp = fopen(file.c_str(), "wb");
    if (!fp) {
      BOOST_LOG(error) << "Couldn't open ["sv << file << ']';
      curl_easy_cleanup(curl);
      return false;
    }

    curl_easy_setopt(curl, CURLOPT_SSLVERSION, ssl_version);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fwrite);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

    CURLcode result = curl_easy_perform(curl);
    if (result != CURLE_OK) {
      BOOST_LOG(error) << "Couldn't download ["sv << url << ", code:" << result << ']';
    }

    curl_easy_cleanup(curl);
    fclose(fp);
    return result == CURLE_OK;
  }

  /**
   * @brief Percent-encode URL data for use in HTTP query strings.
   */
  std::string url_escape(const std::string &url) {
    char *string = curl_easy_escape(nullptr, url.c_str(), static_cast<int>(url.length()));
    std::string result(string);
    curl_free(string);
    return result;
  }

  /**
   * @brief Extract the host component from a URL string.
   */
  std::string url_get_host(const std::string &url) {
    CURLU *curlu = curl_url();
    curl_url_set(curlu, CURLUPART_URL, url.c_str(), static_cast<unsigned int>(url.length()));
    char *host;
    if (curl_url_get(curlu, CURLUPART_HOST, &host, 0) != CURLUE_OK) {
      curl_url_cleanup(curlu);
      return "";
    }
    std::string result(host);
    curl_free(host);
    curl_url_cleanup(curlu);
    return result;
  }
}  // namespace http
