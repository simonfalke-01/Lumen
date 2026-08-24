/**
 * @file src/nvhttp.h
 * @brief Declarations for the nvhttp (GameStream) server.
 */
// macros
#pragma once

// standard includes
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

// lib includes
#include <boost/property_tree/ptree.hpp>
#include <nlohmann/json.hpp>
#include <Simple-Web-Server/server_https.hpp>

// local includes
#include "crypto.h"
#include "thread_safe.h"

/**
 * @brief Contains all the functions and variables related to the nvhttp (GameStream) server.
 */
namespace nvhttp {

  /**
   * @brief The protocol version.
   * @details The version of the GameStream protocol we are mocking.
   * @note The negative 4th number indicates to Moonlight that this is Sunshine.
   */
  constexpr auto VERSION = "7.1.431.-1";

  /**
   * @brief The GFE version we are replicating.
   */
  constexpr auto GFE_VERSION = "3.23.0.74";

  /**
   * @brief The HTTP port, as a difference from the config port.
   */
  constexpr auto PORT_HTTP = 0;

  /**
   * @brief The HTTPS port, as a difference from the config port.
   */
  constexpr auto PORT_HTTPS = -5;

  constexpr std::size_t PAIRING_REQUEST_BUFFER_LIMIT = 64 * 1024;
  constexpr std::size_t PAIRING_UNIQUE_ID_MAX_BYTES = 128;
  constexpr std::size_t PAIRING_CLIENT_CERT_MAX_BYTES = 16 * 1024;
  constexpr std::size_t PAIRING_CLIENT_CERT_HEX_MAX_BYTES = PAIRING_CLIENT_CERT_MAX_BYTES * 2;
  constexpr std::size_t PAIRING_SALT_HEX_BYTES = 32;
  constexpr std::size_t PAIRING_CLIENT_CHALLENGE_HEX_BYTES = 32;
  constexpr std::size_t PAIRING_SERVER_CHALLENGE_RESPONSE_HEX_BYTES = 64;
  constexpr std::size_t PAIRING_CLIENT_SECRET_HEX_MAX_BYTES = 4096;
  constexpr std::size_t PAIRING_CLIENT_NAME_MAX_BYTES = 128;
  constexpr std::size_t PAIRING_REQUEST_ID_HEX_BYTES = 32;

  /**
   * @brief Start the nvhttp server.
   * @examples
   * nvhttp::start();
   * @examples_end
   */
  void start();

  /**
   * @brief Setup the nvhttp server.
   * @param pkey
   * @param cert
   */
  void setup(const std::string &pkey, const std::string &cert);

  bool is_valid_pairing_unique_id(std::string_view value);
  bool is_valid_pairing_hex(std::string_view value, std::size_t minimum_bytes, std::size_t maximum_bytes);
  /**
   * @brief Check whether legacy PIN pairing may originate from an address.
   * @param address Normalized or native client source address.
   * @return True only for loopback, local-host, or private/trusted LAN scopes.
   */
  bool is_trusted_pairing_source(const boost::asio::ip::address &address);

  /**
   * @brief Simple-Web-Server HTTPS backend configured for Sunshine certificate handling.
   */
  class SunshineHTTPS: public SimpleWeb::HTTPS {
  public:
    /**
     * @brief Construct an HTTPS connection using Sunshine's TLS context.
     *
     * @param io_context Boost.Asio context used for network operations.
     * @param ctx TLS context configured with Sunshine's certificate and key.
     */
    SunshineHTTPS(boost::asio::io_context &io_context, boost::asio::ssl::context &ctx):
        SimpleWeb::HTTPS(io_context, ctx) {
    }

    void bind_verified_client_certificate(std::string certificate) {
      verified_client_certificate_ = std::move(certificate);
    }

    [[nodiscard]] const std::string &verified_client_certificate() const noexcept {
      return verified_client_certificate_;
    }

    virtual ~SunshineHTTPS() {
      // Gracefully shutdown the TLS connection
      SimpleWeb::error_code ec;
      shutdown(ec);
    }

  private:
    std::string verified_client_certificate_;
  };

  /**
   * @brief Enumerates supported pAIR PHASE options.
   */
  enum class PAIR_PHASE {
    NONE,  ///< Sunshine is not in a pairing phase
    GETSERVERCERT,  ///< Sunshine is in the get server certificate phase
    CLIENTCHALLENGE,  ///< Sunshine is in the client challenge phase
    SERVERCHALLENGERESP,  ///< Sunshine is in the server challenge response phase
    CLIENTPAIRINGSECRET  ///< Sunshine is in the client pairing secret phase
  };

  /**
   * @brief Pairing handshake state exchanged with a Moonlight client.
   */
  struct pair_session_t {
    struct {
      std::string uniqueID = {};
      std::string cert = {};
      std::string name = {};
    } client;  ///< Client object or client certificate data owned by this state..

    std::unique_ptr<crypto::aes_t> cipher_key = {};  ///< Cipher key.
    std::vector<uint8_t> clienthash = {};  ///< Client certificate hash used during pairing.

    std::string serversecret = {};  ///< Server pairing secret.
    std::string serverchallenge = {};  ///< Server challenge sent during pairing.

    struct {
      util::Either<
        std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTP>::Response>,
        std::shared_ptr<typename SimpleWeb::ServerBase<SunshineHTTPS>::Response>>
        response;
      std::string salt = {};
    } async_insert_pin;  ///< Async insert pin.

    /**
     * @brief used as a security measure to prevent out of order calls
     */
    PAIR_PHASE last_phase = PAIR_PHASE::NONE;
  };

  /**
   * @brief Bounded, synchronized owner for in-progress pairing handshakes.
   *
   * A locked session keeps both the manager lock and the session storage alive
   * until the caller finishes mutating the handshake state. This prevents a
   * concurrent timeout or request from erasing state while it is in use.
   *
   * @warning These controls bound online abuse only. The legacy GameStream
   * four-digit PIN transcript remains susceptible to a passive offline search
   * of all 10,000 PINs; a modern PAKE or high-entropy invitation is required to
   * remove that protocol-level limitation.
   */
  class pairing_session_manager_t {
  public:
    using clock_t = std::chrono::steady_clock;
    using time_point_t = clock_t::time_point;

    static constexpr std::chrono::seconds SESSION_TTL {120};
    static constexpr std::size_t MAX_GLOBAL_SESSIONS = 32;
    static constexpr std::size_t MAX_SESSIONS_PER_SOURCE = 4;
    static constexpr std::uint8_t MAX_PIN_ATTEMPTS = 3;

    enum class add_status_e {
      ADDED,
      DUPLICATE_UNIQUE_ID,
      DUPLICATE_REQUEST_ID,
      GLOBAL_LIMIT,
      SOURCE_LIMIT,
      RANDOM_FAILURE,
      CLOSED,
      INVALID_FIELDS,
      REPLACED
    };

    enum class pin_attempt_status_e {
      ACCEPTED,
      SESSION_EXHAUSTED,
      SOURCE_RATE_LIMITED,
      MISSING_SESSION
    };

    struct pending_request_t {
      std::string request_id;
      std::string source;
      std::uint64_t age_seconds;
      std::string client_fingerprint;
    };

    struct add_result_t {
      add_status_e status;
      std::string request_id;

      explicit operator bool() const noexcept {
        return status == add_status_e::ADDED || status == add_status_e::REPLACED;
      }
    };

    class locked_session_t {
    public:
      locked_session_t() = default;
      locked_session_t(locked_session_t &&) noexcept = default;
      locked_session_t &operator=(locked_session_t &&) noexcept = default;

      explicit operator bool() const noexcept;
      pair_session_t &session() const;
      const std::string &unique_id() const noexcept;
      const std::string &request_id() const noexcept;
      const std::string &source() const noexcept;

    private:
      friend class pairing_session_manager_t;

      locked_session_t(
        std::unique_lock<std::recursive_mutex> lock,
        std::shared_ptr<pair_session_t> session,
        std::string unique_id,
        std::string request_id,
        std::string source
      );

      std::unique_lock<std::recursive_mutex> lock_;
      std::shared_ptr<pair_session_t> session_;
      std::string unique_id_;
      std::string request_id_;
      std::string source_;
    };

    pairing_session_manager_t() = default;
    pairing_session_manager_t(const pairing_session_manager_t &) = delete;
    pairing_session_manager_t &operator=(const pairing_session_manager_t &) = delete;

    add_result_t add(
      pair_session_t session,
      std::string source,
      std::string request_id = {},
      time_point_t now = clock_t::now()
    );
    locked_session_t find_by_unique_id(std::string_view unique_id, std::string_view source, time_point_t now = clock_t::now());
    locked_session_t find_pending_by_request_id(std::string_view request_id, time_point_t now = clock_t::now());
    locked_session_t find_single_pending(time_point_t now = clock_t::now());
    pin_attempt_status_e record_pin_attempt(locked_session_t &session, time_point_t now = clock_t::now());
    void erase(std::string_view unique_id);
    std::size_t cleanup_expired(time_point_t now = clock_t::now());
    bool cancel_by_request_id(std::string_view request_id);
    void cancel_all();
    void open();
    void close();
    bool accepting();
    std::size_t size(time_point_t now = clock_t::now());
    std::vector<pending_request_t> pending_requests(time_point_t now = clock_t::now());

  private:
    struct entry_t {
      std::shared_ptr<pair_session_t> session;
      std::string source;
      std::string request_id;
      time_point_t created_at;
      std::uint8_t pin_attempts = 0;
      std::string client_fingerprint;
    };

    std::size_t cleanup_expired_locked(time_point_t now);
    void cleanup_pin_submissions_locked(time_point_t now);
    void erase_locked(std::unordered_map<std::string, entry_t>::iterator entry);

    std::recursive_mutex mutex_;
    std::unordered_map<std::string, entry_t> sessions_;
    std::unordered_map<std::string, std::string> request_to_unique_id_;
    std::unordered_map<std::string, std::deque<time_point_t>> pin_submissions_by_source_;
    bool accepting_ = true;
  };

  /**
   * @brief removes the temporary pairing session
   * @param sess
   */
  void remove_session(const pair_session_t &sess);

  /**
   * @brief Pair, phase 1
   *
   * Moonlight will send a salt and client certificate, we'll also need the user provided pin.
   *
   * PIN and SALT will be used to derive a shared AES key that needs to be stored
   * in order to be used to decrypt_symmetric in the next phases.
   *
   * At this stage we only have to send back our public certificate.
   * @param sess Pairing session that owns the request state.
   * @param tree XML property tree used for the response body.
   * @param pin PIN supplied by the client during pairing.
   */
  void getservercert(pair_session_t &sess, boost::property_tree::ptree &tree, const std::string &pin);

  /**
   * @brief Pair, phase 2
   *
   * Using the AES key that we generated in phase 1 we have to decrypt the client challenge,
   *
   * We generate a SHA256 hash with the following:
   *  - Decrypted challenge
   *  - Server certificate signature
   *  - Server secret: a randomly generated secret
   *
   * The hash + server_challenge will then be AES encrypted and sent as the `challengeresponse` in the returned XML
   * @param sess Pairing session that owns the request state.
   * @param tree XML property tree used for the response body.
   * @param challenge Client challenge bytes from the pairing request.
   */
  void clientchallenge(pair_session_t &sess, boost::property_tree::ptree &tree, const std::string &challenge);

  /**
   * @brief Pair, phase 3
   *
   * Moonlight will send back a `serverchallengeresp`: an AES encrypted client hash,
   * we have to send back the `pairingsecret`:
   * using our private key we have to sign the certificate_signature + server_secret (generated in phase 2)
   * @param sess Pairing session that owns the request state.
   * @param tree XML property tree used for the response body.
   * @param encrypted_response Encrypted response.
   */
  void serverchallengeresp(pair_session_t &sess, boost::property_tree::ptree &tree, const std::string &encrypted_response);

  /**
   * @brief Pair, phase 4 (final)
   *
   * We now have to use everything we exchanged before in order to verify and finally pair the clients
   *
   * We'll check the client_hash obtained at phase 3, it should contain the following:
   *   - The original server_challenge
   *   - The signature of the X509 client_cert
   *   - The unencrypted client_pairing_secret
   * We'll check that SHA256(server_challenge + client_public_cert_signature + client_secret) == client_hash
   *
   * Then using the client certificate public key we should be able to verify that
   * the client secret has been signed by Moonlight
   * @param sess Pairing session that owns the request state.
   * @param add_cert Add cert.
   * @param tree XML property tree used for the response body.
   * @param client_pairing_secret Client pairing secret.
   */
  void clientpairingsecret(pair_session_t &sess, std::shared_ptr<safe::queue_t<crypto::x509_t>> &add_cert, boost::property_tree::ptree &tree, const std::string &client_pairing_secret);

  /**
   * @brief Compare the user supplied pin to the Moonlight pin.
   * @param pin The user supplied pin.
   * @param name The user supplied name.
   * @return `true` if the pin is correct, `false` otherwise.
   * @examples
   * bool pin_status = nvhttp::pin("1234", "laptop");
   * @examples_end
   */
  bool pin(std::string pin, std::string name);

  /**
   * @brief Submit a PIN for one explicitly identified pending request.
   * @param pin The user supplied PIN.
   * @param name The user supplied client name.
   * @param request_id Cryptographically random request ID returned by the
   * pairing-request listing endpoint.
   * @return `true` when the PIN was delivered to that pending request.
   */
  bool pin(std::string pin, std::string name, std::string_view request_id);

  /**
   * @brief Return non-secret IDs for pairing requests awaiting a PIN.
   */
  std::vector<pairing_session_manager_t::pending_request_t> pending_pairing_requests();

  /**
   * @brief Cancel a pending request and release its held client response.
   */
  bool cancel_pairing_request(std::string_view request_id);

#ifdef SUNSHINE_TESTS
  pairing_session_manager_t &pairing_sessions_for_tests();

  std::string legacy_pair_challenge_xml_for_tests();
  std::string legacy_applist_xml_for_tests(
    const std::vector<std::pair<std::string, std::string>> &apps,
    bool hdr_supported
  );
  std::string legacy_launch_xml_for_tests(std::string_view session_url);
  std::string legacy_resume_xml_for_tests(std::string_view session_url);
  std::string legacy_cancel_xml_for_tests();
  std::string_view legacy_appasset_content_type_for_tests();
  std::string legacy_query_log_value_for_tests(std::string_view name, std::string_view value);
  void reset_paired_clients_for_tests();
  bool upsert_paired_client_for_tests(
    std::string name,
    std::string uuid,
    std::string certificate,
    bool enabled
  );
  bool paired_client_enabled_for_tests(std::string_view certificate);
  std::string legacy_pairing_source_xml_for_tests(const boost::asio::ip::address &address);
  std::string verified_transport_certificate_for_tests(const SunshineHTTPS &transport);
#endif

  /**
   * @brief Remove single client.
   * @param uuid The UUID of the client to remove.
   * @examples
   * nvhttp::unpair_client("4D7BB2DD-5704-A405-B41C-891A022932E1");
   * @examples_end
   *
   * @return True when the client entry was found and removed.
   */
  bool unpair_client(std::string_view uuid);
  /**
   * @brief Atomically persist and remove one paired client.
   * @param uuid Paired-client UUID to revoke.
   * @return Immutable removed certificate, or no value when missing or persistence fails.
   */
  std::optional<std::string> revoke_client(std::string_view uuid);

  /**
   * @brief Enable or disable a client.
   * @param uuid The UUID of the client.
   * @param enabled Whether the client should be enabled.
   * @return true if the client was found and updated.
   */
  bool set_client_enabled(std::string_view uuid, bool enabled);
  /**
   * @brief Atomically persist a client enable state and snapshot its certificate.
   * @param uuid Paired-client UUID to update.
   * @param enabled New authorization state.
   * @return Immutable certificate, or no value when missing or persistence fails.
   */
  std::optional<std::string> set_client_enabled_with_certificate(std::string_view uuid, bool enabled);
  /**
   * @brief Get cert by UUID.
   *
   * @param uuid Client UUID being looked up or removed.
   * @return PEM certificate for the paired client, or an empty string when unknown.
   */
  std::string get_cert_by_uuid(std::string_view uuid);

  /**
   * @brief Get all paired clients.
   * @return The list of all paired clients.
   * @examples
   * nlohmann::json clients = nvhttp::get_all_clients();
   * @examples_end
   */
  nlohmann::json get_all_clients();

  /**
   * @brief Remove all paired clients.
   * @examples
   * nvhttp::erase_all_clients();
   * @examples_end
   * @return True only when the removal was committed to persistent state.
   */
  bool erase_all_clients();
}  // namespace nvhttp
