/**
 * @file src/protocol_lsp/runtime/control_server.cpp
 * @brief Authenticated deterministic-CBOR LSPC host control vertical slice.
 */

#include "control_server.h"

#include "../../protocol_common/cbor.h"
#include "../core/control.h"
#include "../security/secure_zero.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <limits>
#include <mutex>
#include <new>
#include <thread>
#include <utility>

namespace lumen::lsp::runtime {
  namespace {
    namespace cbor = lumen::protocol_common::cbor;

    constexpr std::size_t maximum_control_connections = 64;
    constexpr std::size_t maximum_pending_pairings = 4;
    constexpr std::uint64_t pairing_ttl_seconds = 120;
    constexpr std::uint64_t pairing_retry_cooldown_seconds = 2;
    constexpr std::uint8_t maximum_pairing_challenges = 3;
    constexpr std::size_t maximum_applications = 64;
    constexpr std::size_t maximum_application_id_bytes = 128;
    constexpr std::size_t maximum_application_name_bytes = 256;
    constexpr std::size_t maximum_application_image_bytes = 512;
    constexpr std::uint64_t response_deadline_microseconds = 1'000'000;
    constexpr std::uint64_t path_probe_semantic_deadline_microseconds = 60'000'000;  ///< Covers all legal LSPP retries plus margin.

    template<std::size_t Size>
    cbor::Value::Bytes bytes(const std::array<std::uint8_t, Size> &value) {
      return {value.begin(), value.end()};
    }

    template<std::size_t Size>
    bool fixed_bytes(const cbor::Value &value, std::array<std::uint8_t, Size> &output) noexcept {
      const auto *encoded = std::get_if<cbor::Value::Bytes>(&value.storage);
      if (encoded == nullptr || encoded->size() != Size) {
        return false;
      }
      std::copy(encoded->begin(), encoded->end(), output.begin());
      return true;
    }

    const std::uint64_t *unsigned_value(const cbor::Value &value) noexcept {
      return std::get_if<std::uint64_t>(&value.storage);
    }

    const cbor::Value::Map *exact_map(
      const std::span<const std::uint8_t> payload,
      const std::size_t expected_entries
    ) noexcept {
      cbor::Limits limits;
      limits.max_encoded_bytes = maximum_control_frame_bytes - lspc_header_size;
      limits.max_byte_string_bytes = maximum_control_frame_bytes - lspc_header_size;
      limits.max_text_bytes = maximum_application_image_bytes;
      limits.max_array_elements = maximum_applications;
      limits.max_map_entries = 32;
      limits.max_container_depth = 3;
      thread_local cbor::DecodeResult decoded;
      decoded = cbor::decode(payload, limits);
      if (!decoded) {
        return nullptr;
      }
      const auto *map = std::get_if<cbor::Value::Map>(&decoded.value->storage);
      if (map == nullptr || map->size() != expected_entries) {
        return nullptr;
      }
      for (std::size_t index = 0; index < map->size(); ++index) {
        if ((*map)[index].first != index + 1) {
          return nullptr;
        }
      }
      return map;
    }

    std::optional<std::vector<std::uint8_t>> encode_control_value(cbor::Value value) {
      cbor::Limits limits;
      limits.max_encoded_bytes = maximum_control_frame_bytes - lspc_header_size;
      limits.max_byte_string_bytes = maximum_control_frame_bytes - lspc_header_size;
      limits.max_text_bytes = maximum_application_image_bytes;
      limits.max_array_elements = maximum_applications;
      limits.max_map_entries = 32;
      limits.max_container_depth = 3;
      auto encoded = cbor::encode(value, limits);
      if (!encoded) {
        return std::nullopt;
      }
      return std::move(encoded.bytes);
    }

    std::optional<std::vector<std::uint8_t>> status_payload(const ControlStatus status) {
      return encode_control_value(cbor::Value {cbor::Value::Map {
        {1, wire_version},
        {2, static_cast<std::uint8_t>(status)},
      }});
    }

    bool valid_text(const std::string &value, const std::size_t maximum) noexcept {
      return !value.empty() && value.size() <= maximum && cbor::is_valid_utf8(value);
    }

    std::uint64_t saturating_add(const std::uint64_t value, const std::uint64_t increment) noexcept {
      return value > std::numeric_limits<std::uint64_t>::max() - increment ?
               std::numeric_limits<std::uint64_t>::max() :
               value + increment;
    }
  }  // namespace

  bool TrustedClient::valid() const noexcept {
    return !is_zero(client_id) && !is_zero(identity_key) && revocation_generation != 0 &&
           (permissions.mask() & ~PermissionSet::known_mask) == 0;
  }

  std::optional<std::vector<std::uint8_t>> authentication_signature_transcript(
    const Identifier128 &host_id,
    const Identifier128 &client_id,
    const Secret256 &client_nonce,
    const Secret256 &server_nonce,
    const std::uint32_t connection_generation
  ) {
    if (is_zero(host_id) || is_zero(client_id) || is_zero(client_nonce) || is_zero(server_nonce) || connection_generation == 0) {
      return std::nullopt;
    }
    return encode_control_value(cbor::Value {cbor::Value::Map {
      {1, "lumen-stream/1 auth"},
      {2, bytes(host_id)},
      {3, bytes(client_id)},
      {4, bytes(client_nonce)},
      {5, bytes(server_nonce)},
      {6, connection_generation},
    }});
  }

  std::optional<std::vector<std::uint8_t>> pairing_confirmation_aad(
    const PairingTranscriptBindings &bindings
  ) {
    if (is_zero(bindings.host_id) || is_zero(bindings.host_identity_key) || is_zero(bindings.dtls_spki_sha256) ||
        is_zero(bindings.client_id) || is_zero(bindings.client_identity_key) || is_zero(bindings.pairing_session_id) ||
        is_zero(bindings.client_pairing_nonce) || bindings.connection_generation == 0 || bindings.approval_generation == 0 ||
        is_zero(bindings.client_hello_nonce) || is_zero(bindings.server_hello_nonce) || is_zero(bindings.scrypt_salt) ||
        bindings.requested_permissions.mask() == 0 || bindings.effective_permissions.mask() == 0 ||
        bindings.expires_at_utc_seconds == 0 || is_zero(bindings.pairing_exporter)) {
      return std::nullopt;
    }
    return encode_control_value(cbor::Value {cbor::Value::Map {
      {1, "lumen-stream/1 pin-pair aad"},
      {2, pairing_schema_version},
      {3, bytes(bindings.host_id)},
      {4, bytes(bindings.host_identity_key)},
      {5, bytes(bindings.dtls_spki_sha256)},
      {6, bytes(bindings.client_id)},
      {7, bytes(bindings.client_identity_key)},
      {8, bytes(bindings.pairing_session_id)},
      {9, bytes(bindings.client_pairing_nonce)},
      {10, bindings.connection_generation},
      {11, bindings.approval_generation},
      {12, bytes(bindings.client_hello_nonce)},
      {13, bytes(bindings.server_hello_nonce)},
      {14, bytes(bindings.scrypt_salt)},
      {15, bindings.requested_permissions.mask()},
      {16, bindings.effective_permissions.mask()},
      {17, bindings.expires_at_utc_seconds},
      {18, bytes(bindings.pairing_exporter)},
    }});
  }

  std::optional<std::vector<std::uint8_t>> pairing_client_signature_transcript(
    const std::span<const std::uint8_t> aad,
    const std::array<std::uint8_t, pairing_confirmation_size> &confirmation_a
  ) {
    if (aad.empty() || is_zero(confirmation_a)) {
      return std::nullopt;
    }
    return encode_control_value(cbor::Value {cbor::Value::Map {
      {1, "lumen-stream/1 pin-pair client"},
      {2, cbor::Value::Bytes {aad.begin(), aad.end()}},
      {3, bytes(confirmation_a)},
    }});
  }

  std::optional<std::vector<std::uint8_t>> pairing_host_signature_transcript(
    const std::span<const std::uint8_t> aad,
    const std::array<std::uint8_t, pairing_confirmation_size> &confirmation_a,
    const std::array<std::uint8_t, pairing_confirmation_size> &confirmation_b,
    const std::uint32_t revocation_generation
  ) {
    if (aad.empty() || is_zero(confirmation_a) || is_zero(confirmation_b) || revocation_generation == 0) {
      return std::nullopt;
    }
    return encode_control_value(cbor::Value {cbor::Value::Map {
      {1, "lumen-stream/1 pin-pair host"},
      {2, cbor::Value::Bytes {aad.begin(), aad.end()}},
      {3, bytes(confirmation_a)},
      {4, bytes(confirmation_b)},
      {5, revocation_generation},
    }});
  }

  class HostControlServer::Impl {
  public:
    /** @brief Secure association-bound exporter and hello nonce ownership. */
    struct ConnectionSecrets {
      PairingDtlsExporter exporter {};  ///< Dedicated pairing exporter.
      Secret256 client_nonce {};  ///< Accepted CLIENT_HELLO nonce.
      Secret256 server_nonce {};  ///< Fresh SERVER_HELLO nonce.

      /** @brief Construct empty association secret ownership. */
      ConnectionSecrets() = default;
      ConnectionSecrets(const ConnectionSecrets &) = delete;
      ConnectionSecrets &operator=(const ConnectionSecrets &) = delete;

      /** @brief Transfer fixed secrets and clear the moved-from association. */
      ConnectionSecrets(ConnectionSecrets &&other) noexcept:
          exporter {other.exporter},
          client_nonce {other.client_nonce},
          server_nonce {other.server_nonce} {
        other.clear();
      }

      /** @brief Clear current secrets before transferring another association. */
      ConnectionSecrets &operator=(ConnectionSecrets &&other) noexcept {
        if (this != &other) {
          clear();
          exporter = other.exporter;
          client_nonce = other.client_nonce;
          server_nonce = other.server_nonce;
          other.clear();
        }
        return *this;
      }

      /** @brief Securely clear exporter and hello nonces on destruction. */
      ~ConnectionSecrets() {
        clear();
      }

      /** @brief Securely clear all association-bound pairing bytes. */
      void clear() noexcept {
        secure_zero(exporter);
        secure_zero(client_nonce);
        secure_zero(server_nonce);
      }
    };

    struct Connection {
      PeerEndpoint peer;  ///< Exact DTLS association.
      std::uint32_t generation {};  ///< Assigned connection authority generation.
      ConnectionSecrets secrets {};  ///< Secure exporter and hello nonce owner.
      std::optional<TrustedClient> authenticated_client;  ///< Authenticated LSP trust record.
      selective_ack_window inbound;  ///< Received message-ID/ACK state.
      outbound_control_window<maximum_control_frame_bytes> outbound;  ///< Byte-identical retry storage.
      response_cache<maximum_control_frame_bytes, maximum_control_frame_bytes> responses;  ///< Idempotent terminal responses.
      control_rto rto {true};  ///< Local-path initial RTO.
      std::uint64_t next_message_id {1};  ///< Next outbound logical message ID.

      struct PendingVideoConfig {
        Identifier128 session_id {};  ///< Exact configured session identifier.
        std::uint32_t video_generation {};  ///< Exact configured video generation.
        std::uint64_t request_id {};  ///< Random request identifier echoed by VIDEO_CONFIG_ACK.
        std::uint64_t message_id {};  ///< Reliable outbound message identifier.
        bool active {};  ///< Whether a matching acknowledgement remains pending.
      } pending_video;  ///< At most one pending video configuration per connection.

      struct AcceptedVideoAck {
        std::uint64_t request_id {};  ///< VIDEO_CONFIG request identifier answered by this frame.
        std::array<std::uint8_t, maximum_control_frame_bytes> frame {};  ///< Byte-identical accepted ACK.
        std::size_t size {};  ///< Populated leading bytes in `frame`.
      };

      std::array<AcceptedVideoAck, 4> accepted_video_acks {};  ///< Bounded recent ACK cache across rekeys.
      std::size_t next_video_ack_slot {};  ///< Ring slot replaced by the next accepted video ACK.

      struct PendingAudioConfig {
        AudioConfigPayload payload {};  ///< Exact configuration awaiting client installation.
        std::uint64_t request_id {};  ///< Random request identifier echoed by AUDIO_CONFIG_ACK.
        std::uint64_t message_id {};  ///< Reliable outbound message identifier.
        bool active {};  ///< Whether a matching acknowledgement remains pending.
      } pending_audio;  ///< At most one pending audio configuration per connection.

      struct AcceptedAudioAck {
        std::uint64_t request_id {};  ///< AUDIO_CONFIG request identifier answered by this frame.
        std::array<std::uint8_t, maximum_control_frame_bytes> frame {};  ///< Byte-identical accepted ACK frame.
        std::size_t size {};  ///< Populated leading bytes in `frame`.
      };

      std::array<AcceptedAudioAck, 4> accepted_audio_acks {};  ///< Bounded recent ACK cache across same-association updates.
      std::size_t next_audio_ack_slot {};  ///< Ring slot replaced by the next accepted ACK.

      struct PendingMicrophoneConfig {
        MicrophoneConfigPayload payload {};  ///< Exact configuration awaiting client installation.
        std::uint64_t request_id {};  ///< Random request identifier echoed by MICROPHONE_CONFIG_ACK.
        std::uint64_t message_id {};  ///< Reliable outbound message identifier.
        bool active {};  ///< Whether a matching acknowledgement remains pending.
      } pending_microphone;  ///< At most one pending microphone configuration per connection.

      struct AcceptedMicrophoneAck {
        std::uint64_t request_id {};  ///< MICROPHONE_CONFIG request answered by this frame.
        std::array<std::uint8_t, maximum_control_frame_bytes> frame {};  ///< Byte-identical accepted ACK.
        std::size_t size {};  ///< Populated leading bytes in `frame`.
      };

      std::array<AcceptedMicrophoneAck, 4> accepted_microphone_acks {};  ///< Bounded ACK cache across rekeys.
      std::size_t next_microphone_ack_slot {};  ///< Ring slot replaced by the next accepted microphone ACK.

      struct PendingOutboundPathProbe {
        PathProbePayload probe {};  ///< Exact intent and protected candidate size.
        std::uint64_t request_id {};  ///< Random response correlation identifier.
        std::uint64_t message_id {};  ///< Reliable intent message identifier.
        std::uint64_t deadline_microseconds {};  ///< Full semantic probe lifetime.
        bool datagram_sent {};  ///< Whether peer LSPC acknowledgement released `LSPP` transmission.
        bool active {};  ///< Whether PATH_PROBE_ACK remains outstanding.
      } outbound_path_probe;  ///< One host-originated probe per direction.

      struct PendingInboundPathProbe {
        PathProbePayload probe {};  ///< Authenticated peer intent awaiting exact `LSPP`.
        packet_slab<maximum_control_frame_bytes> request {};  ///< Byte-identical request for response caching.
        lspc_header header {};  ///< Original request correlation and generation fields.
        std::uint64_t deadline_microseconds {};  ///< Bounded authenticated datagram deadline.
        bool active {};  ///< Whether an exact protected probe remains expected.
      } inbound_path_probe;  ///< One peer-originated reverse probe.

      struct AcceptedPathProbeAck {
        std::uint64_t request_id {};  ///< PATH_PROBE request answered by this exact frame.
        std::array<std::uint8_t, maximum_control_frame_bytes> frame {};  ///< Byte-identical accepted ACK.
        std::size_t size {};  ///< Populated leading bytes.
      };

      std::array<AcceptedPathProbeAck, 4> accepted_path_probe_acks {};  ///< Bounded ACK duplicate cache.
      std::size_t next_path_probe_ack_slot {};  ///< Next ACK cache replacement slot.
      std::array<std::uint64_t, 4> cancelled_path_probe_request_ids {};  ///< Retired requests whose late ACK is harmless.
      std::size_t next_cancelled_path_probe_slot {};  ///< Next cancelled-request replacement slot.
      bool hello_complete {};  ///< Whether CLIENT_HELLO completed.
    };

    /** @brief Bounded PIN pairing state owned by one authenticated DTLS association. */
    struct PendingPairing {
      Identifier128 session_id {};  ///< Random pairing-session identifier.
      PeerEndpoint peer {};  ///< Exact association permitted to poll and finish.
      std::uint32_t connection_generation {};  ///< Exact authenticated association generation.
      PairingDtlsExporter exporter {};  ///< Raw exporter bound into SPAKE confirmation AAD.
      Secret256 client_hello_nonce {};  ///< CLIENT_HELLO nonce.
      Secret256 server_hello_nonce {};  ///< SERVER_HELLO nonce.
      Identifier128 client_id {};  ///< Proposed stable client identity.
      PublicKey256 client_identity_key {};  ///< Proposed Ed25519 public key.
      Digest256 identity_key_fingerprint {};  ///< SHA-256 fingerprint exposed to administration.
      std::string client_name;  ///< One-through-64-byte client display name.
      Identifier128 client_pairing_nonce {};  ///< Pairing-specific nonce.
      Identifier128 scrypt_salt {};  ///< Client-selected scrypt salt.
      std::array<std::uint8_t, pairing_spake_point_size> point_a {};  ///< Client SPAKE point.
      std::array<std::uint8_t, pairing_spake_point_size> point_b {};  ///< Host SPAKE point after approval.
      PermissionSet requested_permissions {};  ///< Original BEGIN permission request bound into AAD.
      PermissionSet effective_permissions {};  ///< Fixed host/request intersection.
      std::uint64_t expires_at_utc_seconds {};  ///< Absolute 120-second expiry.
      std::uint64_t cooldown_until_utc_seconds {};  ///< Earliest next PIN challenge.
      PairingPollLimiter poll_limiter {};  ///< Allocation-free floor, backoff, abuse count, and cooldown.
      std::uint32_t approval_generation {};  ///< Current nonzero challenge generation.
      std::uint8_t challenges_used {};  ///< PIN challenges consumed, at most three.
      PairingAdministrationState state {PairingAdministrationState::awaiting_pin};  ///< Current low-rate state.
      std::vector<std::uint8_t> final_aad;  ///< Exact published challenge transcript AAD.
      std::unique_ptr<ControlPairingSpakeSession> spake;  ///< Host provider state after derivation.

      /** @brief Construct empty secure pairing state. */
      PendingPairing() = default;
      PendingPairing(const PendingPairing &) = delete;
      PendingPairing &operator=(const PendingPairing &) = delete;

      /** @brief Transfer all ownership and securely clear the moved-from fixed buffers. */
      PendingPairing(PendingPairing &&other) noexcept {
        move_from(std::move(other));
      }

      /** @brief Clear current state before transferring another pending pairing. */
      PendingPairing &operator=(PendingPairing &&other) noexcept {
        if (this != &other) {
          clear();
          move_from(std::move(other));
        }
        return *this;
      }

      /** @brief Securely clear every secret-bearing pairing field. */
      ~PendingPairing() {
        clear();
      }

      /** @brief Securely clear exporter, nonce, salt, point, AAD, and provider state. */
      void clear() noexcept {
        spake.reset();
        secure_zero(exporter);
        secure_zero(client_hello_nonce);
        secure_zero(server_hello_nonce);
        secure_zero(client_pairing_nonce);
        secure_zero(scrypt_salt);
        secure_zero(point_a);
        secure_zero(point_b);
        secure_zero(final_aad);
      }

    private:
      /** @brief Move all fields, then clear duplicated fixed-width bytes in the source. */
      void move_from(PendingPairing &&other) noexcept {
        session_id = other.session_id;
        peer = std::move(other.peer);
        connection_generation = other.connection_generation;
        exporter = other.exporter;
        client_hello_nonce = other.client_hello_nonce;
        server_hello_nonce = other.server_hello_nonce;
        client_id = other.client_id;
        client_identity_key = other.client_identity_key;
        identity_key_fingerprint = other.identity_key_fingerprint;
        client_name = std::move(other.client_name);
        client_pairing_nonce = other.client_pairing_nonce;
        scrypt_salt = other.scrypt_salt;
        point_a = other.point_a;
        point_b = other.point_b;
        requested_permissions = other.requested_permissions;
        effective_permissions = other.effective_permissions;
        expires_at_utc_seconds = other.expires_at_utc_seconds;
        cooldown_until_utc_seconds = other.cooldown_until_utc_seconds;
        poll_limiter = other.poll_limiter;
        approval_generation = other.approval_generation;
        challenges_used = other.challenges_used;
        state = other.state;
        final_aad = std::move(other.final_aad);
        spake = std::move(other.spake);
        other.clear();
      }
    };

    /** @brief Immutable async scrypt/SPAKE work item detached from live pairing storage. */
    struct PairingWork {
      Identifier128 session_id {};  ///< Session receiving the derived challenge.
      std::uint32_t approval_generation {};  ///< Exact challenge generation.
      std::uint64_t cooldown_until_utc_seconds {};  ///< Retry time published on provider failure.
      ControlPairingApprovalInput input;  ///< Complete provider input including entered PIN.

      /** @brief Construct empty worker-owned secret storage. */
      PairingWork() = default;
      PairingWork(const PairingWork &) = delete;
      PairingWork &operator=(const PairingWork &) = delete;

      /** @brief Transfer secret ownership and clear the moved-from PIN. */
      PairingWork(PairingWork &&other) noexcept:
          session_id {other.session_id},
          approval_generation {other.approval_generation},
          cooldown_until_utc_seconds {other.cooldown_until_utc_seconds},
          input {std::move(other.input)} {
        secure_zero(other.input.pin_digits);
        secure_zero(other.input.final_aad);
      }

      /** @brief Clear current secrets before taking another work item. */
      PairingWork &operator=(PairingWork &&other) noexcept {
        if (this != &other) {
          clear();
          session_id = other.session_id;
          approval_generation = other.approval_generation;
          cooldown_until_utc_seconds = other.cooldown_until_utc_seconds;
          input = std::move(other.input);
          secure_zero(other.input.pin_digits);
          secure_zero(other.input.final_aad);
        }
        return *this;
      }

      /** @brief Securely clear worker-owned PIN and AAD bytes. */
      ~PairingWork() {
        clear();
      }

      /** @brief Securely clear retained secret-bearing fields. */
      void clear() noexcept {
        secure_zero(input.pin_digits);
        secure_zero(input.final_aad);
        input.final_aad.clear();
      }
    };

    /** @brief Persisted-success replay retained independently of the LSP response cache. */
    struct CompletedPairing {
      Identifier128 session_id {};  ///< Completed pairing session.
      Identifier128 client_id {};  ///< Persisted client identifier.
      PublicKey256 client_identity_key {};  ///< Persisted identity key.
      PeerEndpoint peer {};  ///< Exact association allowed to replay FINISH.
      std::uint32_t connection_generation {};  ///< Exact completed association generation.
      PairFinishPayload finish {};  ///< Exact semantic FINISH request.
      std::vector<std::uint8_t> result_bytes;  ///< Exact encoded RESULT bytes and signatures.
      std::uint64_t expires_at_utc_seconds {};  ///< Bounded replay lifetime.
      bool active {};  ///< Whether the fixed cache slot is populated.
    };

    Impl(
      const HostIdentity &identity,
      const Digest256 spki_sha256,
      ControlTrustStore &trust_store,
      ControlApplicationProvider &applications,
      ControlStartHandler &start_handler,
      ControlCrypto &crypto,
      ControlPairingProvider &pairing_provider,
      const PermissionSet pairing_permissions,
      ControlTransport &transport,
      const std::size_t maximum_connections
    ) noexcept:
        identity_ {identity},
        spki_sha256_ {spki_sha256},
        trust_store_ {trust_store},
        applications_ {applications},
        start_handler_ {start_handler},
        crypto_ {crypto},
        pairing_provider_ {pairing_provider},
        pairing_permissions_ {pairing_permissions},
        transport_ {transport},
        maximum_connections_ {maximum_connections} {
      try {
        if (identity_.valid() && !is_zero(spki_sha256_) && pairing_permissions_.mask() != 0 && maximum_connections_ > 0 &&
            maximum_connections_ <= maximum_control_connections) {
          connections_.reserve(maximum_connections_);
          pairings_.reserve(maximum_pending_pairings);
          pairing_work_.reserve(maximum_pending_pairings);
          pairing_worker_ = std::jthread {[this](const std::stop_token stop_token) {
            pairing_worker(stop_token);
          }};
          ready_ = true;
        }
      } catch (...) {
        ready_ = false;
      }
    }

    ~Impl() {
      pairing_worker_.request_stop();
      pairing_condition_.notify_all();
      if (pairing_worker_.joinable()) {
        pairing_worker_.join();
      }
      std::scoped_lock lock(mutex_);
      for (auto &pairing : pairings_) {
        clear_pairing(pairing);
      }
      for (auto &work : pairing_work_) {
        work.clear();
      }
      for (auto &completed : completed_pairings_) {
        clear_completed_pairing(completed);
      }
      pairings_.clear();
      pairing_work_.clear();
    }

    /** @brief Clear retained PIN/SPAKE/exporter material before releasing a pending session. */
    static void clear_pairing(PendingPairing &pairing) noexcept {
      pairing.clear();
    }

    /** @brief Clear one completed-result replay slot. */
    static void clear_completed_pairing(CompletedPairing &pairing) noexcept {
      secure_zero(pairing.finish.confirmation_a);
      secure_zero(pairing.finish.client_signature);
      secure_zero(pairing.result_bytes);
      pairing.result_bytes.clear();
      pairing = {};
    }

    /** @brief Consume a failed challenge and return the session to bounded PIN cooldown. */
    static void transition_pairing_to_cooldown(
      PendingPairing &pairing,
      const std::uint64_t now_utc_seconds
    ) noexcept {
      pairing.spake.reset();
      secure_zero(pairing.point_b);
      secure_zero(pairing.final_aad);
      pairing.final_aad.clear();
      pairing.state = PairingAdministrationState::cooldown;
      pairing.cooldown_until_utc_seconds = saturating_add(now_utc_seconds, pairing_retry_cooldown_seconds);
    }

    /** @brief Erase expired PIN sessions without touching persisted trust. */
    void retire_expired_pairings(const std::uint64_t now_utc_seconds) noexcept {
      for (std::size_t index = 0; index < pairings_.size();) {
        if (now_utc_seconds < pairings_[index].expires_at_utc_seconds) {
          ++index;
          continue;
        }
        clear_pairing(pairings_[index]);
        pairings_.erase(pairings_.begin() + static_cast<std::ptrdiff_t>(index));
      }
      for (auto &completed : completed_pairings_) {
        if (completed.active && now_utc_seconds >= completed.expires_at_utc_seconds) {
          clear_completed_pairing(completed);
        }
      }
    }

    /** @brief Execute expensive pairing derivation on the dedicated worker. */
    void pairing_worker(const std::stop_token stop_token) noexcept {
      while (!stop_token.stop_requested()) {
        PairingWork work;
        {
          std::unique_lock lock(mutex_);
          pairing_condition_.wait(lock, stop_token, [&]() {
            return !pairing_work_.empty();
          });
          if (stop_token.stop_requested()) {
            return;
          }
          work = std::move(pairing_work_.front());
          pairing_work_.erase(pairing_work_.begin());
        }
        std::array<std::uint8_t, pairing_spake_point_size> point_b {};
        auto session = pairing_provider_.approve(work.input, point_b);
        work.clear();
        std::scoped_lock lock(mutex_);
        const auto pairing = std::ranges::find(pairings_, work.session_id, &PendingPairing::session_id);
        if (pairing == pairings_.end() || pairing->approval_generation != work.approval_generation ||
            pairing->state != PairingAdministrationState::deriving) {
          continue;
        }
        if (!session || is_zero(point_b) || point_b[0] != 0x04) {
          pairing->spake.reset();
          pairing->point_b = {};
          pairing->state = PairingAdministrationState::cooldown;
          pairing->cooldown_until_utc_seconds = work.cooldown_until_utc_seconds;
          continue;
        }
        pairing->point_b = point_b;
        pairing->spake = std::move(session);
        pairing->state = PairingAdministrationState::challenge_ready;
      }
    }

    std::uint32_t association_ready(
      const PeerEndpoint &peer,
      const PairingDtlsExporter &exporter
    ) noexcept {
      std::scoped_lock lock(mutex_);
      if (!ready_ || !peer.valid() || is_zero(exporter) || connections_.size() >= maximum_connections_) {
        return 0;
      }
      if (find(peer) != connections_.size() || next_generation_ == 0) {
        return 0;
      }
      Connection connection;
      connection.peer = peer;
      connection.generation = next_generation_;
      connection.secrets.exporter = exporter;
      if (!crypto_.random(connection.secrets.server_nonce) || is_zero(connection.secrets.server_nonce)) {
        return 0;
      }
      ++next_generation_;
      if (next_generation_ == 0) {
        next_generation_ = 0;
      }
      try {
        connections_.push_back(std::move(connection));
        return connections_.back().generation;
      } catch (...) {
        return 0;
      }
    }

    void association_closed(const PeerEndpoint &peer) noexcept {
      std::scoped_lock lock(mutex_);
      const auto index = find(peer);
      if (index != connections_.size()) {
        connections_.erase(connections_.begin() + static_cast<std::ptrdiff_t>(index));
      }
      for (std::size_t pairing_index = 0; pairing_index < pairings_.size();) {
        if (pairings_[pairing_index].peer != peer) {
          ++pairing_index;
          continue;
        }
        clear_pairing(pairings_[pairing_index]);
        pairings_.erase(pairings_.begin() + static_cast<std::ptrdiff_t>(pairing_index));
      }
      for (auto &completed : completed_pairings_) {
        if (completed.active && completed.peer == peer) {
          clear_completed_pairing(completed);
        }
      }
    }

    void disconnect_client(const Identifier128 &client_id) noexcept {
      std::scoped_lock lock(mutex_);
      std::array<PeerEndpoint, maximum_control_connections> peers {};
      std::size_t count = 0;
      for (const auto &connection : connections_) {
        if (connection.authenticated_client && connection.authenticated_client->client_id == client_id) {
          peers[count++] = connection.peer;
        }
      }
      for (std::size_t index = 0; index < count; ++index) {
        transport_.close(peers[index]);
        if (const auto remaining = find(peers[index]); remaining != connections_.size()) {
          connections_.erase(connections_.begin() + static_cast<std::ptrdiff_t>(remaining));
        }
      }
    }

    bool receive(
      const PeerEndpoint &peer,
      const std::span<const std::uint8_t> frame,
      const std::uint64_t now_microseconds,
      const std::uint64_t now_utc_seconds
    ) noexcept {
      std::scoped_lock lock(mutex_);
      const auto index = find(peer);
      if (index == connections_.size()) {
        return false;
      }
      auto &connection = connections_[index];
      const auto parsed = parse_lspc(frame);
      if (!parsed) {
        transport_.close(peer);
        return false;
      }
      const auto release_path_probe = connection.outbound_path_probe.active &&
                                      !connection.outbound_path_probe.datagram_sent &&
                                      acknowledgement_covers(
                                        parsed.header.acknowledgement_base,
                                        parsed.header.acknowledgement_bitmap,
                                        connection.outbound_path_probe.message_id
                                      );
      connection.outbound.acknowledge(parsed.header.acknowledgement_base, parsed.header.acknowledgement_bitmap);
      if (release_path_probe) {
        if (!start_handler_.path_probe_intent_acknowledged(
              connection.peer,
              connection.outbound_path_probe.probe,
              now_microseconds
            )) {
          transport_.close(peer);
          return false;
        }
        connection.outbound_path_probe.datagram_sent = true;
      }

      if (has_flag(parsed.header.flags, lspc_flag::acknowledgement_only)) {
        const auto observed = connection.inbound.observe(parsed.header.message_id);
        if (observed == receive_id_result::too_far_ahead || observed == receive_id_result::too_old ||
            observed == receive_id_result::zero) {
          transport_.close(peer);
          return false;
        }
        return true;
      }
      const auto message_type = static_cast<ControlMessageType>(parsed.header.message_type);
      if (has_flag(parsed.header.flags, lspc_flag::response)) {
        if (message_type == ControlMessageType::video_config_ack) {
          return video_config_ack(connection, frame, parsed.header, parsed.payload, now_microseconds);
        }
        if (message_type == ControlMessageType::audio_config_ack) {
          return audio_config_ack(connection, frame, parsed.header, parsed.payload, now_microseconds);
        }
        if (message_type == ControlMessageType::microphone_config_ack) {
          return microphone_config_ack(connection, frame, parsed.header, parsed.payload, now_microseconds);
        }
        if (message_type == ControlMessageType::path_probe_ack) {
          return path_probe_ack(connection, frame, parsed.header, parsed.payload, now_microseconds);
        }
        transport_.close(peer);
        return false;
      }
      if (parsed.header.request_id == 0) {
        transport_.close(peer);
        return false;
      }

      const auto cached = connection.responses.lookup(parsed.header.request_id, frame);
      if (cached.result == response_cache_result::hit) {
        return transport_.send(peer, cached.response);
      }
      if (cached.result == response_cache_result::conflicting_request) {
        transport_.close(peer);
        return false;
      }

      if (message_type == ControlMessageType::path_probe && connection.inbound_path_probe.active &&
          parsed.header.request_id == connection.inbound_path_probe.header.request_id) {
        if (connection.inbound_path_probe.request.bytes().size() == frame.size() &&
            std::ranges::equal(connection.inbound_path_probe.request.bytes(), frame)) {
          return send_acknowledgement_only(connection);
        }
        transport_.close(peer);
        return false;
      }

      const auto observed = connection.inbound.observe(parsed.header.message_id);
      if (observed == receive_id_result::duplicate) {
        transport_.close(peer);
        return false;
      }
      if (observed != receive_id_result::accepted) {
        transport_.close(peer);
        return false;
      }

      if (message_type == ControlMessageType::client_hello) {
        if (parsed.header.connection_generation != 0 || connection.hello_complete) {
          return send_error(connection, frame, parsed.header, ControlMessageType::server_hello, ControlStatus::stale_generation, now_microseconds);
        }
        return client_hello(connection, frame, parsed.header, parsed.payload, now_microseconds);
      }
      if (!connection.hello_complete || parsed.header.connection_generation != connection.generation) {
        return send_error(connection, frame, parsed.header, response_type(message_type), ControlStatus::stale_generation, now_microseconds);
      }
      switch (message_type) {
        case ControlMessageType::pair_begin:
          return pair_begin(connection, frame, parsed.header, parsed.payload, now_microseconds, now_utc_seconds);
        case ControlMessageType::pair_poll:
          return pair_poll(connection, frame, parsed.header, parsed.payload, now_microseconds, now_utc_seconds);
        case ControlMessageType::pair_finish:
          return pair_finish(connection, frame, parsed.header, parsed.payload, now_microseconds, now_utc_seconds);
        case ControlMessageType::auth_request:
          return authenticate(connection, frame, parsed.header, parsed.payload, now_microseconds);
        case ControlMessageType::list_applications:
          return list_applications(connection, frame, parsed.header, parsed.payload, now_microseconds);
        case ControlMessageType::start:
          return start_input(connection, frame, parsed.header, parsed.payload, now_microseconds);
        case ControlMessageType::attach:
          return attach_input(connection, frame, parsed.header, parsed.payload, now_microseconds);
        case ControlMessageType::stop:
          return stop_input(connection, frame, parsed.header, parsed.payload, now_microseconds);
        case ControlMessageType::path_probe:
          return receive_path_probe(connection, frame, parsed.header, parsed.payload, now_microseconds);
        case ControlMessageType::video_config:
        case ControlMessageType::video_config_ack:
        case ControlMessageType::audio_config:
        case ControlMessageType::audio_config_ack:
        case ControlMessageType::microphone_config:
        case ControlMessageType::microphone_config_ack:
        case ControlMessageType::path_probe_ack:
        case ControlMessageType::client_hello:
        case ControlMessageType::server_hello:
        case ControlMessageType::pair_pending:
        case ControlMessageType::pair_challenge:
        case ControlMessageType::pair_result:
        case ControlMessageType::auth_response:
        case ControlMessageType::applications:
        case ControlMessageType::start_response:
        case ControlMessageType::attach_response:
        case ControlMessageType::stop_response:
          return send_error(connection, frame, parsed.header, response_type(message_type), ControlStatus::unsupported, now_microseconds);
      }
      return send_error(connection, frame, parsed.header, message_type, ControlStatus::unsupported, now_microseconds);
    }

    void tick(const std::uint64_t now_microseconds) noexcept {
      std::scoped_lock lock(mutex_);
      for (std::size_t index = 0; index < connections_.size();) {
        auto &connection = connections_[index];
        if (connection.inbound_path_probe.active &&
            now_microseconds >= connection.inbound_path_probe.deadline_microseconds) {
          const auto request = connection.inbound_path_probe.request;
          const auto header = connection.inbound_path_probe.header;
          connection.inbound_path_probe = {};
          if (!send_error(
                connection,
                request.bytes(),
                header,
                ControlMessageType::path_probe_ack,
                ControlStatus::timeout,
                now_microseconds
              )) {
            const auto peer = connection.peer;
            transport_.close(peer);
            if (const auto remaining = find(peer); remaining != connections_.size()) {
              connections_.erase(connections_.begin() + static_cast<std::ptrdiff_t>(remaining));
            }
            continue;
          }
        }
        if (connection.outbound_path_probe.active &&
            now_microseconds >= connection.outbound_path_probe.deadline_microseconds) {
          const auto probe = connection.outbound_path_probe.probe;
          if (!start_handler_.path_probe_rejected(connection.peer, probe, ControlStatus::timeout)) {
            const auto peer = connection.peer;
            transport_.close(peer);
            if (const auto remaining = find(peer); remaining != connections_.size()) {
              connections_.erase(connections_.begin() + static_cast<std::ptrdiff_t>(remaining));
            }
            continue;
          }
          connection.outbound_path_probe = {};
        }
        if (connection.outbound.has_failed(now_microseconds)) {
          const auto peer = connection.peer;
          transport_.close(peer);
          if (const auto remaining = find(peer); remaining != connections_.size()) {
            connections_.erase(connections_.begin() + static_cast<std::ptrdiff_t>(remaining));
          }
          continue;
        }
        if (auto *due = connection.outbound.due(now_microseconds); due != nullptr) {
          if (!transport_.send(connection.peer, due->frame.bytes())) {
            const auto peer = connection.peer;
            transport_.close(peer);
            if (const auto remaining = find(peer); remaining != connections_.size()) {
              connections_.erase(connections_.begin() + static_cast<std::ptrdiff_t>(remaining));
            }
            continue;
          }
          connection.outbound.mark_retransmitted(*due, now_microseconds, connection.rto);
        }
        ++index;
      }
    }

    [[nodiscard]] std::uint64_t path_probe_interval(const PeerEndpoint &peer) const noexcept {
      std::scoped_lock lock(mutex_);
      const auto index = find(peer);
      return index == connections_.size() ? 0 : std::max<std::uint64_t>(1'000'000U, connections_[index].rto.timeout_microseconds());
    }

    [[nodiscard]] std::size_t connection_count() const noexcept {
      std::scoped_lock lock(mutex_);
      return connections_.size();
    }

    [[nodiscard]] std::vector<PendingPairingSummary> pending_pairings(const std::uint64_t now_utc_seconds) noexcept {
      std::scoped_lock lock(mutex_);
      retire_expired_pairings(now_utc_seconds);
      std::vector<PendingPairingSummary> result;
      try {
        result.reserve(pairings_.size());
        for (auto &pairing : pairings_) {
          if (pairing.state == PairingAdministrationState::cooldown &&
              pairing.challenges_used < maximum_pairing_challenges &&
              now_utc_seconds >= pairing.cooldown_until_utc_seconds) {
            pairing.state = PairingAdministrationState::awaiting_pin;
          }
          result.push_back({
            .pairing_session_id = pairing.session_id,
            .client_id = pairing.client_id,
            .identity_key_fingerprint = pairing.identity_key_fingerprint,
            .client_name = pairing.client_name,
            .client_name_verified = false,
            .effective_permissions = pairing.effective_permissions,
            .expires_at_utc_seconds = pairing.expires_at_utc_seconds,
            .challenges_used = pairing.challenges_used,
            .state = pairing.state,
          });
        }
      } catch (...) {
        result.clear();
      }
      return result;
    }

    std::size_t submit_pairing_pin(
      const Identifier128 &pairing_session_id,
      const std::array<std::uint8_t, 6> &pin_digits,
      const std::uint64_t now_utc_seconds
    ) noexcept {
      if (is_zero(pairing_session_id) || std::ranges::any_of(pin_digits, [](const std::uint8_t digit) {
            return digit < '0' || digit > '9';
          })) {
        return 0;
      }
      std::scoped_lock lock(mutex_);
      retire_expired_pairings(now_utc_seconds);
      const auto pairing = std::ranges::find(pairings_, pairing_session_id, &PendingPairing::session_id);
      if (pairing == pairings_.end()) {
        return 0;
      }
      if (pairing->state == PairingAdministrationState::cooldown &&
          pairing->challenges_used < maximum_pairing_challenges &&
          now_utc_seconds >= pairing->cooldown_until_utc_seconds) {
        pairing->state = PairingAdministrationState::awaiting_pin;
      }
      if (pairing->state != PairingAdministrationState::awaiting_pin ||
          pairing->challenges_used >= maximum_pairing_challenges ||
          pairing->approval_generation == std::numeric_limits<std::uint32_t>::max()) {
        return 0;
      }
      const auto approval_generation = pairing->approval_generation + 1U;
      try {
        const auto aad = pairing_confirmation_aad({
          .host_id = identity_.host_id,
          .host_identity_key = identity_.application_public_key,
          .dtls_spki_sha256 = spki_sha256_,
          .client_id = pairing->client_id,
          .client_identity_key = pairing->client_identity_key,
          .pairing_session_id = pairing->session_id,
          .client_pairing_nonce = pairing->client_pairing_nonce,
          .connection_generation = pairing->connection_generation,
          .approval_generation = approval_generation,
          .client_hello_nonce = pairing->client_hello_nonce,
          .server_hello_nonce = pairing->server_hello_nonce,
          .scrypt_salt = pairing->scrypt_salt,
          .requested_permissions = pairing->requested_permissions,
          .effective_permissions = pairing->effective_permissions,
          .expires_at_utc_seconds = pairing->expires_at_utc_seconds,
          .pairing_exporter = pairing->exporter,
        });
        if (!aad) {
          return 0;
        }
        auto retained_aad = *aad;
        PairingWork work;
        work.session_id = pairing->session_id;
        work.approval_generation = approval_generation;
        work.cooldown_until_utc_seconds = saturating_add(now_utc_seconds, pairing_retry_cooldown_seconds);
        work.input.pin_digits = pin_digits;
        work.input.scrypt_salt = pairing->scrypt_salt;
        work.input.client_id = pairing->client_id;
        work.input.host_id = identity_.host_id;
        work.input.point_a = pairing->point_a;
        work.input.final_aad = std::move(*aad);
        pairing_work_.push_back(std::move(work));
        pairing->approval_generation = approval_generation;
        ++pairing->challenges_used;
        pairing->final_aad = std::move(retained_aad);
        pairing->point_b = {};
        pairing->spake.reset();
        pairing->state = PairingAdministrationState::deriving;
      } catch (...) {
        return 0;
      }
      pairing_condition_.notify_one();
      return 1;
    }

    void cancel_pairings() noexcept {
      std::scoped_lock lock(mutex_);
      for (auto &pairing : pairings_) {
        clear_pairing(pairing);
      }
      for (auto &work : pairing_work_) {
        work.clear();
      }
      pairings_.clear();
      pairing_work_.clear();
    }

    [[nodiscard]] std::size_t pairing_count(const std::uint64_t now_utc_seconds) noexcept {
      std::scoped_lock lock(mutex_);
      retire_expired_pairings(now_utc_seconds);
      return pairings_.size();
    }

    /** @brief Expose host-originated probe initiation to the owning server facade. */
    bool start_path_probe_public(
      const PeerEndpoint &peer,
      const PathProbePayload &probe,
      const std::uint64_t now_microseconds
    ) noexcept {
      return start_path_probe(peer, probe, now_microseconds);
    }

    /** @brief Expose peer-originated probe completion to the owning server facade. */
    bool complete_path_probe_public(
      const PeerEndpoint &peer,
      const PathProbePayload &probe,
      const std::uint64_t now_microseconds
    ) noexcept {
      return complete_path_probe(peer, probe, now_microseconds);
    }

    /** @brief Retire only the exact outstanding host probe after data-plane timeout. */
    bool cancel_path_probe(
      const PeerEndpoint &peer,
      const PathProbePayload &probe
    ) noexcept {
      std::scoped_lock lock(mutex_);
      const auto index = find(peer);
      if (index == connections_.size()) {
        return false;
      }
      auto &pending = connections_[index].outbound_path_probe;
      if (!pending.active || pending.probe != probe) {
        return false;
      }
      connections_[index].outbound.acknowledge(pending.message_id, 0);
      connections_[index].cancelled_path_probe_request_ids[connections_[index].next_cancelled_path_probe_slot] = pending.request_id;
      connections_[index].next_cancelled_path_probe_slot =
        (connections_[index].next_cancelled_path_probe_slot + 1U) % connections_[index].cancelled_path_probe_request_ids.size();
      pending = {};
      return true;
    }

  private:
    [[nodiscard]] std::size_t find(const PeerEndpoint &peer) const noexcept {
      const auto iterator = std::ranges::find(connections_, peer, &Connection::peer);
      return static_cast<std::size_t>(std::distance(connections_.begin(), iterator));
    }

    /** @brief Return whether one selective-ACK field explicitly covers a message ID. */
    [[nodiscard]] static bool acknowledgement_covers(
      const std::uint64_t base,
      const std::uint64_t bitmap,
      const std::uint64_t message_id
    ) noexcept {
      if (message_id == 0 || base == 0) {
        return false;
      }
      if (message_id == base) {
        return true;
      }
      if (message_id > base) {
        return false;
      }
      const auto distance = base - message_id;
      return distance <= 64U && (bitmap & (std::uint64_t {1} << (distance - 1U))) != 0;
    }

    static ControlMessageType response_type(const ControlMessageType request) noexcept {
      switch (request) {
        case ControlMessageType::client_hello:
          return ControlMessageType::server_hello;
        case ControlMessageType::pair_begin:
        case ControlMessageType::pair_poll:
          return ControlMessageType::pair_pending;
        case ControlMessageType::pair_finish:
          return ControlMessageType::pair_result;
        case ControlMessageType::auth_request:
          return ControlMessageType::auth_response;
        case ControlMessageType::list_applications:
          return ControlMessageType::applications;
        case ControlMessageType::start:
          return ControlMessageType::start_response;
        case ControlMessageType::attach:
          return ControlMessageType::attach_response;
        case ControlMessageType::stop:
          return ControlMessageType::stop_response;
        case ControlMessageType::video_config:
          return ControlMessageType::video_config_ack;
        case ControlMessageType::audio_config:
          return ControlMessageType::audio_config_ack;
        case ControlMessageType::audio_config_ack:
        case ControlMessageType::microphone_config:
          return ControlMessageType::microphone_config_ack;
        case ControlMessageType::path_probe:
          return ControlMessageType::path_probe_ack;
        case ControlMessageType::microphone_config_ack:
        case ControlMessageType::video_config_ack:
        case ControlMessageType::path_probe_ack:
        case ControlMessageType::server_hello:
        case ControlMessageType::pair_pending:
        case ControlMessageType::pair_challenge:
        case ControlMessageType::pair_result:
        case ControlMessageType::auth_response:
        case ControlMessageType::applications:
        case ControlMessageType::start_response:
        case ControlMessageType::attach_response:
        case ControlMessageType::stop_response:
          return request;
      }
      return request;
    }

    bool send_error(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &request_header,
      const ControlMessageType response,
      const ControlStatus status,
      const std::uint64_t now_microseconds
    ) noexcept {
      const auto payload = status_payload(status);
      return payload && send_response(connection, request, request_header, response, *payload, true, now_microseconds);
    }

    bool send_response(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &request_header,
      const ControlMessageType response_type,
      const std::span<const std::uint8_t> payload,
      const bool error,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (connection.next_message_id == 0 || payload.size() > maximum_control_frame_bytes - lspc_header_size) {
        transport_.close(connection.peer);
        return false;
      }
      std::array<std::uint8_t, maximum_control_frame_bytes> storage {};
      auto flags = static_cast<std::uint8_t>(
        static_cast<std::uint8_t>(lspc_flag::acknowledgement_required) |
        static_cast<std::uint8_t>(lspc_flag::response)
      );
      if (error) {
        flags |= static_cast<std::uint8_t>(lspc_flag::error_response);
      }
      const lspc_header header {
        .flags = flags,
        .message_type = static_cast<std::uint16_t>(response_type),
        .connection_generation = connection.generation,
        .payload_length = static_cast<std::uint32_t>(payload.size()),
        .message_id = connection.next_message_id,
        .request_id = request_header.request_id,
        .acknowledgement_base = connection.inbound.base(),
        .acknowledgement_bitmap = connection.inbound.bitmap(),
      };
      const auto serialized = serialize_lspc(header, payload, storage);
      if (!serialized) {
        transport_.close(connection.peer);
        return false;
      }
      const auto response = std::span<const std::uint8_t> {storage.data(), serialized.bytes_written};
      const auto cache_result = connection.responses.insert(request_header.request_id, request, response);
      if (cache_result != response_cache_result::stored && cache_result != response_cache_result::hit) {
        transport_.close(connection.peer);
        return false;
      }
      if (connection.outbound.store(
            connection.next_message_id,
            response,
            now_microseconds,
            saturating_add(now_microseconds, response_deadline_microseconds),
            connection.rto
          ) != outbound_store_result::stored) {
        transport_.close(connection.peer);
        return false;
      }
      ++connection.next_message_id;
      return transport_.send(connection.peer, response);
    }

    /** @brief Send one untracked ACK-only LSPC frame for an accepted client response. */
    bool send_acknowledgement_only(Connection &connection) noexcept {
      if (connection.next_message_id == 0) {
        return false;
      }
      std::array<std::uint8_t, lspc_header_size> storage {};
      const lspc_header header {
        .flags = static_cast<std::uint8_t>(lspc_flag::acknowledgement_only),
        .message_type = 0,
        .connection_generation = connection.generation,
        .payload_length = 0,
        .message_id = connection.next_message_id,
        .request_id = 0,
        .acknowledgement_base = connection.inbound.base(),
        .acknowledgement_bitmap = connection.inbound.bitmap(),
      };
      const auto serialized = serialize_lspc(header, {}, storage);
      if (!serialized) {
        return false;
      }
      ++connection.next_message_id;
      return transport_.send(connection.peer, storage);
    }

    /** @brief Reliably send one server-originated VIDEO_CONFIG after START or ATTACH response. */
    bool send_video_config(
      Connection &connection,
      const VideoConfigPayload &configuration,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (connection.pending_video.active) {
        return connection.pending_video.session_id == configuration.session_id &&
               connection.pending_video.video_generation == configuration.video.video_generation;
      }
      if (connection.next_message_id == 0) {
        return false;
      }
      const auto payload = encode_video_config(configuration);
      std::array<std::uint8_t, 8> request_bytes {};
      if (!payload || !crypto_.random(request_bytes)) {
        return false;
      }
      std::uint64_t request_id = 0;
      for (const auto byte : request_bytes) {
        request_id = (request_id << 8U) | byte;
      }
      if (request_id == 0) {
        request_id = 1;
      }
      std::array<std::uint8_t, maximum_control_frame_bytes> storage {};
      const lspc_header header {
        .flags = static_cast<std::uint8_t>(lspc_flag::acknowledgement_required),
        .message_type = static_cast<std::uint16_t>(ControlMessageType::video_config),
        .connection_generation = connection.generation,
        .payload_length = static_cast<std::uint32_t>(payload->size()),
        .message_id = connection.next_message_id,
        .request_id = request_id,
        .acknowledgement_base = connection.inbound.base(),
        .acknowledgement_bitmap = connection.inbound.bitmap(),
      };
      const auto serialized = serialize_lspc(header, *payload, storage);
      if (!serialized) {
        return false;
      }
      const auto frame = std::span<const std::uint8_t> {storage.data(), serialized.bytes_written};
      if (connection.outbound.store(
            connection.next_message_id,
            frame,
            now_microseconds,
            saturating_add(now_microseconds, response_deadline_microseconds),
            connection.rto
          ) != outbound_store_result::stored) {
        return false;
      }
      connection.pending_video = {
        .session_id = configuration.session_id,
        .video_generation = configuration.video.video_generation,
        .request_id = request_id,
        .message_id = connection.next_message_id,
        .active = true,
      };
      ++connection.next_message_id;
      return transport_.send(connection.peer, frame);
    }

    /** @brief Validate and commit one idempotent VIDEO_CONFIG_ACK response. */
    bool video_config_ack(
      Connection &connection,
      const std::span<const std::uint8_t> frame,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      (void) now_microseconds;
      const auto accepted_duplicate = std::ranges::find_if(connection.accepted_video_acks, [&](const Connection::AcceptedVideoAck &accepted) {
        return accepted.size == frame.size() && accepted.request_id == header.request_id &&
               std::ranges::equal(std::span<const std::uint8_t> {accepted.frame}.first(accepted.size), frame);
      });
      const auto observed = connection.inbound.observe(header.message_id);
      if (observed != receive_id_result::accepted) {
        if (accepted_duplicate != connection.accepted_video_acks.end()) {
          return send_acknowledgement_only(connection);
        }
        transport_.close(connection.peer);
        return false;
      }
      if (!connection.hello_complete || !connection.authenticated_client ||
          header.connection_generation != connection.generation || header.request_id == 0 ||
          !connection.pending_video.active || header.request_id != connection.pending_video.request_id ||
          frame.size() > maximum_control_frame_bytes) {
        transport_.close(connection.peer);
        return false;
      }
      const auto acknowledgement = decode_video_config_ack(payload);
      if (!acknowledgement || acknowledgement->session_id != connection.pending_video.session_id ||
          acknowledgement->video_generation != connection.pending_video.video_generation ||
          has_flag(header.flags, lspc_flag::error_response) != (acknowledgement->status != ControlStatus::success) ||
          !start_handler_.video_config_acknowledged(
            connection.peer,
            *connection.authenticated_client,
            connection.generation,
            *acknowledgement
          )) {
        transport_.close(connection.peer);
        return false;
      }
      connection.outbound.acknowledge(connection.pending_video.message_id, 0);
      connection.pending_video.active = false;
      auto &accepted = connection.accepted_video_acks[connection.next_video_ack_slot];
      accepted.request_id = header.request_id;
      std::ranges::copy(frame, accepted.frame.begin());
      accepted.size = frame.size();
      connection.next_video_ack_slot = (connection.next_video_ack_slot + 1U) % connection.accepted_video_acks.size();
      return send_acknowledgement_only(connection);
    }

    /** @brief Retain and transmit one reliable host-originated PATH_PROBE intent. */
    bool start_path_probe(
      const PeerEndpoint &peer,
      const PathProbePayload &probe,
      const std::uint64_t now_microseconds
    ) noexcept {
      std::scoped_lock lock(mutex_);
      const auto index = find(peer);
      if (index == connections_.size()) {
        return false;
      }
      auto &connection = connections_[index];
      if (!connection.authenticated_client || connection.outbound_path_probe.active ||
          connection.next_message_id == 0) {
        return false;
      }
      const auto payload = encode_path_probe(probe);
      std::array<std::uint8_t, 8> request_bytes {};
      if (!payload || !crypto_.random(request_bytes)) {
        return false;
      }
      std::uint64_t request_id = 0;
      for (const auto byte : request_bytes) {
        request_id = (request_id << 8U) | byte;
      }
      if (request_id == 0) {
        request_id = 1;
      }
      std::array<std::uint8_t, maximum_control_frame_bytes> storage {};
      const lspc_header header {
        .flags = static_cast<std::uint8_t>(lspc_flag::acknowledgement_required),
        .message_type = static_cast<std::uint16_t>(ControlMessageType::path_probe),
        .connection_generation = connection.generation,
        .payload_length = static_cast<std::uint32_t>(payload->size()),
        .message_id = connection.next_message_id,
        .request_id = request_id,
        .acknowledgement_base = connection.inbound.base(),
        .acknowledgement_bitmap = connection.inbound.bitmap(),
      };
      const auto serialized = serialize_lspc(header, *payload, storage);
      if (!serialized) {
        return false;
      }
      const auto frame = std::span<const std::uint8_t> {storage.data(), serialized.bytes_written};
      if (connection.outbound.store(
            connection.next_message_id,
            frame,
            now_microseconds,
            saturating_add(now_microseconds, response_deadline_microseconds),
            connection.rto
          ) != outbound_store_result::stored) {
        return false;
      }
      connection.outbound_path_probe = {
        .probe = probe,
        .request_id = request_id,
        .message_id = connection.next_message_id,
        .deadline_microseconds = saturating_add(now_microseconds, path_probe_semantic_deadline_microseconds),
        .datagram_sent = false,
        .active = true,
      };
      ++connection.next_message_id;
      return transport_.send(peer, frame);
    }

    /** @brief Retain one peer intent until its exact protected LSPP arrives. */
    bool receive_path_probe(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      const auto decoded = decode_path_probe(payload);
      if (!decoded) {
        return send_error(connection, request, header, ControlMessageType::path_probe_ack, ControlStatus::malformed, now_microseconds);
      }
      if (connection.inbound_path_probe.active) {
        return send_error(connection, request, header, ControlMessageType::path_probe_ack, ControlStatus::busy, now_microseconds);
      }
      const auto deadline = saturating_add(now_microseconds, path_probe_semantic_deadline_microseconds);
      if (!start_handler_.path_probe_requested(connection.peer, *decoded, deadline) ||
          !connection.inbound_path_probe.request.assign(request)) {
        return send_error(connection, request, header, ControlMessageType::path_probe_ack, ControlStatus::busy, now_microseconds);
      }
      connection.inbound_path_probe.probe = *decoded;
      connection.inbound_path_probe.header = header;
      connection.inbound_path_probe.deadline_microseconds = deadline;
      connection.inbound_path_probe.active = true;
      return send_acknowledgement_only(connection);
    }

    /** @brief Send the reliable semantic ACK after exact authenticated peer LSPP admission. */
    bool complete_path_probe(
      const PeerEndpoint &peer,
      const PathProbePayload &probe,
      const std::uint64_t now_microseconds
    ) noexcept {
      std::scoped_lock lock(mutex_);
      const auto index = find(peer);
      if (index == connections_.size()) {
        return false;
      }
      auto &connection = connections_[index];
      if (!connection.inbound_path_probe.active || connection.inbound_path_probe.probe != probe) {
        return false;
      }
      const auto payload = encode_path_probe(probe);
      if (!payload || !send_response(
                        connection,
                        connection.inbound_path_probe.request.bytes(),
                        connection.inbound_path_probe.header,
                        ControlMessageType::path_probe_ack,
                        *payload,
                        false,
                        now_microseconds
                      )) {
        return false;
      }
      connection.inbound_path_probe = {};
      return true;
    }

    /** @brief Validate one host-originated PATH_PROBE_ACK and cache exact duplicates. */
    bool path_probe_ack(
      Connection &connection,
      const std::span<const std::uint8_t> frame,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      (void) now_microseconds;
      const auto duplicate = std::ranges::find_if(connection.accepted_path_probe_acks, [&](const Connection::AcceptedPathProbeAck &accepted) {
        return accepted.size == frame.size() && accepted.request_id == header.request_id &&
               std::ranges::equal(std::span<const std::uint8_t> {accepted.frame}.first(accepted.size), frame);
      });
      const auto observed = connection.inbound.observe(header.message_id);
      if (observed != receive_id_result::accepted) {
        if (duplicate != connection.accepted_path_probe_acks.end()) {
          return send_acknowledgement_only(connection);
        }
        transport_.close(connection.peer);
        return false;
      }
      if (!connection.authenticated_client || header.request_id == 0) {
        transport_.close(connection.peer);
        return false;
      }
      if (!connection.outbound_path_probe.active) {
        const auto cancelled = std::ranges::find(connection.cancelled_path_probe_request_ids, header.request_id);
        if (cancelled == connection.cancelled_path_probe_request_ids.end()) {
          transport_.close(connection.peer);
          return false;
        }
        *cancelled = 0;
        auto &accepted = connection.accepted_path_probe_acks[connection.next_path_probe_ack_slot];
        accepted.request_id = header.request_id;
        std::ranges::copy(frame, accepted.frame.begin());
        accepted.size = frame.size();
        connection.next_path_probe_ack_slot =
          (connection.next_path_probe_ack_slot + 1U) % connection.accepted_path_probe_acks.size();
        return send_acknowledgement_only(connection);
      }
      if (!connection.outbound_path_probe.datagram_sent ||
          header.request_id != connection.outbound_path_probe.request_id) {
        transport_.close(connection.peer);
        return false;
      }
      const auto rejected = has_flag(header.flags, lspc_flag::error_response);
      if (rejected) {
        const auto status = decode_control_error(payload);
        if (!status || !start_handler_.path_probe_rejected(
                         connection.peer,
                         connection.outbound_path_probe.probe,
                         *status
                       )) {
          transport_.close(connection.peer);
          return false;
        }
      } else {
        const auto decoded = decode_path_probe(payload);
        if (!decoded || *decoded != connection.outbound_path_probe.probe ||
            !start_handler_.path_probe_acknowledged(connection.peer, *decoded)) {
          transport_.close(connection.peer);
          return false;
        }
      }
      connection.outbound.acknowledge(connection.outbound_path_probe.message_id, 0);
      connection.outbound_path_probe = {};
      auto &accepted = connection.accepted_path_probe_acks[connection.next_path_probe_ack_slot];
      accepted.request_id = header.request_id;
      std::ranges::copy(frame, accepted.frame.begin());
      accepted.size = frame.size();
      connection.next_path_probe_ack_slot = (connection.next_path_probe_ack_slot + 1U) % connection.accepted_path_probe_acks.size();
      return send_acknowledgement_only(connection);
    }

    /**
     * @brief Reliably send one server-originated AUDIO_CONFIG after START or ATTACH response.
     *
     * @param connection Authenticated connection state.
     * @param configuration Exact selected audio tuple.
     * @param now_microseconds Monotonic send time used by retransmission state.
     * @return True when the frame entered reliable output and its first send succeeded.
     */
    bool send_audio_config(
      Connection &connection,
      const AudioConfigPayload &configuration,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (connection.pending_audio.active) {
        return connection.pending_audio.payload.session_id == configuration.session_id &&
               connection.pending_audio.payload.audio.audio_generation == configuration.audio.audio_generation;
      }
      if (connection.next_message_id == 0) {
        return false;
      }
      const auto payload = encode_audio_config(configuration);
      std::array<std::uint8_t, 8> request_bytes {};
      if (!payload || !crypto_.random(request_bytes)) {
        return false;
      }
      std::uint64_t request_id = 0;
      for (const auto byte : request_bytes) {
        request_id = (request_id << 8U) | byte;
      }
      if (request_id == 0) {
        request_id = 1;
      }
      if (request_id == connection.pending_video.request_id) {
        request_id = request_id == std::numeric_limits<std::uint64_t>::max() ? 1U : request_id + 1U;
      }
      std::array<std::uint8_t, maximum_control_frame_bytes> storage {};
      const lspc_header header {
        .flags = static_cast<std::uint8_t>(lspc_flag::acknowledgement_required),
        .message_type = static_cast<std::uint16_t>(ControlMessageType::audio_config),
        .connection_generation = connection.generation,
        .payload_length = static_cast<std::uint32_t>(payload->size()),
        .message_id = connection.next_message_id,
        .request_id = request_id,
        .acknowledgement_base = connection.inbound.base(),
        .acknowledgement_bitmap = connection.inbound.bitmap(),
      };
      const auto serialized = serialize_lspc(header, *payload, storage);
      if (!serialized) {
        return false;
      }
      const auto frame = std::span<const std::uint8_t> {storage.data(), serialized.bytes_written};
      if (connection.outbound.store(
            connection.next_message_id,
            frame,
            now_microseconds,
            saturating_add(now_microseconds, response_deadline_microseconds),
            connection.rto
          ) != outbound_store_result::stored) {
        return false;
      }
      connection.pending_audio = {
        .payload = configuration,
        .request_id = request_id,
        .message_id = connection.next_message_id,
        .active = true,
      };
      ++connection.next_message_id;
      return transport_.send(connection.peer, frame);
    }

    /**
     * @brief Validate and commit one idempotent AUDIO_CONFIG_ACK response.
     *
     * @param connection Authenticated connection state.
     * @param frame Complete byte-identical LSPC frame.
     * @param header Parsed LSPC header.
     * @param payload Exact ACK CBOR payload.
     * @param now_microseconds Current monotonic time.
     * @return True when accepted or recognized as an exact cached duplicate.
     */
    bool audio_config_ack(
      Connection &connection,
      const std::span<const std::uint8_t> frame,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      (void) now_microseconds;
      const auto accepted_duplicate = std::ranges::find_if(connection.accepted_audio_acks, [&](const Connection::AcceptedAudioAck &accepted) {
        return accepted.size == frame.size() && accepted.request_id == header.request_id &&
               std::ranges::equal(std::span<const std::uint8_t> {accepted.frame}.first(accepted.size), frame);
      });
      const auto observed = connection.inbound.observe(header.message_id);
      if (observed != receive_id_result::accepted) {
        if (accepted_duplicate != connection.accepted_audio_acks.end()) {
          return send_acknowledgement_only(connection);
        }
        transport_.close(connection.peer);
        return false;
      }
      if (!connection.hello_complete || !connection.authenticated_client ||
          header.connection_generation != connection.generation || header.request_id == 0 ||
          !connection.pending_audio.active || header.request_id != connection.pending_audio.request_id ||
          frame.size() > maximum_control_frame_bytes) {
        transport_.close(connection.peer);
        return false;
      }
      const auto acknowledgement = decode_audio_config_ack(payload);
      if (!acknowledgement || acknowledgement->session_id != connection.pending_audio.payload.session_id ||
          acknowledgement->audio_generation != connection.pending_audio.payload.audio.audio_generation ||
          has_flag(header.flags, lspc_flag::error_response) == (acknowledgement->status == ControlStatus::success) ||
          !start_handler_.audio_config_acknowledged(
            connection.peer,
            *connection.authenticated_client,
            connection.generation,
            *acknowledgement
          )) {
        transport_.close(connection.peer);
        return false;
      }
      connection.outbound.acknowledge(connection.pending_audio.message_id, 0);
      connection.pending_audio.active = false;
      auto &accepted = connection.accepted_audio_acks[connection.next_audio_ack_slot];
      accepted.request_id = header.request_id;
      std::ranges::copy(frame, accepted.frame.begin());
      accepted.size = frame.size();
      connection.next_audio_ack_slot = (connection.next_audio_ack_slot + 1U) % connection.accepted_audio_acks.size();
      return send_acknowledgement_only(connection);
    }

    /** @brief Reliably send one server-originated MICROPHONE_CONFIG. */
    bool send_microphone_config(
      Connection &connection,
      const MicrophoneConfigPayload &configuration,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (connection.pending_microphone.active) {
        return connection.pending_microphone.payload.session_id == configuration.session_id &&
               connection.pending_microphone.payload.microphone.microphone_generation ==
                 configuration.microphone.microphone_generation;
      }
      if (connection.next_message_id == 0) {
        return false;
      }
      const auto payload = encode_microphone_config(configuration);
      std::array<std::uint8_t, 8> request_bytes {};
      if (!payload || !crypto_.random(request_bytes)) {
        return false;
      }
      std::uint64_t request_id = 0;
      for (const auto byte : request_bytes) {
        request_id = (request_id << 8U) | byte;
      }
      if (request_id == 0) {
        request_id = 1;
      }
      if (request_id == connection.pending_audio.request_id) {
        request_id = request_id == std::numeric_limits<std::uint64_t>::max() ? 1U : request_id + 1U;
      }
      if (request_id == connection.pending_video.request_id) {
        request_id = request_id == std::numeric_limits<std::uint64_t>::max() ? 1U : request_id + 1U;
      }
      std::array<std::uint8_t, maximum_control_frame_bytes> storage {};
      const lspc_header header {
        .flags = static_cast<std::uint8_t>(lspc_flag::acknowledgement_required),
        .message_type = static_cast<std::uint16_t>(ControlMessageType::microphone_config),
        .connection_generation = connection.generation,
        .payload_length = static_cast<std::uint32_t>(payload->size()),
        .message_id = connection.next_message_id,
        .request_id = request_id,
        .acknowledgement_base = connection.inbound.base(),
        .acknowledgement_bitmap = connection.inbound.bitmap(),
      };
      const auto serialized = serialize_lspc(header, *payload, storage);
      if (!serialized) {
        return false;
      }
      const auto frame = std::span<const std::uint8_t> {storage.data(), serialized.bytes_written};
      if (connection.outbound.store(
            connection.next_message_id,
            frame,
            now_microseconds,
            saturating_add(now_microseconds, response_deadline_microseconds),
            connection.rto
          ) != outbound_store_result::stored) {
        return false;
      }
      connection.pending_microphone = {
        .payload = configuration,
        .request_id = request_id,
        .message_id = connection.next_message_id,
        .active = true,
      };
      ++connection.next_message_id;
      return transport_.send(connection.peer, frame);
    }

    /** @brief Validate and commit one idempotent MICROPHONE_CONFIG_ACK response. */
    bool microphone_config_ack(
      Connection &connection,
      const std::span<const std::uint8_t> frame,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      (void) now_microseconds;
      const auto accepted_duplicate = std::ranges::find_if(connection.accepted_microphone_acks, [&](const Connection::AcceptedMicrophoneAck &accepted) {
        return accepted.size == frame.size() && accepted.request_id == header.request_id &&
               std::ranges::equal(std::span<const std::uint8_t> {accepted.frame}.first(accepted.size), frame);
      });
      const auto observed = connection.inbound.observe(header.message_id);
      if (observed != receive_id_result::accepted) {
        if (accepted_duplicate != connection.accepted_microphone_acks.end()) {
          return send_acknowledgement_only(connection);
        }
        transport_.close(connection.peer);
        return false;
      }
      if (!connection.hello_complete || !connection.authenticated_client ||
          header.connection_generation != connection.generation || header.request_id == 0 ||
          !connection.pending_microphone.active || header.request_id != connection.pending_microphone.request_id ||
          frame.size() > maximum_control_frame_bytes) {
        transport_.close(connection.peer);
        return false;
      }
      const auto acknowledgement = decode_microphone_config_ack(payload);
      if (!acknowledgement || acknowledgement->session_id != connection.pending_microphone.payload.session_id ||
          acknowledgement->microphone_generation != connection.pending_microphone.payload.microphone.microphone_generation ||
          has_flag(header.flags, lspc_flag::error_response) != (acknowledgement->status != ControlStatus::success) ||
          !start_handler_.microphone_config_acknowledged(
            connection.peer,
            *connection.authenticated_client,
            connection.generation,
            *acknowledgement
          )) {
        transport_.close(connection.peer);
        return false;
      }
      connection.outbound.acknowledge(connection.pending_microphone.message_id, 0);
      connection.pending_microphone.active = false;
      auto &accepted = connection.accepted_microphone_acks[connection.next_microphone_ack_slot];
      accepted.request_id = header.request_id;
      std::ranges::copy(frame, accepted.frame.begin());
      accepted.size = frame.size();
      connection.next_microphone_ack_slot = (connection.next_microphone_ack_slot + 1U) % connection.accepted_microphone_acks.size();
      return send_acknowledgement_only(connection);
    }

    bool client_hello(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      const auto *map = exact_map(payload, 2);
      const auto *version = map == nullptr ? nullptr : unsigned_value((*map)[0].second);
      if (version == nullptr || *version != wire_version || !fixed_bytes((*map)[1].second, connection.secrets.client_nonce) ||
          is_zero(connection.secrets.client_nonce)) {
        return send_error(connection, request, header, ControlMessageType::server_hello, ControlStatus::malformed, now_microseconds);
      }
      connection.hello_complete = true;
      const auto response = encode_control_value(cbor::Value {cbor::Value::Map {
        {1, wire_version},
        {2, static_cast<std::uint8_t>(ControlStatus::success)},
        {3, connection.generation},
        {4, bytes(identity_.host_id)},
        {5, bytes(identity_.application_public_key)},
        {6, bytes(spki_sha256_)},
        {7, bytes(connection.secrets.server_nonce)},
      }});
      return response && send_response(connection, request, header, ControlMessageType::server_hello, *response, false, now_microseconds);
    }

    bool pair_begin(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds,
      const std::uint64_t now_utc_seconds
    ) noexcept {
      if (connection.authenticated_client) {
        return send_error(connection, request, header, ControlMessageType::pair_pending, ControlStatus::stale_generation, now_microseconds);
      }
      std::optional<PairBeginPayload> begin;
      try {
        const auto decoded = decode_pair_begin(payload);
        if (!decoded) {
          return send_error(connection, request, header, ControlMessageType::pair_pending, ControlStatus::malformed, now_microseconds);
        }
        begin = std::move(*decoded);
      } catch (...) {
        return send_error(connection, request, header, ControlMessageType::pair_pending, ControlStatus::internal_failure, now_microseconds);
      }
      retire_expired_pairings(now_utc_seconds);
      const auto source_busy = std::ranges::any_of(pairings_, [&](const PendingPairing &pairing) {
        return pairing.peer == connection.peer ||
               (pairing.peer.family == connection.peer.family &&
                pairing.peer.remote_address == connection.peer.remote_address);
      });
      if (pairings_.size() >= maximum_pending_pairings || source_busy) {
        return send_error(connection, request, header, ControlMessageType::pair_pending, ControlStatus::busy, now_microseconds);
      }
      const auto identity_busy = std::ranges::any_of(pairings_, [&](const PendingPairing &pairing) {
        return pairing.client_id == begin->client_id || pairing.client_identity_key == begin->client_identity_key;
      });
      if (identity_busy) {
        return send_error(connection, request, header, ControlMessageType::pair_pending, ControlStatus::busy, now_microseconds);
      }
      const auto existing = trust_store_.find(begin->client_id);
      auto effective_permissions = PermissionSet::from_mask(
        begin->requested_permissions.mask() & pairing_permissions_.mask()
      );
      if (existing) {
        const auto requested_contains_stored =
          (begin->requested_permissions.mask() & existing->permissions.mask()) == existing->permissions.mask();
        if (!existing->enabled || existing->identity_key != begin->client_identity_key || !requested_contains_stored) {
          return send_error(connection, request, header, ControlMessageType::pair_pending, ControlStatus::permission_denied, now_microseconds);
        }
        effective_permissions = existing->permissions;
      }
      if (!effective_permissions || effective_permissions->mask() == 0) {
        return send_error(connection, request, header, ControlMessageType::pair_pending, ControlStatus::permission_denied, now_microseconds);
      }
      try {
        PendingPairing pairing;
        pairing.peer = connection.peer;
        pairing.connection_generation = connection.generation;
        pairing.exporter = connection.secrets.exporter;
        pairing.client_hello_nonce = connection.secrets.client_nonce;
        pairing.server_hello_nonce = connection.secrets.server_nonce;
        pairing.client_id = begin->client_id;
        pairing.client_identity_key = begin->client_identity_key;
        pairing.client_name = begin->client_name;
        pairing.client_pairing_nonce = begin->client_pairing_nonce;
        pairing.scrypt_salt = begin->scrypt_salt;
        pairing.point_a = begin->point_a;
        pairing.requested_permissions = begin->requested_permissions;
        pairing.effective_permissions = *effective_permissions;
        pairing.expires_at_utc_seconds = saturating_add(now_utc_seconds, pairing_ttl_seconds);
        if (!crypto_.random(pairing.session_id) || is_zero(pairing.session_id) ||
            !crypto_.sha256(pairing.client_identity_key, pairing.identity_key_fingerprint)) {
          return send_error(connection, request, header, ControlMessageType::pair_pending, ControlStatus::internal_failure, now_microseconds);
        }
        const auto response = encode_pair_pending({
          .pairing_session_id = pairing.session_id,
          .expires_at_utc_seconds = pairing.expires_at_utc_seconds,
          .effective_permissions = pairing.effective_permissions,
        });
        if (!response) {
          return send_error(connection, request, header, ControlMessageType::pair_pending, ControlStatus::internal_failure, now_microseconds);
        }
        pairings_.push_back(std::move(pairing));
        return send_response(connection, request, header, ControlMessageType::pair_pending, *response, false, now_microseconds);
      } catch (...) {
        return send_error(connection, request, header, ControlMessageType::pair_pending, ControlStatus::busy, now_microseconds);
      }
    }

    bool pair_poll(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds,
      const std::uint64_t now_utc_seconds
    ) noexcept {
      std::optional<PairPollPayload> poll;
      try {
        const auto decoded = decode_pair_poll(payload);
        if (!decoded) {
          return send_error(connection, request, header, ControlMessageType::pair_pending, ControlStatus::malformed, now_microseconds);
        }
        poll = *decoded;
      } catch (...) {
        return send_error(connection, request, header, ControlMessageType::pair_pending, ControlStatus::internal_failure, now_microseconds);
      }
      retire_expired_pairings(now_utc_seconds);
      const auto pairing = std::ranges::find(pairings_, poll->pairing_session_id, &PendingPairing::session_id);
      if (pairing == pairings_.end() || pairing->peer != connection.peer ||
          pairing->connection_generation != connection.generation) {
        return send_error(connection, request, header, ControlMessageType::pair_pending, ControlStatus::authentication_failed, now_microseconds);
      }
      if (pairing->poll_limiter.admit(now_microseconds) != PairingPollResult::accepted) {
        return send_error(connection, request, header, ControlMessageType::pair_pending, ControlStatus::busy, now_microseconds);
      }
      try {
        if (pairing->state == PairingAdministrationState::challenge_ready && pairing->spake) {
          const auto challenge = encode_pair_challenge({
            .pairing_session_id = pairing->session_id,
            .approval_generation = pairing->approval_generation,
            .point_b = pairing->point_b,
            .effective_permissions = pairing->effective_permissions,
            .expires_at_utc_seconds = pairing->expires_at_utc_seconds,
          });
          return challenge && send_response(
                                connection,
                                request,
                                header,
                                ControlMessageType::pair_challenge,
                                *challenge,
                                false,
                                now_microseconds
                              );
        }
        if (pairing->challenges_used >= maximum_pairing_challenges &&
            pairing->state != PairingAdministrationState::deriving) {
          return send_error(connection, request, header, ControlMessageType::pair_pending, ControlStatus::authentication_failed, now_microseconds);
        }
        const auto pending = encode_pair_pending({
          .pairing_session_id = pairing->session_id,
          .expires_at_utc_seconds = pairing->expires_at_utc_seconds,
          .effective_permissions = pairing->effective_permissions,
        });
        return pending && send_response(
                            connection,
                            request,
                            header,
                            ControlMessageType::pair_pending,
                            *pending,
                            false,
                            now_microseconds
                          );
      } catch (...) {
        return send_error(connection, request, header, ControlMessageType::pair_pending, ControlStatus::internal_failure, now_microseconds);
      }
    }

    bool pair_finish(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds,
      const std::uint64_t now_utc_seconds
    ) noexcept {
      std::optional<PairFinishPayload> finish;
      try {
        const auto decoded = decode_pair_finish(payload);
        if (!decoded) {
          return send_error(connection, request, header, ControlMessageType::pair_result, ControlStatus::malformed, now_microseconds);
        }
        finish = *decoded;
      } catch (...) {
        return send_error(connection, request, header, ControlMessageType::pair_result, ControlStatus::internal_failure, now_microseconds);
      }
      retire_expired_pairings(now_utc_seconds);
      for (const auto &completed : completed_pairings_) {
        if (!completed.active || completed.session_id != finish->pairing_session_id) {
          continue;
        }
        if (completed.peer != connection.peer || completed.connection_generation != connection.generation ||
            completed.finish != *finish) {
          return send_error(connection, request, header, ControlMessageType::pair_result, ControlStatus::authentication_failed, now_microseconds);
        }
        return send_response(
          connection,
          request,
          header,
          ControlMessageType::pair_result,
          completed.result_bytes,
          false,
          now_microseconds
        );
      }
      const auto pairing = std::ranges::find(pairings_, finish->pairing_session_id, &PendingPairing::session_id);
      if (pairing == pairings_.end() || pairing->peer != connection.peer ||
          pairing->connection_generation != connection.generation ||
          pairing->state != PairingAdministrationState::challenge_ready || !pairing->spake ||
          pairing->approval_generation != finish->approval_generation) {
        return send_error(connection, request, header, ControlMessageType::pair_result, ControlStatus::authentication_failed, now_microseconds);
      }
      std::array<std::uint8_t, pairing_confirmation_size> confirmation_b {};
      std::optional<std::vector<std::uint8_t>> client_transcript;
      try {
        client_transcript = pairing_client_signature_transcript(pairing->final_aad, finish->confirmation_a);
      } catch (...) {
        return send_error(connection, request, header, ControlMessageType::pair_result, ControlStatus::internal_failure, now_microseconds);
      }
      if (!pairing->spake->finish(finish->confirmation_a, confirmation_b) || !client_transcript ||
          !crypto_.verify(pairing->client_identity_key, *client_transcript, finish->client_signature)) {
        secure_zero(confirmation_b);
        transition_pairing_to_cooldown(*pairing, now_utc_seconds);
        return send_error(connection, request, header, ControlMessageType::pair_result, ControlStatus::authentication_failed, now_microseconds);
      }
      TrustedClient proposed {
        .client_id = pairing->client_id,
        .identity_key = pairing->client_identity_key,
        .permissions = pairing->effective_permissions,
        .revocation_generation = 1,
        .enabled = true,
      };
      const auto pairing_index = static_cast<std::size_t>(std::distance(pairings_.begin(), pairing));
      TrustedClient effective;
      const auto insertion = trust_store_.insert_if_absent(proposed, effective);
      const auto identical_permissions_changed = insertion == TrustInsertResult::identical &&
                                                 effective.permissions != pairing->effective_permissions;
      if ((insertion != TrustInsertResult::inserted && insertion != TrustInsertResult::identical) ||
          identical_permissions_changed) {
        secure_zero(confirmation_b);
        clear_pairing(pairings_[pairing_index]);
        pairings_.erase(pairings_.begin() + static_cast<std::ptrdiff_t>(pairing_index));
        return send_error(
          connection,
          request,
          header,
          ControlMessageType::pair_result,
          insertion == TrustInsertResult::conflict || identical_permissions_changed ?
            ControlStatus::authentication_failed :
            ControlStatus::internal_failure,
          now_microseconds
        );
      }
      try {
        const auto host_transcript = pairing_host_signature_transcript(
          pairing->final_aad,
          finish->confirmation_a,
          confirmation_b,
          effective.revocation_generation
        );
        std::array<std::uint8_t, ed25519_signature_size> host_signature {};
        if (!host_transcript || !crypto_.sign(*host_transcript, host_signature)) {
          throw std::bad_alloc {};
        }
        const auto response = encode_pair_result({
          .pairing_session_id = pairing->session_id,
          .approval_generation = pairing->approval_generation,
          .permissions = effective.permissions,
          .revocation_generation = effective.revocation_generation,
          .confirmation_b = confirmation_b,
          .host_signature = host_signature,
        });
        if (!response) {
          throw std::bad_alloc {};
        }
        CompletedPairing completed {
          .session_id = pairing->session_id,
          .client_id = effective.client_id,
          .client_identity_key = effective.identity_key,
          .peer = connection.peer,
          .connection_generation = connection.generation,
          .finish = *finish,
          .result_bytes = std::move(*response),
          .expires_at_utc_seconds = pairing->expires_at_utc_seconds,
          .active = true,
        };
        auto &completed_slot = completed_pairings_[next_completed_pairing_slot_];
        clear_completed_pairing(completed_slot);
        completed_slot = std::move(completed);
        next_completed_pairing_slot_ = (next_completed_pairing_slot_ + 1U) % completed_pairings_.size();
        connection.authenticated_client = effective;
        const auto response_bytes = std::span<const std::uint8_t> {completed_slot.result_bytes};
        clear_pairing(pairings_[pairing_index]);
        pairings_.erase(pairings_.begin() + static_cast<std::ptrdiff_t>(pairing_index));
        secure_zero(confirmation_b);
        return send_response(
          connection,
          request,
          header,
          ControlMessageType::pair_result,
          response_bytes,
          false,
          now_microseconds
        );
      } catch (...) {
        secure_zero(confirmation_b);
        clear_pairing(pairings_[pairing_index]);
        pairings_.erase(pairings_.begin() + static_cast<std::ptrdiff_t>(pairing_index));
        return send_error(connection, request, header, ControlMessageType::pair_result, ControlStatus::internal_failure, now_microseconds);
      }
    }

    bool authenticate(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      const auto *map = exact_map(payload, 3);
      Identifier128 client_id {};
      std::array<std::uint8_t, ed25519_signature_size> signature {};
      const auto *version = map == nullptr ? nullptr : unsigned_value((*map)[0].second);
      if (version == nullptr || *version != wire_version || !fixed_bytes((*map)[1].second, client_id) ||
          !fixed_bytes((*map)[2].second, signature) || is_zero(client_id)) {
        return send_error(connection, request, header, ControlMessageType::auth_response, ControlStatus::malformed, now_microseconds);
      }
      const auto client = trust_store_.find(client_id);
      const auto transcript = authentication_signature_transcript(
        identity_.host_id,
        client_id,
        connection.secrets.client_nonce,
        connection.secrets.server_nonce,
        connection.generation
      );
      if (!client || !client->valid() || !client->enabled || !transcript || !crypto_.verify(client->identity_key, *transcript, signature)) {
        return send_error(connection, request, header, ControlMessageType::auth_response, ControlStatus::authentication_failed, now_microseconds);
      }
      std::array<std::uint8_t, ed25519_signature_size> server_signature {};
      if (!crypto_.sign(*transcript, server_signature)) {
        return send_error(connection, request, header, ControlMessageType::auth_response, ControlStatus::internal_failure, now_microseconds);
      }
      connection.authenticated_client = *client;
      const auto response = encode_control_value(cbor::Value {cbor::Value::Map {
        {1, wire_version},
        {2, static_cast<std::uint8_t>(ControlStatus::success)},
        {3, client->permissions.mask()},
        {4, client->revocation_generation},
        {5, connection.generation},
        {6, bytes(server_signature)},
      }});
      std::ranges::fill(server_signature, 0);
      return response && send_response(connection, request, header, ControlMessageType::auth_response, *response, false, now_microseconds);
    }

    bool list_applications(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      const auto *map = exact_map(payload, 1);
      const auto *version = map == nullptr ? nullptr : unsigned_value((*map)[0].second);
      if (version == nullptr || *version != wire_version) {
        return send_error(connection, request, header, ControlMessageType::applications, ControlStatus::malformed, now_microseconds);
      }
      if (!connection.authenticated_client ||
          !connection.authenticated_client->permissions.contains(Permission::browse_applications)) {
        return send_error(connection, request, header, ControlMessageType::applications, ControlStatus::permission_denied, now_microseconds);
      }
      const auto snapshot = applications_.snapshot();
      if (!snapshot || snapshot->size() > maximum_applications) {
        return send_error(connection, request, header, ControlMessageType::applications, ControlStatus::busy, now_microseconds);
      }
      cbor::Value::Array application_values;
      try {
        application_values.reserve(snapshot->size());
        for (const auto &application : *snapshot) {
          if (!valid_text(application.id, maximum_application_id_bytes) ||
              !valid_text(application.name, maximum_application_name_bytes) ||
              (!application.image_path.empty() && !valid_text(application.image_path, maximum_application_image_bytes))) {
            return send_error(connection, request, header, ControlMessageType::applications, ControlStatus::internal_failure, now_microseconds);
          }
          application_values.emplace_back(cbor::Value::Map {
            {1, application.id},
            {2, application.name},
            {3, application.image_path},
          });
        }
      } catch (...) {
        return send_error(connection, request, header, ControlMessageType::applications, ControlStatus::internal_failure, now_microseconds);
      }
      const auto response = encode_control_value(cbor::Value {cbor::Value::Map {
        {1, wire_version},
        {2, static_cast<std::uint8_t>(ControlStatus::success)},
        {3, std::move(application_values)},
      }});
      if (!response) {
        return send_error(connection, request, header, ControlMessageType::applications, ControlStatus::busy, now_microseconds);
      }
      return send_response(connection, request, header, ControlMessageType::applications, *response, false, now_microseconds);
    }

    bool start_input(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (!connection.authenticated_client ||
          !connection.authenticated_client->permissions.contains(Permission::start_attach) ||
          !connection.authenticated_client->permissions.contains(Permission::input)) {
        return send_error(connection, request, header, ControlMessageType::start_response, ControlStatus::permission_denied, now_microseconds);
      }
      const auto decoded = decode_start(payload);
      if (!decoded) {
        return send_error(connection, request, header, ControlMessageType::start_response, ControlStatus::malformed, now_microseconds);
      }
      const auto selected = start_handler_.start_input(
        connection.peer,
        *connection.authenticated_client,
        connection.generation,
        *decoded
      );
      if (!selected) {
        return send_error(connection, request, header, ControlMessageType::start_response, selected.error(), now_microseconds);
      }
      const auto response = encode_start_response(*selected);
      if (!response || !send_response(connection, request, header, ControlMessageType::start_response, *response, false, now_microseconds)) {
        return false;
      }
      const auto video_configuration = start_handler_.video_configuration(
        selected->session_id,
        selected->video.video_generation
      );
      if (video_configuration == nullptr || !send_video_config(connection, *video_configuration, now_microseconds)) {
        return false;
      }
      if (!send_audio_config(
            connection,
            AudioConfigPayload {
              .session_id = selected->session_id,
              .stream_generation = selected->stream_generation,
              .audio = selected->audio,
            },
            now_microseconds
          )) {
        return false;
      }
      return !selected->microphone || send_microphone_config(
                                        connection,
                                        MicrophoneConfigPayload {
                                          .session_id = selected->session_id,
                                          .stream_generation = selected->stream_generation,
                                          .microphone = *selected->microphone,
                                        },
                                        now_microseconds
                                      );
    }

    bool stop_input(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (!connection.authenticated_client ||
          !connection.authenticated_client->permissions.contains(Permission::stop_own_stream)) {
        return send_error(connection, request, header, ControlMessageType::stop_response, ControlStatus::permission_denied, now_microseconds);
      }
      const auto decoded = decode_stop(payload);
      if (!decoded) {
        return send_error(connection, request, header, ControlMessageType::stop_response, ControlStatus::malformed, now_microseconds);
      }
      const auto status = start_handler_.stop_input(
        *connection.authenticated_client,
        connection.generation,
        *decoded
      );
      const auto response = encode_stop_response(status);
      return response && send_response(
                           connection,
                           request,
                           header,
                           ControlMessageType::stop_response,
                           *response,
                           status != ControlStatus::success,
                           now_microseconds
                         );
    }

    bool attach_input(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (!connection.authenticated_client ||
          !connection.authenticated_client->permissions.contains(Permission::start_attach) ||
          !connection.authenticated_client->permissions.contains(Permission::input)) {
        return send_error(connection, request, header, ControlMessageType::attach_response, ControlStatus::permission_denied, now_microseconds);
      }
      const auto decoded = decode_attach(payload);
      if (!decoded) {
        return send_error(connection, request, header, ControlMessageType::attach_response, ControlStatus::malformed, now_microseconds);
      }
      const auto attached = start_handler_.attach_input(
        connection.peer,
        *connection.authenticated_client,
        connection.generation,
        *decoded
      );
      if (!attached) {
        return send_error(connection, request, header, ControlMessageType::attach_response, attached.error(), now_microseconds);
      }
      const auto response = encode_attach_response(*attached);
      if (!response || !send_response(connection, request, header, ControlMessageType::attach_response, *response, false, now_microseconds)) {
        return false;
      }
      const auto video_configuration = start_handler_.video_configuration(
        attached->session_id,
        attached->video.video_generation
      );
      if (video_configuration == nullptr || !send_video_config(connection, *video_configuration, now_microseconds)) {
        return false;
      }
      if (!send_audio_config(
            connection,
            AudioConfigPayload {
              .session_id = attached->session_id,
              .stream_generation = attached->stream_generation,
              .audio = attached->audio,
            },
            now_microseconds
          )) {
        return false;
      }
      return !attached->microphone || send_microphone_config(
                                        connection,
                                        MicrophoneConfigPayload {
                                          .session_id = attached->session_id,
                                          .stream_generation = attached->stream_generation,
                                          .microphone = *attached->microphone,
                                        },
                                        now_microseconds
                                      );
    }

    const HostIdentity &identity_;  ///< Stable LSP-only identity.
    Digest256 spki_sha256_ {};  ///< Exact DTLS leaf SPKI pin.
    ControlTrustStore &trust_store_;  ///< Persistent LSP trust owner.
    ControlApplicationProvider &applications_;  ///< Product application snapshot.
    ControlStartHandler &start_handler_;  ///< Input-only START authority owner.
    ControlCrypto &crypto_;  ///< Randomness and Ed25519 operations.
    ControlPairingProvider &pairing_provider_;  ///< SPAKE provider called only from `pairing_worker_`.
    PermissionSet pairing_permissions_ {};  ///< Host pairing permission ceiling.
    ControlTransport &transport_;  ///< Exact DTLS record output.
    std::vector<Connection> connections_;  ///< Bounded authenticated-DTLS association state.
    std::vector<PendingPairing> pairings_;  ///< At most four pending association/source-bound PIN sessions.
    std::vector<PairingWork> pairing_work_;  ///< At most four async scrypt/SPAKE work items.
    std::array<CompletedPairing, 4> completed_pairings_ {};  ///< Lost-result replay independent of request-ID caching.
    std::size_t next_completed_pairing_slot_ {};  ///< Next fixed replay-cache slot.
    std::size_t maximum_connections_ {};  ///< Configured association bound.
    std::uint32_t next_generation_ {1};  ///< Next nonzero connection generation.
    bool ready_ {};  ///< Constructor validation and allocation status.
    mutable std::recursive_mutex mutex_;  ///< Synchronizes socket callbacks and low-rate administration.
    std::condition_variable_any pairing_condition_;  ///< Dedicated worker wakeup without socket/HTTP blocking.
    std::jthread pairing_worker_;  ///< Sole synchronous scrypt/SPAKE execution owner.
  };

  HostControlServer::HostControlServer(
    const HostIdentity &identity,
    const Digest256 spki_sha256,
    ControlTrustStore &trust_store,
    ControlApplicationProvider &applications,
    ControlStartHandler &start_handler,
    ControlCrypto &crypto,
    ControlPairingProvider &pairing_provider,
    const PermissionSet pairing_permissions,
    ControlTransport &transport,
    const std::size_t maximum_connections
  ) noexcept:
      impl_ {new (std::nothrow) Impl {
        identity,
        spki_sha256,
        trust_store,
        applications,
        start_handler,
        crypto,
        pairing_provider,
        pairing_permissions,
        transport,
        maximum_connections,
      }} {
  }

  HostControlServer::~HostControlServer() = default;

  std::uint32_t HostControlServer::association_ready(
    const PeerEndpoint &peer,
    const PairingDtlsExporter &exporter
  ) noexcept {
    return impl_ ? impl_->association_ready(peer, exporter) : 0;
  }

  void HostControlServer::association_closed(const PeerEndpoint &peer) noexcept {
    if (impl_) {
      impl_->association_closed(peer);
    }
  }

  void HostControlServer::disconnect_client(const Identifier128 &client_id) noexcept {
    if (impl_) {
      impl_->disconnect_client(client_id);
    }
  }

  bool HostControlServer::receive(
    const PeerEndpoint &peer,
    const std::span<const std::uint8_t> frame,
    const std::uint64_t now_microseconds,
    const std::uint64_t now_utc_seconds
  ) noexcept {
    return impl_ && impl_->receive(peer, frame, now_microseconds, now_utc_seconds);
  }

  void HostControlServer::tick(const std::uint64_t now_microseconds) noexcept {
    if (impl_) {
      impl_->tick(now_microseconds);
    }
  }

  bool HostControlServer::start_path_probe(
    const PeerEndpoint &peer,
    const PathProbePayload &probe,
    const std::uint64_t now_microseconds
  ) noexcept {
    return impl_ && impl_->start_path_probe_public(peer, probe, now_microseconds);
  }

  bool HostControlServer::complete_path_probe(
    const PeerEndpoint &peer,
    const PathProbePayload &probe,
    const std::uint64_t now_microseconds
  ) noexcept {
    return impl_ && impl_->complete_path_probe_public(peer, probe, now_microseconds);
  }

  bool HostControlServer::cancel_path_probe(
    const PeerEndpoint &peer,
    const PathProbePayload &probe
  ) noexcept {
    return impl_ && impl_->cancel_path_probe(peer, probe);
  }

  std::uint64_t HostControlServer::path_probe_interval(const PeerEndpoint &peer) const noexcept {
    return impl_ ? impl_->path_probe_interval(peer) : 0;
  }

  std::size_t HostControlServer::connection_count() const noexcept {
    return impl_ ? impl_->connection_count() : 0;
  }

  std::vector<PendingPairingSummary> HostControlServer::pending_pairings(const std::uint64_t now_utc_seconds) noexcept {
    return impl_ ? impl_->pending_pairings(now_utc_seconds) : std::vector<PendingPairingSummary> {};
  }

  std::size_t HostControlServer::submit_pairing_pin(
    const Identifier128 &pairing_session_id,
    const std::array<std::uint8_t, 6> &pin_digits,
    const std::uint64_t now_utc_seconds
  ) noexcept {
    return impl_ ? impl_->submit_pairing_pin(pairing_session_id, pin_digits, now_utc_seconds) : 0;
  }

  void HostControlServer::cancel_pairings() noexcept {
    if (impl_) {
      impl_->cancel_pairings();
    }
  }

  std::size_t HostControlServer::pairing_count(const std::uint64_t now_utc_seconds) noexcept {
    return impl_ ? impl_->pairing_count(now_utc_seconds) : 0;
  }
}  // namespace lumen::lsp::runtime
