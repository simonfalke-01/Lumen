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
    constexpr std::size_t maximum_incoming_objects = 16;
    constexpr std::size_t maximum_buffered_object_bytes = 32U * 1'024U * 1'024U;
    constexpr std::size_t maximum_object_chunk_bytes = 768;
    constexpr std::uint64_t pairing_ttl_seconds = 120;
    constexpr std::uint64_t pairing_retry_cooldown_seconds = 2;
    constexpr std::uint8_t maximum_pairing_challenges = 3;
    constexpr std::size_t maximum_applications = 64;
    constexpr std::size_t maximum_application_image_bytes = 512;
    constexpr std::uint64_t response_deadline_microseconds = 1'000'000;
    constexpr std::uint64_t clipboard_response_deadline_microseconds = 5'000'000;
    constexpr std::uint64_t path_probe_semantic_deadline_microseconds = 60'000'000;  ///< Covers all legal LSPP retries plus margin.

    /** @brief Return local monotonic microseconds for asynchronous terminal responses. */
    std::uint64_t control_monotonic_microseconds() noexcept {
      return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                                          std::chrono::steady_clock::now().time_since_epoch()
      )
                                          .count());
    }

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
      control_rto rto {control_path_profile::local};  ///< Local-path initial RTO.
      std::uint64_t next_message_id {1};  ///< Next outbound logical message ID.

      struct PendingVideoConfig {
        Identifier128 session_id {};  ///< Exact configured session identifier.
        std::uint32_t video_generation {};  ///< Exact configured video generation.
        std::uint64_t request_id {};  ///< Random request identifier echoed by VIDEO_CONFIG_ACK.
        std::uint64_t message_id {};  ///< Reliable outbound message identifier.
        std::uint64_t deadline_microseconds {};  ///< Original absolute configuration-response deadline.
        bool active {};  ///< Whether a matching acknowledgement remains pending.
      } pending_video;  ///< At most one pending video configuration per connection.

      struct AcceptedVideoAck {
        std::uint64_t request_id {};  ///< VIDEO_CONFIG request identifier answered by this frame.
        std::array<std::uint8_t, maximum_control_frame_bytes> frame {};  ///< Byte-identical accepted ACK.
        std::size_t size {};  ///< Populated leading bytes in `frame`.
      };

      std::array<AcceptedVideoAck, 4> accepted_video_acks {};  ///< Bounded recent ACK cache across rekeys.
      std::size_t next_video_ack_slot {};  ///< Ring slot replaced by the next accepted video ACK.

      struct PendingVideoActivation {
        VideoConfigAckPayload acknowledgement {};  ///< Validated acknowledgement awaiting semantic activation.
        packet_slab<maximum_control_frame_bytes> frame {};  ///< Exact accepted response retained across dispatch.
        std::uint64_t deadline_microseconds {};  ///< Original absolute configuration-response deadline.
        bool active {};  ///< Whether `tick()` still owes the semantic callback.
      } pending_video_activation;  ///< Receipt-ACKed video activation dispatched outside provider callbacks.

      struct PendingAudioConfig {
        AudioConfigPayload payload {};  ///< Exact configuration awaiting client installation.
        std::uint64_t request_id {};  ///< Random request identifier echoed by AUDIO_CONFIG_ACK.
        std::uint64_t message_id {};  ///< Reliable outbound message identifier.
        std::uint64_t deadline_microseconds {};  ///< Original absolute configuration-response deadline.
        bool active {};  ///< Whether a matching acknowledgement remains pending.
      } pending_audio;  ///< At most one pending audio configuration per connection.

      struct AcceptedAudioAck {
        std::uint64_t request_id {};  ///< AUDIO_CONFIG request identifier answered by this frame.
        std::array<std::uint8_t, maximum_control_frame_bytes> frame {};  ///< Byte-identical accepted ACK frame.
        std::size_t size {};  ///< Populated leading bytes in `frame`.
      };

      std::array<AcceptedAudioAck, 4> accepted_audio_acks {};  ///< Bounded recent ACK cache across same-association updates.
      std::size_t next_audio_ack_slot {};  ///< Ring slot replaced by the next accepted ACK.

      struct PendingAudioActivation {
        AudioConfigAckPayload acknowledgement {};  ///< Validated acknowledgement awaiting semantic activation.
        packet_slab<maximum_control_frame_bytes> frame {};  ///< Exact accepted response retained across dispatch.
        std::uint64_t deadline_microseconds {};  ///< Original absolute configuration-response deadline.
        bool active {};  ///< Whether `tick()` still owes the semantic callback.
      } pending_audio_activation;  ///< Receipt-ACKed audio activation dispatched outside provider callbacks.

      struct PendingMicrophoneConfig {
        MicrophoneConfigPayload payload {};  ///< Exact configuration awaiting client installation.
        std::uint64_t request_id {};  ///< Random request identifier echoed by MICROPHONE_CONFIG_ACK.
        std::uint64_t message_id {};  ///< Reliable outbound message identifier.
        std::uint64_t deadline_microseconds {};  ///< Original absolute configuration-response deadline.
        bool active {};  ///< Whether a matching acknowledgement remains pending.
      } pending_microphone;  ///< At most one pending microphone configuration per connection.

      struct AcceptedMicrophoneAck {
        std::uint64_t request_id {};  ///< MICROPHONE_CONFIG request answered by this frame.
        std::array<std::uint8_t, maximum_control_frame_bytes> frame {};  ///< Byte-identical accepted ACK.
        std::size_t size {};  ///< Populated leading bytes in `frame`.
      };

      std::array<AcceptedMicrophoneAck, 4> accepted_microphone_acks {};  ///< Bounded ACK cache across rekeys.
      std::size_t next_microphone_ack_slot {};  ///< Ring slot replaced by the next accepted microphone ACK.

      struct PendingMicrophoneActivation {
        MicrophoneConfigAckPayload acknowledgement {};  ///< Validated acknowledgement awaiting semantic activation.
        std::uint64_t deadline_microseconds {};  ///< Original absolute configuration-response deadline.
        bool active {};  ///< Whether `tick()` still owes the one semantic callback.
      } pending_microphone_activation;  ///< Receipt-ACKed microphone activation dispatched outside provider callbacks.

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

      struct IncomingObject {
        Identifier128 object_id {};  ///< Stable object identifier.
        std::uint32_t total_length {};  ///< Complete bounded byte length.
        Digest256 sha256 {};  ///< Complete-object commitment.
        std::vector<std::uint8_t> bytes;  ///< Contiguous accepted prefix.
        bool complete {};  ///< Whether SHA-256 validated the complete bytes.
      };

      std::vector<IncomingObject> incoming_objects;  ///< At most sixteen active or completed inbound objects.
      std::size_t buffered_object_bytes {};  ///< Complete retained bytes across this connection.

      std::vector<ControlApplicationProvider::ArtworkObject> outgoing_objects;  ///< Frozen artwork transfer queue.
      std::size_t outgoing_object_index {};  ///< Current artwork object index.
      std::uint32_t outgoing_object_offset {};  ///< Next contiguous byte offset.
      std::uint64_t outgoing_object_request_id {};  ///< Exact current chunk response correlation.
      std::uint64_t outgoing_object_message_id {};  ///< Exact current reliable request message.
      bool outgoing_object_pending {};  ///< Whether one OBJECT_CHUNK response remains pending.

      struct AcceptedObjectAck {
        std::uint64_t request_id {};  ///< OBJECT_CHUNK request answered by this frame.
        std::array<std::uint8_t, maximum_control_frame_bytes> frame {};  ///< Byte-identical accepted response.
        std::size_t size {};  ///< Populated leading bytes.
      };

      std::array<AcceptedObjectAck, 4> accepted_object_acks {};  ///< Bounded late-duplicate cache.
      std::size_t next_object_ack_slot {};  ///< Next accepted object ACK replacement slot.

      CertificateRotatePayload pending_certificate_rotation {};  ///< Exact old-identity-signed request.
      std::uint64_t certificate_rotation_request_id {};  ///< Exact ACK correlation identifier.
      std::uint64_t certificate_rotation_message_id {};  ///< Exact reliable request message identifier.
      bool certificate_rotation_pending {};  ///< Whether client atomic persistence remains unacknowledged.
      std::uint32_t completed_certificate_rotation_generation {};  ///< Latest terminal rotation generation.
      bool completed_certificate_rotation_succeeded {};  ///< Whether the latest terminal ACK succeeded.
      std::array<std::uint8_t, maximum_control_frame_bytes> accepted_certificate_rotation_ack {};  ///< Latest accepted ACK.
      std::size_t accepted_certificate_rotation_ack_size {};  ///< Populated leading ACK bytes.
      std::uint64_t accepted_certificate_rotation_request_id {};  ///< Latest accepted request correlation.

      struct OutboundClipboard {
        Identifier128 session_id {};  ///< Stream session bound into the update.
        std::uint64_t sequence {};  ///< Host-local update sequence.
        std::vector<std::uint8_t> utf8;  ///< Complete UTF-8 text being delivered.
        Identifier128 object_id {};  ///< OBJECT_CHUNK identity for non-inline text.
        Digest256 sha256 {};  ///< Complete-object commitment for non-inline text.
        std::uint64_t request_id {};  ///< CLIPBOARD_UPDATE response correlation.
        std::uint64_t message_id {};  ///< Reliable CLIPBOARD_UPDATE message identifier.
        std::uint64_t deadline_microseconds {};  ///< Semantic response deadline.
        bool awaiting_object {};  ///< Whether the object transfer must finish before the update.
        bool awaiting_response {};  ///< Whether CLIPBOARD_UPDATE_RESPONSE remains outstanding.
      } outbound_clipboard;  ///< At most one host clipboard update in flight.

      struct QueuedClipboard {
        Identifier128 session_id {};  ///< Stream session for the newest text.
        std::vector<std::uint8_t> utf8;  ///< Newest text superseding older queued text.
        bool active {};  ///< Whether text waits for the in-flight update.
      } queued_clipboard;  ///< Latest-wins clipboard text behind the in-flight update.

      std::uint64_t next_clipboard_sequence {1};  ///< Next host clipboard sequence.
      std::uint64_t completed_clipboard_request_id {};  ///< Latest accepted clipboard response correlation.

      struct PendingText {
        packet_slab<maximum_control_frame_bytes> request {};  ///< Byte-identical request for terminal caching.
        lspc_header header {};  ///< Exact deferred response correlation.
        bool active {};  ///< Whether worker completion remains pending.
      } pending_text;  ///< At most one asynchronous text commit per connection.

      struct PendingStart {
        packet_slab<maximum_control_frame_bytes> request {};  ///< Exact START retained until its receipt ACK is flushed.
        lspc_header header {};  ///< Original request correlation and generation.
        bool active {};  ///< Whether START awaits dispatch outside the provider callback.
      } pending_start;  ///< One bounded capture-preparation operation per connection.

      /** @brief One input-rate request awaiting dispatch after its receipt ACK leaves the DTLS callback. */
      struct PendingInputRate {
        packet_slab<maximum_control_frame_bytes> request {};  ///< Exact request retained until its receipt ACK is flushed.
        lspc_header header {};  ///< Original request correlation and generation.
        bool active {};  ///< Whether rate selection awaits dispatch outside the DTLS callback.
      } pending_input_rate;  ///< At most one deferred rate selection per connection.

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
      std::uint32_t frozen_revocation_generation {};  ///< Existing-trust generation frozen at BEGIN, or zero for new trust.
      bool recovering_existing_trust {};  ///< Whether identical enabled trust existed at BEGIN.
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
        frozen_revocation_generation = other.frozen_revocation_generation;
        recovering_existing_trust = other.recovering_existing_trust;
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

    /** @brief One asynchronous edge-barrier text operation owned by the control worker. */
    struct TextWork {
      PeerEndpoint peer {};  ///< Exact authenticated association.
      TrustedClient client {};  ///< Frozen authenticated owner.
      std::uint32_t connection_generation {};  ///< Exact authority generation.
      TextInputPayload request {};  ///< Exact semantic text request.
      std::vector<std::uint8_t> utf8;  ///< Complete inline or assembled UTF-8 bytes.
      std::uint64_t deadline_microseconds {};  ///< Request-origin absolute terminal deadline.
      std::uint64_t request_id {};  ///< Exact deferred response correlation.
      std::uint64_t message_id {};  ///< Exact authenticated inbound message incarnation.
      Digest256 request_digest {};  ///< Complete canonical request digest.
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
          text_work_.reserve(maximum_connections_);
          pairing_worker_ = std::jthread {[this](const std::stop_token stop_token) {
            pairing_worker(stop_token);
          }};
          text_worker_ = std::jthread {[this](const std::stop_token stop_token) {
            text_worker(stop_token);
          }};
          ready_ = true;
        }
      } catch (...) {
        ready_ = false;
      }
    }

    ~Impl() {
      shutdown();
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

    /** @brief Stop asynchronous control work while product callbacks and transport output remain valid. */
    void shutdown() noexcept {
      {
        std::unique_lock lock(mutex_);
        if (shutdown_started_) {
          shutdown_condition_.wait(lock, [this]() {
            return shutdown_complete_;
          });
          return;
        }
        shutdown_started_ = true;
        ready_ = false;
        pairing_worker_.request_stop();
        text_worker_.request_stop();
        pairing_condition_.notify_all();
        text_condition_.notify_all();
      }
      if (pairing_worker_.joinable() && pairing_worker_.get_id() != std::this_thread::get_id()) {
        pairing_worker_.join();
      }
      if (text_worker_.joinable() && text_worker_.get_id() != std::this_thread::get_id()) {
        text_worker_.join();
      }

      std::scoped_lock lock(mutex_);
      const auto now = control_monotonic_microseconds();
      for (auto &connection : connections_) {
        if (connection.pending_text.active) {
          const auto frame = parse_lspc(connection.pending_text.request.bytes());
          if (frame) {
            const auto request = decode_text_input(frame.payload);
            if (request) {
              const auto response = encode_text_input_response({
                .status = ControlStatus::internal_failure,
                .session_id = request->session_id,
                .input_generation = request->input_generation,
                .preceding_edge_id = request->preceding_edge_id,
              });
              if (response) {
                (void) send_response(
                  connection,
                  connection.pending_text.request.bytes(),
                  connection.pending_text.header,
                  ControlMessageType::text_input_response,
                  *response,
                  true,
                  now
                );
              }
            }
          }
          connection.pending_text = {};
        }
        connection.outgoing_objects.clear();
        connection.outgoing_object_index = 0;
        connection.outgoing_object_offset = 0;
        connection.outgoing_object_request_id = 0;
        connection.outgoing_object_message_id = 0;
        connection.outgoing_object_pending = false;
        connection.outbound_clipboard = {};
        connection.queued_clipboard = {};
      }
      text_work_.clear();
      shutdown_complete_ = true;
      shutdown_condition_.notify_all();
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

    /** @brief Execute edge-barrier text work without blocking control receive/retry dispatch. */
    void text_worker(const std::stop_token stop_token) noexcept {
      while (!stop_token.stop_requested()) {
        TextWork work;
        {
          std::unique_lock lock(mutex_);
          text_condition_.wait(lock, stop_token, [&]() {
            return !text_work_.empty();
          });
          if (stop_token.stop_requested()) {
            return;
          }
          work = std::move(text_work_.front());
          text_work_.erase(text_work_.begin());
        }
        auto status = start_handler_.text_input(
          work.peer,
          work.client,
          work.connection_generation,
          work.request,
          work.utf8,
          work.deadline_microseconds
        );
        std::scoped_lock lock(mutex_);
        const auto index = find(work.peer);
        if (index == connections_.size()) {
          continue;
        }
        auto &connection = connections_[index];
        Digest256 pending_digest {};
        if (!connection.pending_text.active || connection.generation != work.connection_generation ||
            connection.pending_text.header.request_id != work.request_id ||
            connection.pending_text.header.message_id != work.message_id ||
            !crypto_.sha256(connection.pending_text.request.bytes(), pending_digest) ||
            pending_digest != work.request_digest) {
          continue;
        }
        const auto now = control_monotonic_microseconds();
        if (now >= work.deadline_microseconds) {
          status = ControlStatus::timeout;
        }
        if (status == ControlStatus::success && work.request.object_id) {
          const auto object = std::ranges::find(
            connection.incoming_objects,
            *work.request.object_id,
            &Connection::IncomingObject::object_id
          );
          if (object != connection.incoming_objects.end()) {
            connection.buffered_object_bytes -= object->total_length;
            connection.incoming_objects.erase(object);
          }
        }
        const auto response = encode_text_input_response({
          .status = status,
          .session_id = work.request.session_id,
          .input_generation = work.request.input_generation,
          .preceding_edge_id = work.request.preceding_edge_id,
        });
        const auto request = connection.pending_text.request;
        const auto header = connection.pending_text.header;
        connection.pending_text = {};
        if (!response || !send_response(
                           connection,
                           request.bytes(),
                           header,
                           ControlMessageType::text_input_response,
                           *response,
                           status != ControlStatus::success,
                           now
                         )) {
          transport_.close(work.peer);
        }
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

    /** @brief Cancel pending/completed pairing state for one client under the control lock. */
    void cancel_client_pairings(const Identifier128 &client_id) noexcept {
      for (std::size_t index = 0; index < pairings_.size();) {
        if (pairings_[index].client_id != client_id) {
          ++index;
          continue;
        }
        clear_pairing(pairings_[index]);
        pairings_.erase(pairings_.begin() + static_cast<std::ptrdiff_t>(index));
      }
      for (auto &completed : completed_pairings_) {
        if (completed.active && completed.client_id == client_id) {
          clear_completed_pairing(completed);
        }
      }
    }

    /** @brief Request close of every authenticated association for one client under the control lock. */
    void request_client_disconnects(const Identifier128 &client_id) noexcept {
      std::array<PeerEndpoint, maximum_control_connections> peers {};
      std::size_t count = 0;
      for (const auto &connection : connections_) {
        if (connection.authenticated_client && connection.authenticated_client->client_id == client_id) {
          peers[count++] = connection.peer;
        }
      }
      for (std::size_t index = 0; index < count; ++index) {
        transport_.close(peers[index]);
      }
    }

    void disconnect_client(const Identifier128 &client_id) noexcept {
      std::scoped_lock lock(mutex_);
      request_client_disconnects(client_id);
    }

    bool update_trusted_client(
      const Identifier128 &client_id,
      const PermissionSet permissions,
      const bool enabled
    ) noexcept {
      std::scoped_lock lock(mutex_);
      cancel_client_pairings(client_id);
      if (!trust_store_.update_existing(client_id, permissions, enabled)) {
        return false;
      }
      request_client_disconnects(client_id);
      return true;
    }

    bool revoke_trusted_client(const Identifier128 &client_id) noexcept {
      std::scoped_lock lock(mutex_);
      cancel_client_pairings(client_id);
      if (!trust_store_.revoke_existing(client_id)) {
        return false;
      }
      request_client_disconnects(client_id);
      return true;
    }

    bool receive(
      const PeerEndpoint &peer,
      const std::span<const std::uint8_t> frame,
      const std::uint64_t now_microseconds,
      const std::uint64_t now_utc_seconds
    ) noexcept {
      std::scoped_lock lock(mutex_);
      if (!ready_) {
        return false;
      }
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
      (void) connection.outbound.acknowledge(
        parsed.header.acknowledgement_base,
        parsed.header.acknowledgement_bitmap,
        now_microseconds,
        connection.rto
      );
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
        if (message_type == ControlMessageType::certificate_rotate_ack) {
          return certificate_rotation_ack(connection, frame, parsed.header, parsed.payload, now_microseconds);
        }
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
        if (message_type == ControlMessageType::object_chunk) {
          return object_chunk_acknowledgement(connection, frame, parsed.header, parsed.payload, now_microseconds);
        }
        if (message_type == ControlMessageType::clipboard_update_response) {
          return clipboard_update_response(connection, parsed.header, parsed.payload, now_microseconds);
        }
        transport_.close(peer);
        return false;
      }
      if (parsed.header.request_id == 0) {
        transport_.close(peer);
        return false;
      }

      response_semantic_identity semantic_identity {
        .message_type = parsed.header.message_type,
        .schema_version = wire_version,
        .generation = response_cache_generation(
          parsed.header.message_type,
          parsed.header.connection_generation,
          connection.generation
        ),
      };
      wire::write_be<std::uint64_t>(std::span<std::uint8_t> {semantic_identity.semantic_id}.last<8>(), parsed.header.request_id);
      if (!crypto_.sha256(frame, semantic_identity.request_digest)) {
        transport_.close(peer);
        return false;
      }
      const auto cached = connection.responses.lookup(
        parsed.header.request_id,
        semantic_identity,
        frame,
        now_microseconds
      );
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
      if (message_type == ControlMessageType::text_input && connection.pending_text.active &&
          parsed.header.request_id == connection.pending_text.header.request_id) {
        if (connection.pending_text.request.bytes().size() == frame.size() &&
            std::ranges::equal(connection.pending_text.request.bytes(), frame)) {
          return send_acknowledgement_only(connection);
        }
        transport_.close(peer);
        return false;
      }

      if (message_type == ControlMessageType::start && connection.pending_start.active &&
          parsed.header.request_id == connection.pending_start.header.request_id) {
        if (std::ranges::equal(connection.pending_start.request.bytes(), frame)) {
          return send_acknowledgement_only(connection);
        }
        transport_.close(peer);
        return false;
      }

      if (connection.pending_input_rate.active &&
          parsed.header.request_id == connection.pending_input_rate.header.request_id) {
        if (std::ranges::equal(connection.pending_input_rate.request.bytes(), frame)) {
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
        case ControlMessageType::quit_application:
          return quit_application(connection, frame, parsed.header, parsed.payload, now_microseconds);
        case ControlMessageType::start:
          return queue_start(connection, frame, parsed.header, now_microseconds);
        case ControlMessageType::attach:
          return attach_input(connection, frame, parsed.header, parsed.payload, now_microseconds);
        case ControlMessageType::stop:
          return stop_input(connection, frame, parsed.header, parsed.payload, now_microseconds);
        case ControlMessageType::text_input:
          return text_input(connection, frame, parsed.header, parsed.payload, now_microseconds);
        case ControlMessageType::input_rate_request:
          return queue_input_rate(connection, frame, parsed.header, now_microseconds);
        case ControlMessageType::path_probe:
          return receive_path_probe(connection, frame, parsed.header, parsed.payload, now_microseconds);
        case ControlMessageType::object_chunk:
          return object_chunk(connection, frame, parsed.header, parsed.payload, now_microseconds);
        case ControlMessageType::clipboard_update:
          return clipboard_update(connection, frame, parsed.header, parsed.payload, now_microseconds);
        case ControlMessageType::clipboard_update_response:
        case ControlMessageType::certificate_rotate:
        case ControlMessageType::certificate_rotate_ack:
        case ControlMessageType::quit_application_response:
        case ControlMessageType::video_config:
        case ControlMessageType::video_config_ack:
        case ControlMessageType::audio_config:
        case ControlMessageType::audio_config_ack:
        case ControlMessageType::microphone_config:
        case ControlMessageType::microphone_config_ack:
        case ControlMessageType::text_input_response:
        case ControlMessageType::input_rate_response:
        case ControlMessageType::stream_ended:
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

    /** @brief Dispatch receipt-ACKed media activation, START, and input-rate work outside DTLS callbacks. */
    void tick(const std::uint64_t now_microseconds) noexcept {
      std::scoped_lock lock(mutex_);
      for (std::size_t index = 0; index < connections_.size();) {
        auto &connection = connections_[index];
        const auto configuration_receipts_ready =
          (!connection.pending_video.active || connection.pending_video_activation.active) &&
          (!connection.pending_audio.active || connection.pending_audio_activation.active) &&
          !connection.pending_microphone.active;
        if (configuration_receipts_ready && connection.pending_video_activation.active) {
          const auto pending = connection.pending_video_activation;
          connection.pending_video_activation = {};
          if (!connection.authenticated_client || !connection.pending_video.active ||
              now_microseconds >= pending.deadline_microseconds ||
              !start_handler_.video_config_acknowledged(
                connection.peer,
                *connection.authenticated_client,
                connection.generation,
                pending.acknowledgement
              )) {
            const auto peer = connection.peer;
            transport_.close(peer);
            if (const auto remaining = find(peer); remaining != connections_.size()) {
              connections_.erase(connections_.begin() + static_cast<std::ptrdiff_t>(remaining));
            }
            continue;
          }
          (void) connection.outbound.acknowledge(
            connection.pending_video.message_id,
            0,
            now_microseconds,
            connection.rto
          );
          connection.pending_video.active = false;
          auto &accepted = connection.accepted_video_acks[connection.next_video_ack_slot];
          accepted.request_id = connection.pending_video.request_id;
          std::ranges::copy(pending.frame.bytes(), accepted.frame.begin());
          accepted.size = pending.frame.bytes().size();
          connection.next_video_ack_slot =
            (connection.next_video_ack_slot + 1U) % connection.accepted_video_acks.size();
        }
        if (configuration_receipts_ready && connection.pending_audio_activation.active) {
          const auto pending = connection.pending_audio_activation;
          connection.pending_audio_activation = {};
          if (!connection.authenticated_client || !connection.pending_audio.active ||
              now_microseconds >= pending.deadline_microseconds ||
              !start_handler_.audio_config_acknowledged(
                connection.peer,
                *connection.authenticated_client,
                connection.generation,
                pending.acknowledgement
              )) {
            const auto peer = connection.peer;
            transport_.close(peer);
            if (const auto remaining = find(peer); remaining != connections_.size()) {
              connections_.erase(connections_.begin() + static_cast<std::ptrdiff_t>(remaining));
            }
            continue;
          }
          (void) connection.outbound.acknowledge(
            connection.pending_audio.message_id,
            0,
            now_microseconds,
            connection.rto
          );
          connection.pending_audio.active = false;
          auto &accepted = connection.accepted_audio_acks[connection.next_audio_ack_slot];
          accepted.request_id = connection.pending_audio.request_id;
          std::ranges::copy(pending.frame.bytes(), accepted.frame.begin());
          accepted.size = pending.frame.bytes().size();
          connection.next_audio_ack_slot =
            (connection.next_audio_ack_slot + 1U) % connection.accepted_audio_acks.size();
        }
        if (configuration_receipts_ready && connection.pending_microphone_activation.active) {
          const auto pending = connection.pending_microphone_activation;
          connection.pending_microphone_activation = {};
          if (!connection.authenticated_client || now_microseconds >= pending.deadline_microseconds ||
              !start_handler_.microphone_config_acknowledged(
                connection.peer,
                *connection.authenticated_client,
                connection.generation,
                pending.acknowledgement
              )) {
            const auto peer = connection.peer;
            transport_.close(peer);
            if (const auto remaining = find(peer); remaining != connections_.size()) {
              connections_.erase(connections_.begin() + static_cast<std::ptrdiff_t>(remaining));
            }
            continue;
          }
        }
        if (connection.pending_start.active) {
          const auto pending = connection.pending_start;
          connection.pending_start = {};
          if (!start_input(
                connection,
                pending.request.bytes(),
                pending.header,
                pending.request.bytes().subspan(lspc_header_size),
                control_monotonic_microseconds()
              )) {
            const auto peer = connection.peer;
            transport_.close(peer);
            if (const auto remaining = find(peer); remaining != connections_.size()) {
              connections_.erase(connections_.begin() + static_cast<std::ptrdiff_t>(remaining));
            }
            continue;
          }
        }
        if (connection.pending_input_rate.active) {
          const auto pending = connection.pending_input_rate;
          connection.pending_input_rate = {};
          const auto peer = connection.peer;
          if (!input_rate(
                connection,
                pending.request.bytes(),
                pending.header,
                pending.request.bytes().subspan(lspc_header_size),
                control_monotonic_microseconds()
              )) {
            transport_.close(peer);
            if (const auto remaining = find(peer); remaining != connections_.size()) {
              connections_.erase(connections_.begin() + static_cast<std::ptrdiff_t>(remaining));
            }
            continue;
          }
        }
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
        if (connection.outbound_clipboard.awaiting_response &&
            now_microseconds >= connection.outbound_clipboard.deadline_microseconds &&
            !finish_clipboard(connection, now_microseconds)) {
          const auto peer = connection.peer;
          transport_.close(peer);
          if (const auto remaining = find(peer); remaining != connections_.size()) {
            connections_.erase(connections_.begin() + static_cast<std::ptrdiff_t>(remaining));
          }
          continue;
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

    [[nodiscard]] std::optional<std::vector<PeerEndpoint>> authenticated_peers() const noexcept {
      std::scoped_lock lock(mutex_);
      std::vector<PeerEndpoint> result;
      try {
        result.reserve(connections_.size());
        for (const auto &connection : connections_) {
          if (connection.authenticated_client) {
            result.push_back(connection.peer);
          }
        }
      } catch (...) {
        return std::nullopt;
      }
      return result;
    }

    [[nodiscard]] std::optional<std::vector<PeerEndpoint>> begin_certificate_rotation() noexcept {
      std::scoped_lock lock(mutex_);
      if (pairing_suspended_) {
        return std::nullopt;
      }
      pairing_suspended_ = true;
      for (auto &pairing : pairings_) {
        clear_pairing(pairing);
      }
      pairings_.clear();
      for (auto &work : pairing_work_) {
        work.clear();
      }
      pairing_work_.clear();
      for (auto &completed : completed_pairings_) {
        clear_completed_pairing(completed);
      }
      std::vector<PeerEndpoint> result;
      try {
        result.reserve(connections_.size());
        for (const auto &connection : connections_) {
          if (connection.authenticated_client) {
            result.push_back(connection.peer);
          }
        }
      } catch (...) {
        pairing_suspended_ = false;
        return std::nullopt;
      }
      return result;
    }

    void end_certificate_rotation() noexcept {
      std::scoped_lock lock(mutex_);
      pairing_suspended_ = false;
    }

    [[nodiscard]] CertificateRotationState certificate_rotation_state(
      const PeerEndpoint &peer,
      const std::uint32_t rotation_generation
    ) const noexcept {
      std::scoped_lock lock(mutex_);
      const auto index = find(peer);
      if (index == connections_.size()) {
        return CertificateRotationState::absent;
      }
      const auto &connection = connections_[index];
      if (connection.certificate_rotation_pending &&
          connection.pending_certificate_rotation.rotation_generation == rotation_generation) {
        return CertificateRotationState::pending;
      }
      if (connection.completed_certificate_rotation_generation != rotation_generation) {
        return CertificateRotationState::absent;
      }
      return connection.completed_certificate_rotation_succeeded ?
               CertificateRotationState::succeeded :
               CertificateRotationState::failed;
    }

    void commit_certificate_rotation(const Digest256 &new_spki_sha256) noexcept {
      if (is_zero(new_spki_sha256)) {
        return;
      }
      std::scoped_lock lock(mutex_);
      spki_sha256_ = new_spki_sha256;
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
      if (pairing_suspended_) {
        return 0;
      }
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
      (void) connections_[index].outbound.acknowledge(pending.message_id, 0, 0, connections_[index].rto);
      connections_[index].cancelled_path_probe_request_ids[connections_[index].next_cancelled_path_probe_slot] = pending.request_id;
      connections_[index].next_cancelled_path_probe_slot =
        (connections_[index].next_cancelled_path_probe_slot + 1U) % connections_[index].cancelled_path_probe_request_ids.size();
      pending = {};
      return true;
    }

    bool send_clipboard_update(
      const PeerEndpoint &peer,
      const Identifier128 &session_id,
      std::vector<std::uint8_t> utf8,
      const std::uint64_t now_microseconds
    ) noexcept {
      std::scoped_lock lock(mutex_);
      const auto index = find(peer);
      if (index == connections_.size() || !connections_[index].authenticated_client ||
          !connections_[index].authenticated_client->permissions.contains(Permission::clipboard) ||
          is_zero(session_id) || !valid_clipboard_bundle(utf8)) {
        return false;
      }
      auto &connection = connections_[index];
      if (connection.outbound_clipboard.awaiting_object || connection.outbound_clipboard.awaiting_response) {
        try {
          connection.queued_clipboard.session_id = session_id;
          connection.queued_clipboard.utf8 = std::move(utf8);
          connection.queued_clipboard.active = true;
        } catch (...) {
          return false;
        }
        return true;
      }
      return start_clipboard(connection, session_id, std::move(utf8), now_microseconds);
    }

    bool send_stream_ended(
      const PeerEndpoint &peer,
      const StreamEndedPayload &ended,
      const std::uint64_t now_microseconds
    ) noexcept {
      std::scoped_lock lock(mutex_);
      const auto index = find(peer);
      if (index == connections_.size() || !connections_[index].authenticated_client ||
          connections_[index].next_message_id == 0) {
        return false;
      }
      auto &connection = connections_[index];
      const auto payload = encode_stream_ended(ended);
      if (!payload) {
        return false;
      }
      std::array<std::uint8_t, maximum_control_frame_bytes> storage {};
      const lspc_header header {
        .flags = static_cast<std::uint8_t>(lspc_flag::acknowledgement_required),
        .message_type = static_cast<std::uint16_t>(ControlMessageType::stream_ended),
        .connection_generation = connection.generation,
        .payload_length = static_cast<std::uint32_t>(payload->size()),
        .message_id = connection.next_message_id,
        .request_id = 0,
        .acknowledgement_base = connection.inbound.base(),
        .acknowledgement_bitmap = connection.inbound.bitmap(),
      };
      const auto serialized = serialize_lspc(header, *payload, storage);
      if (!serialized) {
        return false;
      }
      const auto frame = std::span<const std::uint8_t> {storage}.first(serialized.bytes_written);
      const auto deadline = saturating_add(now_microseconds, response_deadline_microseconds);
      if (connection.outbound.reserve(connection.next_message_id, frame, deadline) != outbound_store_result::stored) {
        return false;
      }
      const auto message_id = connection.next_message_id++;
      if (!transport_.send(peer, frame)) {
        return false;
      }
      return connection.outbound.mark_initial_submitted(message_id, now_microseconds, connection.rto) ==
             outbound_submission_result::submitted;
    }

    bool start_certificate_rotation(
      const PeerEndpoint &peer,
      const Digest256 &new_spki_sha256,
      const std::uint32_t rotation_generation,
      const std::uint64_t now_microseconds
    ) noexcept {
      std::scoped_lock lock(mutex_);
      const auto index = find(peer);
      if (index == connections_.size() || !connections_[index].authenticated_client ||
          connections_[index].certificate_rotation_pending || connections_[index].next_message_id == 0) {
        return false;
      }
      auto &connection = connections_[index];
      const auto transcript = encode_certificate_rotation_transcript(
        identity_.host_id,
        identity_.application_public_key,
        spki_sha256_,
        new_spki_sha256,
        connection.generation,
        rotation_generation
      );
      CertificateRotatePayload rotation {
        .host_id = identity_.host_id,
        .connection_generation = connection.generation,
        .rotation_generation = rotation_generation,
        .new_spki_sha256 = new_spki_sha256,
      };
      if (!transcript || !crypto_.sign(*transcript, rotation.host_signature)) {
        return false;
      }
      const auto payload = encode_certificate_rotate(rotation);
      std::array<std::uint8_t, 8> request_bytes {};
      if (!payload || !crypto_.random(request_bytes)) {
        return false;
      }
      auto request_id = wire::read_be<std::uint64_t>(request_bytes);
      if (request_id == 0) {
        request_id = 1;
      }
      std::array<std::uint8_t, maximum_control_frame_bytes> storage {};
      const lspc_header header {
        .flags = static_cast<std::uint8_t>(lspc_flag::acknowledgement_required),
        .message_type = static_cast<std::uint16_t>(ControlMessageType::certificate_rotate),
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
      const auto frame = std::span<const std::uint8_t> {storage}.first(serialized.bytes_written);
      const auto deadline = saturating_add(now_microseconds, response_deadline_microseconds);
      if (connection.outbound.reserve(connection.next_message_id, frame, deadline) != outbound_store_result::stored) {
        return false;
      }
      connection.pending_certificate_rotation = rotation;
      connection.certificate_rotation_request_id = request_id;
      connection.certificate_rotation_message_id = connection.next_message_id;
      connection.certificate_rotation_pending = true;
      connection.completed_certificate_rotation_generation = 0;
      connection.completed_certificate_rotation_succeeded = false;
      const auto message_id = connection.next_message_id++;
      if (!transport_.send(peer, frame)) {
        return false;
      }
      return connection.outbound.mark_initial_submitted(message_id, now_microseconds, connection.rto) ==
             outbound_submission_result::submitted;
    }

    /** @brief Validate exact client persistence acknowledgement for one signed rotation. */
    bool certificate_rotation_ack(
      Connection &connection,
      const std::span<const std::uint8_t> frame,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      const auto observed = connection.inbound.observe(header.message_id);
      if (observed != receive_id_result::accepted) {
        return connection.accepted_certificate_rotation_ack_size == frame.size() &&
               connection.accepted_certificate_rotation_request_id == header.request_id &&
               std::ranges::equal(
                 std::span<const std::uint8_t> {connection.accepted_certificate_rotation_ack}.first(frame.size()),
                 frame
               ) &&
               send_acknowledgement_only(connection);
      }
      if (!connection.certificate_rotation_pending ||
          header.request_id != connection.certificate_rotation_request_id) {
        return false;
      }
      ControlStatus status = ControlStatus::success;
      if (has_flag(header.flags, lspc_flag::error_response)) {
        const auto error = decode_control_error(payload);
        if (!error || *error == ControlStatus::success) {
          return false;
        }
        status = *error;
      } else {
        const auto acknowledgement = decode_certificate_rotate_ack(payload);
        if (!acknowledgement || acknowledgement->status != ControlStatus::success ||
            acknowledgement->host_id != connection.pending_certificate_rotation.host_id ||
            acknowledgement->connection_generation != connection.pending_certificate_rotation.connection_generation ||
            acknowledgement->rotation_generation != connection.pending_certificate_rotation.rotation_generation) {
          return false;
        }
      }
      (void) status;
      (void) connection.outbound.acknowledge(
        connection.certificate_rotation_message_id,
        0,
        now_microseconds,
        connection.rto
      );
      connection.accepted_certificate_rotation_request_id = header.request_id;
      connection.accepted_certificate_rotation_ack_size = frame.size();
      std::copy(frame.begin(), frame.end(), connection.accepted_certificate_rotation_ack.begin());
      connection.certificate_rotation_pending = false;
      connection.completed_certificate_rotation_generation = connection.pending_certificate_rotation.rotation_generation;
      connection.completed_certificate_rotation_succeeded = status == ControlStatus::success;
      connection.pending_certificate_rotation = {};
      return send_acknowledgement_only(connection);
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
        case ControlMessageType::certificate_rotate:
          return ControlMessageType::certificate_rotate_ack;
        case ControlMessageType::list_applications:
          return ControlMessageType::applications;
        case ControlMessageType::quit_application:
          return ControlMessageType::quit_application_response;
        case ControlMessageType::start:
          return ControlMessageType::start_response;
        case ControlMessageType::attach:
          return ControlMessageType::attach_response;
        case ControlMessageType::stop:
          return ControlMessageType::stop_response;
        case ControlMessageType::text_input:
          return ControlMessageType::text_input_response;
        case ControlMessageType::input_rate_request:
          return ControlMessageType::input_rate_response;
        case ControlMessageType::video_config:
          return ControlMessageType::video_config_ack;
        case ControlMessageType::audio_config:
          return ControlMessageType::audio_config_ack;
        case ControlMessageType::audio_config_ack:
        case ControlMessageType::microphone_config:
          return ControlMessageType::microphone_config_ack;
        case ControlMessageType::path_probe:
          return ControlMessageType::path_probe_ack;
        case ControlMessageType::object_chunk:
          return ControlMessageType::object_chunk;
        case ControlMessageType::clipboard_update:
          return ControlMessageType::clipboard_update_response;
        case ControlMessageType::clipboard_update_response:
        case ControlMessageType::certificate_rotate_ack:
        case ControlMessageType::quit_application_response:
        case ControlMessageType::microphone_config_ack:
        case ControlMessageType::video_config_ack:
        case ControlMessageType::path_probe_ack:
        case ControlMessageType::text_input_response:
        case ControlMessageType::input_rate_response:
        case ControlMessageType::stream_ended:
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
      response_cache_metadata metadata {
        .identity = {
          .message_type = request_header.message_type,
          .schema_version = wire_version,
          .generation = response_cache_generation(
            request_header.message_type,
            request_header.connection_generation,
            connection.generation
          ),
        },
        .retention_deadline_microseconds = saturating_add(now_microseconds, response_deadline_microseconds),
      };
      wire::write_be<std::uint64_t>(std::span<std::uint8_t> {metadata.identity.semantic_id}.last<8>(), request_header.request_id);
      if (!crypto_.sha256(request, metadata.identity.request_digest)) {
        transport_.close(connection.peer);
        return false;
      }
      const auto cache_result = connection.responses.insert(
        request_header.request_id,
        metadata,
        request,
        response,
        now_microseconds
      );
      if (cache_result != response_cache_result::stored && cache_result != response_cache_result::hit) {
        transport_.close(connection.peer);
        return false;
      }
      const auto deadline = saturating_add(now_microseconds, response_deadline_microseconds);
      if (connection.outbound.reserve(
            connection.next_message_id,
            response,
            deadline
          ) != outbound_store_result::stored) {
        transport_.close(connection.peer);
        return false;
      }
      const auto message_id = connection.next_message_id++;
      if (!transport_.send(connection.peer, response)) {
        return false;
      }
      return connection.outbound.mark_initial_submitted(message_id, now_microseconds, connection.rto) ==
             outbound_submission_result::submitted;
    }

    /** @brief Send one untracked ACK-only LSPC frame confirming receipt of accepted client control. */
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

    /** @brief Retain and send the next contiguous outgoing artwork chunk. */
    bool send_next_object_chunk(Connection &connection, const std::uint64_t now_microseconds) noexcept {
      try {
        if (connection.outgoing_object_pending) {
          return true;
        }
        while (connection.outgoing_object_index < connection.outgoing_objects.size() &&
               connection.outgoing_object_offset >= connection.outgoing_objects[connection.outgoing_object_index].bytes.size()) {
          ++connection.outgoing_object_index;
          connection.outgoing_object_offset = 0;
        }
        if (connection.outgoing_object_index >= connection.outgoing_objects.size()) {
          connection.outgoing_objects.clear();
          connection.outgoing_object_index = 0;
          if (connection.outbound_clipboard.awaiting_object) {
            connection.outbound_clipboard.awaiting_object = false;
            return send_clipboard_request(connection, now_microseconds);
          }
          return true;
        }
        auto &object = connection.outgoing_objects[connection.outgoing_object_index];
        const auto remaining = object.bytes.size() - connection.outgoing_object_offset;
        const auto chunk_bytes = std::min(remaining, maximum_object_chunk_bytes);
        ObjectChunkPayload chunk {
          .object_id = object.object_id,
          .offset = connection.outgoing_object_offset,
          .total_length = static_cast<std::uint32_t>(object.bytes.size()),
          .bytes = std::vector<std::uint8_t> {
            object.bytes.begin() + static_cast<std::ptrdiff_t>(connection.outgoing_object_offset),
            object.bytes.begin() + static_cast<std::ptrdiff_t>(connection.outgoing_object_offset + chunk_bytes),
          },
          .sha256 = object.sha256,
        };
        const auto payload = encode_object_chunk(chunk);
        std::array<std::uint8_t, 8> request_bytes {};
        if (!payload || connection.next_message_id == 0 || !crypto_.random(request_bytes)) {
          return false;
        }
        auto request_id = wire::read_be<std::uint64_t>(request_bytes);
        if (request_id == 0) {
          request_id = 1;
        }
        std::array<std::uint8_t, maximum_control_frame_bytes> storage {};
        const lspc_header header {
          .flags = static_cast<std::uint8_t>(lspc_flag::acknowledgement_required),
          .message_type = static_cast<std::uint16_t>(ControlMessageType::object_chunk),
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
        const auto frame = std::span<const std::uint8_t> {storage}.first(serialized.bytes_written);
        const auto deadline = saturating_add(now_microseconds, response_deadline_microseconds);
        if (connection.outbound.reserve(connection.next_message_id, frame, deadline) != outbound_store_result::stored) {
          return false;
        }
        connection.outgoing_object_request_id = request_id;
        connection.outgoing_object_message_id = connection.next_message_id;
        connection.outgoing_object_pending = true;
        const auto message_id = connection.next_message_id++;
        if (!transport_.send(connection.peer, frame)) {
          return false;
        }
        return connection.outbound.mark_initial_submitted(message_id, now_microseconds, connection.rto) ==
               outbound_submission_result::submitted;
      } catch (...) {
        return false;
      }
    }

    /** @brief Validate one exact response-flagged artwork prefix acknowledgement. */
    bool object_chunk_acknowledgement(
      Connection &connection,
      const std::span<const std::uint8_t> frame,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      const auto accepted_duplicate = std::ranges::find_if(connection.accepted_object_acks, [&](const Connection::AcceptedObjectAck &accepted) {
        return accepted.size == frame.size() && accepted.request_id == header.request_id &&
               std::ranges::equal(std::span<const std::uint8_t> {accepted.frame}.first(accepted.size), frame);
      });
      const auto observed = connection.inbound.observe(header.message_id);
      if (observed != receive_id_result::accepted) {
        return accepted_duplicate != connection.accepted_object_acks.end() && send_acknowledgement_only(connection);
      }
      if (!connection.authenticated_client || !connection.outgoing_object_pending ||
          header.request_id != connection.outgoing_object_request_id ||
          connection.outgoing_object_index >= connection.outgoing_objects.size()) {
        return false;
      }
      if (has_flag(header.flags, lspc_flag::error_response)) {
        const auto error = decode_control_error(payload);
        if (!error || *error == ControlStatus::success) {
          return false;
        }
        (void) connection.outbound.acknowledge(
          connection.outgoing_object_message_id,
          0,
          now_microseconds,
          connection.rto
        );
        connection.outgoing_objects.clear();
        connection.outgoing_object_index = 0;
        connection.outgoing_object_offset = 0;
        connection.outgoing_object_pending = false;
        if (!send_acknowledgement_only(connection)) {
          return false;
        }
        return !connection.outbound_clipboard.awaiting_object || finish_clipboard(connection, now_microseconds);
      }
      const auto acknowledgement = decode_object_chunk_ack(payload);
      const auto &object = connection.outgoing_objects[connection.outgoing_object_index];
      if (!acknowledgement || acknowledgement->status != ControlStatus::success ||
          acknowledgement->object_id != object.object_id ||
          acknowledgement->total_length != object.bytes.size() ||
          acknowledgement->next_offset <= connection.outgoing_object_offset ||
          acknowledgement->next_offset > object.bytes.size()) {
        return false;
      }
      (void) connection.outbound.acknowledge(
        connection.outgoing_object_message_id,
        0,
        now_microseconds,
        connection.rto
      );
      auto &accepted = connection.accepted_object_acks[connection.next_object_ack_slot];
      accepted.request_id = header.request_id;
      accepted.size = frame.size();
      std::copy(frame.begin(), frame.end(), accepted.frame.begin());
      connection.next_object_ack_slot = (connection.next_object_ack_slot + 1U) % connection.accepted_object_acks.size();
      connection.outgoing_object_offset = acknowledgement->next_offset;
      connection.outgoing_object_pending = false;
      if (!send_acknowledgement_only(connection)) {
        return false;
      }
      return send_next_object_chunk(connection, now_microseconds);
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
      const auto deadline = saturating_add(now_microseconds, response_deadline_microseconds);
      if (connection.outbound.reserve(
            connection.next_message_id,
            frame,
            deadline
          ) != outbound_store_result::stored) {
        return false;
      }
      connection.pending_video = {
        .session_id = configuration.session_id,
        .video_generation = configuration.video.video_generation,
        .request_id = request_id,
        .message_id = connection.next_message_id,
        .deadline_microseconds = deadline,
        .active = true,
      };
      const auto message_id = connection.next_message_id++;
      if (!transport_.send(connection.peer, frame)) {
        return false;
      }
      return connection.outbound.mark_initial_submitted(message_id, now_microseconds, connection.rto) ==
             outbound_submission_result::submitted;
    }

    /** @brief Validate, receipt-ack, and defer one idempotent VIDEO_CONFIG_ACK response. */
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
      const auto pending_duplicate = connection.pending_video_activation.active &&
                                     connection.pending_video.request_id == header.request_id &&
                                     connection.pending_video_activation.frame.bytes().size() == frame.size() &&
                                     std::ranges::equal(connection.pending_video_activation.frame.bytes(), frame);
      const auto observed = connection.inbound.observe(header.message_id);
      if (observed != receive_id_result::accepted) {
        if (accepted_duplicate != connection.accepted_video_acks.end() || pending_duplicate) {
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
          connection.pending_video_activation.active) {
        transport_.close(connection.peer);
        return false;
      }
      auto &pending = connection.pending_video_activation;
      pending = {};
      if (!pending.frame.assign(frame)) {
        transport_.close(connection.peer);
        return false;
      }
      pending.acknowledgement = *acknowledgement;
      pending.deadline_microseconds = connection.pending_video.deadline_microseconds;
      pending.active = true;
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
      const auto deadline = saturating_add(now_microseconds, response_deadline_microseconds);
      if (connection.outbound.reserve(
            connection.next_message_id,
            frame,
            deadline
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
      const auto message_id = connection.next_message_id++;
      if (!transport_.send(peer, frame)) {
        return false;
      }
      return connection.outbound.mark_initial_submitted(message_id, now_microseconds, connection.rto) ==
             outbound_submission_result::submitted;
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
      (void) connection.outbound.acknowledge(
        connection.outbound_path_probe.message_id,
        0,
        now_microseconds,
        connection.rto
      );
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
      const auto deadline = saturating_add(now_microseconds, response_deadline_microseconds);
      if (connection.outbound.reserve(
            connection.next_message_id,
            frame,
            deadline
          ) != outbound_store_result::stored) {
        return false;
      }
      connection.pending_audio = {
        .payload = configuration,
        .request_id = request_id,
        .message_id = connection.next_message_id,
        .deadline_microseconds = deadline,
        .active = true,
      };
      const auto message_id = connection.next_message_id++;
      if (!transport_.send(connection.peer, frame)) {
        return false;
      }
      return connection.outbound.mark_initial_submitted(message_id, now_microseconds, connection.rto) ==
             outbound_submission_result::submitted;
    }

    /**
     * @brief Validate, receipt-ack, and defer one idempotent AUDIO_CONFIG_ACK response.
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
      const auto pending_duplicate = connection.pending_audio_activation.active &&
                                     connection.pending_audio.request_id == header.request_id &&
                                     connection.pending_audio_activation.frame.bytes().size() == frame.size() &&
                                     std::ranges::equal(connection.pending_audio_activation.frame.bytes(), frame);
      const auto observed = connection.inbound.observe(header.message_id);
      if (observed != receive_id_result::accepted) {
        if (accepted_duplicate != connection.accepted_audio_acks.end() || pending_duplicate) {
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
          connection.pending_audio_activation.active) {
        transport_.close(connection.peer);
        return false;
      }
      auto &pending = connection.pending_audio_activation;
      pending = {};
      if (!pending.frame.assign(frame)) {
        transport_.close(connection.peer);
        return false;
      }
      pending.acknowledgement = *acknowledgement;
      pending.deadline_microseconds = connection.pending_audio.deadline_microseconds;
      pending.active = true;
      return send_acknowledgement_only(connection);
    }

    /** @brief Reliably send one server-originated MICROPHONE_CONFIG. */
    bool send_microphone_config(
      Connection &connection,
      const MicrophoneConfigPayload &configuration,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (connection.pending_microphone_activation.active) {
        return connection.pending_microphone_activation.acknowledgement.session_id == configuration.session_id &&
               connection.pending_microphone_activation.acknowledgement.microphone_generation ==
                 configuration.microphone.microphone_generation;
      }
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
      const auto deadline = saturating_add(now_microseconds, response_deadline_microseconds);
      if (connection.outbound.reserve(
            connection.next_message_id,
            frame,
            deadline
          ) != outbound_store_result::stored) {
        return false;
      }
      connection.pending_microphone = {
        .payload = configuration,
        .request_id = request_id,
        .message_id = connection.next_message_id,
        .deadline_microseconds = deadline,
        .active = true,
      };
      const auto message_id = connection.next_message_id++;
      if (!transport_.send(connection.peer, frame)) {
        return false;
      }
      return connection.outbound.mark_initial_submitted(message_id, now_microseconds, connection.rto) ==
             outbound_submission_result::submitted;
    }

    /** @brief Validate and commit one idempotent MICROPHONE_CONFIG_ACK response. */
    bool microphone_config_ack(
      Connection &connection,
      const std::span<const std::uint8_t> frame,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
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
          connection.pending_microphone_activation.active) {
        transport_.close(connection.peer);
        return false;
      }
      (void) connection.outbound.acknowledge(
        connection.pending_microphone.message_id,
        0,
        now_microseconds,
        connection.rto
      );
      connection.pending_microphone.active = false;
      auto &accepted = connection.accepted_microphone_acks[connection.next_microphone_ack_slot];
      accepted.request_id = header.request_id;
      std::ranges::copy(frame, accepted.frame.begin());
      accepted.size = frame.size();
      connection.next_microphone_ack_slot = (connection.next_microphone_ack_slot + 1U) % connection.accepted_microphone_acks.size();
      connection.pending_microphone_activation = {
        .acknowledgement = *acknowledgement,
        .deadline_microseconds = connection.pending_microphone.deadline_microseconds,
        .active = true,
      };
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
      if (pairing_suspended_) {
        return send_error(connection, request, header, ControlMessageType::pair_pending, ControlStatus::busy, now_microseconds);
      }
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
        pairing.frozen_revocation_generation = existing ? existing->revocation_generation : 0;
        pairing.recovering_existing_trust = existing.has_value();
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
      const auto current_trust = trust_store_.find(pairing->client_id);
      const auto trust_snapshot_matches = pairing->recovering_existing_trust ?
                                            current_trust && current_trust->enabled &&
                                              current_trust->identity_key == pairing->client_identity_key &&
                                              current_trust->permissions == pairing->effective_permissions &&
                                              current_trust->revocation_generation == pairing->frozen_revocation_generation :
                                            !current_trust;
      if (!trust_snapshot_matches) {
        const auto pairing_index = static_cast<std::size_t>(std::distance(pairings_.begin(), pairing));
        clear_pairing(pairings_[pairing_index]);
        pairings_.erase(pairings_.begin() + static_cast<std::ptrdiff_t>(pairing_index));
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

    /** @brief Emit the canonical authenticated application catalog and queue its artwork. */
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
      std::vector<std::uint8_t> response;
      try {
        auto encoded = encode_applications(*snapshot);
        if (!encoded) {
          const auto status = encoded.error() == ControlWireError::size_limit ?
                                ControlStatus::busy :
                                ControlStatus::internal_failure;
          return send_error(connection, request, header, ControlMessageType::applications, status, now_microseconds);
        }
        response = std::move(*encoded);
      } catch (...) {
        return send_error(connection, request, header, ControlMessageType::applications, ControlStatus::internal_failure, now_microseconds);
      }
      if (!send_response(connection, request, header, ControlMessageType::applications, response, false, now_microseconds)) {
        return false;
      }
      const auto artwork = applications_.artwork_snapshot();
      if (!artwork) {
        return false;
      }
      try {
        connection.outgoing_objects = *artwork;
        if (connection.outbound_clipboard.awaiting_object) {
          connection.outgoing_objects.push_back({
            .object_id = connection.outbound_clipboard.object_id,
            .sha256 = connection.outbound_clipboard.sha256,
            .bytes = connection.outbound_clipboard.utf8,
          });
        }
      } catch (...) {
        return false;
      }
      connection.outgoing_object_index = 0;
      connection.outgoing_object_offset = 0;
      connection.outgoing_object_pending = false;
      return send_next_object_chunk(connection, now_microseconds);
    }

    /** @brief Validate and execute one session-owned application quit request. */
    bool quit_application(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (!connection.authenticated_client ||
          !connection.authenticated_client->permissions.contains(Permission::quit_application)) {
        return send_error(
          connection,
          request,
          header,
          ControlMessageType::quit_application_response,
          ControlStatus::permission_denied,
          now_microseconds
        );
      }
      const auto decoded = decode_quit_application(payload);
      if (!decoded) {
        return send_error(connection, request, header, ControlMessageType::quit_application_response, ControlStatus::malformed, now_microseconds);
      }
      const auto status = start_handler_.quit_application(
        *connection.authenticated_client,
        connection.generation,
        *decoded
      );
      const auto response = encode_quit_application_response({
        .status = status,
        .session_id = decoded->session_id,
      });
      return response && send_response(
                           connection,
                           request,
                           header,
                           ControlMessageType::quit_application_response,
                           *response,
                           status != ControlStatus::success,
                           now_microseconds
                         );
    }

    /** @brief Resolve inline/object UTF-8 and execute one edge-barrier-bound text commit. */
    bool text_input(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (!connection.authenticated_client ||
          !connection.authenticated_client->permissions.contains(Permission::input)) {
        return send_error(connection, request, header, ControlMessageType::text_input_response, ControlStatus::permission_denied, now_microseconds);
      }
      const auto decoded = decode_text_input(payload);
      if (!decoded) {
        return send_error(connection, request, header, ControlMessageType::text_input_response, ControlStatus::malformed, now_microseconds);
      }
      if (connection.pending_text.active || text_work_.size() >= maximum_connections_) {
        return send_error(connection, request, header, ControlMessageType::text_input_response, ControlStatus::busy, now_microseconds);
      }
      std::span<const std::uint8_t> utf8 = decoded->inline_utf8;
      if (decoded->object_id) {
        const auto found = std::ranges::find(connection.incoming_objects, *decoded->object_id, &Connection::IncomingObject::object_id);
        if (found == connection.incoming_objects.end() || !found->complete || !decoded->sha256 ||
            found->sha256 != *decoded->sha256 || found->bytes.size() != decoded->utf8_length) {
          return send_error(connection, request, header, ControlMessageType::text_input_response, ControlStatus::stale_generation, now_microseconds);
        }
        utf8 = found->bytes;
      }
      try {
        Digest256 request_digest {};
        if (!crypto_.sha256(request, request_digest)) {
          return send_error(connection, request, header, ControlMessageType::text_input_response, ControlStatus::internal_failure, now_microseconds);
        }
        TextWork work {
          .peer = connection.peer,
          .client = *connection.authenticated_client,
          .connection_generation = connection.generation,
          .request = *decoded,
          .utf8 = std::vector<std::uint8_t> {utf8.begin(), utf8.end()},
          .deadline_microseconds = saturating_add(now_microseconds, response_deadline_microseconds),
          .request_id = header.request_id,
          .message_id = header.message_id,
          .request_digest = request_digest,
        };
        connection.pending_text.request.assign(request);
        connection.pending_text.header = header;
        connection.pending_text.active = true;
        text_work_.push_back(std::move(work));
      } catch (...) {
        connection.pending_text = {};
        return send_error(connection, request, header, ControlMessageType::text_input_response, ControlStatus::busy, now_microseconds);
      }
      text_condition_.notify_one();
      return true;
    }

    /**
     * @brief Receipt-ACK one authenticated rate request before acquiring the platform input lock.
     *
     * The UDP owner flushes this ACK after the DTLS callback returns and before calling tick().
     * The ACK confirms receipt only; the deferred response still validates and selects the offer.
     *
     * @param connection Authenticated association retaining the pending request.
     * @param request Complete byte-identical request retained for duplicate handling and response caching.
     * @param header Parsed request identity and generation.
     * @param now_microseconds Current receipt time used for immediate admission errors.
     * @return True when the receipt ACK or bounded error response was queued.
     */
    bool queue_input_rate(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &header,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (!connection.authenticated_client ||
          !connection.authenticated_client->permissions.contains(Permission::input)) {
        return send_error(connection, request, header, ControlMessageType::input_rate_response, ControlStatus::permission_denied, now_microseconds);
      }
      if (connection.pending_input_rate.active) {
        return send_error(connection, request, header, ControlMessageType::input_rate_response, ControlStatus::busy, now_microseconds);
      }
      if (!connection.pending_input_rate.request.assign(request)) {
        return send_error(connection, request, header, ControlMessageType::input_rate_response, ControlStatus::internal_failure, now_microseconds);
      }
      connection.pending_input_rate.header = header;
      connection.pending_input_rate.active = true;
      return send_acknowledgement_only(connection);
    }

    /**
     * @brief Validate and execute one receipt-ACKed generation-scoped device rate offer.
     *
     * @param connection Association whose current input authority must still match the offer.
     * @param request Retained request bytes used for exact response caching.
     * @param header Original request correlation and generation.
     * @param payload Encoded rate offer validated before applying any change.
     * @param now_microseconds Dispatch time used for errors before backend work.
     * @return True when the selected rates or semantic error response was queued.
     */
    bool input_rate(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (!connection.authenticated_client ||
          !connection.authenticated_client->permissions.contains(Permission::input)) {
        return send_error(connection, request, header, ControlMessageType::input_rate_response, ControlStatus::permission_denied, now_microseconds);
      }
      const auto decoded = decode_input_rate_request(payload);
      if (!decoded) {
        return send_error(connection, request, header, ControlMessageType::input_rate_response, ControlStatus::malformed, now_microseconds);
      }
      const auto selected = start_handler_.input_rate(
        connection.peer,
        *connection.authenticated_client,
        connection.generation,
        *decoded
      );
      // Lock acquisition and selection must not consume the response's retransmission lifetime.
      const auto response_now = control_monotonic_microseconds();
      if (!selected) {
        return send_error(connection, request, header, ControlMessageType::input_rate_response, selected.error(), response_now);
      }
      const auto response = encode_input_rate_response(*selected);
      return response && send_response(connection, request, header, ControlMessageType::input_rate_response, *response, false, response_now);
    }

    /** @brief Resolve an inline/object bundle and hand one client clipboard update to the product. */
    bool clipboard_update(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (!connection.authenticated_client ||
          !connection.authenticated_client->permissions.contains(Permission::clipboard)) {
        return send_error(connection, request, header, ControlMessageType::clipboard_update_response, ControlStatus::permission_denied, now_microseconds);
      }
      const auto decoded = decode_clipboard_update(payload);
      if (!decoded) {
        return send_error(connection, request, header, ControlMessageType::clipboard_update_response, ControlStatus::malformed, now_microseconds);
      }
      std::span<const std::uint8_t> utf8 = decoded->inline_content;
      auto object = connection.incoming_objects.end();
      if (decoded->object_id) {
        object = std::ranges::find(connection.incoming_objects, *decoded->object_id, &Connection::IncomingObject::object_id);
        if (object == connection.incoming_objects.end() || !object->complete || !decoded->sha256 ||
            object->sha256 != *decoded->sha256 || object->bytes.size() != decoded->content_length) {
          return send_error(connection, request, header, ControlMessageType::clipboard_update_response, ControlStatus::stale_generation, now_microseconds);
        }
        utf8 = object->bytes;
      }
      auto status = valid_clipboard_bundle(utf8) ?
                      start_handler_.clipboard_update(
                        connection.peer,
                        *connection.authenticated_client,
                        connection.generation,
                        *decoded,
                        utf8
                      ) :
                      ControlStatus::malformed;
      if (object != connection.incoming_objects.end()) {
        connection.buffered_object_bytes -= object->total_length;
        connection.incoming_objects.erase(object);
      }
      if (status != ControlStatus::success) {
        return send_error(connection, request, header, ControlMessageType::clipboard_update_response, status, now_microseconds);
      }
      const auto response = encode_clipboard_update_response({
        .status = ControlStatus::success,
        .session_id = decoded->session_id,
        .sequence = decoded->sequence,
      });
      return response && send_response(
                           connection,
                           request,
                           header,
                           ControlMessageType::clipboard_update_response,
                           *response,
                           false,
                           now_microseconds
                         );
    }

    /** @brief Begin delivering one host clipboard text, inline or after its object transfer. */
    bool start_clipboard(
      Connection &connection,
      const Identifier128 &session_id,
      std::vector<std::uint8_t> utf8,
      const std::uint64_t now_microseconds
    ) noexcept {
      try {
        auto &outbound = connection.outbound_clipboard;
        outbound = {};
        outbound.session_id = session_id;
        outbound.sequence = connection.next_clipboard_sequence++;
        outbound.utf8 = std::move(utf8);
        if (outbound.utf8.size() <= maximum_inline_clipboard_bytes) {
          return send_clipboard_request(connection, now_microseconds);
        }
        if (!crypto_.random(outbound.object_id) || is_zero(outbound.object_id) ||
            !crypto_.sha256(outbound.utf8, outbound.sha256)) {
          outbound = {};
          return false;
        }
        connection.outgoing_objects.push_back({
          .object_id = outbound.object_id,
          .sha256 = outbound.sha256,
          .bytes = outbound.utf8,
        });
        outbound.awaiting_object = true;
        return send_next_object_chunk(connection, now_microseconds);
      } catch (...) {
        connection.outbound_clipboard = {};
        return false;
      }
    }

    /** @brief Reliably send the CLIPBOARD_UPDATE request for the current outbound text. */
    bool send_clipboard_request(Connection &connection, const std::uint64_t now_microseconds) noexcept {
      auto &outbound = connection.outbound_clipboard;
      ClipboardUpdatePayload update {
        .session_id = outbound.session_id,
        .sequence = outbound.sequence,
        .content_length = static_cast<std::uint32_t>(outbound.utf8.size()),
      };
      try {
        if (outbound.utf8.size() <= maximum_inline_clipboard_bytes) {
          update.inline_content = outbound.utf8;
        } else {
          update.object_id = outbound.object_id;
          update.sha256 = outbound.sha256;
        }
      } catch (...) {
        return false;
      }
      const auto payload = encode_clipboard_update(update);
      std::array<std::uint8_t, 8> request_bytes {};
      if (!payload || connection.next_message_id == 0 || !crypto_.random(request_bytes)) {
        return false;
      }
      auto request_id = wire::read_be<std::uint64_t>(request_bytes);
      if (request_id == 0) {
        request_id = 1;
      }
      std::array<std::uint8_t, maximum_control_frame_bytes> storage {};
      const lspc_header header {
        .flags = static_cast<std::uint8_t>(lspc_flag::acknowledgement_required),
        .message_type = static_cast<std::uint16_t>(ControlMessageType::clipboard_update),
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
      const auto frame = std::span<const std::uint8_t> {storage}.first(serialized.bytes_written);
      const auto deadline = saturating_add(now_microseconds, response_deadline_microseconds);
      if (connection.outbound.reserve(connection.next_message_id, frame, deadline) != outbound_store_result::stored) {
        return false;
      }
      outbound.request_id = request_id;
      outbound.message_id = connection.next_message_id;
      outbound.deadline_microseconds = saturating_add(now_microseconds, clipboard_response_deadline_microseconds);
      outbound.awaiting_response = true;
      const auto message_id = connection.next_message_id++;
      if (!transport_.send(connection.peer, frame)) {
        return false;
      }
      return connection.outbound.mark_initial_submitted(message_id, now_microseconds, connection.rto) ==
             outbound_submission_result::submitted;
    }

    /** @brief Retire the current outbound clipboard update and start the newest queued text. */
    bool finish_clipboard(Connection &connection, const std::uint64_t now_microseconds) noexcept {
      connection.outbound_clipboard = {};
      if (!connection.queued_clipboard.active) {
        return true;
      }
      auto queued = std::move(connection.queued_clipboard);
      connection.queued_clipboard = {};
      return start_clipboard(connection, queued.session_id, std::move(queued.utf8), now_microseconds);
    }

    /** @brief Validate one client response to the in-flight host clipboard update. */
    bool clipboard_update_response(
      Connection &connection,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      const auto observed = connection.inbound.observe(header.message_id);
      if (observed != receive_id_result::accepted) {
        return header.request_id == connection.completed_clipboard_request_id && send_acknowledgement_only(connection);
      }
      auto &outbound = connection.outbound_clipboard;
      if (!outbound.awaiting_response || header.request_id != outbound.request_id) {
        // A response that arrives after the semantic deadline only needs receipt confirmation.
        return send_acknowledgement_only(connection);
      }
      if (has_flag(header.flags, lspc_flag::error_response)) {
        const auto error = decode_control_error(payload);
        if (!error || *error == ControlStatus::success) {
          return false;
        }
      } else {
        const auto response = decode_clipboard_update_response(payload);
        if (!response || response->session_id != outbound.session_id || response->sequence != outbound.sequence) {
          return false;
        }
      }
      (void) connection.outbound.acknowledge(outbound.message_id, 0, now_microseconds, connection.rto);
      connection.completed_clipboard_request_id = header.request_id;
      if (!send_acknowledgement_only(connection)) {
        return false;
      }
      return finish_clipboard(connection, now_microseconds);
    }

    /** @brief Append one authenticated contiguous object chunk and cache its terminal prefix. */
    bool object_chunk(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (!connection.authenticated_client ||
          (!connection.authenticated_client->permissions.contains(Permission::input) &&
           !connection.authenticated_client->permissions.contains(Permission::clipboard))) {
        return send_error(connection, request, header, ControlMessageType::object_chunk, ControlStatus::permission_denied, now_microseconds);
      }
      const auto decoded = decode_object_chunk(payload);
      if (!decoded) {
        return send_error(connection, request, header, ControlMessageType::object_chunk, ControlStatus::malformed, now_microseconds);
      }
      auto found = std::ranges::find(connection.incoming_objects, decoded->object_id, &Connection::IncomingObject::object_id);
      ControlStatus status = ControlStatus::success;
      std::uint32_t next_offset = decoded->offset;
      if (found == connection.incoming_objects.end()) {
        if (decoded->offset != 0 || connection.incoming_objects.size() >= maximum_incoming_objects ||
            decoded->total_length > maximum_buffered_object_bytes - connection.buffered_object_bytes) {
          status = decoded->offset == 0 ? ControlStatus::busy : ControlStatus::stale_generation;
        } else {
          try {
            Connection::IncomingObject object {
              .object_id = decoded->object_id,
              .total_length = decoded->total_length,
              .sha256 = decoded->sha256,
            };
            object.bytes.reserve(decoded->total_length);
            connection.incoming_objects.push_back(std::move(object));
            connection.buffered_object_bytes += decoded->total_length;
            found = std::prev(connection.incoming_objects.end());
          } catch (...) {
            status = ControlStatus::busy;
          }
        }
      }
      if (status == ControlStatus::success && found != connection.incoming_objects.end()) {
        if (found->complete) {
          next_offset = found->total_length;
        } else if (found->total_length != decoded->total_length || found->sha256 != decoded->sha256 ||
                   found->bytes.size() != decoded->offset) {
          status = ControlStatus::stale_generation;
          connection.buffered_object_bytes -= found->total_length;
          connection.incoming_objects.erase(found);
        } else {
          try {
            found->bytes.insert(found->bytes.end(), decoded->bytes.begin(), decoded->bytes.end());
            next_offset = static_cast<std::uint32_t>(found->bytes.size());
          } catch (...) {
            status = ControlStatus::busy;
          }
          if (status == ControlStatus::success && next_offset == found->total_length) {
            Digest256 digest;
            if (!crypto_.sha256(found->bytes, digest) || digest != found->sha256) {
              status = ControlStatus::authentication_failed;
              connection.buffered_object_bytes -= found->total_length;
              connection.incoming_objects.erase(found);
            } else {
              found->complete = true;
            }
          }
        }
      }
      const auto response = encode_object_chunk_ack({
        .status = status,
        .object_id = decoded->object_id,
        .next_offset = next_offset,
        .total_length = decoded->total_length,
      });
      return response && send_response(
                           connection,
                           request,
                           header,
                           ControlMessageType::object_chunk,
                           *response,
                           status != ControlStatus::success,
                           now_microseconds
                         );
    }

    /**
     * @brief Acknowledge START before dispatching slow capture preparation from tick().
     * @param connection Authenticated association receiving the request.
     * @param request Complete validated LSPC frame retained for idempotent response caching.
     * @param header Parsed request correlation fields.
     * @param now_microseconds Monotonic receipt time for immediate error responses.
     * @return Whether the ACK or rejection was accepted by the transport.
     */
    bool queue_start(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &header,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (!connection.authenticated_client ||
          !connection.authenticated_client->permissions.contains(Permission::start_attach) ||
          !connection.authenticated_client->permissions.contains(Permission::input)) {
        return send_error(connection, request, header, ControlMessageType::start_response, ControlStatus::permission_denied, now_microseconds);
      }
      if (connection.pending_start.active) {
        return send_error(connection, request, header, ControlMessageType::start_response, ControlStatus::busy, now_microseconds);
      }
      if (!connection.pending_start.request.assign(request)) {
        return false;
      }
      connection.pending_start.header = header;
      connection.pending_start.active = true;
      return send_acknowledgement_only(connection);
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
      const auto response_time = control_monotonic_microseconds();
      if (!response || !send_response(connection, request, header, ControlMessageType::start_response, *response, false, response_time)) {
        return false;
      }
      const auto video_configuration = start_handler_.video_configuration(
        selected->session_id,
        selected->video.video_generation
      );
      if (video_configuration == nullptr || !send_video_config(connection, *video_configuration, response_time)) {
        return false;
      }
      if (!send_audio_config(
            connection,
            AudioConfigPayload {
              .session_id = selected->session_id,
              .stream_generation = selected->stream_generation,
              .audio = selected->audio,
            },
            response_time
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
                                        response_time
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
    std::vector<TextWork> text_work_;  ///< At most one queued text operation per connection.
    std::array<CompletedPairing, 4> completed_pairings_ {};  ///< Lost-result replay independent of request-ID caching.
    std::size_t next_completed_pairing_slot_ {};  ///< Next fixed replay-cache slot.
    std::size_t maximum_connections_ {};  ///< Configured association bound.
    std::uint32_t next_generation_ {1};  ///< Next nonzero connection generation.
    bool ready_ {};  ///< Constructor validation and allocation status.
    bool pairing_suspended_ {};  ///< Administrative certificate rotation excludes PIN pairing.
    bool shutdown_started_ {};  ///< Whether asynchronous admission has permanently closed.
    bool shutdown_complete_ {};  ///< Whether workers and queued terminal responses are fully drained.
    mutable std::recursive_mutex mutex_;  ///< Synchronizes socket callbacks and low-rate administration.
    std::condition_variable_any shutdown_condition_;  ///< Wakes concurrent shutdown callers after full join.
    std::condition_variable_any pairing_condition_;  ///< Dedicated worker wakeup without socket/HTTP blocking.
    std::condition_variable_any text_condition_;  ///< Edge-barrier text worker wakeup.
    std::jthread pairing_worker_;  ///< Sole synchronous scrypt/SPAKE execution owner.
    std::jthread text_worker_;  ///< Sole asynchronous text barrier/platform injection owner.
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

  void HostControlServer::shutdown() noexcept {
    if (impl_) {
      impl_->shutdown();
    }
  }

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

  bool HostControlServer::update_trusted_client(
    const Identifier128 &client_id,
    const PermissionSet permissions,
    const bool enabled
  ) noexcept {
    return impl_ && impl_->update_trusted_client(client_id, permissions, enabled);
  }

  bool HostControlServer::revoke_trusted_client(const Identifier128 &client_id) noexcept {
    return impl_ && impl_->revoke_trusted_client(client_id);
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

  bool HostControlServer::send_stream_ended(
    const PeerEndpoint &peer,
    const StreamEndedPayload &ended,
    const std::uint64_t now_microseconds
  ) noexcept {
    return impl_ && impl_->send_stream_ended(peer, ended, now_microseconds);
  }

  bool HostControlServer::send_clipboard_update(
    const PeerEndpoint &peer,
    const Identifier128 &session_id,
    std::vector<std::uint8_t> utf8,
    const std::uint64_t now_microseconds
  ) noexcept {
    return impl_ && impl_->send_clipboard_update(peer, session_id, std::move(utf8), now_microseconds);
  }

  bool HostControlServer::start_certificate_rotation(
    const PeerEndpoint &peer,
    const Digest256 &new_spki_sha256,
    const std::uint32_t rotation_generation,
    const std::uint64_t now_microseconds
  ) noexcept {
    return impl_ && impl_->start_certificate_rotation(
                      peer,
                      new_spki_sha256,
                      rotation_generation,
                      now_microseconds
                    );
  }

  std::optional<std::vector<PeerEndpoint>> HostControlServer::authenticated_peers() const noexcept {
    return impl_ ? impl_->authenticated_peers() : std::nullopt;
  }

  std::optional<std::vector<PeerEndpoint>> HostControlServer::begin_certificate_rotation() noexcept {
    return impl_ ? impl_->begin_certificate_rotation() : std::nullopt;
  }

  void HostControlServer::end_certificate_rotation() noexcept {
    if (impl_) {
      impl_->end_certificate_rotation();
    }
  }

  CertificateRotationState HostControlServer::certificate_rotation_state(
    const PeerEndpoint &peer,
    const std::uint32_t rotation_generation
  ) const noexcept {
    return impl_ ?
             impl_->certificate_rotation_state(peer, rotation_generation) :
             CertificateRotationState::absent;
  }

  void HostControlServer::commit_certificate_rotation(const Digest256 &new_spki_sha256) noexcept {
    if (impl_) {
      impl_->commit_certificate_rotation(new_spki_sha256);
    }
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
