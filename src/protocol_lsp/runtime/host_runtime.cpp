/**
 * @file src/protocol_lsp/runtime/host_runtime.cpp
 * @brief Production LSP host runtime factory and lifecycle.
 */

#include "host_runtime.h"

#include "../core/rtp.h"
#include "../input_plane/feedback.h"
#include "../input_plane/rate.h"
#include "../media/frame_pipeline.h"
#include "../packet_classifier.h"
#include "../security/wolfssl_dtls_server.h"
#include "../service.h"
#include "../session_authority.h"
#include "../ssrc_registry.h"
#include "../transport/rtcp.h"
#include "audio_sender.h"
#include "control_server.h"
#include "host_forward_path.h"
#include "identity.h"
#include "input_owner.h"
#include "libsrtp_provider.h"
#include "microphone_receiver.h"
#include "udp_socket.h"
#include "video_sender.h"

#ifdef _WIN32
  #include "../../platform/windows/virtual_display.h"
  #include "../../platform/windows/virtual_display_frame.h"
  #include "../../platform/windows/virtual_microphone.h"
#endif

#ifndef LUMEN_LSP_RUNTIME_AVAILABLE
  #define LUMEN_LSP_RUNTIME_AVAILABLE 0
#endif

#if LUMEN_LSP_RUNTIME_AVAILABLE
  #include "../../config.h"
  #include "../../globals.h"
  #include "../../httpcommon.h"
  #include "../../process.h"

  #include <wolfssl/options.h>
  #include <wolfssl/wolfcrypt/ed25519.h>
  #include <wolfssl/wolfcrypt/hash.h>
  #include <wolfssl/wolfcrypt/random.h>
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <limits>
#include <mutex>
#include <new>
#include <ranges>
#include <string_view>
#include <thread>
#include <type_traits>

namespace platf::virtual_display {
  class session_lease_t;
}

namespace lumen::lsp::runtime {
  namespace {
    std::mutex runtime_registry_mutex;  ///< Protects the process administration pointer lifetime.
    HostRuntime *registered_runtime {};  ///< Active runtime exposed to the web administration layer.

    [[maybe_unused]] void register_runtime(HostRuntime *runtime) noexcept {
      std::scoped_lock lock(runtime_registry_mutex);
      registered_runtime = runtime;
    }

    [[maybe_unused]] void unregister_runtime(HostRuntime *runtime) noexcept {
      std::scoped_lock lock(runtime_registry_mutex);
      if (registered_runtime == runtime) {
        registered_runtime = nullptr;
      }
    }
  }  // namespace

#if LUMEN_LSP_RUNTIME_AVAILABLE
  namespace {
    constexpr std::size_t runtime_receive_batch = 64;
    constexpr std::uint32_t runtime_poll_milliseconds = 2;
    constexpr std::uint64_t invitation_lifetime_seconds = 10U * 60U;
    constexpr std::uint64_t attach_grace_microseconds = 10U * 1'000'000U;
    constexpr std::uint64_t attach_readiness_deadline_microseconds = 3U * 1'000'000U;
    constexpr std::array<std::uint8_t, 4> lspp_app_name {'L', 'S', 'P', 'P'};  ///< Exact path-probe APP name.

    /**
     * @brief Normalize an SSRC to a deterministic nonzero value outside a reserved set.
     *
     * @param candidate Random candidate, possibly zero or colliding.
     * @param reserved Already selected SSRCs.
     * @return Unique nonzero SSRC, or zero only when the bounded search is exhausted.
     */
    std::uint32_t next_unique_nonzero_ssrc(
      std::uint32_t candidate,
      const std::span<const std::uint32_t> reserved
    ) noexcept {
      if (candidate == 0) {
        candidate = 1;
      }
      for (std::size_t attempt = 0; attempt <= reserved.size(); ++attempt) {
        if (std::ranges::find(reserved, candidate) == reserved.end()) {
          return candidate;
        }
        candidate = candidate == std::numeric_limits<std::uint32_t>::max() ? 1U : candidate + 1U;
      }
      return 0;
    }

    std::string lowercase_hex(const std::span<const std::uint8_t> bytes) {
      constexpr std::string_view digits = "0123456789abcdef";
      std::string encoded(bytes.size() * 2, '0');
      for (std::size_t index = 0; index < bytes.size(); ++index) {
        encoded[index * 2] = digits[bytes[index] >> 4U];
        encoded[index * 2 + 1] = digits[bytes[index] & 0x0fU];
      }
      return encoded;
    }

    std::optional<std::uint8_t> hex_value(const char value) noexcept {
      if (value >= '0' && value <= '9') {
        return static_cast<std::uint8_t>(value - '0');
      }
      if (value >= 'a' && value <= 'f') {
        return static_cast<std::uint8_t>(value - 'a' + 10);
      }
      return std::nullopt;
    }

    template<std::size_t Size>
    bool decode_hex(const std::string_view encoded, std::array<std::uint8_t, Size> &output) noexcept {
      if (encoded.size() != Size * 2) {
        return false;
      }
      for (std::size_t index = 0; index < Size; ++index) {
        const auto high = hex_value(encoded[index * 2]);
        const auto low = hex_value(encoded[index * 2 + 1]);
        if (!high || !low) {
          return false;
        }
        output[index] = static_cast<std::uint8_t>((*high << 4U) | *low);
      }
      return true;
    }

    std::string capability_hex(const PermissionSet permissions) {
      constexpr std::string_view digits = "0123456789abcdef";
      std::string encoded(16, '0');
      auto value = static_cast<std::uint64_t>(permissions.mask());
      for (std::size_t index = encoded.size(); index > 0; --index) {
        encoded[index - 1] = digits[value & 0x0fU];
        value >>= 4U;
      }
      return encoded;
    }

    std::uint64_t utc_seconds() noexcept {
      return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                          std::chrono::system_clock::now().time_since_epoch()
      )
                                          .count());
    }

    class PersistentTrustStore final: public ControlTrustStore {
    public:
      explicit PersistentTrustStore(std::filesystem::path state_file):
          state_file_ {std::move(state_file)} {
      }

      std::optional<TrustedClient> find(const Identifier128 &client_id) noexcept override {
        try {
          if (is_zero(client_id) || !std::filesystem::exists(state_file_)) {
            return std::nullopt;
          }
          http::state_file_tree_t state;
          if (!http::read_state_file(state_file_.string(), state)) {
            return std::nullopt;
          }
          const auto base = "lsp.trusted_clients." + lowercase_hex(client_id);
          TrustedClient client {.client_id = client_id};
          const auto identity_key = state.get_optional<std::string>(base + ".identity_key");
          const auto permissions = state.get_optional<std::uint32_t>(base + ".permissions");
          const auto revocation = state.get_optional<std::uint32_t>(base + ".revocation_generation");
          const auto enabled = state.get_optional<bool>(base + ".enabled");
          if (!identity_key || !permissions || !revocation ||
              !decode_hex(*identity_key, client.identity_key)) {
            return std::nullopt;
          }
          const auto permission_set = PermissionSet::from_mask(*permissions);
          if (!permission_set) {
            return std::nullopt;
          }
          client.permissions = *permission_set;
          client.revocation_generation = *revocation;
          client.enabled = enabled.value_or(true);
          return client.valid() ? std::optional<TrustedClient> {client} : std::nullopt;
        } catch (...) {
          return std::nullopt;
        }
      }

      bool upsert(const TrustedClient &client) noexcept override {
        if (!client.valid()) {
          return false;
        }
        const auto base = "lsp.trusted_clients." + lowercase_hex(client.client_id);
        return http::update_state_file(state_file_.string(), [&](http::state_file_tree_t &state) {
          state.put(base + ".identity_key", lowercase_hex(client.identity_key));
          state.put(base + ".permissions", client.permissions.mask());
          state.put(base + ".revocation_generation", client.revocation_generation);
          state.put(base + ".enabled", client.enabled);
        });
      }

      std::vector<TrustedClientSummary> list() noexcept {
        std::vector<TrustedClientSummary> clients;
        try {
          if (!std::filesystem::exists(state_file_)) {
            return clients;
          }
          http::state_file_tree_t state;
          if (!http::read_state_file(state_file_.string(), state)) {
            return clients;
          }
          const auto records = state.get_child_optional("lsp.trusted_clients");
          if (!records) {
            return clients;
          }
          for (const auto &[encoded_id, record] : *records) {
            TrustedClientSummary client;
            const auto permissions = record.get_optional<std::uint32_t>("permissions");
            const auto revocation = record.get_optional<std::uint32_t>("revocation_generation");
            const auto enabled = record.get_optional<bool>("enabled");
            const auto permission_set = permissions ? PermissionSet::from_mask(*permissions) : std::nullopt;
            if (decode_hex(encoded_id, client.client_id) && permission_set && revocation && *revocation != 0) {
              client.permissions = *permission_set;
              client.revocation_generation = *revocation;
              client.enabled = enabled.value_or(true);
              clients.push_back(client);
            }
          }
          return clients;
        } catch (...) {
          return {};
        }
      }

      bool update_permissions(const Identifier128 &client_id, const PermissionSet permissions, const bool enabled) noexcept {
        auto client = find(client_id);
        if (!client || client->revocation_generation == std::numeric_limits<std::uint32_t>::max()) {
          return false;
        }
        client->permissions = permissions;
        client->enabled = enabled;
        ++client->revocation_generation;
        return upsert(*client);
      }

      bool revoke(const Identifier128 &client_id) noexcept {
        if (is_zero(client_id)) {
          return false;
        }
        bool removed = false;
        const auto encoded = lowercase_hex(client_id);
        const auto updated = http::update_state_file(state_file_.string(), [&](http::state_file_tree_t &state) {
          auto records = state.get_child_optional("lsp.trusted_clients");
          if (records) {
            removed = records->erase(encoded) != 0;
            state.put_child("lsp.trusted_clients", *records);
          }
        });
        return updated && removed;
      }

    private:
      std::filesystem::path state_file_;  ///< Shared product state file containing the distinct `lsp` subtree.
    };

    class ProcessApplicationProvider final: public ControlApplicationProvider {
    public:
      std::optional<std::vector<ControlApplication>> snapshot() noexcept override {
        try {
          std::vector<ControlApplication> applications;
          const auto &configured = proc::proc.get_apps();
          applications.reserve(configured.size());
          for (const auto &application : configured) {
            applications.push_back({
              .id = application.id,
              .name = application.name,
              .image_path = application.image_path,
            });
          }
          return applications;
        } catch (...) {
          return std::nullopt;
        }
      }
    };

    class WolfsslControlCrypto final: public ControlCrypto {
    public:
      explicit WolfsslControlCrypto(const HostIdentity &identity) noexcept {
        rng_ready_ = wc_InitRng(&rng_) == 0;
        key_ready_ = wc_ed25519_init(&host_key_) == 0;
        if (!rng_ready_ || !key_ready_ ||
            wc_ed25519_import_private_key(
              identity.application_private_key.data(),
              static_cast<word32>(identity.application_private_key.size()),
              identity.application_public_key.data(),
              static_cast<word32>(identity.application_public_key.size()),
              &host_key_
            ) != 0 ||
            wc_ed25519_check_key(&host_key_) != 0) {
          ready_ = false;
          return;
        }
        ready_ = true;
      }

      ~WolfsslControlCrypto() override {
        if (key_ready_) {
          wc_ed25519_free(&host_key_);
        }
        if (rng_ready_) {
          wc_FreeRng(&rng_);
        }
      }

      [[nodiscard]] bool ready() const noexcept {
        return ready_;
      }

      bool random(const std::span<std::uint8_t> output) noexcept override {
        return ready_ && !output.empty() && output.size() <= std::numeric_limits<word32>::max() &&
               wc_RNG_GenerateBlock(&rng_, output.data(), static_cast<word32>(output.size())) == 0;
      }

      bool sha256(const std::span<const std::uint8_t> input, Digest256 &digest) noexcept override {
        return input.size() <= std::numeric_limits<word32>::max() &&
               wc_Sha256Hash(input.data(), static_cast<word32>(input.size()), digest.data()) == 0;
      }

      bool sign(
        const std::span<const std::uint8_t> transcript,
        const std::span<std::uint8_t, ed25519_signature_size> signature
      ) noexcept override {
        word32 size = signature.size();
        return ready_ && transcript.size() <= std::numeric_limits<word32>::max() &&
               wc_ed25519_sign_msg(
                 transcript.data(),
                 static_cast<word32>(transcript.size()),
                 signature.data(),
                 &size,
                 &host_key_
               ) == 0 &&
               size == signature.size();
      }

      bool verify(
        const PublicKey256 &public_key,
        const std::span<const std::uint8_t> transcript,
        const std::span<const std::uint8_t, ed25519_signature_size> signature
      ) noexcept override {
        if (!ready_ || transcript.size() > std::numeric_limits<word32>::max()) {
          return false;
        }
        ed25519_key key {};
        if (wc_ed25519_init(&key) != 0) {
          return false;
        }
        const auto imported = wc_ed25519_import_public(
          public_key.data(),
          static_cast<word32>(public_key.size()),
          &key
        );
        int verified = 0;
        const auto status = imported == 0 ? wc_ed25519_verify_msg(
                                              signature.data(),
                                              static_cast<word32>(signature.size()),
                                              transcript.data(),
                                              static_cast<word32>(transcript.size()),
                                              &verified,
                                              &key
                                            ) :
                                            imported;
        wc_ed25519_free(&key);
        return status == 0 && verified == 1;
      }

      bool equal_secret(const Secret256 &left, const Secret256 &right) noexcept override {
        volatile std::uint8_t difference = 0;
        for (std::size_t index = 0; index < left.size(); ++index) {
          difference = static_cast<std::uint8_t>(difference | (left[index] ^ right[index]));
        }
        return difference == 0;
      }

    private:
      WC_RNG rng_ {};  ///< wolfCrypt random generator.
      ed25519_key host_key_ {};  ///< Imported host application identity key.
      bool rng_ready_ {};  ///< Whether the RNG must be freed.
      bool key_ready_ {};  ///< Whether the key must be freed.
      bool ready_ {};  ///< Complete crypto-boundary readiness.
    };

    bool valid_runtime_config(const HostRuntimeConfig &config) noexcept {
      return config.host.valid() && !config.identity_file.empty() && !config.state_file.empty() &&
             !config.host_name.empty() && config.host_name.size() <= 255;
    }

    /**
     * @brief Split bounded encoder initialization into exact prefix-free video codec units.
     *
     * @param initialization Annex-B H.264/HEVC initialization or one low-overhead AV1 OBU.
     * @param codec Negotiated codec that determines the exact required unit sequence.
     * @return Prefix-free SPS/PPS, VPS/SPS/PPS, or AV1 sequence header; otherwise no value.
     */
    std::optional<std::vector<std::vector<std::uint8_t>>> split_video_codec_units(
      const std::span<const std::uint8_t> initialization,
      const VideoCodec codec
    ) {
      if (codec == VideoCodec::av1) {
        return initialization.empty() || initialization.size() > 512U ?
                 std::nullopt :
                 std::optional {std::vector<std::vector<std::uint8_t>> {
                   {initialization.begin(), initialization.end()},
                 }};
      }
      const auto expected = codec == VideoCodec::h264 ? std::size_t {2} : std::size_t {3};
      std::vector<std::vector<std::uint8_t>> sets;
      sets.reserve(expected);
      auto find_prefix = [&](const std::size_t start) -> std::optional<std::pair<std::size_t, std::size_t>> {
        for (std::size_t index = start; index + 3U <= initialization.size(); ++index) {
          if (initialization[index] == 0 && initialization[index + 1U] == 0 && initialization[index + 2U] == 1U) {
            return std::pair {index, std::size_t {3}};
          }
          if (index + 4U <= initialization.size() && initialization[index] == 0 && initialization[index + 1U] == 0 &&
              initialization[index + 2U] == 0 && initialization[index + 3U] == 1U) {
            return std::pair {index, std::size_t {4}};
          }
        }
        return std::nullopt;
      };
      auto prefix = find_prefix(0);
      if (!prefix || prefix->first != 0) {
        return std::nullopt;
      }
      while (prefix) {
        const auto payload_start = prefix->first + prefix->second;
        const auto next = find_prefix(payload_start);
        const auto payload_end = next ? next->first : initialization.size();
        if (payload_start >= payload_end || payload_end - payload_start > 512U) {
          return std::nullopt;
        }
        sets.emplace_back(
          initialization.begin() + static_cast<std::ptrdiff_t>(payload_start),
          initialization.begin() + static_cast<std::ptrdiff_t>(payload_end)
        );
        prefix = next;
      }
      return sets.size() == expected ? std::optional {std::move(sets)} : std::nullopt;
    }

    /** @brief Parse the frozen 56-byte plaintext SRTCP APP `LSPV` status. */
    std::optional<transport::lspv_status> parse_lspv_status(
      const std::span<const std::uint8_t> packet,
      const std::uint32_t expected_sender_ssrc
    ) noexcept {
      if (packet.size() != 56U || packet[0] != 0x80U || packet[1] != 204U ||
          wire::read_be<std::uint16_t>(packet.subspan<2, 2>()) != 13U ||
          wire::read_be<std::uint32_t>(packet.subspan<4, 4>()) != expected_sender_ssrc ||
          !std::ranges::equal(transport::lspv_app_name, packet.subspan<8, 4>()) ||
          packet[12] != wire_version || (packet[13] & ~0x01U) != 0 || packet[14] > 3U ||
          packet[15] < 2U || packet[15] > 4U || packet[52] > packet[15] || packet[53] > 1U ||
          wire::read_be<std::uint16_t>(packet.subspan<54, 2>()) != 0) {
        return std::nullopt;
      }
      transport::lspv_status status {
        .session_generation = wire::read_be<std::uint32_t>(packet.subspan<16, 4>()),
        .video_generation = wire::read_be<std::uint32_t>(packet.subspan<20, 4>()),
        .recovery_epoch = wire::read_be<std::uint32_t>(packet.subspan<24, 4>()),
        .largest_complete_frame_id = wire::read_be<std::uint64_t>(packet.subspan<28, 8>()),
        .largest_decoded_frame_id = wire::read_be<std::uint64_t>(packet.subspan<36, 8>()),
        .largest_metal_committed_frame_id = wire::read_be<std::uint64_t>(packet.subspan<44, 8>()),
        .deadline_miss = (packet[13] & 0x01U) != 0,
        .decoder_status = static_cast<transport::lspv_decoder_status>(packet[14]),
        .decode_submissions_in_flight = packet[52],
        .maximum_decode_submissions = packet[15],
        .render_mailbox_occupancy = packet[53],
      };
      return transport::validate_lspv_status(status) == transport::lspv_status_error::none ?
               std::optional {status} :
               std::nullopt;
    }
  }  // namespace

  class ProductHostRuntime final:
      public HostRuntime,
      private ControlTransport,
      private ControlStartHandler,
      private InputNeutralizer,
      private AttachTokenVerifier {
  public:
    explicit ProductHostRuntime(HostRuntimeConfig config) noexcept:
        config_ {std::move(config)},
        authority_ {*this, this} {
    }

    ~ProductHostRuntime() override {
      stop();
    }

    RuntimeCreateStatus initialize() noexcept {
      auto identity = load_or_create_identity(config_.identity_file);
      if (!identity) {
        return RuntimeCreateStatus::identity_failed;
      }
      identity_ = std::move(*identity);
      crypto_ = std::make_unique<WolfsslControlCrypto>(identity_);
      trust_store_ = std::make_unique<PersistentTrustStore>(config_.state_file);
      applications_ = std::make_unique<ProcessApplicationProvider>();
      if (!crypto_ || !crypto_->ready() || !trust_store_ || !applications_) {
        return RuntimeCreateStatus::crypto_failed;
      }

      srtp_ = std::make_unique<LibsrtpServerProvider>(LibsrtpCallbacks {
        .context = this,
        .plaintext_packet = secure_packet_callback,
      });
      if (!srtp_ || !srtp_->ready(SrtpRequirements {})) {
        return RuntimeCreateStatus::srtp_failed;
      }
      input_owner_ = std::make_unique<InputOwner>(InputOwnerCallbacks {
                                                    .context = this,
                                                    .verify_digest = input_digest_callback,
                                                    .baseline_committed = input_baseline_callback,
                                                    .baseline_acknowledged = input_baseline_acknowledged_callback,
                                                  },
                                                  *srtp_);
      if (!input_owner_) {
        return RuntimeCreateStatus::allocation_failed;
      }

      dtls_ = std::make_unique<WolfsslDtlsServerProvider>(WolfsslDtlsServerConfig {
        .certificate_der = identity_.certificate_der,
        .private_key_der = identity_.private_key_der,
        .cookie_secret = identity_.cookie_secret,
        .maximum_associations = 64,
        .callbacks = {
          .context = this,
          .send_datagram = dtls_send_callback,
          .application_data = application_data_callback,
          .association_ready = association_ready_callback,
          .server_certificate = server_certificate_callback,
          .association_closed = association_closed_callback,
        },
      });
      if (!dtls_ || !dtls_->ready(DtlsRequirements {})) {
        return RuntimeCreateStatus::dtls_failed;
      }

      control_ = std::make_unique<HostControlServer>(
        identity_,
        dtls_->server_spki_sha256(),
        *trust_store_,
        *applications_,
        static_cast<ControlStartHandler &>(*this),
        *crypto_,
        static_cast<ControlTransport &>(*this)
      );
      if (!control_) {
        return RuntimeCreateStatus::control_failed;
      }
      service_ = std::make_unique<HostService>(config_.host, socket_, dtls_.get(), srtp_.get());
      return service_ ? RuntimeCreateStatus::ready : RuntimeCreateStatus::allocation_failed;
    }

    ServiceStartResult start() noexcept override {
      if (!service_) {
        return ServiceStartResult::dtls_provider_not_ready;
      }
      const auto result = service_->start();
      if (result != ServiceStartResult::started) {
        return result;
      }
      if (!create_pairing_invitation()) {
        service_->stop();
        return ServiceStartResult::dtls_provider_not_ready;
      }
      active_ = true;
      try {
        worker_ = std::jthread {[this](const std::stop_token stop_token) {
          run(stop_token);
        }};
      } catch (...) {
        active_ = false;
        service_->stop();
        return ServiceStartResult::socket_bind_failed;
      }
      register_runtime(this);
      return result;
    }

    void stop() noexcept override {
      unregister_runtime(this);
      active_ = false;
      worker_.request_stop();
      std::unique_ptr<ActiveAudioRuntime> audio;
      std::unique_ptr<ActiveVideoRuntime> video;
      std::unique_ptr<LspMicrophoneReceiver> microphone;
      {
        std::scoped_lock lock(session_mutex_);
        audio = std::move(audio_runtime_);
        video = std::move(video_runtime_);
        microphone = std::move(microphone_runtime_);
      }
      stop_audio_runtime(std::move(audio));
      stop_video_runtime(std::move(video));
      if (microphone) {
        microphone->shutdown();
      }
      process_pending_audio_retirements();
      process_pending_video_retirements();
      process_pending_microphone_retirements();
      retire_all_forward_paths();
      socket_.close();
      if (worker_.joinable()) {
        worker_.join();
      }
      if (service_) {
        service_->stop();
      }
      {
        std::scoped_lock lock(session_mutex_);
        if (authority_.snapshot().state != SessionState::ready) {
          (void) authority_.stop_from_host(NeutralizationReason::service_shutdown);
        }
        if (active_process_generation_ != 0) {
          (void) proc::proc.terminate_lsp_generation(active_process_generation_);
          active_process_generation_ = 0;
        }
        active_audio_configuration_.reset();
        active_video_configuration_.reset();
        pending_inbound_path_probe_ = {};
        active_microphone_configuration_.reset();
        active_microphone_required_ = false;
        clear_attach_lifecycle();
        clear_session_ssrc_history();
      }
      pairing_uri_.reset();
    }

    [[nodiscard]] bool active() const noexcept override {
      return active_;
    }

    std::optional<DiscoveryDescriptor> discovery() const override {
      if (!active_) {
        return std::nullopt;
      }
      return DiscoveryDescriptor {
        .type = std::string {discovery_service},
        .port = config_.host.port,
        .txt = {
          {"v", "1"},
          {"id", lowercase_hex(identity_.host_id)},
          {"caps", capability_hex(config_.host.pairing_permissions)},
        },
      };
    }

    std::optional<std::string> pairing_invitation_uri() const override {
      std::scoped_lock lock(administration_mutex_);
      if (!active_ || utc_seconds() >= pairing_expiration_utc_seconds_) {
        return std::nullopt;
      }
      return pairing_uri_;
    }

    RuntimeAdministrationSnapshot administration_snapshot() const override {
      ReconnectTelemetrySnapshot reconnect;
      {
        std::scoped_lock lock(session_mutex_);
        reconnect = reconnect_telemetry_;
      }
      return {
        .active = active(),
        .profile = config_.host.profile,
        .port = config_.host.port,
        .invitation_uri = pairing_invitation_uri(),
        .reconnect = reconnect,
      };
    }

    std::vector<TrustedClientSummary> trusted_clients() noexcept override {
      return trust_store_ ? trust_store_->list() : std::vector<TrustedClientSummary> {};
    }

    bool update_trusted_client(
      const Identifier128 &client_id,
      const PermissionSet permissions,
      const bool enabled
    ) noexcept override {
      if (!trust_store_ || !trust_store_->update_permissions(client_id, permissions, enabled)) {
        return false;
      }
      if (control_) {
        control_->disconnect_client(client_id);
      }
      return true;
    }

    bool revoke_trusted_client(const Identifier128 &client_id) noexcept override {
      if (!trust_store_ || !trust_store_->revoke(client_id)) {
        return false;
      }
      if (control_) {
        control_->disconnect_client(client_id);
      }
      return true;
    }

    std::optional<std::string> issue_pairing_invitation() noexcept override {
      std::scoped_lock lock(administration_mutex_);
      if (!active_ || !control_) {
        return std::nullopt;
      }
      control_->revoke_invitations();
      pairing_uri_.reset();
      if (!create_pairing_invitation()) {
        return std::nullopt;
      }
      return pairing_uri_;
    }

    void revoke_pairing_invitation() noexcept override {
      std::scoped_lock lock(administration_mutex_);
      if (control_) {
        control_->revoke_invitations();
      }
      pairing_uri_.reset();
      pairing_expiration_utc_seconds_ = 0;
    }

  private:
    /** @brief Joined ownership of one acknowledged host-audio capture and sender generation. */
    struct ActiveAudioRuntime {
      PeerEndpoint peer {};  ///< Association authorized to receive this generation.
      std::uint32_t generation {};  ///< Exact active audio generation.
      safe::mail_t mail;  ///< Local shutdown mailbox consumed by `audio::capture`.
      std::shared_ptr<HostAudioSender> sender;  ///< Typed encoded-packet destination and SRTP worker.
      std::jthread capture_thread;  ///< Host loopback capture owner.
      bool remove_srtp_on_retirement {};  ///< Whether association loss deferred SRTP removal until after join.
    };

    /** @brief Prepared VIDEO_CONFIG plus host-only hardware capture and pacing selection. */
    struct ActiveVideoConfiguration {
      /** @brief Construct an empty configuration for fallible pre-commit staging. */
      ActiveVideoConfiguration() = default;
      /** @brief Copy only while ATTACH can still fail without authority mutation. */
      ActiveVideoConfiguration(const ActiveVideoConfiguration &) = default;
      /** @brief Copy-assign only while ATTACH can still fail without authority mutation. */
      ActiveVideoConfiguration &operator=(const ActiveVideoConfiguration &) = default;
      /** @brief Move staged configuration into committed authority without allocation. */
      ActiveVideoConfiguration(ActiveVideoConfiguration &&) noexcept = default;
      /** @brief Move-assign staged configuration into committed authority without allocation. */
      ActiveVideoConfiguration &operator=(ActiveVideoConfiguration &&) noexcept = default;

      VideoConfigPayload wire {};  ///< Exact configuration sent reliably to the client.
      video::config_t capture {};  ///< New LSP-owned capture/encoder configuration.
      std::uint64_t aggregate_pacing_bits_per_second {};  ///< Complete IP-layer pacing ceiling.
      std::uint64_t reserved_overhead_bits_per_second {};  ///< Host audio and control allowance.
      std::uint32_t feedback_sender_ssrc {};  ///< Negotiated client input SSRC for RTCP feedback.
      std::uint32_t input_acknowledgement_ssrc {};  ///< Host LSPI sender SSRC retained across ATTACH allocation.
      std::uint32_t audio_feedback_ssrc {};  ///< Active host-audio SSRC admitted in aggregate CCFB.
      std::uint16_t path_payload_ceiling {1'200};  ///< Authenticated client/family DPLPMTUD ceiling.
      VideoNetworkProfile network_profile {VideoNetworkProfile::adaptive_low_latency};  ///< Selected controller profile.
      std::uint64_t process_generation {};  ///< Application launched after exact display preparation.
      bool reference_invalidation {};  ///< Native no-IDR reference invalidation capability.
      std::shared_ptr<platf::virtual_display::session_lease_t> display_lease;  ///< Prepared VDD owner before ACK.
    };

    static_assert(std::is_nothrow_move_assignable_v<ActiveVideoConfiguration>);
    static_assert(std::is_nothrow_move_assignable_v<std::optional<ActiveVideoConfiguration>>);

    /** @brief Joined ownership of one acknowledged video capture and sender generation. */
    struct ActiveVideoRuntime {
      PeerEndpoint peer {};  ///< Association authorized to receive this generation.
      std::uint32_t generation {};  ///< Exact active video generation.
      safe::mail_t mail;  ///< Local capture shutdown and recovery mailbox.
      std::shared_ptr<HostVideoSender> sender;  ///< Capacity-one RTP/SRTP sender owner.
      std::jthread capture_thread;  ///< Existing capture/VDD/hardware encoder owner.
      std::shared_ptr<platf::virtual_display::session_lease_t> display_lease;  ///< Active exact VDD generation owner.
      bool remove_srtp_on_retirement {};  ///< Whether association loss deferred SRTP removal until join.
    };

    /** @brief One committed ATTACH waiting for every replacement authority boundary. */
    struct AttachReadinessBarrier {
      PeerEndpoint successor_peer {};  ///< Fresh authenticated association receiving the replacement authority.
      std::uint32_t connection_generation {};  ///< Exact fresh connection generation.
      std::uint32_t input_generation {};  ///< Exact fresh input generation.
      std::uint32_t audio_generation {};  ///< Exact fresh audio generation.
      std::uint32_t video_generation {};  ///< Exact fresh video generation.
      std::uint32_t microphone_generation {};  ///< Fresh microphone generation, or zero when absent.
      std::uint64_t request_started_microseconds {};  ///< Monotonic start of the semantic ATTACH attempt.
      std::uint64_t committed_microseconds {};  ///< Monotonic authority/token commit time.
      std::uint64_t deadline_microseconds {};  ///< Bounded generation-qualified full-readiness deadline.
      bool input_baseline_ready {};  ///< Complete neutral baseline committed and urgent ACK scheduled.
      bool audio_ready {};  ///< Mandatory host audio configuration reached a successful terminal state.
      bool video_acknowledged {};  ///< Client accepted the exact replacement video generation.
      bool video_activated {};  ///< Replacement capture and sender ownership are live.
      bool microphone_selected {};  ///< A reverse microphone generation was negotiated.
      bool microphone_required {};  ///< Rejection or local activation failure is session-fatal.
      bool microphone_terminal {};  ///< Selected microphone reached success or optional rejection.
      bool microphone_ready {};  ///< Selected microphone runtime is active.
      bool active {};  ///< Whether this barrier owns current successor readiness.
    };

    /** @brief Bounded semantic ATTACH outcome retained for exact same-association replay. */
    struct AttachIntentOutcome {
      Identifier128 intent_id {};  ///< Client-selected idempotence identifier.
      Identifier128 session_id {};  ///< Session named by the request.
      Secret256 attach_token {};  ///< Presented predecessor token retained only in process memory.
      Secret256 successor_attach_token {};  ///< Client-selected successor retained only in process memory.
      PeerEndpoint peer {};  ///< Exact association on which the side effect committed.
      std::uint32_t connection_generation {};  ///< Exact connection generation of the cached response.
      AttachResponsePayload response {};  ///< Byte-semantically identical successful response values.
      bool active {};  ///< Whether this cache entry is populated.
    };

    /** @brief Shared callback-safe owner of one connection-generation aggregate path. */
    struct ForwardPathGeneration {
      ProductHostRuntime *runtime {};  ///< Product socket owner, valid until every path joins.
      PeerEndpoint peer {};  ///< Exact authenticated association five-tuple.
      std::uint32_t generation {};  ///< Exact control connection generation.
      std::shared_ptr<HostForwardPath> path;  ///< Aggregate scheduler and final socket owner.
      std::uint8_t slot {};  ///< Stable bit index used for callback-to-socket-loop teardown handoff.
      std::atomic<std::uint32_t> fatal_generation {};  ///< Exact generation atomically marked after fatal path completion.

      /** @brief Close and join the callback source before generation storage is destroyed. */
      ~ForwardPathGeneration() {
        if (path) {
          path->close();
          path->join();
        }
      }
    };

    /**
     * @brief Retain one callback-safe path generation without taking session authority.
     *
     * @param peer Exact association five-tuple.
     * @return Shared generation owner, or null when absent.
     */
    [[nodiscard]] std::shared_ptr<ForwardPathGeneration> find_forward_path(
      const PeerEndpoint &peer
    ) const noexcept {
      std::scoped_lock lock(forward_path_mutex_);
      for (const auto &generation : forward_paths_) {
        if (generation && generation->peer == peer) {
          return generation;
        }
      }
      return {};
    }

    /** @brief Enter one synchronous DTLS provider call that may emit pre-authentication output. */
    void begin_dtls_provider_output(const PeerEndpoint &peer) noexcept {
      std::scoped_lock lock(forward_path_mutex_);
      direct_dtls_output_peer_ = peer;
    }

    /** @brief Leave the matching synchronous DTLS provider output scope. */
    void end_dtls_provider_output(const PeerEndpoint &peer) noexcept {
      std::scoped_lock lock(forward_path_mutex_);
      if (direct_dtls_output_peer_ && *direct_dtls_output_peer_ == peer) {
        direct_dtls_output_peer_.reset();
      }
    }

    /** @brief Publish one provider-authenticated peer independently from forward-path lifetime. */
    [[nodiscard]] bool remember_authenticated_peer(const PeerEndpoint &peer) noexcept {
      std::scoped_lock lock(forward_path_mutex_);
      if (std::ranges::find(authenticated_peers_, peer) != authenticated_peers_.end()) {
        return true;
      }
      const auto empty = std::ranges::find_if(authenticated_peers_, [](const PeerEndpoint &candidate) {
        return !candidate.valid();
      });
      if (empty == authenticated_peers_.end()) {
        return false;
      }
      *empty = peer;
      return true;
    }

    /** @brief Forget one closed authenticated peer. */
    void forget_authenticated_peer(const PeerEndpoint &peer) noexcept {
      std::scoped_lock lock(forward_path_mutex_);
      const auto entry = std::ranges::find(authenticated_peers_, peer);
      if (entry != authenticated_peers_.end()) {
        *entry = {};
      }
    }

    /** @brief Permit direct output only inside a provider call for a peer not yet authenticated. */
    [[nodiscard]] bool direct_dtls_output_allowed(const PeerEndpoint &peer) const noexcept {
      std::scoped_lock lock(forward_path_mutex_);
      return direct_dtls_output_peer_ && *direct_dtls_output_peer_ == peer &&
             std::ranges::find(authenticated_peers_, peer) == authenticated_peers_.end();
    }

    /**
     * @brief Allocate, start, and publish one connection-generation path.
     *
     * @param peer Exact authenticated association.
     * @param generation Nonzero control connection generation.
     * @return True only after the path worker is discoverable.
     */
    [[nodiscard]] bool create_forward_path(
      const PeerEndpoint &peer,
      const std::uint32_t generation
    ) noexcept {
      auto owner = std::shared_ptr<ForwardPathGeneration> {new (std::nothrow) ForwardPathGeneration};
      if (!owner) {
        return false;
      }
      owner->runtime = this;
      owner->peer = peer;
      owner->generation = generation;
      {
        std::scoped_lock lock(forward_path_mutex_);
        const auto free = std::ranges::find(forward_paths_, nullptr);
        if (free == forward_paths_.end()) {
          return false;
        }
        owner->slot = static_cast<std::uint8_t>(std::distance(forward_paths_.begin(), free));
      }
      owner->path = std::shared_ptr<HostForwardPath> {new (std::nothrow) HostForwardPath({
        .peer = peer,
        .generation = generation,
        .pacing_bits_per_second = 20'000'000,
        .path_payload_bytes = 1'200,
        .probe_payload_ceiling = 0,
        .callbacks = {
          .context = owner.get(),
          .send_datagram = forward_send_callback,
          .completed = forward_completed_callback,
        },
      })};
      if (!owner->path || !owner->path->ready() || !owner->path->start()) {
        return false;
      }
      std::scoped_lock lock(forward_path_mutex_);
      auto &slot = forward_paths_[owner->slot];
      if (!slot) {
        slot = std::move(owner);
        return true;
      }
      owner->path->close();
      owner->path->join();
      return false;
    }

    /**
     * @brief Close and join one path while keeping it discoverable to DTLS callbacks.
     *
     * @param peer Exact retiring association.
     */
    void retire_forward_path(const PeerEndpoint &peer) noexcept {
      std::shared_ptr<ForwardPathGeneration> owner;
      {
        std::scoped_lock lock(forward_path_mutex_);
        for (const auto &slot : forward_paths_) {
          if (slot && slot->peer == peer) {
            owner = slot;
            break;
          }
        }
      }
      if (owner && owner->path) {
        owner->path->close();
        owner->path->join();
      }
      {
        std::scoped_lock lock(forward_path_mutex_);
        for (auto &slot : forward_paths_) {
          if (slot == owner) {
            slot.reset();
            break;
          }
        }
      }
    }

    /** @brief Close, join, and forget every remaining connection-generation path. */
    void retire_all_forward_paths() noexcept {
      std::array<std::shared_ptr<ForwardPathGeneration>, 64> owners;
      {
        std::scoped_lock lock(forward_path_mutex_);
        owners = forward_paths_;
      }
      for (auto &owner : owners) {
        if (owner && owner->path) {
          owner->path->close();
          owner->path->join();
        }
      }
      {
        std::scoped_lock lock(forward_path_mutex_);
        forward_paths_ = {};
      }
    }

    struct DtlsTimer {
      PeerEndpoint peer;  ///< Association being timed.
      std::uint64_t due_microseconds {};  ///< Monotonic due time.
    };

    /** @brief Authenticated reverse-path intent awaiting one exact protected client LSPP. */
    struct PendingInboundPathProbe {
      PeerEndpoint peer {};  ///< Exact association that established the intent.
      PathProbePayload probe {};  ///< Expected logical identifier and protected size.
      std::uint64_t deadline_microseconds {};  ///< Control-owned bounded receive deadline.
      bool active {};  ///< Whether an authenticated data probe remains expected.
    };

    /**
     * @brief Calculate exact worst-case LSPI wire reservation for the installed association.
     *
     * @param peer Authenticated association used to query the negotiated SRTCP trailer.
     * @return Complete IP/UDP bits per second at the 125-microsecond hard ACK floor.
     */
    [[nodiscard]] std::optional<std::uint64_t> maximum_feedback_bits_per_second(
      const PeerEndpoint &peer
    ) const noexcept {
      if (!srtp_) {
        return std::nullopt;
      }
      const auto trailer = srtp_->protect_trailer_length(peer, SecurePacketClass::rtcp);
      if (!trailer) {
        return std::nullopt;
      }
      constexpr std::uint64_t maximum_lspi_plaintext_bytes =
        12U + input_plane::lspi_fixed_size +
        input_plane::maximum_acknowledged_pointers * input_plane::lspi_pointer_record_size;
      const auto ip_udp_bytes = peer.family == IpAddressFamily::ipv6 ? 48U : 28U;
      const auto charged_bytes = maximum_lspi_plaintext_bytes + *trailer + ip_udp_bytes;
      constexpr std::uint64_t maximum_acknowledgements_per_second = 1'000'000U / 125U;
      if (charged_bytes > std::numeric_limits<std::uint64_t>::max() / 8U /
                            maximum_acknowledgements_per_second) {
        return std::nullopt;
      }
      return charged_bytes * 8U * maximum_acknowledgements_per_second;
    }

    /**
     * @brief Select the first exact supported audio offer in client order.
     *
     * @param request Authenticated START offer.
     * @param generation Nonzero audio configuration generation.
     * @param ssrc Fresh unique host audio SSRC.
     * @return Exact built-in Opus tuple or no value when no offer is supported.
     */
    std::optional<AudioSelectionPayload> select_audio(
      const StartRequestPayload &request,
      const std::uint32_t generation,
      const std::uint32_t ssrc
    ) const noexcept {
      if (!config::audio.stream || generation == 0 || ssrc == 0) {
        return std::nullopt;
      }
      for (const auto &offer : request.audio_offers) {
        const auto stream = audio::select_opus_stream_config(offer.channels, false);
        if (!stream) {
          continue;
        }
        const auto stream_maximum = std::min(2'048'000, stream->streams * 512'000);
        const auto bitrate = std::min(offer.maximum_bitrate, static_cast<std::uint32_t>(stream->bitrate));
        if (bitrate < 6'000 || bitrate > static_cast<std::uint32_t>(stream_maximum)) {
          continue;
        }
        AudioSelectionPayload selected {
          .audio_generation = generation,
          .audio_ssrc = ssrc,
          .audio_payload_type = 111,
          .clock_rate = 48'000,
          .channels = static_cast<std::uint8_t>(stream->channelCount),
          .streams = static_cast<std::uint8_t>(stream->streams),
          .coupled_streams = static_cast<std::uint8_t>(stream->coupledStreams),
          .frame_samples = offer.frame_samples,
          .bitrate = bitrate,
          .inband_fec = offer.inband_fec,
          .dtx = offer.dtx,
          .initial_udp_payload_size = 1'200,
          .initial_preroll_packets = 1,
        };
        std::copy_n(stream->mapping, stream->channelCount, selected.mapping.begin());
        return std::move(selected);
      }
      return std::nullopt;
    }

    /**
     * @brief Select an optional reverse microphone only with permission and a real platform probe.
     *
     * @param request Authenticated START offer.
     * @param client Trusted client permissions.
     * @param generation Nonzero microphone generation.
     * @param ssrc Fresh unique client microphone SSRC.
     * @return Null selection, exact selection, or the required-offer failure status.
     */
    std::expected<std::optional<MicrophoneSelectionPayload>, ControlStatus> select_microphone(
      const StartRequestPayload &request,
      const TrustedClient &client,
      const std::uint32_t generation,
      const std::uint32_t ssrc
    ) const noexcept {
      if (!request.microphone_offer) {
        return std::optional<MicrophoneSelectionPayload> {};
      }
      const auto required = request.microphone_offer->required;
      if (!client.permissions.contains(Permission::microphone)) {
        return required ?
                 std::expected<std::optional<MicrophoneSelectionPayload>, ControlStatus> {std::unexpected(ControlStatus::permission_denied)} :
                 std::expected<std::optional<MicrophoneSelectionPayload>, ControlStatus> {std::optional<MicrophoneSelectionPayload> {}};
      }
      bool available = false;
  #ifdef _WIN32
      if (config::audio.client_microphone) {
        try {
          auto sink = platf::win_audio::make_virtual_microphone();
          available = sink && sink->probe();
        } catch (...) {
          available = false;
        }
      }
  #endif
      if (!available || generation == 0 || ssrc == 0) {
        return required ?
                 std::expected<std::optional<MicrophoneSelectionPayload>, ControlStatus> {std::unexpected(ControlStatus::unsupported_media_tuple)} :
                 std::expected<std::optional<MicrophoneSelectionPayload>, ControlStatus> {std::optional<MicrophoneSelectionPayload> {}};
      }
      return std::optional<MicrophoneSelectionPayload> {MicrophoneSelectionPayload {
        .microphone_generation = generation,
        .microphone_ssrc = ssrc,
        .microphone_payload_type = 112,
        .clock_rate = 48'000,
        .channels = 1,
        .frame_samples = 960,
        .bitrate = std::min<std::uint32_t>(64'000, request.microphone_offer->maximum_bitrate),
        .inband_fec = request.microphone_offer->inband_fec,
        .dtx = request.microphone_offer->dtx,
        .initial_udp_payload_size = 1'200,
      }};
    }

    /**
     * @brief Select and prove the first exact offered Windows hardware video tuple.
     *
     * @param peer Authenticated peer whose address family constrains path accounting.
     * @param request Exact decoded START request and ordered video offers.
     * @param session_id Fresh nonzero session identifier.
     * @param stream_generation Fresh nonzero stream generation.
     * @param video_generation Fresh nonzero video generation.
     * @param primary_ssrc Collision-free primary-video SSRC.
     * @param repair_ssrc Collision-free candidate FlexFEC SSRC.
     * @param rtx_ssrc Collision-free candidate RTX SSRC.
     * @return Fully encoded/preflighted configuration or the exact START failure status.
     */
    std::expected<ActiveVideoConfiguration, ControlStatus> select_video(
      const PeerEndpoint &peer,
      const StartRequestPayload &request,
      const Identifier128 &session_id,
      const std::uint32_t stream_generation,
      const std::uint32_t video_generation,
      const std::uint32_t primary_ssrc,
      const std::uint32_t repair_ssrc,
      const std::uint32_t rtx_ssrc
    ) noexcept {
      const auto expected_profile = config_.host.profile == NetworkProfile::competition ?
                                      VideoNetworkProfile::competition :
                                      VideoNetworkProfile::adaptive_low_latency;
      if (request.network_profile != expected_profile || video_generation == 0 || primary_ssrc == 0 ||
          repair_ssrc == 0 || rtx_ssrc == 0 || primary_ssrc == repair_ssrc || primary_ssrc == rtx_ssrc ||
          repair_ssrc == rtx_ssrc ||
          is_zero(session_id) || stream_generation == 0 || proc::proc.running() > 0) {
        return std::unexpected(ControlStatus::unsupported_media_tuple);
      }
      int numeric_application_id = 0;
      const auto parsed_application = std::from_chars(
        request.application_id.data(),
        request.application_id.data() + request.application_id.size(),
        numeric_application_id
      );
      if (parsed_application.ec != std::errc {} ||
          parsed_application.ptr != request.application_id.data() + request.application_id.size() ||
          numeric_application_id <= 0) {
        return std::unexpected(ControlStatus::malformed);
      }
      const auto competition_capacity = static_cast<std::uint64_t>(config_.host.competition_capacity_mbps) * 1'000'000ULL;
      for (const auto &offer : request.video_offers) {
        const auto video_format = offer.codec == VideoCodec::h264 ? 0 :
                                  offer.codec == VideoCodec::hevc ? 1 :
                                                                    2;
        const auto ten_bit = offer.pixel_format == VideoPixelClass::yuv420_10 ||
                             offer.pixel_format == VideoPixelClass::yuv444_10;
        const auto yuv444 = offer.pixel_format == VideoPixelClass::yuv444_8 ||
                            offer.pixel_format == VideoPixelClass::yuv444_10;
        const auto hdr10 = offer.color_primaries == video_color_primaries_bt2020 &&
                           offer.transfer_function == video_transfer_pq &&
                           offer.matrix_coefficients == video_matrix_bt2020_ncl;
        const auto hlg = offer.transfer_function == video_transfer_hlg;
        if (hlg || (ten_bit != hdr10) || (hdr10 && offer.full_range)) {
          continue;
        }
        auto selected_bitrate = offer.preferred_bits_per_second;
        auto pacing_ceiling = offer.maximum_bits_per_second;
        if (request.network_profile == VideoNetworkProfile::competition) {
          if (competition_capacity == 0) {
            return std::unexpected(ControlStatus::path_capacity_insufficient);
          }
          pacing_ceiling = std::min(pacing_ceiling, competition_capacity);
          selected_bitrate = std::min(selected_bitrate, pacing_ceiling * 9U / 10U);
        }
        if (selected_bitrate < video_minimum_bits_per_second || selected_bitrate > pacing_ceiling ||
            selected_bitrate / 1'000U > static_cast<std::uint64_t>(std::numeric_limits<int>::max())) {
          continue;
        }
        const auto refresh = std::max<std::uint64_t>(
          1,
          static_cast<std::uint64_t>(offer.refresh_numerator) / offer.refresh_denominator
        );
        const auto refresh_x100 = static_cast<std::uint64_t>(offer.refresh_numerator) * 100U / offer.refresh_denominator;
        if (refresh > static_cast<std::uint64_t>(std::numeric_limits<int>::max()) ||
            refresh_x100 > static_cast<std::uint64_t>(std::numeric_limits<int>::max())) {
          continue;
        }
        ActiveVideoConfiguration selected;
        try {
          selected.capture = video::config_t {
            .width = static_cast<int>(offer.width),
            .height = static_cast<int>(offer.height),
            .framerate = static_cast<int>(refresh),
            .framerateX100 = static_cast<int>(refresh_x100),
            .bitrate = static_cast<int>(selected_bitrate / 1'000U),
            .slicesPerFrame = 1,
            .numRefFrames = 0,
            .encoderCscMode = 2 | static_cast<int>(offer.full_range),
            .videoFormat = video_format,
            .dynamicRange = ten_bit ? 1 : 0,
            .chromaSamplingType = yuv444 ? 1 : 0,
            .enableIntraRefresh = 0,
            .output_name = config::video.output_name,
            .optimization_policy = std::make_shared<const stream_policy::EffectiveStreamPolicy>(
              stream_policy::resolve_policy(
                stream_policy::StreamOptimizationMode::latency,
                stream_policy::StreamOptimizationMode::latency,
                config::video.nv,
                0,
                stream_policy::AdvancedOverrides {}
              )
            ),
            .client_protocol = stream_policy::ClientProtocol::lumen_streaming_protocol,
            .capture_input_watermark = [this]() {
              return input_owner_ ? input_owner_->applied_watermark() : std::pair<std::uint64_t, std::uint64_t> {};
            },
          };
        } catch (...) {
          return std::unexpected(ControlStatus::internal_failure);
        }
  #ifdef _WIN32
        auto configured_activation = platf::virtual_display::activation_policy_e::disabled;
        switch (config::video.dd.virtual_display_policy) {
          case config::video_t::dd_t::virtual_display_policy_e::optional:
            configured_activation = platf::virtual_display::activation_policy_e::optional;
            break;
          case config::video_t::dd_t::virtual_display_policy_e::required:
            configured_activation = platf::virtual_display::activation_policy_e::required;
            break;
          case config::video_t::dd_t::virtual_display_policy_e::disabled:
            break;
        }
        const auto activation = platf::virtual_display::lsp_activation_policy(configured_activation);
        auto vdd_session_id = wire::read_be<std::uint64_t>(std::span<const std::uint8_t> {session_id}.first<8>());
        if (vdd_session_id == 0) {
          vdd_session_id = wire::read_be<std::uint64_t>(std::span<const std::uint8_t> {session_id}.subspan<8, 8>());
        }
        if (vdd_session_id == 0) {
          vdd_session_id = 1;
        }
        const auto refresh_ratio = platf::virtual_display::rational_t {
          offer.refresh_numerator,
          offer.refresh_denominator,
        }
                                     .normalized();
        if (!refresh_ratio) {
          continue;
        }
        auto encoder_limits = platf::virtual_display::mode_limits_t {};
        encoder_limits.supports_hdr10 = hdr10;
        encoder_limits.supports_10bit = ten_bit;
        if (video_format == 0) {
          encoder_limits.maximum_width = 4'096;
          encoder_limits.maximum_height = 4'096;
          encoder_limits.maximum_pixels = 4'096ULL * 4'096ULL;
        }
        auto prepared = platf::virtual_display::prepare_system_stream_session(
          activation,
          platf::virtual_display::modern_stream_request(
            vdd_session_id,
            {
              offer.width,
              offer.height,
              *refresh_ratio,
              hdr10 ?
                platf::virtual_display::dynamic_range_e::hdr10 :
                platf::virtual_display::dynamic_range_e::sdr,
              static_cast<std::uint8_t>(ten_bit ? 10 : 8),
            },
            platf::virtual_display::delivery_policy_e::latency,
            platf::virtual_display::fidelity_e::lossless
          ),
          encoder_limits,
          selected.capture.output_name
        );
        if (prepared.outcome == platf::virtual_display::session_prepare_e::rejected) {
          continue;
        }
        selected.capture.output_name = std::move(prepared.capture_name);
        selected.display_lease = std::move(prepared.lease);
        if (prepared.outcome == platf::virtual_display::session_prepare_e::virtual_display && prepared.selection) {
          selected.capture.width = static_cast<int>(prepared.selection->selected_mode.width);
          selected.capture.height = static_cast<int>(prepared.selection->selected_mode.height);
          selected.capture.virtual_display_active = true;
          selected.capture.virtual_display_direct_required =
            activation == platf::virtual_display::activation_policy_e::required;
          selected.capture.virtual_display_generation = prepared.selection->generation;
          selected.capture.virtual_display_desktop_fallback_permitted = false;
          selected.capture.virtual_display_frame_source = platf::virtual_display::make_system_frame_source(
            *prepared.selection,
            std::chrono::milliseconds {250}
          );
          if (!selected.capture.virtual_display_frame_source && selected.capture.virtual_display_direct_required) {
            if (selected.display_lease) {
              (void) selected.display_lease->release();
            }
            continue;
          }
        }
  #else
        continue;
  #endif
        const auto launched = proc::proc.execute_lsp_if_idle(numeric_application_id);
        if (launched.status != 0 || launched.process_generation == 0) {
          return std::unexpected(launched.status == 409 ? ControlStatus::busy : ControlStatus::internal_failure);
        }
        if (video::probe_encoders() != 0) {
          (void) proc::proc.terminate_lsp_generation(launched.process_generation);
          return std::unexpected(ControlStatus::unsupported_media_tuple);
        }
        const auto capability = video::active_lsp_sdr_encoder_capability(video_format);
        if (!capability.supported || !capability.hardware || !capability.verified_low_delay) {
          (void) proc::proc.terminate_lsp_generation(launched.process_generation);
          return std::unexpected(ControlStatus::unsupported_media_tuple);
        }
        const auto codec_supports_yuv444 = video::last_encoder_probe_supported_yuv444_for_codec[video_format];
        const auto hdr420_supported =
          (video_format == 1 && (video::active_hevc_mode == 3 || video::active_hevc_mode == 5)) ||
          (video_format == 2 && (video::active_av1_mode == 3 || video::active_av1_mode == 5));
        const auto hdr444_supported =
          (video_format == 1 && (video::active_hevc_mode == 4 || video::active_hevc_mode == 5)) ||
          (video_format == 2 && (video::active_av1_mode == 4 || video::active_av1_mode == 5));
        if ((yuv444 && !codec_supports_yuv444) ||
            (hdr10 && ((!yuv444 && !hdr420_supported) || (yuv444 && !hdr444_supported)))) {
          (void) proc::proc.terminate_lsp_generation(launched.process_generation);
          continue;
        }
        selected.capture.enableIntraRefresh = capability.reference_invalidation ? 1 : 0;
        auto initialization = video::codec_initialization(selected.capture);
        if (!initialization) {
          (void) proc::proc.terminate_lsp_generation(launched.process_generation);
          return std::unexpected(ControlStatus::unsupported_media_tuple);
        }
        auto codec_units = split_video_codec_units(*initialization, offer.codec);
        if (!codec_units) {
          (void) proc::proc.terminate_lsp_generation(launched.process_generation);
          return std::unexpected(ControlStatus::unsupported_media_tuple);
        }
        std::optional<HdrMetadataPayload> hdr_metadata;
        if (hdr10) {
          const auto captured_metadata = video::active_hdr_metadata(selected.capture);
          if (!captured_metadata) {
            (void) proc::proc.terminate_lsp_generation(launched.process_generation);
            continue;
          }
          hdr_metadata = HdrMetadataPayload {
            .red_primary_x = captured_metadata->displayPrimaries[0].x,
            .red_primary_y = captured_metadata->displayPrimaries[0].y,
            .green_primary_x = captured_metadata->displayPrimaries[1].x,
            .green_primary_y = captured_metadata->displayPrimaries[1].y,
            .blue_primary_x = captured_metadata->displayPrimaries[2].x,
            .blue_primary_y = captured_metadata->displayPrimaries[2].y,
            .white_point_x = captured_metadata->whitePoint.x,
            .white_point_y = captured_metadata->whitePoint.y,
            .maximum_display_luminance = captured_metadata->maxDisplayLuminance,
            .minimum_display_luminance = captured_metadata->minDisplayLuminance,
            .maximum_content_light_level = captured_metadata->maxContentLightLevel,
            .maximum_frame_average_light_level = captured_metadata->maxFrameAverageLightLevel,
            .maximum_full_frame_luminance = captured_metadata->maxFullFrameLuminance,
          };
        }
        std::array<std::uint8_t, 8> origin_bytes {};
        if (!crypto_->random(origin_bytes)) {
          (void) proc::proc.terminate_lsp_generation(launched.process_generation);
          return std::unexpected(ControlStatus::internal_failure);
        }
        auto frame_id_origin = wire::read_be<std::uint64_t>(origin_bytes);
        if (frame_id_origin == 0) {
          frame_id_origin = 1;
        }
        const auto maximum_access_unit_bytes = std::min<std::uint32_t>(
          offer.maximum_complete_access_unit_bytes,
          static_cast<std::uint32_t>(media::competition_frame_size_limit)
        );
        selected.wire = {
          .session_id = session_id,
          .stream_generation = stream_generation,
          .video = {
            .video_generation = video_generation,
            .primary_ssrc = primary_ssrc,
            .primary_payload_type = 97,
            .clock_rate = 90'000,
            .codec = offer.codec,
            .profile = offer.profile,
            .width = offer.width,
            .height = offer.height,
            .refresh_numerator = offer.refresh_numerator,
            .refresh_denominator = offer.refresh_denominator,
            .selected_bits_per_second = selected_bitrate,
            .pixel_format = offer.pixel_format,
            .color_primaries = offer.color_primaries,
            .transfer_function = offer.transfer_function,
            .matrix_coefficients = offer.matrix_coefficients,
            .full_range = offer.full_range,
            .initial_udp_payload_size = 1'200,
            .decoder_surfaces = request.decoder_surfaces,
            .render_mailbox = 1,
            .delivery = video_delivery_complete_access_unit,
            .frame_marking_extension = video_frame_marking_extension_id,
            .absolute_capture_time_extension = video_absolute_capture_time_extension_id,
            .frame_id_extension = video_frame_id_extension_id,
            .input_watermark_extension = video_input_watermark_extension_id,
            .encoder_timing_extension = video_encoder_timing_extension_id,
            .flexfec = offer.flexfec ?
                         std::optional<FlexFecSelectionPayload> {FlexFecSelectionPayload {
                           .repair_ssrc = repair_ssrc,
                           .repair_payload_type = 98,
                           .window_microseconds = request.maximum_capture_to_present_microseconds,
                           .maximum_group_packets = 15,
                         }} :
                         std::nullopt,
            .rtx = offer.rtx ?
                     std::optional<RtxSelectionPayload> {RtxSelectionPayload {
                       .rtx_ssrc = rtx_ssrc,
                       .rtx_payload_type = 99,
                       .associated_payload_type = 97,
                     }} :
                     std::nullopt,
            .maximum_frame_age_microseconds = request.maximum_capture_to_present_microseconds,
            .maximum_complete_access_unit_bytes = maximum_access_unit_bytes,
          },
          .codec_configuration = {
            .kind = offer.codec,
            .units = std::move(*codec_units),
          },
          .frame_id_origin = frame_id_origin,
          .recovery_epoch = 1,
          .hdr_metadata = hdr_metadata,
        };
        const auto video_configuration_preflight = encode_video_config(selected.wire);
        if (!video_configuration_preflight) {
          (void) proc::proc.terminate_lsp_generation(launched.process_generation);
          selected.display_lease.reset();
          return std::unexpected(ControlStatus::unsupported_media_tuple);
        }
        selected.aggregate_pacing_bits_per_second = pacing_ceiling;
        selected.process_generation = launched.process_generation;
        selected.reference_invalidation = capability.reference_invalidation;
        return selected;
      }
      return std::unexpected(ControlStatus::unsupported_media_tuple);
    }

    /**
     * @brief Stop and join one detached audio runtime without holding session authority locks.
     *
     * @param runtime Audio runtime ownership to release.
     */
    static void stop_audio_runtime(std::unique_ptr<ActiveAudioRuntime> runtime) noexcept {
      if (!runtime) {
        return;
      }
      if (runtime->sender) {
        runtime->sender->close();
      }
      if (runtime->mail) {
        runtime->mail->event<bool>(mail::shutdown)->raise(true);
      }
      if (runtime->capture_thread.joinable()) {
        runtime->capture_thread.join();
      }
      if (runtime->sender) {
        runtime->sender->join();
      }
    }

    /**
     * @brief Make an audio runtime quiescent without joining its worker threads.
     *
     * @param runtime Runtime being detached from an authority callback.
     */
    static void begin_audio_runtime_stop(ActiveAudioRuntime &runtime) noexcept {
      if (runtime.sender) {
        runtime.sender->close();
      }
      if (runtime.mail) {
        runtime.mail->event<bool>(mail::shutdown)->raise(true);
      }
    }

    /**
     * @brief Queue a quiescent audio runtime for joining after the current receive callback.
     *
     * @param runtime Runtime ownership to retire.
     */
    void queue_audio_retirement(std::unique_ptr<ActiveAudioRuntime> runtime) noexcept {
      if (!runtime) {
        return;
      }
      begin_audio_runtime_stop(*runtime);
      std::scoped_lock lock(session_mutex_);
      for (auto &pending : pending_audio_retirements_) {
        if (!pending) {
          pending = std::move(runtime);
          return;
        }
      }
      std::terminate();
    }

    /** @brief Join every quiescent audio runtime outside DTLS/control callbacks and session locks. */
    void process_pending_audio_retirements() noexcept {
      while (true) {
        std::unique_ptr<ActiveAudioRuntime> runtime;
        {
          std::scoped_lock lock(session_mutex_);
          const auto pending = std::ranges::find_if(pending_audio_retirements_, [](const auto &candidate) {
            return static_cast<bool>(candidate);
          });
          if (pending == pending_audio_retirements_.end()) {
            return;
          }
          runtime = std::move(*pending);
        }
        const auto remove_srtp = runtime->remove_srtp_on_retirement;
        const auto peer = runtime->peer;
        stop_audio_runtime(std::move(runtime));
        if (remove_srtp && srtp_ && !is_retiring_attach_peer(peer)) {
          retire_forward_path(peer);
          srtp_->remove_association(peer);
        }
      }
    }

    /** @brief Stop and join one detached LSP video runtime outside authority locks. */
    static void stop_video_runtime(std::unique_ptr<ActiveVideoRuntime> runtime) noexcept {
      if (!runtime) {
        return;
      }
      if (runtime->mail) {
        runtime->mail->event<bool>(mail::shutdown)->raise(true);
      }
      if (runtime->capture_thread.joinable()) {
        runtime->capture_thread.join();
      }
      if (runtime->sender) {
        runtime->sender->close();
        runtime->sender->join();
      }
  #ifdef _WIN32
      if (runtime->display_lease) {
        (void) runtime->display_lease->release();
        runtime->display_lease.reset();
      }
  #endif
    }

    /** @brief Make one video capture/sender runtime quiescent without joining in a callback. */
    static void begin_video_runtime_stop(ActiveVideoRuntime &runtime) noexcept {
      if (runtime.mail) {
        runtime.mail->event<bool>(mail::shutdown)->raise(true);
      }
      if (runtime.sender) {
        runtime.sender->close();
      }
    }

    /** @brief Queue video destruction for the socket loop outside control/SRTP callbacks. */
    void queue_video_retirement(std::unique_ptr<ActiveVideoRuntime> runtime) noexcept {
      if (!runtime) {
        return;
      }
      begin_video_runtime_stop(*runtime);
      std::scoped_lock lock(session_mutex_);
      for (auto &pending : pending_video_retirements_) {
        if (!pending) {
          pending = std::move(runtime);
          return;
        }
      }
      std::terminate();
    }

    /** @brief Join every quiescent video owner outside packet/control callbacks. */
    void process_pending_video_retirements() noexcept {
      while (true) {
        std::unique_ptr<ActiveVideoRuntime> runtime;
        bool replacement_activation_failed = false;
        PeerEndpoint failed_replacement_peer;
        {
          std::scoped_lock lock(session_mutex_);
          const auto pending = std::ranges::find_if(pending_video_retirements_, [](const auto &candidate) {
            return static_cast<bool>(candidate);
          });
          if (pending == pending_video_retirements_.end()) {
            if (video_start_pending_ && video_runtime_ && active_video_configuration_) {
              video_start_pending_ = false;
              if (!start_video_capture(*video_runtime_, *active_video_configuration_)) {
                replacement_activation_failed = true;
                failed_replacement_peer = video_runtime_->peer;
                runtime = std::move(video_runtime_);
              } else {
                if (attach_readiness_.active && attach_readiness_.successor_peer == video_runtime_->peer &&
                    attach_readiness_.video_generation == video_runtime_->generation) {
                  attach_readiness_.video_activated = true;
                }
                complete_attach_readiness_if_possible();
                return;
              }
            } else {
              return;
            }
          } else {
            runtime = std::move(*pending);
          }
          if (!runtime) {
            return;
          }
        }
        const auto remove_srtp = runtime->remove_srtp_on_retirement;
        const auto peer = runtime->peer;
        stop_video_runtime(std::move(runtime));
        if (remove_srtp && srtp_ && !is_retiring_attach_peer(peer)) {
          retire_forward_path(peer);
          srtp_->remove_association(peer);
        }
        if (replacement_activation_failed) {
          fail_required_video_session(failed_replacement_peer);
          return;
        }
      }
    }

    /** @brief Terminate required video after a fatal mid-frame/pacer/socket sender failure. */
    void process_video_failure() noexcept {
      std::optional<PeerEndpoint> failed_peer;
      {
        std::scoped_lock lock(session_mutex_);
        if (video_runtime_ && video_runtime_->sender && video_runtime_->sender->snapshot().failed) {
          failed_peer = video_runtime_->peer;
        }
      }
      if (failed_peer) {
        fail_required_video_session(*failed_peer);
      }
    }

    /** @brief Terminate the required media session after fatal audio protection or path failure. */
    void process_audio_failure() noexcept {
      std::optional<PeerEndpoint> failed_peer;
      {
        std::scoped_lock lock(session_mutex_);
        if (audio_runtime_ && audio_runtime_->sender && audio_runtime_->sender->snapshot().failed) {
          failed_peer = audio_runtime_->peer;
        }
      }
      if (failed_peer) {
        fail_required_video_session(*failed_peer);
      }
    }

    /** @brief Queue a microphone receiver for destruction after the current callback. */
    void queue_microphone_retirement(std::unique_ptr<LspMicrophoneReceiver> receiver) noexcept {
      if (!receiver) {
        return;
      }
      std::scoped_lock lock(session_mutex_);
      for (auto &pending : pending_microphone_retirements_) {
        if (!pending) {
          pending = std::move(receiver);
          return;
        }
      }
      std::terminate();
    }

    /** @brief Stop, join, and release every deferred microphone writer outside callbacks. */
    void process_pending_microphone_retirements() noexcept {
      while (true) {
        std::unique_ptr<LspMicrophoneReceiver> receiver;
        {
          std::scoped_lock lock(session_mutex_);
          const auto pending = std::ranges::find_if(pending_microphone_retirements_, [](const auto &candidate) {
            return static_cast<bool>(candidate);
          });
          if (pending == pending_microphone_retirements_.end()) {
            return;
          }
          receiver = std::move(*pending);
        }
        receiver->shutdown();
      }
    }

    /** @brief Create the real Windows virtual microphone and bounded clocked receiver. */
    std::unique_ptr<LspMicrophoneReceiver> create_microphone_runtime(
      const PeerEndpoint &peer,
      const MicrophoneSelectionPayload &selection
    ) noexcept {
  #ifdef _WIN32
      try {
        auto sink = platf::win_audio::make_virtual_microphone();
        if (!sink || !sink->probe()) {
          return nullptr;
        }
        return LspMicrophoneReceiver::create(
          MicrophoneReceiverConfig {
            .peer = peer,
            .generation = selection.microphone_generation,
            .ssrc = selection.microphone_ssrc,
            .payload_type = selection.microphone_payload_type,
            .clock_rate = selection.clock_rate,
            .channels = selection.channels,
            .frame_samples = selection.frame_samples,
            .inband_fec = selection.inband_fec,
            .dtx = selection.dtx,
          },
          std::move(sink)
        );
      } catch (...) {
        return nullptr;
      }
  #else
      (void) peer;
      (void) selection;
      return nullptr;
  #endif
    }

    /**
     * @brief Create the complete acknowledged capture and sender owner.
     *
     * @param peer Authenticated destination association.
     * @param selection Acknowledged audio tuple.
     * @return Started audio runtime or no value on allocation/thread failure.
     */
    std::unique_ptr<ActiveAudioRuntime> create_audio_runtime(
      const PeerEndpoint &peer,
      const AudioSelectionPayload &selection
    ) noexcept {
      std::array<std::uint8_t, 6> random_timeline {};
      const auto forward = find_forward_path(peer);
      if (!srtp_ || !crypto_ || !forward || !forward->path || !crypto_->random(random_timeline)) {
        return nullptr;
      }
      auto sequence = wire::read_be<std::uint16_t>(std::span<const std::uint8_t> {random_timeline}.first<2>());
      auto timestamp = wire::read_be<std::uint32_t>(std::span<const std::uint8_t> {random_timeline}.subspan<2, 4>());
      if (sequence == 0) {
        sequence = 1;
      }
      if (timestamp == 0) {
        timestamp = 1;
      }
      const auto family = peer.family == IpAddressFamily::ipv6 ? media::ip_family::ipv6 : media::ip_family::ipv4;
      auto runtime = std::unique_ptr<ActiveAudioRuntime> {new (std::nothrow) ActiveAudioRuntime};
      if (!runtime) {
        return nullptr;
      }
      runtime->peer = peer;
      runtime->generation = selection.audio_generation;
      runtime->mail = std::shared_ptr<safe::mail_raw_t> {new (std::nothrow) safe::mail_raw_t};
      runtime->sender = std::shared_ptr<HostAudioSender> {new (std::nothrow) HostAudioSender(
        HostAudioSenderConfig {
          .peer = peer,
          .forward_path = forward->path,
          .forward_path_generation = forward->generation,
          .ssrc = selection.audio_ssrc,
          .payload_type = selection.audio_payload_type,
          .initial_sequence = sequence,
          .initial_timestamp = timestamp,
          .frame_samples = selection.frame_samples,
          .path = {.family = family, .udp_payload_size = selection.initial_udp_payload_size},
          .queue_capacity = 2,
          .maximum_queue_age_microseconds = std::max<std::uint64_t>(
            10'000,
            static_cast<std::uint64_t>(selection.frame_samples) * 2'000'000ULL / 48'000ULL
          ),
          .sender_report_interval_microseconds = 1'000'000,
        },
        *srtp_
      )};
      if (!runtime->mail || !runtime->sender || !runtime->sender->ready() || !runtime->sender->start()) {
        queue_audio_retirement(std::move(runtime));
        return nullptr;
      }
      audio::config_t capture_config {};
      capture_config.packetDuration = selection.frame_samples / 48;
      capture_config.frameSamples = selection.frame_samples;
      capture_config.channels = selection.channels;
      capture_config.bitrate = static_cast<int>(selection.bitrate);
      capture_config.captureQueueFrames = 2;
      capture_config.flags[audio::config_t::INBAND_FEC] = selection.inband_fec;
      capture_config.flags[audio::config_t::DTX] = selection.dtx;
      try {
        const auto mail = runtime->mail;
        const auto sender = runtime->sender;
        const auto destination = std::weak_ptr<audio::AudioPacketDestination> {sender};
        runtime->capture_thread = std::jthread([mail, capture_config, destination, sender]() mutable {
          audio::capture(std::move(mail), capture_config, destination);
          sender->close();
        });
      } catch (...) {
        queue_audio_retirement(std::move(runtime));
        return nullptr;
      }
      return runtime;
    }

    /** @brief Create acknowledged capture, hardware encoder, and bounded RTP/SRTP video owners. */
    std::unique_ptr<ActiveVideoRuntime> create_video_runtime(
      const PeerEndpoint &peer,
      const ActiveVideoConfiguration &selection,
      const std::uint8_t decoder_credit,
      std::shared_ptr<platf::virtual_display::session_lease_t> display_lease
    ) noexcept {
      std::array<std::uint8_t, 10> random_timeline {};
      const auto forward = find_forward_path(peer);
      if (!srtp_ || !crypto_ || !forward || !forward->path || !crypto_->random(random_timeline)) {
        return nullptr;
      }
      auto sequence = wire::read_be<std::uint16_t>(std::span<const std::uint8_t> {random_timeline}.first<2>());
      auto flexfec_sequence = selection.wire.video.flexfec ?
                                wire::read_be<std::uint16_t>(std::span<const std::uint8_t> {random_timeline}.subspan<2, 2>()) :
                                std::uint16_t {0};
      auto rtx_sequence = selection.wire.video.rtx ?
                            wire::read_be<std::uint16_t>(std::span<const std::uint8_t> {random_timeline}.subspan<4, 2>()) :
                            std::uint16_t {0};
      auto timestamp = wire::read_be<std::uint32_t>(std::span<const std::uint8_t> {random_timeline}.subspan<6, 4>());
      if (sequence == 0) {
        sequence = 1;
      }
      if (selection.wire.video.flexfec && flexfec_sequence == 0) {
        flexfec_sequence = 1;
      }
      if (selection.wire.video.rtx && rtx_sequence == 0) {
        rtx_sequence = 1;
      }
      if (timestamp == 0) {
        timestamp = 1;
      }
      auto runtime = std::unique_ptr<ActiveVideoRuntime> {new (std::nothrow) ActiveVideoRuntime};
      if (!runtime) {
        return nullptr;
      }
      runtime->peer = peer;
      runtime->generation = selection.wire.video.video_generation;
      runtime->display_lease = std::move(display_lease);
      runtime->mail = std::shared_ptr<safe::mail_raw_t> {new (std::nothrow) safe::mail_raw_t};
      const auto family = peer.family == IpAddressFamily::ipv6 ? media::ip_family::ipv6 : media::ip_family::ipv4;
      runtime->sender = std::shared_ptr<HostVideoSender> {new (std::nothrow) HostVideoSender(
        HostVideoSenderConfig {
          .peer = peer,
          .forward_path = forward->path,
          .forward_path_generation = forward->generation,
          .video = selection.wire.video,
          .initial_sequence = sequence,
          .initial_flexfec_sequence = flexfec_sequence,
          .initial_rtx_sequence = rtx_sequence,
          .initial_timestamp = timestamp,
          .frame_id_origin = selection.wire.frame_id_origin,
          .initial_recovery_epoch = selection.wire.recovery_epoch,
          .maximum_access_unit_bytes = selection.wire.video.maximum_complete_access_unit_bytes,
          .maximum_capture_to_present_microseconds = selection.wire.video.maximum_frame_age_microseconds,
          .aggregate_pacing_bits_per_second = selection.aggregate_pacing_bits_per_second,
          .reserved_overhead_bits_per_second = selection.reserved_overhead_bits_per_second,
          .path_payload_ceiling = selection.path_payload_ceiling,
          .feedback_sender_ssrc = selection.feedback_sender_ssrc,
          .audio_feedback_ssrc = selection.audio_feedback_ssrc,
          .network_profile = selection.network_profile,
          .family = family,
          .capture_mail = runtime->mail,
          .reference_invalidation = selection.reference_invalidation,
        },
        *srtp_
      )};
      if (!runtime->mail || !runtime->sender || !runtime->sender->ready()) {
        queue_video_retirement(std::move(runtime));
        return nullptr;
      }
      runtime->sender->update_decoder_credit(decoder_credit);
      if (!runtime->sender->start()) {
        queue_video_retirement(std::move(runtime));
        return nullptr;
      }
      return runtime;
    }

    /** @brief Start existing capture/VDD/hardware encode only after prior ownership is quiescent. */
    bool start_video_capture(
      ActiveVideoRuntime &runtime,
      const ActiveVideoConfiguration &selection
    ) noexcept {
      if (!runtime.mail || !runtime.sender || runtime.capture_thread.joinable()) {
        return false;
      }
      runtime.mail->event<bool>(mail::idr)->raise(true);
      try {
        const auto mail = runtime.mail;
        const auto sender = runtime.sender;
        auto capture_config = selection.capture;
        runtime.capture_thread = std::jthread([mail, sender, capture_config = std::move(capture_config)]() mutable {
          video::capture(mail, std::move(capture_config), sender->session_key(), sender->egress());
          sender->close();
        });
      } catch (...) {
        return false;
      }
      return true;
    }

    /**
     * @brief Return whether one cached semantic ATTACH exactly matches the request and association.
     *
     * @param cached Retained successful semantic ATTACH outcome.
     * @param peer Association presenting the repeated intent.
     * @param connection_generation Current association generation.
     * @param request Repeated decoded ATTACH request.
     * @return True only for an exact same-association semantic replay.
     */
    [[nodiscard]] bool matches_attach_intent(
      const AttachIntentOutcome &cached,
      const PeerEndpoint &peer,
      const std::uint32_t connection_generation,
      const AttachRequestPayload &request
    ) const noexcept {
      return cached.active && cached.peer == peer && cached.connection_generation == connection_generation &&
             cached.intent_id == request.intent_id && cached.session_id == request.session_id && crypto_ &&
             crypto_->equal_secret(cached.attach_token, request.attach_token) &&
             crypto_->equal_secret(cached.successor_attach_token, request.successor_attach_token);
    }

    /**
     * @brief Find a retained ATTACH outcome by its globally session-unique intent identifier.
     *
     * @param intent_id Nonzero client-selected semantic intent identifier.
     * @return Borrowed retained outcome, or null when the bounded cache has no match.
     */
    [[nodiscard]] const AttachIntentOutcome *find_attach_intent(const Identifier128 &intent_id) const noexcept {
      const auto found = std::ranges::find_if(attach_intent_outcomes_, [&](const AttachIntentOutcome &candidate) {
        return candidate.active && candidate.intent_id == intent_id;
      });
      return found == attach_intent_outcomes_.end() ? nullptr : &*found;
    }

    /**
     * @brief Retain one successful semantic ATTACH in the bounded replay ring.
     *
     * @param peer Association on which authority committed.
     * @param connection_generation Exact committed connection generation.
     * @param request Original decoded semantic request.
     * @param response Exact successful response values.
     */
    void remember_attach_intent(
      const PeerEndpoint &peer,
      const std::uint32_t connection_generation,
      const AttachRequestPayload &request,
      const AttachResponsePayload &response
    ) noexcept {
      attach_intent_outcomes_[next_attach_intent_outcome_] = {
        .intent_id = request.intent_id,
        .session_id = request.session_id,
        .attach_token = request.attach_token,
        .successor_attach_token = request.successor_attach_token,
        .peer = peer,
        .connection_generation = connection_generation,
        .response = response,
        .active = true,
      };
      next_attach_intent_outcome_ = (next_attach_intent_outcome_ + 1U) % attach_intent_outcomes_.size();
    }

    /**
     * @brief Preflight exact persistent SSRC-history capacity and uniqueness without mutation.
     *
     * @param ssrcs Complete new-generation SSRC set.
     * @return True only when every value is nonzero, unique, new to the session, and fits the 512-entry history.
     */
    [[nodiscard]] bool can_retain_session_ssrcs(const std::span<const std::uint32_t> ssrcs) const noexcept {
      std::array<std::uint32_t, 8> additions {};
      std::size_t addition_count = 0;
      const auto history = std::span {session_ssrc_history_}.first(session_ssrc_history_count_);
      for (const auto ssrc : ssrcs) {
        if (ssrc == 0 || std::ranges::find(history, ssrc) != history.end() ||
            std::ranges::find(std::span {additions}.first(addition_count), ssrc) !=
              std::span {additions}.first(addition_count).end()) {
          return false;
        }
        if (addition_count == additions.size()) {
          return false;
        }
        additions[addition_count++] = ssrc;
      }
      if (addition_count > session_ssrc_history_.size() - session_ssrc_history_count_) {
        return false;
      }
      return true;
    }

    /**
     * @brief Commit SSRCs already accepted by `can_retain_session_ssrcs()` without failure.
     *
     * @param ssrcs Exact preflighted SSRC span.
     */
    void retain_preflighted_session_ssrcs(const std::span<const std::uint32_t> ssrcs) noexcept {
      std::ranges::copy(
        ssrcs,
        session_ssrc_history_.begin() + static_cast<std::ptrdiff_t>(session_ssrc_history_count_)
      );
      session_ssrc_history_count_ += ssrcs.size();
    }

    /** @brief Erase the completed session's SSRC replay-namespace history. */
    void clear_session_ssrc_history() noexcept {
      std::ranges::fill(session_ssrc_history_, 0);
      session_ssrc_history_count_ = 0;
    }

    /**
     * @brief Deduplicate and retain one preflighted prior association until full successor readiness.
     *
     * @param peer Prior association candidate.
     * @param successor Fresh authoritative association that must never enter its own retirement set.
     */
    void retain_preflighted_retiring_peer(const PeerEndpoint &peer, const PeerEndpoint &successor) noexcept {
      if (!peer.valid() || peer == successor) {
        return;
      }
      const auto live = std::span {retiring_attach_peers_}.first(retiring_attach_peer_count_);
      if (std::ranges::find(live, peer) != live.end()) {
        return;
      }
      retiring_attach_peers_[retiring_attach_peer_count_++] = peer;
    }

    /**
     * @brief Return whether a committed successor barrier still owns delayed teardown for one peer.
     *
     * @param peer Association queried by media retirement or path discovery.
     * @return True while the aggregate successor barrier still protects the peer's SRTP/path ownership.
     */
    [[nodiscard]] bool is_retiring_attach_peer(const PeerEndpoint &peer) const noexcept {
      std::scoped_lock lock(session_mutex_);
      const auto retiring = std::span {retiring_attach_peers_}.first(retiring_attach_peer_count_);
      return std::ranges::find(retiring, peer) != retiring.end();
    }

    /**
     * @brief Record one pre-commit rejection while leaving the prior authority untouched.
     *
     * @param connection_generation Rejected fresh association generation.
     * @param started_microseconds Monotonic semantic request start.
     */
    void record_reconnect_rejected(
      const std::uint32_t connection_generation,
      const std::uint64_t started_microseconds
    ) noexcept {
      ++reconnect_telemetry_.rejected;
      reconnect_telemetry_.latest_connection_generation = connection_generation;
      reconnect_telemetry_.latest_outcome = ReconnectOutcome::rejected;
      reconnect_telemetry_.latest_request_to_commit_microseconds = 0;
      reconnect_telemetry_.latest_commit_to_ready_microseconds = 0;
      reconnect_telemetry_.latest_total_microseconds = monotonic_microseconds() - started_microseconds;
    }

    /** @brief Record and clear a committed replacement that failed before full readiness. */
    void record_reconnect_failed() noexcept {
      if (!attach_readiness_.active) {
        return;
      }
      ++reconnect_telemetry_.failed;
      reconnect_telemetry_.latest_connection_generation = attach_readiness_.connection_generation;
      reconnect_telemetry_.latest_outcome = ReconnectOutcome::failed;
      reconnect_telemetry_.latest_commit_to_ready_microseconds = 0;
      reconnect_telemetry_.latest_total_microseconds =
        monotonic_microseconds() - attach_readiness_.request_started_microseconds;
      attach_readiness_ = {};
    }

    /** @brief Queue every retained prior association after all replacement lanes are ready. */
    void complete_attach_readiness_if_possible() noexcept {
      std::scoped_lock lock(session_mutex_);
      if (!attach_readiness_.active || !attach_readiness_.input_baseline_ready || !attach_readiness_.audio_ready ||
          !attach_readiness_.video_acknowledged || !attach_readiness_.video_activated ||
          (attach_readiness_.microphone_selected &&
           (!attach_readiness_.microphone_terminal ||
            (attach_readiness_.microphone_required && !attach_readiness_.microphone_ready)))) {
        return;
      }
      std::size_t required_close_slots = 0;
      for (std::size_t index = 0; index < retiring_attach_peer_count_; ++index) {
        const auto &retiring = retiring_attach_peers_[index];
        if (retiring == attach_readiness_.successor_peer) {
          continue;
        }
        const auto pending = std::span {pending_association_closes_}.first(pending_association_close_count_);
        if (std::ranges::find(pending, retiring) == pending.end()) {
          ++required_close_slots;
        }
      }
      if (required_close_slots > pending_association_closes_.size() - pending_association_close_count_) {
        return;
      }
      for (std::size_t index = 0; index < retiring_attach_peer_count_; ++index) {
        if (retiring_attach_peers_[index] != attach_readiness_.successor_peer) {
          (void) queue_association_close(retiring_attach_peers_[index]);
        }
        retiring_attach_peers_[index] = {};
      }
      retiring_attach_peer_count_ = 0;
      const auto ready_at = monotonic_microseconds();
      ++reconnect_telemetry_.completed;
      reconnect_telemetry_.latest_connection_generation = attach_readiness_.connection_generation;
      reconnect_telemetry_.latest_outcome = ReconnectOutcome::ready;
      reconnect_telemetry_.latest_commit_to_ready_microseconds = ready_at - attach_readiness_.committed_microseconds;
      reconnect_telemetry_.latest_total_microseconds = ready_at - attach_readiness_.request_started_microseconds;
      attach_readiness_ = {};
    }

    /** @brief Queue every retained prior association during terminal session teardown. */
    void queue_all_retiring_attach_peers() noexcept {
      for (std::size_t index = 0; index < retiring_attach_peer_count_; ++index) {
        (void) queue_association_close(retiring_attach_peers_[index]);
        retiring_attach_peers_[index] = {};
      }
      retiring_attach_peer_count_ = 0;
    }

    /** @brief Clear secret-bearing intent cache and every incomplete handoff owner. */
    void clear_attach_lifecycle() noexcept {
      record_reconnect_failed();
      for (auto &outcome : attach_intent_outcomes_) {
        outcome = {};
      }
      next_attach_intent_outcome_ = 0;
      for (std::size_t index = 0; index < retiring_attach_peer_count_; ++index) {
        retiring_attach_peers_[index] = {};
      }
      retiring_attach_peer_count_ = 0;
      video_start_pending_ = false;
    }

    /** @brief Terminate a session whose required authenticated video configuration failed. */
    void fail_required_video_session(const PeerEndpoint &peer) noexcept {
      std::unique_ptr<ActiveAudioRuntime> audio;
      std::unique_ptr<ActiveVideoRuntime> video;
      std::unique_ptr<LspMicrophoneReceiver> microphone;
      {
        std::scoped_lock lock(session_mutex_);
        if (authority_.snapshot().state != SessionState::ready) {
          (void) authority_.stop_from_host(NeutralizationReason::transport_loss);
        }
        if (active_process_generation_ != 0) {
          (void) proc::proc.terminate_lsp_generation(active_process_generation_);
          active_process_generation_ = 0;
        }
        active_client_.reset();
        active_audio_configuration_.reset();
        active_video_configuration_.reset();
        pending_inbound_path_probe_ = {};
        active_microphone_configuration_.reset();
        active_microphone_required_ = false;
        audio = std::move(audio_runtime_);
        video = std::move(video_runtime_);
        microphone = std::move(microphone_runtime_);
        ssrc_registry_.reset();
        detached_deadline_microseconds_ = 0;
        (void) queue_association_close(peer);
        queue_all_retiring_attach_peers();
        clear_attach_lifecycle();
        clear_session_ssrc_history();
      }
      queue_audio_retirement(std::move(audio));
      queue_video_retirement(std::move(video));
      queue_microphone_retirement(std::move(microphone));
    }

    bool send(const PeerEndpoint &peer, const std::span<const std::uint8_t> frame) noexcept override {
      return dtls_ && dtls_->send_application_data(peer, frame) == WolfsslDtlsOperationResult::accepted;
    }

    void close(const PeerEndpoint &peer) noexcept override {
      if (dtls_) {
        dtls_->close_association(peer);
      }
    }

    std::expected<StartResponsePayload, ControlStatus> start_input(
      const PeerEndpoint &peer,
      const TrustedClient &client,
      const std::uint32_t connection_generation,
      const StartRequestPayload &request
    ) noexcept override {
      std::scoped_lock lock(session_mutex_);
      const auto forward = find_forward_path(peer);
      if (!forward || !forward->path || forward->generation != connection_generation) {
        return std::unexpected(ControlStatus::stale_generation);
      }
      const auto applications = applications_->snapshot();
      if (!applications || std::ranges::none_of(*applications, [&](const ControlApplication &application) {
            return application.id == request.application_id;
          })) {
        return std::unexpected(ControlStatus::malformed);
      }
      if (authority_.snapshot().state != SessionState::ready) {
        return std::unexpected(ControlStatus::busy);
      }
      if (proc::proc.running() > 0) {
        return std::unexpected(ControlStatus::busy);
      }
      clear_session_ssrc_history();

      const auto family = peer.family == IpAddressFamily::ipv6 ? input_plane::ip_family::ipv6 : input_plane::ip_family::ipv4;
      const auto media_family = peer.family == IpAddressFamily::ipv6 ? media::ip_family::ipv6 : media::ip_family::ipv4;
      if (!media::make_path_payload_limit(media_family, request.offered_maximum_udp_payload)) {
        return std::unexpected(ControlStatus::malformed);
      }
      const auto pointer_budget = input_plane::wire_bits_per_second(family, input_plane::pointer_payload_size, request.pointer_rate);
      const auto controller_budget = input_plane::wire_bits_per_second(family, 96, request.controller_rate);
      const auto sensor_budget = input_plane::wire_bits_per_second(family, 32, request.sensor_rate);
      const auto reconciliation_budget = input_plane::wire_bits_per_second(family, input_plane::maximum_core_state_bytes, request.reconciliation_rate);
      const auto total_budget = pointer_budget + controller_budget + sensor_budget + reconciliation_budget;
      if (pointer_budget == 0 || controller_budget == 0 || sensor_budget == 0 || reconciliation_budget == 0 ||
          total_budget > input_plane::maximum_input_wire_bits_per_second || total_budget > request.maximum_input_wire_bits_per_second) {
        return std::unexpected(ControlStatus::path_capacity_insufficient);
      }

      StartAuthority start;
      if (!crypto_->random(start.session_id) || !crypto_->random(start.attach_token)) {
        return std::unexpected(ControlStatus::internal_failure);
      }
      start.generations = {
        .connection = connection_generation,
        .stream = next_stream_generation_,
        .video = 1,
        .audio = 1,
        .microphone = 1,
        .input = 1,
      };
      if (next_stream_generation_ == std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(ControlStatus::internal_failure);
      }

      std::array<std::uint8_t, 28> ssrc_bytes {};
      if (!crypto_->random(ssrc_bytes)) {
        return std::unexpected(ControlStatus::internal_failure);
      }
      const auto input_ssrc = next_unique_nonzero_ssrc(
        wire::read_be<std::uint32_t>(std::span<const std::uint8_t> {ssrc_bytes}.first<4>()),
        {}
      );
      const std::array input_reserved {input_ssrc};
      const auto acknowledgement_ssrc = next_unique_nonzero_ssrc(
        wire::read_be<std::uint32_t>(std::span<const std::uint8_t> {ssrc_bytes}.subspan<4, 4>()),
        input_reserved
      );
      const std::array audio_reserved {input_ssrc, acknowledgement_ssrc};
      const auto audio_ssrc = next_unique_nonzero_ssrc(
        wire::read_be<std::uint32_t>(std::span<const std::uint8_t> {ssrc_bytes}.subspan<8, 4>()),
        audio_reserved
      );
      const std::array microphone_reserved {input_ssrc, acknowledgement_ssrc, audio_ssrc};
      const auto microphone_ssrc = next_unique_nonzero_ssrc(
        wire::read_be<std::uint32_t>(std::span<const std::uint8_t> {ssrc_bytes}.subspan<12, 4>()),
        microphone_reserved
      );
      const std::array video_reserved {input_ssrc, acknowledgement_ssrc, audio_ssrc, microphone_ssrc};
      const auto video_ssrc = next_unique_nonzero_ssrc(
        wire::read_be<std::uint32_t>(std::span<const std::uint8_t> {ssrc_bytes}.subspan<16, 4>()),
        video_reserved
      );
      const std::array repair_reserved {input_ssrc, acknowledgement_ssrc, audio_ssrc, microphone_ssrc, video_ssrc};
      const auto repair_ssrc = next_unique_nonzero_ssrc(
        wire::read_be<std::uint32_t>(std::span<const std::uint8_t> {ssrc_bytes}.subspan<20, 4>()),
        repair_reserved
      );
      const std::array rtx_reserved {input_ssrc, acknowledgement_ssrc, audio_ssrc, microphone_ssrc, video_ssrc, repair_ssrc};
      const auto rtx_ssrc = next_unique_nonzero_ssrc(
        wire::read_be<std::uint32_t>(std::span<const std::uint8_t> {ssrc_bytes}.subspan<24, 4>()),
        rtx_reserved
      );
      const auto audio_selection = select_audio(request, start.generations.audio, audio_ssrc);
      if (!audio_selection) {
        return std::unexpected(ControlStatus::unsupported_media_tuple);
      }
      const auto microphone_selection = select_microphone(
        request,
        client,
        start.generations.microphone,
        microphone_ssrc
      );
      if (!microphone_selection) {
        return std::unexpected(microphone_selection.error());
      }
      auto video_selection = select_video(
        peer,
        request,
        start.session_id,
        start.generations.stream,
        start.generations.video,
        video_ssrc,
        repair_ssrc,
        rtx_ssrc
      );
      if (!video_selection) {
        return std::unexpected(video_selection.error());
      }
      const auto feedback_bits_per_second = maximum_feedback_bits_per_second(peer);
      if (!feedback_bits_per_second ||
          *feedback_bits_per_second > std::numeric_limits<std::uint64_t>::max() - audio_selection->bitrate) {
        (void) proc::proc.terminate_lsp_generation(video_selection->process_generation);
        return std::unexpected(ControlStatus::internal_failure);
      }
      video_selection->reserved_overhead_bits_per_second =
        static_cast<std::uint64_t>(audio_selection->bitrate) + *feedback_bits_per_second;
      if (video_selection->reserved_overhead_bits_per_second >=
          video_selection->aggregate_pacing_bits_per_second) {
        (void) proc::proc.terminate_lsp_generation(video_selection->process_generation);
        return std::unexpected(ControlStatus::path_capacity_insufficient);
      }
      video_selection->feedback_sender_ssrc = input_ssrc;
      video_selection->input_acknowledgement_ssrc = acknowledgement_ssrc;
      video_selection->audio_feedback_ssrc = audio_ssrc;
      video_selection->path_payload_ceiling = request.offered_maximum_udp_payload;
      video_selection->network_profile = request.network_profile;
      const auto initial_forward_rate = std::min(
        video_selection->aggregate_pacing_bits_per_second,
        video_selection->wire.video.selected_bits_per_second + video_selection->reserved_overhead_bits_per_second
      );
      if (!forward->path->reconfigure(initial_forward_rate, video_selection->wire.video.initial_udp_payload_size)) {
        (void) proc::proc.terminate_lsp_generation(video_selection->process_generation);
        return std::unexpected(ControlStatus::path_capacity_insufficient);
      }
      constexpr std::uint8_t input_payload_type = 96;
      std::array<SsrcAssignment, 6> assignments {
        SsrcAssignment {
          .ssrc = input_ssrc,
          .payload_type = input_payload_type,
          .lane = MediaLane::input,
          .direction = MediaDirection::client_to_host,
          .format = PayloadFormat::lsp_input,
          .clock_rate = 1'000'000,
          .generation = start.generations.input,
        },
        SsrcAssignment {
          .ssrc = audio_ssrc,
          .payload_type = audio_selection->audio_payload_type,
          .lane = MediaLane::audio,
          .direction = MediaDirection::host_to_client,
          .format = PayloadFormat::opus,
          .clock_rate = audio_selection->clock_rate,
          .generation = audio_selection->audio_generation,
        },
        SsrcAssignment {
          .ssrc = video_selection->wire.video.primary_ssrc,
          .payload_type = video_selection->wire.video.primary_payload_type,
          .lane = MediaLane::video_primary,
          .direction = MediaDirection::host_to_client,
          .format = video_selection->wire.video.codec == VideoCodec::h264 ? PayloadFormat::h264 :
                    video_selection->wire.video.codec == VideoCodec::hevc ? PayloadFormat::hevc :
                                                                            PayloadFormat::av1,
          .clock_rate = video_selection->wire.video.clock_rate,
          .generation = video_selection->wire.video.video_generation,
        },
        SsrcAssignment {},
        SsrcAssignment {},
        SsrcAssignment {},
      };
      std::size_t assignment_count = 3;
      if (video_selection->wire.video.flexfec) {
        assignments[assignment_count++] = SsrcAssignment {
          .ssrc = video_selection->wire.video.flexfec->repair_ssrc,
          .payload_type = video_selection->wire.video.flexfec->repair_payload_type,
          .lane = MediaLane::video_repair,
          .direction = MediaDirection::host_to_client,
          .format = PayloadFormat::flexfec,
          .clock_rate = video_selection->wire.video.clock_rate,
          .generation = video_selection->wire.video.video_generation,
          .associated_primary_ssrc = video_selection->wire.video.primary_ssrc,
        };
      }
      if (video_selection->wire.video.rtx) {
        assignments[assignment_count++] = SsrcAssignment {
          .ssrc = video_selection->wire.video.rtx->rtx_ssrc,
          .payload_type = video_selection->wire.video.rtx->rtx_payload_type,
          .lane = MediaLane::video_rtx,
          .direction = MediaDirection::host_to_client,
          .format = PayloadFormat::video_rtx,
          .clock_rate = video_selection->wire.video.clock_rate,
          .generation = video_selection->wire.video.video_generation,
          .associated_primary_ssrc = video_selection->wire.video.primary_ssrc,
        };
      }
      if (*microphone_selection) {
        assignments[assignment_count++] = SsrcAssignment {
          .ssrc = (*microphone_selection)->microphone_ssrc,
          .payload_type = (*microphone_selection)->microphone_payload_type,
          .lane = MediaLane::microphone,
          .direction = MediaDirection::client_to_host,
          .format = PayloadFormat::opus,
          .clock_rate = (*microphone_selection)->clock_rate,
          .generation = (*microphone_selection)->microphone_generation,
        };
      }
      auto registry = SsrcRegistry::create(std::span<const SsrcAssignment> {assignments}.first(assignment_count));
      if (!registry) {
        (void) proc::proc.terminate_lsp_generation(video_selection->process_generation);
        return std::unexpected(ControlStatus::internal_failure);
      }
      std::array<std::uint32_t, 7> assigned_ssrcs {
        input_ssrc,
        acknowledgement_ssrc,
        audio_selection->audio_ssrc,
        video_selection->wire.video.primary_ssrc,
      };
      std::size_t assigned_ssrc_count = 4;
      if (*microphone_selection) {
        assigned_ssrcs[assigned_ssrc_count++] = (*microphone_selection)->microphone_ssrc;
      }
      if (video_selection->wire.video.flexfec) {
        assigned_ssrcs[assigned_ssrc_count++] = video_selection->wire.video.flexfec->repair_ssrc;
      }
      if (video_selection->wire.video.rtx) {
        assigned_ssrcs[assigned_ssrc_count++] = video_selection->wire.video.rtx->rtx_ssrc;
      }
      const auto assigned_ssrc_span = std::span {assigned_ssrcs}.first(assigned_ssrc_count);
      if (!can_retain_session_ssrcs(assigned_ssrc_span)) {
        (void) proc::proc.terminate_lsp_generation(video_selection->process_generation);
        return std::unexpected(ControlStatus::internal_failure);
      }
      const AuthenticatedClient authority_client {
        .client_id = client.client_id,
        .connection_generation = connection_generation,
        .revocation_generation = client.revocation_generation,
        .permissions = client.permissions,
      };
      if (authority_.start(authority_client, start) != AuthorityResult::accepted) {
        (void) proc::proc.terminate_lsp_generation(video_selection->process_generation);
        return std::unexpected(ControlStatus::busy);
      }
      const InputSessionMapping mapping {
        .peer = peer,
        .forward_path = forward->path,
        .client_id = client.client_id,
        .connection_generation = connection_generation,
        .session_generation = start.generations.stream,
        .input_generation = start.generations.input,
        .input_ssrc = input_ssrc,
        .acknowledgement_ssrc = acknowledgement_ssrc,
        .input_payload_type = input_payload_type,
        .controller_output_enabled = client.permissions.contains(Permission::controller_output),
      };
      if (!input_owner_->configure(mapping)) {
        (void) authority_.stop_from_host(NeutralizationReason::explicit_stop);
        (void) proc::proc.terminate_lsp_generation(video_selection->process_generation);
        return std::unexpected(ControlStatus::internal_failure);
      }
      retain_preflighted_session_ssrcs(assigned_ssrc_span);
      active_client_ = authority_client;
      active_process_generation_ = video_selection->process_generation;
      active_rates_ = {
        .pointer = request.pointer_rate,
        .controller = request.controller_rate,
        .sensor = request.sensor_rate,
        .reconciliation = request.reconciliation_rate,
        .budget = total_budget,
      };
      clear_attach_lifecycle();
      detached_deadline_microseconds_ = 0;
      ssrc_registry_ = std::move(*registry);
      active_audio_configuration_ = AudioConfigPayload {
        .session_id = start.session_id,
        .stream_generation = start.generations.stream,
        .audio = *audio_selection,
      };
      active_microphone_configuration_ = *microphone_selection ?
                                           std::optional<MicrophoneConfigPayload> {MicrophoneConfigPayload {
                                             .session_id = start.session_id,
                                             .stream_generation = start.generations.stream,
                                             .microphone = **microphone_selection,
                                           }} :
                                           std::nullopt;
      active_microphone_required_ = request.microphone_offer && request.microphone_offer->required;
      const auto response_video = video_selection->wire.video;
      active_video_configuration_ = std::move(*video_selection);
      ++next_stream_generation_;
      return StartResponsePayload {
        .session_id = start.session_id,
        .attach_token = start.attach_token,
        .stream_generation = start.generations.stream,
        .input_generation = start.generations.input,
        .input_ssrc = input_ssrc,
        .acknowledgement_ssrc = acknowledgement_ssrc,
        .input_payload_type = input_payload_type,
        .pointer_rate = request.pointer_rate,
        .controller_rate = request.controller_rate,
        .sensor_rate = request.sensor_rate,
        .reconciliation_rate = request.reconciliation_rate,
        .reserved_input_wire_bits_per_second = total_budget,
        .baseline_required = true,
        .audio = *audio_selection,
        .microphone = *microphone_selection,
        .video = response_video,
      };
    }

    std::expected<AttachResponsePayload, ControlStatus> attach_input(
      const PeerEndpoint &peer,
      const TrustedClient &client,
      const std::uint32_t connection_generation,
      const AttachRequestPayload &request
    ) noexcept override {
      std::scoped_lock lock(session_mutex_);
      if (const auto *cached = find_attach_intent(request.intent_id)) {
        if (matches_attach_intent(*cached, peer, connection_generation, request)) {
          return cached->response;
        }
        return std::unexpected(ControlStatus::stale_generation);
      }
      const auto attempt_started_microseconds = monotonic_microseconds();
      ++reconnect_telemetry_.attempts;
      reconnect_telemetry_.latest_connection_generation = connection_generation;
      const auto reject = [&](const ControlStatus status) -> std::expected<AttachResponsePayload, ControlStatus> {
        record_reconnect_rejected(connection_generation, attempt_started_microseconds);
        return std::unexpected(status);
      };
      const auto forward = find_forward_path(peer);
      if (!forward || !forward->path || forward->generation != connection_generation) {
        return reject(ControlStatus::stale_generation);
      }
      if (active_process_generation_ == 0 || proc::proc.running() <= 0 ||
          !active_audio_configuration_ || !active_video_configuration_ ||
          active_video_configuration_->feedback_sender_ssrc == 0 ||
          active_video_configuration_->input_acknowledgement_ssrc == 0) {
        return reject(ControlStatus::stale_generation);
      }
      const auto previous_mapping = input_owner_ ? input_owner_->mapping() : std::nullopt;
      std::array<PeerEndpoint, 4> retiring_candidates {};
      std::size_t retiring_candidate_count = 0;
      const auto add_retiring_candidate = [&](const PeerEndpoint &candidate) {
        if (!candidate.valid() || candidate == peer ||
            std::ranges::find(std::span {retiring_candidates}.first(retiring_candidate_count), candidate) !=
              std::span {retiring_candidates}.first(retiring_candidate_count).end()) {
          return;
        }
        retiring_candidates[retiring_candidate_count++] = candidate;
      };
      if (previous_mapping) {
        add_retiring_candidate(previous_mapping->peer);
      }
      if (audio_runtime_) {
        add_retiring_candidate(audio_runtime_->peer);
      }
      if (video_runtime_) {
        add_retiring_candidate(video_runtime_->peer);
      }
      if (microphone_runtime_) {
        add_retiring_candidate(microphone_runtime_->peer());
      }
      std::size_t additional_retiring_peers = 0;
      const auto retained = std::span {retiring_attach_peers_}.first(retiring_attach_peer_count_);
      for (std::size_t index = 0; index < retiring_candidate_count; ++index) {
        if (std::ranges::find(retained, retiring_candidates[index]) == retained.end()) {
          ++additional_retiring_peers;
        }
      }
      if (additional_retiring_peers > retiring_attach_peers_.size() - retiring_attach_peer_count_) {
        return reject(ControlStatus::busy);
      }
      std::array<std::uint8_t, 28> ssrc_bytes {};
      if (!crypto_->random(ssrc_bytes)) {
        return reject(ControlStatus::internal_failure);
      }
      std::array<std::uint32_t, 520> reserved_ssrcs {};
      if (session_ssrc_history_count_ > reserved_ssrcs.size() - 7U) {
        return reject(ControlStatus::busy);
      }
      std::ranges::copy(
        std::span {session_ssrc_history_}.first(session_ssrc_history_count_),
        reserved_ssrcs.begin()
      );
      auto reserved_ssrc_count = session_ssrc_history_count_;
      const auto input_ssrc = next_unique_nonzero_ssrc(
        wire::read_be<std::uint32_t>(std::span<const std::uint8_t> {ssrc_bytes}.first<4>()),
        std::span<const std::uint32_t> {reserved_ssrcs}.first(reserved_ssrc_count)
      );
      if (input_ssrc == 0) {
        return reject(ControlStatus::internal_failure);
      }
      reserved_ssrcs[reserved_ssrc_count++] = input_ssrc;
      const auto acknowledgement_ssrc = next_unique_nonzero_ssrc(
        wire::read_be<std::uint32_t>(std::span<const std::uint8_t> {ssrc_bytes}.subspan<4, 4>()),
        std::span<const std::uint32_t> {reserved_ssrcs}.first(reserved_ssrc_count)
      );
      if (acknowledgement_ssrc == 0) {
        return reject(ControlStatus::internal_failure);
      }
      reserved_ssrcs[reserved_ssrc_count++] = acknowledgement_ssrc;
      const auto audio_ssrc = next_unique_nonzero_ssrc(
        wire::read_be<std::uint32_t>(std::span<const std::uint8_t> {ssrc_bytes}.subspan<8, 4>()),
        std::span<const std::uint32_t> {reserved_ssrcs}.first(reserved_ssrc_count)
      );
      if (audio_ssrc == 0) {
        return reject(ControlStatus::internal_failure);
      }
      reserved_ssrcs[reserved_ssrc_count++] = audio_ssrc;
      const auto microphone_ssrc = next_unique_nonzero_ssrc(
        wire::read_be<std::uint32_t>(std::span<const std::uint8_t> {ssrc_bytes}.subspan<12, 4>()),
        std::span<const std::uint32_t> {reserved_ssrcs}.first(reserved_ssrc_count)
      );
      if (microphone_ssrc == 0) {
        return reject(ControlStatus::internal_failure);
      }
      reserved_ssrcs[reserved_ssrc_count++] = microphone_ssrc;
      const auto video_ssrc = next_unique_nonzero_ssrc(
        wire::read_be<std::uint32_t>(std::span<const std::uint8_t> {ssrc_bytes}.subspan<16, 4>()),
        std::span<const std::uint32_t> {reserved_ssrcs}.first(reserved_ssrc_count)
      );
      if (video_ssrc == 0) {
        return reject(ControlStatus::internal_failure);
      }
      reserved_ssrcs[reserved_ssrc_count++] = video_ssrc;
      const auto repair_ssrc = next_unique_nonzero_ssrc(
        wire::read_be<std::uint32_t>(std::span<const std::uint8_t> {ssrc_bytes}.subspan<20, 4>()),
        std::span<const std::uint32_t> {reserved_ssrcs}.first(reserved_ssrc_count)
      );
      if (repair_ssrc == 0) {
        return reject(ControlStatus::internal_failure);
      }
      reserved_ssrcs[reserved_ssrc_count++] = repair_ssrc;
      const auto rtx_ssrc = next_unique_nonzero_ssrc(
        wire::read_be<std::uint32_t>(std::span<const std::uint8_t> {ssrc_bytes}.subspan<24, 4>()),
        std::span<const std::uint32_t> {reserved_ssrcs}.first(reserved_ssrc_count)
      );
      if (rtx_ssrc == 0) {
        return reject(ControlStatus::internal_failure);
      }
      const AuthenticatedClient authority_client {
        .client_id = client.client_id,
        .connection_generation = connection_generation,
        .revocation_generation = client.revocation_generation,
        .permissions = client.permissions,
      };
      const auto prepared = authority_.prepare_attach(
        authority_client,
        request.session_id,
        request.attach_token,
        request.successor_attach_token
      );
      if (prepared == AuthorityResult::permission_denied) {
        return reject(ControlStatus::permission_denied);
      }
      if (prepared == AuthorityResult::token_mismatch) {
        return reject(ControlStatus::authentication_failed);
      }
      if (prepared == AuthorityResult::not_owner || prepared == AuthorityResult::stale_generation ||
          prepared == AuthorityResult::generation_exhausted) {
        return reject(ControlStatus::stale_generation);
      }
      if (prepared == AuthorityResult::malformed) {
        return reject(ControlStatus::malformed);
      }
      if (prepared != AuthorityResult::accepted) {
        return reject(ControlStatus::internal_failure);
      }
      const auto prior_snapshot = authority_.snapshot();
      if (prior_snapshot.generations.input == std::numeric_limits<std::uint32_t>::max() ||
          prior_snapshot.generations.video == std::numeric_limits<std::uint32_t>::max()) {
        return reject(ControlStatus::stale_generation);
      }
      const auto next_input_generation = prior_snapshot.generations.input + 1U;
      const auto next_video_generation = prior_snapshot.generations.video + 1U;
      const auto next_audio_generation = prior_snapshot.generations.audio + 1U;
      const auto next_microphone_generation = prior_snapshot.generations.microphone + 1U;
      auto audio_selection = active_audio_configuration_->audio;
      audio_selection.audio_generation = next_audio_generation;
      audio_selection.audio_ssrc = audio_ssrc;
      const auto microphone_permitted = client.permissions.contains(Permission::microphone);
      if (active_microphone_configuration_ && active_microphone_required_ && !microphone_permitted) {
        return reject(ControlStatus::permission_denied);
      }
      auto microphone_selection = active_microphone_configuration_ && microphone_permitted ?
                                    std::optional<MicrophoneSelectionPayload> {active_microphone_configuration_->microphone} :
                                    std::nullopt;
      if (microphone_selection) {
        microphone_selection->microphone_generation = next_microphone_generation;
        microphone_selection->microphone_ssrc = microphone_ssrc;
      }
      ActiveVideoConfiguration video_selection;
      try {
        video_selection = *active_video_configuration_;
      } catch (...) {
        return reject(ControlStatus::internal_failure);
      }
      video_selection.wire.video.video_generation = next_video_generation;
      video_selection.wire.video.primary_ssrc = video_ssrc;
      if (video_selection.wire.video.flexfec) {
        video_selection.wire.video.flexfec->repair_ssrc = repair_ssrc;
      }
      if (video_selection.wire.video.rtx) {
        video_selection.wire.video.rtx->rtx_ssrc = rtx_ssrc;
      }
      video_selection.feedback_sender_ssrc = input_ssrc;
      video_selection.input_acknowledgement_ssrc = acknowledgement_ssrc;
      video_selection.audio_feedback_ssrc = audio_ssrc;
      video_selection.wire.session_id = prior_snapshot.session_id;
      video_selection.wire.stream_generation = prior_snapshot.generations.stream;
      std::array<std::uint8_t, 8> frame_origin_bytes {};
      if (!crypto_->random(frame_origin_bytes)) {
        return reject(ControlStatus::internal_failure);
      }
      video_selection.wire.frame_id_origin = wire::read_be<std::uint64_t>(frame_origin_bytes);
      if (video_selection.wire.frame_id_origin == 0) {
        video_selection.wire.frame_id_origin = 1;
      }
      if (!encode_video_config(video_selection.wire)) {
        return reject(ControlStatus::unsupported_media_tuple);
      }
      const auto initial_forward_rate = std::min(
        video_selection.aggregate_pacing_bits_per_second,
        video_selection.wire.video.selected_bits_per_second + video_selection.reserved_overhead_bits_per_second
      );
      if (!forward->path->reconfigure(initial_forward_rate, video_selection.wire.video.initial_udp_payload_size)) {
        return reject(ControlStatus::path_capacity_insufficient);
      }
      constexpr std::uint8_t input_payload_type = 96;
      std::array<SsrcAssignment, 6> assignments {
        SsrcAssignment {
          .ssrc = input_ssrc,
          .payload_type = input_payload_type,
          .lane = MediaLane::input,
          .direction = MediaDirection::client_to_host,
          .format = PayloadFormat::lsp_input,
          .clock_rate = 1'000'000,
          .generation = next_input_generation,
        },
        SsrcAssignment {
          .ssrc = audio_ssrc,
          .payload_type = audio_selection.audio_payload_type,
          .lane = MediaLane::audio,
          .direction = MediaDirection::host_to_client,
          .format = PayloadFormat::opus,
          .clock_rate = audio_selection.clock_rate,
          .generation = next_audio_generation,
        },
        SsrcAssignment {
          .ssrc = video_selection.wire.video.primary_ssrc,
          .payload_type = video_selection.wire.video.primary_payload_type,
          .lane = MediaLane::video_primary,
          .direction = MediaDirection::host_to_client,
          .format = video_selection.wire.video.codec == VideoCodec::h264 ? PayloadFormat::h264 :
                    video_selection.wire.video.codec == VideoCodec::hevc ? PayloadFormat::hevc :
                                                                           PayloadFormat::av1,
          .clock_rate = video_selection.wire.video.clock_rate,
          .generation = video_selection.wire.video.video_generation,
        },
        SsrcAssignment {},
        SsrcAssignment {},
        SsrcAssignment {},
      };
      std::size_t assignment_count = 3;
      if (video_selection.wire.video.flexfec) {
        assignments[assignment_count++] = SsrcAssignment {
          .ssrc = video_selection.wire.video.flexfec->repair_ssrc,
          .payload_type = video_selection.wire.video.flexfec->repair_payload_type,
          .lane = MediaLane::video_repair,
          .direction = MediaDirection::host_to_client,
          .format = PayloadFormat::flexfec,
          .clock_rate = video_selection.wire.video.clock_rate,
          .generation = video_selection.wire.video.video_generation,
          .associated_primary_ssrc = video_selection.wire.video.primary_ssrc,
        };
      }
      if (video_selection.wire.video.rtx) {
        assignments[assignment_count++] = SsrcAssignment {
          .ssrc = video_selection.wire.video.rtx->rtx_ssrc,
          .payload_type = video_selection.wire.video.rtx->rtx_payload_type,
          .lane = MediaLane::video_rtx,
          .direction = MediaDirection::host_to_client,
          .format = PayloadFormat::video_rtx,
          .clock_rate = video_selection.wire.video.clock_rate,
          .generation = video_selection.wire.video.video_generation,
          .associated_primary_ssrc = video_selection.wire.video.primary_ssrc,
        };
      }
      if (microphone_selection) {
        assignments[assignment_count++] = SsrcAssignment {
          .ssrc = microphone_selection->microphone_ssrc,
          .payload_type = microphone_selection->microphone_payload_type,
          .lane = MediaLane::microphone,
          .direction = MediaDirection::client_to_host,
          .format = PayloadFormat::opus,
          .clock_rate = microphone_selection->clock_rate,
          .generation = microphone_selection->microphone_generation,
        };
      }
      auto registry = SsrcRegistry::create(std::span<const SsrcAssignment> {assignments}.first(assignment_count));
      const InputSessionMapping mapping {
        .peer = peer,
        .forward_path = forward->path,
        .client_id = client.client_id,
        .connection_generation = connection_generation,
        .session_generation = prior_snapshot.generations.stream,
        .input_generation = next_input_generation,
        .input_ssrc = input_ssrc,
        .acknowledgement_ssrc = acknowledgement_ssrc,
        .input_payload_type = input_payload_type,
        .controller_output_enabled = client.permissions.contains(Permission::controller_output),
      };
      if (!registry || !input_owner_ || !input_owner_->ready_for_configuration(mapping)) {
        return reject(ControlStatus::internal_failure);
      }
      std::array<std::uint32_t, 7> assigned_ssrcs {
        input_ssrc,
        acknowledgement_ssrc,
        audio_selection.audio_ssrc,
        video_selection.wire.video.primary_ssrc,
      };
      std::size_t assigned_ssrc_count = 4;
      if (microphone_selection) {
        assigned_ssrcs[assigned_ssrc_count++] = microphone_selection->microphone_ssrc;
      }
      if (video_selection.wire.video.flexfec) {
        assigned_ssrcs[assigned_ssrc_count++] = video_selection.wire.video.flexfec->repair_ssrc;
      }
      if (video_selection.wire.video.rtx) {
        assigned_ssrcs[assigned_ssrc_count++] = video_selection.wire.video.rtx->rtx_ssrc;
      }
      const auto assigned_ssrc_span = std::span {assigned_ssrcs}.first(assigned_ssrc_count);
      if (!can_retain_session_ssrcs(assigned_ssrc_span)) {
        return reject(ControlStatus::busy);
      }
      const AttachResponsePayload response {
        .session_id = prior_snapshot.session_id,
        .attach_token = request.successor_attach_token,
        .connection_generation = connection_generation,
        .stream_generation = prior_snapshot.generations.stream,
        .input_generation = next_input_generation,
        .input_ssrc = input_ssrc,
        .acknowledgement_ssrc = acknowledgement_ssrc,
        .input_payload_type = input_payload_type,
        .pointer_rate = active_rates_.pointer,
        .controller_rate = active_rates_.controller,
        .sensor_rate = active_rates_.sensor,
        .reconciliation_rate = active_rates_.reconciliation,
        .reserved_input_wire_bits_per_second = active_rates_.budget,
        .baseline_required = true,
        .audio = audio_selection,
        .microphone = microphone_selection,
        .video = video_selection.wire.video,
      };
      const auto result = authority_.attach(
        authority_client,
        request.session_id,
        request.attach_token,
        request.successor_attach_token
      );
      if (result != AuthorityResult::accepted) {
        return reject(result == AuthorityResult::neutralization_failed ? ControlStatus::internal_failure : ControlStatus::stale_generation);
      }
      input_owner_->commit_configuration(mapping);
      retain_preflighted_session_ssrcs(assigned_ssrc_span);
      const auto snapshot = authority_.snapshot();
      active_client_ = authority_client;
      ssrc_registry_ = std::move(*registry);
      active_audio_configuration_ = AudioConfigPayload {
        .session_id = snapshot.session_id,
        .stream_generation = snapshot.generations.stream,
        .audio = audio_selection,
      };
      active_microphone_configuration_ = microphone_selection ?
                                           std::optional<MicrophoneConfigPayload> {MicrophoneConfigPayload {
                                             .session_id = snapshot.session_id,
                                             .stream_generation = snapshot.generations.stream,
                                             .microphone = *microphone_selection,
                                           }} :
                                           std::nullopt;
      if (!microphone_selection && microphone_runtime_) {
        queue_microphone_retirement(std::move(microphone_runtime_));
      }
      active_video_configuration_ = std::move(video_selection);
      detached_deadline_microseconds_ = 0;
      video_start_pending_ = false;
      for (std::size_t index = 0; index < retiring_candidate_count; ++index) {
        retain_preflighted_retiring_peer(retiring_candidates[index], peer);
      }
      if (pending_inbound_path_probe_.active && is_retiring_attach_peer(pending_inbound_path_probe_.peer)) {
        pending_inbound_path_probe_ = {};
      }
      record_reconnect_failed();
      const auto committed_microseconds = monotonic_microseconds();
      attach_readiness_ = {
        .successor_peer = peer,
        .connection_generation = snapshot.generations.connection,
        .input_generation = snapshot.generations.input,
        .audio_generation = audio_selection.audio_generation,
        .video_generation = response.video.video_generation,
        .microphone_generation = microphone_selection ? microphone_selection->microphone_generation : 0,
        .request_started_microseconds = attempt_started_microseconds,
        .committed_microseconds = committed_microseconds,
        .deadline_microseconds = committed_microseconds >
                                     std::numeric_limits<std::uint64_t>::max() - attach_readiness_deadline_microseconds ?
                                   std::numeric_limits<std::uint64_t>::max() :
                                   committed_microseconds + attach_readiness_deadline_microseconds,
        .microphone_selected = microphone_selection.has_value(),
        .microphone_required = active_microphone_required_,
        .microphone_terminal = !microphone_selection,
        .active = true,
      };
      ++reconnect_telemetry_.committed;
      reconnect_telemetry_.latest_connection_generation = snapshot.generations.connection;
      reconnect_telemetry_.latest_outcome = ReconnectOutcome::committed;
      reconnect_telemetry_.latest_request_to_commit_microseconds = committed_microseconds - attempt_started_microseconds;
      reconnect_telemetry_.latest_commit_to_ready_microseconds = 0;
      reconnect_telemetry_.latest_total_microseconds = reconnect_telemetry_.latest_request_to_commit_microseconds;
      remember_attach_intent(peer, connection_generation, request, response);
      return response;
    }

    /** @copydoc ControlStartHandler::video_configuration */
    const VideoConfigPayload *video_configuration(
      const Identifier128 &session_id,
      const std::uint32_t video_generation
    ) noexcept override {
      std::scoped_lock lock(session_mutex_);
      if (!active_video_configuration_ || active_video_configuration_->wire.session_id != session_id ||
          active_video_configuration_->wire.video.video_generation != video_generation) {
        return nullptr;
      }
      return &active_video_configuration_->wire;
    }

    /** @copydoc ControlStartHandler::video_config_acknowledged */
    bool video_config_acknowledged(
      const PeerEndpoint &peer,
      const TrustedClient &client,
      const std::uint32_t connection_generation,
      const VideoConfigAckPayload &acknowledgement
    ) noexcept override {
      std::unique_ptr<ActiveVideoRuntime> prior_video;
      {
        std::scoped_lock lock(session_mutex_);
        const auto snapshot = authority_.snapshot();
        if (!active_client_ || !active_video_configuration_ ||
            active_client_->client_id != client.client_id ||
            active_client_->connection_generation != connection_generation ||
            snapshot.session_id != acknowledgement.session_id ||
            active_video_configuration_->wire.session_id != acknowledgement.session_id ||
            active_video_configuration_->wire.stream_generation != snapshot.generations.stream ||
            active_video_configuration_->wire.video.video_generation != acknowledgement.video_generation ||
            acknowledgement.decoder_credit > active_video_configuration_->wire.video.decoder_surfaces) {
          return false;
        }
        if (video_runtime_ && video_runtime_->peer == peer &&
            video_runtime_->generation == acknowledgement.video_generation) {
          if (acknowledgement.status == ControlStatus::success && attach_readiness_.active &&
              attach_readiness_.successor_peer == peer &&
              attach_readiness_.connection_generation == connection_generation &&
              attach_readiness_.video_generation == acknowledgement.video_generation) {
            attach_readiness_.video_acknowledged = true;
            attach_readiness_.video_activated = video_runtime_->capture_thread.joinable();
          }
          complete_attach_readiness_if_possible();
          return acknowledgement.status == ControlStatus::success;
        }
        if (acknowledgement.status != ControlStatus::success) {
          fail_required_video_session(peer);
          return true;
        }
        auto display_lease = video_runtime_ ?
                               std::move(video_runtime_->display_lease) :
                               std::move(active_video_configuration_->display_lease);
        auto replacement = create_video_runtime(
          peer,
          *active_video_configuration_,
          acknowledgement.decoder_credit,
          std::move(display_lease)
        );
        if (!replacement) {
          fail_required_video_session(peer);
          return true;
        }
        const auto replacing_active_video = static_cast<bool>(video_runtime_);
        prior_video = std::move(video_runtime_);
        if (prior_video) {
          const auto audio_owns_old_srtp = audio_runtime_ && audio_runtime_->peer == prior_video->peer;
          prior_video->remove_srtp_on_retirement = !audio_owns_old_srtp;
        }
        video_runtime_ = std::move(replacement);
        if (attach_readiness_.active && attach_readiness_.successor_peer == peer &&
            attach_readiness_.connection_generation == connection_generation &&
            attach_readiness_.video_generation == acknowledgement.video_generation) {
          attach_readiness_.video_acknowledged = true;
        }
        if (replacing_active_video) {
          video_start_pending_ = true;
        } else if (!start_video_capture(*video_runtime_, *active_video_configuration_)) {
          auto failed_replacement = std::move(video_runtime_);
          queue_video_retirement(std::move(failed_replacement));
          fail_required_video_session(peer);
          return true;
        } else if (attach_readiness_.active && attach_readiness_.successor_peer == peer &&
                   attach_readiness_.connection_generation == connection_generation &&
                   attach_readiness_.video_generation == acknowledgement.video_generation) {
          attach_readiness_.video_activated = true;
        }
      }
      queue_video_retirement(std::move(prior_video));
      complete_attach_readiness_if_possible();
      return true;
    }

    bool audio_config_acknowledged(
      const PeerEndpoint &peer,
      const TrustedClient &client,
      const std::uint32_t connection_generation,
      const AudioConfigAckPayload &acknowledgement
    ) noexcept override {
      std::unique_ptr<ActiveAudioRuntime> prior_audio;
      {
        std::scoped_lock lock(session_mutex_);
        const auto snapshot = authority_.snapshot();
        if (!active_client_ || !active_audio_configuration_ ||
            active_client_->client_id != client.client_id ||
            active_client_->connection_generation != connection_generation ||
            snapshot.session_id != acknowledgement.session_id ||
            active_audio_configuration_->session_id != acknowledgement.session_id ||
            active_audio_configuration_->stream_generation != snapshot.generations.stream ||
            active_audio_configuration_->audio.audio_generation != acknowledgement.audio_generation) {
          return false;
        }
        if (audio_runtime_ && audio_runtime_->peer == peer &&
            audio_runtime_->generation == acknowledgement.audio_generation) {
          if (acknowledgement.status == ControlStatus::success && attach_readiness_.active &&
              attach_readiness_.successor_peer == peer &&
              attach_readiness_.connection_generation == connection_generation &&
              attach_readiness_.audio_generation == acknowledgement.audio_generation) {
            attach_readiness_.audio_ready = true;
          }
          complete_attach_readiness_if_possible();
          return acknowledgement.status == ControlStatus::success;
        }
        if (acknowledgement.status != ControlStatus::success) {
          fail_required_video_session(peer);
          return true;
        }
        auto replacement = create_audio_runtime(peer, active_audio_configuration_->audio);
        if (!replacement) {
          fail_required_video_session(peer);
          return true;
        }
        prior_audio = std::move(audio_runtime_);
        audio_runtime_ = std::move(replacement);
        if (attach_readiness_.active && attach_readiness_.successor_peer == peer &&
            attach_readiness_.connection_generation == connection_generation &&
            attach_readiness_.audio_generation == acknowledgement.audio_generation) {
          attach_readiness_.audio_ready = true;
        }
      }
      queue_audio_retirement(std::move(prior_audio));
      complete_attach_readiness_if_possible();
      return true;
    }

    bool microphone_config_acknowledged(
      const PeerEndpoint &peer,
      const TrustedClient &client,
      const std::uint32_t connection_generation,
      const MicrophoneConfigAckPayload &acknowledgement
    ) noexcept override {
      std::unique_ptr<LspMicrophoneReceiver> prior_microphone;
      {
        std::scoped_lock lock(session_mutex_);
        const auto snapshot = authority_.snapshot();
        if (!active_client_ || !active_microphone_configuration_ ||
            active_client_->client_id != client.client_id ||
            active_client_->connection_generation != connection_generation ||
            snapshot.session_id != acknowledgement.session_id ||
            active_microphone_configuration_->session_id != acknowledgement.session_id ||
            active_microphone_configuration_->stream_generation != snapshot.generations.stream ||
            active_microphone_configuration_->microphone.microphone_generation != acknowledgement.microphone_generation) {
          return false;
        }
        if (microphone_runtime_ && microphone_runtime_->peer() == peer &&
            microphone_runtime_->generation() == acknowledgement.microphone_generation) {
          if (attach_readiness_.active && attach_readiness_.successor_peer == peer &&
              attach_readiness_.connection_generation == connection_generation &&
              attach_readiness_.microphone_generation == acknowledgement.microphone_generation) {
            attach_readiness_.microphone_terminal = true;
            attach_readiness_.microphone_ready = acknowledgement.status == ControlStatus::success;
          }
          complete_attach_readiness_if_possible();
          return acknowledgement.status == ControlStatus::success;
        }
        if (acknowledgement.status == ControlStatus::success) {
          auto replacement = create_microphone_runtime(peer, active_microphone_configuration_->microphone);
          if (!replacement) {
            if (active_microphone_required_) {
              fail_required_video_session(peer);
              return true;
            }
            prior_microphone = std::move(microphone_runtime_);
          } else {
            prior_microphone = std::move(microphone_runtime_);
            microphone_runtime_ = std::move(replacement);
          }
        } else {
          if (active_microphone_required_) {
            fail_required_video_session(peer);
            return true;
          }
          prior_microphone = std::move(microphone_runtime_);
        }
        if (attach_readiness_.active && attach_readiness_.successor_peer == peer &&
            attach_readiness_.connection_generation == connection_generation &&
            attach_readiness_.microphone_generation == acknowledgement.microphone_generation) {
          attach_readiness_.microphone_terminal = true;
          attach_readiness_.microphone_ready = microphone_runtime_ && microphone_runtime_->peer() == peer &&
                                               microphone_runtime_->generation() == acknowledgement.microphone_generation;
        }
      }
      queue_microphone_retirement(std::move(prior_microphone));
      complete_attach_readiness_if_possible();
      return true;
    }

    /** @copydoc ControlStartHandler::path_probe_intent_acknowledged */
    bool path_probe_intent_acknowledged(
      const PeerEndpoint &peer,
      const PathProbePayload &probe,
      const std::uint64_t now_microseconds
    ) noexcept override {
      std::scoped_lock lock(session_mutex_);
      if (is_retiring_attach_peer(peer)) {
        return true;
      }
      return video_runtime_ && video_runtime_->peer == peer && video_runtime_->sender &&
             video_runtime_->sender->send_path_probe(probe, now_microseconds);
    }

    /** @copydoc ControlStartHandler::path_probe_requested */
    bool path_probe_requested(
      const PeerEndpoint &peer,
      const PathProbePayload &probe,
      const std::uint64_t deadline_microseconds
    ) noexcept override {
      std::scoped_lock lock(session_mutex_);
      const auto mapping = input_owner_ ? input_owner_->mapping() : std::nullopt;
      if (!mapping || mapping->peer != peer || !active_video_configuration_ ||
          probe.udp_payload_size > active_video_configuration_->path_payload_ceiling ||
          pending_inbound_path_probe_.active ||
          std::ranges::find(recent_inbound_path_probe_ids_, probe.probe_id) != recent_inbound_path_probe_ids_.end()) {
        return false;
      }
      pending_inbound_path_probe_ = {
        .peer = peer,
        .probe = probe,
        .deadline_microseconds = deadline_microseconds,
        .active = true,
      };
      return true;
    }

    /** @copydoc ControlStartHandler::path_probe_acknowledged */
    bool path_probe_acknowledged(
      const PeerEndpoint &peer,
      const PathProbePayload &probe
    ) noexcept override {
      std::scoped_lock lock(session_mutex_);
      if (is_retiring_attach_peer(peer)) {
        return true;
      }
      return video_runtime_ && video_runtime_->peer == peer && video_runtime_->sender &&
             video_runtime_->sender->acknowledge_path_probe(probe);
    }

    /** @copydoc ControlStartHandler::path_probe_rejected */
    bool path_probe_rejected(
      const PeerEndpoint &peer,
      const PathProbePayload &probe,
      const ControlStatus status
    ) noexcept override {
      std::scoped_lock lock(session_mutex_);
      if (is_retiring_attach_peer(peer)) {
        return true;
      }
      if (!video_runtime_ || video_runtime_->peer != peer || !video_runtime_->sender) {
        return false;
      }
      switch (status) {
        case ControlStatus::timeout:
          return video_runtime_->sender->reject_path_probe(probe);
        case ControlStatus::busy:
        case ControlStatus::stale_generation:
        case ControlStatus::path_capacity_insufficient:
          return video_runtime_->sender->rollback_path_probe(probe);
        case ControlStatus::malformed:
        case ControlStatus::unsupported:
        case ControlStatus::authentication_failed:
        case ControlStatus::permission_denied:
        case ControlStatus::unsupported_media_tuple:
        case ControlStatus::internal_failure:
        case ControlStatus::success:
          return false;
      }
      return false;
    }

    ControlStatus stop_input(
      const TrustedClient &client,
      const std::uint32_t connection_generation,
      const StopRequestPayload &request
    ) noexcept override {
      std::unique_ptr<ActiveAudioRuntime> audio;
      std::unique_ptr<ActiveVideoRuntime> video;
      std::unique_ptr<LspMicrophoneReceiver> microphone;
      bool process_stopped = false;
      {
        std::scoped_lock lock(session_mutex_);
        const AuthenticatedClient authority_client {
          .client_id = client.client_id,
          .connection_generation = connection_generation,
          .revocation_generation = client.revocation_generation,
          .permissions = client.permissions,
        };
        const auto stopped = authority_.stop_owned(authority_client, request.session_id);
        if (stopped == AuthorityResult::permission_denied) {
          return ControlStatus::permission_denied;
        }
        if (stopped == AuthorityResult::not_owner || stopped == AuthorityResult::stale_generation) {
          return ControlStatus::stale_generation;
        }
        if (stopped != AuthorityResult::accepted) {
          return ControlStatus::malformed;
        }
        process_stopped = active_process_generation_ == 0 ||
                          proc::proc.terminate_lsp_generation(active_process_generation_);
        active_process_generation_ = 0;
        active_client_.reset();
        active_audio_configuration_.reset();
        active_video_configuration_.reset();
        pending_inbound_path_probe_ = {};
        active_microphone_configuration_.reset();
        active_microphone_required_ = false;
        audio = std::move(audio_runtime_);
        video = std::move(video_runtime_);
        microphone = std::move(microphone_runtime_);
        ssrc_registry_.reset();
        detached_deadline_microseconds_ = 0;
        queue_all_retiring_attach_peers();
        clear_attach_lifecycle();
        clear_session_ssrc_history();
      }
      queue_audio_retirement(std::move(audio));
      queue_video_retirement(std::move(video));
      queue_microphone_retirement(std::move(microphone));
      return process_stopped ? ControlStatus::success : ControlStatus::internal_failure;
    }

    bool neutralize(const NeutralizationRequest &request) noexcept override {
      (void) request;
      if (input_owner_) {
        input_owner_->neutralize();
      }
      return true;
    }

    bool matches(const Secret256 &presented, const Secret256 &expected) const noexcept override {
      return crypto_ && crypto_->equal_secret(presented, expected);
    }

    bool create_pairing_invitation() noexcept {
      PairingInvitation invitation {
        .host_id = identity_.host_id,
        .host_identity_key = identity_.application_public_key,
        .dtls_spki_sha256 = dtls_->server_spki_sha256(),
        .port = config_.host.port,
        .host = config_.host_name,
        .expires_at_utc_seconds = utc_seconds() + invitation_lifetime_seconds,
        .offered_permissions = config_.host.pairing_permissions,
      };
      if (!crypto_->random(invitation.invitation_id) || !crypto_->random(invitation.invitation_secret) ||
          !control_->add_invitation(invitation)) {
        return false;
      }
      auto encoded = encode_invitation_uri(invitation);
      std::ranges::fill(invitation.invitation_secret, 0);
      if (!encoded) {
        return false;
      }
      pairing_uri_ = std::move(*encoded);
      pairing_expiration_utc_seconds_ = invitation.expires_at_utc_seconds;
      return true;
    }

    void run(const std::stop_token stop_token) noexcept {
      while (!stop_token.stop_requested() && active_) {
        (void) socket_.wait_readable(runtime_poll_milliseconds);
        const auto result = socket_.receive_batch(runtime_receive_batch, [this](const ReceivedDatagram &datagram) {
          const auto packet_class = classify_packet(datagram.payload);
          if (packet_class == PacketClass::dtls) {
            refresh_dtls_timer(datagram.peer, datagram.received_at_microseconds);
            begin_dtls_provider_output(datagram.peer);
          }
          auto disposition = DatagramResult::inactive;
          if (service_) {
            disposition = service_->receive(datagram.peer, datagram.payload);
          }
          if (packet_class == PacketClass::dtls) {
            end_dtls_provider_output(datagram.peer);
          }
          if (datagram_result_requires_association_close(disposition)) {
            (void) queue_association_close(datagram.peer);
          }
          process_pending_audio_retirements();
          process_pending_video_retirements();
          process_pending_microphone_retirements();
          process_failed_forward_paths();
          process_pending_association_closes();
          process_audio_failure();
          process_video_failure();
          if (packet_class == PacketClass::dtls && !datagram_result_requires_association_close(disposition)) {
            refresh_dtls_timer(datagram.peer, datagram.received_at_microseconds);
          }
        });
        if (result == ReceiveBatchResult::fatal || result == ReceiveBatchResult::closed) {
          break;
        }
        const auto now = monotonic_microseconds();
        if (control_) {
          control_->tick(now);
        }
        process_path_probes(now);
        process_dtls_timers(now);
        process_pending_audio_retirements();
        process_pending_video_retirements();
        process_pending_microphone_retirements();
        process_failed_forward_paths();
        process_pending_association_closes();
        process_audio_failure();
        process_video_failure();
        process_attach_readiness_deadline(now);
        process_detached_grace(now);
        process_application_exit();
      }
      active_ = false;
    }

    void refresh_dtls_timer(const PeerEndpoint &peer, const std::uint64_t now_microseconds) noexcept {
      if (!dtls_) {
        return;
      }
      const auto seconds = dtls_->timeout_seconds(peer);
      const auto iterator = std::ranges::find(dtls_timers_, peer, &DtlsTimer::peer);
      if (seconds == 0) {
        if (iterator != dtls_timers_.end()) {
          dtls_timers_.erase(iterator);
        }
        return;
      }
      const auto delay = static_cast<std::uint64_t>(seconds) * 1'000'000U;
      const auto due = now_microseconds > std::numeric_limits<std::uint64_t>::max() - delay ?
                         std::numeric_limits<std::uint64_t>::max() :
                         now_microseconds + delay;
      if (iterator != dtls_timers_.end()) {
        iterator->due_microseconds = due;
      } else if (dtls_timers_.size() < 64) {
        try {
          dtls_timers_.push_back({peer, due});
        } catch (...) {
          dtls_->close_association(peer);
        }
      }
    }

    void process_dtls_timers(const std::uint64_t now_microseconds) noexcept {
      for (std::size_t index = 0; index < dtls_timers_.size();) {
        if (now_microseconds < dtls_timers_[index].due_microseconds) {
          ++index;
          continue;
        }
        const auto peer = dtls_timers_[index].peer;
        begin_dtls_provider_output(peer);
        const auto result = dtls_->handle_timeout(peer);
        end_dtls_provider_output(peer);
        dtls_timers_.erase(dtls_timers_.begin() + static_cast<std::ptrdiff_t>(index));
        if (result == WolfsslDtlsOperationResult::accepted) {
          refresh_dtls_timer(peer, now_microseconds);
        }
      }
    }

    /** @brief Drive one host DPLPMTUD search and retire reverse intents on their control deadline. */
    void process_path_probes(const std::uint64_t now_microseconds) noexcept {
      std::shared_ptr<HostVideoSender> sender;
      PeerEndpoint peer;
      {
        std::scoped_lock lock(session_mutex_);
        if (pending_inbound_path_probe_.active &&
            now_microseconds >= pending_inbound_path_probe_.deadline_microseconds) {
          pending_inbound_path_probe_ = {};
        }
        if (video_runtime_ && video_runtime_->sender) {
          sender = video_runtime_->sender;
          peer = video_runtime_->peer;
        }
      }
      if (!sender || !control_ || !crypto_) {
        return;
      }

      if (is_retiring_attach_peer(peer)) {
        if (const auto outstanding = sender->outstanding_path_probe()) {
          (void) control_->cancel_path_probe(peer, *outstanding);
          (void) sender->rollback_path_probe(*outstanding);
        }
        return;
      }

      const auto interval = control_->path_probe_interval(peer);
      const auto before = sender->outstanding_path_probe();
      if (!sender->tick_path_probe(now_microseconds, interval)) {
        fail_required_video_session(peer);
        return;
      }
      const auto after = sender->outstanding_path_probe();
      if (before && !after) {
        (void) control_->cancel_path_probe(peer, *before);
      }
      if (after) {
        return;
      }

      std::array<std::uint8_t, 8> probe_id_bytes {};
      if (!crypto_->random(probe_id_bytes)) {
        return;
      }
      auto probe_id = wire::read_be<std::uint64_t>(probe_id_bytes);
      if (probe_id == 0) {
        probe_id = 1;
      }
      const auto probe = sender->begin_path_probe(probe_id, now_microseconds, interval);
      if (probe && !control_->start_path_probe(peer, *probe, now_microseconds)) {
        (void) sender->rollback_path_probe(*probe);
      }
    }

    [[nodiscard]] bool queue_association_close(PeerEndpoint peer) noexcept {
      std::scoped_lock lock(session_mutex_);
      for (std::size_t index = 0; index < pending_association_close_count_; ++index) {
        if (pending_association_closes_[index] == peer) {
          return true;
        }
      }
      if (pending_association_close_count_ < pending_association_closes_.size()) {
        pending_association_closes_[pending_association_close_count_++] = std::move(peer);
        return true;
      }
      return false;
    }

    void process_pending_association_closes() noexcept {
      std::scoped_lock lock(session_mutex_);
      while (pending_association_close_count_ != 0) {
        auto peer = std::move(pending_association_closes_[--pending_association_close_count_]);
        pending_association_closes_[pending_association_close_count_] = {};
        const auto callback_will_retire = dtls_ && dtls_->close_association(peer);
        if (!callback_will_retire) {
          retire_forward_path(peer);
          if (srtp_) {
            srtp_->remove_association(peer);
          }
        }
      }
    }

    /** @brief Close every atomically reported fatal path association on the socket owner. */
    void process_failed_forward_paths() noexcept {
      auto pending = pending_forward_failures_.exchange(0, std::memory_order_acq_rel);
      for (std::size_t index = 0; pending != 0 && index < forward_paths_.size(); ++index) {
        const auto bit = std::uint64_t {1} << index;
        if ((pending & bit) == 0) {
          continue;
        }
        pending &= ~bit;
        PeerEndpoint peer;
        {
          std::scoped_lock lock(forward_path_mutex_);
          const auto &owner = forward_paths_[index];
          if (!owner || owner->fatal_generation.load(std::memory_order_acquire) != owner->generation) {
            continue;
          }
          peer = owner->peer;
        }
        if (dtls_) {
          (void) dtls_->close_association(peer);
        }
      }
    }

    /**
     * @brief Terminate a committed successor that misses its generation-qualified readiness deadline.
     *
     * @param now_microseconds Current socket-owner monotonic time.
     */
    void process_attach_readiness_deadline(const std::uint64_t now_microseconds) noexcept {
      std::optional<PeerEndpoint> expired_peer;
      {
        std::scoped_lock lock(session_mutex_);
        if (!attach_readiness_.active || now_microseconds < attach_readiness_.deadline_microseconds) {
          return;
        }
        const auto snapshot = authority_.snapshot();
        if (snapshot.state == SessionState::streaming &&
            snapshot.generations.connection == attach_readiness_.connection_generation) {
          expired_peer = attach_readiness_.successor_peer;
        } else {
          record_reconnect_failed();
        }
      }
      if (expired_peer) {
        fail_required_video_session(*expired_peer);
      }
    }

    void process_detached_grace(const std::uint64_t now_microseconds) noexcept {
      std::unique_ptr<ActiveAudioRuntime> audio;
      std::unique_ptr<ActiveVideoRuntime> video;
      std::unique_ptr<LspMicrophoneReceiver> microphone;
      {
        std::scoped_lock lock(session_mutex_);
        if (detached_deadline_microseconds_ == 0 || now_microseconds < detached_deadline_microseconds_) {
          return;
        }
        detached_deadline_microseconds_ = 0;
        if (authority_.snapshot().state == SessionState::detached) {
          (void) authority_.stop_from_host(NeutralizationReason::transport_loss);
          if (active_process_generation_ != 0) {
            (void) proc::proc.terminate_lsp_generation(active_process_generation_);
            active_process_generation_ = 0;
          }
          active_client_.reset();
          active_audio_configuration_.reset();
          active_video_configuration_.reset();
          pending_inbound_path_probe_ = {};
          active_microphone_configuration_.reset();
          active_microphone_required_ = false;
          audio = std::move(audio_runtime_);
          video = std::move(video_runtime_);
          microphone = std::move(microphone_runtime_);
          ssrc_registry_.reset();
          queue_all_retiring_attach_peers();
          clear_attach_lifecycle();
          clear_session_ssrc_history();
        }
      }
      stop_audio_runtime(std::move(audio));
      stop_video_runtime(std::move(video));
      if (microphone) {
        microphone->shutdown();
      }
    }

    /** @brief Stop media authority when the generation-owned application exits. */
    void process_application_exit() noexcept {
      std::unique_ptr<ActiveAudioRuntime> audio;
      std::unique_ptr<ActiveVideoRuntime> video;
      std::unique_ptr<LspMicrophoneReceiver> microphone;
      {
        std::scoped_lock lock(session_mutex_);
        if (active_process_generation_ == 0 || proc::proc.running() > 0) {
          return;
        }
        (void) authority_.stop_from_host(NeutralizationReason::explicit_stop);
        active_process_generation_ = 0;
        active_client_.reset();
        active_audio_configuration_.reset();
        active_video_configuration_.reset();
        pending_inbound_path_probe_ = {};
        active_microphone_configuration_.reset();
        active_microphone_required_ = false;
        audio = std::move(audio_runtime_);
        video = std::move(video_runtime_);
        microphone = std::move(microphone_runtime_);
        ssrc_registry_.reset();
        detached_deadline_microseconds_ = 0;
        queue_all_retiring_attach_peers();
        clear_attach_lifecycle();
        clear_session_ssrc_history();
      }
      stop_audio_runtime(std::move(audio));
      stop_video_runtime(std::move(video));
      if (microphone) {
        microphone->shutdown();
      }
    }

    /** @brief Submit one immutable aggregate-path datagram through the native socket. */
    static UdpSendResult forward_send_callback(
      void *context,
      const PeerEndpoint &peer,
      const std::span<const std::uint8_t> datagram
    ) noexcept {
      const auto *owner = static_cast<ForwardPathGeneration *>(context);
      return owner && owner->runtime ?
               owner->runtime->socket_.send_datagram_result(peer, datagram) :
               UdpSendResult::fatal;
    }

    /** @brief Hand a fatal path generation to the socket loop without taking session authority. */
    static void forward_completed_callback(
      void *context,
      const std::uint64_t token,
      const HostForwardLane lane,
      const HostForwardCompletion completion,
      const std::uint64_t completed_at_microseconds,
      const std::size_t protected_bytes,
      const std::uint16_t charged_bytes
    ) noexcept {
      auto *owner = static_cast<ForwardPathGeneration *>(context);
      (void) token;
      (void) lane;
      (void) completed_at_microseconds;
      (void) protected_bytes;
      (void) charged_bytes;
      if (owner == nullptr || owner->runtime == nullptr || completion != HostForwardCompletion::fatal) {
        return;
      }
      std::uint32_t expected = 0;
      if (owner->fatal_generation.compare_exchange_strong(
            expected,
            owner->generation,
            std::memory_order_acq_rel,
            std::memory_order_acquire
          )) {
        owner->runtime->pending_forward_failures_.fetch_or(
          std::uint64_t {1} << owner->slot,
          std::memory_order_release
        );
      }
    }

    static bool dtls_send_callback(
      void *context,
      const PeerEndpoint &peer,
      const std::span<const std::uint8_t> datagram
    ) noexcept {
      auto &runtime = *static_cast<ProductHostRuntime *>(context);
      const auto forward = runtime.find_forward_path(peer);
      if (forward && forward->path) {
        const auto now = monotonic_microseconds();
        const auto deadline = now > std::numeric_limits<std::uint64_t>::max() - 100'000U ?
                                std::numeric_limits<std::uint64_t>::max() :
                                now + 100'000U;
        return forward->path->submit_copy(
                 HostForwardLane::urgent_control,
                 datagram,
                 deadline
               ) == HostForwardSubmitResult::accepted;
      }
      return runtime.direct_dtls_output_allowed(peer) && runtime.socket_.send_datagram(peer, datagram);
    }

    static bool application_data_callback(
      void *context,
      const PeerEndpoint &peer,
      const std::span<const std::uint8_t> plaintext
    ) noexcept {
      auto &runtime = *static_cast<ProductHostRuntime *>(context);
      return runtime.control_ && runtime.control_->receive(
                                   peer,
                                   plaintext,
                                   monotonic_microseconds(),
                                   utc_seconds()
                                 );
    }

    static bool association_ready_callback(
      void *context,
      const PeerEndpoint &peer,
      const DtlsAssociationSecurity &security
    ) noexcept {
      auto &runtime = *static_cast<ProductHostRuntime *>(context);
      if (!runtime.srtp_ || !runtime.control_ ||
          !runtime.srtp_->install_association(peer, security.srtp)) {
        return false;
      }
      const auto generation = runtime.control_->association_ready(peer);
      if (generation == 0) {
        runtime.srtp_->remove_association(peer);
        return false;
      }
      if (!runtime.create_forward_path(peer, generation)) {
        runtime.control_->association_closed(peer);
        runtime.srtp_->remove_association(peer);
        return false;
      }
      if (!runtime.remember_authenticated_peer(peer)) {
        runtime.retire_forward_path(peer);
        runtime.control_->association_closed(peer);
        runtime.srtp_->remove_association(peer);
        return false;
      }
      return true;
    }

    static bool server_certificate_callback(
      void *context,
      const std::span<const std::uint8_t> certificate_der,
      const Digest256 &spki_sha256
    ) noexcept {
      const auto &runtime = *static_cast<ProductHostRuntime *>(context);
      return !is_zero(spki_sha256) && certificate_der.size() == runtime.identity_.certificate_der.size() &&
             std::ranges::equal(certificate_der, runtime.identity_.certificate_der);
    }

    static void association_closed_callback(void *context, const PeerEndpoint &peer) noexcept {
      auto &runtime = *static_cast<ProductHostRuntime *>(context);
      runtime.forget_authenticated_peer(peer);
      std::unique_ptr<ActiveAudioRuntime> audio;
      std::unique_ptr<ActiveVideoRuntime> video;
      std::unique_ptr<LspMicrophoneReceiver> microphone;
      {
        std::scoped_lock session_lock(runtime.session_mutex_);
        if (runtime.pending_inbound_path_probe_.active && runtime.pending_inbound_path_probe_.peer == peer) {
          runtime.pending_inbound_path_probe_ = {};
        }
        if (runtime.input_owner_) {
          const auto mapping = runtime.input_owner_->mapping();
          if (mapping && mapping->peer == peer) {
            (void) runtime.authority_.transport_lost(mapping->connection_generation);
            runtime.detached_deadline_microseconds_ = monotonic_microseconds() + attach_grace_microseconds;
            runtime.ssrc_registry_.reset();
            runtime.active_client_.reset();
            runtime.record_reconnect_failed();
            runtime.queue_all_retiring_attach_peers();
            runtime.video_start_pending_ = false;
          }
        }
        if (runtime.audio_runtime_ && runtime.audio_runtime_->peer == peer) {
          audio = std::move(runtime.audio_runtime_);
        }
        if (runtime.video_runtime_ && runtime.video_runtime_->peer == peer) {
          video = std::move(runtime.video_runtime_);
        }
        if (runtime.microphone_runtime_ && runtime.microphone_runtime_->peer() == peer) {
          microphone = std::move(runtime.microphone_runtime_);
        }
      }
      const auto audio_uses_closed_peer = audio && audio->peer == peer;
      const auto video_uses_closed_peer = video && video->peer == peer;
      if (video_uses_closed_peer) {
        video->remove_srtp_on_retirement = true;
        if (audio_uses_closed_peer) {
          audio->remove_srtp_on_retirement = false;
        }
      } else if (audio_uses_closed_peer) {
        audio->remove_srtp_on_retirement = true;
      }
      const auto deferred_srtp_removal = audio_uses_closed_peer || video_uses_closed_peer;
      runtime.queue_audio_retirement(std::move(audio));
      runtime.queue_video_retirement(std::move(video));
      runtime.queue_microphone_retirement(std::move(microphone));
      if (!deferred_srtp_removal && runtime.srtp_) {
        runtime.retire_forward_path(peer);
        runtime.srtp_->remove_association(peer);
      }
      if (runtime.control_) {
        runtime.control_->association_closed(peer);
      }
      {
        std::scoped_lock session_lock(runtime.session_mutex_);
        const auto timer = std::ranges::find(runtime.dtls_timers_, peer, &DtlsTimer::peer);
        if (timer != runtime.dtls_timers_.end()) {
          runtime.dtls_timers_.erase(timer);
        }
      }
    }

    static bool secure_packet_callback(
      void *context,
      const PeerEndpoint &peer,
      const SecurePacketClass packet_class,
      const std::span<const std::uint8_t> plaintext,
      const std::size_t protected_bytes
    ) noexcept {
      auto &runtime = *static_cast<ProductHostRuntime *>(context);
      if (packet_class == SecurePacketClass::rtcp && plaintext.size() >= 12U &&
          std::ranges::equal(transport::lspv_app_name, plaintext.subspan<8, 4>())) {
        std::shared_ptr<HostVideoSender> sender;
        std::optional<InputSessionMapping> mapping;
        std::uint32_t stream_generation = 0;
        std::uint32_t video_generation = 0;
        {
          std::scoped_lock session_lock(runtime.session_mutex_);
          if (!runtime.input_owner_ || !runtime.active_video_configuration_ ||
              !runtime.video_runtime_ || runtime.video_runtime_->peer != peer ||
              !runtime.video_runtime_->sender) {
            return true;
          }
          mapping = runtime.input_owner_->mapping();
          if (!mapping || mapping->peer != peer) {
            return true;
          }
          stream_generation = runtime.active_video_configuration_->wire.stream_generation;
          video_generation = runtime.active_video_configuration_->wire.video.video_generation;
          sender = runtime.video_runtime_->sender;
        }
        const auto status = parse_lspv_status(plaintext, mapping->input_ssrc);
        if (!status || status->session_generation != stream_generation ||
            status->video_generation != video_generation) {
          return true;
        }
        (void) sender->receive_video_status(*status, monotonic_microseconds());
        return true;
      }
      std::scoped_lock session_lock(runtime.session_mutex_);
      if (!runtime.input_owner_) {
        return true;
      }
      if (packet_class == SecurePacketClass::rtcp) {
        const auto mapping = runtime.input_owner_->mapping();
        if (plaintext.size() >= 12U && std::ranges::equal(lspp_app_name, plaintext.subspan<8, 4>())) {
          if (!mapping || mapping->peer != peer || !runtime.pending_inbound_path_probe_.active ||
              runtime.pending_inbound_path_probe_.peer != peer) {
            return true;
          }
          const auto probe = parse_path_probe_datagram(plaintext, protected_bytes, mapping->input_ssrc);
          if (!probe || *probe != runtime.pending_inbound_path_probe_.probe || !runtime.control_ ||
              !runtime.control_->complete_path_probe(peer, *probe, monotonic_microseconds())) {
            return true;
          }
          runtime.recent_inbound_path_probe_ids_[runtime.next_recent_inbound_path_probe_id_] = probe->probe_id;
          runtime.next_recent_inbound_path_probe_id_ =
            (runtime.next_recent_inbound_path_probe_id_ + 1U) % runtime.recent_inbound_path_probe_ids_.size();
          runtime.pending_inbound_path_probe_ = {};
          return true;
        }
        if (runtime.video_runtime_ && runtime.video_runtime_->peer == peer && runtime.video_runtime_->sender &&
            plaintext.size() >= 4U) {
          auto &sender = *runtime.video_runtime_->sender;
          const auto now = monotonic_microseconds();
          if (plaintext[1] == transport::rtcp_sender_report_type ||
              plaintext[1] == transport::rtcp_receiver_report_type) {
            if (sender.receive_compound_rtcp(plaintext, now)) {
              std::size_t offset = 0;
              while (offset < plaintext.size()) {
                const auto parsed = transport::parse_rtcp_packet(plaintext.subspan(offset));
                if (!parsed) {
                  break;
                }
                if (parsed.packet_type == transport::rtcp_transport_feedback_type &&
                    parsed.count == transport::rtcp_congestion_feedback_format) {
                  (void) sender.receive_congestion_feedback(parsed.packet, now);
                } else if ((parsed.packet_type == transport::rtcp_transport_feedback_type &&
                            parsed.count == transport::rtcp_generic_nack_format) ||
                           (parsed.packet_type == transport::rtcp_payload_feedback_type &&
                            (parsed.count == transport::rtcp_picture_loss_indication_format ||
                             parsed.count == transport::rtcp_full_intra_request_format))) {
                  (void) sender.receive_repair_feedback(parsed.packet, now);
                }
                offset += parsed.packet.size();
              }
            }
            return true;
          }
          if (plaintext[1] == transport::rtcp_transport_feedback_type &&
              (plaintext[0] & 0x1fU) == transport::rtcp_congestion_feedback_format) {
            (void) sender.receive_congestion_feedback(plaintext, now);
            return true;
          }
          if ((plaintext[1] == transport::rtcp_transport_feedback_type &&
               (plaintext[0] & 0x1fU) == transport::rtcp_generic_nack_format) ||
              (plaintext[1] == transport::rtcp_payload_feedback_type &&
               ((plaintext[0] & 0x1fU) == transport::rtcp_picture_loss_indication_format ||
                (plaintext[0] & 0x1fU) == transport::rtcp_full_intra_request_format))) {
            (void) sender.receive_repair_feedback(plaintext, now);
            return true;
          }
        }
        const auto input_accepted = runtime.input_owner_->receive_rtcp(peer, plaintext);
        const auto microphone_accepted = !runtime.microphone_runtime_ ||
                                         runtime.microphone_runtime_->receive_rtcp(peer, plaintext);
        return input_accepted && microphone_accepted;
      }
      if (!runtime.ssrc_registry_) {
        return true;
      }
      const auto rtp = parse_rtp_fixed_header(plaintext);
      if (!rtp) {
        return true;
      }
      const auto *assignment = runtime.ssrc_registry_->find(rtp.header.ssrc);
      if (assignment == nullptr || assignment->payload_type != rtp.header.payload_type || assignment->generation == 0) {
        return true;
      }
      if (assignment->lane == MediaLane::input) {
        return runtime.input_owner_->receive(peer, plaintext);
      }
      if (assignment->lane == MediaLane::microphone && runtime.microphone_runtime_ &&
          runtime.microphone_runtime_->generation() == assignment->generation) {
        return runtime.microphone_runtime_->receive_rtp(peer, plaintext);
      }
      return true;
    }

    static bool input_digest_callback(
      void *context,
      const std::span<const std::uint8_t> bytes,
      const Digest256 &expected
    ) noexcept {
      auto &runtime = *static_cast<ProductHostRuntime *>(context);
      Digest256 actual {};
      return runtime.crypto_ && runtime.crypto_->sha256(bytes, actual) && runtime.crypto_->equal_secret(actual, expected);
    }

    static bool input_baseline_callback(
      void *context,
      const PeerEndpoint &peer,
      const std::uint32_t session_generation,
      const std::uint32_t input_generation
    ) noexcept {
      auto &runtime = *static_cast<ProductHostRuntime *>(context);
      std::scoped_lock session_lock(runtime.session_mutex_);
      if (!runtime.active_client_) {
        return false;
      }
      const auto snapshot = runtime.authority_.snapshot();
      const auto forward = runtime.find_forward_path(peer);
      const auto committed = snapshot.generations.connection == runtime.active_client_->connection_generation &&
                             snapshot.generations.stream == session_generation && snapshot.generations.input == input_generation &&
                             forward && forward->generation == snapshot.generations.connection &&
                             runtime.authority_.commit_input_baseline(
                               *runtime.active_client_,
                               session_generation,
                               input_generation
                             ) == AuthorityResult::accepted;
      return committed;
    }

    /** @brief Advance successor readiness only after the neutral baseline LSPI ACK entered aggregate output. */
    static void input_baseline_acknowledged_callback(
      void *context,
      const PeerEndpoint &peer,
      const std::uint32_t session_generation,
      const std::uint32_t input_generation
    ) noexcept {
      auto &runtime = *static_cast<ProductHostRuntime *>(context);
      std::scoped_lock session_lock(runtime.session_mutex_);
      const auto snapshot = runtime.authority_.snapshot();
      if (runtime.attach_readiness_.active && runtime.attach_readiness_.successor_peer == peer &&
          runtime.attach_readiness_.connection_generation == snapshot.generations.connection &&
          snapshot.generations.stream == session_generation &&
          runtime.attach_readiness_.input_generation == input_generation &&
          snapshot.generations.input == input_generation && snapshot.input_baseline_complete) {
        runtime.attach_readiness_.input_baseline_ready = true;
        runtime.complete_attach_readiness_if_possible();
      }
    }

    HostRuntimeConfig config_;  ///< Immutable runtime configuration.
    HostIdentity identity_;  ///< Fresh LSP-only identity and credentials.
    NativeUdpSocket socket_;  ///< One nonblocking application socket.
    std::unique_ptr<WolfsslControlCrypto> crypto_;  ///< Application identity crypto.
    std::unique_ptr<PersistentTrustStore> trust_store_;  ///< Distinct LSP trust persistence.
    std::unique_ptr<ProcessApplicationProvider> applications_;  ///< Product application snapshot.
    std::unique_ptr<LibsrtpServerProvider> srtp_;  ///< Concrete SRTP/SRTCP provider.
    std::unique_ptr<InputOwner> input_owner_;  ///< Ordered authenticated input apply owner.
    std::unique_ptr<WolfsslDtlsServerProvider> dtls_;  ///< Concrete DTLS 1.3 provider.
    std::unique_ptr<HostControlServer> control_;  ///< LSPC reliability/auth/application control.
    std::unique_ptr<HostService> service_;  ///< RFC 7983 dispatcher and socket activation guard.
    SessionAuthority authority_;  ///< START/baseline/disconnect input authority state.
    std::optional<AuthenticatedClient> active_client_;  ///< Current input session owner.
    std::optional<SsrcRegistry> ssrc_registry_;  ///< Authenticated input SSRC mapping.
    std::optional<AudioConfigPayload> active_audio_configuration_;  ///< Selected or rekeyed audio tuple awaiting/holding ACK.
    std::unique_ptr<ActiveAudioRuntime> audio_runtime_;  ///< Acknowledged capture and SRTP sender generation.
    std::optional<ActiveVideoConfiguration> active_video_configuration_;  ///< Hardware-proven selected video tuple awaiting/holding ACK.
    std::unique_ptr<ActiveVideoRuntime> video_runtime_;  ///< Acknowledged capture/encode/RTP/SRTP video generation.
    std::optional<MicrophoneConfigPayload> active_microphone_configuration_;  ///< Selected reverse microphone tuple.
    bool active_microphone_required_ {};  ///< Whether failure of the selected reverse microphone is session-fatal.
    std::unique_ptr<LspMicrophoneReceiver> microphone_runtime_;  ///< Acknowledged reverse microphone writer.
    PendingInboundPathProbe pending_inbound_path_probe_ {};  ///< One authenticated reverse probe intent.
    std::array<std::uint64_t, 64> recent_inbound_path_probe_ids_ {};  ///< Session replay fence for completed probes.
    std::size_t next_recent_inbound_path_probe_id_ {};  ///< Next reverse-probe replay-cache replacement slot.
    std::uint32_t next_stream_generation_ {1};  ///< Next nonzero LSP stream-session generation.
    std::uint64_t active_process_generation_ {};  ///< Generation-qualified LSP-owned application process.

    struct ActiveRates {
      std::uint32_t pointer {};  ///< Selected pointer reports/s.
      std::uint32_t controller {};  ///< Selected controller reports/s.
      std::uint32_t sensor {};  ///< Selected sensor reports/s.
      std::uint32_t reconciliation {};  ///< Selected reconciliation reports/s.
      std::uint64_t budget {};  ///< Reserved input wire bits/s.
    } active_rates_;  ///< Retained input selection across ATTACH/rekey.

    std::array<AttachIntentOutcome, 64> attach_intent_outcomes_ {};  ///< Bounded semantic-success replay cache for the active session.
    std::size_t next_attach_intent_outcome_ {};  ///< Next replacement slot in the ATTACH intent ring.
    std::array<std::uint32_t, 512> session_ssrc_history_ {};  ///< Every SSRC assigned during the active session, without overwrite.
    std::size_t session_ssrc_history_count_ {};  ///< Live leading session SSRC history entries.
    AttachReadinessBarrier attach_readiness_ {};  ///< Current successor's aggregate authority/media readiness barrier.
    std::array<PeerEndpoint, 64> retiring_attach_peers_ {};  ///< Deduplicated prior associations retained until full successor readiness.
    std::size_t retiring_attach_peer_count_ {};  ///< Live leading retiring-association entries.
    ReconnectTelemetrySnapshot reconnect_telemetry_ {};  ///< Secret-free reconnect/rekey administration counters and timings.
    bool video_start_pending_ {};  ///< Fresh capture waits for prior VDD/frame-source ownership to join.
    std::uint64_t detached_deadline_microseconds_ {};  ///< Bounded process-hold deadline.
    mutable std::mutex forward_path_mutex_;  ///< Dedicated path lookup/lifetime lock, never used for session authority.
    std::array<std::shared_ptr<ForwardPathGeneration>, 64> forward_paths_ {};  ///< Active connection-generation path owners.
    std::array<PeerEndpoint, 64> authenticated_peers_ {};  ///< Provider-authenticated peers that must never regain direct socket output.
    std::optional<PeerEndpoint> direct_dtls_output_peer_;  ///< Current synchronous provider receive/timer output scope.
    std::atomic<std::uint64_t> pending_forward_failures_ {};  ///< Fatal path slots awaiting socket-loop association teardown.
    mutable std::recursive_mutex session_mutex_;  ///< Synchronizes socket authority with the input apply worker.
    std::vector<DtlsTimer> dtls_timers_;  ///< Bounded association retransmission timers.
    std::array<PeerEndpoint, 64> pending_association_closes_ {};  ///< Old associations retired after response submission.
    std::size_t pending_association_close_count_ {};  ///< Live leading deferred-close entries.
    std::array<std::unique_ptr<ActiveAudioRuntime>, 64> pending_audio_retirements_ {};  ///< Quiescent audio owners awaiting callback-safe joins.
    std::array<std::unique_ptr<ActiveVideoRuntime>, 64> pending_video_retirements_ {};  ///< Video owners awaiting callback-safe capture/sender joins.
    std::array<std::unique_ptr<LspMicrophoneReceiver>, 64> pending_microphone_retirements_ {};  ///< Microphone owners awaiting callback-safe destruction.
    std::jthread worker_;  ///< Socket receive/control timer owner.
    std::optional<std::string> pairing_uri_;  ///< Current UI-bound invitation issuance copy.
    std::uint64_t pairing_expiration_utc_seconds_ {};  ///< Current invitation expiry.
    std::atomic<bool> active_ {};  ///< Listener/worker availability.
    mutable std::recursive_mutex administration_mutex_;  ///< Synchronizes invitation and web administration state.
  };
#endif

  HostRuntimeCreateResult create_host_runtime(HostRuntimeConfig config) noexcept {
#if !LUMEN_LSP_RUNTIME_AVAILABLE
    (void) config;
    return {.status = RuntimeCreateStatus::provider_unavailable};
#else
    if (!valid_runtime_config(config)) {
      return {.status = RuntimeCreateStatus::invalid_configuration};
    }
    auto runtime = std::unique_ptr<ProductHostRuntime> {new (std::nothrow) ProductHostRuntime {std::move(config)}};
    if (!runtime) {
      return {.status = RuntimeCreateStatus::allocation_failed};
    }
    const auto status = runtime->initialize();
    if (status != RuntimeCreateStatus::ready) {
      return {.status = status};
    }
    return {
      .runtime = std::move(runtime),
      .status = RuntimeCreateStatus::ready,
    };
#endif
  }

  std::optional<RuntimeAdministrationSnapshot> administration_snapshot() {
    std::scoped_lock lock(runtime_registry_mutex);
    return registered_runtime ? std::optional {registered_runtime->administration_snapshot()} : std::nullopt;
  }

  std::vector<TrustedClientSummary> administration_trusted_clients() {
    std::scoped_lock lock(runtime_registry_mutex);
    return registered_runtime ? registered_runtime->trusted_clients() : std::vector<TrustedClientSummary> {};
  }

  bool administration_update_trusted_client(
    const Identifier128 &client_id,
    const PermissionSet permissions,
    const bool enabled
  ) {
    std::scoped_lock lock(runtime_registry_mutex);
    return registered_runtime && registered_runtime->update_trusted_client(client_id, permissions, enabled);
  }

  bool administration_revoke_trusted_client(const Identifier128 &client_id) {
    std::scoped_lock lock(runtime_registry_mutex);
    return registered_runtime && registered_runtime->revoke_trusted_client(client_id);
  }

  std::optional<std::string> administration_issue_pairing_invitation() {
    std::scoped_lock lock(runtime_registry_mutex);
    return registered_runtime ? registered_runtime->issue_pairing_invitation() : std::nullopt;
  }

  void administration_revoke_pairing_invitation() {
    std::scoped_lock lock(runtime_registry_mutex);
    if (registered_runtime) {
      registered_runtime->revoke_pairing_invitation();
    }
  }
}  // namespace lumen::lsp::runtime
