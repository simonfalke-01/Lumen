/**
 * @file src/protocol_lsp/runtime/host_runtime.cpp
 * @brief Production LSP host runtime factory and lifecycle.
 */

#include "host_runtime.h"

#include "../packet_classifier.h"
#include "../core/rtp.h"
#include "../security/wolfssl_dtls_server.h"
#include "../service.h"
#include "../session_authority.h"
#include "../ssrc_registry.h"
#include "../input_plane/rate.h"
#include "control_server.h"
#include "identity.h"
#include "input_owner.h"
#include "libsrtp_provider.h"
#include "udp_socket.h"

#ifndef LUMEN_LSP_RUNTIME_AVAILABLE
  #define LUMEN_LSP_RUNTIME_AVAILABLE 0
#endif

#if LUMEN_LSP_RUNTIME_AVAILABLE
  #include <wolfssl/options.h>
  #include <wolfssl/wolfcrypt/ed25519.h>
  #include <wolfssl/wolfcrypt/random.h>
  #include <wolfssl/wolfcrypt/hash.h>

  #include "../../httpcommon.h"
  #include "../../process.h"
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <charconv>
#include <cstdio>
#include <limits>
#include <mutex>
#include <new>
#include <ranges>
#include <string_view>
#include <thread>

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
      ).count());
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
            ) != 0 || wc_ed25519_check_key(&host_key_) != 0) {
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
               ) == 0 && size == signature.size();
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
                                            ) : imported;
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
        .send_datagram = secure_send_callback,
      });
      if (!srtp_ || !srtp_->ready(SrtpRequirements {})) {
        return RuntimeCreateStatus::srtp_failed;
      }
      input_owner_ = std::make_unique<InputOwner>(InputOwnerCallbacks {
        .context = this,
        .verify_digest = input_digest_callback,
        .send_acknowledgement = input_ack_callback,
        .baseline_committed = input_baseline_callback,
      });
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
      if (!active_) {
        return;
      }
      active_ = false;
      worker_.request_stop();
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
          (void)authority_.stop_from_host(NeutralizationReason::service_shutdown);
        }
        if (active_process_generation_ != 0) {
          (void)proc::proc.terminate_lsp_generation(active_process_generation_);
          active_process_generation_ = 0;
        }
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
      return {
        .active = active(),
        .profile = config_.host.profile,
        .port = config_.host.port,
        .invitation_uri = pairing_invitation_uri(),
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
    struct DtlsTimer {
      PeerEndpoint peer;  ///< Association being timed.
      std::uint64_t due_microseconds {};  ///< Monotonic due time.
    };

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
      const auto applications = applications_->snapshot();
      if (!applications || std::ranges::none_of(*applications, [&](const ControlApplication &application) {
            return application.id == request.application_id;
          })) {
        return std::unexpected(ControlStatus::malformed);
      }
      if (authority_.snapshot().state != SessionState::ready) {
        return std::unexpected(ControlStatus::busy);
      }

      const auto family = peer.family == IpAddressFamily::ipv6 ? input_plane::ip_family::ipv6 : input_plane::ip_family::ipv4;
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

      std::array<std::uint8_t, 8> ssrc_bytes {};
      if (!crypto_->random(ssrc_bytes)) {
        return std::unexpected(ControlStatus::internal_failure);
      }
      auto input_ssrc = wire::read_be<std::uint32_t>(std::span<const std::uint8_t> {ssrc_bytes}.first<4>());
      auto acknowledgement_ssrc = wire::read_be<std::uint32_t>(std::span<const std::uint8_t> {ssrc_bytes}.subspan<4, 4>());
      if (input_ssrc == 0) {
        input_ssrc = 1;
      }
      if (acknowledgement_ssrc == 0 || acknowledgement_ssrc == input_ssrc) {
        acknowledgement_ssrc = input_ssrc == std::numeric_limits<std::uint32_t>::max() ? input_ssrc - 1U : input_ssrc + 1U;
      }
      constexpr std::uint8_t input_payload_type = 96;
      const SsrcAssignment assignment {
        .ssrc = input_ssrc,
        .payload_type = input_payload_type,
        .lane = MediaLane::input,
        .direction = MediaDirection::client_to_host,
        .format = PayloadFormat::lsp_input,
        .clock_rate = 1'000'000,
        .generation = start.generations.input,
      };
      auto registry = SsrcRegistry::create(std::span<const SsrcAssignment> {&assignment, 1});
      if (!registry) {
        return std::unexpected(ControlStatus::internal_failure);
      }
      const AuthenticatedClient authority_client {
        .client_id = client.client_id,
        .connection_generation = connection_generation,
        .revocation_generation = client.revocation_generation,
        .permissions = client.permissions,
      };
      if (authority_.start(authority_client, start) != AuthorityResult::accepted) {
        return std::unexpected(ControlStatus::busy);
      }
      int numeric_application_id = 0;
      const auto parsed_application = std::from_chars(
        request.application_id.data(),
        request.application_id.data() + request.application_id.size(),
        numeric_application_id
      );
      if (parsed_application.ec != std::errc {} || parsed_application.ptr != request.application_id.data() + request.application_id.size() ||
          numeric_application_id <= 0) {
        (void)authority_.stop_from_host(NeutralizationReason::explicit_stop);
        return std::unexpected(ControlStatus::malformed);
      }
      const auto launched = proc::proc.execute_lsp_if_idle(numeric_application_id);
      if (launched.status != 0 || launched.process_generation == 0) {
        (void)authority_.stop_from_host(NeutralizationReason::explicit_stop);
        return std::unexpected(launched.status == 409 ? ControlStatus::busy : ControlStatus::internal_failure);
      }
      const InputSessionMapping mapping {
        .peer = peer,
        .client_id = client.client_id,
        .connection_generation = connection_generation,
        .session_generation = start.generations.stream,
        .input_generation = start.generations.input,
        .input_ssrc = input_ssrc,
        .acknowledgement_ssrc = acknowledgement_ssrc,
        .input_payload_type = input_payload_type,
      };
      if (!input_owner_->configure(mapping)) {
        (void)authority_.stop_from_host(NeutralizationReason::explicit_stop);
        (void)proc::proc.terminate_lsp_generation(launched.process_generation);
        return std::unexpected(ControlStatus::internal_failure);
      }
      active_client_ = authority_client;
      active_process_generation_ = launched.process_generation;
      active_rates_ = {
        .pointer = request.pointer_rate,
        .controller = request.controller_rate,
        .sensor = request.sensor_rate,
        .reconciliation = request.reconciliation_rate,
        .budget = total_budget,
      };
      last_attach_intent_ = {};
      detached_deadline_microseconds_ = 0;
      ssrc_registry_ = std::move(*registry);
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
      };
    }

    std::expected<AttachResponsePayload, ControlStatus> attach_input(
      const PeerEndpoint &peer,
      const TrustedClient &client,
      const std::uint32_t connection_generation,
      const AttachRequestPayload &request
    ) noexcept override {
      std::scoped_lock lock(session_mutex_);
      if (request.intent_id == last_attach_intent_ || active_process_generation_ == 0 || proc::proc.running() <= 0) {
        return std::unexpected(ControlStatus::stale_generation);
      }
      const auto previous_mapping = input_owner_ ? input_owner_->mapping() : std::nullopt;
      if (previous_mapping && previous_mapping->peer != peer && pending_association_close_count_ == pending_association_closes_.size()) {
        return std::unexpected(ControlStatus::busy);
      }
      Secret256 replacement_token {};
      std::array<std::uint8_t, 8> ssrc_bytes {};
      if (!crypto_->random(replacement_token) || !crypto_->random(ssrc_bytes)) {
        return std::unexpected(ControlStatus::internal_failure);
      }
      auto input_ssrc = wire::read_be<std::uint32_t>(std::span<const std::uint8_t> {ssrc_bytes}.first<4>());
      auto acknowledgement_ssrc = wire::read_be<std::uint32_t>(std::span<const std::uint8_t> {ssrc_bytes}.subspan<4, 4>());
      if (input_ssrc == 0) {
        input_ssrc = 1;
      }
      if (acknowledgement_ssrc == 0 || acknowledgement_ssrc == input_ssrc) {
        acknowledgement_ssrc = input_ssrc == std::numeric_limits<std::uint32_t>::max() ? input_ssrc - 1U : input_ssrc + 1U;
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
        replacement_token
      );
      if (prepared == AuthorityResult::permission_denied) {
        return std::unexpected(ControlStatus::permission_denied);
      }
      if (prepared == AuthorityResult::token_mismatch) {
        return std::unexpected(ControlStatus::authentication_failed);
      }
      if (prepared == AuthorityResult::not_owner || prepared == AuthorityResult::stale_generation ||
          prepared == AuthorityResult::generation_exhausted) {
        return std::unexpected(ControlStatus::stale_generation);
      }
      if (prepared != AuthorityResult::accepted) {
        return std::unexpected(ControlStatus::internal_failure);
      }
      const auto prior_snapshot = authority_.snapshot();
      if (prior_snapshot.generations.input == std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(ControlStatus::stale_generation);
      }
      const auto next_input_generation = prior_snapshot.generations.input + 1U;
      constexpr std::uint8_t input_payload_type = 96;
      const SsrcAssignment assignment {
        .ssrc = input_ssrc,
        .payload_type = input_payload_type,
        .lane = MediaLane::input,
        .direction = MediaDirection::client_to_host,
        .format = PayloadFormat::lsp_input,
        .clock_rate = 1'000'000,
        .generation = next_input_generation,
      };
      auto registry = SsrcRegistry::create(std::span<const SsrcAssignment> {&assignment, 1});
      const InputSessionMapping mapping {
        .peer = peer,
        .client_id = client.client_id,
        .connection_generation = connection_generation,
        .session_generation = prior_snapshot.generations.stream,
        .input_generation = next_input_generation,
        .input_ssrc = input_ssrc,
        .acknowledgement_ssrc = acknowledgement_ssrc,
        .input_payload_type = input_payload_type,
      };
      if (!registry || !input_owner_ || !input_owner_->ready_for_configuration(mapping)) {
        return std::unexpected(ControlStatus::internal_failure);
      }
      const auto result = authority_.attach(
        authority_client,
        request.session_id,
        request.attach_token,
        replacement_token
      );
      if (result != AuthorityResult::accepted) {
        return std::unexpected(result == AuthorityResult::neutralization_failed ? ControlStatus::internal_failure : ControlStatus::stale_generation);
      }
      input_owner_->commit_configuration(mapping);
      const auto snapshot = authority_.snapshot();
      active_client_ = authority_client;
      ssrc_registry_ = std::move(*registry);
      last_attach_intent_ = request.intent_id;
      detached_deadline_microseconds_ = 0;
      if (previous_mapping && previous_mapping->peer != peer) {
        queue_association_close(std::move(previous_mapping->peer));
      }
      return AttachResponsePayload {
        .session_id = snapshot.session_id,
        .attach_token = replacement_token,
        .connection_generation = snapshot.generations.connection,
        .stream_generation = snapshot.generations.stream,
        .input_generation = snapshot.generations.input,
        .input_ssrc = input_ssrc,
        .acknowledgement_ssrc = acknowledgement_ssrc,
        .input_payload_type = input_payload_type,
        .pointer_rate = active_rates_.pointer,
        .controller_rate = active_rates_.controller,
        .sensor_rate = active_rates_.sensor,
        .reconciliation_rate = active_rates_.reconciliation,
        .reserved_input_wire_bits_per_second = active_rates_.budget,
        .baseline_required = true,
      };
    }

    ControlStatus stop_input(
      const TrustedClient &client,
      const std::uint32_t connection_generation,
      const StopRequestPayload &request
    ) noexcept override {
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
      const auto process_stopped = active_process_generation_ == 0 ||
                                   proc::proc.terminate_lsp_generation(active_process_generation_);
      active_process_generation_ = 0;
      active_client_.reset();
      ssrc_registry_.reset();
      detached_deadline_microseconds_ = 0;
      last_attach_intent_ = {};
      return process_stopped ? ControlStatus::success : ControlStatus::internal_failure;
    }

    bool neutralize(const NeutralizationRequest &request) noexcept override {
      (void)request;
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
        (void)socket_.wait_readable(runtime_poll_milliseconds);
        const auto result = socket_.receive_batch(runtime_receive_batch, [this](const ReceivedDatagram &datagram) {
          if (classify_packet(datagram.payload) == PacketClass::dtls) {
            refresh_dtls_timer(datagram.peer, datagram.received_at_microseconds);
          }
          if (service_) {
            service_->receive(datagram.peer, datagram.payload);
          }
          process_pending_association_closes();
          if (classify_packet(datagram.payload) == PacketClass::dtls) {
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
        process_dtls_timers(now);
        process_detached_grace(now);
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
                         std::numeric_limits<std::uint64_t>::max() : now_microseconds + delay;
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
        const auto result = dtls_->handle_timeout(peer);
        dtls_timers_.erase(dtls_timers_.begin() + static_cast<std::ptrdiff_t>(index));
        if (result == WolfsslDtlsOperationResult::accepted) {
          refresh_dtls_timer(peer, now_microseconds);
        }
      }
    }

    void queue_association_close(PeerEndpoint peer) noexcept {
      for (std::size_t index = 0; index < pending_association_close_count_; ++index) {
        if (pending_association_closes_[index] == peer) {
          return;
        }
      }
      if (pending_association_close_count_ < pending_association_closes_.size()) {
        pending_association_closes_[pending_association_close_count_++] = std::move(peer);
      }
    }

    void process_pending_association_closes() noexcept {
      std::scoped_lock lock(session_mutex_);
      while (pending_association_close_count_ != 0) {
        auto peer = std::move(pending_association_closes_[--pending_association_close_count_]);
        pending_association_closes_[pending_association_close_count_] = {};
        if (dtls_) {
          (void)dtls_->close_association(peer);
        }
      }
    }

    void process_detached_grace(const std::uint64_t now_microseconds) noexcept {
      std::scoped_lock lock(session_mutex_);
      if (detached_deadline_microseconds_ == 0 || now_microseconds < detached_deadline_microseconds_) {
        return;
      }
      detached_deadline_microseconds_ = 0;
      if (authority_.snapshot().state == SessionState::detached) {
        (void)authority_.stop_from_host(NeutralizationReason::transport_loss);
        if (active_process_generation_ != 0) {
          (void)proc::proc.terminate_lsp_generation(active_process_generation_);
          active_process_generation_ = 0;
        }
        active_client_.reset();
        ssrc_registry_.reset();
        last_attach_intent_ = {};
      }
    }

    static bool dtls_send_callback(
      void *context,
      const PeerEndpoint &peer,
      const std::span<const std::uint8_t> datagram
    ) noexcept {
      return static_cast<ProductHostRuntime *>(context)->socket_.send_datagram(peer, datagram);
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
      if (runtime.control_->association_ready(peer) == 0) {
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
      std::scoped_lock session_lock(runtime.session_mutex_);
      if (runtime.input_owner_) {
        const auto mapping = runtime.input_owner_->mapping();
        if (mapping && mapping->peer == peer) {
          (void)runtime.authority_.transport_lost(mapping->connection_generation);
          runtime.detached_deadline_microseconds_ = monotonic_microseconds() + attach_grace_microseconds;
          runtime.ssrc_registry_.reset();
          runtime.active_client_.reset();
        }
      }
      if (runtime.srtp_) {
        runtime.srtp_->remove_association(peer);
      }
      if (runtime.control_) {
        runtime.control_->association_closed(peer);
      }
      const auto timer = std::ranges::find(runtime.dtls_timers_, peer, &DtlsTimer::peer);
      if (timer != runtime.dtls_timers_.end()) {
        runtime.dtls_timers_.erase(timer);
      }
    }

    static bool secure_packet_callback(
      void *context,
      const PeerEndpoint &peer,
      const SecurePacketClass packet_class,
      const std::span<const std::uint8_t> plaintext
    ) noexcept {
      auto &runtime = *static_cast<ProductHostRuntime *>(context);
      std::scoped_lock session_lock(runtime.session_mutex_);
      if (!runtime.input_owner_) {
        return true;
      }
      if (packet_class == SecurePacketClass::rtcp) {
        return runtime.input_owner_->receive_rtcp(peer, plaintext);
      }
      if (!runtime.ssrc_registry_) {
        return true;
      }
      const auto rtp = parse_rtp_fixed_header(plaintext);
      if (!rtp) {
        return true;
      }
      const auto *assignment = runtime.ssrc_registry_->find(rtp.header.ssrc);
      if (assignment == nullptr || assignment->lane != MediaLane::input ||
          assignment->payload_type != rtp.header.payload_type || assignment->generation == 0) {
        return true;
      }
      return runtime.input_owner_->receive(peer, plaintext);
    }

    static bool secure_send_callback(
      void *context,
      const PeerEndpoint &peer,
      const std::span<const std::uint8_t> datagram
    ) noexcept {
      return static_cast<ProductHostRuntime *>(context)->socket_.send_datagram(peer, datagram);
    }

    static bool input_digest_callback(
      void *context,
      const std::span<const std::uint8_t> bytes,
      const Digest256 &expected
    ) noexcept {
      auto &runtime = *static_cast<ProductHostRuntime *>(context);
      std::scoped_lock session_lock(runtime.session_mutex_);
      Digest256 actual {};
      return runtime.crypto_ && runtime.crypto_->sha256(bytes, actual) && runtime.crypto_->equal_secret(actual, expected);
    }

    static bool input_ack_callback(
      void *context,
      const PeerEndpoint &peer,
      const std::span<const std::uint8_t> rtcp_packet
    ) noexcept {
      auto &runtime = *static_cast<ProductHostRuntime *>(context);
      return runtime.srtp_ && runtime.srtp_->protect_and_send(peer, SecurePacketClass::rtcp, rtcp_packet);
    }

    static bool input_baseline_callback(
      void *context,
      const PeerEndpoint &peer,
      const std::uint32_t session_generation,
      const std::uint32_t input_generation
    ) noexcept {
      auto &runtime = *static_cast<ProductHostRuntime *>(context);
      std::scoped_lock session_lock(runtime.session_mutex_);
      if (!runtime.active_client_ || !runtime.input_owner_) {
        return false;
      }
      const auto mapping = runtime.input_owner_->mapping();
      return mapping && mapping->peer == peer && runtime.authority_.commit_input_baseline(
                                                  *runtime.active_client_,
                                                  session_generation,
                                                  input_generation
                                                ) == AuthorityResult::accepted;
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
    std::uint32_t next_stream_generation_ {1};  ///< Next nonzero input-only session generation.
    std::uint64_t active_process_generation_ {};  ///< Generation-qualified LSP-owned application process.
    struct ActiveRates {
      std::uint32_t pointer {};  ///< Selected pointer reports/s.
      std::uint32_t controller {};  ///< Selected controller reports/s.
      std::uint32_t sensor {};  ///< Selected sensor reports/s.
      std::uint32_t reconciliation {};  ///< Selected reconciliation reports/s.
      std::uint64_t budget {};  ///< Reserved input wire bits/s.
    } active_rates_;  ///< Retained input selection across ATTACH/rekey.
    Identifier128 last_attach_intent_ {};  ///< Last consumed attach intent, preventing semantic replay.
    std::uint64_t detached_deadline_microseconds_ {};  ///< Bounded process-hold deadline.
    mutable std::recursive_mutex session_mutex_;  ///< Synchronizes socket authority with the input apply worker.
    std::vector<DtlsTimer> dtls_timers_;  ///< Bounded association retransmission timers.
    std::array<PeerEndpoint, 64> pending_association_closes_ {};  ///< Old associations retired after response submission.
    std::size_t pending_association_close_count_ {};  ///< Live leading deferred-close entries.
    std::jthread worker_;  ///< Socket receive/control timer owner.
    std::optional<std::string> pairing_uri_;  ///< Current UI-bound invitation issuance copy.
    std::uint64_t pairing_expiration_utc_seconds_ {};  ///< Current invitation expiry.
    std::atomic<bool> active_ {};  ///< Listener/worker availability.
    mutable std::recursive_mutex administration_mutex_;  ///< Synchronizes invitation and web administration state.
  };
#endif

  HostRuntimeCreateResult create_host_runtime(HostRuntimeConfig config) noexcept {
#if !LUMEN_LSP_RUNTIME_AVAILABLE
    (void)config;
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
