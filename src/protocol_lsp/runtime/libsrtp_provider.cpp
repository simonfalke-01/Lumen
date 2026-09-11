/**
 * @file src/protocol_lsp/runtime/libsrtp_provider.cpp
 * @brief Concrete libSRTP 2.8.0 association provider for the LSP runtime.
 */

#include "libsrtp_provider.h"

#include "../core/wire.h"
#include "../security/secure_zero.h"

#ifndef LUMEN_LSP_LIBSRTP_AVAILABLE
  #define LUMEN_LSP_LIBSRTP_AVAILABLE 0
#endif

#if LUMEN_LSP_LIBSRTP_AVAILABLE
  #if __has_include(<srtp2/srtp.h>)
    #include <srtp2/srtp.h>
  #else
    #include <srtp.h>
  #endif
#endif

#include <algorithm>
#include <array>
#include <limits>
#include <mutex>
#include <new>
#include <shared_mutex>
#include <unordered_map>
#include <utility>

namespace lumen::lsp::runtime {
  namespace {
    [[maybe_unused]] constexpr std::size_t maximum_protected_packet_bytes = 2'048;  ///< Provider-wide bounded UDP payload slab.
#if LUMEN_LSP_LIBSRTP_AVAILABLE
    constexpr std::size_t srtp_master_material_size = srtp_aes_128_key_size + srtp_aead_salt_size;
    constexpr std::size_t maximum_streams_per_direction = 32;
    constexpr std::size_t maximum_encrypted_extension_ids = 14;

    /** @brief Hash one exact association five-tuple for bounded lookup. */
    struct PeerEndpointHash {
      std::size_t operator()(const PeerEndpoint &peer) const noexcept {
        auto hash = std::hash<std::string> {}(peer.local_address);
        hash ^= std::hash<std::string> {}(peer.remote_address) + 0x9e3779b9U + (hash << 6U) + (hash >> 2U);
        hash ^= static_cast<std::size_t>(peer.local_port) << 16U;
        hash ^= std::hash<std::uint32_t> {}(peer.interface_index) + 0x9e3779b9U + (hash << 6U) + (hash >> 2U);
        hash ^= std::hash<std::uint32_t> {}(peer.canonical_remote.scope_id) + 0x9e3779b9U + (hash << 6U) + (hash >> 2U);
        hash ^= peer.remote_port;
        hash ^= static_cast<std::size_t>(peer.family) << 1U;
        return hash;
      }
    };

    /** @brief Extract the packet-visible SSRC before any libSRTP state lookup. */
    [[nodiscard]] std::optional<std::uint32_t> packet_ssrc(
      const SecurePacketClass packet_class,
      const std::span<const std::uint8_t> packet
    ) noexcept {
      if (packet_class == SecurePacketClass::rtp) {
        return packet.size() >= 12U ?
                 std::optional<std::uint32_t> {wire::read_be<std::uint32_t>(packet.subspan<8, 4>())} :
                 std::nullopt;
      }
      if (packet_class == SecurePacketClass::rtcp) {
        return packet.size() >= 8U ?
                 std::optional<std::uint32_t> {wire::read_be<std::uint32_t>(packet.subspan<4, 4>())} :
                 std::nullopt;
      }
      return std::nullopt;
    }
#endif
  }  // namespace

  class LibsrtpServerProvider::Impl {
  public:
    Impl(const LibsrtpCallbacks callbacks, const std::size_t maximum_associations) noexcept:
        callbacks_ {callbacks},
        maximum_associations_ {maximum_associations} {
#if LUMEN_LSP_LIBSRTP_AVAILABLE
      static std::once_flag once;
      static bool initialized = false;
      try {
        std::call_once(once, []() noexcept {
          initialized = srtp_init() == srtp_err_status_ok;
        });
        ready_ = initialized && callbacks_.plaintext_packet != nullptr &&
                 maximum_associations_ > 0 && maximum_associations_ <= 64;
        if (ready_) {
          associations_.reserve(maximum_associations_);
        }
      } catch (...) {
        ready_ = false;
      }
#else
      (void) callbacks_;
      (void) maximum_associations_;
#endif
    }

    ~Impl() {
#if LUMEN_LSP_LIBSRTP_AVAILABLE
      for (const auto &[peer, association] : associations_) {
        (void) peer;
        association->retire();
      }
      associations_.clear();
#endif
    }

    [[nodiscard]] bool ready(const SrtpRequirements &requirements) const noexcept {
      return ready_ && requirements.protection_profile == "SRTP_AEAD_AES_128_GCM" &&
             requirements.exporter_label == "EXTRACTOR-dtls_srtp" && requirements.require_replay_protection &&
             requirements.require_encrypted_extensions && !requirements.allow_mki;
    }

    ProviderDatagramResult receive(
      const PeerEndpoint &peer,
      const SecurePacketClass packet_class,
      const std::span<std::uint8_t> datagram,
      const std::uint64_t received_at_microseconds,
      const IpEcn ecn
    ) noexcept {
#if !LUMEN_LSP_LIBSRTP_AVAILABLE
      (void) peer;
      (void) packet_class;
      (void) datagram;
      (void) received_at_microseconds;
      (void) ecn;
      return ProviderDatagramResult::fatal;
#else
      auto association = find_cached(peer);
      const auto visible_ssrc = packet_ssrc(packet_class, datagram);
      if (!ready_ || !association || !visible_ssrc || *visible_ssrc == 0 || datagram.empty() ||
          datagram.size() > maximum_protected_packet_bytes) {
        secure_zero(datagram);
        return ProviderDatagramResult::dropped;
      }
      const auto protected_bytes = datagram.size();
      std::size_t plaintext_bytes = 0;
      auto *stream = association->find_stream(MediaDirection::client_to_host, *visible_ssrc);
      if (stream == nullptr) {
        secure_zero(datagram);
        return ProviderDatagramResult::dropped;
      }
      std::optional<SrtpLifetimeEvent> lifetime_event;
      {
        std::scoped_lock lock(stream->mutex);
        if (!association->active.load(std::memory_order_acquire) || stream->context == nullptr ||
            packet_count(*stream, packet_class) >= hard_packet_limit(packet_class)) {
          secure_zero(datagram);
          return ProviderDatagramResult::fatal;
        }
        auto size = static_cast<int>(datagram.size());
        const auto status = packet_class == SecurePacketClass::rtcp ?
                              srtp_unprotect_rtcp(stream->context, datagram.data(), &size) :
                              srtp_unprotect(stream->context, datagram.data(), &size);
        if (status != srtp_err_status_ok || size <= 0) {
          secure_zero(datagram);
          return ProviderDatagramResult::dropped;
        }
        plaintext_bytes = static_cast<std::size_t>(size);
        lifetime_event = record_lifetime(*stream, packet_class);
      }
      if (!association->active.load(std::memory_order_acquire)) {
        secure_zero(datagram);
        return ProviderDatagramResult::dropped;
      }
      unprotected_packets_.fetch_add(1, std::memory_order_relaxed);
      publish_lifetime(*association, *stream, MediaDirection::client_to_host, lifetime_event);
      const auto accepted = callbacks_.plaintext_packet(
        callbacks_.context,
        peer,
        packet_class,
        std::span<const std::uint8_t> {datagram.data(), plaintext_bytes},
        protected_bytes,
        received_at_microseconds,
        ecn
      );
      secure_zero(datagram);
      return accepted ? ProviderDatagramResult::accepted : ProviderDatagramResult::fatal;
#endif
    }

    bool install(const PeerEndpoint &peer, const DtlsSrtpKeyMaterial &key_material) noexcept {
#if !LUMEN_LSP_LIBSRTP_AVAILABLE
      (void) peer;
      (void) key_material;
      return false;
#else
      if (!ready_ || !peer.valid()) {
        return false;
      }
      auto association = std::shared_ptr<Association> {new (std::nothrow) Association};
      if (!association) {
        return false;
      }
      try {
        association->peer = peer;
      } catch (...) {
        return false;
      }
      std::copy(
        key_material.client_write_key.begin(),
        key_material.client_write_key.end(),
        association->inbound_material.begin()
      );
      std::copy(
        key_material.client_write_salt.begin(),
        key_material.client_write_salt.end(),
        association->inbound_material.begin() + srtp_aes_128_key_size
      );
      std::copy(
        key_material.server_write_key.begin(),
        key_material.server_write_key.end(),
        association->outbound_material.begin()
      );
      std::copy(
        key_material.server_write_salt.begin(),
        key_material.server_write_salt.end(),
        association->outbound_material.begin() + srtp_aes_128_key_size
      );

      std::unique_lock lock(associations_mutex_);
      if (associations_.size() >= maximum_associations_ && !associations_.contains(peer)) {
        return false;
      }
      try {
        if (const auto prior = associations_.find(peer); prior != associations_.end()) {
          prior->second->retire();
        }
        associations_.insert_or_assign(peer, std::move(association));
      } catch (...) {
        return false;
      }
      return true;
#endif
    }

    /** @brief Install one exact stream in its thread-owned directional context. */
    bool install_stream(
      const PeerEndpoint &peer,
      const MediaDirection direction,
      const std::uint32_t ssrc,
      const std::span<const int> encrypted_extension_ids
    ) noexcept {
#if !LUMEN_LSP_LIBSRTP_AVAILABLE
      (void) peer;
      (void) direction;
      (void) ssrc;
      (void) encrypted_extension_ids;
      return false;
#else
      auto association = find_cached(peer);
      if (!ready_ || !association || ssrc == 0 ||
          encrypted_extension_ids.size() > maximum_encrypted_extension_ids) {
        return false;
      }
      std::array<int, maximum_encrypted_extension_ids> extension_ids {};
      for (std::size_t index = 0; index < encrypted_extension_ids.size(); ++index) {
        const auto id = encrypted_extension_ids[index];
        bool duplicate = false;
        for (std::size_t prior = 0; prior < index; ++prior) {
          duplicate = duplicate || extension_ids[prior] == id;
        }
        if (id <= 0 || id >= 15 || duplicate) {
          return false;
        }
        extension_ids[index] = id;
      }
      const auto inbound = direction == MediaDirection::client_to_host;
      std::scoped_lock lock(association->install_mutex);
      if (!association->active.load(std::memory_order_acquire)) {
        return false;
      }
      if (association->find_stream(direction, ssrc) != nullptr) {
        return true;
      }
      auto &streams = inbound ? association->inbound_streams : association->outbound_streams;
      auto &stream_count = inbound ? association->inbound_stream_count : association->outbound_stream_count;
      const auto count = stream_count.load(std::memory_order_relaxed);
      if (count == streams.size()) {
        return false;
      }
      auto stream = std::unique_ptr<StreamState> {new (std::nothrow) StreamState};
      if (!stream) {
        return false;
      }
      srtp_policy_t policy {};
      srtp_crypto_policy_set_aes_gcm_128_16_auth(&policy.rtp);
      srtp_crypto_policy_set_aes_gcm_128_16_auth(&policy.rtcp);
      policy.ssrc.type = ssrc_specific;
      policy.ssrc.value = ssrc;
      policy.key = inbound ? association->inbound_material.data() : association->outbound_material.data();
      policy.window_size = 128;
      policy.allow_repeat_tx = 0;
      policy.enc_xtn_hdr = encrypted_extension_ids.empty() ? nullptr : extension_ids.data();
      policy.enc_xtn_hdr_count = static_cast<int>(encrypted_extension_ids.size());
      policy.next = nullptr;
      if (srtp_create(&stream->context, &policy) != srtp_err_status_ok) {
        return false;
      }
      stream->ssrc = ssrc;
      streams[count] = std::move(stream);
      stream_count.store(count + 1U, std::memory_order_release);
      return true;
#endif
    }

    bool remove(const PeerEndpoint &peer) noexcept {
#if !LUMEN_LSP_LIBSRTP_AVAILABLE
      (void) peer;
      return false;
#else
      std::unique_lock lock(associations_mutex_);
      const auto entry = associations_.find(peer);
      if (entry == associations_.end()) {
        return false;
      }
      entry->second->retire();
      associations_.erase(entry);
      return true;
#endif
    }

    [[nodiscard]] std::optional<std::size_t> protect_trailer_length(
      const PeerEndpoint &peer,
      const SecurePacketClass packet_class
    ) const noexcept {
#if !LUMEN_LSP_LIBSRTP_AVAILABLE
      (void) peer;
      (void) packet_class;
      return std::nullopt;
#else
      auto association = find_cached(peer);
      if (!ready_ || !association) {
        return std::nullopt;
      }
      auto *stream = association->outbound_stream_count.load(std::memory_order_acquire) == 0 ?
                       nullptr :
                       association->outbound_streams[0].get();
      if (stream == nullptr) {
        return std::nullopt;
      }
      std::scoped_lock lock(stream->mutex);
      if (!association->active.load(std::memory_order_acquire) || stream->context == nullptr) {
        return std::nullopt;
      }
      std::uint32_t length = 0;
      const auto status = packet_class == SecurePacketClass::rtcp ?
                            srtp_get_protect_rtcp_trailer_length(stream->context, 0, 0, &length) :
                            srtp_get_protect_trailer_length(stream->context, 0, 0, &length);
      return status == srtp_err_status_ok && length != 0 ? std::optional<std::size_t> {length} : std::nullopt;
#endif
    }

    bool protect_in_place(
      const PeerEndpoint &peer,
      const SecurePacketClass packet_class,
      const std::span<std::uint8_t> packet_storage,
      const std::size_t plaintext_bytes,
      std::size_t &protected_bytes
    ) noexcept {
      protected_bytes = 0;
#if !LUMEN_LSP_LIBSRTP_AVAILABLE
      (void) peer;
      (void) packet_class;
      (void) packet_storage;
      (void) plaintext_bytes;
      return false;
#else
      auto association = find_cached(peer);
      const auto visible_ssrc = plaintext_bytes <= packet_storage.size() ?
                                  packet_ssrc(packet_class, packet_storage.first(plaintext_bytes)) :
                                  std::nullopt;
      if (!ready_ || !association || !visible_ssrc || *visible_ssrc == 0 || plaintext_bytes == 0 ||
          plaintext_bytes > packet_storage.size() || packet_storage.size() > maximum_protected_packet_bytes) {
        return false;
      }
      auto *stream = association->find_stream(MediaDirection::host_to_client, *visible_ssrc);
      if (stream == nullptr) {
        return false;
      }
      std::optional<SrtpLifetimeEvent> lifetime_event;
      {
        std::scoped_lock lock(stream->mutex);
        if (!association->active.load(std::memory_order_acquire) || stream->context == nullptr ||
            packet_count(*stream, packet_class) >= hard_packet_limit(packet_class)) {
          return false;
        }
        std::uint32_t trailer = 0;
        const auto trailer_status = packet_class == SecurePacketClass::rtcp ?
                                      srtp_get_protect_rtcp_trailer_length(stream->context, 0, 0, &trailer) :
                                      srtp_get_protect_trailer_length(stream->context, 0, 0, &trailer);
        if (trailer_status != srtp_err_status_ok || packet_storage.size() - plaintext_bytes < trailer) {
          return false;
        }
        auto size = static_cast<int>(plaintext_bytes);
        const auto status = packet_class == SecurePacketClass::rtcp ?
                              srtp_protect_rtcp(stream->context, packet_storage.data(), &size) :
                              srtp_protect(stream->context, packet_storage.data(), &size);
        if (status != srtp_err_status_ok || size <= 0 || static_cast<std::size_t>(size) > packet_storage.size()) {
          return false;
        }
        protected_bytes = static_cast<std::size_t>(size);
        lifetime_event = record_lifetime(*stream, packet_class);
      }
      if (!association->active.load(std::memory_order_acquire)) {
        protected_bytes = 0;
        secure_zero(packet_storage);
        return false;
      }
      protected_packets_.fetch_add(1, std::memory_order_relaxed);
      publish_lifetime(*association, *stream, MediaDirection::host_to_client, lifetime_event);
      return true;
#endif
    }

    [[nodiscard]] std::size_t association_count() const noexcept {
#if LUMEN_LSP_LIBSRTP_AVAILABLE
      std::shared_lock lock(associations_mutex_);
      return associations_.size();
#else
      return 0;
#endif
    }

    [[nodiscard]] LibsrtpProviderSnapshot snapshot() const noexcept {
      return {
        .protected_packets = protected_packets_.load(std::memory_order_relaxed),
        .unprotected_packets = unprotected_packets_.load(std::memory_order_relaxed),
        .soft_lifetime_events = soft_lifetime_events_.load(std::memory_order_relaxed),
        .hard_lifetime_events = hard_lifetime_events_.load(std::memory_order_relaxed),
      };
    }

  private:
#if LUMEN_LSP_LIBSRTP_AVAILABLE
    static constexpr std::uint64_t srtp_hard_packet_limit =
      (std::uint64_t {1} << 48U) / maximum_streams_per_direction -
      1U;  ///< Per-SSRC share that bounds aggregate directional SRTP key use.
    static constexpr std::uint64_t srtp_rekey_margin = 100'000'000U;  ///< About 1,000 seconds at the endpoint packet-rate ceiling.
    static constexpr std::uint64_t srtp_soft_packet_limit = srtp_hard_packet_limit - srtp_rekey_margin;  ///< Planned-rekey SRTP threshold.
    static constexpr std::uint64_t srtcp_hard_packet_limit =
      (std::uint64_t {1} << 31U) / maximum_streams_per_direction -
      1U;  ///< Per-SSRC share that bounds aggregate directional SRTCP key use.
    static constexpr std::uint64_t srtcp_rekey_margin = 1'000'000U;  ///< About 1,000 seconds at the controller-output ceiling.
    static constexpr std::uint64_t srtcp_soft_packet_limit = srtcp_hard_packet_limit - srtcp_rekey_margin;  ///< Planned-rekey SRTCP threshold.
    static_assert((srtp_hard_packet_limit + 1U) * maximum_streams_per_direction <= (std::uint64_t {1} << 48U));
    static_assert((srtcp_hard_packet_limit + 1U) * maximum_streams_per_direction <= (std::uint64_t {1} << 31U));
    static_assert(srtp_rekey_margin < srtp_hard_packet_limit);
    static_assert(srtcp_rekey_margin < srtcp_hard_packet_limit);

    struct StreamState {
      srtp_t context {};  ///< Exact one-SSRC libSRTP context.
      std::uint32_t ssrc {};  ///< Installed stream identity.
      std::uint64_t rtp_packets {};  ///< Successful SRTP operations under the stream mutex.
      std::uint64_t rtcp_packets {};  ///< Successful SRTCP operations under the stream mutex.
      std::mutex mutex;  ///< Serializes only this SSRC's replay/sequence state.
      std::atomic<bool> soft_reported {};  ///< Whether soft lifetime was signalled.
      std::atomic<bool> hard_reported {};  ///< Whether hard lifetime was signalled.

      ~StreamState() {
        if (context != nullptr) {
          srtp_dealloc(context);
        }
      }
    };

    struct Association {
      PeerEndpoint peer;  ///< Exact five-tuple.
      std::array<std::uint8_t, srtp_master_material_size> inbound_material {};  ///< Retained client-write master material.
      std::array<std::uint8_t, srtp_master_material_size> outbound_material {};  ///< Retained server-write master material.
      std::array<std::unique_ptr<StreamState>, maximum_streams_per_direction> inbound_streams {};  ///< Client-write contexts.
      std::array<std::unique_ptr<StreamState>, maximum_streams_per_direction> outbound_streams {};  ///< Server-write contexts.
      std::atomic<std::size_t> inbound_stream_count {};  ///< Release-published inbound entries.
      std::atomic<std::size_t> outbound_stream_count {};  ///< Release-published outbound entries.
      std::mutex install_mutex;  ///< Setup-only stream publication serialization.
      std::atomic<bool> active {true};  ///< False before map replacement/removal.

      /** @brief Construct an empty exact-stream association. */
      Association() = default;
      Association(const Association &) = delete;
      Association &operator=(const Association &) = delete;

      /** @brief Deallocate directional contexts and clear retained master material. */
      ~Association() {
        retire();
      }

      /** @brief Quiesce every per-SSRC context and wipe retained exporter material. */
      void retire() noexcept {
        std::scoped_lock install_lock(install_mutex);
        if (!active.exchange(false, std::memory_order_acq_rel)) {
          return;
        }
        const auto retire_streams = [](auto &streams) noexcept {
          for (auto &stream : streams) {
            if (!stream) {
              continue;
            }
            std::scoped_lock stream_lock(stream->mutex);
            if (stream->context != nullptr) {
              srtp_dealloc(stream->context);
              stream->context = nullptr;
            }
          }
        };
        retire_streams(inbound_streams);
        retire_streams(outbound_streams);
        secure_zero(inbound_material);
        secure_zero(outbound_material);
      }

      [[nodiscard]] StreamState *find_stream(
        const MediaDirection direction,
        const std::uint32_t ssrc
      ) const noexcept {
        const auto &streams = direction == MediaDirection::client_to_host ? inbound_streams : outbound_streams;
        const auto count = direction == MediaDirection::client_to_host ?
                             inbound_stream_count.load(std::memory_order_acquire) :
                             outbound_stream_count.load(std::memory_order_acquire);
        for (std::size_t index = 0; index < count; ++index) {
          if (streams[index] && streams[index]->ssrc == ssrc) {
            return streams[index].get();
          }
        }
        return nullptr;
      }
    };

    /**
     * @brief Return the conservative AEAD invocation ceiling for one packet class.
     *
     * @param packet_class RTP or RTCP lifetime namespace.
     * @return Maximum successful invocations admitted for that namespace.
     */
    [[nodiscard]] static constexpr std::uint64_t hard_packet_limit(
      const SecurePacketClass packet_class
    ) noexcept {
      return packet_class == SecurePacketClass::rtcp ? srtcp_hard_packet_limit : srtp_hard_packet_limit;
    }

    /**
     * @brief Return the planned-rekey threshold for one packet class.
     *
     * @param packet_class RTP or RTCP lifetime namespace.
     * @return First invocation count that requests a fresh association.
     */
    [[nodiscard]] static constexpr std::uint64_t soft_packet_limit(
      const SecurePacketClass packet_class
    ) noexcept {
      return packet_class == SecurePacketClass::rtcp ? srtcp_soft_packet_limit : srtp_soft_packet_limit;
    }

    /**
     * @brief Return the mutex-owned successful-operation counter for one packet class.
     *
     * @param stream Exact one-SSRC stream state.
     * @param packet_class RTP or RTCP lifetime namespace.
     * @return Reference to the selected counter.
     */
    [[nodiscard]] static std::uint64_t &packet_count(
      StreamState &stream,
      const SecurePacketClass packet_class
    ) noexcept {
      return packet_class == SecurePacketClass::rtcp ? stream.rtcp_packets : stream.rtp_packets;
    }

    /**
     * @brief Record one successful invocation and return its first lifetime transition.
     *
     * @param stream Exact one-SSRC stream state.
     * @param packet_class RTP or RTCP lifetime namespace.
     * @return First soft/hard transition, or no event below a new threshold.
     */
    [[nodiscard]] std::optional<SrtpLifetimeEvent> record_lifetime(
      StreamState &stream,
      const SecurePacketClass packet_class
    ) noexcept {
      const auto packets = ++packet_count(stream, packet_class);
      if (packets >= hard_packet_limit(packet_class) &&
          !stream.hard_reported.exchange(true, std::memory_order_acq_rel)) {
        hard_lifetime_events_.fetch_add(1, std::memory_order_relaxed);
        return SrtpLifetimeEvent::hard_limit;
      } else if (packets >= soft_packet_limit(packet_class) &&
                 !stream.soft_reported.exchange(true, std::memory_order_acq_rel)) {
        soft_lifetime_events_.fetch_add(1, std::memory_order_relaxed);
        return SrtpLifetimeEvent::soft_limit;
      }
      return std::nullopt;
    }

    void publish_lifetime(
      const Association &association,
      const StreamState &stream,
      const MediaDirection direction,
      const std::optional<SrtpLifetimeEvent> event
    ) noexcept {
      if (event && callbacks_.lifetime_event != nullptr) {
        callbacks_.lifetime_event(callbacks_.context, association.peer, stream.ssrc, direction, *event);
      }
    }

    [[nodiscard]] Association *find_cached(const PeerEndpoint &peer) const noexcept {
      struct ThreadCache {
        const Impl *owner {};
        PeerEndpoint peer;
        std::shared_ptr<Association> association;
      };

      thread_local ThreadCache cache;
      if (cache.owner == this && cache.peer == peer && cache.association &&
          cache.association->active.load(std::memory_order_acquire)) {
        return cache.association.get();
      }
      std::shared_lock lock(associations_mutex_);
      const auto entry = associations_.find(peer);
      auto association = entry == associations_.end() ? std::shared_ptr<Association> {} : entry->second;
      lock.unlock();
      try {
        cache.peer = peer;
        cache.owner = this;
        cache.association = std::move(association);
      } catch (...) {
        cache.owner = nullptr;
        cache.association = {};
        return nullptr;
      }
      return cache.association && cache.association->active.load(std::memory_order_acquire) ?
               cache.association.get() :
               nullptr;
    }

    std::unordered_map<PeerEndpoint, std::shared_ptr<Association>, PeerEndpointHash> associations_;  ///< Bounded exact association map.
    mutable std::shared_mutex associations_mutex_;  ///< Short lifetime-only map synchronization, never held during crypto.
#endif
    LibsrtpCallbacks callbacks_;  ///< Socket and lane callbacks.
    std::size_t maximum_associations_ {};  ///< Hard association bound.
    alignas(64) std::atomic<std::uint64_t> protected_packets_ {};  ///< Single-writer outbound protection count.
    alignas(64) std::atomic<std::uint64_t> unprotected_packets_ {};  ///< Single-writer inbound authentication count.
    std::atomic<std::uint64_t> soft_lifetime_events_ {};  ///< First soft-limit events.
    std::atomic<std::uint64_t> hard_lifetime_events_ {};  ///< First hard-limit events.
    bool ready_ {};  ///< Process initialization and callback readiness.
  };

  LibsrtpServerProvider::LibsrtpServerProvider(
    const LibsrtpCallbacks callbacks,
    const std::size_t maximum_associations
  ) noexcept:
      impl_ {new (std::nothrow) Impl {callbacks, maximum_associations}} {
  }

  LibsrtpServerProvider::~LibsrtpServerProvider() = default;

  bool LibsrtpServerProvider::ready(const SrtpRequirements &requirements) const noexcept {
    return impl_ && impl_->ready(requirements);
  }

  ProviderDatagramResult LibsrtpServerProvider::receive_secure_packet(
    const PeerEndpoint &peer,
    const SecurePacketClass packet_class,
    const std::span<std::uint8_t> datagram,
    const std::uint64_t received_at_microseconds,
    const IpEcn ecn
  ) noexcept {
    return impl_ ?
             impl_->receive(peer, packet_class, datagram, received_at_microseconds, ecn) :
             ProviderDatagramResult::fatal;
  }

  bool LibsrtpServerProvider::install_association(
    const PeerEndpoint &peer,
    const DtlsSrtpKeyMaterial &key_material
  ) noexcept {
    return impl_ && impl_->install(peer, key_material);
  }

  bool LibsrtpServerProvider::install_stream(
    const PeerEndpoint &peer,
    const MediaDirection direction,
    const std::uint32_t ssrc,
    const std::span<const int> encrypted_extension_ids
  ) noexcept {
    return impl_ && impl_->install_stream(peer, direction, ssrc, encrypted_extension_ids);
  }

  bool LibsrtpServerProvider::remove_association(const PeerEndpoint &peer) noexcept {
    return impl_ && impl_->remove(peer);
  }

  std::optional<std::size_t> LibsrtpServerProvider::protect_trailer_length(
    const PeerEndpoint &peer,
    const SecurePacketClass packet_class
  ) const noexcept {
    return impl_ ? impl_->protect_trailer_length(peer, packet_class) : std::nullopt;
  }

  bool LibsrtpServerProvider::protect_in_place(
    const PeerEndpoint &peer,
    const SecurePacketClass packet_class,
    const std::span<std::uint8_t> packet_storage,
    const std::size_t plaintext_bytes,
    std::size_t &protected_bytes
  ) noexcept {
    return impl_ && impl_->protect_in_place(peer, packet_class, packet_storage, plaintext_bytes, protected_bytes);
  }

  std::size_t LibsrtpServerProvider::association_count() const noexcept {
    return impl_ ? impl_->association_count() : 0;
  }

  LibsrtpProviderSnapshot LibsrtpServerProvider::snapshot() const noexcept {
    return impl_ ? impl_->snapshot() : LibsrtpProviderSnapshot {};
  }
}  // namespace lumen::lsp::runtime
