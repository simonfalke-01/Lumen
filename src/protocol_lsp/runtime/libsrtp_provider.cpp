/**
 * @file src/protocol_lsp/runtime/libsrtp_provider.cpp
 * @brief Concrete libSRTP 2.8.0 association provider for the LSP runtime.
 */

#include "libsrtp_provider.h"

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
#include <utility>
#include <vector>

namespace lumen::lsp::runtime {
  namespace {
#if LUMEN_LSP_LIBSRTP_AVAILABLE
    constexpr std::size_t maximum_protected_packet_bytes = 2'048;
    constexpr std::size_t maximum_srtp_trailer_bytes = 64;
    constexpr std::size_t srtp_master_material_size = srtp_aes_128_key_size + srtp_aead_salt_size;

    void clear_secret(const std::span<std::uint8_t> bytes) noexcept {
      volatile std::uint8_t *cursor = bytes.data();
      for (std::size_t index = 0; index < bytes.size(); ++index) {
        cursor[index] = 0;
      }
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
        ready_ = initialized && callbacks_.plaintext_packet != nullptr && callbacks_.send_datagram != nullptr &&
                 maximum_associations_ > 0 && maximum_associations_ <= 64;
        if (ready_) {
          associations_.reserve(maximum_associations_);
        }
      } catch (...) {
        ready_ = false;
      }
#else
      (void)callbacks_;
      (void)maximum_associations_;
#endif
    }

    ~Impl() {
#if LUMEN_LSP_LIBSRTP_AVAILABLE
      for (auto &association : associations_) {
        destroy(association);
      }
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
      const std::span<const std::uint8_t> datagram
    ) noexcept {
#if !LUMEN_LSP_LIBSRTP_AVAILABLE
      (void)peer;
      (void)packet_class;
      (void)datagram;
      return ProviderDatagramResult::fatal;
#else
      std::scoped_lock lock(mutex_);
      const auto index = find(peer);
      if (!ready_ || index == associations_.size() || datagram.empty() || datagram.size() > maximum_protected_packet_bytes) {
        return ProviderDatagramResult::dropped;
      }
      std::array<std::uint8_t, maximum_protected_packet_bytes> packet {};
      std::copy(datagram.begin(), datagram.end(), packet.begin());
      auto size = static_cast<int>(datagram.size());
      const auto status = packet_class == SecurePacketClass::rtcp ?
                            srtp_unprotect_rtcp(associations_[index].inbound, packet.data(), &size) :
                            srtp_unprotect(associations_[index].inbound, packet.data(), &size);
      if (status != srtp_err_status_ok || size <= 0) {
        clear_secret(packet);
        return ProviderDatagramResult::dropped;
      }
      const auto accepted = callbacks_.plaintext_packet(
        callbacks_.context,
        peer,
        packet_class,
        std::span<const std::uint8_t> {packet.data(), static_cast<std::size_t>(size)}
      );
      clear_secret(packet);
      return accepted ? ProviderDatagramResult::accepted : ProviderDatagramResult::fatal;
#endif
    }

    bool install(const PeerEndpoint &peer, const DtlsSrtpKeyMaterial &key_material) noexcept {
#if !LUMEN_LSP_LIBSRTP_AVAILABLE
      (void)peer;
      (void)key_material;
      return false;
#else
      std::scoped_lock lock(mutex_);
      if (!ready_ || !peer.valid()) {
        return false;
      }
      if (const auto existing = find(peer); existing != associations_.size()) {
        destroy(associations_[existing]);
        associations_.erase(associations_.begin() + static_cast<std::ptrdiff_t>(existing));
      }
      if (associations_.size() >= maximum_associations_) {
        return false;
      }

      Association association {.peer = peer};
      std::array<std::uint8_t, srtp_master_material_size> inbound_material {};
      std::array<std::uint8_t, srtp_master_material_size> outbound_material {};
      std::copy(key_material.client_write_key.begin(), key_material.client_write_key.end(), inbound_material.begin());
      std::copy(key_material.client_write_salt.begin(), key_material.client_write_salt.end(), inbound_material.begin() + srtp_aes_128_key_size);
      std::copy(key_material.server_write_key.begin(), key_material.server_write_key.end(), outbound_material.begin());
      std::copy(key_material.server_write_salt.begin(), key_material.server_write_salt.end(), outbound_material.begin() + srtp_aes_128_key_size);

      srtp_policy_t inbound_policy {};
      srtp_crypto_policy_set_aes_gcm_128_16_auth(&inbound_policy.rtp);
      srtp_crypto_policy_set_aes_gcm_128_16_auth(&inbound_policy.rtcp);
      inbound_policy.ssrc.type = ssrc_any_inbound;
      inbound_policy.key = inbound_material.data();
      inbound_policy.window_size = 128;
      inbound_policy.allow_repeat_tx = 0;
      inbound_policy.next = nullptr;

      srtp_policy_t outbound_policy {};
      srtp_crypto_policy_set_aes_gcm_128_16_auth(&outbound_policy.rtp);
      srtp_crypto_policy_set_aes_gcm_128_16_auth(&outbound_policy.rtcp);
      outbound_policy.ssrc.type = ssrc_any_outbound;
      outbound_policy.key = outbound_material.data();
      outbound_policy.window_size = 128;
      outbound_policy.allow_repeat_tx = 0;
      outbound_policy.next = nullptr;

      const auto inbound_status = srtp_create(&association.inbound, &inbound_policy);
      const auto outbound_status = inbound_status == srtp_err_status_ok ?
                                     srtp_create(&association.outbound, &outbound_policy) : srtp_err_status_fail;
      clear_secret(inbound_material);
      clear_secret(outbound_material);
      if (inbound_status != srtp_err_status_ok || outbound_status != srtp_err_status_ok) {
        destroy(association);
        return false;
      }
      try {
        associations_.push_back(std::move(association));
        return true;
      } catch (...) {
        destroy(association);
        return false;
      }
#endif
    }

    bool remove(const PeerEndpoint &peer) noexcept {
#if !LUMEN_LSP_LIBSRTP_AVAILABLE
      (void)peer;
      return false;
#else
      std::scoped_lock lock(mutex_);
      const auto index = find(peer);
      if (index == associations_.size()) {
        return false;
      }
      destroy(associations_[index]);
      associations_.erase(associations_.begin() + static_cast<std::ptrdiff_t>(index));
      return true;
#endif
    }

    bool protect_and_send(
      const PeerEndpoint &peer,
      const SecurePacketClass packet_class,
      const std::span<const std::uint8_t> plaintext
    ) noexcept {
#if !LUMEN_LSP_LIBSRTP_AVAILABLE
      (void)peer;
      (void)packet_class;
      (void)plaintext;
      return false;
#else
      std::scoped_lock lock(mutex_);
      const auto index = find(peer);
      if (!ready_ || index == associations_.size() || plaintext.empty() ||
          plaintext.size() > maximum_protected_packet_bytes - maximum_srtp_trailer_bytes) {
        return false;
      }
      std::array<std::uint8_t, maximum_protected_packet_bytes> packet {};
      std::copy(plaintext.begin(), plaintext.end(), packet.begin());
      auto size = static_cast<int>(plaintext.size());
      const auto status = packet_class == SecurePacketClass::rtcp ?
                            srtp_protect_rtcp(associations_[index].outbound, packet.data(), &size) :
                            srtp_protect(associations_[index].outbound, packet.data(), &size);
      const auto sent = status == srtp_err_status_ok && size > 0 && callbacks_.send_datagram(
                                                                      callbacks_.context,
                                                                      peer,
                                                                      std::span<const std::uint8_t> {packet.data(), static_cast<std::size_t>(size)}
                                                                    );
      clear_secret(packet);
      return sent;
#endif
    }

    [[nodiscard]] std::size_t association_count() const noexcept {
#if LUMEN_LSP_LIBSRTP_AVAILABLE
      std::scoped_lock lock(mutex_);
      return associations_.size();
#else
      return 0;
#endif
    }

  private:
#if LUMEN_LSP_LIBSRTP_AVAILABLE
    struct Association {
      PeerEndpoint peer;  ///< Exact five-tuple.
      srtp_t inbound {};  ///< Client-write RTP/SRTCP context.
      srtp_t outbound {};  ///< Server-write RTP/SRTCP context.
    };

    [[nodiscard]] std::size_t find(const PeerEndpoint &peer) const noexcept {
      const auto iterator = std::find_if(associations_.begin(), associations_.end(), [&peer](const Association &candidate) {
        return candidate.peer == peer;
      });
      return static_cast<std::size_t>(std::distance(associations_.begin(), iterator));
    }

    static void destroy(Association &association) noexcept {
      if (association.inbound != nullptr) {
        srtp_dealloc(association.inbound);
        association.inbound = nullptr;
      }
      if (association.outbound != nullptr) {
        srtp_dealloc(association.outbound);
        association.outbound = nullptr;
      }
    }

    std::vector<Association> associations_;  ///< Installed directional context pairs.
#endif
    LibsrtpCallbacks callbacks_;  ///< Socket and lane callbacks.
    std::size_t maximum_associations_ {};  ///< Hard association bound.
    bool ready_ {};  ///< Process initialization and callback readiness.
    mutable std::mutex mutex_;  ///< Serializes context lifetime with receive and reverse-path ACK protection.
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
    const std::span<const std::uint8_t> datagram
  ) noexcept {
    return impl_ ? impl_->receive(peer, packet_class, datagram) : ProviderDatagramResult::fatal;
  }

  bool LibsrtpServerProvider::install_association(
    const PeerEndpoint &peer,
    const DtlsSrtpKeyMaterial &key_material
  ) noexcept {
    return impl_ && impl_->install(peer, key_material);
  }

  bool LibsrtpServerProvider::remove_association(const PeerEndpoint &peer) noexcept {
    return impl_ && impl_->remove(peer);
  }

  bool LibsrtpServerProvider::protect_and_send(
    const PeerEndpoint &peer,
    const SecurePacketClass packet_class,
    const std::span<const std::uint8_t> plaintext
  ) noexcept {
    return impl_ && impl_->protect_and_send(peer, packet_class, plaintext);
  }

  std::size_t LibsrtpServerProvider::association_count() const noexcept {
    return impl_ ? impl_->association_count() : 0;
  }
}  // namespace lumen::lsp::runtime
