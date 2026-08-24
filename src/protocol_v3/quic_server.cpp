/**
 * @file src/protocol_v3/quic_server.cpp
 * @brief Production one-port MsQuic transport for Lumen protocol v3.
 */

#include "quic_server.h"

#include "../protocol_common/crypto.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <condition_variable>
#include <deque>
#include <limits>
#include <map>
#include <mutex>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <thread>
#include <utility>

#if defined(_WIN32) && defined(LUMEN_EXPERIMENTAL_MSQUIC)
  #include "../platform/windows/msquic_shim/lumen_msquic_shim.h"
#endif

namespace lumen::protocol_v3::quic_server {
  namespace cbor = lumen::protocol_common::cbor;
  namespace crypto = lumen::protocol_common::crypto;

  namespace {
    constexpr auto shutdown_protocol_violation = static_cast<std::uint64_t>(ApplicationCloseCode::malformed);
    constexpr auto shutdown_internal_error = static_cast<std::uint64_t>(ApplicationCloseCode::internal_failure);
    constexpr auto shutdown_server_stopping = static_cast<std::uint64_t>(ApplicationCloseCode::normal_shutdown);
    constexpr auto shutdown_connection_replaced = static_cast<std::uint64_t>(ApplicationCloseCode::connection_replaced);
    constexpr auto shutdown_abuse_limit = static_cast<std::uint64_t>(ApplicationCloseCode::abuse_limit);
    constexpr auto force_close_send_drain_timeout = std::chrono::milliseconds {250};
    constexpr auto congestion_sample_interval = std::chrono::milliseconds {5};
    constexpr std::size_t maximum_packet_bytes = 16U * 1024U * 1024U;
    constexpr std::array<Lane, 6> all_lanes {
      Lane::control,
      Lane::input_edge,
      Lane::audio,
      Lane::microphone,
      Lane::key_config,
      Lane::delta_video,
    };

    std::size_t lane_index(const Lane lane) noexcept {
      return static_cast<std::size_t>(lane);
    }

    bool is_latency(const Profile profile) noexcept {
      return profile == Profile::latency;
    }

    bool valid_config(const Config &config) noexcept {
      return config.udp_port != 0 && config.certificate &&
             !config.certificate->pkcs12.empty() && !config.certificate->password.empty() &&
             config.maximum_connections > 0 && config.maximum_connections <= 64 &&
             config.maximum_connections_per_source > 0 &&
             config.maximum_connections_per_source <= 8 &&
             config.maximum_connections_per_source <= config.maximum_connections &&
             config.maximum_queued_packets > 0 && config.maximum_queued_packets <= 4'096 &&
             config.maximum_queued_bytes > 0 && config.maximum_queued_bytes <= 64U * 1024U * 1024U &&
             config.maximum_in_flight_sends > 0 &&
             config.maximum_in_flight_sends <= SendSlotPool::maximum_capacity &&
             (!is_latency(config.profile) || config.maximum_in_flight_sends >= 2) &&
             config.urgent_send_reserve > 0 && config.urgent_send_reserve <= 32 &&
             config.maximum_in_flight_sends > config.urgent_send_reserve &&
             config.video_bitrate_kbps >= 1'000 && config.video_bitrate_kbps <= 500'000 &&
             config.initial_rtt_microseconds > 0 && config.initial_rtt_microseconds <= 1'000'000 &&
             config.audio_lifetime.count() > 0 && config.audio_lifetime <= std::chrono::seconds {1} &&
             config.video_lifetime.count() > 0 && config.video_lifetime <= std::chrono::seconds {1} &&
             config.quality_video_lifetime.count() > 0 &&
             config.quality_video_lifetime <= std::chrono::seconds {1} &&
             config.handshake_timeout == std::chrono::seconds {5} &&
             config.hello_timeout == std::chrono::seconds {5};
    }

    std::uint16_t read_be16(const std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
      return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) | bytes[offset + 1]);
    }

    std::uint32_t read_be32(const std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
      return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
             (static_cast<std::uint32_t>(bytes[offset + 1]) << 16U) |
             (static_cast<std::uint32_t>(bytes[offset + 2]) << 8U) |
             bytes[offset + 3];
    }

    std::uint64_t read_be64(const std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
      std::uint64_t value = 0;
      for (std::size_t index = 0; index < 8; ++index) {
        value = (value << 8U) | bytes[offset + index];
      }
      return value;
    }

    bool valid_bulk_transfer(const BulkTransfer &transfer) {
      if (!transfer.bytes || transfer.request_id == 0 || transfer.object_id == 0 ||
          transfer.bytes->size() < bulk_header_bytes ||
          transfer.bytes->size() > bulk_header_bytes + maximum_bulk_payload_bytes) {
        return false;
      }
      const auto bytes = std::span<const std::uint8_t> {*transfer.bytes};
      const auto payload_size = read_be64(bytes, 24);
      if (!std::equal(bytes.begin(), bytes.begin() + 4, std::array<std::uint8_t, 4> {'U', 'L', 'B', '3'}.begin()) ||
          bytes[4] != 3 || bytes[5] != 1 || read_be16(bytes, 6) != 0 ||
          read_be64(bytes, 8) != transfer.request_id || read_be64(bytes, 16) != transfer.object_id ||
          payload_size > maximum_bulk_payload_bytes ||
          bytes.size() != bulk_header_bytes + payload_size) {
        return false;
      }
      const auto digest = crypto::sha256(bytes.subspan(bulk_header_bytes));
      return digest && std::ranges::equal(*digest, bytes.subspan(32, 32));
    }

    std::expected<DatagramRecord, ParseError> parse_datagram_header(
      const std::span<const std::uint8_t> header,
      const std::size_t complete_size,
      const Direction direction,
      const std::span<const std::uint8_t, 16> expected_session_id,
      const std::size_t negotiated_maximum
    ) {
      if (header.size() < datagram_header_bytes || complete_size < datagram_header_bytes) {
        return std::unexpected(ParseError::truncated);
      }
      if (complete_size > std::min(negotiated_maximum, maximum_semantic_datagram_bytes)) {
        return std::unexpected(ParseError::size_limit);
      }
      if (!std::equal(header.begin(), header.begin() + 4, std::array<std::uint8_t, 4> {'U', 'L', 'M', '3'}.begin()) ||
          header[4] != 3) {
        return std::unexpected(ParseError::magic_or_version);
      }
      const auto channel = header[5];
      const auto kind = header[6];
      const auto flags = header[7];
      if ((flags & ~0x3fU) != 0) {
        return std::unexpected(ParseError::reserved_flags);
      }
      if (read_be16(header, 8) != datagram_header_bytes) {
        return std::unexpected(ParseError::header_length);
      }
      const auto payload_length = read_be16(header, 10);
      if (complete_size != datagram_header_bytes + payload_length) {
        return std::unexpected(ParseError::payload_length);
      }
      std::array<std::uint8_t, 16> session_id {};
      std::copy_n(header.begin() + 12, session_id.size(), session_id.begin());
      if (std::ranges::all_of(session_id, [](const std::uint8_t byte) {
            return byte == 0;
          })) {
        return std::unexpected(ParseError::zero_session);
      }
      if (!std::equal(session_id.begin(), session_id.end(), expected_session_id.begin())) {
        return std::unexpected(ParseError::session_mismatch);
      }
      if (direction == Direction::host_to_client && channel == 2 && kind == 2) {
        return std::unexpected(ParseError::phase_one_fec);
      }
      const bool valid_route = direction == Direction::client_to_host ?
                                 ((channel == 1 && kind == 1) ||
                                  (channel == 2 && kind == 3) ||
                                  (channel == 4 && kind == 1)) :
                                 ((channel == 1 && (kind == 2 || kind == 3)) ||
                                  (channel == 2 && kind == 1) ||
                                  (channel == 3 && kind == 1));
      if (!valid_route) {
        return std::unexpected(ParseError::reserved_route);
      }
      if (channel == 2 && kind == 1 && (flags & 0x08U) != 0) {
        return std::unexpected(ParseError::phase_one_fec);
      }
      if (channel == 2 && kind == 1 && (flags & 0x02U) != 0) {
        return std::unexpected(ParseError::flags_forbidden);
      }
      if ((channel != 2 || kind == 3) && flags != 0) {
        return std::unexpected(ParseError::flags_forbidden);
      }
      return DatagramRecord {
        .channel = channel,
        .kind = kind,
        .flags = flags,
        .session_id = session_id,
        .sequence = read_be64(header, 28),
        .object_id = read_be64(header, 36),
        .payload = {},
      };
    }
  }  // namespace

  bool AbuseTracker::observe_malformed_record(const MonotonicClock::time_point now) noexcept {
    if (malformed_size_ != 0 && malformed_records_[malformed_begin_] > now) {
      malformed_begin_ = 0;
      malformed_size_ = 0;
    }
    while (malformed_size_ != 0 &&
           malformed_records_[malformed_begin_] <= now - malformed_record_window) {
      malformed_begin_ = (malformed_begin_ + 1) % malformed_records_.size();
      --malformed_size_;
    }
    if (malformed_size_ == malformed_records_.size()) {
      return true;
    }
    const auto insertion = (malformed_begin_ + malformed_size_) % malformed_records_.size();
    malformed_records_[insertion] = now;
    ++malformed_size_;
    return malformed_size_ >= malformed_record_limit;
  }

  bool AbuseTracker::observe_invalid_datagram(const MonotonicClock::time_point now) noexcept {
    constexpr auto bucket_width = std::chrono::seconds {1};
    if (!datagram_bucket_initialized_ || now < datagram_bucket_start_) {
      datagram_bucket_start_ = now;
      datagrams_in_bucket_ = 1;
      preceding_excess_buckets_ = 0;
      datagram_bucket_initialized_ = true;
      return false;
    }

    const auto elapsed = now - datagram_bucket_start_;
    if (elapsed >= bucket_width) {
      const auto elapsed_buckets = elapsed / bucket_width;
      if (elapsed_buckets == 1 && datagrams_in_bucket_ > invalid_datagram_rate_limit) {
        preceding_excess_buckets_ = std::min(
          preceding_excess_buckets_ + 1,
          invalid_datagram_rate_seconds - 1
        );
      } else {
        preceding_excess_buckets_ = 0;
      }
      datagram_bucket_start_ += elapsed_buckets * bucket_width;
      datagrams_in_bucket_ = 0;
    }

    if (datagrams_in_bucket_ != std::numeric_limits<std::uint32_t>::max()) {
      ++datagrams_in_bucket_;
    }
    return datagrams_in_bucket_ > invalid_datagram_rate_limit &&
           preceding_excess_buckets_ >= invalid_datagram_rate_seconds - 1;
  }

  bool AbuseTracker::observe_malformed_datagram(const MonotonicClock::time_point now) noexcept {
    const auto malformed_limit = observe_malformed_record(now);
    const auto rate_limit = observe_invalid_datagram(now);
    return malformed_limit || rate_limit;
  }

  std::expected<ControlFrame, ParseError> parse_control_frame(const std::span<const std::uint8_t> bytes) {
    if (bytes.size() < control_header_bytes) {
      return std::unexpected(ParseError::truncated);
    }
    if (bytes.size() > control_header_bytes + maximum_control_payload_bytes) {
      return std::unexpected(ParseError::size_limit);
    }
    if (!std::equal(bytes.begin(), bytes.begin() + 4, std::array<std::uint8_t, 4> {'U', 'L', 'C', '3'}.begin()) ||
        bytes[4] != 3) {
      return std::unexpected(ParseError::magic_or_version);
    }
    const auto flags = bytes[5];
    if ((flags & ~0x07U) != 0 || ((flags & 0x02U) != 0 && (flags & 0x01U) == 0)) {
      return std::unexpected(ParseError::control_flags);
    }
    const auto request_id = read_be64(bytes, 8);
    if ((flags & 0x01U) != 0 && request_id == 0) {
      return std::unexpected(ParseError::control_flags);
    }
    if (read_be32(bytes, 20) != 0) {
      return std::unexpected(ParseError::reserved_flags);
    }
    const auto payload_length = read_be32(bytes, 16);
    if (payload_length > maximum_control_payload_bytes ||
        bytes.size() != control_header_bytes + payload_length) {
      return std::unexpected(ParseError::payload_length);
    }
    const auto decoded = cbor::decode(bytes.subspan(control_header_bytes));
    if (!decoded || !std::holds_alternative<cbor::Value::Map>(decoded.value->storage)) {
      return std::unexpected(ParseError::control_cbor);
    }
    return ControlFrame {
      .flags = flags,
      .message_type = read_be16(bytes, 6),
      .request_id = request_id,
      .bytes = bytes,
    };
  }

  std::expected<DatagramRecord, ParseError> parse_datagram_record(
    const std::span<const std::uint8_t> bytes,
    const Direction direction,
    const std::span<const std::uint8_t, 16> expected_session_id,
    const std::size_t negotiated_maximum
  ) {
    auto parsed = parse_datagram_header(
      bytes,
      bytes.size(),
      direction,
      expected_session_id,
      negotiated_maximum
    );
    if (!parsed) {
      return parsed;
    }
    parsed->payload = bytes.subspan(datagram_header_bytes);
    return parsed;
  }

  Delivery delivery_for(const Lane lane) noexcept {
    switch (lane) {
      case Lane::control:
      case Lane::key_config:
        return Delivery::reliable_stream;
      case Lane::input_edge:
      case Lane::audio:
      case Lane::microphone:
      case Lane::delta_video:
        return Delivery::datagram;
    }
    return Delivery::reliable_stream;
  }

  std::uint8_t latency_priority(const Lane lane) noexcept {
    switch (lane) {
      case Lane::control:
      case Lane::input_edge:
        return 0;
      case Lane::audio:
      case Lane::microphone:
        return 1;
      case Lane::key_config:
        return 2;
      case Lane::delta_video:
        return 3;
    }
    return 3;
  }

  bool accepted(const ApiStatus status) noexcept {
    return status == ApiStatus::success || status == ApiStatus::pending;
  }

  SendSlotPool::SendSlotPool(const std::size_t capacity) noexcept:
      capacity_ {std::min(capacity, maximum_capacity)} {
  }

  std::optional<SendSlotPool::Lease> SendSlotPool::acquire() noexcept {
    if (active_ >= capacity_) {
      return std::nullopt;
    }
    for (std::size_t offset = 0; offset < capacity_; ++offset) {
      const auto index = (next_ + offset) % capacity_;
      auto &slot = slots_[index];
      if (slot.occupied) {
        continue;
      }
      constexpr auto maximum_generation = std::numeric_limits<std::uint64_t>::max() >> 8U;
      slot.generation = slot.generation >= maximum_generation ? 1 : slot.generation + 1;
      slot.occupied = true;
      ++active_;
      next_ = (index + 1) % capacity_;
      return Lease {
        .index = index,
        .token = (slot.generation << 8U) | index,
      };
    }
    return std::nullopt;
  }

  std::optional<std::size_t> SendSlotPool::index(const std::uint64_t token) const noexcept {
    const auto index = static_cast<std::size_t>(token & 0xffU);
    const auto generation = token >> 8U;
    if (generation == 0 || index >= capacity_) {
      return std::nullopt;
    }
    const auto &slot = slots_[index];
    return slot.occupied && slot.generation == generation ? std::optional<std::size_t> {index} : std::nullopt;
  }

  bool SendSlotPool::release(const std::uint64_t token) noexcept {
    const auto live_index = index(token);
    if (!live_index) {
      return false;
    }
    slots_[*live_index].occupied = false;
    --active_;
    next_ = *live_index;
    return true;
  }

  void SendSlotPool::clear() noexcept {
    for (auto &slot : slots_) {
      slot.occupied = false;
    }
    active_ = 0;
    next_ = 0;
  }

  bool SendSlotPool::occupied(const std::size_t index) const noexcept {
    return index < capacity_ && slots_[index].occupied;
  }

  std::size_t SendSlotPool::capacity() const noexcept {
    return capacity_;
  }

  std::size_t SendSlotPool::active() const noexcept {
    return active_;
  }

  CertificateCredential::~CertificateCredential() {
    if (!pkcs12.empty()) {
      OPENSSL_cleanse(pkcs12.data(), pkcs12.size());
    }
    if (!password.empty()) {
      OPENSSL_cleanse(password.data(), password.size());
    }
  }

  std::shared_ptr<const CertificateCredential> make_certificate_credential_from_pem(
    const std::string_view certificate_pem,
    const std::string_view private_key_pem
  ) {
    if (certificate_pem.empty() || private_key_pem.empty() ||
        certificate_pem.size() > INT_MAX || private_key_pem.size() > INT_MAX) {
      return {};
    }
    const auto bio_deleter = [](BIO *value) { BIO_free(value); };
    const auto x509_deleter = [](X509 *value) { X509_free(value); };
    const auto key_deleter = [](EVP_PKEY *value) { EVP_PKEY_free(value); };
    const auto pkcs12_deleter = [](PKCS12 *value) { PKCS12_free(value); };
    std::unique_ptr<BIO, decltype(bio_deleter)> certificate_bio {
      BIO_new_mem_buf(certificate_pem.data(), static_cast<int>(certificate_pem.size())),
      bio_deleter,
    };
    std::unique_ptr<BIO, decltype(bio_deleter)> key_bio {
      BIO_new_mem_buf(private_key_pem.data(), static_cast<int>(private_key_pem.size())),
      bio_deleter,
    };
    if (!certificate_bio || !key_bio) {
      return {};
    }
    std::unique_ptr<X509, decltype(x509_deleter)> certificate {
      PEM_read_bio_X509(certificate_bio.get(), nullptr, nullptr, nullptr),
      x509_deleter,
    };
    std::unique_ptr<EVP_PKEY, decltype(key_deleter)> key {
      PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr),
      key_deleter,
    };
    if (!certificate || !key || X509_check_private_key(certificate.get(), key.get()) != 1) {
      return {};
    }
    std::array<std::uint8_t, 32> password_bytes {};
    if (RAND_bytes(password_bytes.data(), static_cast<int>(password_bytes.size())) != 1) {
      return {};
    }
    static constexpr char digits[] = "0123456789abcdef";
    std::string password;
    password.reserve(password_bytes.size() * 2);
    for (const auto byte : password_bytes) {
      password.push_back(digits[byte >> 4U]);
      password.push_back(digits[byte & 0x0fU]);
    }
    OPENSSL_cleanse(password_bytes.data(), password_bytes.size());
    std::unique_ptr<PKCS12, decltype(pkcs12_deleter)> pkcs12 {
      PKCS12_create(
        password.c_str(),
        "Lumen protocol v3",
        key.get(),
        certificate.get(),
        nullptr,
        0,
        0,
        0,
        0,
        0
      ),
      pkcs12_deleter,
    };
    if (!pkcs12) {
      return {};
    }
    const auto encoded_size = i2d_PKCS12(pkcs12.get(), nullptr);
    if (encoded_size <= 0 || encoded_size > 1'048'576) {
      return {};
    }
    auto credential = std::make_shared<CertificateCredential>();
    credential->pkcs12.resize(static_cast<std::size_t>(encoded_size));
    auto *destination = credential->pkcs12.data();
    if (i2d_PKCS12(pkcs12.get(), &destination) != encoded_size) {
      return {};
    }
    credential->password = std::move(password);
    return credential;
  }

  std::optional<RemoteSourcePrefix> normalize_remote_source(
    const std::uint16_t address_family,
    const std::span<const std::uint8_t> address
  ) noexcept {
    RemoteSourcePrefix source;
    if (address_family == 2 && address.size() >= 4) {
      source.family = RemoteSourcePrefix::Family::ipv4;
      std::copy_n(address.begin(), 4, source.bytes.begin());
      return source;
    }
    if (address_family != 23 || address.size() < 16) {
      return std::nullopt;
    }
    const bool mapped = std::all_of(address.begin(), address.begin() + 10, [](const auto byte) {
      return byte == 0;
    }) && address[10] == 0xff && address[11] == 0xff;
    if (mapped) {
      source.family = RemoteSourcePrefix::Family::ipv4;
      std::copy_n(address.begin() + 12, 4, source.bytes.begin());
    } else {
      source.family = RemoteSourcePrefix::Family::ipv6;
      std::copy_n(address.begin(), 8, source.bytes.begin());
    }
    return source;
  }

  std::size_t latency_video_send_budget(const LatencyVideoBudgetInput &input) noexcept {
    if (input.maximum_in_flight_sends <= input.urgent_send_reserve ||
        input.maximum_datagram_bytes == 0 || input.video_bitrate_kbps == 0 ||
        input.smoothed_rtt_microseconds == 0) {
      return 0;
    }
    const auto send_capacity = input.maximum_in_flight_sends - input.urgent_send_reserve;
    const long double bdp_bytes =
      static_cast<long double>(input.video_bitrate_kbps) *
      static_cast<long double>(input.smoothed_rtt_microseconds) / 8'000.0L;
    auto budget = static_cast<std::size_t>(
      std::max<long double>(1.0L, std::ceil(bdp_bytes / input.maximum_datagram_bytes))
    );
    budget = std::min(budget, send_capacity);
    if (input.congestion_window_bytes && input.bytes_in_flight) {
      const auto available = *input.congestion_window_bytes > *input.bytes_in_flight ?
                               *input.congestion_window_bytes - *input.bytes_in_flight :
                               0;
      budget = std::min(budget, static_cast<std::size_t>(available / input.maximum_datagram_bytes));
    }
    return budget;
  }

  struct QuicServer::Impl: public std::enable_shared_from_this<QuicServer::Impl> {
    enum class BulkSendResult {
      submitted,
      unknown_connection,
      shutting_down,
      unauthenticated,
      invalid_object,
      would_block,
      api_failure,
    };

    struct QueuedPacket {
      std::uint64_t sequence {};
      Lane lane {Lane::control};
      std::shared_ptr<const std::vector<std::uint8_t>> bytes;
      MonotonicClock::time_point deadline {};
      bool replaceable {};
      std::uint64_t object_id {};
      bool independently_decodable {};
    };

    struct VideoFrameState {
      std::uint64_t first_sequence {};
      std::shared_ptr<const LazyVideoFrame> frame;
      std::size_t next_fragment {};
      std::size_t in_flight {};
      bool canceled {};
      bool recovery_signaled {};
      bool congestion_sampled {};
    };

    struct PendingSend {
      QueuedPacket packet;
      VideoFrameState *video_frame {};
      std::array<std::uint8_t, 256> video_header {};
      std::size_t byte_count {};
    };

    struct BulkSend {
      BulkTransfer transfer;
      std::uint64_t send_token {};
      bool buffer_released {};
    };

    struct Connection {
      Connection(
        const Handle native_handle,
        const std::uint64_t process_id,
        RemoteSourcePrefix source,
        const std::size_t send_capacity
      ):
          handle {native_handle},
          id {process_id},
          remote_source {std::move(source)},
          send_slots {send_capacity} {
      }

      /** @brief Acquire one connection-owned send context. */
      PendingSend *acquire_send(std::uint64_t &token) noexcept {
        const auto lease = send_slots.acquire();
        if (!lease) {
          return nullptr;
        }
        token = lease->token;
        return &pending[lease->index];
      }

      /** @brief Resolve one live completion token to its send context. */
      PendingSend *find_send(const std::uint64_t token) noexcept {
        const auto index = send_slots.index(token);
        return index ? &pending[*index] : nullptr;
      }

      /** @brief Release one live send context and its retained storage. */
      bool release_send(const std::uint64_t token) noexcept {
        const auto index = send_slots.index(token);
        if (!index) {
          return false;
        }
        pending[*index] = {};
        return send_slots.release(token);
      }

      /** @brief Drop all send contexts after transport callbacks quiesce. */
      void clear_sends() noexcept {
        for (std::size_t index = 0; index < send_slots.capacity(); ++index) {
          if (send_slots.occupied(index)) {
            pending[index] = {};
          }
        }
        send_slots.clear();
        pending_video_fragments = 0;
        pending_video_object.reset();
        pending_video_objects_mixed = false;
      }

      Handle handle {invalid_handle};
      std::uint64_t id {};
      RemoteSourcePrefix remote_source;
      bool connected {};
      bool hello_received {};
      bool closing {};
      bool force_closing {};
      bool factory_called {};
      bool datagram_send_enabled {};
      std::uint16_t maximum_datagram_bytes {};
      Profile profile {Profile::quality};
      std::uint64_t video_bitrate_kbps {100'000};
      std::uint64_t next_packet_sequence {1};
      std::array<std::deque<QueuedPacket>, all_lanes.size()> queues;
      std::size_t queued_packets {};
      std::size_t queued_bytes {};
      std::deque<std::shared_ptr<VideoFrameState>> video_frames;
      std::size_t video_frame_bytes {};
      std::array<PendingSend, SendSlotPool::maximum_capacity> pending;
      SendSlotPool send_slots;
      std::size_t pending_video_fragments {};
      std::optional<std::uint64_t> pending_video_object;
      bool pending_video_objects_mixed {};
      std::map<std::uint64_t, BulkTransfer> pending_bulk;
      std::map<Handle, std::shared_ptr<BulkSend>> bulk_streams;
      std::size_t bulk_transfer_count {};
      std::size_t bulk_buffered_bytes {};
      Handle control_stream {invalid_handle};
      std::vector<std::uint8_t> control_receive;
      std::shared_ptr<ControlSessionV3> session;
      std::optional<std::array<std::uint8_t, 16>> active_session_id;
      std::optional<CongestionSample> congestion;
      MonotonicClock::time_point last_congestion_sample_at {};
      MonotonicClock::time_point connected_at {};
      AbuseTracker abuse;
    };

    Impl(
      MsQuicApi &api,
      Config config,
      SessionFactory &session_factory,
      Observer *observer,
      CongestionObserver *congestion_observer
    ):
        api_ {api},
        config_ {std::move(config)},
        session_factory_ {session_factory},
        observer_ {observer},
        congestion_observer_ {congestion_observer},
        teardown_thread_ {[this](const std::stop_token stop) { teardown_sessions(stop); }} {
    }

    ~Impl() {
      force_close_all();
      teardown_thread_.request_stop();
      teardown_condition_.notify_all();
      if (teardown_thread_.joinable()) {
        teardown_thread_.join();
      }
    }

    ApiStatus start() {
      std::lock_guard lock {mutex_};
      if (running_) {
        return ApiStatus::success;
      }
      if (!valid_config(config_) || !api_.is_schannel()) {
        return ApiStatus::invalid_state;
      }

      Handle registration = invalid_handle;
      auto status = api_.registration_open("Lumen protocol v3", registration);
      if (!accepted(status) || registration == invalid_handle) {
        return accepted(status) ? ApiStatus::invalid_state : status;
      }
      registration_ = registration;

      Handle configuration = invalid_handle;
      status = api_.configuration_open(
        registration_,
        required_alpn,
        1,
        0,
        static_cast<std::uint64_t>(config_.handshake_timeout.count()),
        static_cast<std::uint64_t>(config_.hello_timeout.count()),
        configuration
      );
      if (!accepted(status) || configuration == invalid_handle) {
        close_roots_locked();
        return accepted(status) ? ApiStatus::invalid_state : status;
      }
      configuration_ = configuration;

      status = api_.configuration_load_pkcs12(
        configuration_,
        config_.certificate->pkcs12,
        config_.certificate->password
      );
      if (!accepted(status)) {
        close_roots_locked();
        return status;
      }
      status = api_.configuration_leaf_spki_sha256(configuration_, leaf_spki_sha256_);
      if (!accepted(status) ||
          std::ranges::all_of(leaf_spki_sha256_, [](const std::uint8_t byte) {
            return byte == 0;
          })) {
        close_roots_locked();
        return accepted(status) ? ApiStatus::invalid_state : status;
      }

      const std::weak_ptr<Impl> weak = weak_from_this();
      Handle listener = invalid_handle;
      status = api_.listener_open(
        registration_,
        [weak](const ListenerEvent &event) {
          if (const auto self = weak.lock()) {
            return self->on_listener_event(event);
          }
          return ApiStatus::aborted;
        },
        listener
      );
      if (!accepted(status) || listener == invalid_handle) {
        close_roots_locked();
        return accepted(status) ? ApiStatus::invalid_state : status;
      }
      listener_ = listener;
      running_ = true;
      stopping_ = false;

      status = api_.listener_start(listener_, required_alpn, config_.udp_port);
      if (!accepted(status)) {
        running_ = false;
        stopping_ = true;
        api_.listener_close(listener_);
        listener_ = invalid_handle;
        close_roots_locked();
        stopping_ = false;
        return status;
      }
      emit_locked(Event::Kind::listener_started, nullptr, 0, Lane::control, 0);
      return status;
    }

    void stop() noexcept {
      std::lock_guard lock {mutex_};
      if (!running_ && !stopping_) {
        return;
      }
      running_ = false;
      stopping_ = true;
      if (listener_ != invalid_handle) {
        api_.listener_stop(listener_);
      }
      for (auto &[id, connection] : connections_) {
        static_cast<void>(id);
        begin_shutdown_locked(*connection, shutdown_server_stopping);
      }
      if (listener_ == invalid_handle && connections_.empty()) {
        close_roots_locked();
        stopping_ = false;
      }
    }

    EnqueueResult enqueue(const std::uint64_t connection_id, Packet packet) {
      std::unique_lock lock {mutex_};
      const auto found = connections_.find(connection_id);
      if (found == connections_.end()) {
        return EnqueueResult::unknown_connection;
      }
      const auto connection_owner = found->second;
      auto &connection = *connection_owner;
      if (stopping_ || connection.closing || !connection.connected) {
        return EnqueueResult::shutting_down;
      }
      if (!packet.bytes || packet.bytes->empty() || packet.bytes->size() > maximum_packet_bytes) {
        return EnqueueResult::invalid_packet;
      }
      std::uint64_t object_id = 0;
      bool independently_decodable = false;
      if (delivery_for(packet.lane) == Delivery::datagram) {
        if (!connection.datagram_send_enabled || connection.maximum_datagram_bytes == 0) {
          return EnqueueResult::datagram_not_negotiated;
        }
        if (packet.bytes->size() > connection.maximum_datagram_bytes) {
          return EnqueueResult::datagram_too_large;
        }
        const auto active = connection.active_session_id;
        const auto parsed = active ? parse_datagram_record(
                                       *packet.bytes,
                                       Direction::host_to_client,
                                       std::span<const std::uint8_t, 16> {*active},
                                       connection.maximum_datagram_bytes
                                     ) :
                                     std::expected<DatagramRecord, ParseError> {
                                       std::unexpected(ParseError::session_mismatch)
                                     };
        if (!parsed) {
          return EnqueueResult::invalid_packet;
        }
        const bool lane_matches =
          (packet.lane == Lane::input_edge && parsed->channel == 1) ||
          (packet.lane == Lane::delta_video && parsed->channel == 2) ||
          (packet.lane == Lane::audio && parsed->channel == 3);
        if (!lane_matches) {
          return EnqueueResult::invalid_packet;
        }
        object_id = parsed->object_id;
        independently_decodable = parsed->channel == 2 && (parsed->flags & 0x01U) != 0;
      } else if (!parse_control_frame(*packet.bytes)) {
        return EnqueueResult::invalid_packet;
      }

      const auto now = MonotonicClock::now();
      if (packet.deadline == MonotonicClock::time_point {}) {
        if (packet.lane == Lane::audio || packet.lane == Lane::microphone) {
          packet.deadline = now + config_.audio_lifetime;
        } else if (packet.lane == Lane::delta_video) {
          packet.deadline = now + (is_latency(connection.profile) ?
                                     config_.video_lifetime :
                                     config_.quality_video_lifetime);
        }
      }
      if (packet.deadline != MonotonicClock::time_point {} && packet.deadline <= now) {
        return EnqueueResult::would_block;
      }

      drop_expired_locked(connection, now);
      auto &lane_queue = connection.queues[lane_index(packet.lane)];
      if (is_latency(connection.profile) && (packet.replaceable || independently_decodable)) {
        for (auto it = lane_queue.begin(); it != lane_queue.end();) {
          const bool same_replaceable_lane =
            it->lane == packet.lane && (it->replaceable || independently_decodable);
          const bool replace_video_object =
            packet.lane != Lane::delta_video ||
            (it->object_id != object_id &&
             (independently_decodable || !it->independently_decodable));
          if (same_replaceable_lane && replace_video_object) {
            const auto removed = *it;
            connection.queued_bytes -= removed.bytes->size();
            --connection.queued_packets;
            it = lane_queue.erase(it);
            emit_locked(
              Event::Kind::packet_superseded,
              &connection,
              removed.sequence,
              removed.lane,
              removed.bytes->size()
            );
          } else {
            ++it;
          }
        }
      }

      const auto would_overflow = [&]() {
        return connection.queued_packets >= config_.maximum_queued_packets ||
               packet.bytes->size() > config_.maximum_queued_bytes -
                                        std::min(
                                          connection.queued_bytes + connection.video_frame_bytes,
                                          config_.maximum_queued_bytes
                                        );
      };
      while (would_overflow() && is_latency(connection.profile)) {
        std::deque<QueuedPacket> *candidate_queue = nullptr;
        std::deque<QueuedPacket>::iterator candidate;
        std::uint8_t candidate_priority = 0;
        for (const auto candidate_lane : all_lanes) {
          auto &queue = connection.queues[lane_index(candidate_lane)];
          const auto found = std::find_if(queue.begin(), queue.end(), [](const QueuedPacket &queued) {
            return queued.replaceable;
          });
          if (found != queue.end() && latency_priority(found->lane) > candidate_priority) {
            candidate_queue = &queue;
            candidate = found;
            candidate_priority = latency_priority(found->lane);
          }
        }
        if (candidate_queue == nullptr || candidate_priority <= latency_priority(packet.lane)) {
          break;
        }
        const auto removed = *candidate;
        connection.queued_bytes -= removed.bytes->size();
        --connection.queued_packets;
        candidate_queue->erase(candidate);
        emit_locked(
          Event::Kind::packet_backpressured,
          &connection,
          removed.sequence,
          removed.lane,
          removed.bytes->size()
        );
      }
      if (would_overflow()) {
        emit_locked(Event::Kind::packet_backpressured, &connection, 0, packet.lane, packet.bytes->size());
        return EnqueueResult::would_block;
      }

      QueuedPacket queued {
        .sequence = connection.next_packet_sequence++,
        .lane = packet.lane,
        .bytes = std::move(packet.bytes),
        .deadline = packet.deadline,
        .replaceable = packet.replaceable,
        .object_id = object_id,
        .independently_decodable = independently_decodable,
      };
      connection.queued_bytes += queued.bytes->size();
      const auto sequence = queued.sequence;
      const auto bytes = queued.bytes->size();
      const auto lane = queued.lane;
      lane_queue.push_back(std::move(queued));
      ++connection.queued_packets;
      emit_locked(Event::Kind::packet_queued, &connection, sequence, lane, bytes);
      drain_locked(connection_owner, lock);
      return EnqueueResult::queued;
    }

    EnqueueResult enqueue_video_frame(
      const std::uint64_t connection_id,
      std::shared_ptr<const LazyVideoFrame> frame
    ) {
      if (!frame || frame->object_id() == 0 || frame->fragment_count() == 0 ||
          frame->fragment_count() > std::numeric_limits<std::uint16_t>::max() ||
          frame->retained_bytes() == 0 || frame->retained_bytes() > config_.maximum_queued_bytes ||
          frame->maximum_datagram_bytes() < datagram_header_bytes ||
          frame->maximum_datagram_bytes() > maximum_semantic_datagram_bytes) {
        return EnqueueResult::invalid_packet;
      }
      std::unique_lock lock {mutex_};
      const auto found = connections_.find(connection_id);
      if (found == connections_.end()) {
        return EnqueueResult::unknown_connection;
      }
      const auto connection_owner = found->second;
      auto &connection = *connection_owner;
      if (stopping_ || connection.closing || !connection.connected) {
        return EnqueueResult::shutting_down;
      }
      if (!connection.datagram_send_enabled || connection.maximum_datagram_bytes == 0) {
        return EnqueueResult::datagram_not_negotiated;
      }
      if (frame->maximum_datagram_bytes() > connection.maximum_datagram_bytes) {
        return EnqueueResult::datagram_too_large;
      }
      const auto now = MonotonicClock::now();
      if (frame->deadline() == MonotonicClock::time_point {} || frame->deadline() <= now) {
        return EnqueueResult::would_block;
      }
      const auto active = connection.active_session_id;
      if (!active) {
        return EnqueueResult::invalid_packet;
      }
      std::array<std::uint8_t, 256> sample_header {};
      VideoFragmentView sample;
      if (!frame->materialize(0, sample_header, sample) || sample.header_size < datagram_header_bytes ||
          sample.header_size > sample_header.size() || !sample.payload || sample.payload_size == 0 ||
          sample.header_size + sample.payload_size > connection.maximum_datagram_bytes) {
        return EnqueueResult::invalid_packet;
      }
      const auto parsed = parse_datagram_header(
        std::span<const std::uint8_t> {sample_header}.first(sample.header_size),
        sample.header_size + sample.payload_size,
        Direction::host_to_client,
        std::span<const std::uint8_t, 16> {*active},
        connection.maximum_datagram_bytes
      );
      if (!parsed || parsed->channel != 2 || parsed->kind != 1 ||
          parsed->object_id != frame->object_id() ||
          ((parsed->flags & 0x01U) != 0) != frame->independently_decodable()) {
        return EnqueueResult::invalid_packet;
      }

      drop_expired_locked(connection, now);
      const auto object_capacity = is_latency(connection.profile) ? 1U : 2U;
      if (connection.video_frames.size() >= object_capacity &&
          is_latency(connection.profile) && frame->independently_decodable()) {
        const auto candidate = std::find_if(
          connection.video_frames.begin(),
          connection.video_frames.end(),
          [](const auto &state) { return state->in_flight == 0; }
        );
        if (candidate != connection.video_frames.end()) {
          const auto removed = *candidate;
          connection.video_frame_bytes -= removed->frame->retained_bytes();
          connection.video_frames.erase(candidate);
          emit_locked(
            Event::Kind::packet_superseded,
            &connection,
            removed->first_sequence,
            Lane::delta_video,
            removed->frame->retained_bytes()
          );
        }
      }
      if (connection.video_frames.size() >= object_capacity ||
          frame->retained_bytes() > config_.maximum_queued_bytes -
                                      std::min(
                                        connection.queued_bytes + connection.video_frame_bytes,
                                        config_.maximum_queued_bytes
                                      ) ||
          connection.next_packet_sequence >
            std::numeric_limits<std::uint64_t>::max() - frame->fragment_count()) {
        emit_locked(
          Event::Kind::packet_backpressured,
          &connection,
          0,
          Lane::delta_video,
          frame->retained_bytes()
        );
        return EnqueueResult::would_block;
      }
      auto state = std::make_shared<VideoFrameState>();
      state->first_sequence = connection.next_packet_sequence;
      connection.next_packet_sequence += frame->fragment_count();
      state->frame = std::move(frame);
      connection.video_frame_bytes += state->frame->retained_bytes();
      const auto sequence = state->first_sequence;
      const auto bytes = state->frame->retained_bytes();
      connection.video_frames.push_back(std::move(state));
      emit_locked(Event::Kind::packet_queued, &connection, sequence, Lane::delta_video, bytes);
      drain_locked(connection_owner, lock);
      return EnqueueResult::queued;
    }

    BulkSendResult send_bulk(
      const std::uint64_t connection_id,
      BulkTransfer transfer,
      const bool reserved = false
    ) {
      if (!valid_bulk_transfer(transfer)) {
        return BulkSendResult::invalid_object;
      }
      const auto payload_bytes = transfer.bytes->size() - bulk_header_bytes;
      Handle connection_handle = invalid_handle;
      auto stream_slot = std::make_shared<Handle>(invalid_handle);
      auto send = std::make_shared<BulkSend>();
      send->transfer = std::move(transfer);
      {
        std::lock_guard lock {mutex_};
        const auto found = connections_.find(connection_id);
        if (found == connections_.end()) {
          return BulkSendResult::unknown_connection;
        }
        auto &connection = *found->second;
        if (stopping_ || connection.closing || !connection.connected) {
          if (reserved && connection.bulk_transfer_count != 0) {
            --connection.bulk_transfer_count;
            connection.bulk_buffered_bytes -= std::min(connection.bulk_buffered_bytes, payload_bytes);
          }
          return BulkSendResult::shutting_down;
        }
        if (!connection.session || !connection.session->authenticated()) {
          if (reserved && connection.bulk_transfer_count != 0) {
            --connection.bulk_transfer_count;
            connection.bulk_buffered_bytes -= std::min(connection.bulk_buffered_bytes, payload_bytes);
          }
          return BulkSendResult::unauthenticated;
        }
        if (!reserved) {
          if (connection.bulk_transfer_count >= maximum_bulk_streams ||
              payload_bytes > maximum_bulk_buffered_bytes -
                                std::min(connection.bulk_buffered_bytes, maximum_bulk_buffered_bytes)) {
            return BulkSendResult::would_block;
          }
          ++connection.bulk_transfer_count;
          connection.bulk_buffered_bytes += payload_bytes;
        }
        connection_handle = connection.handle;
        send->send_token = next_send_token_++;
      }

      const std::weak_ptr<Impl> weak = weak_from_this();
      Handle stream = invalid_handle;
      const auto opened = api_.stream_open_unidirectional(
        connection_handle,
        [weak, connection_id, stream_slot](const StreamEvent &event) {
          if (const auto self = weak.lock(); self && *stream_slot != invalid_handle) {
            return self->on_bulk_stream_event(connection_id, *stream_slot, event);
          }
          return ApiStatus::aborted;
        },
        stream
      );
      if (!accepted(opened) || stream == invalid_handle) {
        std::lock_guard lock {mutex_};
        if (const auto found = connections_.find(connection_id); found != connections_.end()) {
          auto &connection = *found->second;
          if (connection.bulk_transfer_count != 0) {
            --connection.bulk_transfer_count;
          }
          connection.bulk_buffered_bytes -= std::min(connection.bulk_buffered_bytes, payload_bytes);
        }
        return BulkSendResult::api_failure;
      }
      *stream_slot = stream;
      {
        std::lock_guard lock {mutex_};
        const auto found = connections_.find(connection_id);
        if (found == connections_.end() || found->second->closing) {
          if (found != connections_.end()) {
            auto &connection = *found->second;
            if (connection.bulk_transfer_count != 0) {
              --connection.bulk_transfer_count;
            }
            connection.bulk_buffered_bytes -= std::min(connection.bulk_buffered_bytes, payload_bytes);
          }
          api_.stream_close(stream);
          return BulkSendResult::shutting_down;
        }
        found->second->bulk_streams.emplace(stream, send);
      }

      const auto priority = api_.stream_set_priority(stream, 16);
      const auto started = accepted(priority) ? api_.stream_start(stream) : priority;
      const std::array<Buffer, 1> buffers {{
        {send->transfer.bytes->data(), send->transfer.bytes->size()},
      }};
      const auto submitted = accepted(started) ?
                               api_.stream_send(stream, buffers, send->send_token, false, true) :
                               started;
      if (!accepted(submitted)) {
        bool active = false;
        {
          std::lock_guard lock {mutex_};
          const auto found = connections_.find(connection_id);
          active = found != connections_.end() && found->second->bulk_streams.contains(stream);
        }
        if (active) {
          api_.stream_shutdown(stream, shutdown_internal_error);
        }
        return BulkSendResult::api_failure;
      }
      return BulkSendResult::submitted;
    }

    bool set_connection_policy(
      const std::uint64_t connection_id,
      const Profile profile,
      const std::uint64_t video_bitrate_kbps
    ) noexcept {
      std::lock_guard lock {mutex_};
      const auto found = connections_.find(connection_id);
      if (found == connections_.end() || found->second->closing ||
          video_bitrate_kbps < 1'000 || video_bitrate_kbps > 500'000) {
        return false;
      }
      found->second->profile = profile;
      found->second->video_bitrate_kbps = video_bitrate_kbps;
      return true;
    }

    std::size_t active_connections() const noexcept {
      std::lock_guard lock {mutex_};
      return connections_.size();
    }

    bool revoke_connection(const std::uint64_t connection_id) noexcept {
      std::lock_guard lock {mutex_};
      const auto found = connections_.find(connection_id);
      if (found == connections_.end() || found->second->closing) {
        return false;
      }
      begin_shutdown_locked(*found->second, shutdown_connection_replaced);
      return true;
    }

    std::size_t queued_packets() const noexcept {
      std::lock_guard lock {mutex_};
      std::size_t total = 0;
      for (const auto &[id, connection] : connections_) {
        static_cast<void>(id);
        total += connection->queued_packets + connection->video_frames.size();
      }
      return total;
    }

    bool running() const noexcept {
      std::lock_guard lock {mutex_};
      return running_;
    }

    std::optional<std::array<std::uint8_t, 32>> leaf_spki_sha256() const noexcept {
      std::lock_guard lock {mutex_};
      return running_ ? std::optional {leaf_spki_sha256_} : std::nullopt;
    }

    ApiStatus on_listener_event(const ListenerEvent &event) {
      std::lock_guard lock {mutex_};
      if (event.kind == ListenerEvent::Kind::stop_complete) {
        if (listener_ != invalid_handle) {
          api_.listener_close(listener_);
          listener_ = invalid_handle;
        }
        emit_locked(Event::Kind::listener_stopped, nullptr, 0, Lane::control, 0);
        if (connections_.empty()) {
          close_roots_locked();
          stopping_ = false;
        }
        return ApiStatus::success;
      }

      if (!running_ || stopping_ || event.connection == invalid_handle || !event.remote_source ||
          connections_.size() >= config_.maximum_connections) {
        return ApiStatus::aborted;
      }

      const auto source_count = connections_per_source_.find(*event.remote_source);
      if (source_count != connections_per_source_.end() &&
          source_count->second >= config_.maximum_connections_per_source) {
        return ApiStatus::aborted;
      }

      const auto id = next_connection_id_++;
      auto connection = std::make_shared<Connection>(
        event.connection,
        id,
        *event.remote_source,
        config_.maximum_in_flight_sends
      );
      const std::weak_ptr<Impl> weak = weak_from_this();
      const auto callback_status = api_.connection_set_callback(
        event.connection,
        [weak, id](const ConnectionEvent &connection_event) {
          if (const auto self = weak.lock()) {
            return self->on_connection_event(id, connection_event);
          }
          return ApiStatus::aborted;
        }
      );
      if (!accepted(callback_status)) {
        return callback_status;
      }
      connections_.emplace(id, connection);
      connection_ids_.emplace(event.connection, id);
      ++connections_per_source_[connection->remote_source];
      const auto configured = api_.connection_set_configuration(event.connection, configuration_);
      if (!accepted(configured)) {
        erase_connection_locked(id, true);
        // Ownership was accepted when the callback was installed. Closing and
        // returning success avoids MsQuic's NEW_CONNECTION double-free path.
        return ApiStatus::success;
      }
      emit_locked(Event::Kind::connection_accepted, connection.get(), 0, Lane::control, 0);
      return ApiStatus::success;
    }

    ApiStatus on_connection_event(const std::uint64_t id, const ConnectionEvent &event) {
      std::unique_lock lock {mutex_};
      const auto found = connections_.find(id);
      if (found == connections_.end()) {
        return ApiStatus::aborted;
      }
      const auto connection_owner = found->second;
      auto &connection = *connection_owner;

      switch (event.kind) {
        case ConnectionEvent::Kind::connected:
          if (event.resumed || event.early_data_accepted || connection.connected) {
            begin_shutdown_locked(connection, shutdown_protocol_violation);
            return ApiStatus::aborted;
          }
          if (!accepted(api_.connection_set_idle_timeout(
                connection.handle,
                static_cast<std::uint64_t>(config_.hello_timeout.count())
              ))) {
            begin_shutdown_locked(connection, shutdown_internal_error);
            return ApiStatus::aborted;
          }
          connection.connected = true;
          connection.connected_at = MonotonicClock::now();
          emit_locked(Event::Kind::connection_connected, &connection, 0, Lane::control, 0);
          drain_locked(connection_owner, lock);
          return ApiStatus::success;

        case ConnectionEvent::Kind::datagram_state_changed: {
          connection.datagram_send_enabled =
            event.datagram_send_enabled && event.maximum_datagram_bytes >= datagram_header_bytes;
          connection.maximum_datagram_bytes = connection.datagram_send_enabled ?
                                                static_cast<std::uint16_t>(std::min<std::size_t>(
                                                  event.maximum_datagram_bytes,
                                                  maximum_semantic_datagram_bytes
                                                )) :
                                                0;
          for (const auto lane : {Lane::input_edge, Lane::audio, Lane::microphone, Lane::delta_video}) {
            auto &queue = connection.queues[lane_index(lane)];
            for (auto it = queue.begin(); it != queue.end();) {
              if (connection.maximum_datagram_bytes == 0 ||
                  it->bytes->size() > connection.maximum_datagram_bytes) {
                const auto removed = *it;
                connection.queued_bytes -= removed.bytes->size();
                --connection.queued_packets;
                it = queue.erase(it);
                emit_locked(
                  Event::Kind::packet_backpressured,
                  &connection,
                  removed.sequence,
                  removed.lane,
                  removed.bytes->size()
                );
              } else {
                ++it;
              }
            }
          }
          const auto video_frames = connection.video_frames;
          for (const auto &state : video_frames) {
            if (!state->canceled &&
                (connection.maximum_datagram_bytes == 0 ||
                 state->frame->maximum_datagram_bytes() > connection.maximum_datagram_bytes)) {
              emit_locked(
                Event::Kind::packet_backpressured,
                &connection,
                state->first_sequence,
                Lane::delta_video,
                state->frame->retained_bytes()
              );
              cancel_video_frame_locked(connection, state.get(), true);
            }
          }
          if (const auto session = connection.session) {
            try {
              const auto maximum = connection.maximum_datagram_bytes;
              lock.unlock();
              session->datagram_maximum_changed(maximum);
              lock.lock();
              if (!connections_.contains(id) || connection.closing) {
                return ApiStatus::aborted;
              }
            } catch (...) {
              if (!lock.owns_lock()) {
                lock.lock();
              }
              begin_shutdown_locked(connection, shutdown_internal_error);
              return ApiStatus::aborted;
            }
          }
          emit_locked(
            Event::Kind::datagram_negotiated,
            &connection,
            0,
            Lane::delta_video,
            connection.maximum_datagram_bytes
          );
          drain_locked(connection_owner, lock);
          return ApiStatus::success;
        }

        case ConnectionEvent::Kind::datagram_send_complete:
        case ConnectionEvent::Kind::stream_send_complete:
          complete_send_locked(connection, event.send_token, event.canceled);
          if (!connection.closing) {
            drain_locked(connection_owner, lock);
          }
          return ApiStatus::success;

        case ConnectionEvent::Kind::datagram_received:
          {
            const auto session = connection.session;
            const auto active = connection.active_session_id;
            if (!session || !session->authenticated() || !active) {
              emit_locked(
                Event::Kind::parser_drop,
                &connection,
                0,
                Lane::input_edge,
                event.received_bytes.size(),
                ParseError::session_mismatch,
                ApiStatus::success
              );
              begin_shutdown_locked(connection, shutdown_protocol_violation);
              return ApiStatus::aborted;
            }
            const auto parsed = parse_datagram_record(
              event.received_bytes,
              Direction::client_to_host,
              std::span<const std::uint8_t, 16> {*active},
              maximum_semantic_datagram_bytes
            );
            if (parsed) {
              try {
                lock.unlock();
                session->datagram(*parsed);
                lock.lock();
                if (!connections_.contains(id) || connection.closing) {
                  return ApiStatus::aborted;
                }
              } catch (const std::runtime_error &) {
                if (!lock.owns_lock()) {
                  lock.lock();
                }
                if (!connections_.contains(id) || connection.closing) {
                  return ApiStatus::aborted;
                }
                emit_locked(
                  Event::Kind::parser_drop,
                  &connection,
                  0,
                  Lane::input_edge,
                  event.received_bytes.size(),
                  ParseError::none,
                  ApiStatus::success
                );
                if (connection.abuse.observe_malformed_datagram(MonotonicClock::now())) {
                  begin_shutdown_locked(connection, shutdown_abuse_limit);
                  return ApiStatus::aborted;
                }
              } catch (...) {
                if (!lock.owns_lock()) {
                  lock.lock();
                }
                emit_locked(
                  Event::Kind::session_failure,
                  &connection,
                  0,
                  Lane::input_edge,
                  event.received_bytes.size(),
                  ParseError::none,
                  ApiStatus::transport_error
                );
                begin_shutdown_locked(connection, shutdown_internal_error);
                return ApiStatus::aborted;
              }
            } else {
              emit_locked(
                Event::Kind::parser_drop,
                &connection,
                0,
                Lane::input_edge,
                event.received_bytes.size(),
                parsed.error(),
                ApiStatus::success
              );
              if (connection.abuse.observe_malformed_datagram(MonotonicClock::now())) {
                begin_shutdown_locked(connection, shutdown_abuse_limit);
                return ApiStatus::aborted;
              }
            }
            return ApiStatus::success;
          }

        case ConnectionEvent::Kind::peer_stream_started:
          if (event.stream == invalid_handle || event.stream_id != 0 || event.peer_stream_unidirectional ||
              connection.control_stream != invalid_handle) {
            if (event.stream != invalid_handle) {
              const std::weak_ptr<Impl> weak = weak_from_this();
              static_cast<void>(api_.stream_set_callback(
                event.stream,
                [weak, id, stream = event.stream](const StreamEvent &stream_event) {
                  if (const auto self = weak.lock()) {
                    return self->on_stream_event(id, stream, false, stream_event);
                  }
                  return ApiStatus::aborted;
                }
              ));
              api_.stream_shutdown(event.stream, shutdown_protocol_violation);
            }
            if (!connection.session || !connection.session->authenticated() ||
                !connection.active_session_id) {
              begin_shutdown_locked(connection, shutdown_protocol_violation);
            } else if (connection.abuse.observe_malformed_record(MonotonicClock::now())) {
              begin_shutdown_locked(connection, shutdown_abuse_limit);
            }
            return ApiStatus::aborted;
          }
          connection.control_stream = event.stream;
          {
            const std::weak_ptr<Impl> weak = weak_from_this();
            const auto callback = api_.stream_set_callback(
              event.stream,
              [weak, id, stream = event.stream](const StreamEvent &stream_event) {
                if (const auto self = weak.lock()) {
                  return self->on_stream_event(id, stream, true, stream_event);
                }
                return ApiStatus::aborted;
              }
            );
            if (!accepted(callback)) {
              begin_shutdown_locked(connection, shutdown_internal_error);
              return callback;
            }
          }
          static_cast<void>(api_.stream_set_priority(event.stream, 0));
          drain_locked(connection_owner, lock);
          return ApiStatus::success;

        case ConnectionEvent::Kind::shutdown_by_transport:
        case ConnectionEvent::Kind::shutdown_by_peer:
          connection.closing = true;
          for (auto &queue : connection.queues) {
            queue.clear();
          }
          cancel_all_video_frames_locked(connection);
          connection.queued_packets = 0;
          connection.queued_bytes = 0;
          if (connection.session) {
            defer_disconnect_locked(connection);
          }
          return ApiStatus::success;

        case ConnectionEvent::Kind::shutdown_complete:
          if (connection.force_closing) {
            send_drain_condition_.notify_all();
            return ApiStatus::success;
          }
          erase_connection_locked(id, true);
          return ApiStatus::success;
      }
      return ApiStatus::transport_error;
    }

    ApiStatus on_bulk_stream_event(
      const std::uint64_t id,
      const Handle stream,
      const StreamEvent &event
    ) {
      std::unique_lock lock {mutex_};
      const auto found = connections_.find(id);
      if (found == connections_.end()) {
        return ApiStatus::aborted;
      }
      auto &connection = *found->second;
      const auto bulk = connection.bulk_streams.find(stream);
      if (bulk == connection.bulk_streams.end()) {
        return ApiStatus::aborted;
      }
      const auto send = bulk->second;
      const auto release_buffer = [&] {
        if (!send->buffer_released) {
          const auto payload = send->transfer.bytes ? send->transfer.bytes->size() - bulk_header_bytes : 0;
          connection.bulk_buffered_bytes -= std::min(connection.bulk_buffered_bytes, payload);
          send->transfer.bytes.reset();
          send->buffer_released = true;
          send_drain_condition_.notify_all();
        }
      };
      switch (event.kind) {
        case StreamEvent::Kind::start_complete:
          if (event.canceled) {
            api_.stream_shutdown(stream, shutdown_internal_error);
          }
          return ApiStatus::success;
        case StreamEvent::Kind::send_complete:
          if (event.send_token != send->send_token || event.canceled) {
            api_.stream_shutdown(stream, shutdown_internal_error);
            return ApiStatus::aborted;
          }
          release_buffer();
          return ApiStatus::success;
        case StreamEvent::Kind::writable:
        case StreamEvent::Kind::send_shutdown_complete:
          return ApiStatus::success;
        case StreamEvent::Kind::receive:
        case StreamEvent::Kind::peer_send_shutdown:
        case StreamEvent::Kind::peer_send_aborted:
        case StreamEvent::Kind::peer_receive_aborted:
          api_.stream_shutdown(stream, shutdown_protocol_violation);
          return ApiStatus::aborted;
        case StreamEvent::Kind::shutdown_complete:
          release_buffer();
          if (connection.bulk_transfer_count != 0) {
            --connection.bulk_transfer_count;
          }
          connection.bulk_streams.erase(bulk);
          send_drain_condition_.notify_all();
          if (connection.force_closing) {
            return ApiStatus::success;
          }
          lock.unlock();
          api_.stream_close(stream);
          return ApiStatus::success;
      }
      return ApiStatus::transport_error;
    }

    ApiStatus on_stream_event(
      const std::uint64_t id,
      const Handle stream,
      const bool is_control,
      const StreamEvent &event
    ) {
      std::unique_lock lock {mutex_};
      const auto found = connections_.find(id);
      if (found == connections_.end()) {
        return ApiStatus::aborted;
      }
      const auto connection_owner = found->second;
      auto &connection = *connection_owner;
      switch (event.kind) {
        case StreamEvent::Kind::receive:
          {
            if (!is_control || stream != connection.control_stream) {
              api_.stream_shutdown(stream, shutdown_protocol_violation);
              if (!connection.session || !connection.session->authenticated() ||
                  !connection.active_session_id) {
                begin_shutdown_locked(connection, shutdown_protocol_violation);
              } else if (connection.abuse.observe_malformed_record(MonotonicClock::now())) {
                begin_shutdown_locked(connection, shutdown_abuse_limit);
              }
              return ApiStatus::aborted;
            }
            std::size_t received = 0;
            for (const auto &buffer : event.buffers) {
              if (buffer.size > control_header_bytes + maximum_control_payload_bytes -
                                  std::min(connection.control_receive.size(), control_header_bytes + maximum_control_payload_bytes)) {
                begin_shutdown_locked(connection, shutdown_protocol_violation);
                return ApiStatus::aborted;
              }
              connection.control_receive.insert(
                connection.control_receive.end(),
                buffer.data,
                buffer.data + buffer.size
              );
              received += buffer.size;
            }
            if (received != event.total_buffer_bytes) {
              begin_shutdown_locked(connection, shutdown_protocol_violation);
              return ApiStatus::aborted;
            }
            while (connection.control_receive.size() >= control_header_bytes) {
              const auto view = std::span<const std::uint8_t> {connection.control_receive};
              if (!std::equal(
                    view.begin(),
                    view.begin() + 4,
                    std::array<std::uint8_t, 4> {'U', 'L', 'C', '3'}.begin()
                  ) ||
                  view[4] != 3) {
                begin_shutdown_locked(connection, shutdown_protocol_violation);
                return ApiStatus::aborted;
              }
              const auto payload = read_be32(view, 16);
              if (payload > maximum_control_payload_bytes) {
                begin_shutdown_locked(connection, shutdown_protocol_violation);
                return ApiStatus::aborted;
              }
              const auto frame_size = control_header_bytes + static_cast<std::size_t>(payload);
              if (connection.control_receive.size() < frame_size) {
                break;
              }
              const auto parsed = parse_control_frame(view.first(frame_size));
              if (!parsed) {
                emit_locked(
                  Event::Kind::parser_drop,
                  &connection,
                  0,
                  Lane::control,
                  frame_size,
                  parsed ? ParseError::none : parsed.error(),
                  ApiStatus::success
                );
                if (!connection.session || !connection.session->authenticated()) {
                  begin_shutdown_locked(connection, shutdown_protocol_violation);
                  return ApiStatus::aborted;
                }
                connection.control_receive.erase(
                  connection.control_receive.begin(),
                  connection.control_receive.begin() + static_cast<std::ptrdiff_t>(frame_size)
                );
                if (connection.abuse.observe_malformed_record(MonotonicClock::now())) {
                  begin_shutdown_locked(connection, shutdown_abuse_limit);
                  return ApiStatus::aborted;
                }
                continue;
              }
              if (!connection.hello_received) {
                if (MonotonicClock::now() - connection.connected_at >= config_.hello_timeout ||
                    parsed->message_type != 0x0001 || parsed->flags != 0 ||
                    parsed->request_id == 0 || parsed->request_id % 2 == 0) {
                  begin_shutdown_locked(connection, shutdown_protocol_violation);
                  return ApiStatus::aborted;
                }
                connection.hello_received = true;
                connection.factory_called = true;
                try {
                  connection.profile = config_.profile;
                  connection.video_bitrate_kbps = config_.video_bitrate_kbps;
                  const ConnectionContext context {
                    .connection_id = connection.id,
                    .remote_source = connection.remote_source,
                    .local_udp_port = config_.udp_port,
                    .maximum_datagram_bytes = connection.maximum_datagram_bytes,
                    .profile = config_.profile,
                    .leaf_spki_sha256 = leaf_spki_sha256_,
                    .connected_at = connection.connected_at,
                  };
                  const auto maximum = connection.maximum_datagram_bytes;
                  lock.unlock();
                  std::shared_ptr<ControlSessionV3> created = session_factory_.create(context);
                  if (created && maximum != 0) {
                    created->datagram_maximum_changed(maximum);
                  }
                  lock.lock();
                  if (!connections_.contains(id) || connection.closing) {
                    lock.unlock();
                    if (created) {
                      created->disconnect();
                    }
                    return ApiStatus::aborted;
                  }
                  connection.session = std::move(created);
                } catch (...) {
                  if (!lock.owns_lock()) {
                    lock.lock();
                  }
                  defer_disconnect_locked(connection);
                  emit_locked(
                    Event::Kind::session_failure,
                    &connection,
                    0,
                    Lane::control,
                    0,
                    ParseError::none,
                    ApiStatus::transport_error
                  );
                }
                if (!connection.session) {
                  begin_shutdown_locked(connection, shutdown_internal_error);
                  return ApiStatus::aborted;
                }
              }
              if (!connection.session) {
                begin_shutdown_locked(connection, shutdown_protocol_violation);
                return ApiStatus::aborted;
              }
              try {
                const auto session = connection.session;
                lock.unlock();
                auto responses = session->control(*parsed);
                auto bulk_transfers = session->take_bulk_transfers();
                const auto idle_timeout = session->idle_timeout_ms();
                const auto active_session = session->active_session_id();
                lock.lock();
                if (!connections_.contains(id) || connection.closing || connection.session != session) {
                  return ApiStatus::aborted;
                }
                connection.active_session_id = active_session;
                if (!accepted(api_.connection_set_idle_timeout(connection.handle, idle_timeout))) {
                  begin_shutdown_locked(connection, shutdown_internal_error);
                  return ApiStatus::aborted;
                }
                std::vector<std::uint64_t> response_request_ids;
                response_request_ids.reserve(responses.size());
                for (auto &response : responses) {
                  const auto parsed_response = response ? parse_control_frame(*response) :
                                                          std::expected<ControlFrame, ParseError> {
                                                            std::unexpected(ParseError::truncated)
                                                          };
                  if (!parsed_response) {
                    begin_shutdown_locked(connection, shutdown_internal_error);
                    return ApiStatus::aborted;
                  }
                  response_request_ids.push_back(parsed_response->request_id);
                  QueuedPacket packet {
                    .sequence = connection.next_packet_sequence++,
                    .lane = Lane::control,
                    .bytes = std::move(response),
                    .deadline = {},
                    .replaceable = false,
                    .object_id = 0,
                    .independently_decodable = false,
                  };
                  if (packet.bytes->size() > config_.maximum_queued_bytes -
                                               std::min(connection.queued_bytes, config_.maximum_queued_bytes) ||
                      connection.queued_packets >= config_.maximum_queued_packets) {
                    begin_shutdown_locked(connection, shutdown_internal_error);
                    return ApiStatus::aborted;
                  }
                  connection.queued_bytes += packet.bytes->size();
                  connection.queues[lane_index(packet.lane)].push_back(std::move(packet));
                  ++connection.queued_packets;
                }
                for (auto &transfer : bulk_transfers) {
                  const auto payload_bytes = transfer.bytes && transfer.bytes->size() >= bulk_header_bytes ?
                                               transfer.bytes->size() - bulk_header_bytes :
                                               maximum_bulk_buffered_bytes + 1;
                  if (!valid_bulk_transfer(transfer) ||
                      !std::ranges::contains(response_request_ids, transfer.request_id) ||
                      connection.pending_bulk.contains(transfer.request_id) ||
                      connection.bulk_transfer_count >= maximum_bulk_streams ||
                      payload_bytes > maximum_bulk_buffered_bytes -
                                        std::min(connection.bulk_buffered_bytes, maximum_bulk_buffered_bytes)) {
                    begin_shutdown_locked(connection, shutdown_internal_error);
                    return ApiStatus::aborted;
                  }
                  ++connection.bulk_transfer_count;
                  connection.bulk_buffered_bytes += payload_bytes;
                  connection.pending_bulk.emplace(transfer.request_id, std::move(transfer));
                }
              } catch (...) {
                if (!lock.owns_lock()) {
                  lock.lock();
                }
                begin_shutdown_locked(connection, shutdown_internal_error);
                return ApiStatus::aborted;
              }
              connection.control_receive.erase(
                connection.control_receive.begin(),
                connection.control_receive.begin() + static_cast<std::ptrdiff_t>(frame_size)
              );
            }
            drain_locked(connection_owner, lock);
            return ApiStatus::success;
          }
        case StreamEvent::Kind::send_complete:
          complete_send_locked(connection, event.send_token, event.canceled);
          drain_locked(connection_owner, lock);
          return ApiStatus::success;
        case StreamEvent::Kind::writable:
          drain_locked(connection_owner, lock);
          return ApiStatus::success;
        case StreamEvent::Kind::start_complete:
          if (event.canceled) {
            begin_shutdown_locked(connection, shutdown_internal_error);
          }
          return ApiStatus::success;
        case StreamEvent::Kind::peer_send_shutdown:
        case StreamEvent::Kind::peer_send_aborted:
        case StreamEvent::Kind::peer_receive_aborted:
        case StreamEvent::Kind::send_shutdown_complete:
          begin_shutdown_locked(connection, shutdown_protocol_violation);
          return ApiStatus::success;
        case StreamEvent::Kind::shutdown_complete:
          if (connection.force_closing) {
            send_drain_condition_.notify_all();
            if (!is_control) {
              lock.unlock();
              api_.stream_close(stream);
            }
            return ApiStatus::success;
          }
          api_.stream_close(stream);
          if (connection.control_stream == stream) {
            connection.control_stream = invalid_handle;
          }
          return ApiStatus::success;
      }
      return ApiStatus::transport_error;
    }

    void note_video_send_locked(Connection &connection, const std::uint64_t object_id) noexcept {
      if (connection.pending_video_fragments == 0) {
        connection.pending_video_object = object_id;
        connection.pending_video_objects_mixed = false;
      } else if (connection.pending_video_object != object_id) {
        connection.pending_video_objects_mixed = true;
      }
      ++connection.pending_video_fragments;
    }

    void recompute_pending_video_objects_locked(Connection &connection) noexcept {
      connection.pending_video_object.reset();
      connection.pending_video_objects_mixed = false;
      for (std::size_t index = 0; index < connection.send_slots.capacity(); ++index) {
        if (!connection.send_slots.occupied(index) ||
            connection.pending[index].packet.lane != Lane::delta_video) {
          continue;
        }
        const auto object_id = connection.pending[index].packet.object_id;
        if (!connection.pending_video_object) {
          connection.pending_video_object = object_id;
        } else if (*connection.pending_video_object != object_id) {
          connection.pending_video_objects_mixed = true;
          return;
        }
      }
    }

    void release_send_locked(Connection &connection, const std::uint64_t token) noexcept {
      const auto *pending = connection.find_send(token);
      if (pending == nullptr) {
        return;
      }
      const auto video = pending->packet.lane == Lane::delta_video;
      const auto mixed = connection.pending_video_objects_mixed;
      static_cast<void>(connection.release_send(token));
      if (!video) {
        return;
      }
      connection.pending_video_fragments -= std::min<std::size_t>(connection.pending_video_fragments, 1);
      if (connection.pending_video_fragments == 0) {
        connection.pending_video_object.reset();
        connection.pending_video_objects_mixed = false;
      } else if (mixed) {
        recompute_pending_video_objects_locked(connection);
      }
    }

    std::size_t video_send_budget_locked(const Connection &connection) const noexcept {
      const auto rtt = connection.congestion &&
                           (connection.congestion->valid_fields & CongestionSample::valid_rtt) != 0 ?
                         connection.congestion->smoothed_rtt_microseconds :
                         config_.initial_rtt_microseconds;
      const auto congestion_window = connection.congestion &&
                                         (connection.congestion->valid_fields &
                                          CongestionSample::valid_congestion_window) != 0 ?
                                       std::optional<std::uint64_t> {
                                         connection.congestion->congestion_window_bytes
                                       } :
                                       std::nullopt;
      const auto bytes_in_flight = connection.congestion &&
                                       (connection.congestion->valid_fields &
                                        CongestionSample::valid_bytes_in_flight) != 0 ?
                                     std::optional<std::uint64_t> {
                                       connection.congestion->bytes_in_flight
                                     } :
                                     std::nullopt;
      return latency_video_send_budget({
        .maximum_in_flight_sends = config_.maximum_in_flight_sends,
        .urgent_send_reserve = config_.urgent_send_reserve,
        .maximum_datagram_bytes = connection.maximum_datagram_bytes,
        .video_bitrate_kbps = connection.video_bitrate_kbps,
        .smoothed_rtt_microseconds = rtt,
        .congestion_window_bytes = congestion_window,
        .bytes_in_flight = bytes_in_flight,
      });
    }

    void sample_congestion_locked(Connection &connection, const bool force) noexcept {
      const auto now = MonotonicClock::now();
      if (!force && now - connection.last_congestion_sample_at < congestion_sample_interval) {
        return;
      }
      connection.last_congestion_sample_at = now;
      try {
        if (const auto sample = api_.congestion_sample(connection.handle)) {
          connection.congestion = *sample;
          if (congestion_observer_ != nullptr) {
            congestion_observer_->on_congestion_sample(connection.id, *sample, next_event_time_locked());
          }
        }
      } catch (...) {
      }
    }

    void complete_send_locked(
      Connection &connection,
      const std::uint64_t token,
      const bool canceled
    ) {
      const auto *pending = connection.find_send(token);
      if (pending == nullptr) {
        return;
      }
      const auto sequence = pending->packet.sequence;
      const auto lane = pending->packet.lane;
      const auto bytes = pending->byte_count != 0 ? pending->byte_count : pending->packet.bytes->size();
      auto *const video_frame = pending->video_frame;
      const auto sample_video_frame = video_frame != nullptr && !video_frame->congestion_sampled;
      if (sample_video_frame) {
        video_frame->congestion_sampled = true;
      }
      release_send_locked(connection, token);
      send_drain_condition_.notify_all();
      emit_locked(
        canceled ? Event::Kind::send_canceled : Event::Kind::send_completed,
        &connection,
        sequence,
        lane,
        bytes
      );
      if (video_frame != nullptr) {
        video_frame->in_flight -= std::min<std::size_t>(video_frame->in_flight, 1);
        if (canceled) {
          cancel_video_frame_locked(connection, video_frame, true);
        } else if (video_frame->in_flight == 0 &&
                   (video_frame->canceled ||
                    video_frame->next_fragment >= video_frame->frame->fragment_count())) {
          erase_video_frame_locked(connection, video_frame);
        }
      }
      if (canceled && delivery_for(lane) == Delivery::reliable_stream) {
        begin_shutdown_locked(connection, shutdown_internal_error);
      }
      if (lane == Lane::delta_video) {
        sample_congestion_locked(connection, sample_video_frame);
      }
    }

    void signal_video_recovery_locked(VideoFrameState *const state) noexcept {
      if (!state || state->recovery_signaled) {
        return;
      }
      state->recovery_signaled = true;
      state->frame->request_recovery();
    }

    void erase_video_frame_locked(
      Connection &connection,
      const VideoFrameState *const state
    ) noexcept {
      const auto found = std::find_if(
        connection.video_frames.begin(),
        connection.video_frames.end(),
        [state](const auto &candidate) { return candidate.get() == state; }
      );
      if (found == connection.video_frames.end()) {
        return;
      }
      connection.video_frame_bytes -= std::min(
        connection.video_frame_bytes,
        (*found)->frame->retained_bytes()
      );
      connection.video_frames.erase(found);
    }

    void cancel_video_frame_locked(
      Connection &connection,
      VideoFrameState *const state,
      const bool request_recovery
    ) noexcept {
      if (!state) {
        return;
      }
      state->canceled = true;
      state->next_fragment = state->frame->fragment_count();
      if (request_recovery) {
        signal_video_recovery_locked(state);
      }
      if (state->in_flight == 0) {
        erase_video_frame_locked(connection, state);
      }
    }

    void cancel_all_video_frames_locked(Connection &connection) noexcept {
      for (auto it = connection.video_frames.begin(); it != connection.video_frames.end();) {
        auto &state = **it;
        state.canceled = true;
        state.next_fragment = state.frame->fragment_count();
        if (state.in_flight == 0) {
          connection.video_frame_bytes -= std::min(
            connection.video_frame_bytes,
            state.frame->retained_bytes()
          );
          it = connection.video_frames.erase(it);
        } else {
          ++it;
        }
      }
    }

    VideoFrameState *next_video_frame_locked(const Connection &connection) const noexcept {
      const auto found = std::find_if(
        connection.video_frames.begin(),
        connection.video_frames.end(),
        [](const auto &state) {
          return !state->canceled && state->next_fragment < state->frame->fragment_count();
        }
      );
      return found == connection.video_frames.end() ? nullptr : found->get();
    }

    void drop_expired_locked(Connection &connection, const MonotonicClock::time_point now) {
      for (auto &queue : connection.queues) {
        for (auto it = queue.begin(); it != queue.end();) {
          if (it->deadline != MonotonicClock::time_point {} && it->deadline <= now) {
            const auto removed = *it;
            connection.queued_bytes -= removed.bytes->size();
            --connection.queued_packets;
            it = queue.erase(it);
            emit_locked(
              Event::Kind::packet_expired,
              &connection,
              removed.sequence,
              removed.lane,
              removed.bytes->size()
            );
          } else {
            ++it;
          }
        }
      }
      const auto expired_frames = connection.video_frames;
      for (const auto &state : expired_frames) {
        if (!state->canceled && state->frame->deadline() <= now) {
          emit_locked(
            Event::Kind::packet_expired,
            &connection,
            state->first_sequence,
            Lane::delta_video,
            state->frame->retained_bytes()
          );
          cancel_video_frame_locked(connection, state.get(), true);
        }
      }
    }

    std::optional<Lane> next_lane_locked(const Connection &connection) const {
      const auto quality_priority = [](const Lane lane) {
        if (lane == Lane::control || lane == Lane::key_config) {
          return std::uint8_t {0};
        }
        if (lane == Lane::input_edge || lane == Lane::audio || lane == Lane::microphone) {
          return std::uint8_t {1};
        }
        return std::uint8_t {2};
      };
      std::optional<Lane> selected;
      std::uint8_t selected_priority = std::numeric_limits<std::uint8_t>::max();
      std::uint64_t selected_sequence = std::numeric_limits<std::uint64_t>::max();
      for (const auto lane : all_lanes) {
        const auto &queue = connection.queues[lane_index(lane)];
        if (queue.empty()) {
          continue;
        }
        const auto priority = is_latency(connection.profile) ?
                                latency_priority(lane) :
                                quality_priority(lane);
        if (priority < selected_priority ||
            (priority == selected_priority && queue.front().sequence < selected_sequence)) {
          selected = lane;
          selected_priority = priority;
          selected_sequence = queue.front().sequence;
        }
      }
      if (const auto frame = next_video_frame_locked(connection)) {
        const auto priority = is_latency(connection.profile) ?
                                latency_priority(Lane::delta_video) :
                                quality_priority(Lane::delta_video);
        const auto sequence = frame->first_sequence + frame->next_fragment;
        if (priority < selected_priority ||
            (priority == selected_priority && sequence < selected_sequence)) {
          selected = Lane::delta_video;
        }
      }
      return selected;
    }

    bool submit_video_fragment_locked(
      const std::shared_ptr<Connection> &connection_owner,
      VideoFrameState *const state,
      std::unique_lock<std::mutex> &lock
    ) {
      auto &connection = *connection_owner;
      if (!state || state->canceled ||
          state->next_fragment >= state->frame->fragment_count() ||
          !connection.datagram_send_enabled || connection.maximum_datagram_bytes == 0 ||
          connection.send_slots.active() >= config_.maximum_in_flight_sends - config_.urgent_send_reserve) {
        return false;
      }
      if (state->frame->deadline() <= MonotonicClock::now()) {
        cancel_video_frame_locked(connection, state, true);
        return true;
      }

      const auto budget = video_send_budget_locked(connection);
      const auto wrong_latency_object = is_latency(connection.profile) &&
                                        connection.pending_video_object &&
                                        (*connection.pending_video_object != state->frame->object_id() ||
                                         connection.pending_video_objects_mixed);
      if (wrong_latency_object || connection.pending_video_fragments >= budget) {
        return false;
      }

      const auto fragment_index = state->next_fragment;
      std::uint64_t token {};
      auto *const pending = connection.acquire_send(token);
      if (pending == nullptr) {
        return false;
      }
      VideoFragmentView fragment;
      if (!state->frame->materialize(fragment_index, pending->video_header, fragment) ||
          fragment.header_size < datagram_header_bytes ||
          fragment.header_size > pending->video_header.size() ||
          !fragment.payload || fragment.payload_size == 0 ||
          fragment.header_size + fragment.payload_size > connection.maximum_datagram_bytes) {
        static_cast<void>(connection.release_send(token));
        cancel_video_frame_locked(connection, state, true);
        emit_locked(
          Event::Kind::packet_backpressured,
          &connection,
          state->first_sequence + fragment_index,
          Lane::delta_video,
          0
        );
        return true;
      }
      const auto active = connection.active_session_id;
      const auto parsed = active ? parse_datagram_header(
                                     std::span<const std::uint8_t> {pending->video_header}.first(fragment.header_size),
                                     fragment.header_size + fragment.payload_size,
                                     Direction::host_to_client,
                                     std::span<const std::uint8_t, 16> {*active},
                                     connection.maximum_datagram_bytes
                                   ) :
                                   std::expected<DatagramRecord, ParseError> {
                                     std::unexpected(ParseError::session_mismatch)
                                   };
      if (!parsed || parsed->channel != 2 || parsed->kind != 1 ||
          parsed->object_id != state->frame->object_id()) {
        static_cast<void>(connection.release_send(token));
        cancel_video_frame_locked(connection, state, true);
        return true;
      }

      pending->packet = {
        .sequence = state->first_sequence + fragment_index,
        .lane = Lane::delta_video,
        .bytes = nullptr,
        .deadline = state->frame->deadline(),
        .replaceable = state->frame->replaceable(),
        .object_id = state->frame->object_id(),
        .independently_decodable = state->frame->independently_decodable(),
      };
      pending->video_frame = state;
      pending->byte_count = fragment.header_size + fragment.payload_size;
      const std::array<Buffer, 2> buffers {{
        {pending->video_header.data(), fragment.header_size},
        {fragment.payload, fragment.payload_size},
      }};
      note_video_send_locked(connection, pending->packet.object_id);
      ++state->next_fragment;
      ++state->in_flight;
      const auto sequence = pending->packet.sequence;
      const auto byte_count = pending->byte_count;
      emit_locked(
        Event::Kind::send_submitted,
        &connection,
        sequence,
        Lane::delta_video,
        byte_count
      );

      const auto connection_handle = connection.handle;
      const auto cancel_on_blocked = is_latency(connection.profile);
      lock.unlock();
      const auto status = api_.datagram_send(
        connection_handle,
        buffers,
        token,
        false,
        cancel_on_blocked
      );
      lock.lock();
      if (!connections_.contains(connection.id) || connection.closing) {
        return false;
      }
      if (!accepted(status)) {
        release_send_locked(connection, token);
        state->in_flight -= std::min<std::size_t>(state->in_flight, 1);
        cancel_video_frame_locked(connection, state, true);
        emit_locked(
          Event::Kind::packet_backpressured,
          &connection,
          sequence,
          Lane::delta_video,
          byte_count
        );
        emit_locked(
          Event::Kind::api_failure,
          &connection,
          sequence,
          Lane::delta_video,
          byte_count,
          ParseError::none,
          status
        );
      }
      return true;
    }

    void drain_locked(
      const std::shared_ptr<Connection> &connection_owner,
      std::unique_lock<std::mutex> &lock
    ) {
      auto &connection = *connection_owner;
      if (!connection.connected || connection.closing) {
        return;
      }
      drop_expired_locked(connection, MonotonicClock::now());
      while ((connection.queued_packets != 0 || next_video_frame_locked(connection)) &&
             connection.send_slots.active() < config_.maximum_in_flight_sends) {
        const auto next_lane = next_lane_locked(connection);
        if (!next_lane) {
          return;
        }
        auto &queue = connection.queues[lane_index(*next_lane)];
        if (*next_lane == Lane::delta_video) {
          const auto frame = next_video_frame_locked(connection);
          const bool use_lazy_frame = frame &&
                                      (queue.empty() ||
                                       frame->first_sequence + frame->next_fragment < queue.front().sequence);
          if (use_lazy_frame) {
            if (!submit_video_fragment_locked(connection_owner, frame, lock)) {
              return;
            }
            continue;
          }
        }
        auto next = queue.begin();
        if (delivery_for(next->lane) == Delivery::datagram &&
            (!connection.datagram_send_enabled || connection.maximum_datagram_bytes == 0)) {
          return;
        }

        const bool urgent = next->lane != Lane::delta_video;
        if (!urgent &&
            connection.send_slots.active() >= config_.maximum_in_flight_sends - config_.urgent_send_reserve) {
          return;
        }
        if (next->lane == Lane::delta_video) {
          const auto budget = video_send_budget_locked(connection);
          const auto wrong_latency_object = is_latency(connection.profile) &&
                                            connection.pending_video_object &&
                                            (*connection.pending_video_object != next->object_id ||
                                             connection.pending_video_objects_mixed);
          if (wrong_latency_object || connection.pending_video_fragments >= budget) {
            return;
          }
        }

        Handle stream = invalid_handle;
        if (delivery_for(next->lane) == Delivery::reliable_stream) {
          stream = connection.control_stream;
          if (stream == invalid_handle) {
            return;
          }
        }

        std::uint64_t token {};
        auto *const pending = connection.acquire_send(token);
        if (pending == nullptr) {
          return;
        }
        pending->packet = *next;
        const std::array<Buffer, 1> buffers {{
          {pending->packet.bytes->data(), pending->packet.bytes->size()},
        }};
        if (pending->packet.lane == Lane::delta_video) {
          note_video_send_locked(connection, pending->packet.object_id);
        }
        const auto sequence = pending->packet.sequence;
        const auto lane = pending->packet.lane;
        const auto byte_count = pending->packet.bytes->size();
        std::optional<std::uint64_t> control_request_id;
        if (delivery_for(lane) == Delivery::reliable_stream) {
          const auto sent = parse_control_frame(*pending->packet.bytes);
          if (sent) {
            control_request_id = sent->request_id;
          }
        }
        connection.queued_bytes -= next->bytes->size();
        --connection.queued_packets;
        queue.erase(next);
        emit_locked(
          Event::Kind::send_submitted,
          &connection,
          sequence,
          lane,
          byte_count
        );

        const auto datagram = delivery_for(lane) == Delivery::datagram;
        const auto connection_handle = connection.handle;
        const auto cancel_on_blocked = is_latency(connection.profile);
        lock.unlock();
        const auto status = datagram ?
                              api_.datagram_send(
                                connection_handle,
                                buffers,
                                token,
                                urgent,
                                cancel_on_blocked
                              ) :
                              api_.stream_send(stream, buffers, token, urgent, false);
        lock.lock();
        if (!connections_.contains(connection.id) || connection.closing) {
          return;
        }
        if (!accepted(status)) {
          release_send_locked(connection, token);
          emit_locked(
            Event::Kind::packet_backpressured,
            &connection,
            sequence,
            lane,
            byte_count
          );
          emit_locked(
            Event::Kind::api_failure,
            &connection,
            sequence,
            lane,
            byte_count,
            ParseError::none,
            status
          );
          begin_shutdown_locked(connection, shutdown_internal_error);
          return;
        }
        if (!datagram) {
          const auto staged = control_request_id ? connection.pending_bulk.find(*control_request_id) :
                                                   connection.pending_bulk.end();
          if (staged != connection.pending_bulk.end()) {
            auto transfer = std::move(staged->second);
            connection.pending_bulk.erase(staged);
            const auto id = connection.id;
            lock.unlock();
            const auto bulk_status = send_bulk(id, std::move(transfer), true);
            lock.lock();
            const auto live = connections_.find(id);
            if (live == connections_.end()) {
              return;
            }
            if (bulk_status != BulkSendResult::submitted) {
              begin_shutdown_locked(*live->second, shutdown_internal_error);
              return;
            }
          }
        }
      }
    }

    void begin_shutdown_locked(Connection &connection, const std::uint64_t error) noexcept {
      if (connection.closing) {
        return;
      }
      connection.closing = true;
      for (auto &queue : connection.queues) {
        queue.clear();
      }
      cancel_all_video_frames_locked(connection);
      connection.queued_packets = 0;
      connection.queued_bytes = 0;
      if (connection.session) {
        defer_disconnect_locked(connection);
      }
      api_.connection_shutdown(connection.handle, error);
    }

    void erase_connection_locked(const std::uint64_t id, const bool close_handle) noexcept {
      const auto found = connections_.find(id);
      if (found == connections_.end()) {
        return;
      }
      auto connection = found->second;
      if (connection->session) {
        defer_disconnect_locked(*connection);
      }
      connection->clear_sends();
      for (auto &queue : connection->queues) {
        queue.clear();
      }
      connection->video_frames.clear();
      connection->video_frame_bytes = 0;
      connection->queued_packets = 0;
      if (connection->control_stream != invalid_handle) {
        api_.stream_close(connection->control_stream);
        connection->control_stream = invalid_handle;
      }
      for (const auto &[stream, _] : connection->bulk_streams) {
        api_.stream_close(stream);
      }
      connection->bulk_streams.clear();
      connection->pending_bulk.clear();
      connection->bulk_transfer_count = 0;
      connection->bulk_buffered_bytes = 0;
      connection_ids_.erase(connection->handle);
      const auto source = connections_per_source_.find(connection->remote_source);
      if (source != connections_per_source_.end()) {
        if (source->second <= 1) {
          connections_per_source_.erase(source);
        } else {
          --source->second;
        }
      }
      if (close_handle) {
        api_.connection_close(connection->handle);
      }
      emit_locked(Event::Kind::connection_closed, connection.get(), 0, Lane::control, 0);
      connections_.erase(found);
      if (stopping_ && listener_ == invalid_handle && connections_.empty()) {
        close_roots_locked();
        stopping_ = false;
      }
    }

    void close_roots_locked() noexcept {
      if (configuration_ != invalid_handle) {
        api_.configuration_close(configuration_);
        configuration_ = invalid_handle;
      }
      if (registration_ != invalid_handle) {
        api_.registration_close(registration_);
        registration_ = invalid_handle;
      }
    }

    void force_close_all() noexcept {
      struct DetachedConnection {
        std::shared_ptr<Connection> owner;
        std::vector<Handle> streams;
      };

      Handle listener = invalid_handle;
      Handle configuration = invalid_handle;
      Handle registration = invalid_handle;
      std::vector<DetachedConnection> detached;
      {
        std::lock_guard lock {mutex_};
        running_ = false;
        stopping_ = true;
        listener = std::exchange(listener_, invalid_handle);
        configuration = std::exchange(configuration_, invalid_handle);
        registration = std::exchange(registration_, invalid_handle);
        detached.reserve(connections_.size());
        for (auto &[id, connection] : connections_) {
          static_cast<void>(id);
          connection->force_closing = true;
          connection->closing = true;
          for (auto &queue : connection->queues) {
            queue.clear();
          }
          cancel_all_video_frames_locked(*connection);
          connection->queued_packets = 0;
          connection->queued_bytes = 0;
          if (connection->session) {
            defer_disconnect_locked(*connection);
          }
          DetachedConnection handles {.owner = connection, .streams = {}};
          if (connection->control_stream != invalid_handle) {
            handles.streams.push_back(connection->control_stream);
          }
          for (const auto &[stream, _] : connection->bulk_streams) {
            handles.streams.push_back(stream);
          }
          detached.push_back(std::move(handles));
        }
      }

      if (listener != invalid_handle) {
        api_.listener_stop(listener);
        api_.listener_close(listener);
      }
      for (auto &handles : detached) {
        for (const auto stream : handles.streams) {
          api_.stream_shutdown(stream, shutdown_server_stopping);
        }
        api_.connection_shutdown(handles.owner->handle, shutdown_server_stopping);
        {
          std::unique_lock lock {mutex_};
          static_cast<void>(send_drain_condition_.wait_for(
            lock,
            force_close_send_drain_timeout,
            [&] {
              return handles.owner->send_slots.active() == 0 &&
                     std::ranges::all_of(handles.owner->bulk_streams, [](const auto &entry) {
                       return entry.second->buffer_released;
                     });
            }
          ));
        }
        for (const auto stream : handles.streams) {
          api_.stream_close(stream);
        }
        api_.connection_close(handles.owner->handle);
        {
          std::lock_guard lock {mutex_};
          handles.owner->clear_sends();
          handles.owner->pending_bulk.clear();
          handles.owner->bulk_streams.clear();
          handles.owner->control_receive.clear();
          connection_ids_.erase(handles.owner->handle);
          connections_.erase(handles.owner->id);
        }
      }
      {
        std::lock_guard lock {mutex_};
        connection_ids_.clear();
        connections_per_source_.clear();
      }
      if (configuration != invalid_handle) {
        api_.configuration_close(configuration);
      }
      if (registration != invalid_handle) {
        api_.registration_close(registration);
      }
      {
        std::lock_guard lock {mutex_};
        stopping_ = false;
      }
    }

    MonotonicClock::time_point next_event_time_locked() noexcept {
      auto now = MonotonicClock::now();
      if (now <= last_event_time_) {
        now = last_event_time_ + std::chrono::nanoseconds {1};
      }
      last_event_time_ = now;
      return now;
    }

    void defer_disconnect_locked(Connection &connection) noexcept {
      if (!connection.session) {
        return;
      }
      {
        std::lock_guard teardown_lock {teardown_mutex_};
        teardown_sessions_.push_back(std::move(connection.session));
      }
      teardown_condition_.notify_one();
    }

    void teardown_sessions(const std::stop_token stop) noexcept {
      while (true) {
        std::shared_ptr<ControlSessionV3> session;
        {
          std::unique_lock lock {teardown_mutex_};
          teardown_condition_.wait(lock, [&] {
            return stop.stop_requested() || !teardown_sessions_.empty();
          });
          if (teardown_sessions_.empty()) {
            if (stop.stop_requested()) {
              return;
            }
            continue;
          }
          session = std::move(teardown_sessions_.front());
          teardown_sessions_.pop_front();
        }
        while (session.use_count() > 1) {
          std::this_thread::yield();
        }
        try {
          session->disconnect();
        } catch (...) {
        }
      }
    }

    void emit_locked(
      const Event::Kind kind,
      const Connection *connection,
      const std::uint64_t packet_sequence,
      const Lane lane,
      const std::size_t bytes,
      const ParseError parse_error = ParseError::none,
      const ApiStatus api_status = ApiStatus::success
    ) noexcept {
      if (observer_ == nullptr) {
        return;
      }
      const Event event {
        .kind = kind,
        .connection_id = connection == nullptr ? 0 : connection->id,
        .packet_sequence = packet_sequence,
        .lane = lane,
        .bytes = bytes,
        .parse_error = parse_error,
        .api_status = api_status,
        .timestamp = next_event_time_locked(),
      };
      try {
        observer_->on_event(event);
      } catch (...) {
      }
    }

    MsQuicApi &api_;
    Config config_;
    SessionFactory &session_factory_;
    Observer *observer_;
    CongestionObserver *congestion_observer_;
    mutable std::mutex mutex_;
    std::condition_variable send_drain_condition_;
    Handle registration_ {invalid_handle};
    Handle configuration_ {invalid_handle};
    Handle listener_ {invalid_handle};
    std::array<std::uint8_t, 32> leaf_spki_sha256_ {};
    bool running_ {};
    bool stopping_ {};
    std::uint64_t next_connection_id_ {1};
    std::uint64_t next_send_token_ {1};
    std::map<std::uint64_t, std::shared_ptr<Connection>> connections_;
    std::map<Handle, std::uint64_t> connection_ids_;
    std::map<RemoteSourcePrefix, std::size_t> connections_per_source_;
    MonotonicClock::time_point last_event_time_ {};
    std::mutex teardown_mutex_;
    std::condition_variable teardown_condition_;
    std::deque<std::shared_ptr<ControlSessionV3>> teardown_sessions_;
    std::jthread teardown_thread_;
  };

  QuicServer::QuicServer(
    MsQuicApi &api,
    Config config,
    SessionFactory &session_factory,
    Observer *observer,
    CongestionObserver *congestion_observer
  ):
      impl_ {std::make_shared<Impl>(
        api,
        std::move(config),
        session_factory,
        observer,
        congestion_observer
      )} {
  }

  QuicServer::~QuicServer() = default;

  ApiStatus QuicServer::start() {
    if (!impl_) {
      return ApiStatus::invalid_state;
    }
    return impl_->start();
  }

  void QuicServer::stop() noexcept {
    if (impl_) {
      impl_->stop();
    }
  }

  EnqueueResult QuicServer::enqueue(const std::uint64_t connection_id, Packet packet) {
    if (!impl_) {
      return EnqueueResult::shutting_down;
    }
    return impl_->enqueue(connection_id, std::move(packet));
  }

  EnqueueResult QuicServer::enqueue_video_frame(
    const std::uint64_t connection_id,
    std::shared_ptr<const LazyVideoFrame> frame
  ) {
    return impl_ ? impl_->enqueue_video_frame(connection_id, std::move(frame)) :
                   EnqueueResult::shutting_down;
  }

  bool QuicServer::set_connection_policy(
    const std::uint64_t connection_id,
    const Profile profile,
    const std::uint64_t video_bitrate_kbps
  ) noexcept {
    return impl_ && impl_->set_connection_policy(connection_id, profile, video_bitrate_kbps);
  }

  bool QuicServer::revoke_connection(const std::uint64_t connection_id) noexcept {
    return impl_ && impl_->revoke_connection(connection_id);
  }

  std::size_t QuicServer::active_connections() const noexcept {
    return impl_ ? impl_->active_connections() : 0;
  }

  std::size_t QuicServer::queued_packets() const noexcept {
    return impl_ ? impl_->queued_packets() : 0;
  }

  bool QuicServer::running() const noexcept {
    return impl_ && impl_->running();
  }

  std::optional<std::array<std::uint8_t, 32>> QuicServer::leaf_spki_sha256() const noexcept {
    if (!impl_ || !impl_->running()) {
      return std::nullopt;
    }
    return impl_->leaf_spki_sha256();
  }

#if defined(_WIN32) && defined(LUMEN_EXPERIMENTAL_MSQUIC)
  namespace {
    static_assert(static_cast<int>(ApiStatus::success) == LUMEN_MSQUIC_SUCCESS);
    static_assert(static_cast<int>(ApiStatus::pending) == LUMEN_MSQUIC_PENDING);
    static_assert(static_cast<int>(ApiStatus::out_of_memory) == LUMEN_MSQUIC_OUT_OF_MEMORY);
    static_assert(static_cast<int>(ApiStatus::invalid_state) == LUMEN_MSQUIC_INVALID_STATE);
    static_assert(static_cast<int>(ApiStatus::not_supported) == LUMEN_MSQUIC_NOT_SUPPORTED);
    static_assert(static_cast<int>(ApiStatus::aborted) == LUMEN_MSQUIC_ABORTED);
    static_assert(static_cast<int>(ApiStatus::transport_error) == LUMEN_MSQUIC_TRANSPORT_ERROR);

    ApiStatus shim_status(const lumen_msquic_status value) noexcept {
      return static_cast<ApiStatus>(value);
    }

    class ShimMsQuicApi final: public MsQuicApi {
    public:
      ShimMsQuicApi() {
        if (lumen_msquic_open(LUMEN_MSQUIC_SHIM_ABI_VERSION, &shim_) != LUMEN_MSQUIC_SUCCESS) {
          throw std::runtime_error {"lumen_msquic_shim_open_failed"};
        }
      }

      ~ShimMsQuicApi() override {
        if (shim_) {
          lumen_msquic_close(shim_);
        }
      }

      bool is_schannel() const noexcept override {
        return shim_ && lumen_msquic_is_schannel(shim_) != 0;
      }

      ApiStatus registration_open(std::string_view name, Handle &h) override {
        const std::string owned {name};
        return shim_status(lumen_msquic_registration_open(shim_, owned.c_str(), &h));
      }

      void registration_close(Handle h) noexcept override {
        lumen_msquic_registration_close(shim_, h);
      }

      ApiStatus configuration_open(
        Handle r,
        std::string_view alpn,
        std::uint16_t bidi,
        std::uint16_t unidi,
        std::uint64_t handshake_timeout_ms,
        std::uint64_t initial_idle_timeout_ms,
        Handle &h
      ) override {
        return shim_status(lumen_msquic_configuration_open(
          shim_,
          r,
          reinterpret_cast<const std::uint8_t *>(alpn.data()),
          alpn.size(),
          bidi,
          unidi,
          handshake_timeout_ms,
          initial_idle_timeout_ms,
          &h
        ));
      }

      ApiStatus configuration_load_pkcs12(
        Handle h,
        std::span<const std::uint8_t> pkcs12,
        std::string_view password
      ) override {
        const std::string owned_password {password};
        return shim_status(lumen_msquic_configuration_load_pkcs12(
          shim_,
          h,
          pkcs12.data(),
          pkcs12.size(),
          owned_password.c_str()
        ));
      }

      ApiStatus configuration_leaf_spki_sha256(
        Handle h,
        std::span<std::uint8_t, 32> output
      ) override {
        return shim_status(lumen_msquic_configuration_leaf_spki_sha256(shim_, h, output.data()));
      }

      void configuration_close(Handle h) noexcept override {
        lumen_msquic_configuration_close(shim_, h);
      }

      ApiStatus listener_open(Handle r, ListenerCallback cb, Handle &h) override {
        auto holder = std::make_shared<ListenerHolder>();
        holder->callback = std::move(cb);
        const auto result = shim_status(lumen_msquic_listener_open(shim_, r, &listener_callback, holder.get(), &h));
        if (accepted(result)) {
          std::lock_guard lock {mutex_};
          listeners_[h] = std::move(holder);
        }
        return result;
      }

      ApiStatus listener_start(Handle h, std::string_view alpn, std::uint16_t port) override {
        return shim_status(lumen_msquic_listener_start(
          shim_,
          h,
          reinterpret_cast<const std::uint8_t *>(alpn.data()),
          alpn.size(),
          port
        ));
      }

      void listener_stop(Handle h) noexcept override {
        lumen_msquic_listener_stop(shim_, h);
      }

      void listener_close(Handle h) noexcept override {
        lumen_msquic_listener_close(shim_, h);
        std::lock_guard lock {mutex_};
        listeners_.erase(h);
      }

      ApiStatus connection_set_callback(Handle h, ConnectionCallback cb) override {
        auto holder = std::make_shared<ConnectionHolder>();
        holder->callback = std::move(cb);
        const auto result = shim_status(lumen_msquic_connection_set_callback(shim_, h, &connection_callback, holder.get()));
        if (accepted(result)) {
          std::lock_guard lock {mutex_};
          connections_[h] = std::move(holder);
        }
        return result;
      }

      ApiStatus connection_set_configuration(Handle h, Handle c) override {
        return shim_status(lumen_msquic_connection_set_configuration(shim_, h, c));
      }

      ApiStatus connection_set_idle_timeout(Handle h, std::uint64_t timeout_ms) override {
        return shim_status(lumen_msquic_connection_set_idle_timeout(shim_, h, timeout_ms));
      }

      void connection_shutdown(Handle h, std::uint64_t e) noexcept override {
        lumen_msquic_connection_shutdown(shim_, h, e);
      }

      void connection_close(Handle h) noexcept override {
        lumen_msquic_connection_close(shim_, h);
        std::lock_guard lock {mutex_};
        connections_.erase(h);
      }

      ApiStatus stream_open_unidirectional(Handle connection, StreamCallback cb, Handle &h) override {
        auto holder = std::make_shared<StreamHolder>();
        holder->callback = std::move(cb);
        const auto result = shim_status(lumen_msquic_stream_open_unidirectional(
          shim_, connection, &stream_callback, holder.get(), &h
        ));
        if (accepted(result)) {
          std::lock_guard lock {mutex_};
          streams_[h] = std::move(holder);
        }
        return result;
      }

      ApiStatus stream_start(Handle h) override {
        return shim_status(lumen_msquic_stream_start(shim_, h));
      }

      ApiStatus stream_set_callback(Handle h, StreamCallback cb) override {
        auto holder = std::make_shared<StreamHolder>();
        holder->callback = std::move(cb);
        const auto result = shim_status(lumen_msquic_stream_set_callback(shim_, h, &stream_callback, holder.get()));
        if (accepted(result)) {
          std::lock_guard lock {mutex_};
          streams_[h] = std::move(holder);
        }
        return result;
      }

      ApiStatus stream_send(
        Handle h,
        std::span<const Buffer> b,
        std::uint64_t t,
        bool urgent,
        bool fin
      ) override {
        const auto buffers = shim_buffers(b);
        return shim_status(lumen_msquic_stream_send(
          shim_, h, buffers.data(), buffers.size(), t, urgent, fin
        ));
      }

      ApiStatus stream_set_priority(Handle h, std::uint16_t p) override {
        return shim_status(lumen_msquic_stream_set_priority(shim_, h, p));
      }

      void stream_receive_complete(Handle h, std::uint64_t b) noexcept override {
        lumen_msquic_stream_receive_complete(shim_, h, b);
      }

      void stream_shutdown(Handle h, std::uint64_t e) noexcept override {
        lumen_msquic_stream_shutdown(shim_, h, e);
      }

      void stream_close(Handle h) noexcept override {
        lumen_msquic_stream_close(shim_, h);
        std::lock_guard lock {mutex_};
        streams_.erase(h);
      }

      ApiStatus datagram_send(Handle h, std::span<const Buffer> b, std::uint64_t t, bool urgent, bool cancel) override {
        const auto buffers = shim_buffers(b);
        return shim_status(lumen_msquic_datagram_send(shim_, h, buffers.data(), buffers.size(), t, urgent, cancel));
      }

      std::optional<CongestionSample> congestion_sample(Handle h) noexcept override {
        lumen_msquic_statistics statistics {};
        if (lumen_msquic_connection_statistics(shim_, h, &statistics) != LUMEN_MSQUIC_SUCCESS) {
          return std::nullopt;
        }
        return CongestionSample {
          .valid_fields = statistics.valid_fields,
          .smoothed_rtt_microseconds = statistics.smoothed_rtt_microseconds,
          .minimum_rtt_microseconds = statistics.minimum_rtt_microseconds,
          .congestion_window_bytes = statistics.congestion_window_bytes,
          .bytes_in_flight = statistics.bytes_in_flight,
          .packets_lost = statistics.packets_lost,
        };
      }

    private:
      struct ListenerHolder: std::enable_shared_from_this<ListenerHolder> {
        ListenerCallback callback;
      };

      struct ConnectionHolder: std::enable_shared_from_this<ConnectionHolder> {
        ConnectionCallback callback;
      };

      struct StreamHolder: std::enable_shared_from_this<StreamHolder> {
        StreamCallback callback;
      };

      static lumen_msquic_status LUMEN_MSQUIC_CALL listener_callback(void *raw, const lumen_msquic_listener_event *e) {
        const auto h = static_cast<ListenerHolder *>(raw)->shared_from_this();
        ListenerEvent out;
        out.kind = e->kind == LUMEN_MSQUIC_LISTENER_NEW_CONNECTION ?
                     ListenerEvent::Kind::new_connection :
                     ListenerEvent::Kind::stop_complete;
        out.connection = e->connection;
        if (out.kind == ListenerEvent::Kind::new_connection) {
          out.remote_source = normalize_remote_source(
            e->remote_address_family,
            std::span<const std::uint8_t, 16> {e->remote_address}
          );
        }
        return static_cast<lumen_msquic_status>(h->callback(out));
      }

      static lumen_msquic_status LUMEN_MSQUIC_CALL connection_callback(void *raw, const lumen_msquic_connection_event *e) {
        const auto h = static_cast<ConnectionHolder *>(raw)->shared_from_this();
        ConnectionEvent out;
        switch (e->kind) {
          case LUMEN_MSQUIC_CONNECTION_CONNECTED:
            out.kind = ConnectionEvent::Kind::connected;
            break;
          case LUMEN_MSQUIC_CONNECTION_DATAGRAM_STATE:
            out.kind = ConnectionEvent::Kind::datagram_state_changed;
            break;
          case LUMEN_MSQUIC_CONNECTION_DATAGRAM_RECEIVED:
            out.kind = ConnectionEvent::Kind::datagram_received;
            break;
          case LUMEN_MSQUIC_CONNECTION_DATAGRAM_SEND_COMPLETE:
            out.kind = ConnectionEvent::Kind::datagram_send_complete;
            break;
          case LUMEN_MSQUIC_CONNECTION_PEER_STREAM:
            out.kind = ConnectionEvent::Kind::peer_stream_started;
            break;
          case LUMEN_MSQUIC_CONNECTION_SHUTDOWN_TRANSPORT:
            out.kind = ConnectionEvent::Kind::shutdown_by_transport;
            break;
          case LUMEN_MSQUIC_CONNECTION_SHUTDOWN_PEER:
            out.kind = ConnectionEvent::Kind::shutdown_by_peer;
            break;
          case LUMEN_MSQUIC_CONNECTION_SHUTDOWN_COMPLETE:
            out.kind = ConnectionEvent::Kind::shutdown_complete;
            break;
        }
        out.stream = e->stream;
        out.stream_id = e->stream_id;
        out.send_token = e->send_token;
        out.transport_error = e->error;
        out.maximum_datagram_bytes = e->maximum_datagram_bytes;
        out.datagram_send_enabled = e->datagram_enabled;
        out.resumed = e->resumed;
        out.canceled = e->canceled;
        out.peer_stream_unidirectional = e->peer_stream_unidirectional;
        out.received_bytes = {e->bytes, e->byte_count};
        return static_cast<lumen_msquic_status>(h->callback(out));
      }

      static lumen_msquic_status LUMEN_MSQUIC_CALL stream_callback(void *raw, const lumen_msquic_stream_event *e) {
        const auto h = static_cast<StreamHolder *>(raw)->shared_from_this();
        StreamEvent out;
        out.kind = static_cast<StreamEvent::Kind>(e->kind);
        out.total_buffer_bytes = e->total_buffer_bytes;
        out.send_token = e->send_token;
        out.error = e->error;
        out.canceled = e->canceled;
        std::vector<Buffer> buffers;
        buffers.reserve(e->buffer_count);
        for (std::size_t i = 0; i < e->buffer_count; ++i) {
          buffers.push_back({e->buffers[i].data, e->buffers[i].size});
        }
        out.buffers = buffers;
        return static_cast<lumen_msquic_status>(h->callback(out));
      }

      static std::vector<lumen_msquic_buffer> shim_buffers(std::span<const Buffer> input) {
        std::vector<lumen_msquic_buffer> out;
        out.reserve(input.size());
        for (const auto &b : input) {
          out.push_back({b.data, b.size});
        }
        return out;
      }

      lumen_msquic_shim *shim_ {};
      std::mutex mutex_;
      std::map<Handle, std::shared_ptr<ListenerHolder>> listeners_;
      std::map<Handle, std::shared_ptr<ConnectionHolder>> connections_;
      std::map<Handle, std::shared_ptr<StreamHolder>> streams_;
    };
  }  // namespace
#endif

  std::unique_ptr<MsQuicApi> make_native_msquic_api() {
#if defined(_WIN32) && defined(LUMEN_EXPERIMENTAL_MSQUIC)
    return std::make_unique<ShimMsQuicApi>();
#else
    return {};
#endif
  }
}  // namespace lumen::protocol_v3::quic_server
