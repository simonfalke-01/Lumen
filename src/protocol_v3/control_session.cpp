/**
 * @file src/protocol_v3/control_session.cpp
 * @brief Authenticated protocol-v3 HELLO, pairing, authorization, and START state machine.
 */

#include "control_session.h"
#include "start_mode_contract.h"

#include "../protocol_common/crypto.h"

#include <algorithm>
#include <climits>
#include <map>
#include <openssl/rand.h>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace lumen::protocol_v3::control_session {
  namespace crypto = lumen::protocol_common::crypto;

  struct ResponseCacheCoordinator::SharedState {
    struct Entry {
      std::uint64_t request_id {};
      std::vector<std::uint8_t> request;
      std::shared_ptr<const std::vector<std::uint8_t>> response;
      resource_budget::ResourceBudgetCoordinator::SharedLease budget;
      quic_server::MonotonicClock::time_point completed_at {};
      std::size_t charge {};
    };

    struct Pending {
      std::uint64_t generation {};
      std::uint64_t request_id {};
      std::vector<std::uint8_t> request;
      resource_budget::ResourceBudgetCoordinator::Lease budget;
      std::size_t charge {};
    };

    struct Connection {
      Connection() {
        entries.reserve(ResponseCacheCoordinator::maximum_entries_per_connection);
        pending.reserve(ResponseCacheCoordinator::maximum_entries_per_connection);
      }

      std::uint64_t retired_floor {};
      std::size_t bytes {};
      std::size_t pending_bytes {};
      std::vector<Entry> entries;
      std::vector<Pending> pending;
    };

    static std::optional<std::size_t> charge(
      const std::size_t request_bytes,
      const std::size_t response_bytes
    ) noexcept {
      if (request_bytes > SIZE_MAX - ResponseCacheCoordinator::fixed_entry_charge ||
          response_bytes > SIZE_MAX - ResponseCacheCoordinator::fixed_entry_charge - request_bytes) {
        return std::nullopt;
      }
      return ResponseCacheCoordinator::fixed_entry_charge + request_bytes + response_bytes;
    }

    explicit SharedState(std::shared_ptr<resource_budget::ResourceBudgetCoordinator> shared_budget):
        budget {std::move(shared_budget)} {
    }

    void retire(Connection &connection, const std::vector<Entry>::iterator entry) noexcept {
      connection.retired_floor = std::max(connection.retired_floor, entry->request_id);
      connection.bytes -= std::min(connection.bytes, entry->charge);
      host_bytes -= std::min(host_bytes, entry->charge);
      connection.entries.erase(entry);
    }

    void expire(const quic_server::MonotonicClock::time_point now) noexcept {
      for (auto &[_, connection] : connections) {
        for (auto entry = connection.entries.begin(); entry != connection.entries.end();) {
          if (entry->completed_at + ResponseCacheCoordinator::ttl <= now) {
            retire(connection, entry);
            entry = connection.entries.begin();
          } else {
            ++entry;
          }
        }
      }
    }

    bool retire_oldest(Connection &connection) noexcept {
      if (connection.entries.empty()) {
        return false;
      }
      const auto oldest = std::ranges::min_element(
        connection.entries,
        {},
        [](const auto &entry) {
          return std::pair {entry.completed_at, entry.request_id};
        }
      );
      retire(connection, oldest);
      return true;
    }

    bool retire_oldest_host() noexcept {
      Connection *selected_connection = nullptr;
      std::vector<Entry>::iterator selected_entry;
      std::optional<std::tuple<quic_server::MonotonicClock::time_point, std::uint64_t, std::uint64_t>> selected;
      for (auto &[connection_id, connection] : connections) {
        for (auto entry = connection.entries.begin(); entry != connection.entries.end(); ++entry) {
          const auto candidate = std::tuple {entry->completed_at, entry->request_id, connection_id};
          if (!selected || candidate < *selected) {
            selected = candidate;
            selected_connection = &connection;
            selected_entry = entry;
          }
        }
      }
      if (selected_connection == nullptr) {
        return false;
      }
      retire(*selected_connection, selected_entry);
      return true;
    }

    void cancel(const std::uint64_t connection_id, const std::uint64_t generation) noexcept {
      std::scoped_lock lock {mutex};
      const auto connection = connections.find(connection_id);
      if (connection == connections.end()) {
        return;
      }
      const auto pending = std::ranges::find_if(connection->second.pending, [&](const Pending &entry) {
        return entry.generation == generation;
      });
      if (pending == connection->second.pending.end()) {
        return;
      }
      const auto charge = pending->charge;
      connection->second.pending_bytes -= std::min(connection->second.pending_bytes, charge);
      host_pending_bytes -= std::min(host_pending_bytes, charge);
      connection->second.pending.erase(pending);
    }

    std::shared_ptr<resource_budget::ResourceBudgetCoordinator> budget;
    std::mutex mutex;
    std::map<std::uint64_t, Connection> connections;
    std::size_t host_bytes {};
    std::size_t host_pending_bytes {};
    std::uint64_t next_generation {1};
  };

  ResponseCacheCoordinator::Reservation::Reservation(
    std::shared_ptr<SharedState> state,
    const std::uint64_t connection_id,
    const std::uint64_t generation
  ) noexcept:
      state_ {std::move(state)},
      connection_id_ {connection_id},
      generation_ {generation} {
  }

  ResponseCacheCoordinator::Reservation::~Reservation() {
    cancel();
  }

  ResponseCacheCoordinator::Reservation::Reservation(Reservation &&other) noexcept:
      state_ {std::exchange(other.state_, {})},
      connection_id_ {std::exchange(other.connection_id_, 0)},
      generation_ {std::exchange(other.generation_, 0)} {
  }

  ResponseCacheCoordinator::Reservation &ResponseCacheCoordinator::Reservation::operator=(
    Reservation &&other
  ) noexcept {
    if (this != &other) {
      cancel();
      state_ = std::exchange(other.state_, {});
      connection_id_ = std::exchange(other.connection_id_, 0);
      generation_ = std::exchange(other.generation_, 0);
    }
    return *this;
  }

  ResponseCacheCoordinator::Reservation::operator bool() const noexcept {
    return state_ && connection_id_ != 0 && generation_ != 0;
  }

  void ResponseCacheCoordinator::Reservation::cancel() noexcept {
    if (state_) {
      state_->cancel(connection_id_, generation_);
      state_.reset();
      connection_id_ = 0;
      generation_ = 0;
    }
  }

  ResponseCacheCoordinator::ResponseCacheCoordinator(
    std::shared_ptr<resource_budget::ResourceBudgetCoordinator> resource_budget
  ):
      state_ {std::make_shared<SharedState>(std::move(resource_budget))} {
    if (!state_->budget) {
      throw std::invalid_argument {"v3 response cache resource budget"};
    }
  }

  ResponseCacheCoordinator::~ResponseCacheCoordinator() = default;

  ResponseCacheCoordinator::Admission ResponseCacheCoordinator::reserve(
    const std::uint64_t connection_id,
    const std::uint64_t request_id,
    const std::span<const std::uint8_t> request,
    const std::size_t worst_case_response_bytes,
    const quic_server::MonotonicClock::time_point now
  ) {
    Admission admission;
    std::vector<std::uint8_t> retained_request {request.begin(), request.end()};
    const auto reserved_charge = SharedState::charge(retained_request.capacity(), worst_case_response_bytes);
    if (connection_id == 0 || request_id == 0 || request.empty() || !reserved_charge ||
        *reserved_charge > maximum_bytes_per_connection) {
      return admission;
    }

    std::scoped_lock lock {state_->mutex};
    state_->expire(now);
    auto &connection = state_->connections[connection_id];
    if (request_id <= connection.retired_floor) {
      admission.decision = Decision::retired;
      return admission;
    }
    if (const auto retained = std::ranges::find_if(connection.entries, [&](const SharedState::Entry &entry) {
          return entry.request_id == request_id;
        }); retained != connection.entries.end()) {
      admission.decision = std::ranges::equal(retained->request, request) ?
                             Decision::replay :
                             Decision::request_id_conflict;
      admission.replay = admission.decision == Decision::replay ? retained->response : nullptr;
      return admission;
    }
    if (const auto pending = std::ranges::find_if(connection.pending, [&](const SharedState::Pending &entry) {
          return entry.request_id == request_id;
        }); pending != connection.pending.end()) {
      admission.decision = std::ranges::equal(pending->request, request) ?
                             Decision::in_progress :
                             Decision::request_id_conflict;
      return admission;
    }

    while ((connection.entries.size() + connection.pending.size() >= maximum_entries_per_connection ||
            connection.bytes + connection.pending_bytes > maximum_bytes_per_connection - *reserved_charge) &&
           state_->retire_oldest(connection)) {
    }
    if (connection.entries.size() + connection.pending.size() >= maximum_entries_per_connection ||
        connection.bytes + connection.pending_bytes > maximum_bytes_per_connection - *reserved_charge) {
      return admission;
    }
    while (state_->host_bytes + state_->host_pending_bytes > maximum_bytes_host - *reserved_charge &&
           state_->retire_oldest_host()) {
    }
    if (state_->host_bytes + state_->host_pending_bytes > maximum_bytes_host - *reserved_charge ||
        state_->next_generation == UINT64_MAX) {
      return admission;
    }

    std::optional<resource_budget::ResourceBudgetCoordinator::Lease> budget;
    while (!(budget = state_->budget->reserve(
               resource_budget::ResourceClass::cached_responses,
               *reserved_charge
             ))) {
      if (!state_->retire_oldest_host()) {
        return admission;
      }
    }

    const auto generation = state_->next_generation++;
    connection.pending.push_back(SharedState::Pending {
      .generation = generation,
      .request_id = request_id,
      .request = std::move(retained_request),
      .budget = std::move(*budget),
      .charge = *reserved_charge,
    });
    connection.pending_bytes += *reserved_charge;
    state_->host_pending_bytes += *reserved_charge;
    admission.decision = Decision::reserved;
    admission.reservation = Reservation {state_, connection_id, generation};
    return admission;
  }

  bool ResponseCacheCoordinator::commit(
    Reservation &&reservation,
    std::shared_ptr<const std::vector<std::uint8_t>> response,
    const quic_server::MonotonicClock::time_point now
  ) {
    if (!reservation || !response || response->empty() || reservation.state_ != state_) {
      return false;
    }
    std::scoped_lock lock {state_->mutex};
    const auto connection = state_->connections.find(reservation.connection_id_);
    if (connection == state_->connections.end()) {
      return false;
    }
    const auto pending = std::ranges::find_if(connection->second.pending, [&](const SharedState::Pending &entry) {
      return entry.generation == reservation.generation_;
    });
    if (pending == connection->second.pending.end()) {
      return false;
    }
    const auto actual_charge = SharedState::charge(pending->request.capacity(), response->capacity());
    if (!actual_charge || *actual_charge > pending->charge) {
      return false;
    }

    const auto reserved_charge = pending->charge;
    const auto request_id = pending->request_id;
    auto request = std::move(pending->request);
    auto budget = std::move(pending->budget);
    if (!budget.resize(*actual_charge)) {
      return false;
    }
    auto shared_budget = state_->budget->adopt_shared(response, std::move(budget));
    if (!shared_budget) {
      return false;
    }
    connection->second.pending_bytes -= std::min(connection->second.pending_bytes, reserved_charge);
    state_->host_pending_bytes -= std::min(state_->host_pending_bytes, reserved_charge);
    connection->second.pending.erase(pending);
    connection->second.entries.push_back(SharedState::Entry {
      .request_id = request_id,
      .request = std::move(request),
      .response = std::move(response),
      .budget = std::move(*shared_budget),
      .completed_at = now,
      .charge = *actual_charge,
    });
    connection->second.bytes += *actual_charge;
    state_->host_bytes += *actual_charge;
    reservation.state_.reset();
    reservation.connection_id_ = 0;
    reservation.generation_ = 0;
    return true;
  }

  void ResponseCacheCoordinator::cancel(Reservation &&reservation) noexcept {
    reservation.cancel();
  }

  void ResponseCacheCoordinator::disconnect(const std::uint64_t connection_id) noexcept {
    std::scoped_lock lock {state_->mutex};
    const auto connection = state_->connections.find(connection_id);
    if (connection == state_->connections.end()) {
      return;
    }
    state_->host_bytes -= std::min(state_->host_bytes, connection->second.bytes);
    state_->host_pending_bytes -= std::min(state_->host_pending_bytes, connection->second.pending_bytes);
    state_->connections.erase(connection);
  }

  namespace {
    using Map = cbor::Value::Map;
    using Bytes = cbor::Value::Bytes;

    constexpr std::string_view pair_client_domain {"lumen/3 pair client\0", 20};
    constexpr std::string_view pair_host_domain {"lumen/3 pair host\0", 18};
    constexpr std::string_view auth_client_domain {"lumen/3 auth client\0", 20};
    constexpr std::string_view auth_host_domain {"lumen/3 auth host\0", 18};

    std::size_t worst_case_response_bytes(
      const std::uint16_t message_type,
      const std::size_t request_bytes
    ) noexcept {
      switch (message_type) {
        case 0x0100:  // START_RESPONSE may carry codec initialization.
        case 0x0200:  // APPLICATION_LIST_RESPONSE may carry a bounded page.
          return request_bytes + ResponseCacheCoordinator::fixed_entry_charge <
                  ResponseCacheCoordinator::maximum_bytes_per_connection ?
                   ResponseCacheCoordinator::maximum_bytes_per_connection - request_bytes -
                     ResponseCacheCoordinator::fixed_entry_charge :
                   0;
        default:
          return 64U * 1024U;
      }
    }

    [[noreturn]] void close_with(
      const quic_server::ApplicationCloseCode code,
      const std::string_view message
    ) {
      throw quic_server::ApplicationCloseError {code, std::string {message}};
    }

    template<std::size_t Size>
    bool nonzero(const std::array<std::uint8_t, Size> &value) noexcept {
      return std::ranges::any_of(value, [](const auto byte) { return byte != 0; });
    }

    const cbor::Value *field(const Map &map, const std::uint64_t key) noexcept {
      const auto found = std::lower_bound(map.begin(), map.end(), key, [](const auto &entry, const auto wanted) {
        return entry.first < wanted;
      });
      return found != map.end() && found->first == key ? &found->second : nullptr;
    }

    bool exact_keys(const Map &map, const std::uint64_t first, const std::uint64_t last) noexcept {
      if (map.size() != last - first + 1) {
        return false;
      }
      for (std::size_t index = 0; index < map.size(); ++index) {
        if (map[index].first != first + index) {
          return false;
        }
      }
      return true;
    }

    std::optional<std::uint64_t> unsigned_field(const Map &map, const std::uint64_t key) noexcept {
      const auto *value = field(map, key);
      return value ? std::get_if<std::uint64_t>(&value->storage) ?
                       std::optional {*std::get_if<std::uint64_t>(&value->storage)} :
                       std::nullopt :
                     std::nullopt;
    }

    std::optional<bool> bool_field(const Map &map, const std::uint64_t key) noexcept {
      const auto *value = field(map, key);
      if (!value) {
        return std::nullopt;
      }
      const auto *boolean = std::get_if<bool>(&value->storage);
      return boolean ? std::optional {*boolean} : std::nullopt;
    }

    const Map *map_field(const Map &map, const std::uint64_t key) noexcept {
      const auto *value = field(map, key);
      return value ? std::get_if<Map>(&value->storage) : nullptr;
    }

    const cbor::Value::Array *array_field(const Map &map, const std::uint64_t key) noexcept {
      const auto *value = field(map, key);
      return value ? std::get_if<cbor::Value::Array>(&value->storage) : nullptr;
    }

    const std::string *text_field(const Map &map, const std::uint64_t key) noexcept {
      const auto *value = field(map, key);
      return value ? std::get_if<std::string>(&value->storage) : nullptr;
    }

    bool is_null(const Map &map, const std::uint64_t key) noexcept {
      const auto *value = field(map, key);
      return value && std::holds_alternative<cbor::Null>(value->storage);
    }

    template<std::size_t Size>
    std::optional<std::array<std::uint8_t, Size>> fixed_field(
      const Map &map,
      const std::uint64_t key
    ) noexcept {
      const auto *value = field(map, key);
      const auto *bytes = value ? std::get_if<Bytes>(&value->storage) : nullptr;
      if (!bytes || bytes->size() != Size) {
        return std::nullopt;
      }
      std::array<std::uint8_t, Size> output;
      std::copy(bytes->begin(), bytes->end(), output.begin());
      return output;
    }

    template<std::size_t Size>
    Bytes bytes(const std::array<std::uint8_t, Size> &value) {
      return {value.begin(), value.end()};
    }

    cbor::Value unsigned_value(const std::uint64_t value) {
      return cbor::Value {value};
    }

    Map decode_map(const quic_server::ControlFrame &frame) {
      const auto decoded = cbor::decode(frame.bytes.subspan(quic_server::control_header_bytes));
      if (!decoded) {
        close_with(quic_server::ApplicationCloseCode::malformed, "v3 control CBOR");
      }
      const auto *map = std::get_if<Map>(&decoded.value->storage);
      if (!map) {
        close_with(quic_server::ApplicationCloseCode::malformed, "v3 control map");
      }
      return *map;
    }

    std::vector<std::uint8_t> encode_frame(
      const std::uint16_t type,
      const std::uint64_t request_id,
      const std::uint8_t flags,
      const Map &fields
    ) {
      const auto payload = cbor::encode(cbor::Value {fields});
      if (!payload || payload.bytes.empty() || payload.bytes.size() > quic_server::maximum_control_payload_bytes) {
        throw std::runtime_error {"v3 control encode"};
      }
      std::vector<std::uint8_t> output {'U', 'L', 'C', '3', 3, flags};
      output.reserve(quic_server::control_header_bytes + payload.bytes.size());
      const auto append = [&output](const std::uint64_t value, std::size_t count) {
        while (count-- > 0) {
          output.push_back(static_cast<std::uint8_t>(value >> (count * 8U)));
        }
      };
      append(type, 2);
      append(request_id, 8);
      append(payload.bytes.size(), 4);
      append(0, 4);
      output.insert(output.end(), payload.bytes.begin(), payload.bytes.end());
      return output;
    }

    std::vector<std::uint8_t> transcript(
      const std::string_view domain,
      const Bytes32 &spki,
      const std::initializer_list<std::span<const std::uint8_t>> frames
    ) {
      std::size_t size = domain.size() + spki.size();
      for (const auto frame : frames) {
        size += 4 + frame.size();
      }
      std::vector<std::uint8_t> output;
      output.reserve(size);
      output.insert(output.end(), domain.begin(), domain.end());
      output.insert(output.end(), spki.begin(), spki.end());
      for (const auto frame : frames) {
        const auto length = static_cast<std::uint32_t>(frame.size());
        output.push_back(static_cast<std::uint8_t>(length >> 24U));
        output.push_back(static_cast<std::uint8_t>(length >> 16U));
        output.push_back(static_cast<std::uint8_t>(length >> 8U));
        output.push_back(static_cast<std::uint8_t>(length));
        output.insert(output.end(), frame.begin(), frame.end());
      }
      return output;
    }

    Identifier derived_id(const Bytes32 &public_key) {
      const auto digest = crypto::sha256(public_key);
      if (!digest) {
        throw std::runtime_error {"v3 identity digest"};
      }
      Identifier output;
      std::copy_n(digest->begin(), output.size(), output.begin());
      return output;
    }

    Map without_last_signature(Map fields, const std::uint64_t key) {
      if (fields.empty() || fields.back().first != key) {
        throw std::runtime_error {"v3 signature field"};
      }
      fields.pop_back();
      return fields;
    }

    bool valid_profile_array(const cbor::Value::Array &profiles) noexcept {
      if (profiles.empty() || profiles.size() > 2) {
        return false;
      }
      std::uint64_t previous = 0;
      for (const auto &profile : profiles) {
        const auto *value = std::get_if<std::uint64_t>(&profile.storage);
        if (!value || *value < 1 || *value > 2 || *value <= previous) {
          return false;
        }
        previous = *value;
      }
      return true;
    }

    bool valid_start_request(const Map &fields, const std::uint16_t datagram_maximum) noexcept {
      if (!exact_keys(fields, 1, 18) || datagram_maximum < quic_server::maximum_semantic_datagram_bytes) {
        return false;
      }
      const auto intent = fixed_field<16>(fields, 1);
      const auto application = unsigned_field(fields, 2);
      const auto profile = unsigned_field(fields, 3);
      const auto width = unsigned_field(fields, 4);
      const auto height = unsigned_field(fields, 5);
      const auto refresh_numerator = unsigned_field(fields, 6);
      const auto refresh_denominator = unsigned_field(fields, 7);
      const auto bitrate = unsigned_field(fields, 8);
      const auto semantic_cap = unsigned_field(fields, 12);
      const auto trace = fixed_field<16>(fields, 13);
      const auto resume = bool_field(fields, 16);
      const auto host_audio = bool_field(fields, 18);
      const auto *codecs = array_field(fields, 9);
      const auto *audio = array_field(fields, 10);
      const auto *hdr = array_field(fields, 14);
      const auto *presentation = array_field(fields, 15);
      const auto mode_shape = width && height && refresh_numerator && refresh_denominator ?
                                start_mode::admit_shape({*width, *height, *refresh_numerator, *refresh_denominator}) :
                                start_mode::AdmissionError::dimensions;
      return intent && nonzero(*intent) && application && *application <= UINT32_MAX && profile &&
             (*profile == 1 || *profile == 2) && mode_shape == start_mode::AdmissionError::none &&
             bitrate && *bitrate >= 1'000 && *bitrate <= 500'000 && semantic_cap &&
             *semantic_cap == quic_server::maximum_semantic_datagram_bytes && trace && nonzero(*trace) && resume && host_audio &&
             codecs && !codecs->empty() && codecs->size() <= 16 && audio && !audio->empty() && audio->size() <= 6 &&
             (is_null(fields, 11) || map_field(fields, 11)) && hdr && hdr->size() <= 16 &&
             presentation && !presentation->empty() && presentation->size() <= 3 && map_field(fields, 17);
    }

  }  // namespace

  struct ControlSession::Impl {
    enum class State {
      hello,
      authorization,
      ready,
      streaming,
      closed,
    };

    struct OutstandingHostRequest {
      std::uint16_t request_type {};
      std::uint16_t acknowledgement_type {};
      Identifier session_id {};
      std::uint32_t generation {};
      std::shared_ptr<const std::vector<std::uint8_t>> encoded;
      quic_server::MonotonicClock::time_point deadline {};
    };

    Impl(
      quic_server::ConnectionContext live_connection,
      Config policy,
      Random &random_source,
      HostIdentity &host_identity,
      AuthorizationStore &authorization_store,
      NonceRegistry &nonce_registry,
      PairingAdmission &pairing_limiter,
      ConnectionAuthorityRegistry &authority_registry,
      SessionBackend &session_backend
    ):
        connection {std::move(live_connection)},
        config {std::move(policy)},
        random {random_source},
        identity {host_identity},
        authorization {authorization_store},
        nonces {nonce_registry},
        pairing_admission {pairing_limiter},
        authorities {authority_registry},
        backend {session_backend},
        datagram_maximum {connection.maximum_datagram_bytes} {
      spki = connection.leaf_spki_sha256;
      phase_deadline = connection.connected_at + config.server_hello_timeout;
      if (!config.response_cache || !nonzero(spki) || identity.host_id() != derived_id(identity.public_key()) ||
          config.server_hello_timeout != std::chrono::seconds {2} ||
          config.authorization_request_timeout != std::chrono::seconds {3} ||
          config.signed_response_timeout != std::chrono::seconds {2} ||
          config.start_response_timeout != std::chrono::seconds {10} ||
          config.attach_response_timeout != std::chrono::seconds {3} ||
          config.configuration_ack_timeout != std::chrono::seconds {3} ||
          config.stop_response_timeout != std::chrono::seconds {2} ||
          config.teardown_timeout != std::chrono::seconds {5} ||
          config.authenticated_idle_timeout != std::chrono::seconds {120}) {
        throw std::invalid_argument {"invalid v3 host identity"};
      }
    }

    quic_server::MonotonicClock::time_point begin_control(
      const quic_server::ControlFrame &frame
    ) noexcept {
      const auto now = quic_server::MonotonicClock::now();
      const bool begins_expected_phase =
        (state == State::hello && frame.message_type == 0x0001) ||
        (state == State::authorization && (frame.message_type == 0x0003 || frame.message_type == 0x0010));
      if (begins_expected_phase && phase_deadline != quic_server::MonotonicClock::time_point {} &&
          now <= phase_deadline) {
        phase_deadline = {};
      }
      if ((frame.flags & 1U) != 0) {
        if (const auto outstanding = outstanding_host_requests.find(frame.request_id);
            outstanding != outstanding_host_requests.end()) {
          operation_deadline = outstanding->second.deadline;
          return application_deadline();
        }
      }
      const auto timeout = [&]() {
        switch (frame.message_type) {
          case 0x0001:
            return config.server_hello_timeout;
          case 0x0003:
          case 0x0010:
            return config.signed_response_timeout;
          case 0x0100:
            return config.start_response_timeout;
          case 0x0102:
            return config.attach_response_timeout;
          case 0x0130:
            return config.stop_response_timeout;
          default:
            return config.authenticated_idle_timeout;
        }
      }();
      operation_deadline = now + timeout;
      return application_deadline();
    }

    quic_server::MonotonicClock::time_point application_deadline() const noexcept {
      auto deadline = quic_server::MonotonicClock::time_point::max();
      const auto include = [&](const quic_server::MonotonicClock::time_point candidate) {
        if (candidate != quic_server::MonotonicClock::time_point {}) {
          deadline = std::min(deadline, candidate);
        }
      };
      include(phase_deadline);
      include(operation_deadline);
      include(authenticated_idle_deadline);
      for (const auto &[_, request] : outstanding_host_requests) {
        include(request.deadline);
      }
      return deadline;
    }

    void finish_control() {
      const auto now = quic_server::MonotonicClock::now();
      if (operation_deadline != quic_server::MonotonicClock::time_point {} && now > operation_deadline) {
        operation_deadline = {};
        close_with(quic_server::ApplicationCloseCode::phase_timeout, "v3 response deadline expired");
      }
      operation_deadline = {};
      if (state == State::ready || state == State::streaming) {
        phase_deadline = {};
        authenticated_idle_deadline = now + config.authenticated_idle_timeout;
      }
    }

    void record_authenticated_activity() noexcept {
      if (state == State::ready || state == State::streaming) {
        authenticated_idle_deadline =
          quic_server::MonotonicClock::now() + config.authenticated_idle_timeout;
      }
    }

    std::shared_ptr<const std::vector<std::uint8_t>> response(
      const quic_server::ControlFrame &frame,
      const std::uint16_t type,
      Map fields
    ) {
      auto encoded = std::make_shared<const std::vector<std::uint8_t>>(
        encode_frame(type, frame.request_id, 1, fields)
      );
      return encoded;
    }

    std::vector<std::shared_ptr<const std::vector<std::uint8_t>>> process(
      const quic_server::ControlFrame &frame
    ) {
      if (phase_deadline != quic_server::MonotonicClock::time_point {} &&
          quic_server::MonotonicClock::now() > phase_deadline) {
        close_with(quic_server::ApplicationCloseCode::phase_timeout, "v3 request phase expired");
      }
      if (state == State::closed || frame.request_id == 0) {
        close_with(quic_server::ApplicationCloseCode::malformed, "invalid v3 request");
      }
      if ((frame.flags & 1U) != 0) {
        return configuration_acknowledgement(frame);
      }
      if (frame.flags != 0 || frame.request_id % 2 == 0) {
        close_with(quic_server::ApplicationCloseCode::malformed, "invalid v3 client request authority");
      }
      auto admission = config.response_cache->reserve(
        connection.connection_id,
        frame.request_id,
        frame.bytes,
        worst_case_response_bytes(frame.message_type, frame.bytes.size()),
        quic_server::MonotonicClock::now()
      );
      switch (admission.decision) {
        case ResponseCacheCoordinator::Decision::replay:
          return {std::move(admission.replay)};
        case ResponseCacheCoordinator::Decision::in_progress:
          throw std::runtime_error {"v3 request already in progress"};
        case ResponseCacheCoordinator::Decision::request_id_conflict:
        case ResponseCacheCoordinator::Decision::retired:
          throw ResponseCacheError {ResponseCacheError::Kind::request_id_conflict};
        case ResponseCacheCoordinator::Decision::resource_limit:
          throw ResponseCacheError {ResponseCacheError::Kind::resource_limit};
        case ResponseCacheCoordinator::Decision::reserved:
          break;
      }
      if (!admission.reservation) {
        throw std::runtime_error {"v3 response cache reservation"};
      }
      auto reservation = std::move(*admission.reservation);
      const auto expected = last_request_id == 0 ? 1 : last_request_id + 2;
      if (frame.request_id != expected || frame.request_id < last_request_id) {
        close_with(quic_server::ApplicationCloseCode::malformed, "v3 request sequence");
      }
      last_request_id = frame.request_id;
      const auto fields = decode_map(frame);
      std::vector<std::shared_ptr<const std::vector<std::uint8_t>>> output;
      try {
        switch (state) {
          case State::hello:
            output = {hello(frame, fields)};
            break;
          case State::authorization:
            output = pairing ? std::vector {pair(frame, fields)} :
                               std::vector {authenticate(frame, fields)};
            break;
          case State::ready:
            output = frame.message_type == 0x0100 ? start(frame, fields) :
                                                    authenticated_control(frame, fields);
            break;
          case State::streaming:
            if (frame.message_type == 0x0100 && client_record && !backend.owned_session(*client_record)) {
              session_id.reset();
              outstanding_host_requests.clear();
              completed_host_acknowledgements.clear();
              media_started = false;
              state = State::ready;
              output = start(frame, fields);
            } else {
              output = authenticated_control(frame, fields);
            }
            break;
          case State::closed:
            close_with(quic_server::ApplicationCloseCode::malformed, "unsupported v3 request state");
        }
        if (output.empty() || !output.front() ||
            !config.response_cache->commit(
              std::move(reservation),
              output.front(),
              quic_server::MonotonicClock::now()
            )) {
          throw ResponseCacheError {ResponseCacheError::Kind::resource_limit};
        }
        return output;
      } catch (...) {
        config.response_cache->cancel(std::move(reservation));
        throw;
      }
    }

    std::shared_ptr<const std::vector<std::uint8_t>> hello(
      const quic_server::ControlFrame &frame,
      const Map &fields
    ) {
      if (frame.message_type != 0x0001 || !exact_keys(fields, 1, 8)) {
        close_with(quic_server::ApplicationCloseCode::malformed, "invalid v3 CLIENT_HELLO");
      }
      if (unsigned_field(fields, 1) != 3 || unsigned_field(fields, 2) != 3) {
        close_with(quic_server::ApplicationCloseCode::version_or_alpn, "unsupported v3 version");
      }
      const auto nonce = fixed_field<32>(fields, 3);
      const auto capabilities = unsigned_field(fields, 4);
      const auto *profiles = array_field(fields, 5);
      const auto client = fixed_field<16>(fields, 6);
      const auto invitation = fixed_field<16>(fields, 7);
      const auto attempt = fixed_field<16>(fields, 8);
      if (!nonce || !nonzero(*nonce) || !capabilities || (*capabilities & ~config.capabilities) != 0 ||
          !profiles || !valid_profile_array(*profiles) || !attempt || !nonzero(*attempt) ||
          (client.has_value() == invitation.has_value()) ||
          (!client && !is_null(fields, 6)) || (!invitation && !is_null(fields, 7))) {
        close_with(quic_server::ApplicationCloseCode::malformed, "invalid v3 CLIENT_HELLO fields");
      }
      const auto now = quic_server::MonotonicClock::now();
      if (!pairing_admission.admit_hello(connection.remote_source, *attempt, now)) {
        close_with(quic_server::ApplicationCloseCode::abuse_limit, "v3 CLIENT_HELLO admission limit");
      }
      if (!nonces.claim(connection.remote_source, *attempt, *nonce, now)) {
        close_with(quic_server::ApplicationCloseCode::authentication_failed, "replayed v3 CLIENT_HELLO");
      }
      if (!random.fill(server_nonce) || !nonzero(server_nonce)) {
        throw std::runtime_error {"v3 server nonce"};
      }
      pairing = invitation.has_value();
      claimed_client_id = client;
      invitation_id = invitation;
      attempt_id = *attempt;
      client_hello.assign(frame.bytes.begin(), frame.bytes.end());
      Map response_fields {
        {1, unsigned_value(3)},
        {2, bytes(server_nonce)},
        {3, bytes(identity.host_id())},
        {4, bytes(identity.public_key())},
        {5, bytes(spki)},
        {6, unsigned_value(config.capabilities)},
        {7, unsigned_value(quic_server::maximum_semantic_datagram_bytes)},
        {8, bytes(attempt_id)},
      };
      auto encoded = response(frame, 0x0002, response_fields);
      server_hello = *encoded;
      state = State::authorization;
      phase_deadline =
        quic_server::MonotonicClock::now() + config.authorization_request_timeout;
      return encoded;
    }

    std::shared_ptr<const std::vector<std::uint8_t>> pair(
      const quic_server::ControlFrame &frame,
      const Map &fields
    ) {
      if (frame.message_type != 0x0010 || !exact_keys(fields, 1, 9)) {
        close_with(quic_server::ApplicationCloseCode::malformed, "invalid v3 PAIR_REQUEST");
      }
      const auto id = fixed_field<16>(fields, 1);
      const auto token = fixed_field<32>(fields, 2);
      const auto invitation_hash = fixed_field<32>(fields, 3);
      const auto attempt = fixed_field<16>(fields, 4);
      const auto client_id = fixed_field<16>(fields, 5);
      const auto client_public = fixed_field<32>(fields, 6);
      const auto *name = text_field(fields, 7);
      const auto permissions = unsigned_field(fields, 8);
      const auto signature = fixed_field<64>(fields, 9);
      if (!id || !token || !nonzero(*token) || !attempt) {
        close_with(quic_server::ApplicationCloseCode::malformed, "invalid v3 PAIR_REQUEST fields");
      }
      if (id != invitation_id || *attempt != attempt_id) {
        close_with(quic_server::ApplicationCloseCode::authentication_failed, "v3 pairing authority mismatch");
      }
      if (!pairing_admission.admit(connection.remote_source, *id, quic_server::MonotonicClock::now())) {
        close_with(quic_server::ApplicationCloseCode::abuse_limit, "v3 pairing admission limit");
      }
      if (!invitation_hash || !nonzero(*invitation_hash) || !client_id ||
          !client_public || derived_id(*client_public) != *client_id || !name || name->empty() ||
          name->size() > 64 || !cbor::is_valid_utf8(*name) || !permissions ||
          (*permissions & ~defined_permission_mask) != 0 || !signature) {
        close_with(quic_server::ApplicationCloseCode::malformed, "invalid v3 pairing fields");
      }
      const auto unsigned_request = encode_frame(
        frame.message_type,
        frame.request_id,
        0,
        without_last_signature(fields, 9)
      );
      const auto client_transcript = transcript(
        pair_client_domain,
        spki,
        {client_hello, server_hello, unsigned_request}
      );
      if (!crypto::ed25519_verify(*client_public, client_transcript, *signature)) {
        close_with(quic_server::ApplicationCloseCode::authentication_failed, "invalid v3 client pairing signature");
      }
      PairingClaim claim {
        .invitation_id = *id,
        .invitation_token = *token,
        .invitation_sha256 = *invitation_hash,
        .pair_attempt_id = *attempt,
        .client_id = *client_id,
        .client_public_key = *client_public,
        .display_name = *name,
        .requested_permissions = *permissions,
        .approved_permissions = *permissions & config.default_pairing_permissions,
      };
      auto stored = authorization.consume_invitation(claim);
      if (!stored || stored->client_id != *client_id || stored->public_key != *client_public ||
          stored->permissions == 0 || (stored->permissions & ~claim.approved_permissions) != 0 ||
          stored->generation == 0) {
        close_with(quic_server::ApplicationCloseCode::authentication_failed, "v3 invitation rejected");
      }
      client_record = *stored;
      const auto authority = authorities.claim(stored->client_id, connection.connection_id, true);
      if (!authority) {
        close_with(quic_server::ApplicationCloseCode::unauthorized, "v3 connection authority rejected");
      }
      authority_generation = authority->generation;
      if (authority->replaced_connection_id) {
        backend.revoke_connection(*authority->replaced_connection_id);
      }
      Map response_fields {
        {1, unsigned_value(0)},
        {2, bytes(identity.host_id())},
        {3, bytes(identity.public_key())},
        {4, bytes(stored->client_id)},
        {5, unsigned_value(stored->permissions)},
        {6, unsigned_value(3)},
        {7, bytes(attempt_id)},
        {8, unsigned_value(stored->generation)},
      };
      const auto unsigned_response = encode_frame(0x0011, frame.request_id, 1, response_fields);
      const auto host_transcript = transcript(
        pair_host_domain,
        spki,
        {client_hello, server_hello, frame.bytes, unsigned_response}
      );
      const auto host_signature = identity.sign(host_transcript);
      if (!host_signature) {
        throw std::runtime_error {"v3 host pairing signature"};
      }
      response_fields.emplace_back(9, bytes(*host_signature));
      state = State::ready;
      return response(frame, 0x0011, std::move(response_fields));
    }

    std::shared_ptr<const std::vector<std::uint8_t>> authenticate(
      const quic_server::ControlFrame &frame,
      const Map &fields
    ) {
      if (frame.message_type != 0x0003 || !exact_keys(fields, 1, 4)) {
        close_with(quic_server::ApplicationCloseCode::malformed, "invalid v3 CLIENT_AUTH");
      }
      const auto client_id = fixed_field<16>(fields, 1);
      const auto attempt = fixed_field<16>(fields, 2);
      const auto replace = bool_field(fields, 3);
      const auto signature = fixed_field<64>(fields, 4);
      if (!client_id || client_id != claimed_client_id || !attempt || *attempt != attempt_id ||
          !replace || !signature) {
        close_with(quic_server::ApplicationCloseCode::authentication_failed, "invalid v3 auth fields");
      }
      const auto record = authorization.paired_client(*client_id);
      if (!record || record->client_id != *client_id || derived_id(record->public_key) != *client_id ||
          record->permissions == 0 || (record->permissions & ~defined_permission_mask) != 0 ||
          record->generation == 0) {
        close_with(quic_server::ApplicationCloseCode::authentication_failed, "unknown v3 client");
      }
      const auto unsigned_request = encode_frame(
        frame.message_type,
        frame.request_id,
        0,
        without_last_signature(fields, 4)
      );
      const auto client_transcript = transcript(
        auth_client_domain,
        spki,
        {client_hello, server_hello, unsigned_request}
      );
      if (!crypto::ed25519_verify(record->public_key, client_transcript, *signature)) {
        close_with(quic_server::ApplicationCloseCode::authentication_failed, "invalid v3 client auth signature");
      }
      client_record = *record;
      const auto authority = authorities.claim(record->client_id, connection.connection_id, *replace);
      if (!authority) {
        close_with(quic_server::ApplicationCloseCode::unauthorized, "v3 connection replacement rejected");
      }
      authority_generation = authority->generation;
      if (authority->replaced_connection_id) {
        backend.revoke_connection(*authority->replaced_connection_id);
      }
      const auto owned_session = backend.owned_session(*record);
      Map response_fields {
        {1, unsigned_value(0)},
        {2, bytes(record->client_id)},
        {3, unsigned_value(record->permissions)},
        {4, unsigned_value(*authority_generation)},
        {5, owned_session ? cbor::Value {bytes(*owned_session)} : cbor::Value {cbor::Null {}}},
        {6, bytes(attempt_id)},
      };
      const auto unsigned_response = encode_frame(0x0004, frame.request_id, 1, response_fields);
      const auto host_transcript = transcript(
        auth_host_domain,
        spki,
        {client_hello, server_hello, frame.bytes, unsigned_response}
      );
      const auto host_signature = identity.sign(host_transcript);
      if (!host_signature) {
        throw std::runtime_error {"v3 host auth signature"};
      }
      response_fields.emplace_back(7, bytes(*host_signature));
      state = State::ready;
      return response(frame, 0x0004, std::move(response_fields));
    }

    std::vector<std::shared_ptr<const std::vector<std::uint8_t>>> start(
      const quic_server::ControlFrame &frame,
      const Map &fields
    ) {
      if (frame.message_type != 0x0100 || !valid_start_request(fields, datagram_maximum)) {
        close_with(quic_server::ApplicationCloseCode::malformed, "invalid v3 START");
      }
      if (!client_record || (client_record->permissions & start_permission) == 0) {
        close_with(quic_server::ApplicationCloseCode::unauthorized, "unauthorized v3 START");
      }
      const auto request_intent = fixed_field<16>(fields, 1);
      if (!request_intent) {
        close_with(quic_server::ApplicationCloseCode::malformed, "missing v3 START intent");
      }
      auto authority_lease = current_authority_lease();
      if (!authority_lease) {
        close_with(quic_server::ApplicationCloseCode::unauthorized, "stale v3 START authority");
      }
      auto result = backend.start(
        *client_record,
        fields,
        connection.connection_id,
        datagram_maximum
      );
      if (!result) {
        const auto status = result.error();
        if (status == 0 || status > 12) {
          throw std::runtime_error {"invalid v3 START failure status"};
        }
        Map failed {
          {1, unsigned_value(status)}, {2, bytes(*request_intent)},
        };
        for (std::uint64_t key = 3; key <= 23; ++key) {
          failed.emplace_back(key, key == 19 ? cbor::Value {cbor::Value::Array {}} : cbor::Value {cbor::Null {}});
        }
        return {response(frame, 0x0101, std::move(failed))};
      }
      if (outstanding_host_requests.size() + result->host_requests.size() > 32) {
        close_with(quic_server::ApplicationCloseCode::resource_limit, "v3 host request limit");
      }
      if (!nonzero(result->session_id) || !exact_keys(result->response_fields, 2, 23) ||
          (!result->replay_requires_attach &&
           (result->host_requests.size() < 2 || result->host_requests.size() > 3)) ||
          (result->replay_requires_attach && !result->host_requests.empty())) {
        throw std::runtime_error {"v3 START failed"};
      }
      const auto response_session = fixed_field<16>(result->response_fields, 3);
      const auto response_intent = fixed_field<16>(result->response_fields, 2);
      if (!response_session || *response_session != result->session_id ||
          !response_intent || response_intent != request_intent ||
          unsigned_field(result->response_fields, 11) != quic_server::maximum_semantic_datagram_bytes) {
        throw std::runtime_error {"invalid v3 START selection"};
      }
      Map response_fields {{1, unsigned_value(0)}};
      response_fields.insert(
        response_fields.end(),
        result->response_fields.begin(),
        result->response_fields.end()
      );
      session_id = result->session_id;
      state = State::streaming;
      std::vector<std::shared_ptr<const std::vector<std::uint8_t>>> output;
      output.reserve(1 + result->host_requests.size());
      output.push_back(response(frame, 0x0101, std::move(response_fields)));
      if (result->replay_requires_attach) {
        session_id.reset();
        state = State::ready;
        return output;
      }
      const auto deadline = quic_server::MonotonicClock::now() + config.configuration_ack_timeout;
      for (auto &request : result->host_requests) {
        if ((request.message_type != 0x0140 && request.message_type != 0x0142 && request.message_type != 0x0144) ||
            (request.message_type == 0x0144 && (client_record->permissions & microphone_permission) == 0) ||
            (request.message_type == 0x0140 && !exact_keys(request.request_fields, 1, 9)) ||
            (request.message_type != 0x0140 && !exact_keys(request.request_fields, 1, 4)) ||
            next_host_request_id > UINT64_MAX - 2) {
          throw std::runtime_error {"invalid v3 host configuration request"};
        }
        const auto request_session = fixed_field<16>(request.request_fields, 1);
        const auto generation = unsigned_field(request.request_fields, 2);
        if (!request_session || *request_session != result->session_id || !generation ||
            *generation == 0 || *generation > UINT32_MAX) {
          throw std::runtime_error {"invalid v3 host configuration fields"};
        }
        const auto request_id = next_host_request_id;
        next_host_request_id += 2;
        auto encoded = std::make_shared<const std::vector<std::uint8_t>>(
          encode_frame(request.message_type, request_id, 0, request.request_fields)
        );
        const auto acknowledgement_type = static_cast<std::uint16_t>(request.message_type + 1);
        outstanding_host_requests.emplace(request_id, OutstandingHostRequest {
          .request_type = request.message_type,
          .acknowledgement_type = acknowledgement_type,
          .session_id = result->session_id,
          .generation = static_cast<std::uint32_t>(*generation),
          .encoded = encoded,
          .deadline = deadline,
        });
        output.push_back(std::move(encoded));
      }
      return output;
    }

    std::vector<std::shared_ptr<const std::vector<std::uint8_t>>> configuration_acknowledgement(
      const quic_server::ControlFrame &frame
    ) {
      if (state != State::streaming || !client_record || !session_id ||
          frame.request_id % 2 != 0 || (frame.flags != 1 && frame.flags != 3)) {
        close_with(quic_server::ApplicationCloseCode::malformed, "invalid v3 configuration acknowledgement authority");
      }
      if (const auto completed = completed_host_acknowledgements.find(frame.request_id);
          completed != completed_host_acknowledgements.end()) {
        if (!std::ranges::equal(completed->second, frame.bytes)) {
          close_with(quic_server::ApplicationCloseCode::request_id_conflict, "v3 configuration acknowledgement conflict");
        }
        return {};
      }
      const auto outstanding = outstanding_host_requests.find(frame.request_id);
      if (outstanding == outstanding_host_requests.end() ||
          outstanding->second.acknowledgement_type != frame.message_type) {
        close_with(quic_server::ApplicationCloseCode::malformed, "unknown v3 configuration acknowledgement");
      }
      if (quic_server::MonotonicClock::now() > outstanding->second.deadline) {
        close_with(quic_server::ApplicationCloseCode::phase_timeout, "expired v3 configuration acknowledgement");
      }
      const auto fields = decode_map(frame);
      const auto status = unsigned_field(fields, 1);
      const auto acknowledged_session = fixed_field<16>(fields, 2);
      const auto generation = unsigned_field(fields, 3);
      const bool video = frame.message_type == 0x0141;
      const auto decoder_capacity = video ? unsigned_field(fields, 4) : std::nullopt;
      if ((!video && !exact_keys(fields, 1, 3)) || (video && !exact_keys(fields, 1, 4)) ||
          !status || *status != 0 || frame.flags != 1 || !acknowledged_session ||
          *acknowledged_session != outstanding->second.session_id || !generation ||
          *generation != outstanding->second.generation ||
          (video && (!decoder_capacity || (*decoder_capacity != 1 && *decoder_capacity != 2)))) {
        close_with(quic_server::ApplicationCloseCode::malformed, "rejected or malformed v3 configuration acknowledgement");
      }
      const auto acknowledgement = frame.message_type == 0x0141 ? ConfigurationAcknowledgement::video :
                                   frame.message_type == 0x0143 ? ConfigurationAcknowledgement::audio :
                                                                  ConfigurationAcknowledgement::microphone;
      auto authority_lease = current_authority_lease();
      if (!authority_lease) {
        close_with(quic_server::ApplicationCloseCode::unauthorized, "stale v3 configuration acknowledgement authority");
      }
      if (!backend.acknowledge_configuration(
            *client_record,
            acknowledgement,
            outstanding->second.session_id,
            outstanding->second.generation,
            video ? std::optional {static_cast<std::uint32_t>(*decoder_capacity)} : std::nullopt
          )) {
        throw std::runtime_error {"v3 configuration backend rejected acknowledgement"};
      }
      if (completed_host_acknowledgements.size() >= 32) {
        close_with(quic_server::ApplicationCloseCode::resource_limit, "v3 configuration acknowledgement cache");
      }
      completed_host_acknowledgements.emplace(
        frame.request_id,
        std::vector<std::uint8_t> {frame.bytes.begin(), frame.bytes.end()}
      );
      outstanding_host_requests.erase(outstanding);
      if (outstanding_host_requests.empty() && !media_started) {
        if (!backend.start_media(*client_record, *session_id)) {
          throw std::runtime_error {"v3 media start barrier failed"};
        }
        media_started = true;
      }
      return {};
    }

    std::vector<std::shared_ptr<const std::vector<std::uint8_t>>> authenticated_control(
      const quic_server::ControlFrame &frame,
      const Map &fields
    ) {
      if (!client_record) {
        close_with(quic_server::ApplicationCloseCode::unauthorized, "stale v3 control authority");
      }
      const auto operation = [&]() -> std::optional<AuthenticatedControl> {
        switch (frame.message_type) {
          case 0x0005: return AuthenticatedControl::ping;
          case 0x0102: return AuthenticatedControl::session_attach;
          case 0x0120: return AuthenticatedControl::input_reset;
          case 0x0122: return AuthenticatedControl::text_composition;
          case 0x0130: return AuthenticatedControl::stop;
          case 0x0200: return AuthenticatedControl::application_list;
          case 0x0202: return AuthenticatedControl::application_asset;
          default: return std::nullopt;
        }
      }();
      if (!operation) {
        close_with(quic_server::ApplicationCloseCode::malformed, "unsupported v3 control operation");
      }
      const auto required_permission = [&]() -> std::uint64_t {
        switch (*operation) {
          case AuthenticatedControl::application_list:
          case AuthenticatedControl::application_asset:
            return browse_permission;
          case AuthenticatedControl::input_reset:
          case AuthenticatedControl::text_composition:
            return input_permission;
          case AuthenticatedControl::stop:
            return stop_permission;
          case AuthenticatedControl::ping:
          case AuthenticatedControl::session_attach:
            return 0;
        }
        return UINT64_MAX;
      }();
      if (required_permission != 0 && (client_record->permissions & required_permission) == 0) {
        close_with(quic_server::ApplicationCloseCode::unauthorized, "forbidden v3 control operation");
      }
      auto authority_lease = current_authority_lease();
      if (!authority_lease) {
        close_with(quic_server::ApplicationCloseCode::unauthorized, "stale v3 control authority");
      }
      auto result = backend.control(
        *client_record,
        *operation,
        fields,
        frame.request_id,
        connection.connection_id,
        *authority_generation
      );
      if (!result || result->request != *operation || result->response_fields.empty()) {
        throw std::runtime_error {"v3 control backend failure"};
      }
      const auto response_type = static_cast<std::uint16_t>(frame.message_type + 1);
      const auto successful_stop = *operation == AuthenticatedControl::stop &&
                                   unsigned_field(result->response_fields, 1) == 0;
      const auto stopped_session = successful_stop ? session_id : std::nullopt;
      if (*operation == AuthenticatedControl::session_attach && unsigned_field(result->response_fields, 1) == 0) {
        const auto attached = fixed_field<16>(result->response_fields, 2);
        if (!attached || !nonzero(*attached)) {
          throw std::runtime_error {"invalid v3 attach response"};
        }
        session_id = *attached;
        state = State::streaming;
      } else if (*operation == AuthenticatedControl::stop && unsigned_field(result->response_fields, 1) == 0) {
        session_id.reset();
        state = State::ready;
        outstanding_host_requests.clear();
        completed_host_acknowledgements.clear();
        media_started = false;
      }
      std::vector<std::shared_ptr<const std::vector<std::uint8_t>>> output;
      output.reserve(1 + result->post_response_events.size());
      output.push_back(response(frame, response_type, std::move(result->response_fields)));
      if (result->bulk_transfer) {
        if (result->bulk_transfer->request_id != frame.request_id ||
            result->bulk_transfer->object_id == 0 || !result->bulk_transfer->bytes) {
          throw std::runtime_error {"invalid v3 bulk transfer binding"};
        }
        pending_bulk_transfers.push_back(std::move(*result->bulk_transfer));
      }
      if (!result->post_response_events.empty()) {
        if (!successful_stop || !stopped_session || result->post_response_events.size() != 1) {
          throw std::runtime_error {"invalid v3 post-response event authority"};
        }
        auto &event = result->post_response_events.front();
        const auto ended_session = fixed_field<16>(event.fields, 1);
        if (event.message_type != 0x0133 || !exact_keys(event.fields, 1, 8) ||
            !ended_session || *ended_session != *stopped_session) {
          throw std::runtime_error {"invalid v3 SESSION_ENDED event"};
        }
        output.push_back(std::make_shared<const std::vector<std::uint8_t>>(
          encode_frame(event.message_type, 0, 0, event.fields)
        ));
      }
      return output;
    }

    void close() noexcept {
      if (state == State::closed) {
        return;
      }
      state = State::closed;
      if (client_record && authority_generation) {
        authorities.release(client_record->client_id, connection.connection_id, *authority_generation);
      }
      try {
        backend.disconnect(session_id, connection.connection_id);
      } catch (...) {
      }
      session_id.reset();
      client_record.reset();
      config.response_cache->disconnect(connection.connection_id);
      outstanding_host_requests.clear();
      completed_host_acknowledgements.clear();
      pending_bulk_transfers.clear();
      media_started = false;
    }

    bool current_authority() noexcept {
      return client_record && authority_generation && authorities.current(
        client_record->client_id,
        connection.connection_id,
        *authority_generation
      );
    }

    std::unique_ptr<ConnectionAuthorityLease> current_authority_lease() noexcept {
      if (!client_record || !authority_generation) {
        return nullptr;
      }
      return authorities.lease(
        client_record->client_id,
        connection.connection_id,
        *authority_generation
      );
    }

    quic_server::ConnectionContext connection;
    Config config;
    Random &random;
    HostIdentity &identity;
    AuthorizationStore &authorization;
    NonceRegistry &nonces;
    PairingAdmission &pairing_admission;
    ConnectionAuthorityRegistry &authorities;
    SessionBackend &backend;
    State state {State::hello};
    Bytes32 spki {};
    Bytes32 server_nonce {};
    bool pairing {};
    std::optional<Identifier> claimed_client_id;
    std::optional<Identifier> invitation_id;
    Identifier attempt_id {};
    std::optional<ClientRecord> client_record;
    std::optional<std::uint64_t> authority_generation;
    std::optional<Identifier> session_id;
    std::uint16_t datagram_maximum {};
    std::uint64_t last_request_id {};
    std::uint64_t next_host_request_id {2};
    bool media_started {};
    quic_server::MonotonicClock::time_point phase_deadline {};
    quic_server::MonotonicClock::time_point operation_deadline {};
    quic_server::MonotonicClock::time_point authenticated_idle_deadline {};
    std::vector<std::uint8_t> client_hello;
    std::vector<std::uint8_t> server_hello;
    std::map<std::uint64_t, OutstandingHostRequest> outstanding_host_requests;
    std::map<std::uint64_t, std::vector<std::uint8_t>> completed_host_acknowledgements;
    std::vector<quic_server::BulkTransfer> pending_bulk_transfers;
  };

  ControlSession::ControlSession(
    quic_server::ConnectionContext connection,
    Config config,
    Random &random,
    HostIdentity &identity,
    AuthorizationStore &authorization,
    NonceRegistry &nonces,
    PairingAdmission &pairing_admission,
    ConnectionAuthorityRegistry &authorities,
    SessionBackend &backend
  ):
      impl_ {std::make_unique<Impl>(
        std::move(connection),
        std::move(config),
        random,
        identity,
        authorization,
        nonces,
        pairing_admission,
        authorities,
        backend
      )} {
  }

  ControlSession::~ControlSession() {
    if (impl_) {
      impl_->close();
    }
  }

  std::vector<std::shared_ptr<const std::vector<std::uint8_t>>> ControlSession::control(
    const quic_server::ControlFrame &frame
  ) {
    if (impl_->operation_deadline == quic_server::MonotonicClock::time_point {}) {
      static_cast<void>(impl_->begin_control(frame));
    }
    try {
      auto responses = impl_->process(frame);
      impl_->finish_control();
      return responses;
    } catch (const ResponseCacheError &error) {
      impl_->operation_deadline = {};
      close_with(
        error.kind() == ResponseCacheError::Kind::request_id_conflict ?
          quic_server::ApplicationCloseCode::request_id_conflict :
          quic_server::ApplicationCloseCode::resource_limit,
        error.what()
      );
    } catch (...) {
      impl_->operation_deadline = {};
      throw;
    }
  }

  quic_server::MonotonicClock::time_point ControlSession::begin_control(
    const quic_server::ControlFrame &frame
  ) noexcept {
    return impl_->begin_control(frame);
  }

  quic_server::MonotonicClock::time_point ControlSession::application_deadline() const noexcept {
    return impl_->application_deadline();
  }

  void ControlSession::datagram(const quic_server::DatagramRecord &record) {
    if (!impl_->client_record || !impl_->session_id || record.session_id != *impl_->session_id) {
      close_with(quic_server::ApplicationCloseCode::unauthorized, "unauthorized v3 DATAGRAM");
    }
    const bool permitted =
      (record.channel == 1 && (impl_->client_record->permissions & input_permission) != 0) ||
      (record.channel == 2 && record.kind == 3) ||
      (record.channel == 4 && (impl_->client_record->permissions & microphone_permission) != 0);
    if (!permitted) {
      close_with(quic_server::ApplicationCloseCode::unauthorized, "forbidden v3 DATAGRAM channel");
    }
    auto authority_lease = impl_->current_authority_lease();
    if (!authority_lease) {
      close_with(quic_server::ApplicationCloseCode::unauthorized, "unauthorized v3 DATAGRAM");
    }
    impl_->backend.datagram(*impl_->client_record, record);
    impl_->record_authenticated_activity();
  }

  std::optional<Identifier> ControlSession::active_session_id() const noexcept {
    return impl_->current_authority() ? impl_->session_id : std::nullopt;
  }

  bool ControlSession::authenticated() const noexcept {
    return impl_->current_authority();
  }

  std::vector<quic_server::BulkTransfer> ControlSession::take_bulk_transfers() {
    std::vector<quic_server::BulkTransfer> output;
    output.swap(impl_->pending_bulk_transfers);
    return output;
  }

  std::uint64_t ControlSession::idle_timeout_ms() const noexcept {
    const auto deadline = impl_->application_deadline();
    const auto now = quic_server::MonotonicClock::now();
    if (deadline == quic_server::MonotonicClock::time_point::max()) {
      return static_cast<std::uint64_t>(impl_->config.authenticated_idle_timeout.count());
    }
    if (deadline <= now) {
      return 1;
    }
    return static_cast<std::uint64_t>(std::max<std::int64_t>(
      1,
      std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count()
    ));
  }

  void ControlSession::datagram_maximum_changed(const std::uint16_t maximum_bytes) {
    impl_->datagram_maximum = maximum_bytes;
  }

  void ControlSession::disconnect() noexcept {
    impl_->close();
  }

#ifdef SUNSHINE_TESTS
  bool ControlSession::install_authenticated_client_for_test(const ClientRecord &client) noexcept {
    if (impl_->state != Impl::State::hello || !nonzero(client.client_id) ||
        (client.permissions & start_permission) == 0 || impl_->connection.connection_id == 0) {
      return false;
    }
    const auto claim = impl_->authorities.claim(client.client_id, impl_->connection.connection_id, false);
    if (!claim || claim->generation == 0) {
      return false;
    }
    impl_->client_record = client;
    impl_->authority_generation = claim->generation;
    impl_->state = Impl::State::ready;
    impl_->phase_deadline = {};
    impl_->record_authenticated_activity();
    return true;
  }
#endif

  SessionFactory::SessionFactory(
    Config config,
    Random &random,
    HostIdentity &identity,
    AuthorizationStore &authorization,
    NonceRegistry &nonces,
    PairingAdmission &pairing_admission,
    ConnectionAuthorityRegistry &authorities,
    SessionBackend &backend
  ):
      config_ {std::move(config)},
      random_ {random},
      identity_ {identity},
      authorization_ {authorization},
      nonces_ {nonces},
      pairing_admission_ {pairing_admission},
      authorities_ {authorities},
      backend_ {backend} {
  }

  std::unique_ptr<quic_server::ControlSessionV3> SessionFactory::create(
    const quic_server::ConnectionContext &connection
  ) {
    return std::make_unique<ControlSession>(
      connection,
      config_,
      random_,
      identity_,
      authorization_,
      nonces_,
      pairing_admission_,
      authorities_,
      backend_
    );
  }

  bool SecureRandom::fill(const std::span<std::uint8_t> output) noexcept {
    return !output.empty() && output.size() <= INT_MAX &&
           RAND_bytes(output.data(), static_cast<int>(output.size())) == 1;
  }

  SeedHostIdentity::SeedHostIdentity(Bytes32 private_seed):
      private_seed_ {std::span<const std::uint8_t, 32> {private_seed}} {
    const auto public_key = crypto::ed25519_public_key(private_seed_.bytes());
    if (!public_key) {
      throw std::invalid_argument {"invalid v3 host seed"};
    }
    public_key_ = *public_key;
    host_id_ = derived_id(public_key_);
  }

  SeedHostIdentity::~SeedHostIdentity() = default;

  Identifier SeedHostIdentity::host_id() const noexcept {
    return host_id_;
  }

  Bytes32 SeedHostIdentity::public_key() const noexcept {
    return public_key_;
  }

  std::optional<Signature> SeedHostIdentity::sign(
    const std::span<const std::uint8_t> message
  ) noexcept {
    return crypto::ed25519_sign(private_seed_.bytes(), message);
  }

  struct BoundedNonceRegistry::Entry {
    quic_server::RemoteSourcePrefix source;
    Identifier attempt_id {};
    Bytes32 nonce {};
    quic_server::MonotonicClock::time_point expiry {};
  };

  BoundedNonceRegistry::BoundedNonceRegistry() = default;
  BoundedNonceRegistry::~BoundedNonceRegistry() = default;

  bool BoundedNonceRegistry::claim(
    const quic_server::RemoteSourcePrefix &source,
    const Identifier &attempt_id,
    const Bytes32 &nonce,
    const quic_server::MonotonicClock::time_point now
  ) noexcept {
    std::lock_guard lock {mutex_};
    std::erase_if(entries_, [now](const Entry &entry) { return entry.expiry <= now; });
    if (std::ranges::any_of(entries_, [&](const Entry &entry) {
          return entry.attempt_id == attempt_id && entry.nonce == nonce;
        })) {
      return false;
    }
    const auto source_count = std::ranges::count(entries_, source, &Entry::source);
    if (source_count >= 64) {
      return false;
    }
    if (entries_.size() >= 4'096) {
      std::map<quic_server::RemoteSourcePrefix, std::size_t> counts;
      for (const auto &entry : entries_) {
        ++counts[entry.source];
      }
      const auto largest = std::ranges::max_element(counts, {}, [](const auto &entry) {
        return entry.second;
      });
      if (largest == counts.end() || largest->second <= source_count) {
        return false;
      }
      const auto oldest = std::ranges::min_element(entries_, {}, [&](const Entry &entry) {
        return entry.source == largest->first ? entry.expiry : quic_server::MonotonicClock::time_point::max();
      });
      if (oldest == entries_.end() || oldest->source != largest->first) {
        return false;
      }
      entries_.erase(oldest);
    }
    entries_.push_back({source, attempt_id, nonce, now + std::chrono::minutes {10}});
    return true;
  }

  struct BoundedPairingAdmission::Entry {
    quic_server::RemoteSourcePrefix source;
    std::vector<quic_server::MonotonicClock::time_point> attempts;
  };

  BoundedPairingAdmission::BoundedPairingAdmission() = default;
  BoundedPairingAdmission::~BoundedPairingAdmission() = default;

  bool BoundedPairingAdmission::admit_hello(
    const quic_server::RemoteSourcePrefix &source,
    const Identifier &attempt_id,
    const quic_server::MonotonicClock::time_point now
  ) noexcept {
    return admit(source, attempt_id, now);
  }

  bool BoundedPairingAdmission::admit(
    const quic_server::RemoteSourcePrefix &source,
    const Identifier &invitation_id,
    const quic_server::MonotonicClock::time_point now
  ) noexcept {
    static_cast<void>(invitation_id);
    std::lock_guard lock {mutex_};
    const auto cutoff = now - std::chrono::seconds {1};
    for (auto &entry : entries_) {
      std::erase_if(entry.attempts, [cutoff](const auto attempt) { return attempt <= cutoff; });
    }
    std::erase_if(entries_, [](const Entry &entry) { return entry.attempts.empty(); });
    auto found = std::ranges::find(entries_, source, &Entry::source);
    if (found == entries_.end()) {
      if (entries_.size() >= 64) {
        return false;
      }
      entries_.push_back({source, {}});
      found = std::prev(entries_.end());
    }
    if (found->attempts.size() >= 32) {
      return false;
    }
    found->attempts.push_back(now);
    return true;
  }

  struct ConnectionAuthorities::Entry {
    Identifier client_id {};
    std::uint64_t connection_id {};
    std::uint64_t generation {};
    std::size_t leases {};
  };

  struct ConnectionAuthorities::Lease final: ConnectionAuthorityLease {
    Lease(
      ConnectionAuthorities &owner,
      const Identifier &client_id,
      const std::uint64_t connection_id,
      const std::uint64_t generation
    ) noexcept:
        owner_ {owner},
        client_id_ {client_id},
        connection_id_ {connection_id},
        generation_ {generation} {
    }

    ~Lease() override {
      owner_.release_lease(client_id_, connection_id_, generation_);
    }

  private:
    ConnectionAuthorities &owner_;
    Identifier client_id_ {};
    std::uint64_t connection_id_ {};
    std::uint64_t generation_ {};
  };

  ConnectionAuthorities::ConnectionAuthorities() = default;
  ConnectionAuthorities::~ConnectionAuthorities() = default;

  std::optional<AuthorityClaim> ConnectionAuthorities::claim(
    const Identifier &client_id,
    const std::uint64_t connection_id,
    const bool replace_existing
  ) noexcept {
    std::lock_guard lock {mutex_};
    auto found = std::ranges::find(entries_, client_id, &Entry::client_id);
    if (found != entries_.end() && found->connection_id != connection_id && !replace_existing) {
      return std::nullopt;
    }
    if (found != entries_.end() && found->leases != 0) {
      return std::nullopt;
    }
    if (next_generation_ == 0 || next_generation_ == UINT64_MAX) {
      return std::nullopt;
    }
    const auto generation = next_generation_++;
    const auto replaced = found != entries_.end() && found->connection_id != connection_id ?
                            std::optional {found->connection_id} :
                            std::nullopt;
    if (found == entries_.end()) {
      entries_.push_back({client_id, connection_id, generation, 0});
    } else {
      found->connection_id = connection_id;
      found->generation = generation;
    }
    return AuthorityClaim {generation, replaced};
  }

  bool ConnectionAuthorities::current(
    const Identifier &client_id,
    const std::uint64_t connection_id,
    const std::uint64_t generation
  ) noexcept {
    std::lock_guard lock {mutex_};
    const auto found = std::ranges::find(entries_, client_id, &Entry::client_id);
    return found != entries_.end() && found->connection_id == connection_id &&
           found->generation == generation;
  }

  std::unique_ptr<ConnectionAuthorityLease> ConnectionAuthorities::lease(
    const Identifier &client_id,
    const std::uint64_t connection_id,
    const std::uint64_t generation
  ) noexcept {
    std::lock_guard lock {mutex_};
    const auto found = std::ranges::find(entries_, client_id, &Entry::client_id);
    if (found == entries_.end() || found->connection_id != connection_id ||
        found->generation != generation) {
      return nullptr;
    }
    ++found->leases;
    try {
      return std::make_unique<Lease>(*this, client_id, connection_id, generation);
    } catch (...) {
      --found->leases;
      return nullptr;
    }
  }

  void ConnectionAuthorities::release_lease(
    const Identifier &client_id,
    const std::uint64_t connection_id,
    const std::uint64_t generation
  ) noexcept {
    std::lock_guard lock {mutex_};
    const auto found = std::ranges::find(entries_, client_id, &Entry::client_id);
    if (found != entries_.end() && found->connection_id == connection_id &&
        found->generation == generation && found->leases != 0) {
      --found->leases;
      condition_.notify_all();
    }
  }

  void ConnectionAuthorities::release(
    const Identifier &client_id,
    const std::uint64_t connection_id,
    const std::uint64_t generation
  ) noexcept {
    std::unique_lock lock {mutex_};
    condition_.wait(lock, [&] {
      const auto found = std::ranges::find(entries_, client_id, &Entry::client_id);
      return found == entries_.end() || found->connection_id != connection_id ||
             found->generation != generation || found->leases == 0;
    });
    std::erase_if(entries_, [&](const Entry &entry) {
      return entry.client_id == client_id && entry.connection_id == connection_id &&
             entry.generation == generation;
    });
  }

  std::vector<std::uint64_t> ConnectionAuthorities::revoke_client(
    const Identifier &client_id
  ) noexcept {
    std::unique_lock lock {mutex_};
    condition_.wait(lock, [&] {
      const auto found = std::ranges::find(entries_, client_id, &Entry::client_id);
      return found == entries_.end() || found->leases == 0;
    });
    std::vector<std::uint64_t> connections;
    for (const auto &entry : entries_) {
      if (entry.client_id == client_id) {
        connections.push_back(entry.connection_id);
      }
    }
    std::erase_if(entries_, [&](const Entry &entry) { return entry.client_id == client_id; });
    return connections;
  }
}  // namespace lumen::protocol_v3::control_session
