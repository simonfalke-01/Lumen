/**
 * @file src/protocol_lsp/runtime/input_owner.cpp
 * @brief Bounded ordered LSP input receive and platform-apply owner.
 */

#include "input_owner.h"

#include "../../input.h"
#include "../core/packet.h"
#include "../core/rtp.h"
#include "../input_plane/feedback.h"
#include "../input_plane/rate.h"
#include "../input_plane/state.h"
#include "../transport/rtcp.h"
#include "udp_socket.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <condition_variable>
#include <limits>
#include <mutex>
#include <new>
#include <optional>
#include <thread>

namespace lumen::lsp::runtime {
  namespace {
    constexpr std::size_t maximum_input_rtp_bytes = 1'200;
    constexpr std::size_t maximum_latest_state_keys = input_plane::maximum_input_baseline_records;
    constexpr std::uint64_t edge_application_deadline_microseconds = 100'000;

    bool difference(const std::int64_t current, const std::int64_t previous, std::int64_t &output) noexcept {
      if ((previous > 0 && current < std::numeric_limits<std::int64_t>::min() + previous) ||
          (previous < 0 && current > std::numeric_limits<std::int64_t>::max() + previous)) {
        return false;
      }
      output = current - previous;
      return true;
    }
  }  // namespace

  std::size_t write_input_feedback_compound_report(
    const std::span<std::uint8_t> destination,
    const std::uint32_t acknowledgement_ssrc,
    const RtcpCname &cname
  ) noexcept {
    if (destination.size() < 12U || acknowledgement_ssrc == 0 || !cname.valid()) {
      return 0;
    }
    auto receiver_report = destination.first<8>();
    std::ranges::fill(receiver_report, 0);
    receiver_report[0] = 0x80U;
    receiver_report[1] = transport::rtcp_receiver_report_type;
    wire::write_be<std::uint16_t>(receiver_report.subspan(2, 2), 1U);
    wire::write_be<std::uint32_t>(receiver_report.subspan(4, 4), acknowledgement_ssrc);
    const auto sdes_size = transport::write_sdes_cname(
      acknowledgement_ssrc,
      cname.view(),
      destination.subspan(8)
    );
    return sdes_size == 0 ? 0 : 8U + sdes_size;
  }

  void InputFeedbackCompoundGate::reset(
    const std::uint32_t connection_generation,
    const std::uint32_t input_generation
  ) noexcept {
    const auto value = connection_generation == 0 || input_generation == 0 ?
                         0 :
                         (static_cast<std::uint64_t>(connection_generation) << 32U) | input_generation;
    sent_.store(false, std::memory_order_release);
    in_flight_token_.store(0, std::memory_order_release);
    authority_token_.store(value, std::memory_order_release);
  }

  std::uint64_t InputFeedbackCompoundGate::token() const noexcept {
    return authority_token_.load(std::memory_order_acquire);
  }

  bool InputFeedbackCompoundGate::begin_submission(const std::uint64_t token) noexcept {
    if (token == 0 || token != authority_token_.load(std::memory_order_acquire) ||
        sent_.load(std::memory_order_acquire)) {
      return false;
    }
    auto expected = std::uint64_t {0};
    return in_flight_token_.compare_exchange_strong(
      expected,
      token,
      std::memory_order_acq_rel,
      std::memory_order_acquire
    );
  }

  void InputFeedbackCompoundGate::cancel_submission(const std::uint64_t token) noexcept {
    auto expected = token;
    (void) in_flight_token_.compare_exchange_strong(
      expected,
      0,
      std::memory_order_acq_rel,
      std::memory_order_acquire
    );
  }

  void InputFeedbackCompoundGate::complete(const std::uint64_t token, const bool sent) noexcept {
    auto expected = token;
    if (in_flight_token_.compare_exchange_strong(
          expected,
          0,
          std::memory_order_acq_rel,
          std::memory_order_acquire
        ) &&
        sent && authority_token_.load(std::memory_order_acquire) == token) {
      sent_.store(true, std::memory_order_release);
    }
  }

  bool InputFeedbackCompoundGate::reduced_size_allowed(const std::uint64_t token) const noexcept {
    return token != 0 && authority_token_.load(std::memory_order_acquire) == token &&
           sent_.load(std::memory_order_acquire);
  }

  bool InputFeedbackCompoundGate::submission_pending() const noexcept {
    return in_flight_token_.load(std::memory_order_acquire) != 0;
  }

  bool InputSessionMapping::valid() const noexcept {
    return peer.valid() && forward_path && forward_path->ready() &&
           forward_path->generation() == connection_generation && !is_zero(client_id) && !is_zero(session_id) &&
           connection_generation != 0 && session_generation != 0 &&
           input_generation != 0 && input_ssrc != 0 && acknowledgement_ssrc != 0 &&
           input_ssrc != acknowledgement_ssrc && rtcp_cname.valid() &&
           input_payload_type >= 96 && input_payload_type <= 127 && pointer_rate >= 125 && pointer_rate <= 16'000 &&
           controller_rate >= 125 && controller_rate <= 2'000 && sensor_rate >= 125 && sensor_rate <= 4'000 &&
           reconciliation_rate >= 50 && reconciliation_rate <= 1'000 &&
           reserved_input_wire_bits_per_second > 0 && reserved_input_wire_bits_per_second <= 32'000'000U;
  }

  class InputOwner::Impl {
  public:
    class DigestVerifier final: public input_plane::baseline_digest_verifier {
    public:
      explicit DigestVerifier(Impl &owner) noexcept:
          owner_ {owner} {
      }

      bool verify(const std::span<const std::uint8_t> bytes, const Digest256 &digest) const noexcept override {
        return owner_.callbacks_.verify_digest && owner_.callbacks_.verify_digest(owner_.callbacks_.context, bytes, digest);
      }

    private:
      Impl &owner_;  ///< Callback owner.
    };

    Impl(const InputOwnerCallbacks callbacks, LibsrtpServerProvider &srtp) noexcept:
        callbacks_ {callbacks},
        srtp_ {srtp},
        verifier_ {*this},
        platform_ {input::alloc_lsp_platform_input(platform_feedback_callback, this)} {
      if (!callbacks_.verify_digest || !callbacks_.baseline_committed || !callbacks_.baseline_acknowledged || !platform_) {
        return;
      }
      try {
        worker_ = std::jthread {[this](const std::stop_token stop_token) {
          run(stop_token);
        }};
        ready_ = true;
      } catch (...) {
        ready_ = false;
      }
    }

    ~Impl() {
      begin_shutdown();
      if (worker_.joinable()) {
        worker_.join();
      }
      if (platform_) {
        input::stop_lsp_platform_input_feedback(*platform_);
        input::neutralize_lsp_platform_input(*platform_);
        platform_.reset();
      }
    }

    /** @brief Close all producer entry points without releasing callback target storage. */
    void begin_shutdown() noexcept {
      {
        std::scoped_lock lock(mutex_);
        ready_ = false;
        shutting_down_ = true;
      }
      worker_.request_stop();
      condition_.notify_all();
    }

    bool configure(const InputSessionMapping &mapping) noexcept {
      if (!mapping.valid()) {
        return false;
      }
      std::scoped_lock lock(mutex_);
      if (!ready_ || shutting_down_) {
        return false;
      }
      commit_configuration_locked(mapping);
      condition_.notify_all();
      return true;
    }

    void commit_configuration(const InputSessionMapping &mapping) noexcept {
      std::scoped_lock lock(mutex_);
      if (!ready_ || shutting_down_) {
        return;
      }
      commit_configuration_locked(mapping);
      condition_.notify_all();
    }

    /** @brief Install one preflighted mapping while the owner lock is held. */
    void commit_configuration_locked(const InputSessionMapping &mapping) noexcept {
      input::neutralize_lsp_platform_input(*platform_);
      mapping_ = mapping;
      baseline_.reset();
      edges_.reset(mapping.input_generation);
      latest_states_.clear();
      state_progress_ = {};
      edge_deadlines_ = {};
      pointers_ = {};
      highest_accepted_state_ = 0;
      highest_applied_state_ = 0;
      controller_output_.reset(mapping.input_generation);
      controller_generations_ = {};
      device_rates_ = {};
      controller_ordinals_ = {};
      controller_touches_ = {};
      controller_latest_ = {};
      next_controller_sequence_ = 1;
      ack_scheduler_ = {};
      ack_pending_ = false;
      ack_mapping_ = {};
      ack_receive_time_ = 0;
      ack_apply_time_ = 0;
      ack_pending_since_ = 0;
      ack_pending_records_ = 0;
      ack_urgent_ = false;
      compound_gate_.reset(mapping.connection_generation, mapping.input_generation);
      baseline_acknowledged_id_ = 0;
      text_barrier_edge_id_ = 0;
      baseline_receive_time_ = 0;
      baseline_edge_watermark_ = 0;
      edge_receive_time_ = 0;
      baseline_work_pending_ = false;
      baseline_authorization_pending_ = false;
      state_work_pending_ = false;
      edge_work_pending_ = false;
      safety_reset_pending_ = false;
      baseline_requested_ = false;
    }

    bool ready_for_configuration(const InputSessionMapping &mapping) const noexcept {
      std::scoped_lock lock(mutex_);
      return ready_ && !shutting_down_ && mapping.valid();
    }

    bool receive(
      const PeerEndpoint &peer,
      const std::span<const std::uint8_t> packet,
      std::uint64_t received_at_microseconds
    ) noexcept {
      const auto rtp = parse_rtp_fixed_header(packet);
      if (!rtp || rtp.header.padding || rtp.header.extension || rtp.header.csrc_count != 0) {
        return false;
      }
      std::scoped_lock lock(mutex_);
      if (shutting_down_ || !mapping_ || peer != mapping_->peer || rtp.header.ssrc != mapping_->input_ssrc ||
          rtp.header.payload_type != mapping_->input_payload_type) {
        return true;
      }
      if (baseline_authorization_pending_) {
        return true;
      }
      if (received_at_microseconds == 0) {
        received_at_microseconds = monotonic_microseconds();
      }
      if (packet.size() > maximum_input_rtp_bytes || rtp.bytes_consumed >= packet.size()) {
        request_baseline_locked(*mapping_, received_at_microseconds);
        condition_.notify_one();
        return true;
      }
      const auto parsed = input_plane::parse_packet(
        packet.subspan(rtp.bytes_consumed),
        mapping_->input_generation
      );
      if (!parsed) {
        if (parsed.error == input_plane::wire_error::invalid_generation) {
          return true;
        }
        request_baseline_locked(*mapping_, received_at_microseconds);
        condition_.notify_one();
        return true;
      }

      switch (parsed.header.kind) {
        case input_plane::packet_kind::baseline_part:
          classify_baseline_locked(*mapping_, parsed, received_at_microseconds);
          break;
        case input_plane::packet_kind::edge_batch:
          classify_edges_locked(*mapping_, parsed, received_at_microseconds);
          break;
        case input_plane::packet_kind::pointer_motion:
        case input_plane::packet_kind::core_state:
        case input_plane::packet_kind::device_state:
        case input_plane::packet_kind::sensor_state:
          classify_state_locked(*mapping_, parsed, received_at_microseconds);
          break;
      }
      condition_.notify_one();
      return true;
    }

    void neutralize() noexcept {
      std::scoped_lock lock(mutex_);
      neutralize_locked();
    }

    std::optional<InputSessionMapping> mapping() const noexcept {
      std::scoped_lock lock(mutex_);
      return mapping_;
    }

    /** @brief Snapshot greatest applied state and contiguous edge under the owner lock. */
    std::pair<std::uint64_t, std::uint64_t> applied_watermark() const noexcept {
      std::scoped_lock lock(mutex_);
      return {highest_applied_state_, edges_.applied_through()};
    }

    ControlStatus inject_text(
      const Identifier128 &session_id,
      const std::uint32_t input_generation,
      const std::uint64_t preceding_edge_id,
      const std::span<const std::uint8_t> utf8,
      const std::uint64_t deadline_microseconds
    ) noexcept {
      std::unique_lock lock(mutex_);
      while (mapping_ && mapping_->session_generation != 0 && mapping_->input_generation == input_generation &&
             (!baseline_.committed() ||
              edges_.applied_through() < std::max(preceding_edge_id, text_barrier_edge_id_))) {
        const auto now = monotonic_microseconds();
        if (deadline_microseconds == 0 || now >= deadline_microseconds) {
          return ControlStatus::timeout;
        }
        condition_.wait_for(lock, std::chrono::microseconds {std::min<std::uint64_t>(1'000U, deadline_microseconds - now)});
      }
      if (!mapping_ || mapping_->input_generation != input_generation ||
          mapping_->session_generation == 0 || session_id != mapping_->session_id) {
        return ControlStatus::stale_generation;
      }
      return input::apply_lsp_utf8_text(*platform_, utf8) ?
               ControlStatus::success :
               ControlStatus::internal_failure;
    }

    std::expected<InputRateResponsePayload, ControlStatus> configure_input_rate(
      const InputRateRequestPayload &request
    ) noexcept {
      std::scoped_lock lock(mutex_);
      if (!mapping_ || mapping_->session_id != request.session_id ||
          mapping_->input_generation != request.input_generation) {
        return std::unexpected(ControlStatus::stale_generation);
      }
      const auto removal = request.observed_capture_rate == 0 && request.minimum_state_rate == 0 &&
                           request.maximum_state_rate == 0 && request.minimum_sensor_rate == 0 &&
                           request.maximum_sensor_rate == 0 && request.maximum_state_packet_bytes == 0 &&
                           request.maximum_sensor_packet_bytes == 0;
      if (!removal &&
          (request.device_type == InputRateDeviceType::controller || request.device_type == InputRateDeviceType::sensor) &&
          (request.device_id == 0 || request.device_id > controller_generations_.size() ||
           controller_generations_[request.device_id - 1U] != request.instance_generation)) {
        return std::unexpected(ControlStatus::stale_generation);
      }
      auto candidate = device_rates_;
      auto selected = std::ranges::find_if(candidate, [&](const DeviceRate &rate) {
        return rate.active && rate.device_type == request.device_type && rate.device_id == request.device_id &&
               rate.instance_generation == request.instance_generation;
      });
      if (removal) {
        if (selected == candidate.end()) {
          return std::unexpected(ControlStatus::stale_generation);
        }
        *selected = {};
      }
      if (selected == candidate.end()) {
        selected = std::ranges::find_if(candidate, [](const DeviceRate &rate) {
          return !rate.active;
        });
      }
      if (selected == candidate.end()) {
        return std::unexpected(ControlStatus::busy);
      }
      if (!removal) {
        selected->device_type = request.device_type;
        selected->device_id = request.device_id;
        selected->instance_generation = request.instance_generation;
        selected->state_rate = request.maximum_state_rate;
        selected->sensor_rate = request.maximum_sensor_rate;
        selected->maximum_state_packet_bytes = request.maximum_state_packet_bytes;
        selected->maximum_sensor_packet_bytes = request.maximum_sensor_packet_bytes;
        selected->active = true;
      }

      struct Totals {
        std::uint32_t pointer {};
        std::uint32_t controller {};
        std::uint32_t sensor {};
        std::uint32_t reconciliation {};
        std::uint64_t wire_bits {};
      };

      const auto family = mapping_->peer.family == IpAddressFamily::ipv6 ?
                            input_plane::ip_family::ipv6 :
                            input_plane::ip_family::ipv4;
      const auto totals = [&](const std::array<DeviceRate, 64> &rates) {
        Totals result {
          .pointer = mapping_->pointer_rate,
          .controller = mapping_->controller_rate,
          .sensor = mapping_->sensor_rate,
          .reconciliation = mapping_->reconciliation_rate,
        };
        std::array<bool, 4> represented {};
        std::array<std::uint64_t, 4> sums {};
        for (const auto &rate : rates) {
          if (!rate.active) {
            continue;
          }
          const auto index = static_cast<std::size_t>(rate.device_type) - 1U;
          represented[index] = true;
          sums[index] += rate.state_rate;
          result.sensor = static_cast<std::uint32_t>(std::min<std::uint64_t>(
            4'000U,
            static_cast<std::uint64_t>(result.sensor) + rate.sensor_rate
          ));
          result.wire_bits += input_plane::wire_bits_per_second(family, rate.maximum_state_packet_bytes, rate.state_rate);
          if (rate.sensor_rate != 0) {
            result.wire_bits += input_plane::wire_bits_per_second(
              family,
              rate.maximum_sensor_packet_bytes,
              rate.sensor_rate
            );
          }
        }
        result.pointer = std::max(result.pointer, static_cast<std::uint32_t>(std::min<std::uint64_t>(16'000U, sums[0])));
        result.controller = std::max(result.controller, static_cast<std::uint32_t>(std::min<std::uint64_t>(2'000U, sums[1])));
        result.sensor = std::max(result.sensor, static_cast<std::uint32_t>(std::min<std::uint64_t>(4'000U, sums[2])));
        result.reconciliation = std::max(result.reconciliation, static_cast<std::uint32_t>(std::min<std::uint64_t>(1'000U, sums[3])));
        if (!represented[0]) {
          result.wire_bits += input_plane::wire_bits_per_second(family, input_plane::pointer_payload_size, result.pointer);
        }
        if (!represented[1]) {
          result.wire_bits += input_plane::wire_bits_per_second(family, 96, result.controller);
        }
        if (!represented[2]) {
          result.wire_bits += input_plane::wire_bits_per_second(family, 32, result.sensor);
        }
        if (!represented[3]) {
          result.wire_bits += input_plane::wire_bits_per_second(
            family,
            input_plane::maximum_core_state_bytes,
            result.reconciliation
          );
        }
        return result;
      };
      auto aggregate = totals(candidate);
      while (!removal && aggregate.wire_bits > mapping_->reserved_input_wire_bits_per_second &&
             selected->sensor_rate > request.minimum_sensor_rate) {
        --selected->sensor_rate;
        aggregate = totals(candidate);
      }
      while (!removal && aggregate.wire_bits > mapping_->reserved_input_wire_bits_per_second &&
             selected->state_rate > request.minimum_state_rate) {
        --selected->state_rate;
        aggregate = totals(candidate);
      }
      if (aggregate.wire_bits == 0 || aggregate.wire_bits > mapping_->reserved_input_wire_bits_per_second ||
          aggregate.wire_bits > 32'000'000U) {
        return std::unexpected(ControlStatus::path_capacity_insufficient);
      }
      device_rates_ = candidate;
      return InputRateResponsePayload {
        .status = ControlStatus::success,
        .session_id = request.session_id,
        .input_generation = request.input_generation,
        .device_type = request.device_type,
        .device_id = request.device_id,
        .instance_generation = request.instance_generation,
        .state_rate = selected->state_rate,
        .sensor_rate = selected->sensor_rate,
        .pointer_rate = aggregate.pointer,
        .controller_rate = aggregate.controller,
        .aggregate_sensor_rate = aggregate.sensor,
        .reconciliation_rate = aggregate.reconciliation,
        .reserved_input_wire_bits_per_second = aggregate.wire_bits,
      };
    }

    /** @brief Read exact final-sent complete IP/UDP bytes for LSPI and LSPG. */
    [[nodiscard]] std::uint64_t sent_feedback_wire_bytes() const noexcept {
      return sent_feedback_wire_bytes_.load(std::memory_order_relaxed);
    }

    /** @brief Read receive-to-platform-apply latency observations. */
    [[nodiscard]] InputLatencySnapshot latency_snapshot() const noexcept {
      return {
        .samples = apply_latency_samples_.load(std::memory_order_relaxed),
        .latest_microseconds = latest_apply_latency_microseconds_.load(std::memory_order_relaxed),
        .maximum_microseconds = maximum_apply_latency_microseconds_.load(std::memory_order_relaxed),
      };
    }

    bool receive_rtcp(const PeerEndpoint &peer, const std::span<const std::uint8_t> packet) noexcept {
      std::scoped_lock lock(mutex_);
      if (!mapping_ || peer != mapping_->peer || packet.size() < 8 || (packet[0] >> 6U) != 2 || packet[1] != 204 ||
          wire::read_be<std::uint32_t>(packet.subspan(4, 4)) != mapping_->input_ssrc ||
          (std::size_t {wire::read_be<std::uint16_t>(packet.subspan(2, 2))} + 1U) * 4U != packet.size()) {
        return true;
      }
      if (packet.size() < 8 + input_plane::lspg_header_size) {
        return true;
      }
      const auto lspg_size = input_plane::lspg_header_size + wire::read_be<std::uint16_t>(packet.subspan(14, 2));
      if (lspg_size > packet.size() - 8) {
        return true;
      }
      const auto parsed = input_plane::parse_lspg(packet.subspan(8, lspg_size));
      if (!parsed || parsed.subtype != input_plane::lspg_subtype::acknowledgement) {
        return true;
      }
      input_plane::controller_command_ack acknowledgement;
      return input_plane::decode_controller_ack(parsed, acknowledgement) == input_plane::lspg_error::none &&
             controller_output_.acknowledge(acknowledgement) != input_plane::controller_output_result::stale_generation;
    }

  private:
    /** @brief Bind regular-compound completion to one exact connection/input generation pair. */
    [[nodiscard]] static constexpr std::uint64_t mapping_token(
      const InputSessionMapping &mapping
    ) noexcept {
      return (static_cast<std::uint64_t>(mapping.connection_generation) << 32U) |
             mapping.input_generation;
    }

    /** @brief Clear the current mapping while the owner mutex is already held. */
    void neutralize_locked() noexcept {
      mapping_.reset();
      baseline_.reset();
      latest_states_.clear();
      state_progress_ = {};
      edge_deadlines_ = {};
      pointers_ = {};
      device_rates_ = {};
      controller_generations_ = {};
      controller_ordinals_ = {};
      controller_touches_ = {};
      ack_scheduler_ = {};
      ack_pending_ = false;
      ack_mapping_ = {};
      ack_pending_since_ = 0;
      ack_pending_records_ = 0;
      ack_urgent_ = false;
      compound_gate_.reset(0, 0);
      baseline_acknowledged_id_ = 0;
      text_barrier_edge_id_ = 0;
      baseline_receive_time_ = 0;
      baseline_edge_watermark_ = 0;
      edge_receive_time_ = 0;
      baseline_work_pending_ = false;
      baseline_authorization_pending_ = false;
      state_work_pending_ = false;
      edge_work_pending_ = false;
      safety_reset_pending_ = false;
      baseline_requested_ = false;
      input::neutralize_lsp_platform_input(*platform_);
    }

    /** @brief Retained selected rates for one generation-qualified device/report class. */
    struct DeviceRate {
      InputRateDeviceType device_type {InputRateDeviceType::pointer};  ///< Report class.
      std::uint16_t device_id {};  ///< Device identity.
      std::uint32_t instance_generation {};  ///< Exact device incarnation.
      std::uint32_t state_rate {};  ///< Selected state reports per second.
      std::uint32_t sensor_rate {};  ///< Selected sensor reports per second.
      std::uint16_t maximum_state_packet_bytes {};  ///< Frozen state packet bound.
      std::uint16_t maximum_sensor_packet_bytes {};  ///< Frozen sensor packet bound.
      bool active {};  ///< Whether the slot is populated.
    };

    struct PointerState {
      std::uint32_t id {};  ///< Active pointer ID.
      std::uint32_t instance_generation {};  ///< Active pointer generation.
      std::uint64_t physical_ordinal {};  ///< Greatest applied physical ordinal.
      std::uint64_t state_sequence {};  ///< Greatest applied state sequence.
      input_plane::pointer_flag mode {input_plane::pointer_flag::relative};  ///< Last authoritative pointer mode.
      std::int64_t cumulative_x {};  ///< Last cumulative horizontal motion.
      std::int64_t cumulative_y {};  ///< Last cumulative vertical motion.
      std::int64_t vertical_scroll {};  ///< Last cumulative vertical scrolling.
      std::int64_t horizontal_scroll {};  ///< Last cumulative horizontal scrolling.
      std::uint32_t absolute_x {};  ///< Last absolute Q0.32 horizontal coordinate.
      std::uint32_t absolute_y {};  ///< Last absolute Q0.32 vertical coordinate.
    };

    /** @brief Per-supersession-key admission, application, and receive-time watermarks. */
    struct StateProgress {
      input_plane::supersession_key key {};  ///< Exact independently replaceable state key.
      std::uint64_t accepted_sequence {};  ///< Greatest state sequence retained for this key.
      std::uint64_t accepted_ordinal {};  ///< Greatest physical ordinal retained for this key, or zero for core state.
      std::uint64_t applied_sequence {};  ///< Greatest state sequence submitted for this key.
      std::uint64_t applied_ordinal {};  ///< Greatest physical ordinal submitted for this key, or zero for core state.
      std::uint64_t received_at_microseconds {};  ///< Socket receive time of the currently retained value.
      bool occupied {};  ///< Whether this slot names a live supersession key.
    };

    /** @brief Host deadline attached to one retained exactly-once edge identifier. */
    struct EdgeDeadline {
      std::uint64_t edge_id {};  ///< Exact retained edge ID occupying this modulo slot.
      std::uint64_t deadline_microseconds {};  ///< Latest safe host application time.
    };

    /** @brief Last platform-submitted controller touchpad contact used to generate end events. */
    struct ControllerTouchState {
      std::uint32_t contact_id {};  ///< Nonzero controller-local contact ID.
      float x {};  ///< Last normalized horizontal coordinate.
      float y {};  ///< Last normalized vertical coordinate.
      float pressure {};  ///< Last normalized pressure.
      bool active {};  ///< Whether the contact remains submitted.
    };

    /** @brief Apply one exact frozen core bitmap and retain its text barrier. */
    [[nodiscard]] bool apply_core_state(const input_plane::core_state_payload &core) noexcept {
      if ((core.pointer_buttons & ~std::uint32_t {0x1fU}) != 0) {
        return false;
      }
      for (std::uint16_t usage = 0; usage < 256; ++usage) {
        const auto held = (core.key_bitmap[usage / 8U] & (1U << (usage % 8U))) != 0;
        if (!input::apply_lsp_key(*platform_, usage, !held)) {
          return false;
        }
      }
      for (std::uint16_t button = 1; button <= 5; ++button) {
        const auto held = (core.pointer_buttons & (1U << (button - 1U))) != 0;
        if (!input::apply_lsp_pointer_button(*platform_, button, !held)) {
          return false;
        }
      }
      return true;
    }

    /** @brief Apply one exact controller body including digital, analog, battery, and touchpad state. */
    [[nodiscard]] bool apply_controller_state(
      const InputSessionMapping &mapping,
      const input_plane::controller_state_payload &controller
    ) noexcept {
      const auto id = controller.prefix.device_id;
      const auto generation = controller.prefix.instance_generation;
      if (id == 0 || id > controller_generations_.size() || controller_generations_[id - 1U] != generation ||
          !input::apply_lsp_controller_state(
            *platform_,
            id,
            generation,
            static_cast<std::uint8_t>(controller.triggers[0] >> 8U),
            static_cast<std::uint8_t>(controller.triggers[1] >> 8U),
            controller.axes[0],
            controller.axes[1],
            controller.axes[2],
            controller.axes[3]
          )) {
        return false;
      }
      for (std::uint16_t bit = 0; bit <= static_cast<std::uint16_t>(input_plane::controller_button_bit::touchpad_click); ++bit) {
        if (!input::apply_lsp_controller_button(
              *platform_,
              id,
              generation,
              bit,
              (controller.buttons & (std::uint64_t {1} << bit)) == 0
            )) {
          return false;
        }
      }
      if (!input::apply_lsp_controller_battery(
            *platform_,
            mapping.input_generation,
            id,
            generation,
            static_cast<std::uint8_t>(controller.battery_state),
            controller.battery_percent
          )) {
        return false;
      }
      constexpr auto normalized = 1.0f / 4'294'967'295.0f;
      constexpr auto pressure_scale = 1.0f / 65'535.0f;
      auto &previous = controller_touches_[id - 1U];
      for (auto &prior : previous) {
        const auto retained = std::ranges::any_of(controller.touchpad, [&](const auto &contact) {
          return contact.active && contact.contact_id == prior.contact_id;
        });
        if (prior.active && !retained && !input::apply_lsp_controller_touch(*platform_, mapping.input_generation, id, generation, 2, prior.contact_id, prior.x, prior.y, prior.pressure)) {
          return false;
        }
        if (!retained) {
          prior = {};
        }
      }
      for (const auto &contact : controller.touchpad) {
        if (!contact.active) {
          continue;
        }
        auto retained = std::ranges::find_if(previous, [&](const auto &candidate) {
          return candidate.active && candidate.contact_id == contact.contact_id;
        });
        const auto continued = retained != previous.end();
        if (!continued) {
          retained = std::ranges::find_if(previous, [](const auto &candidate) {
            return !candidate.active;
          });
        }
        if (retained == previous.end()) {
          return false;
        }
        *retained = {
          .contact_id = contact.contact_id,
          .x = static_cast<float>(contact.x) * normalized,
          .y = static_cast<float>(contact.y) * normalized,
          .pressure = static_cast<float>(contact.pressure) * pressure_scale,
          .active = true,
        };
        if (!input::apply_lsp_controller_touch(
              *platform_,
              mapping.input_generation,
              id,
              generation,
              continued ? 3U : 1U,
              retained->contact_id,
              retained->x,
              retained->y,
              retained->pressure
            )) {
          return false;
        }
      }
      controller_ordinals_[id - 1U] = controller.prefix.physical_ordinal;
      return true;
    }

    /** @brief Convert one Q16.16 SI sensor vector to the platform's existing float convention. */
    [[nodiscard]] bool apply_controller_sensor(
      const InputSessionMapping &mapping,
      const input_plane::controller_sensor_payload &sensor
    ) noexcept {
      constexpr float q16_16 = 1.0f / 65'536.0f;
      constexpr float radians_to_degrees = 57.29577951308232f;
      const auto scale = sensor.sensor == input_plane::sensor_type::gyroscope ?
                           q16_16 * radians_to_degrees :
                           q16_16;
      return input::apply_lsp_controller_sensor(
        *platform_,
        mapping.input_generation,
        sensor.prefix.device_id,
        sensor.prefix.instance_generation,
        static_cast<std::uint8_t>(sensor.sensor),
        static_cast<float>(sensor.vector[0]) * scale,
        static_cast<float>(sensor.vector[1]) * scale,
        static_cast<float>(sensor.vector[2]) * scale
      );
    }

    /** @brief Apply every active contact in one validated direct-touch body. */
    [[nodiscard]] bool apply_touch_state(const input_plane::parsed_touch_state &touch) noexcept {
      for (std::size_t index = 0; index < touch.contact_count; ++index) {
        const auto contact = touch.contact(index);
        if (!contact || !input::apply_lsp_touch_state(
                          *platform_,
                          touch.prefix.device_id,
                          touch.prefix.instance_generation,
                          contact.value.contact_id,
                          contact.value.active,
                          contact.value.x,
                          contact.value.y,
                          contact.value.pressure,
                          contact.value.major,
                          contact.value.minor,
                          contact.value.orientation
                        )) {
          return false;
        }
      }
      return true;
    }

    /** @brief Apply one validated absolute pen body. */
    [[nodiscard]] bool apply_pen_state(const input_plane::pen_state_payload &pen) noexcept {
      return input::apply_lsp_pen_state(
        *platform_,
        pen.prefix.device_id,
        pen.prefix.instance_generation,
        pen.in_range,
        pen.contact,
        pen.eraser,
        pen.buttons,
        pen.x,
        pen.y,
        pen.pressure,
        pen.tilt_x,
        pen.tilt_y,
        pen.rotation,
        pen.distance,
        pen.contact_id
      );
    }

    /** @brief Apply one fully validated baseline after resetting every prior platform contribution. */
    [[nodiscard]] bool install_platform_baseline_locked(
      const InputSessionMapping &mapping,
      const input_plane::parsed_input_baseline &baseline
    ) noexcept {
      input::neutralize_lsp_platform_input(*platform_);
      pointers_ = {};
      controller_generations_ = {};
      controller_ordinals_ = {};
      controller_touches_ = {};
      controller_touches_ = {};
      text_barrier_edge_id_ = baseline.text_barrier_edge_id;
      highest_accepted_state_ = 1;
      highest_applied_state_ = 1;

      for (std::size_t index = 0; index < baseline.record_count; ++index) {
        const auto record = baseline.record(index);
        highest_accepted_state_ = std::max(highest_accepted_state_, record.header.state_sequence);
        highest_applied_state_ = std::max(highest_applied_state_, record.header.state_sequence);
        if (record.header.kind == input_plane::baseline_record_kind::core) {
          const auto core = input_plane::parse_core_state_payload(record.payload);
          if (!core || !apply_core_state(core.value)) {
            return false;
          }
          text_barrier_edge_id_ = core.value.text_barrier_edge_id;
          continue;
        }
        if (record.header.kind != input_plane::baseline_record_kind::device_lifecycle) {
          continue;
        }
        input_plane::device_lifecycle_payload lifecycle;
        if (input_plane::parse_device_lifecycle_payload(record.payload, lifecycle) != input_plane::wire_error::none) {
          return false;
        }
        if (lifecycle.presence != input_plane::device_presence::active) {
          continue;
        }
        if (lifecycle.device == input_plane::device_type::controller) {
          if (record.header.device_id > controller_generations_.size() ||
              !input::arrive_lsp_controller(
                *platform_,
                mapping.input_generation,
                record.header.device_id,
                record.header.instance_generation,
                0
              )) {
            return false;
          }
          controller_generations_[record.header.device_id - 1U] = record.header.instance_generation;
          controller_output_.bind(record.header.device_id, record.header.instance_generation);
        }
      }

      for (std::size_t index = 0; index < baseline.record_count; ++index) {
        const auto record = baseline.record(index);
        switch (record.header.kind) {
          case input_plane::baseline_record_kind::core:
          case input_plane::baseline_record_kind::device_lifecycle:
            break;
          case input_plane::baseline_record_kind::pointer:
            {
              const auto pointer = input_plane::parse_pointer_payload(record.payload);
              if (!pointer || record.header.device_id == 0 || record.header.device_id > pointers_.size()) {
                return false;
              }
              if (pointer.value.mode == input_plane::pointer_flag::absolute &&
                  !input::apply_lsp_absolute_pointer(
                    *platform_,
                    pointer.value.absolute_x,
                    pointer.value.absolute_y,
                    0,
                    0
                  )) {
                return false;
              }
              pointers_[record.header.device_id - 1U] = {
                .id = record.header.device_id,
                .instance_generation = pointer.value.instance_generation,
                .physical_ordinal = pointer.value.physical_ordinal,
                .state_sequence = record.header.state_sequence,
                .mode = pointer.value.mode,
                .cumulative_x = pointer.value.cumulative_x,
                .cumulative_y = pointer.value.cumulative_y,
                .vertical_scroll = pointer.value.cumulative_vertical_scroll,
                .horizontal_scroll = pointer.value.cumulative_horizontal_scroll,
                .absolute_x = pointer.value.absolute_x,
                .absolute_y = pointer.value.absolute_y,
              };
              break;
            }
          case input_plane::baseline_record_kind::controller:
            {
              const auto controller = input_plane::parse_controller_state_payload(record.payload);
              if (!controller || !apply_controller_state(mapping, controller.value)) {
                return false;
              }
              break;
            }
          case input_plane::baseline_record_kind::controller_sensor:
            {
              const auto sensor = input_plane::parse_controller_sensor_payload(record.payload);
              if (!sensor || !apply_controller_sensor(mapping, sensor.value)) {
                return false;
              }
              break;
            }
          case input_plane::baseline_record_kind::touch:
            {
              const auto touch = input_plane::parse_touch_state_payload(record.payload);
              if (!touch) {
                return false;
              }
              for (std::size_t contact_index = 0; contact_index < touch.contact_count; ++contact_index) {
                const auto contact = touch.contact(contact_index);
                if (!contact || !input::apply_lsp_touch_lifecycle(
                                  *platform_,
                                  touch.prefix.device_id,
                                  touch.prefix.instance_generation,
                                  contact.value.contact_id,
                                  1
                                )) {
                  return false;
                }
              }
              if (!apply_touch_state(touch)) {
                return false;
              }
              break;
            }
          case input_plane::baseline_record_kind::pen:
            {
              const auto pen = input_plane::parse_pen_state_payload(record.payload);
              if (!pen) {
                return false;
              }
              if (pen.value.in_range && !input::apply_lsp_pen_lifecycle(
                                          *platform_,
                                          pen.value.prefix.device_id,
                                          pen.value.prefix.instance_generation,
                                          1
                                        )) {
                return false;
              }
              if (pen.value.in_range && !apply_pen_state(pen.value)) {
                return false;
              }
              break;
            }
        }
      }
      return true;
    }

    /** @brief Return the physical ordinal carried by one validated replaceable packet. */
    [[nodiscard]] static std::optional<std::uint64_t> physical_ordinal(
      const input_plane::parsed_packet &packet
    ) noexcept {
      std::uint64_t ordinal = 0;
      return input_plane::state_physical_ordinal(packet, ordinal) ? std::optional {ordinal} : std::nullopt;
    }

    /** @brief Find or allocate bounded progress for one exact supersession key. */
    [[nodiscard]] StateProgress *state_progress(
      const input_plane::supersession_key &key,
      const bool create
    ) noexcept {
      StateProgress *empty = nullptr;
      for (auto &entry : state_progress_) {
        if (entry.occupied && entry.key == key) {
          return &entry;
        }
        if (!entry.occupied && empty == nullptr) {
          empty = &entry;
        }
      }
      if (!create || empty == nullptr) {
        return nullptr;
      }
      empty->key = key;
      empty->occupied = true;
      return empty;
    }

    /** @brief Schedule a neutral safety reset and fresh baseline request without dropping mapping authority. */
    void request_baseline_locked(
      const InputSessionMapping &mapping,
      const std::uint64_t received_at_microseconds
    ) noexcept {
      if (!mapping_ || *mapping_ != mapping) {
        return;
      }
      latest_states_.clear();
      state_progress_ = {};
      edge_deadlines_ = {};
      baseline_.reset();
      baseline_edge_watermark_ = 0;
      baseline_receive_time_ = received_at_microseconds;
      baseline_work_pending_ = false;
      baseline_authorization_pending_ = false;
      state_work_pending_ = false;
      edge_work_pending_ = false;
      safety_reset_pending_ = true;
    }

    /** @brief Retain one authenticated baseline part directly in the multipart assembler. */
    void classify_baseline_locked(
      const InputSessionMapping &mapping,
      const input_plane::parsed_packet &packet,
      const std::uint64_t received_at_microseconds
    ) noexcept {
      const auto part = input_plane::parse_baseline_part(packet.payload, packet.header.object_id);
      if (!part) {
        request_baseline_locked(mapping, received_at_microseconds);
        return;
      }
      if (baseline_.baseline_id() == 0) {
        baseline_edge_watermark_ = packet.header.edge_watermark;
      } else if (packet.header.edge_watermark != baseline_edge_watermark_) {
        request_baseline_locked(mapping, received_at_microseconds);
        return;
      }
      const auto added = baseline_.add(packet.header, part.value);
      if (added == input_plane::baseline_result::duplicate && baseline_.committed()) {
        schedule_ack(mapping, received_at_microseconds, monotonic_microseconds(), true);
        return;
      }
      if (added != input_plane::baseline_result::accepted && added != input_plane::baseline_result::duplicate) {
        request_baseline_locked(mapping, received_at_microseconds);
        return;
      }
      baseline_receive_time_ = received_at_microseconds;
      baseline_work_pending_ = baseline_.complete() && !baseline_.committed();
    }

    /** @brief Retain validated exactly-once edges and attach bounded host application deadlines. */
    void classify_edges_locked(
      const InputSessionMapping &mapping,
      const input_plane::parsed_packet &packet,
      const std::uint64_t received_at_microseconds
    ) noexcept {
      if (!baseline_.committed()) {
        request_baseline_locked(mapping, received_at_microseconds);
        return;
      }
      const auto batch = input_plane::parse_edge_batch(packet.payload, packet.header.object_id);
      if (!batch) {
        request_baseline_locked(mapping, received_at_microseconds);
        return;
      }
      const auto result = edges_.admit(packet);
      if (result != input_plane::edge_receive_result::accepted && result != input_plane::edge_receive_result::duplicate) {
        request_baseline_locked(mapping, received_at_microseconds);
        return;
      }
      schedule_ack(mapping, received_at_microseconds, monotonic_microseconds(), true);
      const auto deadline = received_at_microseconds >
                                std::numeric_limits<std::uint64_t>::max() - edge_application_deadline_microseconds ?
                              std::numeric_limits<std::uint64_t>::max() :
                              received_at_microseconds + edge_application_deadline_microseconds;
      for (std::size_t index = 0; index < batch.count; ++index) {
        const auto edge = batch.edge(index);
        if (!edge || edge.value.edge_id <= edges_.applied_through()) {
          continue;
        }
        auto &retained = edge_deadlines_[edge.value.edge_id % edge_deadlines_.size()];
        if (retained.edge_id != edge.value.edge_id) {
          retained = {.edge_id = edge.value.edge_id, .deadline_microseconds = deadline};
        }
      }
      edge_work_pending_ = true;
      edge_receive_time_ = received_at_microseconds;
    }

    /** @brief Retain only the newest authenticated replaceable value for one exact key. */
    void classify_state_locked(
      const InputSessionMapping &mapping,
      const input_plane::parsed_packet &packet,
      const std::uint64_t received_at_microseconds
    ) noexcept {
      if (!baseline_.committed()) {
        request_baseline_locked(mapping, received_at_microseconds);
        return;
      }
      input_plane::supersession_key key;
      const auto ordinal = physical_ordinal(packet);
      if (!ordinal || input_plane::make_supersession_key(packet, key) != input_plane::supersession_key_result::success) {
        request_baseline_locked(mapping, received_at_microseconds);
        return;
      }
      auto *progress = state_progress(key, true);
      if (progress == nullptr) {
        return;
      }
      if (packet.header.state_sequence <= progress->accepted_sequence ||
          (*ordinal != 0 && *ordinal <= progress->accepted_ordinal)) {
        return;
      }
      const auto stored = latest_states_.put(packet);
      if (stored == input_plane::latest_state_result::full) {
        return;
      }
      if (stored != input_plane::latest_state_result::stored) {
        if (stored == input_plane::latest_state_result::malformed ||
            stored == input_plane::latest_state_result::payload_too_large ||
            stored == input_plane::latest_state_result::baseline_conflict ||
            stored == input_plane::latest_state_result::inactive_lifecycle) {
          request_baseline_locked(mapping, received_at_microseconds);
        }
        return;
      }
      progress->accepted_sequence = packet.header.state_sequence;
      progress->accepted_ordinal = *ordinal;
      progress->received_at_microseconds = received_at_microseconds;
      highest_accepted_state_ = std::max(highest_accepted_state_, packet.header.state_sequence);
      state_work_pending_ = true;
    }

    void run(const std::stop_token stop_token) noexcept {
      while (!stop_token.stop_requested()) {
        input_plane::baseline_receiver candidate;
        InputSessionMapping candidate_mapping;
        std::uint64_t candidate_received_at = 0;
        std::uint64_t candidate_edge_watermark = 0;
        bool baseline_candidate = false;
        std::optional<InputSessionMapping> acknowledged;
        {
          std::unique_lock lock(mutex_);
          const auto wait = ack_pending_ ? std::chrono::microseconds {125} : std::chrono::microseconds {1'000};
          condition_.wait_for(lock, wait, [&]() {
            return stop_token.stop_requested() || safety_reset_pending_ || baseline_work_pending_ ||
                   edge_work_pending_ || state_work_pending_;
          });
          if (stop_token.stop_requested()) {
            return;
          }
          if (mapping_ && safety_reset_pending_) {
            apply_safety_reset_locked(*mapping_, baseline_receive_time_);
          }
          if (mapping_ && baseline_work_pending_ && baseline_.complete() && !baseline_.committed()) {
            candidate = baseline_;
            candidate_mapping = *mapping_;
            candidate_received_at = baseline_receive_time_;
            candidate_edge_watermark = baseline_edge_watermark_;
            baseline_work_pending_ = false;
            baseline_candidate = true;
          } else if (mapping_) {
            drain_retained_edges_locked(*mapping_);
            drain_latest_states_locked(*mapping_);
            enforce_edge_deadlines_locked(*mapping_, monotonic_microseconds());
          }
          if (mapping_) {
            (void) ensure_regular_compound(*mapping_);
          }
          acknowledged = flush_pending_ack(monotonic_microseconds());
        }
        notify_baseline_acknowledged(acknowledged);
        if (baseline_candidate) {
          complete_baseline(
            candidate_mapping,
            candidate,
            candidate_edge_watermark,
            candidate_received_at
          );
        }
        retry_controller_commands();
      }
    }

    /** @brief Neutralize only when the failing candidate still owns the exact installed generation. */
    void neutralize_if_current(const InputSessionMapping &mapping) noexcept {
      std::scoped_lock lock(mutex_);
      if (mapping_ && *mapping_ == mapping) {
        neutralize_locked();
      }
    }

    /** @brief Verify, authorize, and atomically install one complete retained baseline snapshot. */
    void complete_baseline(
      const InputSessionMapping &mapping,
      input_plane::baseline_receiver candidate,
      const std::uint64_t edge_watermark,
      const std::uint64_t received_at
    ) noexcept {
      if (candidate.commit(verifier_) != input_plane::baseline_result::committed) {
        std::scoped_lock lock(mutex_);
        if (mapping_ && *mapping_ == mapping) {
          request_baseline_locked(mapping, received_at);
        }
        return;
      }
      const auto parsed_baseline = candidate.committed_baseline();
      if (!parsed_baseline || parsed_baseline.edge_watermark != edge_watermark) {
        neutralize_if_current(mapping);
        return;
      }
      {
        std::scoped_lock lock(mutex_);
        if (!mapping_ || *mapping_ != mapping || baseline_.baseline_id() != candidate.baseline_id() || baseline_.committed()) {
          return;
        }
        if (latest_states_.install_baseline(parsed_baseline, mapping.input_generation) !=
            input_plane::baseline_install_result::installed) {
          request_baseline_locked(mapping, received_at);
          return;
        }
        controller_output_.reset(mapping.input_generation);
        controller_latest_ = {};
        next_controller_sequence_ = 1;
        if (!install_platform_baseline_locked(mapping, parsed_baseline)) {
          input::neutralize_lsp_platform_input(*platform_);
          request_baseline_locked(mapping, received_at);
          return;
        }
        baseline_ = candidate;
        edges_.reset(mapping.input_generation, parsed_baseline.edge_watermark);
        edges_.activate_baseline();
        state_progress_ = {};
        edge_deadlines_ = {};
        baseline_requested_ = false;
        baseline_authorization_pending_ = true;
      }

      const auto authorized = callbacks_.baseline_committed(
        callbacks_.context,
        mapping.peer,
        mapping.session_generation,
        mapping.input_generation
      );
      if (!authorized) {
        neutralize_if_current(mapping);
        return;
      }

      std::scoped_lock lock(mutex_);
      if (!mapping_ || *mapping_ != mapping || baseline_.baseline_id() != candidate.baseline_id() ||
          !baseline_.committed() || !baseline_authorization_pending_) {
        return;
      }
      baseline_authorization_pending_ = false;
      schedule_ack(mapping, received_at, monotonic_microseconds(), true);
      condition_.notify_all();
    }

    /** @brief Apply every contiguous retained edge exactly once on the input worker. */
    void drain_retained_edges_locked(const InputSessionMapping &mapping) noexcept {
      const auto applied = edges_.drain([this, &mapping](const input_plane::edge_record &edge) noexcept {
        bool accepted = false;
        switch (edge.kind) {
          case input_plane::edge_kind::key_down:
          case input_plane::edge_kind::key_up:
            accepted = input::apply_lsp_key(*platform_, edge.control_id, edge.kind == input_plane::edge_kind::key_up);
            break;
          case input_plane::edge_kind::pointer_button_down:
          case input_plane::edge_kind::pointer_button_up:
            accepted = input::apply_lsp_pointer_button(
              *platform_,
              edge.control_id,
              edge.kind == input_plane::edge_kind::pointer_button_up
            );
            break;
          case input_plane::edge_kind::controller_arrival:
            if (edge.device_id > controller_generations_.size() || edge.control_id > std::numeric_limits<std::uint8_t>::max() ||
                !input::arrive_lsp_controller(
                  *platform_,
                  mapping.input_generation,
                  edge.device_id,
                  edge.instance_generation,
                  static_cast<std::uint8_t>(edge.control_id)
                )) {
              return false;
            }
            controller_generations_[edge.device_id - 1] = edge.instance_generation;
            controller_output_.bind(edge.device_id, edge.instance_generation);
            {
              const auto lifecycle = latest_states_.observe_lifecycle(
                input_plane::device_type::controller,
                edge.device_id,
                edge.instance_generation,
                input_plane::device_presence::active
              );
              accepted = lifecycle == input_plane::lifecycle_generation_result::advanced ||
                         lifecycle == input_plane::lifecycle_generation_result::duplicate;
              if (!accepted) {
                (void) input::remove_lsp_controller(*platform_, edge.device_id, edge.instance_generation);
                controller_output_.remove(edge.device_id, edge.instance_generation);
                controller_generations_[edge.device_id - 1] = 0;
              }
            }
            break;
          case input_plane::edge_kind::controller_removal:
            if (!input::remove_lsp_controller(*platform_, edge.device_id, edge.instance_generation)) {
              return false;
            }
            controller_output_.remove(edge.device_id, edge.instance_generation);
            controller_generations_[edge.device_id - 1] = 0;
            for (auto &rate : device_rates_) {
              if (rate.active && rate.device_id == edge.device_id &&
                  rate.instance_generation == edge.instance_generation &&
                  (rate.device_type == InputRateDeviceType::controller ||
                   rate.device_type == InputRateDeviceType::sensor)) {
                rate = {};
              }
            }
            {
              const auto lifecycle = latest_states_.observe_lifecycle(
                input_plane::device_type::controller,
                edge.device_id,
                edge.instance_generation,
                input_plane::device_presence::removed
              );
              accepted = lifecycle == input_plane::lifecycle_generation_result::advanced ||
                         lifecycle == input_plane::lifecycle_generation_result::duplicate;
            }
            break;
          case input_plane::edge_kind::controller_button_down:
          case input_plane::edge_kind::controller_button_up:
            accepted = input::apply_lsp_controller_button(
              *platform_,
              edge.device_id,
              edge.instance_generation,
              edge.control_id,
              edge.kind == input_plane::edge_kind::controller_button_up
            );
            break;
          case input_plane::edge_kind::touch_begin:
          case input_plane::edge_kind::touch_end:
          case input_plane::edge_kind::touch_cancel:
            accepted = input::apply_lsp_touch_lifecycle(
              *platform_,
              edge.device_id,
              edge.instance_generation,
              edge.control_id,
              edge.kind == input_plane::edge_kind::touch_begin ? 1U :
                                                                 (edge.kind == input_plane::edge_kind::touch_end ? 2U : 4U)
            );
            break;
          case input_plane::edge_kind::pen_begin:
          case input_plane::edge_kind::pen_end:
          case input_plane::edge_kind::pen_cancel:
            accepted = input::apply_lsp_pen_lifecycle(
              *platform_,
              edge.device_id,
              edge.instance_generation,
              edge.kind == input_plane::edge_kind::pen_begin ? 1U :
                                                               (edge.kind == input_plane::edge_kind::pen_end ? 2U : 4U)
            );
            break;
          default:
            return false;
        }
        if (accepted) {
          auto &deadline = edge_deadlines_[edge.edge_id % edge_deadlines_.size()];
          if (deadline.edge_id == edge.edge_id) {
            deadline = {};
          }
        }
        return accepted;
      });
      if (applied != 0) {
        condition_.notify_all();
        schedule_ack(
          mapping,
          edge_receive_time_,
          monotonic_microseconds(),
          true,
          applied
        );
        condition_.notify_all();
      }
      if (edges_.applied_through() != std::numeric_limits<std::uint64_t>::max()) {
        const auto next = edges_.applied_through() + 1U;
        const auto &blocked = edge_deadlines_[next % edge_deadlines_.size()];
        if (blocked.edge_id == next) {
          request_baseline_locked(mapping, edge_receive_time_);
        }
      }
      edge_work_pending_ = false;
    }

    /** @brief Apply every watermark-ready newest state in global sequence order. */
    void drain_latest_states_locked(const InputSessionMapping &mapping) noexcept {
      (void) latest_states_.drain_ready(
        edges_.applied_through(),
        [this, &mapping](
          const input_plane::common_header &header,
          const input_plane::supersession_key &key,
          const std::span<const std::uint8_t> payload
        ) noexcept {
          auto *progress = state_progress(key, false);
          if (progress == nullptr || header.state_sequence != progress->accepted_sequence) {
            return true;
          }
          const input_plane::parsed_packet packet {
            .header = header,
            .payload = payload,
          };
          latest_apply_succeeded_ = false;
          switch (header.kind) {
            case input_plane::packet_kind::pointer_motion:
              process_pointer(mapping, packet, progress->received_at_microseconds);
              break;
            case input_plane::packet_kind::core_state:
              process_reconciliation(mapping, packet, progress->received_at_microseconds);
              break;
            case input_plane::packet_kind::device_state:
              process_device_state(mapping, packet, progress->received_at_microseconds);
              break;
            case input_plane::packet_kind::sensor_state:
              process_sensor(mapping, packet, progress->received_at_microseconds);
              break;
            case input_plane::packet_kind::edge_batch:
            case input_plane::packet_kind::baseline_part:
              request_baseline_locked(mapping, progress->received_at_microseconds);
              return true;
          }
          if (!latest_apply_succeeded_) {
            request_baseline_locked(mapping, progress->received_at_microseconds);
            return true;
          }
          progress->applied_sequence = header.state_sequence;
          progress->applied_ordinal = progress->accepted_ordinal;
          return true;
        }
      );
      state_work_pending_ = false;
    }

    /** @brief Neutralize ambiguous input and emit an urgent baseline request without losing mapping. */
    void apply_safety_reset_locked(
      const InputSessionMapping &mapping,
      const std::uint64_t received_at_microseconds
    ) noexcept {
      input::neutralize_lsp_platform_input(*platform_);
      baseline_.reset();
      baseline_edge_watermark_ = 0;
      edges_.reset(mapping.input_generation);
      latest_states_.clear();
      state_progress_ = {};
      edge_deadlines_ = {};
      pointers_ = {};
      controller_generations_ = {};
      controller_ordinals_ = {};
      controller_output_.reset(mapping.input_generation);
      controller_latest_ = {};
      next_controller_sequence_ = 1;
      baseline_acknowledged_id_ = 0;
      text_barrier_edge_id_ = 0;
      baseline_requested_ = true;
      safety_reset_pending_ = false;
      schedule_ack(mapping, received_at_microseconds, monotonic_microseconds(), true);
    }

    /** @brief Request a fresh baseline when any retained exactly-once edge misses its host deadline. */
    void enforce_edge_deadlines_locked(
      const InputSessionMapping &mapping,
      const std::uint64_t now_microseconds
    ) noexcept {
      for (const auto &edge : edge_deadlines_) {
        if (edge.edge_id != 0 && edge.deadline_microseconds <= now_microseconds) {
          request_baseline_locked(mapping, edge_receive_time_);
          return;
        }
      }
    }

    void process_pointer(
      const InputSessionMapping &mapping,
      const input_plane::parsed_packet &packet,
      const std::uint64_t received_at
    ) noexcept {
      const auto parsed = input_plane::parse_pointer_payload(packet.payload);
      if (!parsed || packet.header.object_id == 0 || packet.header.object_id > pointers_.size()) {
        return;
      }
      auto &pointer = pointers_[packet.header.object_id - 1U];
      const auto &value = parsed.value;
      if ((pointer.id != 0 && pointer.instance_generation != value.instance_generation) ||
          value.physical_ordinal <= pointer.physical_ordinal) {
        return;
      }
      std::int64_t delta_x = 0;
      std::int64_t delta_y = 0;
      std::int64_t vertical = 0;
      std::int64_t horizontal = 0;
      if (!difference(value.cumulative_vertical_scroll, pointer.vertical_scroll, vertical) ||
          !difference(value.cumulative_horizontal_scroll, pointer.horizontal_scroll, horizontal)) {
        return;
      }
      if (value.mode == input_plane::pointer_flag::relative) {
        if (!difference(value.cumulative_x, pointer.cumulative_x, delta_x) ||
            !difference(value.cumulative_y, pointer.cumulative_y, delta_y) ||
            !input::apply_lsp_pointer(*platform_, delta_x, delta_y, vertical, horizontal)) {
          return;
        }
      } else if (!input::apply_lsp_absolute_pointer(
                   *platform_,
                   value.absolute_x,
                   value.absolute_y,
                   vertical,
                   horizontal
                 )) {
        return;
      }
      pointer = {
        .id = static_cast<std::uint32_t>(packet.header.object_id),
        .instance_generation = value.instance_generation,
        .physical_ordinal = value.physical_ordinal,
        .state_sequence = packet.header.state_sequence,
        .mode = value.mode,
        .cumulative_x = value.cumulative_x,
        .cumulative_y = value.cumulative_y,
        .vertical_scroll = value.cumulative_vertical_scroll,
        .horizontal_scroll = value.cumulative_horizontal_scroll,
        .absolute_x = value.absolute_x,
        .absolute_y = value.absolute_y,
      };
      highest_applied_state_ = std::max(highest_applied_state_, packet.header.state_sequence);
      latest_apply_succeeded_ = true;
      schedule_ack(mapping, received_at, monotonic_microseconds(), false);
    }

    void process_device_state(
      const InputSessionMapping &mapping,
      const input_plane::parsed_packet &packet,
      const std::uint64_t received_at
    ) noexcept {
      const auto prefix = input_plane::parse_device_prefix(packet.payload);
      if (!prefix) {
        return;
      }
      bool applied = false;
      switch (prefix.value.device) {
        case input_plane::device_type::controller:
          {
            const auto controller = input_plane::parse_controller_state_payload(packet.payload);
            applied = controller && apply_controller_state(mapping, controller.value);
            break;
          }
        case input_plane::device_type::touch:
          {
            const auto touch = input_plane::parse_touch_state_payload(packet.payload);
            applied = touch && apply_touch_state(touch);
            break;
          }
        case input_plane::device_type::pen:
          {
            const auto pen = input_plane::parse_pen_state_payload(packet.payload);
            applied = pen && apply_pen_state(pen.value);
            break;
          }
        case input_plane::device_type::keyboard:
        case input_plane::device_type::pointer:
          break;
      }
      if (applied) {
        highest_applied_state_ = std::max(highest_applied_state_, packet.header.state_sequence);
        latest_apply_succeeded_ = true;
        schedule_ack(mapping, received_at, monotonic_microseconds(), false);
      }
    }

    void process_sensor(
      const InputSessionMapping &mapping,
      const input_plane::parsed_packet &packet,
      const std::uint64_t received_at
    ) noexcept {
      const auto sensor = input_plane::parse_controller_sensor_payload(packet.payload);
      if (sensor && apply_controller_sensor(mapping, sensor.value)) {
        highest_accepted_state_ = std::max(highest_accepted_state_, packet.header.state_sequence);
        highest_applied_state_ = std::max(highest_applied_state_, packet.header.state_sequence);
        latest_apply_succeeded_ = true;
        schedule_ack(mapping, received_at, monotonic_microseconds(), false);
      }
    }

    void process_reconciliation(
      const InputSessionMapping &mapping,
      const input_plane::parsed_packet &packet,
      const std::uint64_t received_at
    ) noexcept {
      const auto core = input_plane::parse_core_state_payload(packet.payload);
      if (!core || !apply_core_state(core.value)) {
        return;
      }
      text_barrier_edge_id_ = core.value.text_barrier_edge_id;
      highest_accepted_state_ = std::max(highest_accepted_state_, packet.header.state_sequence);
      highest_applied_state_ = std::max(highest_applied_state_, packet.header.state_sequence);
      latest_apply_succeeded_ = true;
      schedule_ack(mapping, received_at, monotonic_microseconds(), false);
    }

    /** @brief Record one applied input update and emit it at the exact LSPI cadence when due. */
    void schedule_ack(
      const InputSessionMapping &mapping,
      const std::uint64_t receive_time,
      const std::uint64_t apply_time,
      const bool urgent,
      const std::size_t records = 1
    ) noexcept {
      if (!mapping_ || *mapping_ != mapping || records == 0) {
        return;
      }
      if (receive_time != 0 && apply_time >= receive_time) {
        const auto latency = apply_time - receive_time;
        latest_apply_latency_microseconds_.store(latency, std::memory_order_relaxed);
        apply_latency_samples_.fetch_add(1, std::memory_order_relaxed);
        auto maximum = maximum_apply_latency_microseconds_.load(std::memory_order_relaxed);
        while (maximum < latency && !maximum_apply_latency_microseconds_.compare_exchange_weak(
                                      maximum,
                                      latency,
                                      std::memory_order_relaxed
                                    )) {
        }
      }
      if (urgent) {
        if (baseline_.committed()) {
          ack_scheduler_.baseline_committed();
        } else {
          ack_scheduler_.edge_applied();
        }
      }
      const auto ordinary_records = urgent ? records - 1U : records;
      for (std::size_t index = 0; index < ordinary_records; ++index) {
        ack_scheduler_.state_applied();
      }
      if (!ack_pending_) {
        ack_pending_since_ = apply_time;
      }
      ack_pending_records_ = static_cast<std::uint8_t>(
        std::min<std::size_t>(
          std::numeric_limits<std::uint8_t>::max(),
          std::size_t {ack_pending_records_} + records
        )
      );
      ack_urgent_ = ack_urgent_ || urgent;
      ack_pending_ = true;
      ack_mapping_ = mapping;
      ack_receive_time_ = receive_time;
      ack_apply_time_ = apply_time;
    }

    /**
     * @brief Send due LSPI state and return the first admitted baseline ACK mapping.
     *
     * @param now Current monotonic scheduler time.
     * @return Mapping whose baseline ACK entered aggregate output, or no value.
     */
    [[nodiscard]] std::optional<InputSessionMapping> flush_pending_ack(const std::uint64_t now) noexcept {
      const auto ordinary_due = ack_pending_records_ >= 8U ||
                                (now >= ack_pending_since_ && now - ack_pending_since_ >= 1'000U);
      if (!ack_pending_ || !mapping_ || *mapping_ != ack_mapping_ || (!ack_urgent_ && !ordinary_due) ||
          !ack_scheduler_.due(now)) {
        return std::nullopt;
      }
      if (send_ack(ack_mapping_, ack_receive_time_, ack_apply_time_)) {
        ack_scheduler_.mark_sent(now);
        ack_pending_ = false;
        ack_pending_since_ = 0;
        ack_pending_records_ = 0;
        ack_urgent_ = false;
        if (baseline_.committed() && baseline_.baseline_id() != baseline_acknowledged_id_) {
          baseline_acknowledged_id_ = baseline_.baseline_id();
          return ack_mapping_;
        }
      }
      return std::nullopt;
    }

    /**
     * @brief Notify host lifecycle outside the input-owner lock after baseline ACK admission.
     *
     * @param mapping Acknowledged mapping returned by `flush_pending_ack()`, or no value.
     */
    void notify_baseline_acknowledged(const std::optional<InputSessionMapping> &mapping) noexcept {
      if (mapping && callbacks_.baseline_acknowledged) {
        callbacks_.baseline_acknowledged(
          callbacks_.context,
          mapping->peer,
          mapping->session_generation,
          mapping->input_generation
        );
      }
    }

    /** @brief Protect and submit the regular RR/CNAME prerequisite exactly once per mapping. */
    [[nodiscard]] bool ensure_regular_compound(const InputSessionMapping &mapping) noexcept {
      const auto token = mapping_token(mapping);
      if (!mapping_ || *mapping_ != mapping || token == 0 || !mapping.rtcp_cname.valid() ||
          compound_gate_.token() != token) {
        return false;
      }
      if (compound_gate_.reduced_size_allowed(token)) {
        return true;
      }
      if (compound_gate_.submission_pending()) {
        return false;
      }
      auto lease = mapping.forward_path->acquire(HostForwardLane::input_feedback);
      if (!lease || lease->storage.size() < 12U) {
        return false;
      }
      const auto total = write_input_feedback_compound_report(
        lease->storage,
        mapping.acknowledgement_ssrc,
        mapping.rtcp_cname
      );
      if (total == 0) {
        return false;
      }
      std::size_t protected_bytes = 0;
      if (!srtp_.protect_in_place(mapping.peer, SecurePacketClass::rtcp, lease->storage, total, protected_bytes)) {
        return false;
      }
      if (!compound_gate_.begin_submission(token)) {
        return false;
      }
      const auto now = monotonic_microseconds();
      const auto deadline = now > std::numeric_limits<std::uint64_t>::max() - 20'000U ?
                              std::numeric_limits<std::uint64_t>::max() :
                              now + 20'000U;
      if (mapping.forward_path->commit(
            *lease,
            protected_bytes,
            deadline,
            token,
            completion_target()
          ) != HostForwardSubmitResult::accepted) {
        compound_gate_.cancel_submission(token);
        return false;
      }
      return compound_gate_.reduced_size_allowed(token);
    }

    /** @brief Serialize, protect once, and commit one current LSPI acknowledgement. */
    [[nodiscard]] bool send_ack(
      const InputSessionMapping &mapping,
      const std::uint64_t receive_time,
      const std::uint64_t apply_time
    ) noexcept {
      if (!ensure_regular_compound(mapping)) {
        return false;
      }
      input_plane::lspi_ack ack {
        .input_generation = mapping.input_generation,
        .flags = static_cast<std::uint8_t>(
          baseline_requested_ ? static_cast<std::uint8_t>(input_plane::lspi_flag::baseline_requested) : 0U
        ),
        .accepted_baseline_id = baseline_.committed() ? baseline_.baseline_id() : 0,
        .highest_accepted_state_sequence = highest_accepted_state_,
        .highest_applied_state_sequence = highest_applied_state_,
        .contiguous_edge_id = edges_.applied_through(),
        .edge_reception_bitmap = edges_.reception_bitmap(),
        .host_receive_time_us = receive_time,
        .host_apply_time_us = apply_time,
      };
      for (const auto &pointer : pointers_) {
        if (pointer.physical_ordinal == 0) {
          continue;
        }
        ack.pointers[ack.pointer_count++] = {
          .pointer_id = pointer.id,
          .instance_generation = pointer.instance_generation,
          .physical_ordinal = pointer.physical_ordinal,
        };
      }
      auto lease = mapping.forward_path->acquire(HostForwardLane::input_feedback);
      if (!lease) {
        return false;
      }
      const auto payload_size = input_plane::lspi_fixed_size + std::size_t {ack.pointer_count} * input_plane::lspi_pointer_record_size;
      const auto total = 12U + payload_size;
      if (total > lease->storage.size()) {
        return false;
      }
      auto rtcp = lease->storage.first(total);
      std::ranges::fill(rtcp, 0);
      rtcp[0] = 0x80;
      rtcp[1] = 204;
      wire::write_be<std::uint16_t>(rtcp.subspan(2, 2), static_cast<std::uint16_t>(total / 4 - 1));
      wire::write_be<std::uint32_t>(rtcp.subspan(4, 4), mapping.acknowledgement_ssrc);
      std::copy(input_plane::lspi_name.begin(), input_plane::lspi_name.end(), rtcp.begin() + 8);
      if (input_plane::serialize_lspi_ack(ack, rtcp.subspan(12, payload_size)) != input_plane::lspi_error::none) {
        return false;
      }
      std::size_t protected_bytes = 0;
      if (!srtp_.protect_in_place(mapping.peer, SecurePacketClass::rtcp, lease->storage, total, protected_bytes)) {
        return false;
      }
      const auto now = monotonic_microseconds();
      const auto deadline = now > std::numeric_limits<std::uint64_t>::max() - 20'000U ?
                              std::numeric_limits<std::uint64_t>::max() :
                              now + 20'000U;
      return mapping.forward_path->commit(
               *lease,
               protected_bytes,
               deadline,
               0,
               completion_target()
             ) == HostForwardSubmitResult::accepted;
    }

    static void platform_feedback_callback(void *context, const input::lsp_controller_feedback_t &feedback) noexcept {
      static_cast<Impl *>(context)->handle_feedback(feedback.message);
    }

    /** @brief Count final-sent host input-feedback wire bytes without entering owner synchronization. */
    static void forward_completion_callback(
      void *context,
      const std::uint64_t token,
      const HostForwardLane lane,
      const HostForwardCompletion completion,
      const std::uint64_t completed_at_microseconds,
      const std::size_t protected_bytes,
      const std::uint16_t charged_bytes
    ) noexcept {
      (void) lane;
      (void) completed_at_microseconds;
      (void) protected_bytes;
      auto *self = static_cast<Impl *>(context);
      if (self != nullptr && completion == HostForwardCompletion::sent) {
        self->sent_feedback_wire_bytes_.fetch_add(charged_bytes, std::memory_order_relaxed);
      }
      if (self != nullptr && token != 0) {
        self->compound_gate_.complete(token, completion == HostForwardCompletion::sent);
        self->condition_.notify_all();
      }
    }

    /** @brief Return the exact per-slot completion target for LSPI and LSPG datagrams. */
    [[nodiscard]] HostForwardCompletionTarget completion_target() noexcept {
      return {.context = this, .completed = forward_completion_callback};
    }

    void handle_feedback(const platf::gamepad_feedback_msg_t &message) noexcept {
      std::scoped_lock lock(mutex_);
      if (!mapping_ || !mapping_->controller_output_enabled ||
          message.identity.input_generation != mapping_->input_generation ||
          message.identity.id >= controller_generations_.size()) {
        return;
      }
      const auto controller_id = static_cast<std::uint32_t>(message.identity.id) + 1U;
      if (controller_generations_[controller_id - 1] != message.identity.controller_generation) {
        return;
      }
      auto &latest = controller_latest_[controller_id - 1];
      latest.input_generation = mapping_->input_generation;
      latest.controller_id = controller_id;
      latest.instance_generation = message.identity.controller_generation;
      switch (message.type) {
        case platf::gamepad_feedback_e::rumble:
          latest.low_frequency_rumble = message.data.rumble.lowfreq;
          latest.high_frequency_rumble = message.data.rumble.highfreq;
          send_latest(latest);
          return;
        case platf::gamepad_feedback_e::set_rgb_led:
          latest.led_red = message.data.rgb_led.r;
          latest.led_green = message.data.rgb_led.g;
          latest.led_blue = message.data.rgb_led.b;
          send_latest(latest);
          return;
        case platf::gamepad_feedback_e::rumble_triggers:
          {
            std::array<std::uint8_t, 4> parameters {};
            wire::write_be<std::uint16_t>(std::span<std::uint8_t> {parameters}.first<2>(), message.data.rumble_triggers.left_trigger);
            wire::write_be<std::uint16_t>(std::span<std::uint8_t> {parameters}.subspan<2, 2>(), message.data.rumble_triggers.right_trigger);
            send_command(controller_id, message.identity.controller_generation, input_plane::controller_command_kind::haptic_waveform, parameters);
            return;
          }
        case platf::gamepad_feedback_e::set_motion_event_state:
          {
            std::array<std::uint8_t, 4> parameters {
              message.data.motion_event_state.motion_type,
              0,
              0,
              0,
            };
            wire::write_be<std::uint16_t>(std::span<std::uint8_t> {parameters}.subspan<2, 2>(), message.data.motion_event_state.report_rate);
            send_command(controller_id, message.identity.controller_generation, input_plane::controller_command_kind::motion_sensor, parameters);
            return;
          }
        case platf::gamepad_feedback_e::set_adaptive_triggers:
          {
            std::array<std::uint8_t, 23> parameters {};
            parameters[0] = message.data.adaptive_triggers.event_flags;
            parameters[1] = message.data.adaptive_triggers.type_left;
            parameters[2] = message.data.adaptive_triggers.type_right;
            std::copy(message.data.adaptive_triggers.left.begin(), message.data.adaptive_triggers.left.end(), parameters.begin() + 3);
            std::copy(message.data.adaptive_triggers.right.begin(), message.data.adaptive_triggers.right.end(), parameters.begin() + 13);
            send_command(controller_id, message.identity.controller_generation, input_plane::controller_command_kind::adaptive_trigger, parameters);
            return;
          }
      }
    }

    void send_latest(input_plane::controller_latest_state &latest) noexcept {
      if (next_controller_sequence_ == 0 || next_controller_sequence_ == std::numeric_limits<std::uint64_t>::max()) {
        return;
      }
      latest.sequence = next_controller_sequence_++;
      constexpr auto lspg_size = input_plane::lspg_header_size + 8U;
      auto lease = begin_lspg(lspg_size);
      if (lease && input_plane::serialize_controller_latest(
                     latest,
                     lease->storage.subspan(8, lspg_size)
                   ) == input_plane::lspg_error::none) {
        (void) finish_lspg(*lease, lspg_size, 0);
      }
    }

    template<std::size_t Size>
    void send_command(
      const std::uint32_t controller_id,
      const std::uint32_t instance_generation,
      const input_plane::controller_command_kind kind,
      const std::array<std::uint8_t, Size> &parameters
    ) noexcept {
      input_plane::controller_command command {
        .input_generation = mapping_->input_generation,
        .controller_id = controller_id,
        .instance_generation = instance_generation,
        .kind = kind,
        .parameter_length = static_cast<std::uint16_t>(parameters.size()),
        .deadline_us = monotonic_microseconds() + 100'000U,
      };
      std::copy(parameters.begin(), parameters.end(), command.parameters.begin());
      std::uint64_t sequence = 0;
      const auto now = monotonic_microseconds();
      if (controller_output_.enqueue_command(command, now, sequence) != input_plane::controller_output_result::accepted) {
        return;
      }
      command.sequence = sequence;
      send_controller_command(command, now);
    }

    void send_controller_command(const input_plane::controller_command &command, const std::uint64_t now) noexcept {
      const auto size = input_plane::lspg_header_size + 4U + command.parameter_length;
      auto lease = begin_lspg(size);
      if (lease && input_plane::serialize_controller_command(command, lease->storage.subspan(8, size)) == input_plane::lspg_error::none &&
          finish_lspg(*lease, size, command.deadline_us)) {
        controller_output_.mark_command_sent(command.sequence, now);
      }
    }

    void retry_controller_commands() noexcept {
      std::scoped_lock lock(mutex_);
      if (!mapping_) {
        return;
      }
      std::array<input_plane::controller_command, 8> due {};
      const auto now = monotonic_microseconds();
      const auto count = controller_output_.due_commands(now, 20'000, due);
      for (std::size_t index = 0; index < count; ++index) {
        send_controller_command(due[index], now);
      }
    }

    /** @brief Reserve and initialize one direct-write SRTCP APP envelope for LSPG. */
    [[nodiscard]] std::optional<HostForwardLease> begin_lspg(const std::size_t lspg_size) noexcept {
      if (!mapping_ || !mapping_->forward_path || !ensure_regular_compound(*mapping_)) {
        return std::nullopt;
      }
      const auto unpadded = 8U + lspg_size;
      const auto total = (unpadded + 3U) & ~std::size_t {3U};
      auto lease = mapping_->forward_path->acquire(HostForwardLane::input_feedback);
      if (!lease || total > lease->storage.size()) {
        return std::nullopt;
      }
      auto rtcp = lease->storage.first(total);
      std::ranges::fill(rtcp, 0);
      rtcp[0] = 0x80;
      rtcp[1] = 204;
      wire::write_be<std::uint16_t>(rtcp.subspan(2, 2), static_cast<std::uint16_t>(total / 4U - 1U));
      wire::write_be<std::uint32_t>(rtcp.subspan(4, 4), mapping_->acknowledgement_ssrc);
      return lease;
    }

    /** @brief Protect and commit one populated direct-write LSPG envelope. */
    bool finish_lspg(
      HostForwardLease &lease,
      const std::size_t lspg_size,
      const std::uint64_t command_deadline_microseconds
    ) noexcept {
      if (!mapping_ || !mapping_->forward_path) {
        return false;
      }
      const auto total = (8U + lspg_size + 3U) & ~std::size_t {3U};
      std::size_t protected_bytes = 0;
      if (!srtp_.protect_in_place(mapping_->peer, SecurePacketClass::rtcp, lease.storage, total, protected_bytes)) {
        return false;
      }
      const auto now = monotonic_microseconds();
      const auto default_deadline = now > std::numeric_limits<std::uint64_t>::max() - 20'000U ?
                                      std::numeric_limits<std::uint64_t>::max() :
                                      now + 20'000U;
      const auto deadline = command_deadline_microseconds == 0 ? default_deadline : command_deadline_microseconds;
      return mapping_->forward_path->commit(
               lease,
               protected_bytes,
               deadline,
               0,
               completion_target()
             ) == HostForwardSubmitResult::accepted;
    }

    InputOwnerCallbacks callbacks_;  ///< Crypto and SRTCP callbacks.
    LibsrtpServerProvider &srtp_;  ///< Association provider used only for direct in-place protection.
    DigestVerifier verifier_;  ///< Baseline SHA adapter.
    input::lsp_platform_input_ptr platform_;  ///< Existing platform-input boundary.
    mutable std::recursive_mutex mutex_;  ///< Queue, generation, and ordered state synchronization.
    std::condition_variable_any condition_;  ///< Worker wakeup.
    std::optional<InputSessionMapping> mapping_;  ///< Active START mapping.
    input_plane::baseline_receiver baseline_;  ///< Atomic multipart baseline.
    input_plane::edge_receiver edges_;  ///< Exactly-once ordered edge state.
    input_plane::latest_state_table<maximum_latest_state_keys, maximum_input_rtp_bytes> latest_states_;  ///< Per-key newest replaceable state.
    std::array<StateProgress, maximum_latest_state_keys> state_progress_ {};  ///< Per-key accepted/applied sequence and ordinal fences.
    std::array<EdgeDeadline, input_plane::edge_receiver::capacity> edge_deadlines_ {};  ///< Retained-edge host deadlines.
    std::array<PointerState, input_plane::maximum_acknowledged_pointers> pointers_ {};  ///< Per-pointer cumulative/latest application state.
    std::uint64_t highest_accepted_state_ {};  ///< Greatest retained replaceable state sequence.
    std::uint64_t highest_applied_state_ {};  ///< Greatest platform-applied state sequence.
    input_plane::controller_output_manager controller_output_;  ///< Generation-fenced LSPG output/ACK state.
    std::array<std::uint32_t, 16> controller_generations_ {};  ///< Active controller instance generations.
    std::array<DeviceRate, 64> device_rates_ {};  ///< Bounded hot-plug rate selections.
    std::array<std::uint64_t, 16> controller_ordinals_ {};  ///< Greatest applied controller samples.
    std::array<std::array<ControllerTouchState, 2>, 16> controller_touches_ {};  ///< Last complete controller touchpad state.
    std::array<input_plane::controller_latest_state, 16> controller_latest_ {};  ///< Latest rumble/LED state per controller.
    std::uint64_t next_controller_sequence_ {1};  ///< Host-to-client controller output sequence.
    input_plane::lspi_ack_scheduler ack_scheduler_;  ///< Exact 125-us/eight-record/1-ms LSPI cadence.
    InputSessionMapping ack_mapping_;  ///< Mapping owning the newest coalesced acknowledgement.
    std::uint64_t ack_receive_time_ {};  ///< Receive timestamp carried by the newest coalesced acknowledgement.
    std::uint64_t ack_apply_time_ {};  ///< Apply timestamp carried by the newest coalesced acknowledgement.
    std::uint64_t ack_pending_since_ {};  ///< First unsent ordinary record time for the one-millisecond limit.
    std::uint8_t ack_pending_records_ {};  ///< Saturating new-record count for the eight-record threshold.
    bool ack_pending_ {};  ///< Whether current acknowledgement state awaits its legal send instant.
    bool ack_urgent_ {};  ///< Whether baseline or edge state requests the earliest legal send.
    std::uint64_t baseline_acknowledged_id_ {};  ///< Last baseline whose urgent LSPI ACK entered aggregate output.
    std::uint64_t text_barrier_edge_id_ {};  ///< Greatest committed text/IME ordering barrier.
    std::uint64_t baseline_receive_time_ {};  ///< Socket receive time of the newest retained baseline part.
    std::uint64_t baseline_edge_watermark_ {};  ///< Exact common edge watermark shared by current baseline parts.
    std::uint64_t edge_receive_time_ {};  ///< Socket receive time used by the next applied edge ACK.
    bool baseline_work_pending_ {};  ///< Whether a complete baseline awaits digest and authority callbacks.
    bool baseline_authorization_pending_ {};  ///< Platform baseline applied while authority callback completes.
    bool state_work_pending_ {};  ///< Whether newest per-key state may be watermark-ready.
    bool edge_work_pending_ {};  ///< Whether retained exact-once edges may be contiguous.
    bool safety_reset_pending_ {};  ///< Whether malformed or ambiguous input requires neutralization.
    bool baseline_requested_ {};  ///< Whether LSPI must request a fresh complete baseline.
    bool latest_apply_succeeded_ {};  ///< Result of the current worker-owned latest-state dispatch.
    std::jthread worker_;  ///< Dedicated ordered platform apply owner.
    InputFeedbackCompoundGate compound_gate_;  ///< Completion-fenced RR/CNAME prerequisite.
    std::atomic<std::uint64_t> sent_feedback_wire_bytes_ {};  ///< Complete final-sent IP/UDP bytes for LSPI and LSPG.
    std::atomic<std::uint64_t> apply_latency_samples_ {};  ///< Receive-to-apply sample count.
    std::atomic<std::uint64_t> latest_apply_latency_microseconds_ {};  ///< Latest receive-to-apply duration.
    std::atomic<std::uint64_t> maximum_apply_latency_microseconds_ {};  ///< Maximum receive-to-apply duration.
    bool ready_ {};  ///< Callback/platform/worker readiness.
    bool shutting_down_ {};  ///< Permanent producer-admission closure.
  };

  InputOwner::InputOwner(
    const InputOwnerCallbacks callbacks,
    LibsrtpServerProvider &srtp
  ) noexcept:
      impl_ {new (std::nothrow) Impl {callbacks, srtp}} {
  }

  InputOwner::~InputOwner() = default;

  bool InputOwner::configure(const InputSessionMapping &mapping) noexcept {
    return impl_ && impl_->configure(mapping);
  }

  bool InputOwner::ready_for_configuration(const InputSessionMapping &mapping) const noexcept {
    return impl_ && impl_->ready_for_configuration(mapping);
  }

  void InputOwner::commit_configuration(const InputSessionMapping &mapping) noexcept {
    if (impl_) {
      impl_->commit_configuration(mapping);
    }
  }

  bool InputOwner::receive(
    const PeerEndpoint &peer,
    const std::span<const std::uint8_t> packet,
    const std::uint64_t received_at_microseconds
  ) noexcept {
    return impl_ && impl_->receive(peer, packet, received_at_microseconds);
  }

  bool InputOwner::receive_rtcp(const PeerEndpoint &peer, const std::span<const std::uint8_t> packet) noexcept {
    return impl_ && impl_->receive_rtcp(peer, packet);
  }

  void InputOwner::begin_shutdown() noexcept {
    if (impl_) {
      impl_->begin_shutdown();
    }
  }

  void InputOwner::neutralize() noexcept {
    if (impl_) {
      impl_->neutralize();
    }
  }

  std::optional<InputSessionMapping> InputOwner::mapping() const noexcept {
    return impl_ ? impl_->mapping() : std::nullopt;
  }

  /** @copydoc InputOwner::applied_watermark */
  std::pair<std::uint64_t, std::uint64_t> InputOwner::applied_watermark() const noexcept {
    return impl_ ? impl_->applied_watermark() : std::pair<std::uint64_t, std::uint64_t> {};
  }

  ControlStatus InputOwner::inject_text(
    const Identifier128 &session_id,
    const std::uint32_t input_generation,
    const std::uint64_t preceding_edge_id,
    const std::span<const std::uint8_t> utf8,
    const std::uint64_t deadline_microseconds
  ) noexcept {
    return impl_ ?
             impl_->inject_text(session_id, input_generation, preceding_edge_id, utf8, deadline_microseconds) :
             ControlStatus::internal_failure;
  }

  std::expected<InputRateResponsePayload, ControlStatus> InputOwner::configure_input_rate(
    const InputRateRequestPayload &request
  ) noexcept {
    return impl_ ? impl_->configure_input_rate(request) : std::unexpected(ControlStatus::internal_failure);
  }

  /** @copydoc InputOwner::sent_feedback_wire_bytes */
  std::uint64_t InputOwner::sent_feedback_wire_bytes() const noexcept {
    return impl_ ? impl_->sent_feedback_wire_bytes() : 0;
  }

  InputLatencySnapshot InputOwner::latency_snapshot() const noexcept {
    return impl_ ? impl_->latency_snapshot() : InputLatencySnapshot {};
  }
}  // namespace lumen::lsp::runtime
