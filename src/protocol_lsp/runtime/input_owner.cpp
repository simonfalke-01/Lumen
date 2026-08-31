/**
 * @file src/protocol_lsp/runtime/input_owner.cpp
 * @brief Bounded ordered LSP input receive and platform-apply owner.
 */

#include "input_owner.h"

#include "../../input.h"
#include "../core/packet.h"
#include "../core/rtp.h"
#include "../input_plane/feedback.h"
#include "../input_plane/state.h"
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
    constexpr std::size_t input_queue_capacity = 256;
    constexpr std::array<std::uint8_t, 4> neutral_baseline_magic {'L', 'S', 'P', 'B'};
    constexpr std::size_t neutral_baseline_size = 16;

    bool difference(const std::int64_t current, const std::int64_t previous, std::int64_t &output) noexcept {
      if ((previous > 0 && current < std::numeric_limits<std::int64_t>::min() + previous) ||
          (previous < 0 && current > std::numeric_limits<std::int64_t>::max() + previous)) {
        return false;
      }
      output = current - previous;
      return true;
    }
  }  // namespace

  bool InputSessionMapping::valid() const noexcept {
    return peer.valid() && forward_path && forward_path->ready() &&
           forward_path->generation() == connection_generation && !is_zero(client_id) &&
           connection_generation != 0 && session_generation != 0 &&
           input_generation != 0 && input_ssrc != 0 && acknowledgement_ssrc != 0 && input_ssrc != acknowledgement_ssrc &&
           input_payload_type >= 96 && input_payload_type <= 127;
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
      if (!callbacks_.verify_digest || !callbacks_.baseline_committed || !platform_) {
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
      worker_.request_stop();
      condition_.notify_all();
      if (worker_.joinable()) {
        worker_.join();
      }
      if (platform_) {
        input::neutralize_lsp_platform_input(*platform_);
      }
    }

    bool configure(const InputSessionMapping &mapping) noexcept {
      if (!ready_ || !mapping.valid()) {
        return false;
      }
      commit_configuration(mapping);
      return true;
    }

    void commit_configuration(const InputSessionMapping &mapping) noexcept {
      std::scoped_lock lock(mutex_);
      input::neutralize_lsp_platform_input(*platform_);
      head_ = 0;
      tail_ = 0;
      size_ = 0;
      mapping_ = mapping;
      baseline_.reset();
      edges_.reset(mapping.input_generation);
      pointer_ = {};
      pending_pointer_.reset();
      highest_accepted_state_ = 0;
      highest_applied_state_ = 0;
      controller_output_.reset(mapping.input_generation);
      controller_generations_ = {};
      controller_ordinals_ = {};
      controller_latest_ = {};
      touches_ = {};
      next_controller_sequence_ = 1;
      ack_scheduler_ = {};
      ack_pending_ = false;
      ack_mapping_ = {};
      ack_receive_time_ = 0;
      ack_apply_time_ = 0;
      ack_pending_since_ = 0;
      ack_pending_records_ = 0;
      ack_urgent_ = false;
    }

    bool ready_for_configuration(const InputSessionMapping &mapping) const noexcept {
      std::scoped_lock lock(mutex_);
      return ready_ && mapping.valid();
    }

    bool receive(const PeerEndpoint &peer, const std::span<const std::uint8_t> packet) noexcept {
      const auto rtp = parse_rtp_fixed_header(packet);
      if (!rtp || rtp.header.padding || rtp.header.extension || rtp.header.csrc_count != 0) {
        return false;
      }
      std::unique_lock lock(mutex_);
      if (!mapping_ || peer != mapping_->peer || rtp.header.ssrc != mapping_->input_ssrc ||
          rtp.header.payload_type != mapping_->input_payload_type) {
        return true;
      }
      if (packet.size() > maximum_input_rtp_bytes || size_ == input_queue_capacity) {
        return false;
      }
      queue_[tail_].assign(packet);
      tail_ = (tail_ + 1U) % input_queue_capacity;
      ++size_;
      lock.unlock();
      condition_.notify_one();
      return true;
    }

    void neutralize() noexcept {
      std::scoped_lock lock(mutex_);
      head_ = 0;
      tail_ = 0;
      size_ = 0;
      mapping_.reset();
      baseline_.reset();
      pointer_ = {};
      pending_pointer_.reset();
      ack_scheduler_ = {};
      ack_pending_ = false;
      ack_mapping_ = {};
      ack_pending_since_ = 0;
      ack_pending_records_ = 0;
      ack_urgent_ = false;
      input::neutralize_lsp_platform_input(*platform_);
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

    /** @brief Read exact final-sent complete IP/UDP bytes for LSPI and LSPG. */
    [[nodiscard]] std::uint64_t sent_feedback_wire_bytes() const noexcept {
      return sent_feedback_wire_bytes_.load(std::memory_order_relaxed);
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
    struct PointerState {
      std::uint32_t id {};  ///< Active pointer ID.
      std::uint32_t instance_generation {};  ///< Active pointer generation.
      std::uint64_t physical_ordinal {};  ///< Greatest applied physical ordinal.
      std::uint64_t state_sequence {};  ///< Greatest applied state sequence.
      std::int64_t cumulative_x {};  ///< Last cumulative horizontal motion.
      std::int64_t cumulative_y {};  ///< Last cumulative vertical motion.
      std::int64_t vertical_scroll {};  ///< Last cumulative vertical scrolling.
      std::int64_t horizontal_scroll {};  ///< Last cumulative horizontal scrolling.
    };

    struct PendingPointer {
      input_plane::common_header header;  ///< Watermark and state sequence.
      input_plane::pointer_payload value;  ///< Parsed cumulative state.
    };

    struct TouchState {
      std::uint32_t controller_id {};  ///< Owning controller.
      std::uint32_t instance_generation {};  ///< Exact controller generation.
      std::uint64_t physical_ordinal {};  ///< Greatest applied coordinate sample.
      float x {};  ///< Latest normalized X.
      float y {};  ///< Latest normalized Y.
      float pressure {};  ///< Latest normalized pressure.
      bool active {};  ///< Lifecycle begin has applied.
      bool submitted {};  ///< A DOWN coordinate was submitted.
    };

    void run(const std::stop_token stop_token) noexcept {
      while (!stop_token.stop_requested()) {
        packet_slab<maximum_input_rtp_bytes> packet;
        InputSessionMapping mapping;
        {
          std::unique_lock lock(mutex_);
          const auto wait = ack_pending_ ? std::chrono::microseconds {125} : std::chrono::microseconds {1'000};
          condition_.wait_for(lock, wait, [&]() {
            return stop_token.stop_requested() || size_ != 0;
          });
          if (stop_token.stop_requested()) {
            return;
          }
          if (size_ == 0) {
            flush_pending_ack(monotonic_microseconds());
            lock.unlock();
            retry_controller_commands();
            continue;
          }
          packet = queue_[head_];
          queue_[head_].clear();
          head_ = (head_ + 1U) % input_queue_capacity;
          --size_;
          if (!mapping_) {
            continue;
          }
          mapping = *mapping_;
        }
        process(mapping, packet.bytes());
        std::scoped_lock lock(mutex_);
        flush_pending_ack(monotonic_microseconds());
      }
    }

    void process(const InputSessionMapping &mapping, const std::span<const std::uint8_t> rtp_packet) noexcept {
      const auto rtp = parse_rtp_fixed_header(rtp_packet);
      if (!rtp || rtp.bytes_consumed >= rtp_packet.size()) {
        return;
      }
      const auto received_at = monotonic_microseconds();
      const auto packet = input_plane::parse_packet(rtp_packet.subspan(rtp.bytes_consumed), mapping.input_generation);
      if (!packet) {
        return;
      }
      if (packet.header.kind == input_plane::packet_kind::baseline_part) {
        process_baseline(mapping, packet, received_at);
        return;
      }
      std::scoped_lock lock(mutex_);
      if (!mapping_ || *mapping_ != mapping) {
        return;
      }
      switch (packet.header.kind) {
        case input_plane::packet_kind::baseline_part:
          break;
        case input_plane::packet_kind::edge_batch:
          process_edges(mapping, packet, received_at);
          break;
        case input_plane::packet_kind::pointer_motion:
          process_pointer(mapping, packet, received_at);
          break;
        case input_plane::packet_kind::core_state:
          process_reconciliation(mapping, packet, received_at);
          break;
        case input_plane::packet_kind::device_state:
          process_device_state(mapping, packet, received_at);
          break;
        case input_plane::packet_kind::sensor_state:
          process_sensor(mapping, packet, received_at);
          break;
      }
    }

    void process_baseline(
      const InputSessionMapping &mapping,
      const input_plane::parsed_packet &packet,
      const std::uint64_t received_at
    ) noexcept {
      const auto part = input_plane::parse_baseline_part(packet.payload, packet.header.object_id);
      if (!part) {
        return;
      }
      input_plane::baseline_receiver candidate;
      {
        std::scoped_lock lock(mutex_);
        if (!mapping_ || *mapping_ != mapping) {
          return;
        }
        const auto added = baseline_.add(packet.header, part.value);
        if (added != input_plane::baseline_result::accepted && added != input_plane::baseline_result::duplicate) {
          return;
        }
        if (added == input_plane::baseline_result::duplicate && baseline_.committed()) {
          schedule_ack(mapping, received_at, monotonic_microseconds(), true);
          return;
        }
        if (!baseline_.complete() || baseline_.committed()) {
          return;
        }
        candidate = baseline_;
      }
      if (candidate.commit(verifier_) != input_plane::baseline_result::committed) {
        return;
      }
      const auto bytes = candidate.committed_bytes();
      if (bytes.size() != neutral_baseline_size || !std::equal(neutral_baseline_magic.begin(), neutral_baseline_magic.end(), bytes.begin()) ||
          bytes[4] != wire_version || bytes[5] != 0 || bytes[6] != 0 || bytes[7] != 0) {
        neutralize();
        return;
      }
      const auto watermark = wire::read_be<std::uint64_t>(bytes.subspan(8, 8));
      if (watermark != packet.header.edge_watermark) {
        neutralize();
        return;
      }
      if (!callbacks_.baseline_committed(
            callbacks_.context,
            mapping.peer,
            mapping.session_generation,
            mapping.input_generation
          )) {
        neutralize();
        return;
      }
      std::scoped_lock lock(mutex_);
      if (!mapping_ || *mapping_ != mapping || baseline_.baseline_id() != candidate.baseline_id() || baseline_.committed()) {
        return;
      }
      baseline_ = candidate;
      input::neutralize_lsp_platform_input(*platform_);
      edges_.reset(mapping.input_generation, watermark);
      edges_.activate_baseline();
      pointer_ = {};
      highest_accepted_state_ = 1;
      highest_applied_state_ = 1;
      schedule_ack(mapping, received_at, monotonic_microseconds(), true);
    }

    void process_edges(
      const InputSessionMapping &mapping,
      const input_plane::parsed_packet &packet,
      const std::uint64_t received_at
    ) noexcept {
      const auto batch = input_plane::parse_edge_batch(packet.payload, packet.header.object_id);
      if (!batch) {
        return;
      }
      for (std::size_t index = 0; index < batch.count; ++index) {
        const auto edge = batch.edge(index).value;
        if (edge.device != input_plane::device_type::keyboard && edge.device != input_plane::device_type::pointer &&
            edge.device != input_plane::device_type::controller && edge.device != input_plane::device_type::touch) {
          return;
        }
      }
      const auto result = edges_.admit(packet);
      if (result != input_plane::edge_receive_result::accepted && result != input_plane::edge_receive_result::duplicate) {
        return;
      }
      const auto applied = edges_.drain([this](const input_plane::edge_record &edge) noexcept {
        switch (edge.kind) {
          case input_plane::edge_kind::key_down:
          case input_plane::edge_kind::key_up:
            return input::apply_lsp_key(*platform_, edge.control_id, edge.kind == input_plane::edge_kind::key_up);
          case input_plane::edge_kind::pointer_button_down:
          case input_plane::edge_kind::pointer_button_up:
            return input::apply_lsp_pointer_button(
              *platform_,
              edge.control_id,
              edge.kind == input_plane::edge_kind::pointer_button_up
            );
          case input_plane::edge_kind::controller_arrival:
            if (edge.device_id > controller_generations_.size() || edge.control_id > std::numeric_limits<std::uint8_t>::max() ||
                !input::arrive_lsp_controller(
                  *platform_,
                  mapping_->input_generation,
                  edge.device_id,
                  edge.instance_generation,
                  static_cast<std::uint8_t>(edge.control_id)
                )) {
              return false;
            }
            controller_generations_[edge.device_id - 1] = edge.instance_generation;
            controller_output_.bind(edge.device_id, edge.instance_generation);
            return true;
          case input_plane::edge_kind::controller_removal:
            if (!input::remove_lsp_controller(*platform_, edge.device_id, edge.instance_generation)) {
              return false;
            }
            controller_output_.remove(edge.device_id, edge.instance_generation);
            controller_generations_[edge.device_id - 1] = 0;
            return true;
          case input_plane::edge_kind::controller_button_down:
          case input_plane::edge_kind::controller_button_up:
            return input::apply_lsp_controller_button(
              *platform_,
              edge.device_id,
              edge.instance_generation,
              edge.control_id,
              edge.kind == input_plane::edge_kind::controller_button_up
            );
          case input_plane::edge_kind::touch_begin:
            if (edge.device_id == 0 || edge.device_id > touches_.size() || edge.control_id == 0 ||
                edge.control_id > controller_generations_.size() ||
                controller_generations_[edge.control_id - 1] != edge.instance_generation || touches_[edge.device_id - 1].active) {
              return false;
            }
            touches_[edge.device_id - 1] = {
              .controller_id = edge.control_id,
              .instance_generation = edge.instance_generation,
              .active = true,
            };
            return true;
          case input_plane::edge_kind::touch_end:
          case input_plane::edge_kind::touch_cancel:
            if (edge.device_id == 0 || edge.device_id > touches_.size()) {
              return false;
            }
            {
              auto &touch = touches_[edge.device_id - 1];
              if (!touch.active || touch.controller_id != edge.control_id || touch.instance_generation != edge.instance_generation) {
                return false;
              }
              if (touch.submitted && !input::apply_lsp_controller_touch(
                                       *platform_,
                                       mapping_->input_generation,
                                       touch.controller_id,
                                       touch.instance_generation,
                                       edge.kind == input_plane::edge_kind::touch_end ? 2 : 4,
                                       edge.device_id,
                                       touch.x,
                                       touch.y,
                                       touch.pressure
                                     )) {
                return false;
              }
              touch = {};
              return true;
            }
          default:
            return false;
        }
      });
      apply_pending_pointer();
      schedule_ack(mapping, received_at, monotonic_microseconds(), true, std::max<std::size_t>(applied, 1));
    }

    void process_pointer(
      const InputSessionMapping &mapping,
      const input_plane::parsed_packet &packet,
      const std::uint64_t received_at
    ) noexcept {
      const auto parsed = input_plane::parse_pointer_payload(packet.payload);
      if (!parsed || parsed.value.mode != input_plane::pointer_flag::relative ||
          packet.header.state_sequence <= highest_accepted_state_) {
        return;
      }
      highest_accepted_state_ = packet.header.state_sequence;
      pending_pointer_ = PendingPointer {.header = packet.header, .value = parsed.value};
      apply_pending_pointer();
      schedule_ack(mapping, received_at, monotonic_microseconds(), false);
    }

    void process_device_state(
      const InputSessionMapping &mapping,
      const input_plane::parsed_packet &packet,
      const std::uint64_t received_at
    ) noexcept {
      if (packet.header.edge_watermark > edges_.applied_through()) {
        return;
      }
      const auto prefix = input_plane::parse_device_prefix(packet.payload);
      if (!prefix || prefix.value.device_id == 0 || prefix.value.device_id > controller_ordinals_.size() ||
          prefix.value.physical_ordinal <= controller_ordinals_[prefix.value.device_id - 1]) {
        return;
      }
      if (prefix.value.device == input_plane::device_type::controller && packet.payload.size() == 36 &&
          prefix.value.device_id <= controller_generations_.size() &&
          controller_generations_[prefix.value.device_id - 1] == prefix.value.instance_generation &&
          packet.payload[26] == 0 && packet.payload[27] == 0) {
        const auto signed_axis = [&](const std::size_t offset) {
          return std::bit_cast<std::int16_t>(wire::read_be<std::uint16_t>(packet.payload.subspan(offset, 2)));
        };
        const auto applied = input::apply_lsp_controller_state(
          *platform_,
          prefix.value.device_id,
          prefix.value.instance_generation,
          packet.payload[24],
          packet.payload[25],
          signed_axis(28),
          signed_axis(30),
          signed_axis(32),
          signed_axis(34)
        );
        if (applied) {
          controller_ordinals_[prefix.value.device_id - 1] = prefix.value.physical_ordinal;
          highest_accepted_state_ = std::max(highest_accepted_state_, packet.header.state_sequence);
          highest_applied_state_ = std::max(highest_applied_state_, packet.header.state_sequence);
          schedule_ack(mapping, received_at, monotonic_microseconds(), false);
        }
      } else if (prefix.value.device == input_plane::device_type::touch && packet.payload.size() == 40 &&
                 prefix.value.device_id <= touches_.size()) {
        auto &touch = touches_[prefix.value.device_id - 1];
        const auto controller_id = wire::read_be<std::uint32_t>(packet.payload.subspan(24, 4));
        if (!touch.active || touch.controller_id != controller_id || touch.instance_generation != prefix.value.instance_generation ||
            prefix.value.physical_ordinal <= touch.physical_ordinal) {
          return;
        }
        constexpr auto scale = 1.0f / 4'294'967'295.0f;
        const auto x = static_cast<float>(wire::read_be<std::uint32_t>(packet.payload.subspan(28, 4))) * scale;
        const auto y = static_cast<float>(wire::read_be<std::uint32_t>(packet.payload.subspan(32, 4))) * scale;
        const auto pressure = static_cast<float>(wire::read_be<std::uint32_t>(packet.payload.subspan(36, 4))) * scale;
        if (input::apply_lsp_controller_touch(
              *platform_,
              mapping.input_generation,
              controller_id,
              touch.instance_generation,
              touch.submitted ? 3 : 1,
              prefix.value.device_id,
              x,
              y,
              pressure
            )) {
          touch.physical_ordinal = prefix.value.physical_ordinal;
          touch.x = x;
          touch.y = y;
          touch.pressure = pressure;
          touch.submitted = true;
          highest_accepted_state_ = std::max(highest_accepted_state_, packet.header.state_sequence);
          highest_applied_state_ = std::max(highest_applied_state_, packet.header.state_sequence);
          schedule_ack(mapping, received_at, monotonic_microseconds(), false);
        }
      }
    }

    void process_sensor(
      const InputSessionMapping &mapping,
      const input_plane::parsed_packet &packet,
      const std::uint64_t received_at
    ) noexcept {
      if (packet.header.edge_watermark > edges_.applied_through() || packet.payload.size() != 36) {
        return;
      }
      const auto prefix = input_plane::parse_device_prefix(packet.payload, true);
      if (!prefix || prefix.value.device_id > controller_generations_.size() ||
          controller_generations_[prefix.value.device_id - 1] != prefix.value.instance_generation) {
        return;
      }
      const auto decode_float = [&](const std::size_t offset) {
        return std::bit_cast<float>(wire::read_be<std::uint32_t>(packet.payload.subspan(offset, 4)));
      };
      if (input::apply_lsp_controller_sensor(
            *platform_,
            mapping.input_generation,
            prefix.value.device_id,
            prefix.value.instance_generation,
            packet.payload[1],
            decode_float(24),
            decode_float(28),
            decode_float(32)
          )) {
        highest_accepted_state_ = std::max(highest_accepted_state_, packet.header.state_sequence);
        highest_applied_state_ = std::max(highest_applied_state_, packet.header.state_sequence);
        schedule_ack(mapping, received_at, monotonic_microseconds(), false);
      }
    }

    void process_reconciliation(
      const InputSessionMapping &mapping,
      const input_plane::parsed_packet &packet,
      const std::uint64_t received_at
    ) noexcept {
      if (packet.header.edge_watermark > edges_.applied_through() || packet.payload.size() != 36 || packet.payload[0] != 1 ||
          packet.payload[1] != 0 || packet.payload[3] != 0) {
        return;
      }
      for (std::uint16_t usage = 0; usage < 256; ++usage) {
        const auto held = (packet.payload[4 + usage / 8] & (1U << (usage % 8))) != 0;
        if (!input::apply_lsp_key(*platform_, usage, !held)) {
          continue;
        }
      }
      for (std::uint16_t button = 1; button <= 5; ++button) {
        const auto held = (packet.payload[2] & (1U << (button - 1U))) != 0;
        (void) input::apply_lsp_pointer_button(*platform_, button, !held);
      }
      highest_accepted_state_ = std::max(highest_accepted_state_, packet.header.state_sequence);
      highest_applied_state_ = std::max(highest_applied_state_, packet.header.state_sequence);
      schedule_ack(mapping, received_at, monotonic_microseconds(), false);
    }

    void apply_pending_pointer() noexcept {
      if (!pending_pointer_ || pending_pointer_->header.edge_watermark > edges_.applied_through()) {
        return;
      }
      const auto pointer_id = static_cast<std::uint32_t>(pending_pointer_->header.object_id);
      const auto &value = pending_pointer_->value;
      if ((pointer_.id != 0 && (pointer_.id != pointer_id || pointer_.instance_generation != value.instance_generation)) ||
          value.physical_ordinal <= pointer_.physical_ordinal) {
        pending_pointer_.reset();
        return;
      }
      std::int64_t delta_x = 0;
      std::int64_t delta_y = 0;
      std::int64_t vertical = 0;
      std::int64_t horizontal = 0;
      if (!difference(value.cumulative_x, pointer_.cumulative_x, delta_x) ||
          !difference(value.cumulative_y, pointer_.cumulative_y, delta_y) ||
          !difference(value.cumulative_vertical_scroll, pointer_.vertical_scroll, vertical) ||
          !difference(value.cumulative_horizontal_scroll, pointer_.horizontal_scroll, horizontal) ||
          !input::apply_lsp_pointer(*platform_, delta_x, delta_y, vertical, horizontal)) {
        pending_pointer_.reset();
        return;
      }
      pointer_ = {
        .id = pointer_id,
        .instance_generation = value.instance_generation,
        .physical_ordinal = value.physical_ordinal,
        .state_sequence = pending_pointer_->header.state_sequence,
        .cumulative_x = value.cumulative_x,
        .cumulative_y = value.cumulative_y,
        .vertical_scroll = value.cumulative_vertical_scroll,
        .horizontal_scroll = value.cumulative_horizontal_scroll,
      };
      highest_applied_state_ = pointer_.state_sequence;
      pending_pointer_.reset();
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
      flush_pending_ack(apply_time);
    }

    /** @brief Send the newest coalesced LSPI state once its floor/window threshold is due. */
    void flush_pending_ack(const std::uint64_t now) noexcept {
      const auto ordinary_due = ack_pending_records_ >= 8U ||
                                (now >= ack_pending_since_ && now - ack_pending_since_ >= 1'000U);
      if (!ack_pending_ || !mapping_ || *mapping_ != ack_mapping_ || (!ack_urgent_ && !ordinary_due) ||
          !ack_scheduler_.due(now)) {
        return;
      }
      if (send_ack(ack_mapping_, ack_receive_time_, ack_apply_time_)) {
        ack_scheduler_.mark_sent(now);
        ack_pending_ = false;
        ack_pending_since_ = 0;
        ack_pending_records_ = 0;
        ack_urgent_ = false;
      }
    }

    /** @brief Serialize, protect once, and commit one current LSPI acknowledgement. */
    [[nodiscard]] bool send_ack(
      const InputSessionMapping &mapping,
      const std::uint64_t receive_time,
      const std::uint64_t apply_time
    ) noexcept {
      input_plane::lspi_ack ack {
        .input_generation = mapping.input_generation,
        .accepted_baseline_id = baseline_.committed() ? baseline_.baseline_id() : 0,
        .highest_accepted_state_sequence = highest_accepted_state_,
        .highest_applied_state_sequence = highest_applied_state_,
        .contiguous_edge_id = edges_.applied_through(),
        .edge_reception_bitmap = edges_.reception_bitmap(),
        .host_receive_time_us = receive_time,
        .host_apply_time_us = apply_time,
      };
      if (pointer_.physical_ordinal != 0) {
        ack.pointers[0] = {
          .pointer_id = pointer_.id,
          .instance_generation = pointer_.instance_generation,
          .physical_ordinal = pointer_.physical_ordinal,
        };
        ack.pointer_count = 1;
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
      (void) token;
      (void) lane;
      (void) completed_at_microseconds;
      (void) protected_bytes;
      auto *self = static_cast<Impl *>(context);
      if (self != nullptr && completion == HostForwardCompletion::sent) {
        self->sent_feedback_wire_bytes_.fetch_add(charged_bytes, std::memory_order_relaxed);
      }
    }

    /** @brief Return the exact per-slot completion target for LSPI and LSPG datagrams. */
    [[nodiscard]] HostForwardCompletionTarget completion_target() noexcept {
      return {.context = this, .completed = forward_completion_callback};
    }

    void handle_feedback(const platf::gamepad_feedback_msg_t &message) noexcept {
      std::scoped_lock lock(mutex_);
      if (!mapping_ || message.identity.input_generation != mapping_->input_generation ||
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
      if (!mapping_ || !mapping_->forward_path) {
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
    std::array<packet_slab<maximum_input_rtp_bytes>, input_queue_capacity> queue_ {};  ///< Fixed authenticated RTP queue.
    std::size_t head_ {};  ///< Next queue read slot.
    std::size_t tail_ {};  ///< Next queue write slot.
    std::size_t size_ {};  ///< Occupied queue slots.
    std::optional<InputSessionMapping> mapping_;  ///< Active START mapping.
    input_plane::baseline_receiver baseline_;  ///< Atomic multipart baseline.
    input_plane::edge_receiver edges_;  ///< Exactly-once ordered edge state.
    PointerState pointer_;  ///< Last platform-applied cumulative pointer state.
    std::optional<PendingPointer> pending_pointer_;  ///< Newest watermark-blocked pointer state.
    std::uint64_t highest_accepted_state_ {};  ///< Greatest retained replaceable state sequence.
    std::uint64_t highest_applied_state_ {};  ///< Greatest platform-applied state sequence.
    input_plane::controller_output_manager controller_output_;  ///< Generation-fenced LSPG output/ACK state.
    std::array<std::uint32_t, 16> controller_generations_ {};  ///< Active controller instance generations.
    std::array<std::uint64_t, 16> controller_ordinals_ {};  ///< Greatest applied controller samples.
    std::array<TouchState, 16> touches_ {};  ///< Active generation-fenced controller touch contacts.
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
    std::jthread worker_;  ///< Dedicated ordered platform apply owner.
    std::atomic<std::uint64_t> sent_feedback_wire_bytes_ {};  ///< Complete final-sent IP/UDP bytes for LSPI and LSPG.
    bool ready_ {};  ///< Callback/platform/worker readiness.
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

  bool InputOwner::receive(const PeerEndpoint &peer, const std::span<const std::uint8_t> packet) noexcept {
    return impl_ && impl_->receive(peer, packet);
  }

  bool InputOwner::receive_rtcp(const PeerEndpoint &peer, const std::span<const std::uint8_t> packet) noexcept {
    return impl_ && impl_->receive_rtcp(peer, packet);
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

  /** @copydoc InputOwner::sent_feedback_wire_bytes */
  std::uint64_t InputOwner::sent_feedback_wire_bytes() const noexcept {
    return impl_ ? impl_->sent_feedback_wire_bytes() : 0;
  }
}  // namespace lumen::lsp::runtime
