/**
 * @file src/input.h
 * @brief Declarations for gamepad, keyboard, and mouse input handling.
 */
#pragma once

// standard includes
#include <cstdint>
#include <functional>
#include <vector>

// local includes
#include "platform/common.h"
#include "thread_safe.h"

namespace input {
  struct input_t;
  using ordered_injector_t =
    std::function<bool(std::vector<std::uint8_t> &&)>;  ///< Checked direct consumer-thread packet injector.
  using ordered_state_operation_t =
    std::function<bool(const ordered_injector_t &)>;  ///< One complete v3 state operation.

  /**
   * @brief Internal input helpers exposed for focused unit testing.
   */
  namespace detail {
#ifdef SUNSHINE_TESTS
    /** @brief Run one packet through the production checked dispatcher for focused tests. */
    bool passthrough_packet_for_test(input_t *input, std::vector<std::uint8_t> packet);
#endif
    /**
     * @brief Platform-independent actions selected by the delayed left-button state machine.
     */
    struct delayed_left_decision_t {
      bool cancel_timer {false};  ///< Cancel the currently queued timer when possible.
      bool consume_timer {false};  ///< Clear the production timer identifier for a valid expiry.
      bool emit_left_release {false};  ///< Emit a left-button release before continuing.
      bool schedule_timer {false};  ///< Schedule a delayed left-button release.
      bool synthesize_right_click {false};  ///< Emit an immediate right-button press and release.
      std::uint64_t generation {0};  ///< Generation assigned to a newly scheduled timer.
    };

    /**
     * @brief Portable decision state for absolute-pointer left-button release delay.
     */
    class delayed_left_state_t {
    public:
      /**
       * @brief Enable delayed releases after absolute pointer movement.
       */
      void on_absolute_move() noexcept;

      /**
       * @brief Disable delay and flush any pending release before relative movement.
       * @return Actions required by the production input layer.
       */
      delayed_left_decision_t on_relative_move() noexcept;

      /**
       * @brief Handle a left-button press, flushing a prior delayed release first.
       * @return Actions required before emitting the new press.
       */
      delayed_left_decision_t on_left_down() noexcept;

      /**
       * @brief Handle a logical left-button release.
       * @return Timer scheduling decision, or an empty decision when delay is disabled.
       */
      delayed_left_decision_t on_left_up() noexcept;

      /**
       * @brief Handle a right-button press while a left release may be pending.
       * @return Decision indicating whether to synthesize the right click immediately.
       */
      delayed_left_decision_t on_right_down() const noexcept;

      /**
       * @brief Resolve one delayed timer callback.
       * @param generation Generation captured when the timer was scheduled.
       * @param left_pressed Whether a newer logical left press is active.
       * @return Timer consumption and optional left-release decision.
       */
      delayed_left_decision_t on_timer(std::uint64_t generation, bool left_pressed) noexcept;

      /**
       * @brief Reset to the initial absolute-capable state and invalidate stale timers.
       * @return Actions required to cancel and flush pending state.
       */
      delayed_left_decision_t on_reset() noexcept;

    private:
      bool delay_enabled_ {true};  ///< Whether absolute-pointer release delay is active.
      bool release_pending_ {false};  ///< Whether one delayed left release is outstanding.
      std::uint64_t generation_ {0};  ///< Monotonic timer invalidation generation.
    };

    /**
     * @brief Add two signed 16-bit values without overflowing.
     *
     * @param lhs Left-hand operand.
     * @param rhs Right-hand operand.
     * @param result Receives the sum when it is representable as a signed 16-bit value.
     * @return True when the addition succeeds; false when the sum would overflow.
     */
    bool checked_add_int16(std::int16_t lhs, std::int16_t rhs, std::int16_t &result);

#ifdef SUNSHINE_TESTS
    /**
     * @brief Exercise relative mouse packet batching through the production batch implementation.
     *
     * @param dest_x Destination packet horizontal delta, updated when batching succeeds.
     * @param dest_y Destination packet vertical delta, updated when batching succeeds.
     * @param src_x Source packet horizontal delta.
     * @param src_y Source packet vertical delta.
     * @return True when the packets are batched; false when batching terminates.
     */
    bool batch_relative_mouse_for_test(std::int16_t &dest_x, std::int16_t &dest_y, std::int16_t src_x, std::int16_t src_y);

    /**
     * @brief Exercise vertical scroll packet batching through the production batch implementation.
     *
     * @param dest_primary Destination packet primary scroll amount, updated when batching succeeds.
     * @param dest_secondary Destination packet duplicate scroll amount, updated when batching succeeds.
     * @param src Source packet scroll amount.
     * @return True when the packets are batched; false when batching terminates.
     */
    bool batch_vertical_scroll_for_test(std::int16_t &dest_primary, std::int16_t &dest_secondary, std::int16_t src);

    /**
     * @brief Exercise horizontal scroll packet batching through the production batch implementation.
     *
     * @param dest Destination packet scroll amount, updated when batching succeeds.
     * @param src Source packet scroll amount.
     * @return True when the packets are batched; false when batching terminates.
     */
    bool batch_horizontal_scroll_for_test(std::int16_t &dest, std::int16_t src);
#endif
  }  // namespace detail

  /**
   * @brief Write a debug log representation of the input packet.
   *
   * @param input Raw input packet to format for logging.
   */
  void print(void *input);
  /**
   * @brief Reset stream input state after a client disconnect or shutdown.
   *
   * @param input Shared stream input state to reset.
   */
  void reset(std::shared_ptr<input_t> &input);

  /**
   * @brief Queue a raw input message for platform passthrough.
   * @return True when the ordered consumer accepted or coalesced the packet.
   */
  bool passthrough(std::shared_ptr<input_t> &input, std::vector<std::uint8_t> &&input_data);

  /**
   * @brief Queue one protocol-v3 state operation on the ordered input consumer.
   *
   * Edge-free operations may supersede a consecutive stale state and expire
   * under the normal motion-age bound. Operations containing a new edge are
   * non-droppable and preserve strict FIFO ordering. Completion runs only after
   * every packet emitted by the operation has returned from platform injection.
   *
   * @param input Shared stream input state.
   * @param operation Consumer-thread operation using the direct ordered injector.
   * @param supersedable Whether a newer consecutive state may replace this work.
   * @param completion Callback reporting actual platform-injection success or failure.
   * @return True when accepted, coalesced, or safely pressure-dropped; false when closed.
   */
  bool passthrough_state(
    std::shared_ptr<input_t> &input,
    ordered_state_operation_t operation,
    bool supersedable,
    std::function<void(bool)> completion = {}
  );

  /**
   * @brief Bind immutable v3 authority identity to the next controller allocation.
   *
   * Must run inside that input session's ordered state operation immediately
   * before its controller-arrival packet is injected.
   *
   * @param input Session input state.
   * @param controller Client-relative controller slot.
   * @param input_generation Nonzero input authority generation.
   * @param controller_generation Nonzero controller instance generation.
   * @return True when the unallocated slot accepted the identity.
   */
  bool set_gamepad_feedback_identity(
    input_t *input,
    std::uint8_t controller,
    std::uint32_t input_generation,
    std::uint32_t controller_generation
  ) noexcept;

  /**
   * @brief Seal input producers before waiting for the control stream to terminate.
   *
   * @param input Shared stream input state whose blocked producers must be released.
   */
  void begin_close(std::shared_ptr<input_t> &input);

  /**
   * @brief Initialize global input resources and platform backends.
   *
   * @return Cleanup handle for initialized input resources, or null if none are required.
   */
  [[nodiscard]] std::unique_ptr<platf::deinit_t> init();

  /**
   * @brief Probe whether the platform can create virtual gamepads.
   *
   * @return True when at least one configured gamepad backend is available.
   */
  bool probe_gamepads();

  /**
   * @brief Allocate and initialize platform input state for a stream.
   *
   * @param mail Mailbox used to exchange messages with worker threads.
   * @return Shared input state bound to the stream mailbox.
   */
  std::shared_ptr<input_t> alloc(safe::mail_t mail);

  /**
   * @brief Touchscreen coordinate bounds used to scale absolute input.
   */
  struct touch_port_t: public platf::touch_port_t {
    int env_width;  ///< Width of the full capture environment in physical pixels.
    int env_height;  ///< Height of the full capture environment in physical pixels.

    // Offset x and y coordinates of the client
    float client_offsetX;  ///< Horizontal client viewport offset used when scaling touch input.
    float client_offsetY;  ///< Vertical client viewport offset used when scaling touch input.

    float scalar_inv;  ///< Inverse scale factor from client coordinates to display coordinates.
    float scalar_tpcoords;  ///< Scale factor from client coordinates to touch-port coordinates.

    int env_logical_width;  ///< Width of the full capture environment after display scaling.
    int env_logical_height;  ///< Height of the full capture environment after display scaling.

    /**
     * @brief Check whether the touch-port bounds are initialized.
     */
    explicit operator bool() const {
      return width != 0 && height != 0 && env_width != 0 && env_height != 0;
    }
  };

  /**
   * @brief Scale the ellipse axes according to the provided size.
   * @param val The major and minor axis pair.
   * @param rotation The rotation value from the touch/pen event.
   * @param scalar The scalar cartesian coordinate pair.
   * @return The major and minor axis pair.
   */
  std::pair<float, float> scale_client_contact_area(const std::pair<float, float> &val, uint16_t rotation, const std::pair<float, float> &scalar);
}  // namespace input
