/**
 * @file src/input.h
 * @brief Declarations for gamepad, keyboard, and mouse input handling.
 */
#pragma once

// standard includes
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

// local includes
#include "platform/common.h"
#include "thread_safe.h"

namespace input {
  struct input_t;

  /** @brief Opaque held-state owner for one authenticated LSP input authority. */
  struct lsp_platform_input_t;

  /** @brief Controller output forwarded from the existing platform backend into LSPG. */
  struct lsp_controller_feedback_t {
    platf::gamepad_feedback_msg_t message;  ///< Generation-qualified platform feedback value.
  };

  /** @brief Non-reentrant controller feedback callback. */
  using lsp_controller_feedback_callback_t = void (*)(void *, const lsp_controller_feedback_t &) noexcept;

  /** @brief Deleter for the opaque LSP platform-input owner. */
  struct lsp_platform_input_deleter_t {
    /**
     * @brief Destroy one LSP platform-input owner after neutralization.
     *
     * @param input Owner to destroy, or null.
     */
    void operator()(lsp_platform_input_t *input) const noexcept;
  };

  using lsp_platform_input_ptr = std::unique_ptr<lsp_platform_input_t, lsp_platform_input_deleter_t>;  ///< Owning opaque LSP input handle.

  /** @brief Maximum relative pointer distance accepted from one authenticated LSP report. */
  inline constexpr std::int64_t maximum_lsp_pointer_delta = 1'048'576;

  /** @brief Maximum high-resolution wheel distance accepted from one authenticated LSP report. */
  inline constexpr std::int64_t maximum_lsp_scroll_delta = 1'048'576;

  /** @brief Hard loop bound for splitting one accepted LSP platform report. */
  inline constexpr std::size_t maximum_lsp_pointer_chunks = 16;

  /**
   * @brief Validate one report's relative pointer and wheel differences before platform iteration.
   *
   * @param delta_x Relative horizontal difference.
   * @param delta_y Relative vertical difference.
   * @param vertical_scroll Vertical wheel difference.
   * @param horizontal_scroll Horizontal wheel difference.
   * @return True only when every value is inside its strict per-report bound.
   */
  [[nodiscard]] constexpr bool valid_lsp_pointer_differences(
    const std::int64_t delta_x,
    const std::int64_t delta_y,
    const std::int64_t vertical_scroll,
    const std::int64_t horizontal_scroll
  ) noexcept {
    const auto outside = [](const std::int64_t value, const std::int64_t limit) {
      return value < -limit || value > limit;
    };
    return !outside(delta_x, maximum_lsp_pointer_delta) &&
           !outside(delta_y, maximum_lsp_pointer_delta) &&
           !outside(vertical_scroll, maximum_lsp_scroll_delta) &&
           !outside(horizontal_scroll, maximum_lsp_scroll_delta);
  }

  /** @brief Create a fresh neutral LSP platform-input contribution. */
  [[nodiscard]] lsp_platform_input_ptr alloc_lsp_platform_input(
    lsp_controller_feedback_callback_t feedback_callback = nullptr,
    void *feedback_context = nullptr
  );

  /**
   * @brief Disable controller feedback and join its queue worker exactly once.
   *
   * @param input LSP platform owner that remains valid for the duration of the call.
   */
  void stop_lsp_platform_input_feedback(lsp_platform_input_t &input) noexcept;

#ifdef SUNSHINE_TESTS
  namespace detail {
    /** @brief Inject one platform feedback value into the production queue for lifetime testing. */
    bool raise_lsp_platform_feedback_for_test(
      lsp_platform_input_t &input,
      const platf::gamepad_feedback_msg_t &message
    ) noexcept;
  }  // namespace detail
#endif

  /**
   * @brief Map one USB keyboard-page usage to the platform virtual-key boundary.
   *
   * @param usage Keyboard-page usage ID from zero through 255.
   * @return Matching virtual-key value, or zero for reserved/unrepresentable usages.
   */
  [[nodiscard]] std::uint16_t virtual_key_from_hid_usage(std::uint16_t usage) noexcept;

  /**
   * @brief Apply cumulative-pointer differences through the existing platform backend.
   *
   * @param input LSP held-state owner.
   * @param delta_x Relative horizontal difference.
   * @param delta_y Relative vertical difference.
   * @param vertical_scroll Cumulative vertical-scroll difference.
   * @param horizontal_scroll Cumulative horizontal-scroll difference.
   * @return True after every bounded platform update was submitted.
   */
  bool apply_lsp_pointer(
    lsp_platform_input_t &input,
    std::int64_t delta_x,
    std::int64_t delta_y,
    std::int64_t vertical_scroll,
    std::int64_t horizontal_scroll
  ) noexcept;

  /**
   * @brief Apply normalized absolute pointer state plus bounded cumulative wheel differences.
   *
   * @param input LSP held-state owner.
   * @param absolute_x Horizontal Q0.32 coordinate.
   * @param absolute_y Vertical Q0.32 coordinate.
   * @param vertical_scroll Cumulative vertical-scroll difference.
   * @param horizontal_scroll Cumulative horizontal-scroll difference.
   * @return True after the bounded platform update was submitted.
   */
  bool apply_lsp_absolute_pointer(
    lsp_platform_input_t &input,
    std::uint32_t absolute_x,
    std::uint32_t absolute_y,
    std::int64_t vertical_scroll,
    std::int64_t horizontal_scroll
  ) noexcept;

  /**
   * @brief Apply one exactly-once keyboard HID-usage transition.
   *
   * @param input LSP held-state owner.
   * @param hid_usage Keyboard-page HID usage.
   * @param release Whether to release the usage.
   * @return True when the usage is supported and applied.
   */
  bool apply_lsp_key(lsp_platform_input_t &input, std::uint16_t hid_usage, bool release) noexcept;

  /**
   * @brief Inject one validated UTF-8/IME commit through the existing platform backend.
   *
   * @param input LSP authority whose keyboard contribution owns the commit.
   * @param utf8 Nonempty validated UTF-8 bytes.
   * @return True after the complete bounded commit was submitted.
   */
  bool apply_lsp_utf8_text(lsp_platform_input_t &input, std::span<const std::uint8_t> utf8) noexcept;

  /**
   * @brief Apply one exactly-once pointer-button transition.
   *
   * @param input LSP held-state owner.
   * @param button LSP pointer button in the range one through five.
   * @param release Whether to release the button.
   * @return True when the button is supported and applied.
   */
  bool apply_lsp_pointer_button(lsp_platform_input_t &input, std::uint16_t button, bool release) noexcept;

  /**
   * @brief Atomically release all keyboard and pointer state owned by LSP.
   *
   * @param input LSP held-state owner.
   */
  void neutralize_lsp_platform_input(lsp_platform_input_t &input) noexcept;

  /** @brief Allocate one generation-qualified LSP controller. */
  bool arrive_lsp_controller(
    lsp_platform_input_t &input,
    std::uint32_t input_generation,
    std::uint32_t controller_id,
    std::uint32_t instance_generation,
    std::uint8_t type
  ) noexcept;

  /** @brief Remove one exact LSP controller generation. */
  bool remove_lsp_controller(
    lsp_platform_input_t &input,
    std::uint32_t controller_id,
    std::uint32_t instance_generation
  ) noexcept;

  /** @brief Apply the latest analog controller state while retaining edge-owned buttons. */
  bool apply_lsp_controller_state(
    lsp_platform_input_t &input,
    std::uint32_t controller_id,
    std::uint32_t instance_generation,
    std::uint8_t left_trigger,
    std::uint8_t right_trigger,
    std::int16_t left_x,
    std::int16_t left_y,
    std::int16_t right_x,
    std::int16_t right_y
  ) noexcept;

  /** @brief Apply one exactly-once controller button-bit transition. */
  bool apply_lsp_controller_button(
    lsp_platform_input_t &input,
    std::uint32_t controller_id,
    std::uint32_t instance_generation,
    std::uint16_t button_bit,
    bool release
  ) noexcept;

  /** @brief Apply one controller gyroscope or accelerometer sample. */
  bool apply_lsp_controller_sensor(
    lsp_platform_input_t &input,
    std::uint32_t input_generation,
    std::uint32_t controller_id,
    std::uint32_t instance_generation,
    std::uint8_t sensor_type,
    float x,
    float y,
    float z
  ) noexcept;

  /**
   * @brief Apply one generation-qualified controller battery observation.
   *
   * @param input LSP held-state owner.
   * @param input_generation Active input authority generation.
   * @param controller_id Controller identifier in the range one through sixteen.
   * @param instance_generation Exact controller generation.
   * @param battery_state Frozen unknown, discharging, charging, or full state.
   * @param battery_percent Charge percentage, or 255 for unknown.
   * @return True when the controller generation is live and the report was submitted.
   */
  bool apply_lsp_controller_battery(
    lsp_platform_input_t &input,
    std::uint32_t input_generation,
    std::uint32_t controller_id,
    std::uint32_t instance_generation,
    std::uint8_t battery_state,
    std::uint8_t battery_percent
  ) noexcept;

  /** @brief Apply one controller touchpad contact event. */
  bool apply_lsp_controller_touch(
    lsp_platform_input_t &input,
    std::uint32_t input_generation,
    std::uint32_t controller_id,
    std::uint32_t instance_generation,
    std::uint8_t event_type,
    std::uint32_t contact_id,
    float x,
    float y,
    float pressure
  ) noexcept;

  /**
   * @brief Apply one exact pen contact lifecycle transition.
   *
   * @param input LSP held-state owner.
   * @param pen_id Pen device identifier in the range one through sixteen.
   * @param instance_generation Exact pen generation.
   * @param event_type Begin, end, or cancel event type (`1`, `2`, or `4`).
   * @return True when the transition is generation-consistent and retained/applied.
   */
  bool apply_lsp_pen_lifecycle(
    lsp_platform_input_t &input,
    std::uint32_t pen_id,
    std::uint32_t instance_generation,
    std::uint8_t event_type
  ) noexcept;

  /**
   * @brief Apply one exact direct-touch contact lifecycle transition.
   *
   * @param input LSP held-state owner.
   * @param device_id Direct-touch device identifier.
   * @param instance_generation Exact device generation.
   * @param contact_id Device-local contact identifier.
   * @param event_type Begin, end, or cancel event type (`1`, `2`, or `4`).
   * @return True when the transition is generation-consistent and retained/applied.
   */
  bool apply_lsp_touch_lifecycle(
    lsp_platform_input_t &input,
    std::uint32_t device_id,
    std::uint32_t instance_generation,
    std::uint32_t contact_id,
    std::uint8_t event_type
  ) noexcept;

  /**
   * @brief Apply one latest direct-touch contact state after its lifecycle edge.
   *
   * @param input LSP held-state owner.
   * @param device_id Direct-touch device identifier.
   * @param instance_generation Exact device generation.
   * @param contact_id Device-local contact identifier.
   * @param active Whether the contact remains active.
   * @param x Horizontal Q0.32 coordinate.
   * @param y Vertical Q0.32 coordinate.
   * @param pressure Unsigned normalized pressure.
   * @param major Unsigned normalized major-axis size.
   * @param minor Unsigned normalized minor-axis size.
   * @param orientation Signed contact orientation.
   * @return True when the lifecycle exists and the state was submitted.
   */
  bool apply_lsp_touch_state(
    lsp_platform_input_t &input,
    std::uint32_t device_id,
    std::uint32_t instance_generation,
    std::uint32_t contact_id,
    bool active,
    std::uint32_t x,
    std::uint32_t y,
    std::uint16_t pressure,
    std::uint16_t major,
    std::uint16_t minor,
    std::int16_t orientation
  ) noexcept;

  /**
   * @brief Apply one latest absolute pen state after its lifecycle edge.
   *
   * @param input LSP held-state owner.
   * @param pen_id Pen device identifier.
   * @param instance_generation Exact pen generation.
   * @param in_range Whether the tool is in digitizer range.
   * @param contact Whether the tip is touching.
   * @param eraser Whether the eraser tool is selected.
   * @param buttons Frozen pen-button bitmap.
   * @param x Horizontal Q0.32 coordinate.
   * @param y Vertical Q0.32 coordinate.
   * @param pressure Unsigned normalized tip pressure.
   * @param tilt_x Signed X tilt.
   * @param tilt_y Signed Y tilt.
   * @param rotation Signed barrel rotation.
   * @param distance Unsigned normalized hover distance.
   * @param contact_id Nonzero contact identifier while in range.
   * @return True when the lifecycle exists and the state was submitted.
   */
  bool apply_lsp_pen_state(
    lsp_platform_input_t &input,
    std::uint32_t pen_id,
    std::uint32_t instance_generation,
    bool in_range,
    bool contact,
    bool eraser,
    std::uint16_t buttons,
    std::uint32_t x,
    std::uint32_t y,
    std::uint16_t pressure,
    std::int16_t tilt_x,
    std::int16_t tilt_y,
    std::int16_t rotation,
    std::uint16_t distance,
    std::uint16_t contact_id
  ) noexcept;

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
