/**
 * @file src/input.h
 * @brief Declarations for gamepad, keyboard, and mouse input handling.
 */
#pragma once

// standard includes
#include <cstdint>
#include <functional>

// local includes
#include "platform/common.h"
#include "thread_safe.h"

namespace input {
  struct input_t;

  /**
   * @brief Internal input helpers exposed for focused unit testing.
   */
  namespace detail {
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
   */
  void passthrough(std::shared_ptr<input_t> &input, std::vector<std::uint8_t> &&input_data);

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
