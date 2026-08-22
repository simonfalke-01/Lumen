/**
 * @file src/platform/windows/input_transport.h
 * @brief Windows keyboard and mouse input transport abstractions.
 */
#pragma once

// platform includes
#include <Windows.h>

// standard includes
#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace platf::win_input {
  /**
   * @brief Completion classification for one transport operation.
   */
  enum class completion_t {
    accepted,  ///< The operation was accepted by the selected backend.
    rejected,  ///< The operation was definitely not applied.
    ambiguous  ///< The backend may have applied the operation.
  };

  /**
   * @brief Result of one keyboard or mouse transport operation.
   */
  struct result_t {
    completion_t completion {completion_t::accepted};  ///< Completion classification.
    DWORD status {ERROR_SUCCESS};  ///< Native Windows status for diagnostics.

    /**
     * @brief Test whether the operation was accepted.
     * @return `true` when the operation was accepted.
     */
    explicit operator bool() const noexcept {
      return completion == completion_t::accepted;
    }
  };

  /**
   * @brief Runtime backend selected for stateful keyboard and mouse input.
   */
  enum class backend_t {
    probing,  ///< The Virtual HID driver is being probed.
    send_input,  ///< Win32 `SendInput` compatibility backend.
    virtual_hid,  ///< Lumen Virtual HID driver backend.
    fail_closed  ///< No further stateful input is permitted.
  };

  /**
   * @brief Abstract keyboard and mouse transport used by the Windows backend.
   */
  class transport_t {
  public:
    virtual ~transport_t() = default;

    /**
     * @brief Return the current stateful input backend.
     * @return Current backend state.
     */
    [[nodiscard]] virtual backend_t backend() const noexcept = 0;

    /**
     * @brief Inject relative mouse movement.
     * @param delta_x Horizontal movement.
     * @param delta_y Vertical movement.
     * @return Operation result.
     */
    virtual result_t move_mouse(std::int32_t delta_x, std::int32_t delta_y) = 0;

    /**
     * @brief Inject absolute virtual-desktop mouse movement.
     * @param x Horizontal coordinate in the source touch port.
     * @param y Vertical coordinate in the source touch port.
     * @param source_width Source touch-port width.
     * @param source_height Source touch-port height.
     * @return Operation result.
     */
    virtual result_t absolute_mouse(float x, float y, std::int32_t source_width, std::int32_t source_height) = 0;

    /**
     * @brief Change one mouse button.
     * @param button Moonlight mouse button number in the range 1 through 5.
     * @param release `true` to release the button.
     * @return Operation result.
     */
    virtual result_t mouse_button(int button, bool release) = 0;

    /**
     * @brief Inject vertical wheel movement.
     * @param distance Windows high-resolution wheel delta; 120 units represent one detent.
     * @return Operation result.
     */
    virtual result_t vertical_scroll(std::int32_t distance) = 0;

    /**
     * @brief Inject horizontal wheel movement.
     * @param distance Windows high-resolution wheel delta; 120 units represent one detent.
     * @return Operation result.
     */
    virtual result_t horizontal_scroll(std::int32_t distance) = 0;

    /**
     * @brief Change one keyboard key.
     * @param modcode Windows virtual-key code.
     * @param release `true` to release the key.
     * @param flags Moonlight keyboard packet flags.
     * @return Operation result.
     */
    virtual result_t keyboard(std::uint16_t modcode, bool release, std::uint8_t flags) = 0;

    /**
     * @brief Inject UTF-8 text through the Win32 Unicode input path.
     * @param utf8 UTF-8 byte sequence.
     * @param size Number of bytes in `utf8`.
     * @return Operation result.
     */
    virtual result_t unicode(const char *utf8, int size) = 0;

    /**
     * @brief Complete a higher-level input reset after its pressed maps clear.
     * @return Operation result.
     */
    virtual result_t reset_session() = 0;

    /**
     * @brief Release all keyboard keys and mouse buttons owned by the transport.
     * @return Operation result.
     */
    virtual result_t neutralize() = 0;
  };

  /**
   * @brief Injectable Win32 calls used by the `SendInput` transport.
   */
  class win32_api_t {
  public:
    virtual ~win32_api_t() = default;

    /**
     * @brief Call the Win32 `SendInput` API.
     * @param count Number of input records.
     * @param inputs Input records.
     * @param size Size of one input record.
     * @return Number of accepted records.
     */
    virtual UINT send_input(UINT count, INPUT *inputs, int size) = 0;

    /**
     * @brief Synchronize the calling thread with the current input desktop.
     * @return Current input desktop handle.
     */
    virtual HDESK sync_thread_desktop() = 0;

    /**
     * @brief Return the calling thread's last-error value.
     * @return Native Win32 error code.
     */
    virtual DWORD last_error() = 0;
  };

  /**
   * @brief Win32 `SendInput` implementation of the keyboard and mouse transport.
   */
  class send_input_transport_t final: public transport_t {
  public:
    /**
     * @brief Construct a transport using an injectable Win32 call surface.
     * @param api Win32 call surface.
     */
    explicit send_input_transport_t(std::shared_ptr<win32_api_t> api);

    /**
     * @brief Release input state still owned by the Win32 transport.
     */
    ~send_input_transport_t() override;

    backend_t backend() const noexcept override;
    result_t move_mouse(std::int32_t delta_x, std::int32_t delta_y) override;
    result_t absolute_mouse(float x, float y, std::int32_t source_width, std::int32_t source_height) override;
    result_t mouse_button(int button, bool release) override;
    result_t vertical_scroll(std::int32_t distance) override;
    result_t horizontal_scroll(std::int32_t distance) override;
    result_t keyboard(std::uint16_t modcode, bool release, std::uint8_t flags) override;
    result_t unicode(const char *utf8, int size) override;
    result_t reset_session() override;
    result_t neutralize() override;

  private:
    /**
     * @brief Submit one input record with input-desktop retry behavior.
     * @param input Input record.
     * @return Operation result.
     */
    result_t submit(INPUT input);

    std::shared_ptr<win32_api_t> api_;  ///< Win32 call surface.
    mutable std::mutex mutex_;  ///< Serializes state and calls to `SendInput`.
    HDESK last_input_desktop_ {nullptr};  ///< Last observed input desktop.
    std::unordered_map<std::uint16_t, std::uint8_t> held_keys_;  ///< Held keys and their packet flags.
    std::uint8_t held_buttons_ {0};  ///< Held mouse-button bitmap.
  };

  /**
   * @brief Create a production `SendInput` transport.
   * @return New transport instance.
   */
  std::unique_ptr<send_input_transport_t> make_send_input_transport();
}  // namespace platf::win_input
