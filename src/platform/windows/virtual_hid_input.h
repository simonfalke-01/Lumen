/**
 * @file src/platform/windows/virtual_hid_input.h
 * @brief Lean Windows Virtual HID keyboard and mouse transport.
 */
#pragma once

// local includes
#include "input_transport.h"
#include "virtual_hid_protocol.h"

// standard includes
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace platf::win_input {
  /**
   * @brief Result returned by one synchronous Virtual HID operation.
   */
  struct channel_result_t {
    bool accepted {true};  ///< Whether the driver accepted the operation.
    DWORD status {ERROR_SUCCESS};  ///< Native Windows status.

    /**
     * @brief Test whether the operation was accepted.
     * @return `true` when accepted.
     */
    explicit operator bool() const noexcept {
      return accepted;
    }
  };

  /**
   * @brief Test seam for the four-operation Virtual HID control channel.
   */
  class virtual_hid_channel_t {
  public:
    virtual ~virtual_hid_channel_t() = default;

    /**
     * @brief Discover and open the secured driver interface.
     * @return Channel result.
     */
    virtual channel_result_t open() = 0;

    /**
     * @brief Read exact ABI identity and readiness.
     * @param response Driver information returned on success.
     * @return Channel result.
     */
    virtual channel_result_t get_info(LUMEN_VHID_GET_INFO_RESPONSE &response) = 0;

    /**
     * @brief Claim exclusive report submission on the open file.
     * @return Channel result.
     */
    virtual channel_result_t claim() = 0;

    /**
     * @brief Submit one complete fixed report.
     * @param request Tagged report request.
     * @return Channel result.
     */
    virtual channel_result_t submit(const LUMEN_VHID_SUBMIT_REPORT_REQUEST &request) = 0;

    /**
     * @brief Synchronously tear down Virtual HID state and release ownership.
     * @return Channel result.
     */
    virtual channel_result_t reset_and_release() = 0;

    /**
     * @brief Close the secured driver interface.
     */
    virtual void close() noexcept = 0;
  };

  /**
   * @brief Convert a Windows virtual key into a keyboard-page HID usage.
   * @param modcode Windows virtual-key code.
   * @param flags Moonlight keyboard packet flags.
   * @param always_send_scancodes Current scancode compatibility setting.
   * @return HID usage, or no value when the transition is not representable.
   */
  [[nodiscard]] std::optional<std::uint8_t> map_key_to_hid_usage(
    std::uint16_t modcode,
    std::uint8_t flags,
    bool always_send_scancodes
  );

  /**
   * @brief Preferred Virtual HID transport with reset-gated failure recovery.
   */
  class virtual_hid_transport_t final: public transport_t {
  public:
    /**
     * @brief Construct a transport from injectable channel and SendInput objects.
     * @param channel Virtual HID channel.
     * @param fallback SendInput compatibility and auxiliary transport.
     */
    virtual_hid_transport_t(
      std::shared_ptr<virtual_hid_channel_t> channel,
      std::unique_ptr<send_input_transport_t> fallback
    );

    /**
     * @brief Strongly reset an active Virtual HID session before destruction.
     */
    ~virtual_hid_transport_t() override;

    /**
     * @brief Open, validate, and claim the Virtual HID interface.
     * @return `true` only when Virtual HID becomes active.
     */
    bool initialize();

    /**
     * @brief Return the stage associated with the most recent failure.
     * @return Stable diagnostic stage name.
     */
    [[nodiscard]] const std::string &failure_stage() const noexcept;

    /**
     * @brief Return the Windows status associated with the most recent failure.
     * @return Native status code.
     */
    [[nodiscard]] DWORD failure_status() const noexcept;

    /**
     * @brief Return the last keyboard report accepted by the driver.
     * @return Last accepted keyboard snapshot.
     */
    [[nodiscard]] LUMEN_VHID_KEYBOARD_REPORT acknowledged_keyboard_report() const;

    /**
     * @brief Return the last mouse-button snapshot accepted by the driver.
     * @return Last accepted five-button bitmap.
     */
    [[nodiscard]] std::uint8_t acknowledged_mouse_buttons() const;

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
     * @brief Build a complete NKRO report from held keyboard state.
     * @return Keyboard report snapshot.
     */
    LUMEN_VHID_KEYBOARD_REPORT keyboard_report() const;

    /**
     * @brief Build a complete Consumer Control report from held consumer state.
     * @return Consumer Control report snapshot.
     */
    LUMEN_VHID_CONSUMER_REPORT consumer_report() const;

    /**
     * @brief Submit one report and enforce the accepted-input failure boundary.
     * @param request Tagged report request.
     * @param stage Diagnostic stage name.
     * @return Transport result.
     */
    result_t submit_report(const LUMEN_VHID_SUBMIT_REPORT_REQUEST &request, const char *stage);

    /**
     * @brief Record a diagnostic failure.
     * @param stage Failure stage.
     * @param status Native status.
     */
    void set_failure(const char *stage, DWORD status);

    std::shared_ptr<virtual_hid_channel_t> channel_;  ///< Secured driver channel.
    std::unique_ptr<send_input_transport_t> fallback_;  ///< SendInput auxiliary transport.
    mutable std::mutex mutex_;  ///< Serializes reports, state, and recovery.
    std::atomic<backend_t> backend_ {backend_t::probing};  ///< Current stateful backend.
    bool accepted_virtual_input_ {false};  ///< Whether any Virtual HID report was accepted.
    std::unordered_map<std::uint16_t, std::uint8_t> held_keys_;  ///< Held keyboard usages by virtual key.
    std::unordered_map<std::uint16_t, std::uint16_t> held_consumers_;  ///< Held consumer usages by virtual key.
    std::unordered_set<std::uint16_t> fallback_keys_;  ///< Held per-key SendInput transitions.
    LUMEN_VHID_KEYBOARD_REPORT acknowledged_keyboard_ {};  ///< Last accepted keyboard snapshot.
    std::uint8_t held_buttons_ {0};  ///< Desired mouse-button bitmap.
    std::uint8_t acknowledged_buttons_ {0};  ///< Last accepted mouse-button bitmap.
    std::string failure_stage_;  ///< Most recent diagnostic stage.
    DWORD failure_status_ {ERROR_SUCCESS};  ///< Most recent native failure status.
  };

  /**
   * @brief Create and probe the production preferred Windows input transport.
   * @return Virtual HID transport in Virtual HID, SendInput, or fail-closed state.
   */
  std::unique_ptr<transport_t> make_preferred_input_transport();
}  // namespace platf::win_input
