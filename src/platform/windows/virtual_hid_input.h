/**
 * @file src/platform/windows/virtual_hid_input.h
 * @brief Preferred Windows Virtual HID keyboard and mouse transport.
 */
#pragma once

// local includes
#include "input_transport.h"
#include "virtual_hid_protocol.h"

// standard includes
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace platf::win_input {
  /**
   * @brief Completion classes returned by the Virtual HID control channel.
   */
  enum class channel_completion_t {
    accepted,  ///< The request completed successfully.
    definite_reject,  ///< The driver definitely rejected the request.
    ambiguous,  ///< The request may have reached the driver.
    removed  ///< Device removal is confirmed and acts as a quiescence fence.
  };

  /**
   * @brief Result returned by one Virtual HID control-channel operation.
   */
  struct channel_result_t {
    channel_completion_t completion {channel_completion_t::accepted};  ///< Completion classification.
    DWORD status {ERROR_SUCCESS};  ///< Native Windows status.

    /**
     * @brief Test whether the channel operation was accepted.
     * @return `true` when accepted.
     */
    explicit operator bool() const noexcept {
      return completion == channel_completion_t::accepted;
    }
  };

  /**
   * @brief Test seam for the versioned Virtual HID control channel.
   *
   * Implementations execute requests synchronously. Request and response structures
   * use the shared fixed-width C ABI so fakes can inspect every submitted report.
   */
  class virtual_hid_channel_t {
  public:
    virtual ~virtual_hid_channel_t() = default;

    /**
     * @brief Discover and open the report-control device interface.
     * @return Channel result.
     */
    virtual channel_result_t open() = 0;

    /**
     * @brief Exchange protocol capability structures.
     * @param request Capability request.
     * @param response Capability response populated by the channel.
     * @return Channel result.
     */
    virtual channel_result_t get_capabilities(
      const LUMEN_VHID_GET_CAPABILITIES_REQUEST &request,
      LUMEN_VHID_GET_CAPABILITIES_RESPONSE &response
    ) = 0;

    /**
     * @brief Claim the exclusive keyboard and mouse writer session.
     * @param request Claim request.
     * @param response Claim response populated by the channel.
     * @return Channel result.
     */
    virtual channel_result_t claim(
      const LUMEN_VHID_CLAIM_SESSION_REQUEST &request,
      LUMEN_VHID_CLAIM_SESSION_RESPONSE &response
    ) = 0;

    /**
     * @brief Submit one complete HID report snapshot.
     * @param request Report request.
     * @param response Submission response populated by the channel.
     * @return Channel result.
     */
    virtual channel_result_t submit(
      const LUMEN_VHID_SUBMIT_REPORT_REQUEST &request,
      LUMEN_VHID_SUBMIT_REPORT_RESPONSE &response
    ) = 0;

    /**
     * @brief Synchronously reset and neutralize the claimed session.
     * @param request Session request.
     * @param response Reset response populated by the channel.
     * @return Channel result.
     */
    virtual channel_result_t reset(
      const LUMEN_VHID_SESSION_REQUEST &request,
      LUMEN_VHID_SESSION_RESPONSE &response
    ) = 0;

    /**
     * @brief Synchronously neutralize and release the claimed session.
     * @param request Session request.
     * @param response Release response populated by the channel.
     * @return Channel result.
     */
    virtual channel_result_t release(
      const LUMEN_VHID_SESSION_REQUEST &request,
      LUMEN_VHID_SESSION_RESPONSE &response
    ) = 0;

    /**
     * @brief Close the file and establish the driver cleanup fence.
     * @return Channel result.
     */
    virtual channel_result_t cleanup() = 0;
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
   * @brief Preferred Virtual HID transport with one-way fenced fallback.
   */
  class virtual_hid_transport_t final: public transport_t {
  public:
    /**
     * @brief Construct a transport from injectable channel and fallback objects.
     * @param channel Virtual HID channel.
     * @param fallback Win32 compatibility transport.
     */
    virtual_hid_transport_t(
      std::shared_ptr<virtual_hid_channel_t> channel,
      std::unique_ptr<send_input_transport_t> fallback
    );

    /**
     * @brief Neutralize and release any claimed Virtual HID session.
     */
    ~virtual_hid_transport_t() override;

    /**
     * @brief Probe, validate, claim, and neutralize the Virtual HID backend.
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
     * @brief Return the last keyboard snapshot acknowledged by the driver.
     * @return Last acknowledged keyboard report.
     */
    [[nodiscard]] LUMEN_VHID_KEYBOARD_REPORT acknowledged_keyboard_report() const;

    /**
     * @brief Return the last mouse-button snapshot acknowledged by the driver.
     * @return Last acknowledged five-button bitmap.
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
    result_t neutralize() override;

  private:
    /**
     * @brief Original key transition retained for held-state replay.
     */
    struct held_key_t {
      std::uint8_t flags;  ///< Moonlight keyboard flags.
      std::uint8_t usage;  ///< Keyboard-page HID usage.
    };

    /**
     * @brief Build a complete NKRO report from desired key state.
     * @return Keyboard report snapshot.
     */
    LUMEN_VHID_KEYBOARD_REPORT keyboard_report() const;

    /**
     * @brief Submit one raw HID report with the next sequence value.
     * @param device_kind Protocol device kind.
     * @param report_id HID report identifier.
     * @param report Report bytes.
     * @param report_size Number of report bytes.
     * @return Channel result.
     */
    channel_result_t submit_report(
      std::uint16_t device_kind,
      std::uint16_t report_id,
      const void *report,
      std::uint16_t report_size
    );

    /**
     * @brief Fence the Virtual HID session and activate the fallback backend.
     * @param failure Failed operation result.
     * @param stage Diagnostic failure stage.
     * @param definitely_rejected_delta Optional stateless fallback action.
     * @return Result after transition and optional delivery.
     */
    result_t failover(
      channel_result_t failure,
      const char *stage,
      const std::function<result_t()> &definitely_rejected_delta = {}
    );

    /**
     * @brief Replay final desired held state through `SendInput` after fencing.
     * @return Replay result.
     */
    result_t replay_held_state();

    /**
     * @brief Reset then release the active writer session.
     * @return `true` when a recognized quiescence fence succeeds.
     */
    bool fence_and_release();

    /**
     * @brief Record a fallback or fail-closed reason.
     * @param stage Failure stage.
     * @param status Native status.
     */
    void set_failure(const char *stage, DWORD status);

    std::shared_ptr<virtual_hid_channel_t> channel_;  ///< Versioned driver channel.
    std::unique_ptr<send_input_transport_t> fallback_;  ///< Win32 fallback and Unicode route.
    mutable std::mutex mutex_;  ///< Serializes input reports and transitions.
    std::atomic<backend_t> backend_ {backend_t::probing};  ///< Current backend state.
    std::uint16_t protocol_minor_ {LUMEN_VHID_PROTOCOL_MINOR};  ///< Negotiated protocol minor.
    std::uint64_t session_token_ {0};  ///< Current session generation token.
    std::uint64_t sequence_ {0};  ///< Last accepted report sequence.
    std::unordered_map<std::uint16_t, held_key_t> desired_keys_;  ///< Desired held keys by virtual key.
    LUMEN_VHID_KEYBOARD_REPORT acknowledged_keyboard_ {};  ///< Last acknowledged keyboard snapshot.
    std::uint8_t desired_buttons_ {0};  ///< Desired held mouse-button bitmap.
    std::uint8_t acknowledged_buttons_ {0};  ///< Last acknowledged button bitmap.
    std::string failure_stage_;  ///< Most recent diagnostic stage.
    DWORD failure_status_ {ERROR_SUCCESS};  ///< Most recent native failure status.
  };

  /**
   * @brief Create and probe the production preferred Windows input transport.
   * @return Virtual HID transport, already in Virtual HID or fallback state.
   */
  std::unique_ptr<transport_t> make_preferred_input_transport();
}  // namespace platf::win_input
