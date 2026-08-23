/**
 * @file src/platform/windows/virtual_hid_session.h
 * @brief User-mode lifetime and output routing for dynamic VHF gamepads.
 */
#pragma once

// local includes
#include "virtual_hid_protocol.h"

// standard includes
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <unordered_map>

namespace platf::win_gamepad {

  /**
   * @brief Result category returned by one dynamic-gamepad channel operation.
   */
  enum class channel_status_e {
    success,  ///< Operation completed successfully.
    no_data,  ///< Nonblocking output read found no queued event.
    closed,  ///< Channel or device is no longer live.
    failure,  ///< Driver or transport rejected the operation.
  };

  /**
   * @brief Exact status returned by an injectable driver channel.
   */
  struct channel_result_t {
    channel_status_e status {channel_status_e::success};  ///< Portable result category.
    std::uint32_t native_status {};  ///< Native Win32 status for diagnostics.

    /**
     * @brief Check whether the operation succeeded.
     *
     * @return `true` only for `success`.
     */
    explicit operator bool() const noexcept {
      return status == channel_status_e::success;
    }
  };

  /**
   * @brief Injectable synchronous channel for the additive gamepad ABI.
   */
  class gamepad_channel_t {
  public:
    /**
     * @brief Destroy the channel after it has been closed.
     */
    virtual ~gamepad_channel_t() = default;

    /**
     * @brief Discover and open the secured Lumen driver interface.
     *
     * @return Channel result.
     */
    virtual channel_result_t open() = 0;

    /**
     * @brief Query the separately versioned dynamic-gamepad extension.
     *
     * @param response Receives driver capabilities.
     * @return Channel result.
     */
    virtual channel_result_t capabilities(LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE &response) = 0;

    /**
     * @brief Create one known built-in gamepad profile.
     *
     * @param request Validated creation request.
     * @param response Receives authenticated device identity.
     * @return Channel result.
     */
    virtual channel_result_t create(
      const LUMEN_VHID_GAMEPAD_CREATE_REQUEST &request,
      LUMEN_VHID_GAMEPAD_CREATE_RESPONSE &response
    ) = 0;

    /**
     * @brief Submit one complete packed input report.
     *
     * @param request Authenticated report request.
     * @return Channel result.
     */
    virtual channel_result_t submit(const LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST &request) = 0;

    /**
     * @brief Destroy one authenticated dynamic gamepad.
     *
     * @param request Authenticated device request.
     * @return Channel result.
     */
    virtual channel_result_t destroy(const LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST &request) = 0;

    /**
     * @brief Read one queued output report without blocking.
     *
     * @param request Authenticated device request.
     * @param response Receives one output report on success.
     * @return `no_data` when the bounded driver queue is empty.
     */
    virtual channel_result_t read_output(
      const LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST &request,
      LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE &response
    ) = 0;

    /**
     * @brief Reset one authenticated gamepad runtime.
     *
     * @param request Authenticated device request.
     * @return Channel result.
     */
    virtual channel_result_t reset(const LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST &request) = 0;

    /**
     * @brief Close the secured driver interface.
     */
    virtual void close() noexcept = 0;
  };

  /**
   * @brief Driver-created device and profile metadata.
   */
  struct session_device_t {
    LUMEN_VHID_GAMEPAD_HANDLE handle {};  ///< Authenticated driver handle.
    std::uint32_t profile {};  ///< Effective LUMEN_VHID_GAMEPAD_PROFILE_* value.
    std::uint32_t feature_flags {};  ///< Effective LUMEN_VHID_GAMEPAD_FEATURE_* bitmap.
    std::uint16_t vendor_id {};  ///< Advertised vendor ID.
    std::uint16_t product_id {};  ///< Advertised product ID.
    std::uint16_t version_number {};  ///< Advertised revision.
    std::uint8_t input_report_id {};  ///< Primary input report ID.
    std::uint32_t input_report_size {};  ///< Exact packed input report size.
    std::uint32_t output_report_size {};  ///< Maximum output report size.
  };

  /**
   * @brief Callback receiving one authenticated raw output report.
   */
  using output_callback_t = std::function<void(
    const session_device_t &device,
    std::span<const std::uint8_t> report
  )>;

  /**
   * @brief Creation result preserving whether the OS device became visible.
   */
  struct session_create_result_t {
    bool success {};  ///< Whether `device` is live and registered.
    bool became_visible {};  ///< Whether failure occurred after driver creation.
    session_device_t device;  ///< Live device metadata on success.
    std::uint32_t native_status {};  ///< Native error code on failure.
    std::string error;  ///< Human-readable diagnostic.
  };

  /**
   * @brief Own one secured gamepad channel and its bounded output pump.
   */
  class virtual_hid_session_t final {
  public:
    /**
     * @brief Construct a session around an injectable channel.
     *
     * @param channel Dynamic-gamepad channel.
     */
    explicit virtual_hid_session_t(std::shared_ptr<gamepad_channel_t> channel);

    virtual_hid_session_t(const virtual_hid_session_t &) = delete;
    virtual_hid_session_t &operator=(const virtual_hid_session_t &) = delete;
    virtual_hid_session_t(virtual_hid_session_t &&) = delete;
    virtual_hid_session_t &operator=(virtual_hid_session_t &&) = delete;

    /**
     * @brief Stop output routing, destroy owned gamepads, and close the channel.
     */
    ~virtual_hid_session_t();

    /**
     * @brief Open and validate the additive gamepad ABI.
     *
     * @return `true` when dynamic gamepads can be created.
     */
    bool initialize();

    /**
     * @brief Check whether the validated channel remains open.
     *
     * @return `true` while the session can create and submit.
     */
    bool available() const noexcept;

    /**
     * @brief Return the validated capabilities snapshot.
     *
     * @return Driver capability response.
     */
    LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE capabilities() const;

    /**
     * @brief Create and register one dynamic gamepad for output routing.
     *
     * @param client_device_id Stable caller device identity.
     * @param profile One LUMEN_VHID_GAMEPAD_PROFILE_* value.
     * @param callback Raw output callback for this exact generation.
     * @return Creation status and effective profile metadata.
     */
    session_create_result_t create(
      std::uint64_t client_device_id,
      std::uint32_t profile,
      output_callback_t callback
    );

    /**
     * @brief Submit one complete input report for an authenticated device.
     *
     * @param device Exact device returned by `create()`.
     * @param report Complete packed HID input report.
     * @return Channel result.
     */
    channel_result_t submit(const session_device_t &device, std::span<const std::uint8_t> report);

    /**
     * @brief Invalidate routing, destroy, and drain one device generation.
     *
     * @param device Exact device returned by `create()`.
     * @return Channel result from the driver destroy operation.
     */
    channel_result_t destroy(const session_device_t &device) noexcept;

    /**
     * @brief Reset one authenticated dynamic gamepad runtime.
     *
     * @param device Exact device returned by `create()`.
     * @return Channel result.
     */
    channel_result_t reset(const session_device_t &device) noexcept;

    /**
     * @brief Return the most recent initialization or runtime session error.
     *
     * @return Stable diagnostic text.
     */
    std::string failure() const;

  private:
    /**
     * @brief Output route for one exact driver generation.
     */
    struct output_route_t {
      session_device_t device;  ///< Expected authenticated identity.
      output_callback_t callback;  ///< Consumer callback, cleared before destroy.
      std::size_t in_flight {};  ///< Callbacks currently outside the route lock.
      bool closing {};  ///< Stale-event fence.
    };

    /**
     * @brief Execute the nonblocking bounded output pump.
     */
    void output_loop();

    /**
     * @brief Convert a device handle to the common authenticated request.
     *
     * @param handle Exact device handle.
     * @return Initialized authenticated request.
     */
    static LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST authenticated_request(
      const LUMEN_VHID_GAMEPAD_HANDLE &handle
    );

    /**
     * @brief Check exact device ID, generation, and token equality.
     *
     * @param left First handle.
     * @param right Second handle.
     * @return `true` when every identity byte matches.
     */
    static bool same_handle(
      const LUMEN_VHID_GAMEPAD_HANDLE &left,
      const LUMEN_VHID_GAMEPAD_HANDLE &right
    ) noexcept;

    std::shared_ptr<gamepad_channel_t> channel_;  ///< Secured synchronous driver channel.
    mutable std::mutex mutex_;  ///< Protects capabilities, routes, and diagnostics.
    std::condition_variable wake_;  ///< Wakes output polling and teardown drains.
    std::unordered_map<std::uint64_t, output_route_t> routes_;  ///< Routes keyed by driver device ID.
    LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE capabilities_ {};  ///< Validated extension capabilities.
    std::jthread output_thread_;  ///< Single bounded output-routing thread.
    std::atomic_bool available_ {};  ///< Whether new operations may begin.
    bool stop_output_ {};  ///< Output-thread shutdown fence under `mutex_`.
    std::string failure_;  ///< Last initialization diagnostic under `mutex_`.
  };

  /**
   * @brief Create the production SYSTEM driver channel.
   *
   * @return Channel using the Lumen device interface on Windows.
   */
  std::shared_ptr<gamepad_channel_t> make_system_gamepad_channel();

}  // namespace platf::win_gamepad
