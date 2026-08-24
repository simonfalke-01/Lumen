/**
 * @file src/platform/windows/input.cpp
 * @brief Definitions for input handling on Windows.
 */
#ifndef DOXYGEN
  #define WINVER 0x0A00
#endif
#ifdef DOXYGEN
  /**
   * @def CALLBACK
   * @brief Windows callback calling convention marker.
   */
  #define CALLBACK
#endif

// platform includes
#include <Windows.h>

// standard includes
#include <array>
#include <atomic>
#include <cmath>
#include <memory>
#include <mutex>
#include <stop_token>
#include <thread>
#include <vector>

// lib includes
#include <ViGEm/Client.h>
#include <ViGEm/km/BusShared.h>

// local includes
#include "gamepad_router.h"
#include "misc.h"
#include "src/config.h"
#include "src/globals.h"
#include "src/logging.h"
#include "src/platform/common.h"
#include "virtual_hid_gamepad.h"
#include "virtual_hid_input.h"

// Pinned ViGEmClient internals required to own a joinable X360 notification worker.
#include "third-party/ViGEmClient/src/Internal.h"

namespace platf {
  using namespace std::literals;

  thread_local HDESK _lastKnownInputDesktop = nullptr;  ///< Last known input desktop.

  /**
   * @brief ViGEm client pointer released with `vigem_free`.
   */
  using client_t = util::safe_ptr<_VIGEM_CLIENT_T, vigem_free>;
  /**
   * @brief ViGEm target pointer released with `vigem_target_free`.
   */
  using target_t = util::safe_ptr<_VIGEM_TARGET_T, vigem_target_free>;

  class vigem_t;

  /**
   * @brief Immutable identity passed to one ViGEm notification registration.
   */
  struct vigem_notification_t {
    vigem_t *owner {};  ///< ViGEm context that owns the registered target.
    int global_index {};  ///< Router slot used by this exact registration.
    std::uint64_t generation {};  ///< Router generation captured before worker start.
    std::atomic_bool active {false};  ///< Cleared before worker cancellation or slot reuse.
    std::jthread worker;  ///< Joinable X360 output worker owned by this bounded slot.
  };

  /**
   * @brief ViGEm target and report buffers for one virtual gamepad.
   */
  struct gamepad_context_t {
    target_t gp;  ///< Gp.
    feedback_queue_t feedback_queue;  ///< Feedback queue.

    union {
      XUSB_REPORT x360;
      DS4_REPORT_EX ds4;
    } report;  ///< Legacy ViGEm report storage; allocation is X360-only.

    std::map<uint32_t, uint8_t> pointer_id_map;  ///< Legacy DS4 touch map.
    uint8_t available_pointers {};  ///< Legacy DS4 available touch pointers.
    uint8_t client_relative_index;  ///< Client relative index.
    vigem_notification_t notification;  ///< Bounded exact notification registration identity.
    thread_pool_util::ThreadPool::task_id_t repeat_task {};  ///< Legacy DS4 repeat task.
    std::chrono::steady_clock::time_point last_report_ts;  ///< Legacy DS4 report time.
    gamepad_feedback_msg_t last_rumble;  ///< Last rumble.
    gamepad_feedback_msg_t last_rgb_led;  ///< Legacy DS4 LED feedback.
  };

  constexpr float EARTH_G = 9.80665f;  ///< Meters per second squared represented by one gravity unit.

/**
 * @def MPS2_TO_DS4_ACCEL(x)
 * @brief Macro for MPS2 TO DS4 ACCEL.
 */
#define MPS2_TO_DS4_ACCEL(x) (int32_t) (((x) / EARTH_G) * 8192)
/**
 * @def DPS_TO_DS4_GYRO(x)
 * @brief Macro for DPS TO DS4 GYRO.
 */
#define DPS_TO_DS4_GYRO(x) (int32_t) ((x) * (1024 / 64))

/**
 * @def APPLY_CALIBRATION(val, bias, scale)
 * @brief Macro for APPLY CALIBRATION.
 */
#define APPLY_CALIBRATION(val, bias, scale) (int32_t) (((float) (val) + (bias)) / (scale))

  /**
   * @brief DS4 touch unused.
   */
  constexpr DS4_TOUCH ds4_touch_unused = {
    .bPacketCounter = 0,
    .bIsUpTrackingNum1 = 0x80,
    .bTouchData1 = {0x00, 0x00, 0x00},
    .bIsUpTrackingNum2 = 0x80,
    .bTouchData2 = {0x00, 0x00, 0x00},
  };

  // See https://github.com/ViGEm/ViGEmBus/blob/22835473d17fbf0c4d4bb2f2d42fd692b6e44df4/sys/Ds4Pdo.cpp#L153-L164
  /**
   * @brief DS4 report init ex.
   */
  constexpr DS4_REPORT_EX ds4_report_init_ex = {
    {{.bThumbLX = 0x80,
      .bThumbLY = 0x80,
      .bThumbRX = 0x80,
      .bThumbRY = 0x80,
      .wButtons = DS4_BUTTON_DPAD_NONE,
      .bSpecial = 0,
      .bTriggerL = 0,
      .bTriggerR = 0,
      .wTimestamp = 0,
      .bBatteryLvl = 0xFF,
      .wGyroX = 0,
      .wGyroY = 0,
      .wGyroZ = 0,
      .wAccelX = 0,
      .wAccelY = 0,
      .wAccelZ = 0,
      ._bUnknown1 = {0x00, 0x00, 0x00, 0x00, 0x00},
      .bBatteryLvlSpecial = 0x1A,  // Wired - Full battery
      ._bUnknown2 = {0x00, 0x00},
      .bTouchPacketsN = 1,
      .sCurrentTouch = ds4_touch_unused,
      .sPreviousTouch = {ds4_touch_unused, ds4_touch_unused}}}
  };

  /**
   * @brief Updates the DS4 input report with the provided motion data.
   * @details Acceleration is in m/s^2 and gyro is in deg/s.
   * @param gamepad The gamepad to update.
   * @param motion_type The type of motion data.
   * @param x X component of motion.
   * @param y Y component of motion.
   * @param z Z component of motion.
   */
  static void ds4_update_motion(gamepad_context_t &gamepad, uint8_t motion_type, float x, float y, float z) {
    auto &report = gamepad.report.ds4.Report;

    // Use int32 to process this data, so we can clamp if needed.
    int32_t intX;
    int32_t intY;
    int32_t intZ;

    switch (motion_type) {
      case LI_MOTION_TYPE_ACCEL:
        // Convert to the DS4's accelerometer scale
        intX = MPS2_TO_DS4_ACCEL(x);
        intY = MPS2_TO_DS4_ACCEL(y);
        intZ = MPS2_TO_DS4_ACCEL(z);

        // Apply the inverse of ViGEmBus's calibration data
        intX = APPLY_CALIBRATION(intX, -297, 1.010796f);
        intY = APPLY_CALIBRATION(intY, -42, 1.014614f);
        intZ = APPLY_CALIBRATION(intZ, -512, 1.024768f);
        break;
      case LI_MOTION_TYPE_GYRO:
        // Convert to the DS4's gyro scale
        intX = DPS_TO_DS4_GYRO(x);
        intY = DPS_TO_DS4_GYRO(y);
        intZ = DPS_TO_DS4_GYRO(z);

        // Apply the inverse of ViGEmBus's calibration data
        intX = APPLY_CALIBRATION(intX, 1, 0.977596f);
        intY = APPLY_CALIBRATION(intY, 0, 0.972370f);
        intZ = APPLY_CALIBRATION(intZ, 0, 0.971550f);
        break;
      default:
        return;
    }

    // Clamp the values to the range of the data type
    intX = std::clamp(intX, INT16_MIN, INT16_MAX);
    intY = std::clamp(intY, INT16_MIN, INT16_MAX);
    intZ = std::clamp(intZ, INT16_MIN, INT16_MAX);

    // Populate the report
    switch (motion_type) {
      case LI_MOTION_TYPE_ACCEL:
        report.wAccelX = (int16_t) intX;
        report.wAccelY = (int16_t) intY;
        report.wAccelZ = (int16_t) intZ;
        break;
      case LI_MOTION_TYPE_GYRO:
        report.wGyroX = (int16_t) intX;
        report.wGyroY = (int16_t) intY;
        report.wGyroZ = (int16_t) intZ;
        break;
      default:
        return;
    }
  }

  /**
   * @brief ViGEm client connection and virtual gamepad collection.
   */
  class vigem_t {
  public:
    /**
     * @brief Connect to ViGEm and prepare virtual gamepad slots.
     *
     * @return 0 on success; nonzero or negative platform status on failure.
     */
    int init() {
      // Probe ViGEm during startup to see if we can successfully attach gamepads. This will allow us to
      // immediately display the error message in the web UI even before the user tries to stream.
      client_t client {vigem_alloc()};
      VIGEM_ERROR status = vigem_connect(client.get());
      if (!VIGEM_SUCCESS(status)) {
        BOOST_LOG(warning) << "ViGEmBus is unavailable; Xbox 360/XInput emulation is disabled, but Lumen Virtual HID gamepads may still work"sv;
        return -1;
      }
      vigem_disconnect(client.get());

      for (int index = 0; index < static_cast<int>(gamepads.size()); ++index) {
        gamepads[index].notification.owner = this;
        gamepads[index].notification.global_index = index;
        gamepads[index].notification.active.store(false);
      }

      return 0;
    }

    /**
     * @brief Read X360 output on a joinable per-slot worker.
     *
     * @param notification Bounded slot notification state.
     * @param vigem_client Connected ViGEm client retained until the worker joins.
     * @param target Connected X360 target retained until the worker joins.
     * @param stop_token Cooperative cancellation token.
     */
    void run_notification(
      vigem_notification_t *notification,
      client_t::pointer vigem_client,
      target_t::pointer target,
      std::stop_token stop_token
    ) noexcept {
      HANDLE event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
      if (event == nullptr) {
        BOOST_LOG(warning) << "Couldn't create ViGEm X360 notification event: "sv << GetLastError();
        return;
      }

      OVERLAPPED overlapped {};
      overlapped.hEvent = event;
      std::stop_callback cancel {stop_token, [vigem_client, &overlapped] {
                                   if (vigem_client != nullptr &&
                                       vigem_client->hBusDevice != INVALID_HANDLE_VALUE) {
                                     CancelIoEx(vigem_client->hBusDevice, &overlapped);
                                   }
                                 }};

      while (!stop_token.stop_requested()) {
        DWORD transferred = 0;
        XUSB_REQUEST_NOTIFICATION output;
        XUSB_REQUEST_NOTIFICATION_INIT(&output, target->SerialNo);
        overlapped.Internal = 0;
        overlapped.InternalHigh = 0;
        overlapped.Offset = 0;
        overlapped.OffsetHigh = 0;
        ResetEvent(event);
        const BOOL started = DeviceIoControl(
          vigem_client->hBusDevice,
          IOCTL_XUSB_REQUEST_NOTIFICATION,
          &output,
          output.Size,
          &output,
          output.Size,
          &transferred,
          &overlapped
        );
        if (!started && GetLastError() != ERROR_IO_PENDING) {
          if (!stop_token.stop_requested()) {
            BOOST_LOG(warning) << "ViGEm X360 notification request failed: "sv << GetLastError();
          }
          break;
        }
        if (stop_token.stop_requested()) {
          CancelIoEx(vigem_client->hBusDevice, &overlapped);
        }
        if (!GetOverlappedResult(vigem_client->hBusDevice, &overlapped, &transferred, TRUE)) {
          const auto error = GetLastError();
          if (!stop_token.stop_requested() && error != ERROR_OPERATION_ABORTED &&
              error != ERROR_ACCESS_DENIED && error != ERROR_INVALID_HANDLE) {
            BOOST_LOG(warning) << "ViGEm X360 notification read failed: "sv << error;
          }
          break;
        }
        if (!stop_token.stop_requested() && notification->active.load()) {
          rumble(
            notification->global_index,
            notification->generation,
            notification,
            target,
            output.LargeMotor,
            output.SmallMotor
          );
        }
      }
      CloseHandle(event);
    }

    /**
     * @brief Attaches a new gamepad.
     * @param id The gamepad ID.
     * @param feedback_queue The queue for posting messages back to the client.
     * @param generation Router generation assigned to this allocation.
     * @return 0 on success.
     */
    int alloc_gamepad_internal(
      const gamepad_id_t &id,
      feedback_queue_t &feedback_queue,
      std::uint64_t generation
    ) {
      auto &gamepad = gamepads[id.globalIndex];
      assert(!gamepad.gp);

      // Establish a connect to the ViGEm driver if we don't have one yet
      if (!client) {
        BOOST_LOG(debug) << "Connecting to ViGEmBus driver"sv;
        client.reset(vigem_alloc());

        auto status = vigem_connect(client.get());
        if (!VIGEM_SUCCESS(status)) {
          BOOST_LOG(warning) << "Couldn't setup connection to ViGEm for gamepad support ["sv << util::hex(status).to_string_view() << ']';
          client.reset();
          return -1;
        }
      }

      gamepad.gp.reset(vigem_target_x360_alloc());
      XUSB_REPORT_INIT(&gamepad.report.x360);

      auto status = vigem_target_add(client.get(), gamepad.gp.get());
      if (!VIGEM_SUCCESS(status)) {
        BOOST_LOG(error) << "Couldn't add Gamepad to ViGEm connection ["sv << util::hex(status).to_string_view() << ']';
        free_target(id.globalIndex);
        return -1;
      }

      auto *notification = &gamepad.notification;
      {
        std::lock_guard lock(gamepads_mutex);
        gamepad.client_relative_index = id.clientRelativeIndex;
        gamepad.feedback_queue = std::move(feedback_queue);
        gamepad.last_rumble = {};
        gamepad.last_rgb_led = {};
        notification->generation = generation;
        notification->active.store(true);
      }

      notification->worker = std::jthread(
        [this, notification, vigem_client = client.get(), target = gamepad.gp.get()](
          std::stop_token stop_token
        ) {
          run_notification(notification, vigem_client, target, stop_token);
        }
      );

      return 0;
    }

    /**
     * @brief Detaches the specified gamepad
     * @param nr The gamepad.
     */
    void free_target(int nr) {
      auto &gamepad = gamepads[nr];

      {
        std::lock_guard lock(gamepads_mutex);
        gamepad.notification.active.store(false);
        gamepad.feedback_queue.reset();
        gamepad.last_rumble = {};
        gamepad.last_rgb_led = {};
      }

      if (gamepad.notification.worker.joinable()) {
        gamepad.notification.worker.request_stop();
        gamepad.notification.worker.join();
      }

      if (gamepad.repeat_task) {
        task_pool.cancel(gamepad.repeat_task);
        gamepad.repeat_task = nullptr;
      }

      if (gamepad.gp && vigem_target_is_attached(gamepad.gp.get())) {
        auto status = vigem_target_remove(client.get(), gamepad.gp.get());
        if (!VIGEM_SUCCESS(status)) {
          BOOST_LOG(warning) << "Couldn't detach gamepad from ViGEm ["sv << util::hex(status).to_string_view() << ']';
        }
      }

      gamepad.gp.reset();
      gamepad.notification.generation = 0;

      // Disconnect from ViGEm if we just removed the last gamepad
      bool disconnect = true;
      for (auto &gamepad : gamepads) {
        if (gamepad.gp && vigem_target_is_attached(gamepad.gp.get())) {
          disconnect = false;
          break;
        }
      }
      if (disconnect) {
        BOOST_LOG(debug) << "Disconnecting from ViGEmBus driver"sv;
        vigem_disconnect(client.get());
        client.reset();
      }
    }

    /**
     * @brief Pass rumble data back to the client.
     * @param global_index Global gamepad slot.
     * @param generation Exact router generation that registered the callback.
     * @param notification Exact immutable notification identity.
     * @param target The gamepad.
     * @param largeMotor The large motor.
     * @param smallMotor The small motor.
     */
    void rumble(
      int global_index,
      std::uint64_t generation,
      const vigem_notification_t *notification,
      target_t::pointer target,
      std::uint8_t largeMotor,
      std::uint8_t smallMotor
    ) {
      feedback_queue_t feedback_queue;
      gamepad_feedback_msg_t message;
      {
        std::lock_guard lock(gamepads_mutex);
        if (global_index < 0 || global_index >= static_cast<int>(gamepads.size())) {
          return;
        }
        auto &gamepad = gamepads[global_index];
        if (gamepad.notification.generation != generation || &gamepad.notification != notification ||
            gamepad.gp.get() != target || !gamepad.feedback_queue) {
          return;
        }

        const auto normalized_large_motor = static_cast<std::uint16_t>(largeMotor) << 8U;
        const auto normalized_small_motor = static_cast<std::uint16_t>(smallMotor) << 8U;
        if (normalized_small_motor == gamepad.last_rumble.data.rumble.highfreq &&
            normalized_large_motor == gamepad.last_rumble.data.rumble.lowfreq) {
          return;
        }
        message = gamepad_feedback_msg_t::make_rumble(
          gamepad.client_relative_index,
          normalized_large_motor,
          normalized_small_motor
        );
        gamepad.last_rumble = message;
        feedback_queue = gamepad.feedback_queue;
      }
      feedback_queue->raise(message);
    }

    /**
     * @brief Detach all virtual gamepads and disconnect from the ViGEm client.
     */
    ~vigem_t() {
      for (int index = 0; index < static_cast<int>(gamepads.size()); ++index) {
        if (gamepads[index].gp) {
          free_target(index);
        }
      }
      if (client) {
        vigem_disconnect(client.get());
      }
    }

    std::array<gamepad_context_t, MAX_GAMEPADS> gamepads;  ///< Virtual gamepads owned by this ViGEm connection.

    client_t client;  ///< ViGEm client connection used to create virtual gamepads.
    std::mutex gamepads_mutex;  ///< Protects callback routing and generation state.
  };

  /**
   * @brief Submit ordinary state through an already allocated ViGEm target.
   *
   * @param vigem Global ViGEm context.
   * @param nr Global gamepad slot.
   * @param state Current GameStream controller state.
   * @return `true` when ViGEm accepted the complete report.
   */
  static bool vigem_gamepad_update(vigem_t *vigem, int nr, const gamepad_state_t &state);

  /**
   * @brief Ignore touch input for the X360-only ViGEm route.
   *
   * @param vigem Global ViGEm context.
   * @param touch Controller touch event.
   * @return `true` because the visible X360 profile intentionally lacks touch.
   */
  static bool vigem_gamepad_touch(vigem_t *vigem, const gamepad_touch_t &touch);

  /**
   * @brief Ignore motion input for the X360-only ViGEm route.
   *
   * @param vigem Global ViGEm context.
   * @param motion Controller motion event.
   * @return `true` because the visible X360 profile intentionally lacks motion.
   */
  static bool vigem_gamepad_motion(vigem_t *vigem, const gamepad_motion_t &motion);

  /**
   * @brief Ignore battery input for the X360-only ViGEm route.
   *
   * @param vigem Global ViGEm context.
   * @param battery Controller battery event.
   * @return `true` because the visible X360 profile intentionally lacks battery state.
   */
  static bool vigem_gamepad_battery(vigem_t *vigem, const gamepad_battery_t &battery);

  /**
   * @brief Router-owned ViGEm Xbox 360 target adapter.
   */
  class vigem_backend_t final: public win_gamepad::backend_t {
  public:
    /**
     * @brief Construct an attached ViGEm target.
     *
     * @param vigem Global ViGEm context.
     * @param global_index Global gamepad slot.
     * @param generation Router slot generation.
     */
    vigem_backend_t(vigem_t *vigem, int global_index, std::uint64_t generation):
        vigem_ {vigem},
        global_index_ {global_index},
        generation_ {generation} {
    }

    /**
     * @brief Detach the target if the router did not already close it.
     */
    ~vigem_backend_t() override {
      close();
    }

    win_gamepad::backend_kind_e kind() const noexcept override {
      return win_gamepad::backend_kind_e::vigem;
    }

    win_gamepad::profile_kind_e profile() const noexcept override {
      return win_gamepad::profile_kind_e::xbox_360;
    }

    win_gamepad::backend_identity_t identity() const noexcept override {
      return {
        .device_id = generation_,
        .token = {},
      };
    }

    bool update(const gamepad_state_t &state) override {
      return !closed_ && vigem_gamepad_update(vigem_, global_index_, state);
    }

    bool touch(const gamepad_touch_t &touch_event) override {
      return !closed_ && vigem_gamepad_touch(vigem_, touch_event);
    }

    bool motion(const gamepad_motion_t &motion_event) override {
      return !closed_ && vigem_gamepad_motion(vigem_, motion_event);
    }

    bool battery(const gamepad_battery_t &battery_event) override {
      return !closed_ && vigem_gamepad_battery(vigem_, battery_event);
    }

    void close() noexcept override {
      if (!std::exchange(closed_, true) && vigem_) {
        vigem_->free_target(global_index_);
      }
    }

  private:
    vigem_t *vigem_ {};  ///< Non-owning global ViGEm context.
    int global_index_ {};  ///< Global gamepad slot.
    std::uint64_t generation_ {};  ///< Router slot generation.
    bool closed_ {};  ///< Idempotent teardown fence.
  };

  /**
   * @brief Global inputtino device handles shared by clients.
   */
  struct input_raw_t {
    ~input_raw_t() {
      gamepads.reset();
      gamepad_session.reset();
      keyboard_mouse.reset();
      delete vigem;
    }

    std::unique_ptr<win_input::transport_t> keyboard_mouse;  ///< Selected keyboard and mouse transport.
    vigem_t *vigem;  ///< Vigem.
    std::shared_ptr<win_gamepad::virtual_hid_session_t> gamepad_session;  ///< Dynamic VHF gamepad session.
    std::unique_ptr<win_gamepad::router_t> gamepads;  ///< Tagged per-slot gamepad router.

    decltype(CreateSyntheticPointerDevice) *fnCreateSyntheticPointerDevice;  ///< Fn create synthetic pointer device.
    decltype(InjectSyntheticPointerInput) *fnInjectSyntheticPointerInput;  ///< Fn inject synthetic pointer input.
    decltype(DestroySyntheticPointerDevice) *fnDestroySyntheticPointerDevice;  ///< Fn destroy synthetic pointer device.
  };

  input_t input() {
    input_t result {new input_raw_t {}};
    auto &raw = *(input_raw_t *) result.get();

    raw.keyboard_mouse = win_input::make_preferred_input_transport();
    raw.vigem = new vigem_t {};
    if (raw.vigem->init()) {
      delete raw.vigem;
      raw.vigem = nullptr;
    }

    raw.gamepad_session = std::make_shared<win_gamepad::virtual_hid_session_t>(
      win_gamepad::make_system_gamepad_channel()
    );
    if (!raw.gamepad_session->initialize()) {
      BOOST_LOG(warning) << "Lumen Virtual HID gamepads unavailable: "sv << raw.gamepad_session->failure();
    }

    auto vigem_factory = [raw_ptr = &raw](
                           win_gamepad::profile_kind_e profile,
                           const gamepad_id_t &id,
                           const gamepad_arrival_t &,
                           feedback_queue_t feedback_queue,
                           std::uint64_t generation
                         ) -> win_gamepad::create_result_t {
      if (profile != win_gamepad::profile_kind_e::xbox_360) {
        return {
          .backend = {},
          .became_visible = false,
          .error = "ViGEm is restricted to Xbox 360/XInput",
        };
      }
      if (!raw_ptr->vigem) {
        return {
          .backend = {},
          .became_visible = false,
          .error = "ViGEmBus is unavailable",
        };
      }
      if (raw_ptr->vigem->alloc_gamepad_internal(id, feedback_queue, generation) != 0) {
        return {
          .backend = {},
          .became_visible = false,
          .error = "ViGEmBus rejected Xbox 360 target creation",
        };
      }
      return {
        .backend = std::make_unique<vigem_backend_t>(raw_ptr->vigem, id.globalIndex, generation),
        .became_visible = false,
        .error = {},
      };
    };
    raw.gamepads = std::make_unique<win_gamepad::router_t>(
      win_gamepad::make_virtual_hid_gamepad_factory(raw.gamepad_session),
      std::move(vigem_factory)
    );

    // Get pointers to virtual touch/pen input functions (Win10 1809+)
    raw.fnCreateSyntheticPointerDevice = (decltype(CreateSyntheticPointerDevice) *) GetProcAddress(GetModuleHandleA("user32.dll"), "CreateSyntheticPointerDevice");
    raw.fnInjectSyntheticPointerInput = (decltype(InjectSyntheticPointerInput) *) GetProcAddress(GetModuleHandleA("user32.dll"), "InjectSyntheticPointerInput");
    raw.fnDestroySyntheticPointerDevice = (decltype(DestroySyntheticPointerDevice) *) GetProcAddress(GetModuleHandleA("user32.dll"), "DestroySyntheticPointerDevice");

    return result;
  }

  /**
   * @brief Calls InjectSyntheticPointerInput() and switches input desktops if required.
   * @details Must only be called if InjectSyntheticPointerInput() is available.
   * @param input Global Windows input state.
   * @param device The synthetic pointer device handle.
   * @param pointerInfo An array of `POINTER_TYPE_INFO` structs.
   * @param count The number of elements in `pointerInfo`.
   * @return true if input was successfully injected.
   */
  bool inject_synthetic_pointer_input(input_raw_t *input, HSYNTHETICPOINTERDEVICE device, const POINTER_TYPE_INFO *pointerInfo, UINT32 count) {
  retry:
    if (!input->fnInjectSyntheticPointerInput(device, pointerInfo, count)) {
      auto hDesk = syncThreadDesktop();
      if (_lastKnownInputDesktop != hDesk) {
        _lastKnownInputDesktop = hDesk;
        goto retry;
      }
      return false;
    }
    return true;
  }

  void abs_mouse(input_t &input, const touch_port_t &touch_port, float x, float y) {
    // Note: x and y already include the display offset (offset_x/offset_y) from client_to_touchport(),
    // so we must not add offset_x/offset_y again here to avoid double-offsetting on multi-monitor setups.
    auto *raw = (input_raw_t *) input.get();
    const auto result = raw->keyboard_mouse->absolute_mouse(x, y, touch_port.width, touch_port.height);
    if (!result && raw->keyboard_mouse->backend() != win_input::backend_t::fail_closed) {
      BOOST_LOG(error) << "Couldn't send absolute mouse input: "sv << result.status;
    }
  }

  void move_mouse(input_t &input, int deltaX, int deltaY) {
    auto *raw = (input_raw_t *) input.get();
    const auto result = raw->keyboard_mouse->move_mouse(deltaX, deltaY);
    if (!result && raw->keyboard_mouse->backend() != win_input::backend_t::fail_closed) {
      BOOST_LOG(error) << "Couldn't send relative mouse input: "sv << result.status;
    }
  }

  util::point_t get_mouse_loc(input_t &input) {
    static_cast<void>(input);
    POINT p;
    if (!GetCursorPos(&p)) {
      return util::point_t {0.0, 0.0};
    }

    return util::point_t {
      (double) p.x,
      (double) p.y
    };
  }

  void button_mouse(input_t &input, int button, bool release) {
    auto *raw = (input_raw_t *) input.get();
    const auto result = raw->keyboard_mouse->mouse_button(button, release);
    if (!result && raw->keyboard_mouse->backend() != win_input::backend_t::fail_closed) {
      BOOST_LOG(error) << "Couldn't send mouse button input: "sv << result.status;
    }
  }

  void scroll(input_t &input, int distance) {
    auto *raw = (input_raw_t *) input.get();
    const auto result = raw->keyboard_mouse->vertical_scroll(distance);
    if (!result && raw->keyboard_mouse->backend() != win_input::backend_t::fail_closed) {
      BOOST_LOG(error) << "Couldn't send vertical wheel input: "sv << result.status;
    }
  }

  void hscroll(input_t &input, int distance) {
    auto *raw = (input_raw_t *) input.get();
    const auto result = raw->keyboard_mouse->horizontal_scroll(distance);
    if (!result && raw->keyboard_mouse->backend() != win_input::backend_t::fail_closed) {
      BOOST_LOG(error) << "Couldn't send horizontal wheel input: "sv << result.status;
    }
  }

  void keyboard_update(input_t &input, uint16_t modcode, bool release, uint8_t flags) {
    auto *raw = (input_raw_t *) input.get();
    const auto result = raw->keyboard_mouse->keyboard(modcode, release, flags);
    if (!result && raw->keyboard_mouse->backend() != win_input::backend_t::fail_closed) {
      BOOST_LOG(error) << "Couldn't send keyboard input: "sv << result.status;
    }
  }

  void reset_input_session(input_t &input) {
    auto *raw = (input_raw_t *) input.get();
    const auto result = raw->keyboard_mouse->reset_session();
    if (!result) {
      BOOST_LOG(error) << "Couldn't reset keyboard and mouse input session: "sv << result.status;
    }
  }

  bool uses_native_keyboard_repeat(input_t &input) {
    const auto *raw = (const input_raw_t *) input.get();
    return raw && raw->keyboard_mouse && raw->keyboard_mouse->backend() == win_input::backend_t::virtual_hid;
  }

  /**
   * @brief Per-client inputtino devices for touch and pen input.
   */
  struct client_input_raw_t: public client_input_t {
    /**
     * @brief Create per-client raw input devices for touch and pen events.
     *
     * @param input Platform input backend that receives the event.
     */
    client_input_raw_t(input_t &input) {
      global = (input_raw_t *) input.get();
    }

    ~client_input_raw_t() override {
      if (penRepeatTask) {
        task_pool.cancel(penRepeatTask);
      }
      if (touchRepeatTask) {
        task_pool.cancel(touchRepeatTask);
      }

      if (pen) {
        global->fnDestroySyntheticPointerDevice(pen);
      }
      if (touch) {
        global->fnDestroySyntheticPointerDevice(touch);
      }
    }

    input_raw_t *global;

    // Device state and handles for pen and touch input must be stored in the per-client
    // input context, because each connected client may be sending their own independent
    // pen/touch events. To maintain separation, we expose separate pen and touch devices
    // for each client.

    HSYNTHETICPOINTERDEVICE pen {};  ///< Windows synthetic pointer device used for pen events.
    POINTER_TYPE_INFO penInfo {};  ///< Pen info.
    thread_pool_util::ThreadPool::task_id_t penRepeatTask {};  ///< Pen repeat task.

    HSYNTHETICPOINTERDEVICE touch {};  ///< Windows synthetic pointer device used for touch events.
    POINTER_TYPE_INFO touchInfo[10] {};  ///< Touch info.
    UINT32 activeTouchSlots {};  ///< Active touch slots.
    thread_pool_util::ThreadPool::task_id_t touchRepeatTask {};  ///< Touch repeat task.
  };

  /**
   * @brief Allocates a context to store per-client input data.
   * @param input Global Windows input context.
   * @return A unique pointer to a per-client input data context.
   */
  std::unique_ptr<client_input_t> allocate_client_input_context(input_t &input) {
    return std::make_unique<client_input_raw_t>(input);
  }

  /**
   * @brief Compacts the touch slots into a contiguous block and updates the active count.
   * @details Since this swaps entries around, all slot pointers/references are invalid after compaction.
   * @param raw The client-specific input context.
   */
  void perform_touch_compaction(client_input_raw_t *raw) {
    // Windows requires all active touches be contiguous when fed into InjectSyntheticPointerInput().
    UINT32 i;
    for (i = 0; i < ARRAYSIZE(raw->touchInfo); i++) {
      if (raw->touchInfo[i].touchInfo.pointerInfo.pointerFlags == POINTER_FLAG_NONE) {
        // This is an empty slot. Look for a later entry to move into this slot.
        for (UINT32 j = i + 1; j < ARRAYSIZE(raw->touchInfo); j++) {
          if (raw->touchInfo[j].touchInfo.pointerInfo.pointerFlags != POINTER_FLAG_NONE) {
            std::swap(raw->touchInfo[i], raw->touchInfo[j]);
            break;
          }
        }

        // If we didn't find anything, we've reached the end of active slots.
        if (raw->touchInfo[i].touchInfo.pointerInfo.pointerFlags == POINTER_FLAG_NONE) {
          break;
        }
      }
    }

    // Update the number of active touch slots
    raw->activeTouchSlots = i;
  }

  /**
   * @brief Gets a pointer slot by client-relative pointer ID, claiming a new one if necessary.
   * @param raw The raw client-specific input context.
   * @param pointerId The client's pointer ID.
   * @param eventType The LI_TOUCH_EVENT value from the client.
   * @return A pointer to the slot entry.
   */
  POINTER_TYPE_INFO *pointer_by_id(client_input_raw_t *raw, uint32_t pointerId, uint8_t eventType) {
    // Compact active touches into a single contiguous block
    perform_touch_compaction(raw);

    // Try to find a matching pointer ID
    for (UINT32 i = 0; i < ARRAYSIZE(raw->touchInfo); i++) {
      if (raw->touchInfo[i].touchInfo.pointerInfo.pointerId == pointerId && raw->touchInfo[i].touchInfo.pointerInfo.pointerFlags != POINTER_FLAG_NONE) {
        if (eventType == LI_TOUCH_EVENT_DOWN && (raw->touchInfo[i].touchInfo.pointerInfo.pointerFlags & POINTER_FLAG_INCONTACT)) {
          BOOST_LOG(warning) << "Pointer "sv << pointerId << " already down. Did the client drop an up/cancel event?"sv;
        }

        return &raw->touchInfo[i];
      }
    }

    if (eventType != LI_TOUCH_EVENT_HOVER && eventType != LI_TOUCH_EVENT_DOWN) {
      BOOST_LOG(warning) << "Unexpected new pointer "sv << pointerId << " for event "sv << (uint32_t) eventType << ". Did the client drop a down/hover event?"sv;
    }

    // If there was none, grab an unused entry and increment the active slot count
    for (UINT32 i = 0; i < ARRAYSIZE(raw->touchInfo); i++) {
      if (raw->touchInfo[i].touchInfo.pointerInfo.pointerFlags == POINTER_FLAG_NONE) {
        raw->touchInfo[i].touchInfo.pointerInfo.pointerId = pointerId;
        raw->activeTouchSlots = i + 1;
        return &raw->touchInfo[i];
      }
    }

    return nullptr;
  }

  /**
   * @brief Populate common `POINTER_INFO` members shared between pen and touch events.
   * @param pointerInfo The pointer info to populate.
   * @param touchPort The current viewport for translating to screen coordinates.
   * @param eventType The type of touch/pen event.
   * @param x The normalized 0.0-1.0 X coordinate.
   * @param y The normalized 0.0-1.0 Y coordinate.
   */
  void populate_common_pointer_info(POINTER_INFO &pointerInfo, const touch_port_t &touchPort, uint8_t eventType, float x, float y) {
    switch (eventType) {
      case LI_TOUCH_EVENT_HOVER:
        pointerInfo.pointerFlags &= ~POINTER_FLAG_INCONTACT;
        pointerInfo.pointerFlags |= POINTER_FLAG_INRANGE | POINTER_FLAG_UPDATE;
        pointerInfo.ptPixelLocation.x = x * touchPort.width + touchPort.offset_x;
        pointerInfo.ptPixelLocation.y = y * touchPort.height + touchPort.offset_y;
        break;
      case LI_TOUCH_EVENT_DOWN:
        pointerInfo.pointerFlags |= POINTER_FLAG_INRANGE | POINTER_FLAG_INCONTACT | POINTER_FLAG_DOWN;
        pointerInfo.ptPixelLocation.x = x * touchPort.width + touchPort.offset_x;
        pointerInfo.ptPixelLocation.y = y * touchPort.height + touchPort.offset_y;
        break;
      case LI_TOUCH_EVENT_UP:
        // We expect to get another LI_TOUCH_EVENT_HOVER if the pointer remains in range
        pointerInfo.pointerFlags &= ~(POINTER_FLAG_INCONTACT | POINTER_FLAG_INRANGE);
        pointerInfo.pointerFlags |= POINTER_FLAG_UP;
        break;
      case LI_TOUCH_EVENT_MOVE:
        pointerInfo.pointerFlags |= POINTER_FLAG_INRANGE | POINTER_FLAG_INCONTACT | POINTER_FLAG_UPDATE;
        pointerInfo.ptPixelLocation.x = x * touchPort.width + touchPort.offset_x;
        pointerInfo.ptPixelLocation.y = y * touchPort.height + touchPort.offset_y;
        break;
      case LI_TOUCH_EVENT_CANCEL:
      case LI_TOUCH_EVENT_CANCEL_ALL:
        // If we were in contact with the touch surface at the time of the cancellation,
        // we'll set POINTER_FLAG_UP, otherwise set POINTER_FLAG_UPDATE.
        if (pointerInfo.pointerFlags & POINTER_FLAG_INCONTACT) {
          pointerInfo.pointerFlags |= POINTER_FLAG_UP;
        } else {
          pointerInfo.pointerFlags |= POINTER_FLAG_UPDATE;
        }
        pointerInfo.pointerFlags &= ~(POINTER_FLAG_INCONTACT | POINTER_FLAG_INRANGE);
        pointerInfo.pointerFlags |= POINTER_FLAG_CANCELED;
        break;
      case LI_TOUCH_EVENT_HOVER_LEAVE:
        pointerInfo.pointerFlags &= ~(POINTER_FLAG_INCONTACT | POINTER_FLAG_INRANGE);
        pointerInfo.pointerFlags |= POINTER_FLAG_UPDATE;
        break;
      case LI_TOUCH_EVENT_BUTTON_ONLY:
        // On Windows, we can only pass buttons if we have an active pointer
        if (pointerInfo.pointerFlags != POINTER_FLAG_NONE) {
          pointerInfo.pointerFlags |= POINTER_FLAG_UPDATE;
        }
        break;
      default:
        BOOST_LOG(warning) << "Unknown touch event: "sv << (uint32_t) eventType;
        break;
    }
  }

  // Active pointer interactions sent via InjectSyntheticPointerInput() seem to be automatically
  // cancelled by Windows if not repeated/updated within about a second. To avoid this, refresh
  // the injected input periodically.
  constexpr auto ISPI_REPEAT_INTERVAL = 50ms;  ///< Protocol or platform constant for ispi repeat interval.

  /**
   * @brief Repeats the current touch state to avoid the interactions timing out.
   * @param raw The raw client-specific input context.
   */
  void repeat_touch(client_input_raw_t *raw) {
    if (!inject_synthetic_pointer_input(raw->global, raw->touch, raw->touchInfo, raw->activeTouchSlots)) {
      auto err = GetLastError();
      BOOST_LOG(warning) << "Failed to refresh virtual touch input: "sv << err;
    }

    raw->touchRepeatTask = task_pool.pushDelayed(repeat_touch, ISPI_REPEAT_INTERVAL, raw).task_id;
  }

  /**
   * @brief Repeats the current pen state to avoid the interactions timing out.
   * @param raw The raw client-specific input context.
   */
  void repeat_pen(client_input_raw_t *raw) {
    if (!inject_synthetic_pointer_input(raw->global, raw->pen, &raw->penInfo, 1)) {
      auto err = GetLastError();
      BOOST_LOG(warning) << "Failed to refresh virtual pen input: "sv << err;
    }

    raw->penRepeatTask = task_pool.pushDelayed(repeat_pen, ISPI_REPEAT_INTERVAL, raw).task_id;
  }

  /**
   * @brief Cancels all active touches.
   * @param raw The raw client-specific input context.
   */
  void cancel_all_active_touches(client_input_raw_t *raw) {
    // Cancel touch repeat callbacks
    if (raw->touchRepeatTask) {
      task_pool.cancel(raw->touchRepeatTask);
      raw->touchRepeatTask = nullptr;
    }

    // Compact touches to update activeTouchSlots
    perform_touch_compaction(raw);

    // If we have active slots, cancel them all
    if (raw->activeTouchSlots > 0) {
      for (UINT32 i = 0; i < raw->activeTouchSlots; i++) {
        populate_common_pointer_info(raw->touchInfo[i].touchInfo.pointerInfo, {}, LI_TOUCH_EVENT_CANCEL_ALL, 0.0f, 0.0f);
        raw->touchInfo[i].touchInfo.touchMask = TOUCH_MASK_NONE;
      }
      if (!inject_synthetic_pointer_input(raw->global, raw->touch, raw->touchInfo, raw->activeTouchSlots)) {
        auto err = GetLastError();
        BOOST_LOG(warning) << "Failed to cancel all virtual touch input: "sv << err;
      }
    }

    // Zero all touch state
    std::memset(raw->touchInfo, 0, sizeof(raw->touchInfo));
    raw->activeTouchSlots = 0;
  }

  // These are edge-triggered pointer state flags that should always be cleared next frame
  constexpr auto EDGE_TRIGGERED_POINTER_FLAGS = POINTER_FLAG_DOWN | POINTER_FLAG_UP | POINTER_FLAG_CANCELED | POINTER_FLAG_UPDATE;  ///< Protocol or platform constant for edge triggered pointer flags.

  /**
   * @brief Sends a touch event to the OS.
   * @param input The client-specific input context.
   * @param touch_port The current viewport for translating to screen coordinates.
   * @param touch The touch event.
   */
  void touch_update(client_input_t *input, const touch_port_t &touch_port, const touch_input_t &touch) {
    auto raw = (client_input_raw_t *) input;

    // Bail if we're not running on an OS that supports virtual touch input
    if (!raw->global->fnCreateSyntheticPointerDevice || !raw->global->fnInjectSyntheticPointerInput || !raw->global->fnDestroySyntheticPointerDevice) {
      BOOST_LOG(warning) << "Touch input requires Windows 10 1809 or later"sv;
      return;
    }

    // If there's not already a virtual touch device, create one now
    if (!raw->touch) {
      if (touch.eventType != LI_TOUCH_EVENT_CANCEL_ALL) {
        BOOST_LOG(info) << "Creating virtual touch input device"sv;
        raw->touch = raw->global->fnCreateSyntheticPointerDevice(PT_TOUCH, ARRAYSIZE(raw->touchInfo), POINTER_FEEDBACK_DEFAULT);
        if (!raw->touch) {
          auto err = GetLastError();
          BOOST_LOG(warning) << "Failed to create virtual touch device: "sv << err;
          return;
        }
      } else {
        // No need to cancel anything if we had no touch input device
        return;
      }
    }

    // Cancel touch repeat callbacks
    if (raw->touchRepeatTask) {
      task_pool.cancel(raw->touchRepeatTask);
      raw->touchRepeatTask = nullptr;
    }

    // If this is a special request to cancel all touches, do that and return
    if (touch.eventType == LI_TOUCH_EVENT_CANCEL_ALL) {
      cancel_all_active_touches(raw);
      return;
    }

    // Find or allocate an entry for this touch pointer ID
    auto pointer = pointer_by_id(raw, touch.pointerId, touch.eventType);
    if (!pointer) {
      BOOST_LOG(error) << "No unused pointer entries! Cancelling all active touches!"sv;
      cancel_all_active_touches(raw);
      pointer = pointer_by_id(raw, touch.pointerId, touch.eventType);
    }

    pointer->type = PT_TOUCH;

    auto &touchInfo = pointer->touchInfo;
    touchInfo.pointerInfo.pointerType = PT_TOUCH;

    // Populate shared pointer info fields
    populate_common_pointer_info(touchInfo.pointerInfo, touch_port, touch.eventType, touch.x, touch.y);

    touchInfo.touchMask = TOUCH_MASK_NONE;

    // Pressure and contact area only apply to in-contact pointers.
    //
    // The clients also pass distance and tool size for hovers, but Windows doesn't
    // provide APIs to receive that data.
    if (touchInfo.pointerInfo.pointerFlags & POINTER_FLAG_INCONTACT) {
      if (touch.pressureOrDistance != 0.0f) {
        touchInfo.touchMask |= TOUCH_MASK_PRESSURE;

        // Convert the 0.0f..1.0f float to the 0..1024 range that Windows uses
        touchInfo.pressure = (UINT32) (touch.pressureOrDistance * 1024);
      } else {
        // The default touch pressure is 512
        touchInfo.pressure = 512;
      }

      if (touch.contactAreaMajor != 0.0f && touch.contactAreaMinor != 0.0f) {
        // For the purposes of contact area calculation, we will assume the touches
        // are at a 45 degree angle if rotation is unknown. This will scale the major
        // axis value by width and height equally.
        float rotationAngleDegs = touch.rotation == LI_ROT_UNKNOWN ? 45 : touch.rotation;

        float majorAxisAngle = rotationAngleDegs * (M_PI / 180);
        float minorAxisAngle = majorAxisAngle + (M_PI / 2);

        // Estimate the contact rectangle
        float contactWidth = (std::cos(majorAxisAngle) * touch.contactAreaMajor) + (std::cos(minorAxisAngle) * touch.contactAreaMinor);
        float contactHeight = (std::sin(majorAxisAngle) * touch.contactAreaMajor) + (std::sin(minorAxisAngle) * touch.contactAreaMinor);

        // Convert into screen coordinates centered at the touch location and constrained by screen dimensions
        touchInfo.rcContact.left = std::max<LONG>(touch_port.offset_x, touchInfo.pointerInfo.ptPixelLocation.x - std::floor(contactWidth / 2));
        touchInfo.rcContact.right = std::min<LONG>(touch_port.offset_x + touch_port.width, touchInfo.pointerInfo.ptPixelLocation.x + std::ceil(contactWidth / 2));
        touchInfo.rcContact.top = std::max<LONG>(touch_port.offset_y, touchInfo.pointerInfo.ptPixelLocation.y - std::floor(contactHeight / 2));
        touchInfo.rcContact.bottom = std::min<LONG>(touch_port.offset_y + touch_port.height, touchInfo.pointerInfo.ptPixelLocation.y + std::ceil(contactHeight / 2));

        touchInfo.touchMask |= TOUCH_MASK_CONTACTAREA;
      }
    } else {
      touchInfo.pressure = 0;
      touchInfo.rcContact = {};
    }

    if (touch.rotation != LI_ROT_UNKNOWN) {
      touchInfo.touchMask |= TOUCH_MASK_ORIENTATION;
      touchInfo.orientation = touch.rotation;
    } else {
      touchInfo.orientation = 0;
    }

    if (!inject_synthetic_pointer_input(raw->global, raw->touch, raw->touchInfo, raw->activeTouchSlots)) {
      auto err = GetLastError();
      BOOST_LOG(warning) << "Failed to inject virtual touch input: "sv << err;
      return;
    }

    // Clear pointer flags that should only remain set for one frame
    touchInfo.pointerInfo.pointerFlags &= ~EDGE_TRIGGERED_POINTER_FLAGS;

    // If we still have an active touch, refresh the touch state periodically
    if (raw->activeTouchSlots > 1 || touchInfo.pointerInfo.pointerFlags != POINTER_FLAG_NONE) {
      raw->touchRepeatTask = task_pool.pushDelayed(repeat_touch, ISPI_REPEAT_INTERVAL, raw).task_id;
    }
  }

  /**
   * @brief Sends a pen event to the OS.
   * @param input The client-specific input context.
   * @param touch_port The current viewport for translating to screen coordinates.
   * @param pen The pen event.
   */
  void pen_update(client_input_t *input, const touch_port_t &touch_port, const pen_input_t &pen) {
    auto raw = (client_input_raw_t *) input;

    // Bail if we're not running on an OS that supports virtual pen input
    if (!raw->global->fnCreateSyntheticPointerDevice || !raw->global->fnInjectSyntheticPointerInput || !raw->global->fnDestroySyntheticPointerDevice) {
      BOOST_LOG(warning) << "Pen input requires Windows 10 1809 or later"sv;
      return;
    }

    // If there's not already a virtual pen device, create one now
    if (!raw->pen) {
      if (pen.eventType != LI_TOUCH_EVENT_CANCEL_ALL) {
        BOOST_LOG(info) << "Creating virtual pen input device"sv;
        raw->pen = raw->global->fnCreateSyntheticPointerDevice(PT_PEN, 1, POINTER_FEEDBACK_DEFAULT);
        if (!raw->pen) {
          auto err = GetLastError();
          BOOST_LOG(warning) << "Failed to create virtual pen device: "sv << err;
          return;
        }
      } else {
        // No need to cancel anything if we had no pen input device
        return;
      }
    }

    // Cancel pen repeat callbacks
    if (raw->penRepeatTask) {
      task_pool.cancel(raw->penRepeatTask);
      raw->penRepeatTask = nullptr;
    }

    raw->penInfo.type = PT_PEN;

    auto &penInfo = raw->penInfo.penInfo;
    penInfo.pointerInfo.pointerType = PT_PEN;
    penInfo.pointerInfo.pointerId = 0;

    // Populate shared pointer info fields
    populate_common_pointer_info(penInfo.pointerInfo, touch_port, pen.eventType, pen.x, pen.y);

    // Windows only supports a single pen button, so send all buttons as the barrel button
    if (pen.penButtons) {
      penInfo.penFlags |= PEN_FLAG_BARREL;
    } else {
      penInfo.penFlags &= ~PEN_FLAG_BARREL;
    }

    switch (pen.toolType) {
      default:
      case LI_TOOL_TYPE_PEN:
        penInfo.penFlags &= ~PEN_FLAG_ERASER;
        break;
      case LI_TOOL_TYPE_ERASER:
        penInfo.penFlags |= PEN_FLAG_ERASER;
        break;
      case LI_TOOL_TYPE_UNKNOWN:
        // Leave tool flags alone
        break;
    }

    penInfo.penMask = PEN_MASK_NONE;

    // Windows doesn't support hover distance, so only pass pressure/distance when the pointer is in contact
    if ((penInfo.pointerInfo.pointerFlags & POINTER_FLAG_INCONTACT) && pen.pressureOrDistance != 0.0f) {
      penInfo.penMask |= PEN_MASK_PRESSURE;

      // Convert the 0.0f..1.0f float to the 0..1024 range that Windows uses
      penInfo.pressure = (UINT32) (pen.pressureOrDistance * 1024);
    } else {
      // The default pen pressure is 0
      penInfo.pressure = 0;
    }

    if (pen.rotation != LI_ROT_UNKNOWN) {
      penInfo.penMask |= PEN_MASK_ROTATION;
      penInfo.rotation = pen.rotation;
    } else {
      penInfo.rotation = 0;
    }

    // We require rotation and tilt to perform the conversion to X and Y tilt angles
    if (pen.tilt != LI_TILT_UNKNOWN && pen.rotation != LI_ROT_UNKNOWN) {
      auto rotationRads = pen.rotation * (M_PI / 180.f);
      auto tiltRads = pen.tilt * (M_PI / 180.f);
      auto r = std::sin(tiltRads);
      auto z = std::cos(tiltRads);

      // Convert polar coordinates into X and Y tilt angles
      penInfo.penMask |= PEN_MASK_TILT_X | PEN_MASK_TILT_Y;
      penInfo.tiltX = (INT32) (std::atan2(std::sin(-rotationRads) * r, z) * 180.f / M_PI);
      penInfo.tiltY = (INT32) (std::atan2(std::cos(-rotationRads) * r, z) * 180.f / M_PI);
    } else {
      penInfo.tiltX = 0;
      penInfo.tiltY = 0;
    }

    if (!inject_synthetic_pointer_input(raw->global, raw->pen, &raw->penInfo, 1)) {
      auto err = GetLastError();
      BOOST_LOG(warning) << "Failed to inject virtual pen input: "sv << err;
      return;
    }

    // Clear pointer flags that should only remain set for one frame
    penInfo.pointerInfo.pointerFlags &= ~EDGE_TRIGGERED_POINTER_FLAGS;

    // If we still have an active pen interaction, refresh the pen state periodically
    if (penInfo.pointerInfo.pointerFlags != POINTER_FLAG_NONE) {
      raw->penRepeatTask = task_pool.pushDelayed(repeat_pen, ISPI_REPEAT_INTERVAL, raw).task_id;
    }
  }

  void unicode(input_t &input, char *utf8, int size) {
    auto *raw = (input_raw_t *) input.get();
    const auto result = raw->keyboard_mouse->unicode(utf8, size);
    if (!result) {
      BOOST_LOG(error) << "Couldn't send Unicode input: "sv << result.status;
    }
  }

  int alloc_gamepad(input_t &input, const gamepad_id_t &id, const gamepad_arrival_t &metadata, feedback_queue_t feedback_queue) {
    auto raw = (input_raw_t *) input.get();
    if (!raw->gamepads) {
      return -1;
    }
    std::string error;
    if (!raw->gamepads->allocate(
          id,
          metadata,
          config::input.gamepad,
          config::input.gamepad_backend,
          std::move(feedback_queue),
          error
        )) {
      BOOST_LOG(warning) << "Unable to allocate Windows gamepad "sv << id.globalIndex << ": "sv << error;
      return -1;
    }
    if (!error.empty()) {
      BOOST_LOG(warning) << "Windows gamepad "sv << id.globalIndex << ": "sv << error;
    }
    const auto route = raw->gamepads->snapshot(id.globalIndex);
    BOOST_LOG(info)
      << "Gamepad "sv << id.globalIndex << " allocated with backend "sv
      << (route.backend == win_gamepad::backend_kind_e::virtual_hid ? "virtualhid"sv : "vigem"sv);
    return 0;
  }

  void free_gamepad(input_t &input, int nr) {
    auto raw = (input_raw_t *) input.get();

    if (!raw->gamepads) {
      return;
    }
    raw->gamepads->free(nr);
  }

  /**
   * @brief Converts the standard button flags into X360 format.
   * @param gamepad_state The gamepad button/axis state sent from the client.
   * @return XUSB_BUTTON flags.
   */
  static XUSB_BUTTON x360_buttons(const gamepad_state_t &gamepad_state) {
    int buttons {};

    auto flags = gamepad_state.buttonFlags;
    if (flags & DPAD_UP) {
      buttons |= XUSB_GAMEPAD_DPAD_UP;
    }
    if (flags & DPAD_DOWN) {
      buttons |= XUSB_GAMEPAD_DPAD_DOWN;
    }
    if (flags & DPAD_LEFT) {
      buttons |= XUSB_GAMEPAD_DPAD_LEFT;
    }
    if (flags & DPAD_RIGHT) {
      buttons |= XUSB_GAMEPAD_DPAD_RIGHT;
    }
    if (flags & START) {
      buttons |= XUSB_GAMEPAD_START;
    }
    if (flags & BACK) {
      buttons |= XUSB_GAMEPAD_BACK;
    }
    if (flags & LEFT_STICK) {
      buttons |= XUSB_GAMEPAD_LEFT_THUMB;
    }
    if (flags & RIGHT_STICK) {
      buttons |= XUSB_GAMEPAD_RIGHT_THUMB;
    }
    if (flags & LEFT_BUTTON) {
      buttons |= XUSB_GAMEPAD_LEFT_SHOULDER;
    }
    if (flags & RIGHT_BUTTON) {
      buttons |= XUSB_GAMEPAD_RIGHT_SHOULDER;
    }
    if (flags & (HOME | MISC_BUTTON)) {
      buttons |= XUSB_GAMEPAD_GUIDE;
    }
    if (flags & A) {
      buttons |= XUSB_GAMEPAD_A;
    }
    if (flags & B) {
      buttons |= XUSB_GAMEPAD_B;
    }
    if (flags & X) {
      buttons |= XUSB_GAMEPAD_X;
    }
    if (flags & Y) {
      buttons |= XUSB_GAMEPAD_Y;
    }

    return (XUSB_BUTTON) buttons;
  }

  /**
   * @brief Update an X360 report from Sunshine gamepad state.
   * @param gamepad The gamepad to update.
   * @param gamepad_state The gamepad button/axis state sent from the client.
   */
  static void x360_update_state(gamepad_context_t &gamepad, const gamepad_state_t &gamepad_state) {
    auto &report = gamepad.report.x360;

    report.wButtons = x360_buttons(gamepad_state);
    report.bLeftTrigger = gamepad_state.lt;
    report.bRightTrigger = gamepad_state.rt;
    report.sThumbLX = gamepad_state.lsX;
    report.sThumbLY = gamepad_state.lsY;
    report.sThumbRX = gamepad_state.rsX;
    report.sThumbRY = gamepad_state.rsY;
  }

  /**
   * @brief Sends DS4 input with updated timestamps and repeats to keep timestamp updated.
   * @details Some applications require updated timestamps values to register DS4 input.
   * @param vigem The global ViGEm context object.
   * @param nr The global gamepad index.
   */
  void ds4_update_ts_and_send(vigem_t *vigem, int nr) {
    auto &gamepad = vigem->gamepads[nr];

    // Cancel any pending updates. We will requeue one here when we're finished.
    if (gamepad.repeat_task) {
      task_pool.cancel(gamepad.repeat_task);
      gamepad.repeat_task = nullptr;
    }

    if (gamepad.gp && vigem_target_is_attached(gamepad.gp.get())) {
      auto now = std::chrono::steady_clock::now();
      auto delta_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now - gamepad.last_report_ts);

      // Timestamp is reported in 5.333us units
      gamepad.report.ds4.Report.wTimestamp += (uint16_t) (delta_ns.count() / 5333);

      // Send the report to the virtual device
      auto status = vigem_target_ds4_update_ex(vigem->client.get(), gamepad.gp.get(), gamepad.report.ds4);
      if (!VIGEM_SUCCESS(status)) {
        BOOST_LOG(warning) << "Couldn't send gamepad input to ViGEm ["sv << util::hex(status).to_string_view() << ']';
        return;
      }

      // Repeat at least every 100ms to keep the 16-bit timestamp field from overflowing
      gamepad.last_report_ts = now;
      gamepad.repeat_task = task_pool.pushDelayed(ds4_update_ts_and_send, 100ms, vigem, nr).task_id;
    }
  }

  /**
   * @brief Submit updated Sunshine gamepad state to the virtual device.
   * @param vigem Global ViGEm context.
   * @param nr The gamepad index to update.
   * @param gamepad_state The gamepad button/axis state sent from the client.
   */
  static bool vigem_gamepad_update(vigem_t *vigem, int nr, const gamepad_state_t &gamepad_state) {
    if (!vigem) {
      return false;
    }

    auto &gamepad = vigem->gamepads[nr];
    if (!gamepad.gp) {
      return false;
    }

    x360_update_state(gamepad, gamepad_state);
    const auto status = vigem_target_x360_update(vigem->client.get(), gamepad.gp.get(), gamepad.report.x360);
    if (!VIGEM_SUCCESS(status)) {
      BOOST_LOG(warning) << "Couldn't send gamepad input to ViGEm ["sv << util::hex(status).to_string_view() << ']';
      return false;
    }
    return true;
  }

  /**
   * @brief Sends a gamepad touch event to the OS.
   * @param vigem Global ViGEm context.
   * @param touch The touch event.
   */
  static bool vigem_gamepad_touch(vigem_t *vigem, const gamepad_touch_t &touch) {
    if (!vigem) {
      return false;
    }

    auto &gamepad = vigem->gamepads[touch.id.globalIndex];
    if (!gamepad.gp) {
      return false;
    }

    // Touch is only supported on DualShock 4 controllers
    if (vigem_target_get_type(gamepad.gp.get()) != DualShock4Wired) {
      return true;
    }

    auto &report = gamepad.report.ds4.Report;

    uint8_t pointerIndex;
    if (touch.eventType == LI_TOUCH_EVENT_DOWN) {
      if (gamepad.available_pointers & 0x1) {
        // Reserve pointer index 0 for this touch
        gamepad.pointer_id_map[touch.pointerId] = pointerIndex = 0;
        gamepad.available_pointers &= ~(1 << pointerIndex);

        // Set pointer 0 down
        report.sCurrentTouch.bIsUpTrackingNum1 &= ~0x80;
        report.sCurrentTouch.bIsUpTrackingNum1++;
      } else if (gamepad.available_pointers & 0x2) {
        // Reserve pointer index 1 for this touch
        gamepad.pointer_id_map[touch.pointerId] = pointerIndex = 1;
        gamepad.available_pointers &= ~(1 << pointerIndex);

        // Set pointer 1 down
        report.sCurrentTouch.bIsUpTrackingNum2 &= ~0x80;
        report.sCurrentTouch.bIsUpTrackingNum2++;
      } else {
        BOOST_LOG(warning) << "No more free pointer indices! Did the client miss an touch up event?"sv;
        return false;
      }
    } else if (touch.eventType == LI_TOUCH_EVENT_CANCEL_ALL) {
      // Raise both pointers
      report.sCurrentTouch.bIsUpTrackingNum1 |= 0x80;
      report.sCurrentTouch.bIsUpTrackingNum2 |= 0x80;

      // Remove all pointer index mappings
      gamepad.pointer_id_map.clear();

      // All pointers are now available
      gamepad.available_pointers = 0x3;
    } else {
      auto i = gamepad.pointer_id_map.find(touch.pointerId);
      if (i == gamepad.pointer_id_map.end()) {
        BOOST_LOG(warning) << "Pointer ID not found! Did the client miss a touch down event?"sv;
        return false;
      }

      pointerIndex = (*i).second;

      if (touch.eventType == LI_TOUCH_EVENT_UP || touch.eventType == LI_TOUCH_EVENT_CANCEL) {
        // Remove the pointer index mapping
        gamepad.pointer_id_map.erase(i);

        // Set pointer up
        if (pointerIndex == 0) {
          report.sCurrentTouch.bIsUpTrackingNum1 |= 0x80;
        } else {
          report.sCurrentTouch.bIsUpTrackingNum2 |= 0x80;
        }

        // Free the pointer index
        gamepad.available_pointers |= (1 << pointerIndex);
      } else if (touch.eventType != LI_TOUCH_EVENT_MOVE) {
        BOOST_LOG(warning) << "Unsupported touch event for gamepad: "sv << (uint32_t) touch.eventType;
        return false;
      }
    }

    // Touchpad is 1920x943 according to ViGEm
    uint16_t x = touch.x * 1920;
    uint16_t y = touch.y * 943;
    uint8_t touchData[] = {
      (uint8_t) (x & 0xFF),  // Low 8 bits of X
      (uint8_t) ((x >> 8 & 0x0F) | (y & 0x0F) << 4),  // High 4 bits of X and low 4 bits of Y
      (uint8_t) (y >> 4 & 0xFF)  // High 8 bits of Y
    };

    report.sCurrentTouch.bPacketCounter++;
    if (touch.eventType != LI_TOUCH_EVENT_CANCEL_ALL) {
      if (pointerIndex == 0) {
        memcpy(report.sCurrentTouch.bTouchData1, touchData, sizeof(touchData));
      } else {
        memcpy(report.sCurrentTouch.bTouchData2, touchData, sizeof(touchData));
      }
    }

    ds4_update_ts_and_send(vigem, touch.id.globalIndex);
    return true;
  }

  /**
   * @brief Sends a gamepad motion event to the OS.
   * @param vigem Global ViGEm context.
   * @param motion The motion event.
   */
  static bool vigem_gamepad_motion(vigem_t *vigem, const gamepad_motion_t &motion) {
    if (!vigem) {
      return false;
    }

    auto &gamepad = vigem->gamepads[motion.id.globalIndex];
    if (!gamepad.gp) {
      return false;
    }

    // Motion is only supported on DualShock 4 controllers
    if (vigem_target_get_type(gamepad.gp.get()) != DualShock4Wired) {
      return true;
    }

    ds4_update_motion(gamepad, motion.motionType, motion.x, motion.y, motion.z);
    ds4_update_ts_and_send(vigem, motion.id.globalIndex);
    return true;
  }

  /**
   * @brief Sends a gamepad battery event to the OS.
   * @param vigem Global ViGEm context.
   * @param battery The battery event.
   */
  static bool vigem_gamepad_battery(vigem_t *vigem, const gamepad_battery_t &battery) {
    if (!vigem) {
      return false;
    }

    auto &gamepad = vigem->gamepads[battery.id.globalIndex];
    if (!gamepad.gp) {
      return false;
    }

    // Battery is only supported on DualShock 4 controllers
    if (vigem_target_get_type(gamepad.gp.get()) != DualShock4Wired) {
      return true;
    }

    // For details on the report format of these battery level fields, see:
    // https://github.com/torvalds/linux/blob/946c6b59c56dc6e7d8364a8959cb36bf6d10bc37/drivers/hid/hid-playstation.c#L2305-L2314

    auto &report = gamepad.report.ds4.Report;

    // Update the battery state if it is known
    switch (battery.state) {
      case LI_BATTERY_STATE_CHARGING:
      case LI_BATTERY_STATE_DISCHARGING:
        if (battery.state == LI_BATTERY_STATE_CHARGING) {
          report.bBatteryLvlSpecial |= 0x10;  // Connected via USB
        } else {
          report.bBatteryLvlSpecial &= ~0x10;  // Not connected via USB
        }

        // If there was a special battery status set before, clear that and
        // initialize the battery level to 50%. It will be overwritten below
        // if the actual percentage is known.
        if ((report.bBatteryLvlSpecial & 0xF) > 0xA) {
          report.bBatteryLvlSpecial = (report.bBatteryLvlSpecial & ~0xF) | 0x5;
        }
        break;

      case LI_BATTERY_STATE_FULL:
        report.bBatteryLvlSpecial = 0x1B;  // USB + Battery Full
        report.bBatteryLvl = 0xFF;
        break;

      case LI_BATTERY_STATE_NOT_PRESENT:
      case LI_BATTERY_STATE_NOT_CHARGING:
        report.bBatteryLvlSpecial = 0x1F;  // USB + Charging Error
        break;

      default:
        break;
    }

    // Update the battery level if it is known
    if (battery.percentage != LI_BATTERY_PERCENTAGE_UNKNOWN) {
      report.bBatteryLvl = battery.percentage * 255 / 100;

      // Don't overwrite low nibble if there's a special status there (see above)
      if ((report.bBatteryLvlSpecial & 0x10) && (report.bBatteryLvlSpecial & 0xF) <= 0xA) {
        report.bBatteryLvlSpecial = (report.bBatteryLvlSpecial & ~0xF) | ((battery.percentage + 5) / 10);
      }
    }

    ds4_update_ts_and_send(vigem, battery.id.globalIndex);
    return true;
  }

  /**
   * @brief Route ordinary gamepad state to the slot's tagged backend.
   *
   * @param input Global Windows input context.
   * @param nr Global gamepad slot.
   * @param gamepad_state Current buttons, sticks, and triggers.
   */
  void gamepad_update(input_t &input, int nr, const gamepad_state_t &gamepad_state) {
    auto *raw = (input_raw_t *) input.get();
    if (raw->gamepads) {
      static_cast<void>(raw->gamepads->update(nr, gamepad_state));
    }
  }

  /**
   * @brief Route gamepad touch input to the slot's tagged backend.
   *
   * @param input Global Windows input context.
   * @param touch Controller touch event.
   */
  void gamepad_touch(input_t &input, const gamepad_touch_t &touch) {
    auto *raw = (input_raw_t *) input.get();
    if (raw->gamepads) {
      static_cast<void>(raw->gamepads->touch(touch));
    }
  }

  /**
   * @brief Route gamepad motion input to the slot's tagged backend.
   *
   * @param input Global Windows input context.
   * @param motion Controller motion sample.
   */
  void gamepad_motion(input_t &input, const gamepad_motion_t &motion) {
    auto *raw = (input_raw_t *) input.get();
    if (raw->gamepads) {
      static_cast<void>(raw->gamepads->motion(motion));
    }
  }

  /**
   * @brief Route gamepad battery input to the slot's tagged backend.
   *
   * @param input Global Windows input context.
   * @param battery Controller battery metadata.
   */
  void gamepad_battery(input_t &input, const gamepad_battery_t &battery) {
    auto *raw = (input_raw_t *) input.get();
    if (raw->gamepads) {
      static_cast<void>(raw->gamepads->battery(battery));
    }
  }

  void freeInput(void *p) {
    auto input = (input_raw_t *) p;

    delete input;
  }

  std::vector<supported_gamepad_t> &supported_gamepads(input_t *input) {
    if (!input) {
      static std::vector gps {
        supported_gamepad_t {"auto", true, ""},
        supported_gamepad_t {"generic", false, ""},
        supported_gamepad_t {"x360", false, ""},
        supported_gamepad_t {"xone", false, ""},
        supported_gamepad_t {"xseries", false, ""},
        supported_gamepad_t {"ds4", false, ""},
        supported_gamepad_t {"ds5", false, ""},
        supported_gamepad_t {"switch", false, ""},
      };

      return gps;
    }

    const auto *raw = (input_raw_t *) input;
    const bool vhid_available = raw->gamepad_session && raw->gamepad_session->available();
    const bool vigem_available = raw->vigem != nullptr;
    const bool vhid_enabled = vhid_available && config::input.gamepad_backend != "vigem"sv;
    const bool vigem_enabled = vigem_available && config::input.gamepad_backend != "virtualhid"sv;
    const std::string vhid_reason = vhid_enabled ? "" : "gamepads.virtualhid-not-available";
    const std::string vigem_reason = vigem_enabled ? "" : "gamepads.vigem-not-available";
    const bool auto_enabled = config::input.gamepad_backend == "virtualhid"sv ? vhid_enabled :
                              config::input.gamepad_backend == "vigem"sv      ? vigem_enabled :
                                                                                (vhid_enabled || vigem_enabled);
    static std::vector gps {
      supported_gamepad_t {"auto", true, ""},
      supported_gamepad_t {"generic", false, ""},
      supported_gamepad_t {"x360", false, ""},
      supported_gamepad_t {"xone", false, ""},
      supported_gamepad_t {"xseries", false, ""},
      supported_gamepad_t {"ds4", false, ""},
      supported_gamepad_t {"ds5", false, ""},
      supported_gamepad_t {"switch", false, ""},
    };

    gps[0] = {"auto", auto_enabled, auto_enabled ? "" : "gamepads.no-backend-available"};
    gps[1] = {"generic", vhid_enabled, vhid_reason};
    gps[2] = {"x360", vigem_enabled, vigem_reason};
    gps[3] = {"xone", vhid_enabled, vhid_reason};
    gps[4] = {"xseries", vhid_enabled, vhid_reason};
    gps[5] = {"ds4", vhid_enabled, vhid_reason};
    gps[6] = {"ds5", vhid_enabled, vhid_reason};
    gps[7] = {"switch", vhid_enabled, vhid_reason};

    for (auto &[name, is_enabled, reason_disabled] : gps) {
      if (!is_enabled) {
        BOOST_LOG(warning) << "Gamepad " << name << " is disabled due to " << reason_disabled;
      }
    }

    return gps;
  }

  /**
   * @brief Returns the supported platform capabilities to advertise to the client.
   * @return Capability flags.
   */
  platform_caps::caps_t get_capabilities() {
    platform_caps::caps_t caps = 0;

    // ViGEm is X360-only. Modern Virtual HID profiles can expose touchpads.
    if (config::input.gamepad != "x360"sv && config::input.gamepad_backend != "vigem"sv) {
      caps |= platform_caps::controller_touch;
    }

    // We support pen and touch input on Win10 1809+
    if (GetProcAddress(GetModuleHandleA("user32.dll"), "CreateSyntheticPointerDevice") != nullptr) {
      if (config::input.native_pen_touch) {
        caps |= platform_caps::pen_touch;
      }
    } else {
      BOOST_LOG(warning) << "Touch input requires Windows 10 1809 or later"sv;
    }

    return caps;
  }
}  // namespace platf
