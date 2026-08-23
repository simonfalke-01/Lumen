/**
 * @file src/platform/windows/gamepad_profile.h
 * @brief Lightweight Windows gamepad profile identity shared by routing and codecs.
 */
#pragma once

namespace platf::win_gamepad {

  /**
   * @brief Logical controller identity exposed by a Windows gamepad backend.
   */
  enum class profile_kind_e {
    generic,  ///< Generic HID gamepad.
    xbox_360,  ///< Xbox 360 XUSB gamepad.
    xbox_one,  ///< Xbox One HID gamepad.
    xbox_series,  ///< Xbox Series HID gamepad.
    dualshock4,  ///< USB DualShock 4 HID gamepad.
    dualsense,  ///< USB DualSense HID gamepad.
    switch_pro,  ///< Nintendo Switch Pro HID gamepad.
  };

}  // namespace platf::win_gamepad
