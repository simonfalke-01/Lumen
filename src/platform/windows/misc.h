/**
 * @file src/platform/windows/misc.h
 * @brief Miscellaneous declarations for Windows.
 */
#pragma once

// standard includes
#include <chrono>
#include <filesystem>
#include <string>
#include <string_view>

// platform includes
#include <Windows.h>
#include <winnt.h>

namespace platf {
  /**
   * @brief Write status details to the log.
   *
   * @param prefix Text prefix used when formatting the message.
   * @param status Native status code returned by the platform API.
   */
  void print_status(const std::string_view &prefix, HRESULT status);
  /**
   * @brief Synchronize thread desktop.
   *
   * @return Bound input desktop, or `nullptr` when opening or binding fails.
   */
  HDESK syncThreadDesktop();

  /**
   * @brief Read the current Windows high-resolution performance counter.
   *
   * @return Raw QPC tick value from `QueryPerformanceCounter`.
   */
  int64_t qpc_counter();

  /**
   * @brief Convert the difference between two QPC readings to nanoseconds.
   *
   * @param performance_counter1 Newer performance-counter reading.
   * @param performance_counter2 Older performance-counter reading.
   * @return Duration represented by the difference between two QPC values.
   */
  std::chrono::nanoseconds qpc_time_difference(int64_t performance_counter1, int64_t performance_counter2);

  /**
   * @brief Get file version information from a Windows executable or driver file.
   * @param file_path Path to the file to query.
   * @param version_str Output parameter for version string in format "major.minor.build.revision".
   * @return true if version info was successfully extracted, false otherwise.
   */
  bool getFileVersionInfo(const std::filesystem::path &file_path, std::string &version_str);

  /**
   * @brief Cap the GPU driver frame rate just below an LSP stream's rate while it runs.
   *
   * Nested calls are reference counted; the newest stream rate sets the cap. Controlled by the
   * `lsp_frame_cap` option, NVIDIA only, and recorded in the nvprefs undo file so a crash or
   * service stop restores the previous value.
   *
   * @param framerate_x100 Stream frame rate in hundredths of a frame per second.
   */
  void stream_frame_cap_will_start(int framerate_x100);

  /**
   * @brief Release one `stream_frame_cap_will_start()` and restore the cap after the last one.
   */
  void stream_frame_cap_will_stop();
}  // namespace platf
