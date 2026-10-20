/**
 * @file src/process.cpp
 * @brief Definitions for the startup and shutdown of the apps started by a streaming Session.
 */
#define BOOST_BIND_GLOBAL_PLACEHOLDERS

// standard includes
#include <algorithm>
#include <array>
#include <filesystem>
#include <iomanip>
#include <limits>
#include <locale>
#include <numeric>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// lib includes
#include <boost/algorithm/string.hpp>
#include <boost/crc.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/token_functions.hpp>
#include <openssl/evp.h>
#include <openssl/sha.h>

// local includes
#include "config.h"
#include "crypto.h"
#include "display_device.h"
#include "logging.h"
#include "platform/common.h"
#include "process.h"
#include "system_tray.h"
#include "utility.h"

#ifdef _WIN32
  // from_utf8() string conversion function
  #include "platform/windows/utf_utils.h"

  // _SH constants for _wfsopen()
  #include <share.h>
#endif

namespace proc {
  using namespace std::literals;
  namespace pt = boost::property_tree;

  namespace {
    constexpr std::array lsp_environment_names {
      "LUMEN_CLIENT_PROTOCOL",
      "LUMEN_CLIENT_POINTER_RATE",
      "LUMEN_CLIENT_CONTROLLER_RATE",
      "LUMEN_CLIENT_SENSOR_RATE",
      "LUMEN_CLIENT_RECONCILIATION_RATE",
      "LUMEN_CLIENT_CONTROLLER_OUTPUT",
      "LUMEN_CLIENT_AUDIO_CHANNELS",
      "LUMEN_CLIENT_AUDIO_STREAMS",
      "LUMEN_CLIENT_AUDIO_COUPLED_STREAMS",
      "LUMEN_CLIENT_AUDIO_MAPPING",
      "LUMEN_CLIENT_AUDIO_FRAME_SAMPLES",
      "LUMEN_CLIENT_AUDIO_BITRATE",
      "LUMEN_CLIENT_AUDIO_INBAND_FEC",
      "LUMEN_CLIENT_AUDIO_DTX",
      "LUMEN_CLIENT_VIDEO_CODEC",
      "LUMEN_CLIENT_VIDEO_PROFILE",
      "LUMEN_CLIENT_VIDEO_PIXEL_CLASS",
      "LUMEN_CLIENT_VIDEO_COLOR_PRIMARIES",
      "LUMEN_CLIENT_VIDEO_TRANSFER_FUNCTION",
      "LUMEN_CLIENT_VIDEO_MATRIX_COEFFICIENTS",
      "LUMEN_CLIENT_VIDEO_FULL_RANGE",
      "LUMEN_CLIENT_VIDEO_BITRATE",
      "LUMEN_CLIENT_VIDEO_MAXIMUM_FRAME_AGE_US",
      "LUMEN_CLIENT_VIDEO_FLEXFEC",
      "LUMEN_CLIENT_VIDEO_RTX",
    };

    /** @brief Remove prior LSP-only values before every application launch. */
    void clear_lsp_launch_environment(boost::process::v1::environment &env) {
      for (const auto *name : lsp_environment_names) {
        env.erase(name);
      }
    }
  }  // namespace

  proc_t proc;  ///< Global process registry used to track and terminate child processes.

  /**
   * @brief RAII helper that runs shutdown cleanup when destroyed.
   */
  class deinit_t: public platf::deinit_t {
  public:
    /**
     * @brief Destroy the process subsystem deinitializer.
     */
    ~deinit_t() {
      proc.terminate();
    }
  };

  std::unique_ptr<platf::deinit_t> init() {
    return std::make_unique<deinit_t>();
  }

  void apply_launch_environment(
    boost::process::v1::environment &env,
    const int app_id,
    const std::string_view app_name,
    const rtsp_stream::launch_session_t &launch_session
  ) {
    auto refresh_numerator = launch_session.refresh_numerator;
    auto refresh_denominator = launch_session.refresh_denominator;
    if (refresh_numerator == 0 || refresh_denominator == 0) {
      refresh_numerator = launch_session.fps > 0 ? static_cast<std::uint32_t>(launch_session.fps) : 0U;
      refresh_denominator = 1;
    }
    const auto divisor = std::gcd(refresh_numerator, refresh_denominator);
    if (divisor > 1) {
      refresh_numerator /= divisor;
      refresh_denominator /= divisor;
    }
    std::ostringstream exact_fps;
    exact_fps.imbue(std::locale::classic());
    exact_fps << std::setprecision(std::numeric_limits<double>::max_digits10)
              << static_cast<double>(refresh_numerator) / refresh_denominator;

    env["LUMEN_APP_ID"] = std::to_string(app_id);
    env["LUMEN_APP_NAME"] = std::string {app_name};
    env["LUMEN_CLIENT_WIDTH"] = std::to_string(launch_session.width);
    env["LUMEN_CLIENT_HEIGHT"] = std::to_string(launch_session.height);
    env["LUMEN_CLIENT_FPS"] = exact_fps.str();
    env["LUMEN_CLIENT_REFRESH_NUMERATOR"] = std::to_string(refresh_numerator);
    env["LUMEN_CLIENT_REFRESH_DENOMINATOR"] = std::to_string(refresh_denominator);
    env["LUMEN_CLIENT_HDR"] = launch_session.enable_hdr ? "true" : "false";
    env["LUMEN_CLIENT_GCMAP"] = std::to_string(launch_session.gcmap);
    env["LUMEN_CLIENT_HOST_AUDIO"] = launch_session.host_audio ? "true" : "false";
    env["LUMEN_CLIENT_ENABLE_SOPS"] = launch_session.enable_sops ? "true" : "false";


    const auto channel_count = launch_session.surround_info & 65535;
    switch (channel_count) {
      case 2:
        env["LUMEN_CLIENT_AUDIO_CONFIGURATION"] = "2.0";
        break;
      case 6:
        env["LUMEN_CLIENT_AUDIO_CONFIGURATION"] = "5.1";
        break;
      case 8:
        env["LUMEN_CLIENT_AUDIO_CONFIGURATION"] = "7.1";
        break;
    }
    env["LUMEN_CLIENT_AUDIO_SURROUND_PARAMS"] = launch_session.surround_params;
  }

  bool lsp_launch_request_t::valid() const noexcept {
    const auto audio_channels_valid = audio_channels == 2 || audio_channels == 6 || audio_channels == 8;
    return width > 0 && height > 0 && refresh_numerator != 0 && refresh_denominator != 0 &&
           refresh_numerator / refresh_denominator <= static_cast<std::uint32_t>(std::numeric_limits<int>::max()) &&
           pointer_rate >= 125 && pointer_rate <= 16'000 && controller_rate >= 125 && controller_rate <= 2'000 &&
           sensor_rate >= 125 && sensor_rate <= 4'000 && reconciliation_rate >= 50 && reconciliation_rate <= 1'000 &&
           audio_channels_valid && audio_streams != 0 && audio_streams <= audio_channels &&
           audio_coupled_streams <= audio_streams && audio_frame_samples != 0 && audio_bitrate != 0 &&
           video_codec != 0 && video_profile != 0 && video_pixel_class != 0 &&
           video_color_primaries != 0 && video_transfer_function != 0 && video_matrix_coefficients != 0 &&
           video_bits_per_second != 0 &&
           maximum_frame_age_microseconds != 0;
  }

  void apply_lsp_launch_environment(
    boost::process::v1::environment &env,
    const lsp_launch_request_t &request
  ) {
    env["LUMEN_CLIENT_PROTOCOL"] = "lsp/1";
    env["LUMEN_CLIENT_POINTER_RATE"] = std::to_string(request.pointer_rate);
    env["LUMEN_CLIENT_CONTROLLER_RATE"] = std::to_string(request.controller_rate);
    env["LUMEN_CLIENT_SENSOR_RATE"] = std::to_string(request.sensor_rate);
    env["LUMEN_CLIENT_RECONCILIATION_RATE"] = std::to_string(request.reconciliation_rate);
    env["LUMEN_CLIENT_CONTROLLER_OUTPUT"] = request.controller_output ? "true" : "false";
    env["LUMEN_CLIENT_AUDIO_CHANNELS"] = std::to_string(request.audio_channels);
    env["LUMEN_CLIENT_AUDIO_STREAMS"] = std::to_string(request.audio_streams);
    env["LUMEN_CLIENT_AUDIO_COUPLED_STREAMS"] = std::to_string(request.audio_coupled_streams);
    std::string audio_mapping;
    for (std::size_t index = 0; index < request.audio_channels; ++index) {
      if (!audio_mapping.empty()) {
        audio_mapping.push_back(',');
      }
      audio_mapping += std::to_string(request.audio_mapping[index]);
    }
    env["LUMEN_CLIENT_AUDIO_MAPPING"] = audio_mapping;
    env["LUMEN_CLIENT_AUDIO_FRAME_SAMPLES"] = std::to_string(request.audio_frame_samples);
    env["LUMEN_CLIENT_AUDIO_BITRATE"] = std::to_string(request.audio_bitrate);
    env["LUMEN_CLIENT_AUDIO_INBAND_FEC"] = request.audio_inband_fec ? "true" : "false";
    env["LUMEN_CLIENT_AUDIO_DTX"] = request.audio_dtx ? "true" : "false";
    env["LUMEN_CLIENT_VIDEO_CODEC"] = std::to_string(request.video_codec);
    env["LUMEN_CLIENT_VIDEO_PROFILE"] = std::to_string(request.video_profile);
    env["LUMEN_CLIENT_VIDEO_PIXEL_CLASS"] = std::to_string(request.video_pixel_class);
    env["LUMEN_CLIENT_VIDEO_COLOR_PRIMARIES"] = std::to_string(request.video_color_primaries);
    env["LUMEN_CLIENT_VIDEO_TRANSFER_FUNCTION"] = std::to_string(request.video_transfer_function);
    env["LUMEN_CLIENT_VIDEO_MATRIX_COEFFICIENTS"] = std::to_string(request.video_matrix_coefficients);
    env["LUMEN_CLIENT_VIDEO_FULL_RANGE"] = request.video_full_range ? "true" : "false";
    env["LUMEN_CLIENT_VIDEO_BITRATE"] = std::to_string(request.video_bits_per_second);
    env["LUMEN_CLIENT_VIDEO_MAXIMUM_FRAME_AGE_US"] = std::to_string(request.maximum_frame_age_microseconds);
    env["LUMEN_CLIENT_VIDEO_FLEXFEC"] = request.flexfec ? "true" : "false";
    env["LUMEN_CLIENT_VIDEO_RTX"] = request.rtx ? "true" : "false";
  }

  void terminate_process_group(boost::process::v1::child &proc, boost::process::v1::group &group, std::chrono::seconds exit_timeout) {
    if (group.valid() && platf::process_group_running((std::uintptr_t) group.native_handle())) {
      if (exit_timeout.count() > 0) {
        // Request processes in the group to exit gracefully
        if (platf::request_process_group_exit((std::uintptr_t) group.native_handle())) {
          // If the request was successful, wait for a little while for them to exit.
          BOOST_LOG(info) << "Successfully requested the app to exit. Waiting up to "sv << exit_timeout.count() << " seconds for it to close."sv;

          // group::wait_for() and similar functions are broken and deprecated, so we use a simple polling loop
          while (platf::process_group_running((std::uintptr_t) group.native_handle()) && (--exit_timeout).count() >= 0) {
            std::this_thread::sleep_for(1s);
          }

          if (exit_timeout.count() < 0) {
            BOOST_LOG(warning) << "App did not fully exit within the timeout. Terminating the app's remaining processes."sv;
          } else {
            BOOST_LOG(info) << "All app processes have successfully exited."sv;
          }
        } else {
          BOOST_LOG(info) << "App did not respond to a graceful termination request. Forcefully terminating the app's processes."sv;
        }
      } else {
        BOOST_LOG(info) << "No graceful exit timeout was specified for this app. Forcefully terminating the app's processes."sv;
      }

      // We always call terminate() even if we waited successfully for all processes above.
      // This ensures the process group state is consistent with the OS in boost.
      std::error_code ec;
      group.terminate(ec);
      group.detach();
    }

    if (proc.valid()) {
      // avoid zombie process
      proc.detach();
    }
  }

  /**
   * @brief Resolve the working directory for a configured command.
   *
   * @param cmd Command line to execute or inspect.
   * @param env Environment variables for the child process.
   * @return Directory used to launch the command, falling back to PATH lookup when needed.
   */
  boost::filesystem::path find_working_directory(const std::string &cmd, boost::process::v1::environment &env) {
    // Parse the raw command string into parts to get the actual command portion
    std::vector<std::string> parts;
    try {
#ifdef _WIN32
      parts = boost::program_options::split_winmain(cmd);
#else
      parts = boost::program_options::split_unix(cmd);
#endif
    } catch (boost::escaped_list_error &err) {
      BOOST_LOG(error) << "Boost failed to parse command ["sv << cmd << "] because " << err.what();
      return boost::filesystem::path();
    }
    if (parts.empty()) {
      BOOST_LOG(error) << "Unable to parse command: "sv << cmd;
      return boost::filesystem::path();
    }

    BOOST_LOG(debug) << "Parsed target ["sv << parts.at(0) << "] from command ["sv << cmd << ']';

    // If the target is a URL, don't parse any further here
    if (parts.at(0).find("://") != std::string::npos) {
      return boost::filesystem::path();
    }

    // If the cmd path is not an absolute path, resolve it using our PATH variable
    boost::filesystem::path cmd_path(parts.at(0));
    if (!cmd_path.is_absolute()) {
      cmd_path = boost::process::v1::search_path(parts.at(0));
      if (cmd_path.empty()) {
        BOOST_LOG(error) << "Unable to find executable ["sv << parts.at(0) << "]. Is it in your PATH?"sv;
        return boost::filesystem::path();
      }
    }

    BOOST_LOG(debug) << "Resolved target ["sv << parts.at(0) << "] to path ["sv << cmd_path << ']';

    // Now that we have a complete path, we can just use parent_path()
    return cmd_path.parent_path();
  }

  int proc_t::execute(int app_id, std::shared_ptr<rtsp_stream::launch_session_t> launch_session) {
    return execute_impl(app_id, std::move(launch_session), nullptr);
  }

  int proc_t::execute_impl(
    const int app_id,
    std::shared_ptr<rtsp_stream::launch_session_t> launch_session,
    const lsp_launch_request_t *lsp_request
  ) {
    auto lifecycle = _lifecycle->lock();
    // Ensure starting from a clean slate
    terminate();
    const auto process_generation = ++(*_lifecycle)->generation;
    (*_lifecycle)->legacy_attachable = false;
    (*_lifecycle)->lsp_owned = false;
    launch_session->process_generation = process_generation;

    auto iter = std::find_if(_apps.begin(), _apps.end(), [&app_id](const auto app) {
      return app.id == std::to_string(app_id);
    });

    if (iter == _apps.end()) {
      BOOST_LOG(error) << "Couldn't find app with ID ["sv << app_id << ']';
      return 404;
    }
    (*_lifecycle)->legacy_attachable = !launch_session->client_cert.empty();

    _app_id = app_id;
    _app_started_at = std::chrono::system_clock::now();
    _app = *iter;
    _app_prep_begin = std::begin(_app.prep_cmds);
    _app_prep_it = _app_prep_begin;

    // LUMEN_* carries exact modern values while LUMEN_* retains the legacy shape.
    clear_lsp_launch_environment(_env);
    apply_launch_environment(_env, _app_id, _app.name, *launch_session);
    if (lsp_request != nullptr) {
      apply_lsp_launch_environment(_env, *lsp_request);
    }

    if (!_app.output.empty() && _app.output != "null"sv) {
#ifdef _WIN32
      // fopen() interprets the filename as an ANSI string on Windows, so we must convert it
      // to UTF-16 and use the wchar_t variants for proper Unicode log file path support.
      auto woutput = utf_utils::from_utf8(_app.output);

      // Use _SH_DENYNO to allow us to open this log file again for writing even if it is
      // still open from a previous execution. This is required to handle the case of a
      // detached process executing again while the previous process is still running.
      _pipe.reset(_wfsopen(woutput.c_str(), L"a", _SH_DENYNO));
#else
      _pipe.reset(fopen(_app.output.c_str(), "a"));
#endif
    }

    std::error_code ec;
    // Executed when returning from function
    auto fg = util::fail_guard([&]() {
      terminate();
    });

    for (; _app_prep_it != std::end(_app.prep_cmds); ++_app_prep_it) {
      auto &cmd = *_app_prep_it;

      // Skip empty commands
      if (cmd.do_cmd.empty()) {
        continue;
      }

      boost::filesystem::path working_dir = _app.working_dir.empty() ?
                                              find_working_directory(cmd.do_cmd, _env) :
                                              boost::filesystem::path(_app.working_dir);
      BOOST_LOG(info) << "Executing Do Cmd: ["sv << cmd.do_cmd << ']';
      auto child = platf::run_command(cmd.elevated, true, cmd.do_cmd, working_dir, _env, _pipe.get(), ec, nullptr);

      if (ec) {
        BOOST_LOG(error) << "Couldn't run ["sv << cmd.do_cmd << "]: System: "sv << ec.message();
        // We don't want any prep commands failing launch of the desktop.
        // This is to prevent the issue where users reboot their PC and need to log in with Lumen.
        // permission_denied is typically returned when the user impersonation fails, which can happen when user is not signed in yet.
        if (!(_app.cmd.empty() && ec == std::errc::permission_denied)) {
          return -1;
        }
      }

      child.wait(ec);
      if (ec) {
        BOOST_LOG(error) << '[' << cmd.do_cmd << "] wait failed with error code ["sv << ec << ']';
        return -1;
      }
      auto ret = child.exit_code();
      if (ret != 0) {
        BOOST_LOG(error) << '[' << cmd.do_cmd << "] exited with code ["sv << ret << ']';
        return -1;
      }
    }

    for (auto &cmd : _app.detached) {
      boost::filesystem::path working_dir = _app.working_dir.empty() ?
                                              find_working_directory(cmd, _env) :
                                              boost::filesystem::path(_app.working_dir);
      BOOST_LOG(info) << "Spawning ["sv << cmd << "] in ["sv << working_dir << ']';
      auto child = platf::run_command(_app.elevated, true, cmd, working_dir, _env, _pipe.get(), ec, nullptr);
      if (ec) {
        BOOST_LOG(warning) << "Couldn't spawn ["sv << cmd << "]: System: "sv << ec.message();
      } else {
        child.detach();
      }
    }

    if (_app.cmd.empty()) {
      BOOST_LOG(info) << "Executing [Desktop]"sv;
      placebo = true;
    } else {
      boost::filesystem::path working_dir = _app.working_dir.empty() ?
                                              find_working_directory(_app.cmd, _env) :
                                              boost::filesystem::path(_app.working_dir);
      BOOST_LOG(info) << "Executing: ["sv << _app.cmd << "] in ["sv << working_dir << ']';
      _process = platf::run_command(_app.elevated, true, _app.cmd, working_dir, _env, _pipe.get(), ec, &_process_group);
      if (ec) {
        BOOST_LOG(warning) << "Couldn't run ["sv << _app.cmd << "]: System: "sv << ec.message();
        return -1;
      }
    }

    _app_launch_time = std::chrono::steady_clock::now();
    static_cast<void>(authorize_cancel_by_certificate(launch_session->client_cert, process_generation));

    fg.disable();

    return 0;
  }

  proc_t::lsp_launch_result_t proc_t::execute_lsp_if_idle(
    const int app_id,
    const lsp_launch_request_t &request
  ) {
    auto lifecycle = _lifecycle->lock();
    if (running() > 0) {
      return {.status = 409};
    }
    if (!request.valid()) {
      return {.status = -1};
    }
    auto launch = std::make_shared<rtsp_stream::launch_session_t>();
    launch->appid = app_id;
    launch->unique_id = "lsp";
    launch->width = request.width;
    launch->height = request.height;
    launch->fps = static_cast<int>(std::max<std::uint32_t>(1, request.refresh_numerator / request.refresh_denominator));
    launch->refresh_numerator = request.refresh_numerator;
    launch->refresh_denominator = request.refresh_denominator;
    launch->surround_info = request.audio_channels;
    launch->continuous_audio = !request.audio_dtx;
    launch->enable_hdr = request.hdr;
    launch->enable_sops = request.flexfec || request.rtx;
    const auto status = execute_impl(app_id, launch, &request);
    if (status == 0) {
      (*_lifecycle)->lsp_owned = true;
    }
    return {
      .status = status,
      .process_generation = status == 0 ? launch->process_generation : 0,
    };
  }

  lsp_process_state_t proc_t::lsp_process_state() {
    auto lifecycle = _lifecycle->lock();
    const auto application_id = running();
    return {
      .application_id = application_id,
      .process_generation = application_id > 0 ? (*_lifecycle)->generation : 0,
      .running = application_id > 0,
      .lsp_owned = application_id > 0 && (*_lifecycle)->lsp_owned,
    };
  }

  bool proc_t::terminate_lsp_generation(const std::uint64_t process_generation) {
    auto lifecycle = _lifecycle->lock();
    if (process_generation == 0 || process_generation != (*_lifecycle)->generation ||
        !(*_lifecycle)->lsp_owned) {
      return false;
    }
    if (running() > 0) {
      terminate();
    }
    return true;
  }

  int proc_t::running() {
    auto lifecycle = _lifecycle->lock();
#ifndef _WIN32
    // On POSIX OSes, we must periodically wait for our children to avoid
    // them becoming zombies. This must be synchronized carefully with
    // calls to bp::wait() and platf::process_group_running() which both
    // invoke waitpid() under the hood.
    auto reaper = util::fail_guard([]() {
      while (waitpid(-1, nullptr, WNOHANG) > 0);
    });
#endif

    if (placebo) {
      return _app_id;
    } else if (_app.wait_all && _process_group && platf::process_group_running((std::uintptr_t) _process_group.native_handle())) {
      // The app is still running if any process in the group is still running
      return _app_id;
    } else if (_process.running()) {
      // The app is still running only if the initial process launched is still running
      return _app_id;
    } else if (_app.auto_detach && _process.native_exit_code() == 0 && std::chrono::steady_clock::now() - _app_launch_time < 5s) {
      BOOST_LOG(info) << "App exited gracefully within 5 seconds of launch. Treating the app as a detached command."sv;
      BOOST_LOG(info) << "Adjust this behavior in the Applications tab or apps.json if this is not what you want."sv;
      placebo = true;
      return _app_id;
    }

    // Perform cleanup actions now if needed
    if (_process) {
      BOOST_LOG(info) << "App exited with code ["sv << _process.native_exit_code() << ']';
      terminate();
    }

    return 0;
  }

  bool proc_t::authorize_cancel_by_certificate(
    const std::string_view client_certificate,
    const std::uint64_t process_generation
  ) {
    auto lifecycle = _lifecycle->lock();
    if (client_certificate.empty() || process_generation != (*_lifecycle)->generation || !(*_lifecycle)->legacy_attachable) {
      return false;
    }
    (*_lifecycle)->cancel_client_certificates.emplace(client_certificate);
    return true;
  }

  std::uint64_t proc_t::generation() {
    auto lifecycle = _lifecycle->lock();
    return (*_lifecycle)->generation;
  }

  bool proc_t::publish_legacy_session(
    const std::uint64_t process_generation,
    const std::string_view client_certificate,
    const std::function<bool()> &publish
  ) {
    auto lifecycle = _lifecycle->lock();
    if (process_generation != (*_lifecycle)->generation) {
      return false;
    }
    const auto current_app = running();
    if (current_app > 0 && !(*_lifecycle)->legacy_attachable) {
      return false;
    }
    if (!publish()) {
      return false;
    }
    if (current_app > 0 && !client_certificate.empty()) {
      (*_lifecycle)->cancel_client_certificates.emplace(client_certificate);
    }
    return true;
  }

  bool proc_t::terminate_if_owned_by_certificate(const std::string_view client_certificate) {
    auto lifecycle = _lifecycle->lock();
    if (client_certificate.empty() || !(*_lifecycle)->cancel_client_certificates.contains(std::string {client_certificate})) {
      return false;
    }
    if (running() <= 0) {
      return false;
    }
    terminate();
    return true;
  }

  proc_t::owner_cleanup_result_t proc_t::cleanup_owned_process_generation(
    const std::string_view client_certificate,
    const std::uint64_t process_generation
  ) {
    auto lifecycle = _lifecycle->lock();
    if (process_generation != (*_lifecycle)->generation) {
      return {};
    }
    const auto process_running = running() > 0;
    return {
      .generation_matched = true,
      .process_running = process_running,
      .process_terminated = process_running && terminate_if_owned_by_certificate(client_certificate),
    };
  }

  void proc_t::terminate() {
    auto lifecycle = _lifecycle->lock();
    std::error_code ec;
    placebo = false;
    (*_lifecycle)->legacy_attachable = false;
    (*_lifecycle)->lsp_owned = false;
    (*_lifecycle)->cancel_client_certificates.clear();
    terminate_process_group(_process, _process_group, _app.exit_timeout);
    _process = boost::process::v1::child();
    _process_group = boost::process::v1::group();

    for (; _app_prep_it != _app_prep_begin; --_app_prep_it) {
      auto &cmd = *(_app_prep_it - 1);

      if (cmd.undo_cmd.empty()) {
        continue;
      }

      boost::filesystem::path working_dir = _app.working_dir.empty() ?
                                              find_working_directory(cmd.undo_cmd, _env) :
                                              boost::filesystem::path(_app.working_dir);
      BOOST_LOG(info) << "Executing Undo Cmd: ["sv << cmd.undo_cmd << ']';
      auto child = platf::run_command(cmd.elevated, true, cmd.undo_cmd, working_dir, _env, _pipe.get(), ec, nullptr);

      if (ec) {
        BOOST_LOG(warning) << "System: "sv << ec.message();
      }

      child.wait();
      auto ret = child.exit_code();

      if (ret != 0) {
        BOOST_LOG(warning) << "Return code ["sv << ret << ']';
      }
    }

    _pipe.reset();

    bool has_run = _app_id > 0;

    // Only show the Stopped notification if we actually have an app to stop
    // Since terminate() is always run when a new app has started
    if (proc::proc.get_last_run_app_name().length() > 0 && has_run) {
#if defined LUMEN_TRAY && LUMEN_TRAY >= 1
      system_tray::update_tray_stopped(proc::proc.get_last_run_app_name());
#endif

      display_device::revert_configuration();
    }

    _app_id = -1;
  }

  const std::vector<ctx_t> &proc_t::get_apps() const {
    return _apps;
  }

  std::vector<ctx_t> &proc_t::get_apps() {
    return _apps;
  }

  // Gets application image from application list.
  // Returns image from assets directory if found there.
  // Returns default image if image configuration is not set.
  // Returns http content-type header compatible image type.
  std::string proc_t::get_app_image(int app_id) {
    auto iter = std::find_if(_apps.begin(), _apps.end(), [&app_id](const auto app) {
      return app.id == std::to_string(app_id);
    });
    auto app_image_path = iter == _apps.end() ? std::string() : iter->image_path;

    return validate_app_image_path(app_image_path);
  }

  std::string proc_t::get_last_run_app_name() {
    auto lifecycle = _lifecycle->lock();
    return _app.name;
  }

  std::optional<std::chrono::system_clock::time_point> proc_t::started_at() {
    if (running() <= 0) {
      return std::nullopt;
    }
    auto lifecycle = _lifecycle->lock();
    return _app_started_at;
  }

  proc_t::~proc_t() {
    // It's not safe to call terminate() here because our proc_t is a static variable
    // that may be destroyed after the Boost loggers have been destroyed. Instead,
    // we return a deinit_t to main() to handle termination when we're exiting.
    // Once we reach this point here, termination must have already happened.
    assert(!placebo);
    assert(!_process.running());
  }

  /**
   * @brief Find the closing parenthesis for an environment-variable expression.
   *
   * @param begin Iterator positioned at the opening parenthesis.
   * @param end End iterator for the expression being scanned.
   * @return Iterator for the matching closing parenthesis, or end when unmatched.
   */
  std::string_view::iterator find_match(std::string_view::iterator begin, std::string_view::iterator end) {
    int stack = 0;

    --begin;
    do {
      ++begin;
      switch (*begin) {
        case '(':
          ++stack;
          break;
        case ')':
          --stack;
      }
    } while (begin != end && stack != 0);

    if (begin == end) {
      throw std::out_of_range("Missing closing bracket \')\'");
    }
    return begin;
  }

  /**
   * @brief Parse env val.
   *
   * @param env Environment variables for the child process.
   * @param val_raw Raw value that may contain $(NAME) substitutions.
   * @return Value with recognized environment-variable substitutions expanded.
   */
  std::string parse_env_val(boost::process::v1::native_environment &env, const std::string_view &val_raw) {
    auto pos = std::begin(val_raw);
    auto dollar = std::find(pos, std::end(val_raw), '$');

    std::stringstream ss;

    while (dollar != std::end(val_raw)) {
      auto next = dollar + 1;
      if (next != std::end(val_raw)) {
        switch (*next) {
          case '(':
            {
              ss.write(pos, (dollar - pos));
              auto var_begin = next + 1;
              auto var_end = find_match(next, std::end(val_raw));
              auto var_name = std::string {var_begin, var_end};

#ifdef _WIN32
              // Windows treats environment variable names in a case-insensitive manner,
              // so we look for a case-insensitive match here. This is critical for
              // correctly appending to PATH on Windows.
              auto itr = std::find_if(env.cbegin(), env.cend(), [&](const auto &e) {
                return boost::iequals(e.get_name(), var_name);
              });
              if (itr != env.cend()) {
                // Use an existing case-insensitive match
                var_name = itr->get_name();
              }
#endif

              ss << env[var_name].to_string();

              pos = var_end + 1;
              next = var_end;

              break;
            }
          case '$':
            ss.write(pos, (next - pos));
            pos = next + 1;
            ++next;
            break;
        }

        dollar = std::find(next, std::end(val_raw), '$');
      } else {
        dollar = next;
      }
    }

    ss.write(pos, (dollar - pos));

    return ss.str();
  }

  /**
   * @brief Validates a path whether it is a valid PNG.
   * @param path The path to the PNG file.
   * @return true if the file has a valid PNG signature, false otherwise.
   */
  bool check_valid_png(const std::filesystem::path &path) {
    // PNG signature as defined in PNG specification
    // http://www.libpng.org/pub/png/spec/1.2/PNG-Structure.html
    static constexpr std::array<unsigned char, 8> PNG_SIGNATURE = {
      0x89,
      0x50,
      0x4E,
      0x47,
      0x0D,
      0x0A,
      0x1A,
      0x0A
    };

    std::ifstream file(path, std::ios::binary);
    if (!file) {
      return false;
    }

    std::array<unsigned char, 8> header;
    file.read(reinterpret_cast<char *>(header.data()), 8);

    if (file.gcount() != 8) {
      return false;
    }

    return header == PNG_SIGNATURE;
  }

  /**
   * @brief Validate app image path.
   */
  std::string validate_app_image_path(std::string app_image_path) {
    if (app_image_path.empty()) {
      return DEFAULT_APP_IMAGE_PATH;
    }

    // get the image extension and convert it to lowercase
    auto image_extension = std::filesystem::path(app_image_path).extension().string();
    boost::to_lower(image_extension);

    // return the default box image if the extension is not "png"
    if (image_extension != ".png") {
      return DEFAULT_APP_IMAGE_PATH;
    }

    // check if image is in assets directory
    if (auto full_image_path = std::filesystem::path(LUMEN_ASSETS_DIR) / app_image_path; std::filesystem::exists(full_image_path)) {
      // Validate PNG signature
      if (!check_valid_png(full_image_path)) {
        BOOST_LOG(warning) << "Invalid PNG file at path ["sv << full_image_path << ']';
        return DEFAULT_APP_IMAGE_PATH;
      }
      return full_image_path.string();
    }

    if (app_image_path == "./assets/steam.png") {
      // handle old default steam image definition
      return LUMEN_ASSETS_DIR "/steam.png";
    }

    // check if specified image exists
    if (std::error_code code; !std::filesystem::exists(app_image_path, code)) {
      // return default box image if image does not exist
      BOOST_LOG(warning) << "Couldn't find app image at path ["sv << app_image_path << ']';
      return DEFAULT_APP_IMAGE_PATH;
    }

    // Validate PNG signature
    if (!check_valid_png(app_image_path)) {
      BOOST_LOG(warning) << "Invalid PNG file at path ["sv << app_image_path << ']';
      return DEFAULT_APP_IMAGE_PATH;
    }

    // image is a png, and not in assets directory
    // return only "content-type" http header compatible image type
    return app_image_path;
  }

  app_kind_e app_kind(const ctx_t &app) {
    const auto launches_steam = [](std::string command) {
      boost::to_lower(command);
      return command.find("steam://") != std::string::npos || command.find("steam.exe") != std::string::npos;
    };
    if (launches_steam(app.cmd) || std::ranges::any_of(app.detached, launches_steam)) {
      return app_kind_e::steam;
    }
    if (app.cmd.empty() && app.detached.empty()) {
      return app_kind_e::desktop;
    }
    return app_kind_e::app;
  }

  std::optional<std::string> custom_image_path(const ctx_t &app) {
    if (app.image_path.empty()) {
      return std::nullopt;
    }
    auto path = validate_app_image_path(app.image_path);
    std::error_code error;
    const auto image = std::filesystem::weakly_canonical(path, error);
    const auto assets = std::filesystem::weakly_canonical(LUMEN_ASSETS_DIR, error);
    if (error || image.parent_path() == assets) {
      return std::nullopt;
    }
    return path;
  }

  /**
   * @brief Calculate the SHA-256 digest for a file.
   *
   * @param filename File path whose contents should be hashed.
   * @return Lowercase hexadecimal SHA-256 digest, or std::nullopt on read/hash failure.
   */
  std::optional<std::string> calculate_sha256(const std::string &filename) {
    crypto::md_ctx_t ctx {EVP_MD_CTX_create()};
    if (!ctx) {
      return std::nullopt;
    }

    if (!EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr)) {
      return std::nullopt;
    }

    // Read file and update calculated SHA
    char buf[1024 * 16];
    std::ifstream file(filename, std::ifstream::binary);
    while (file.good()) {
      file.read(buf, sizeof(buf));
      if (!EVP_DigestUpdate(ctx.get(), buf, file.gcount())) {
        return std::nullopt;
      }
    }
    file.close();

    unsigned char result[SHA256_DIGEST_LENGTH];
    if (!EVP_DigestFinal_ex(ctx.get(), result, nullptr)) {
      return std::nullopt;
    }

    // Transform byte-array to string
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto &byte : result) {
      ss << std::setw(2) << (int) byte;
    }
    return ss.str();
  }

  /**
   * @brief Calculate the CRC-32 checksum for a string.
   *
   * @param input Bytes to include in the checksum.
   * @return CRC-32 value for the input bytes.
   */
  uint32_t calculate_crc32(const std::string &input) {
    boost::crc_32_type result;
    result.process_bytes(input.data(), input.length());
    return result.checksum();
  }

  bool is_valid_app_id(const std::string_view id) {
    if (id.empty() || id.size() > 10 || id.front() == '0' || !std::ranges::all_of(id, [](const char c) {
          return c >= '0' && c <= '9';
        })) {
      return false;
    }
    return std::stoll(std::string {id}) <= std::numeric_limits<std::int32_t>::max();
  }

  std::tuple<std::string, std::string> calculate_app_id(const std::string &app_name, std::string app_image_path, int index) {
    // Generate id by hashing name with image data if present
    std::vector<std::string> to_hash;
    to_hash.push_back(app_name);
    auto file_path = validate_app_image_path(app_image_path);
    if (file_path != DEFAULT_APP_IMAGE_PATH) {
      auto file_hash = calculate_sha256(file_path);
      if (file_hash) {
        to_hash.push_back(file_hash.value());
      } else {
        // Fallback to just hashing image path
        to_hash.push_back(file_path);
      }
    }

    // Create combined strings for hash
    std::stringstream ss;
    for_each(to_hash.begin(), to_hash.end(), [&ss](const std::string &s) {
      ss << s;
    });
    auto input_no_index = ss.str();
    ss << index;
    auto input_with_index = ss.str();

    // CRC32 then truncate to signed 32-bit range due to client limitations
    auto id_no_index = std::to_string(abs((int32_t) calculate_crc32(input_no_index)));
    auto id_with_index = std::to_string(abs((int32_t) calculate_crc32(input_with_index)));

    return std::make_tuple(id_no_index, id_with_index);
  }

  /**
   * @brief Parse serialized text into the corresponding runtime representation.
   */
  std::optional<proc::proc_t> parse(const std::string &file_name) {
    pt::ptree tree;

    try {
      pt::read_json(file_name, tree);

      auto &apps_node = tree.get_child("apps"s);
      auto &env_vars = tree.get_child("env"s);

      auto this_env = boost::this_process::environment();

      for (auto &[name, val] : env_vars) {
        this_env[name] = parse_env_val(this_env, val.get_value<std::string>());
      }

      std::set<std::string> ids;
      std::vector<proc::ctx_t> apps;
      int i = 0;
      for (auto &[_, app_node] : apps_node) {
        proc::ctx_t ctx;

        auto prep_nodes_opt = app_node.get_child_optional("prep-cmd"s);
        auto detached_nodes_opt = app_node.get_child_optional("detached"s);
        auto exclude_global_prep = app_node.get_optional<bool>("exclude-global-prep-cmd"s);
        auto output = app_node.get_optional<std::string>("output"s);
        auto name = parse_env_val(this_env, app_node.get<std::string>("name"s));
        auto cmd = app_node.get_optional<std::string>("cmd"s);
        auto image_path = app_node.get_optional<std::string>("image-path"s);
        auto working_dir = app_node.get_optional<std::string>("working-dir"s);
        auto elevated = app_node.get_optional<bool>("elevated"s);
        auto auto_detach = app_node.get_optional<bool>("auto-detach"s);
        auto wait_all = app_node.get_optional<bool>("wait-all"s);
        auto exit_timeout = app_node.get_optional<int>("exit-timeout"s);

        std::vector<proc::cmd_t> prep_cmds;
        if (!exclude_global_prep.value_or(false)) {
          prep_cmds.reserve(config::general.prep_cmds.size());
          for (auto &prep_cmd : config::general.prep_cmds) {
            auto do_cmd = parse_env_val(this_env, prep_cmd.do_cmd);
            auto undo_cmd = parse_env_val(this_env, prep_cmd.undo_cmd);

            prep_cmds.emplace_back(
              std::move(do_cmd),
              std::move(undo_cmd),
              std::move(prep_cmd.elevated)
            );
          }
        }

        if (prep_nodes_opt) {
          auto &prep_nodes = *prep_nodes_opt;

          prep_cmds.reserve(prep_cmds.size() + prep_nodes.size());
          for (auto &[_, prep_node] : prep_nodes) {
            auto do_cmd = prep_node.get_optional<std::string>("do"s);
            auto undo_cmd = prep_node.get_optional<std::string>("undo"s);
            auto elevated = prep_node.get_optional<bool>("elevated");

            prep_cmds.emplace_back(
              parse_env_val(this_env, do_cmd.value_or("")),
              parse_env_val(this_env, undo_cmd.value_or("")),
              std::move(elevated.value_or(false))
            );
          }
        }

        std::vector<std::string> detached;
        if (detached_nodes_opt) {
          auto &detached_nodes = *detached_nodes_opt;

          detached.reserve(detached_nodes.size());
          for (auto &[_, detached_val] : detached_nodes) {
            detached.emplace_back(parse_env_val(this_env, detached_val.get_value<std::string>()));
          }
        }

        if (output) {
          ctx.output = parse_env_val(this_env, *output);
        }

        if (cmd) {
          ctx.cmd = parse_env_val(this_env, *cmd);
        }

        if (working_dir) {
          ctx.working_dir = parse_env_val(this_env, *working_dir);
#ifdef _WIN32
          // The working directory, unlike the command itself, should not be quoted
          // when it contains spaces. Unlike POSIX, Windows forbids quotes in paths,
          // so we can safely strip them all out here to avoid confusing the user.
          boost::erase_all(ctx.working_dir, "\"");
#endif
        }

        if (image_path) {
          ctx.image_path = parse_env_val(this_env, *image_path);
        }

        ctx.elevated = elevated.value_or(false);
        ctx.auto_detach = auto_detach.value_or(true);
        ctx.wait_all = wait_all.value_or(true);
        ctx.exit_timeout = std::chrono::seconds {exit_timeout.value_or(5)};

        // The administration API stores a stable ID with each app; older files derive one.
        auto possible_ids = calculate_app_id(name, ctx.image_path, i++);
        if (const auto stored_id = app_node.get_optional<std::string>("id"s);
            stored_id && is_valid_app_id(*stored_id) && ids.count(*stored_id) == 0) {
          ctx.id = *stored_id;
        } else if (ids.count(std::get<0>(possible_ids)) == 0) {
          // Avoid using index to generate id if possible
          ctx.id = std::get<0>(possible_ids);
        } else {
          // Fallback to include index on collision
          ctx.id = std::get<1>(possible_ids);
        }
        ids.insert(ctx.id);

        ctx.name = std::move(name);
        ctx.prep_cmds = std::move(prep_cmds);
        ctx.detached = std::move(detached);

        apps.emplace_back(std::move(ctx));
      }

      return proc::proc_t {
        std::move(this_env),
        std::move(apps)
      };
    } catch (std::exception &e) {
      BOOST_LOG(error) << e.what();
    }

    return std::nullopt;
  }

  /**
   * @brief Refresh cached platform state from the operating system.
   */
  void refresh(const std::string &file_name) {
    auto proc_opt = proc::parse(file_name);

    if (proc_opt) {
      proc = std::move(*proc_opt);
    }
  }
}  // namespace proc
