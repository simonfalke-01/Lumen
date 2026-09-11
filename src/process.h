/**
 * @file src/process.h
 * @brief Declarations for the startup and shutdown of the apps started by a streaming Session.
 */
#pragma once

#ifndef __kernel_entry
  /**
   * @def __kernel_entry
   * @brief Macro for kernel entry.
   */
  #define __kernel_entry
#endif

// standard includes
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

// lib includes
#include <boost/process/v1.hpp>

// local includes
#include "config.h"
#include "platform/common.h"
#include "rtsp.h"
#include "sync.h"
#include "utility.h"

/**
 * @def DEFAULT_APP_IMAGE_PATH
 * @brief Macro for DEFAULT APP IMAGE PATH.
 */
#define DEFAULT_APP_IMAGE_PATH SUNSHINE_ASSETS_DIR "/box.png"

namespace proc {
  /**
   * @brief Boost.Process pipe stream used for child-process I/O.
   */
  using file_t = util::safe_ptr_v2<FILE, int, fclose>;

  /**
   * @brief Parsed command arguments used when launching a child process.
   */
  typedef config::prep_cmd_t cmd_t;

  /**
   * @brief Populate per-session child-process variables from one launch request.
   *
   * `LUMEN_CLIENT_REFRESH_NUMERATOR` and `LUMEN_CLIENT_REFRESH_DENOMINATOR`
   * preserve exact fractional refresh. Legacy `SUNSHINE_CLIENT_FPS` remains an
   * integer for existing application scripts.
   *
   * @param env Environment updated in place.
   * @param app_id Selected configured application ID.
   * @param app_name Selected configured application name.
   * @param launch_session Complete launch selection.
   */
  void apply_launch_environment(
    boost::process::v1::environment &env,
    int app_id,
    std::string_view app_name,
    const rtsp_stream::launch_session_t &launch_session
  );

  /** @brief Exact selected LSP media/input values supplied to a fresh application launch. */
  struct lsp_launch_request_t {
    int width {};  ///< Selected encoded width.
    int height {};  ///< Selected encoded height.
    std::uint32_t refresh_numerator {};  ///< Exact selected refresh numerator.
    std::uint32_t refresh_denominator {};  ///< Exact selected refresh denominator.
    std::uint32_t pointer_rate {};  ///< Selected pointer reports per second.
    std::uint32_t controller_rate {};  ///< Selected controller reports per second.
    std::uint32_t sensor_rate {};  ///< Selected aggregate sensor reports per second.
    std::uint32_t reconciliation_rate {};  ///< Selected reconciliation reports per second.
    std::uint8_t audio_channels {};  ///< Selected Opus channel count.
    std::uint8_t audio_streams {};  ///< Selected Opus stream count.
    std::uint8_t audio_coupled_streams {};  ///< Selected coupled Opus stream count.
    std::array<std::uint8_t, 8> audio_mapping {};  ///< Selected mapping-family-one channel map.
    std::uint16_t audio_frame_samples {};  ///< Selected Opus frame samples at 48 kHz.
    std::uint32_t audio_bitrate {};  ///< Selected Opus bits per second.
    bool audio_inband_fec {};  ///< Selected Opus in-band FEC state.
    bool audio_dtx {};  ///< Selected Opus DTX state.
    std::uint8_t video_codec {};  ///< Selected LSP video codec registry value.
    std::uint8_t video_profile {};  ///< Selected LSP video profile registry value.
    std::uint8_t video_pixel_class {};  ///< Selected LSP decoded pixel class.
    std::uint8_t video_color_primaries {};  ///< Selected H.273 color primaries.
    std::uint8_t video_transfer_function {};  ///< Selected H.273 transfer characteristic.
    std::uint8_t video_matrix_coefficients {};  ///< Selected H.273 matrix coefficients.
    std::uint64_t video_bits_per_second {};  ///< Selected encoded video rate.
    std::uint32_t maximum_frame_age_microseconds {};  ///< Authenticated video frame-age budget.
    bool hdr {};  ///< Whether the selected video tuple carries HDR.
    bool video_full_range {};  ///< Whether selected decoded luma/chroma use full range.
    bool flexfec {};  ///< Whether FlexFEC repair is selected.
    bool rtx {};  ///< Whether RTX repair is selected.
    bool controller_output {};  ///< Whether authenticated controller output is enabled.

    /**
     * @brief Validate complete selected launch fields before process mutation.
     *
     * @return True only when every input, audio, and video field is usable.
     */
    [[nodiscard]] bool valid() const noexcept;
  };

  /**
   * @brief Populate exact LSP-only application environment variables.
   *
   * @param env Child-process environment updated in place.
   * @param request Valid exact LSP input/audio/video selection.
   */
  void apply_lsp_launch_environment(
    boost::process::v1::environment &env,
    const lsp_launch_request_t &request
  );

  /** @brief Authoritative current application process and LSP ownership snapshot. */
  struct lsp_process_state_t {
    int application_id {};  ///< Running configured application ID, or zero.
    std::uint64_t process_generation {};  ///< Current running process generation, or zero.
    bool running {};  ///< Whether the process manager currently reports an active application.
    bool lsp_owned {};  ///< Whether fresh LSP launch semantics own this process generation.
  };

  /**
   * pre_cmds -- guaranteed to be executed unless any of the commands fail.
   * detached -- commands detached from Sunshine
   * cmd -- Runs indefinitely until:
   *    No session is running and a different set of commands it to be executed
   *    Command exits
   * working_dir -- the process working directory. This is required for some games to run properly.
   * cmd_output --
   *    empty    -- The output of the commands are appended to the output of sunshine
   *    "null"   -- The output of the commands are discarded
   *    filename -- The output of the commands are appended to filename
   */
  struct ctx_t {
    std::vector<cmd_t> prep_cmds;  ///< Prep cmds.

    /**
     * Some applications, such as Steam, either exit quickly, or keep running indefinitely.
     *
     * Apps that launch normal child processes and terminate will be handled by the process
     * grouping logic (wait_all). However, apps that launch child processes indirectly or
     * into another process group (such as UWP apps) can only be handled by the auto-detach
     * heuristic which catches processes that exit 0 very quickly, but we won't have proper
     * process tracking for those.
     *
     * For cases where users just want to kick off a background process and never manage the
     * lifetime of that process, they can use detached commands for that.
     */
    std::vector<std::string> detached;

    std::string name;  ///< Human-readable name for this item.
    std::string cmd;  ///< Command line used to launch the application.
    std::string working_dir;  ///< Working dir.
    std::string output;  ///< Captured output from the launched process.
    std::string image_path;  ///< Image path.
    std::string id;  ///< Stable identifier for the configured application.
    bool elevated;  ///< Whether the process should be launched elevated.
    bool auto_detach;  ///< Whether the process should detach automatically.
    bool wait_all;  ///< Whether Sunshine waits for all child processes.
    std::chrono::seconds exit_timeout;  ///< Exit timeout.
  };

  /**
   * @brief Tracks launched child processes and terminates them during shutdown.
   */
  class proc_t {
  public:
    KITTY_DEFAULT_CONSTR_MOVE_THROW(proc_t)

    /**
     * @brief Construct a process manager.
     *
     * @param env Environment used when launching processes.
     * @param apps Application launch contexts.
     */
    proc_t(
      boost::process::v1::environment &&env,
      std::vector<ctx_t> &&apps
    ):
        _app_id(0),
        _env(std::move(env)),
        _apps(std::move(apps)) {
    }

    /**
     * @brief Launch the configured application process.
     *
     * @param app_id App ID.
     * @param launch_session Launch session.
     * @return Process exit code or launch error status.
     */
    int execute(int app_id, std::shared_ptr<rtsp_stream::launch_session_t> launch_session);

    /** @brief Result of one exact selected LSP application launch. */
    struct lsp_launch_result_t {
      int status {};  ///< Zero on success, 409 while another process is active, or launch error.
      std::uint64_t process_generation {};  ///< Generation owned by the accepted LSP session.
    };

    /**
     * @brief Launch one configured application only while the process slot is idle.
     *
     * @param app_id Configured numeric application ID.
     * @param request Exact selected LSP launch environment.
     * @return Launch status and generation-qualified ownership token.
     */
    [[nodiscard]] lsp_launch_result_t execute_lsp_if_idle(
      int app_id,
      const lsp_launch_request_t &request
    );

    /**
     * @brief Snapshot whether the running application is owned and resumable by LSP.
     *
     * @return Atomic running application, generation, and ownership state.
     */
    [[nodiscard]] lsp_process_state_t lsp_process_state();

    /**
     * @brief Terminate an LSP-owned application only when its generation is current.
     *
     * @param process_generation Generation returned by `execute_lsp_if_idle`.
     * @return True when ownership matched and the process was stopped or already exited.
     */
    bool terminate_lsp_generation(std::uint64_t process_generation);

    /**
     * @return `_app_id` if a process is running, otherwise returns `0`
     */
    int running();

    /**
     * @brief Allow a verified legacy client certificate to cancel the current application.
     *
     * @param client_certificate Verified certificate associated with a launched or attached session.
     * @param process_generation Generation captured by the legacy launch or resume request.
     * @return `true` when the generation is current and legacy attachment is permitted.
     */
    bool authorize_cancel_by_certificate(
      std::string_view client_certificate,
      std::uint64_t process_generation
    );

    /**
     * @brief Return the monotonically increasing current process generation.
     *
     * @return Current process generation under the serialized lifecycle boundary.
     */
    [[nodiscard]] std::uint64_t generation();

    /**
     * @brief Publish one legacy session only when its process generation is current.
     *
     * The callback runs while the process lifecycle boundary is held, preventing
     * a replacement process launch from interleaving between generation
     * validation, active-session publication, and certificate authorization.
     *
     * @param process_generation Generation captured by the pending legacy launch.
     * @param client_certificate Verified legacy client certificate.
     * @param publish Callback that starts and publishes the active legacy session.
     * @return `true` when the generation was eligible and publication succeeded.
     */
    bool publish_legacy_session(
      std::uint64_t process_generation,
      std::string_view client_certificate,
      const std::function<bool()> &publish
    );

    /**
     * @brief Terminate the current application only for an authorized legacy client.
     *
     * @param client_certificate Verified certificate requesting cancellation.
     * @return `true` when an owned running application was terminated.
     */
    bool terminate_if_owned_by_certificate(std::string_view client_certificate);

    /** @brief Result of generation-qualified owner cleanup. */
    struct owner_cleanup_result_t {
      bool generation_matched {};  ///< Whether the supplied generation is still current.
      bool process_running {};  ///< Whether a process was running before owner-qualified cleanup.
      bool process_terminated {};  ///< Whether an owned running process was terminated.
    };

    /**
     * @brief Terminate an owned process only when the pending generation is current.
     *
     * @param client_certificate Verified certificate requesting cleanup.
     * @param process_generation Generation captured by the RTSP state being removed.
     * @return Generation-match and process-termination observations.
     */
    [[nodiscard]] owner_cleanup_result_t cleanup_owned_process_generation(
      std::string_view client_certificate,
      std::uint64_t process_generation
    );

    ~proc_t();

    /**
     * @brief Return the configured applications.
     *
     * @return Immutable application list owned by the process manager.
     */
    const std::vector<ctx_t> &get_apps() const;
    /**
     * @brief Return the configured applications.
     *
     * @return Mutable application list owned by the process manager.
     */
    std::vector<ctx_t> &get_apps();
    /**
     * @brief Get app image.
     *
     * @param app_id App ID.
     * @return Validated image path for the requested application.
     */
    std::string get_app_image(int app_id);
    /**
     * @brief Get last run app name.
     *
     * @return Name of the most recently launched application.
     */
    std::string get_last_run_app_name();
    /**
     * @brief Terminate the launched application process.
     */
    void terminate();

  private:
    /**
     * @brief Shared legacy/LSP launch implementation with optional exact LSP environment.
     *
     * @param app_id Configured numeric application ID.
     * @param launch_session Common legacy-compatible launch fields.
     * @param lsp_request Exact LSP selection, or null for a legacy launch.
     * @return Zero on success or the exact launch error.
     */
    int execute_impl(
      int app_id,
      std::shared_ptr<rtsp_stream::launch_session_t> launch_session,
      const lsp_launch_request_t *lsp_request
    );

    int _app_id;

    boost::process::v1::environment _env;
    std::vector<ctx_t> _apps;
    ctx_t _app;
    std::chrono::steady_clock::time_point _app_launch_time;

    /** @brief Process state serialized with generation-qualified legacy cancel owners. */
    struct lifecycle_state_t {
      std::uint64_t generation {};  ///< Monotonic application process generation.
      bool legacy_attachable {};  ///< Whether the current running process permits legacy session attachment.
      bool lsp_owned {};  ///< Whether the current generation was launched by the exact LSP path.
      std::unordered_set<std::string> cancel_client_certificates;  ///< Verified legacy cancel owners for this generation.
    };

    using lifecycle_t = sync_util::sync_t<lifecycle_state_t, std::recursive_mutex>;  ///< Serialized process lifecycle boundary.
    std::unique_ptr<lifecycle_t> _lifecycle = std::make_unique<lifecycle_t>();  ///< Shared generation and owner state.

    // If no command associated with _app_id, yet it's still running
    bool placebo {};

    boost::process::v1::child _process;
    boost::process::v1::group _process_group;

    file_t _pipe;
    std::vector<cmd_t>::const_iterator _app_prep_it;
    std::vector<cmd_t>::const_iterator _app_prep_begin;
  };

  /**
   * @brief Calculate a stable id based on name and image data
   * @return Tuple of id calculated without index (for use if no collision) and one with.
   *
   * @param app_name App name.
   * @param app_image_path App image path.
   * @param index Zero-based index of the item being addressed.
   */
  std::tuple<std::string, std::string> calculate_app_id(const std::string &app_name, std::string app_image_path, int index);

  bool check_valid_png(const std::filesystem::path &path);
  /**
   * @brief Validate app image path.
   *
   * @param app_image_path Candidate image path from the application configuration.
   * @return Existing PNG path, or the default application image when validation fails.
   */
  std::string validate_app_image_path(std::string app_image_path);
  /**
   * @brief Refresh cached platform state from the operating system.
   *
   * @param file_name File name.
   */
  void refresh(const std::string &file_name);
  /**
   * @brief Parse serialized text into the corresponding runtime representation.
   *
   * @param file_name File name.
   * @return Parsed value or parse status.
   */
  std::optional<proc::proc_t> parse(const std::string &file_name);

  /**
   * @brief Initialize proc functions
   * @return Unique pointer to `deinit_t` to manage cleanup
   */
  std::unique_ptr<platf::deinit_t> init();

  /**
   * @brief Terminates all child processes in a process group.
   * @param proc The child process itself.
   * @param group The group of all children in the process tree.
   * @param exit_timeout The timeout to wait for the process group to gracefully exit.
   */
  void terminate_process_group(boost::process::v1::child &proc, boost::process::v1::group &group, std::chrono::seconds exit_timeout);

  extern proc_t proc;
}  // namespace proc
