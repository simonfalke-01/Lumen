/**
 * @file src/platform/windows/virtual_microphone.h
 * @brief Windows user-mode transport for the Lumen virtual microphone driver.
 */
#pragma once

// local includes
#include "src/client_microphone.h"
#include "virtual_microphone_protocol.h"

// platform includes
#include <Windows.h>

// standard includes
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <string>

namespace platf::win_audio {
  /**
   * @brief Result returned by one synchronous virtual microphone operation.
   */
  struct virtual_microphone_result_t {
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
   * @brief Injectable synchronous virtual microphone control channel.
   */
  class virtual_microphone_channel_t {
  public:
    /**
     * @brief Destroy the channel implementation.
     */
    virtual ~virtual_microphone_channel_t() = default;

    /**
     * @brief Discover and open the secured driver interface.
     * @return Channel result.
     */
    virtual virtual_microphone_result_t open() = 0;

    /**
     * @brief Query the exact fixed-format driver ABI.
     * @param response Driver ABI response returned on success.
     * @return Channel result.
     */
    virtual virtual_microphone_result_t query_abi(LUMEN_VMIC_QUERY_ABI_RESPONSE &response) = 0;

    /**
     * @brief Claim exclusive PCM submission for one generation.
     * @param request Fixed format and requested generation.
     * @return Channel result.
     */
    virtual virtual_microphone_result_t open_stream(const LUMEN_VMIC_OPEN_STREAM_REQUEST &request) = 0;

    /**
     * @brief Submit one bounded, generation-scoped PCM chunk.
     * @param request Maximum-size request storage with a validated frame count.
     * @return Channel result.
     */
    virtual virtual_microphone_result_t write_pcm(const LUMEN_VMIC_WRITE_PCM_REQUEST &request) = 0;

    /**
     * @brief Reset the active generation and release exclusive ownership.
     * @param request Generation-scoped reset request.
     * @return Channel result.
     */
    virtual virtual_microphone_result_t reset(const LUMEN_VMIC_RESET_REQUEST &request) = 0;

    /**
     * @brief Query driver FIFO and stream counters.
     * @param response Driver statistics returned on success.
     * @return Channel result.
     */
    virtual virtual_microphone_result_t query_stats(LUMEN_VMIC_QUERY_STATS_RESPONSE &response) = 0;

    /**
     * @brief Close the secured driver interface.
     */
    virtual void close() noexcept = 0;
  };

  /**
   * @brief Runtime state of the generation-scoped virtual microphone sink.
   */
  enum class virtual_microphone_state_e {
    idle,  ///< No driver stream is currently owned.
    active,  ///< The exact driver ABI is open for PCM writes.
    fail_closed  ///< A claimed stream failed and accepts no further PCM.
  };

  /**
   * @brief Probe-capable Windows client microphone injection backend.
   */
  class virtual_microphone_sink_t: public client_microphone::sink_t {
  public:
    /**
     * @brief Destroy the platform backend.
     */
    ~virtual_microphone_sink_t() override = default;

    /**
     * @brief Prove that the backend can target its secured driver or exact virtual endpoint.
     * @return `true` only when a usable backend is present.
     */
    virtual bool probe() = 0;
  };

  /**
   * @brief Fixed 48 kHz mono signed-16 PCM sink backed by the Windows driver.
   */
  class virtual_microphone_t final: public virtual_microphone_sink_t {
  public:
    /**
     * @brief Construct a virtual microphone around an injectable channel.
     * @param channel Driver control channel.
     * @throws std::invalid_argument If `channel` is null.
     */
    explicit virtual_microphone_t(std::shared_ptr<virtual_microphone_channel_t> channel);

    /**
     * @brief Reset any claimed generation before closing the driver handle.
     */
    ~virtual_microphone_t() override;

    virtual_microphone_t(const virtual_microphone_t &) = delete;
    virtual_microphone_t &operator=(const virtual_microphone_t &) = delete;
    virtual_microphone_t(virtual_microphone_t &&) = delete;
    virtual_microphone_t &operator=(virtual_microphone_t &&) = delete;

    /**
     * @brief Probe interface discovery and exact ABI compatibility without claiming a stream.
     * @return `true` only when the compatible interface can be opened and queried.
     */
    bool probe() override;

    bool begin(std::uint64_t generation, std::uint32_t sample_rate, std::uint8_t channels) override;
    bool write(std::uint64_t generation, std::span<const std::int16_t> samples) override;
    void end(std::uint64_t generation) override;

    /**
     * @brief Query the latest driver statistics while a stream is active.
     * @param response Statistics response filled on success.
     * @return `true` when a complete response was returned.
     */
    bool query_stats(LUMEN_VMIC_QUERY_STATS_RESPONSE &response);

    /**
     * @brief Return the current transport state.
     * @return Idle, active, or fail-closed state.
     */
    [[nodiscard]] virtual_microphone_state_e state() const noexcept;

    /**
     * @brief Return the active generation, or zero while idle.
     * @return Current driver stream generation.
     */
    [[nodiscard]] std::uint64_t generation() const noexcept;

    /**
     * @brief Return the stage associated with the most recent failure.
     * @return Stable diagnostic stage name.
     */
    [[nodiscard]] std::string failure_stage() const;

    /**
     * @brief Return the Windows status associated with the most recent failure.
     * @return Native status code.
     */
    [[nodiscard]] DWORD failure_status() const noexcept;

  private:
    /**
     * @brief Validate every fixed ABI identity field.
     * @param response Driver ABI response.
     * @return `true` when the driver exactly matches this client.
     */
    static bool compatible(const LUMEN_VMIC_QUERY_ABI_RESPONSE &response) noexcept;

    /**
     * @brief Reset an owned stream and close its handle.
     * @return `true` when reset succeeded or no stream was owned.
     */
    bool teardown_locked() noexcept;

    /**
     * @brief Record a diagnostic failure while the mutex is held.
     * @param stage Failure stage.
     * @param status Native status.
     */
    void set_failure_locked(const char *stage, DWORD status);

    std::shared_ptr<virtual_microphone_channel_t> channel_;  ///< Secured driver channel.
    mutable std::mutex mutex_;  ///< Serializes lifecycle, writes, and diagnostics.
    virtual_microphone_state_e state_ {virtual_microphone_state_e::idle};  ///< Current state.
    std::uint64_t generation_ {};  ///< Claimed stream generation, or zero while idle.
    bool stream_open_ {};  ///< Whether reset is required before closing the handle.
    std::string failure_stage_;  ///< Most recent diagnostic stage.
    DWORD failure_status_ {ERROR_SUCCESS};  ///< Most recent native failure status.
  };

  /**
   * @brief Create the production Windows virtual microphone sink.
   * @return Unprobed sink using the secured system driver channel.
   */
  std::unique_ptr<virtual_microphone_sink_t> make_virtual_microphone();
}  // namespace platf::win_audio
