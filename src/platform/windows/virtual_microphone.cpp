/**
 * @file src/platform/windows/virtual_microphone.cpp
 * @brief Windows virtual microphone user-mode transport implementation.
 */

#include "virtual_microphone.h"
#include "wasapi_virtual_microphone.h"

// standard includes
#include <algorithm>
#include <stdexcept>
#include <utility>

namespace platf::win_audio {
  namespace {
    /** @brief Production synchronous virtual microphone IOCTL channel. */
    class system_virtual_microphone_channel_t final: public virtual_microphone_channel_t {
    public:
      /** @brief Close the native handle on destruction. */
      ~system_virtual_microphone_channel_t() override {
        close();
      }

      virtual_microphone_result_t open() override {
        if (handle_ != INVALID_HANDLE_VALUE) {
          return {};
        }
        handle_ = CreateFileW(
          LUMEN_VMIC_CONTROL_DEVICE_PATH_W,
          GENERIC_READ | GENERIC_WRITE,
          FILE_SHARE_READ | FILE_SHARE_WRITE,
          nullptr,
          OPEN_EXISTING,
          FILE_ATTRIBUTE_NORMAL,
          nullptr
        );
        return handle_ == INVALID_HANDLE_VALUE ?
                 virtual_microphone_result_t {false, GetLastError()} :
                 virtual_microphone_result_t {};
      }

      virtual_microphone_result_t query_abi(LUMEN_VMIC_QUERY_ABI_RESPONSE &response) override {
        return ioctl(IOCTL_LUMEN_VMIC_QUERY_ABI, nullptr, 0, &response, sizeof(response));
      }

      virtual_microphone_result_t open_stream(const LUMEN_VMIC_OPEN_STREAM_REQUEST &request) override {
        return ioctl(IOCTL_LUMEN_VMIC_OPEN_STREAM, &request, sizeof(request), nullptr, 0);
      }

      virtual_microphone_result_t write_pcm(const LUMEN_VMIC_WRITE_PCM_REQUEST &request) override {
        if (request.frame_count == 0 || request.frame_count > LUMEN_VMIC_MAX_WRITE_FRAMES) {
          return {false, ERROR_INVALID_PARAMETER};
        }
        return ioctl(IOCTL_LUMEN_VMIC_WRITE_PCM, &request, sizeof(request), nullptr, 0);
      }

      virtual_microphone_result_t reset(const LUMEN_VMIC_RESET_REQUEST &request) override {
        return ioctl(IOCTL_LUMEN_VMIC_RESET, &request, sizeof(request), nullptr, 0);
      }

      virtual_microphone_result_t query_stats(LUMEN_VMIC_QUERY_STATS_RESPONSE &response) override {
        return ioctl(IOCTL_LUMEN_VMIC_QUERY_STATS, nullptr, 0, &response, sizeof(response));
      }

      void close() noexcept override {
        if (handle_ != INVALID_HANDLE_VALUE) {
          CloseHandle(std::exchange(handle_, INVALID_HANDLE_VALUE));
        }
      }

    private:
      /**
       * @brief Perform one exact synchronous DeviceIoControl operation.
       * @param code Control code.
       * @param input Optional input buffer.
       * @param input_size Input buffer size.
       * @param output Optional output buffer.
       * @param output_size Output buffer size.
       * @return Channel result.
       */
      virtual_microphone_result_t ioctl(
        DWORD code,
        const void *input,
        DWORD input_size,
        void *output,
        DWORD output_size
      ) {
        if (handle_ == INVALID_HANDLE_VALUE) {
          return {false, ERROR_INVALID_HANDLE};
        }

        DWORD transferred = 0;
        if (!DeviceIoControl(
              handle_,
              code,
              const_cast<void *>(input),
              input_size,
              output,
              output_size,
              &transferred,
              nullptr
            )) {
          return {false, GetLastError()};
        }
        if (transferred != output_size) {
          return {false, ERROR_INVALID_DATA};
        }
        return {};
      }

      HANDLE handle_ {INVALID_HANDLE_VALUE};  ///< Secured control-device handle.
    };

    /** @brief Driver-first production sink with an existing signed virtual-cable fallback. */
    class composite_virtual_microphone_t final: public virtual_microphone_sink_t {
    public:
      composite_virtual_microphone_t(
        std::unique_ptr<virtual_microphone_sink_t> driver,
        std::unique_ptr<virtual_microphone_sink_t> wasapi
      ):
          driver_ {std::move(driver)},
          wasapi_ {std::move(wasapi)} {
      }

      bool probe() override {
        return (driver_ && driver_->probe()) || (wasapi_ && wasapi_->probe());
      }

      bool begin(
        const std::uint64_t generation,
        const std::uint32_t sample_rate,
        const std::uint8_t channels
      ) override {
        if (active_ != nullptr) {
          active_->end(active_generation_);
          active_ = nullptr;
          active_generation_ = 0;
        }
        if (driver_ && driver_->begin(generation, sample_rate, channels)) {
          active_ = driver_.get();
        } else if (wasapi_ && wasapi_->begin(generation, sample_rate, channels)) {
          active_ = wasapi_.get();
        } else {
          return false;
        }
        active_generation_ = generation;
        return true;
      }

      bool write(
        const std::uint64_t generation,
        const std::span<const std::int16_t> samples
      ) override {
        return active_ != nullptr && generation == active_generation_ &&
               active_->write(generation, samples);
      }

      void end(const std::uint64_t generation) override {
        if (active_ == nullptr || generation != active_generation_) {
          return;
        }
        active_->end(generation);
        active_ = nullptr;
        active_generation_ = 0;
      }

    private:
      std::unique_ptr<virtual_microphone_sink_t> driver_;  ///< Preferred secured Lumen driver sink.
      std::unique_ptr<virtual_microphone_sink_t> wasapi_;  ///< Existing signed virtual-cable sink.
      virtual_microphone_sink_t *active_ {};  ///< Backend owning the active generation.
      std::uint64_t active_generation_ {};  ///< Generation routed to `active_`.
    };
  }  // namespace

  virtual_microphone_t::virtual_microphone_t(std::shared_ptr<virtual_microphone_channel_t> channel):
      channel_(std::move(channel)) {
    if (!channel_) {
      throw std::invalid_argument("Virtual microphone requires a driver channel");
    }
  }

  virtual_microphone_t::~virtual_microphone_t() {
    std::lock_guard lock(mutex_);
    static_cast<void>(teardown_locked());
  }

  bool virtual_microphone_t::compatible(const LUMEN_VMIC_QUERY_ABI_RESPONSE &response) noexcept {
    return response.abi_version == LUMEN_VMIC_ABI_VERSION &&
           response.sample_rate_hz == LUMEN_VMIC_SAMPLE_RATE_HZ &&
           response.channel_count == LUMEN_VMIC_CHANNEL_COUNT &&
           response.bits_per_sample == LUMEN_VMIC_BITS_PER_SAMPLE &&
           response.max_write_frames == LUMEN_VMIC_MAX_WRITE_FRAMES;
  }

  bool virtual_microphone_t::probe() {
    std::lock_guard lock(mutex_);
    if (state_ == virtual_microphone_state_e::active) {
      return true;
    }
    if (state_ == virtual_microphone_state_e::fail_closed) {
      return false;
    }

    auto result = channel_->open();
    if (!result) {
      set_failure_locked("interface discovery/open", result.status);
      return false;
    }

    LUMEN_VMIC_QUERY_ABI_RESPONSE abi {};
    result = channel_->query_abi(abi);
    if (!result || !compatible(abi)) {
      set_failure_locked("driver ABI", result ? ERROR_REVISION_MISMATCH : result.status);
      channel_->close();
      return false;
    }

    channel_->close();
    failure_stage_.clear();
    failure_status_ = ERROR_SUCCESS;
    return true;
  }

  bool virtual_microphone_t::begin(
    std::uint64_t generation,
    std::uint32_t sample_rate,
    std::uint8_t channels
  ) {
    std::lock_guard lock(mutex_);
    if (sample_rate != LUMEN_VMIC_SAMPLE_RATE_HZ || channels != LUMEN_VMIC_CHANNEL_COUNT) {
      set_failure_locked("PCM format", ERROR_INVALID_PARAMETER);
      return false;
    }
    if (generation == 0) {
      set_failure_locked("stream generation", ERROR_INVALID_PARAMETER);
      return false;
    }

    if (!teardown_locked()) {
      return false;
    }

    auto result = channel_->open();
    if (!result) {
      set_failure_locked("interface discovery/open", result.status);
      state_ = virtual_microphone_state_e::idle;
      return false;
    }

    LUMEN_VMIC_QUERY_ABI_RESPONSE abi {};
    result = channel_->query_abi(abi);
    if (!result || !compatible(abi)) {
      set_failure_locked("driver ABI", result ? ERROR_REVISION_MISMATCH : result.status);
      channel_->close();
      state_ = virtual_microphone_state_e::idle;
      return false;
    }

    LUMEN_VMIC_OPEN_STREAM_REQUEST request {};
    request.requested_generation = generation;
    request.sample_rate_hz = sample_rate;
    request.channel_count = channels;
    request.bits_per_sample = LUMEN_VMIC_BITS_PER_SAMPLE;
    result = channel_->open_stream(request);
    if (!result) {
      set_failure_locked("open stream", result.status);
      channel_->close();
      state_ = virtual_microphone_state_e::idle;
      return false;
    }

    generation_ = generation;
    stream_open_ = true;
    state_ = virtual_microphone_state_e::active;
    failure_stage_.clear();
    failure_status_ = ERROR_SUCCESS;
    return true;
  }

  bool virtual_microphone_t::write(
    std::uint64_t generation,
    std::span<const std::int16_t> samples
  ) {
    std::lock_guard lock(mutex_);
    if (state_ != virtual_microphone_state_e::active || generation != generation_) {
      set_failure_locked("PCM generation", ERROR_INVALID_STATE);
      return false;
    }

    std::size_t offset = 0;
    while (offset < samples.size()) {
      const auto frame_count = std::min<std::size_t>(LUMEN_VMIC_MAX_WRITE_FRAMES, samples.size() - offset);
      LUMEN_VMIC_WRITE_PCM_REQUEST request {};
      request.generation = generation;
      request.frame_count = static_cast<std::uint32_t>(frame_count);
      std::copy_n(samples.data() + offset, frame_count, request.samples);

      const auto result = channel_->write_pcm(request);
      if (!result) {
        set_failure_locked("write PCM", result.status);
        state_ = virtual_microphone_state_e::fail_closed;
        return false;
      }
      offset += frame_count;
    }

    return true;
  }

  void virtual_microphone_t::end(std::uint64_t generation) {
    std::lock_guard lock(mutex_);
    if (!stream_open_ || generation != generation_) {
      return;
    }
    static_cast<void>(teardown_locked());
  }

  bool virtual_microphone_t::query_stats(LUMEN_VMIC_QUERY_STATS_RESPONSE &response) {
    std::lock_guard lock(mutex_);
    if (!stream_open_) {
      set_failure_locked("query statistics", ERROR_INVALID_STATE);
      return false;
    }

    const auto result = channel_->query_stats(response);
    if (!result) {
      set_failure_locked("query statistics", result.status);
      return false;
    }
    return true;
  }

  virtual_microphone_state_e virtual_microphone_t::state() const noexcept {
    std::lock_guard lock(mutex_);
    return state_;
  }

  std::uint64_t virtual_microphone_t::generation() const noexcept {
    std::lock_guard lock(mutex_);
    return generation_;
  }

  std::string virtual_microphone_t::failure_stage() const {
    std::lock_guard lock(mutex_);
    return failure_stage_;
  }

  DWORD virtual_microphone_t::failure_status() const noexcept {
    std::lock_guard lock(mutex_);
    return failure_status_;
  }

  bool virtual_microphone_t::teardown_locked() noexcept {
    if (!stream_open_) {
      return true;
    }

    const LUMEN_VMIC_RESET_REQUEST request {generation_};
    const auto result = channel_->reset(request);
    const auto reset_succeeded = static_cast<bool>(result);
    if (!reset_succeeded) {
      set_failure_locked("reset stream", result.status);
    }

    channel_->close();
    stream_open_ = false;
    generation_ = 0;
    state_ = reset_succeeded ? virtual_microphone_state_e::idle : virtual_microphone_state_e::fail_closed;
    return reset_succeeded;
  }

  void virtual_microphone_t::set_failure_locked(const char *stage, DWORD status) {
    failure_stage_ = stage;
    failure_status_ = status;
  }

  std::unique_ptr<virtual_microphone_sink_t> make_virtual_microphone() {
    return std::make_unique<composite_virtual_microphone_t>(
      std::make_unique<virtual_microphone_t>(std::make_shared<system_virtual_microphone_channel_t>()),
      make_wasapi_virtual_microphone()
    );
  }
}  // namespace platf::win_audio
