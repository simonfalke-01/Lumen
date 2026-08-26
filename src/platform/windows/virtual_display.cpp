/**
 * @file src/platform/windows/virtual_display.cpp
 * @brief Transactional Lumen virtual-display coordinator implementation.
 */
#include "virtual_display.h"

#include "../../protocol_v3/start_mode_contract.h"

#ifndef _WIN32
  #include "virtual_display_driver/LumenVirtualDisplayProtocol.h"
#endif

#include <algorithm>
#include <cstring>
#include <limits>
#include <numeric>
#include <stdexcept>
#include <string_view>
#include <utility>

#ifdef _WIN32
  #include <Windows.h>
  #include <initguid.h>
  #include <cfgmgr32.h>
  #include <devpkey.h>
  #include <SetupAPI.h>

  #include "virtual_display_driver/LumenVirtualDisplayProtocol.h"
  #include "virtual_display_driver/LumenVirtualDisplayGuids.h"
  #include "src/video.h"

  #include <memory>
#endif

namespace platf::virtual_display {
  namespace {
    /** @brief Compare positive rationals without overflow. */
    int compare(const rational_t &left, const rational_t &right) noexcept {
      const auto left_product = static_cast<std::uint64_t>(left.numerator) * right.denominator;
      const auto right_product = static_cast<std::uint64_t>(right.numerator) * left.denominator;
      return left_product < right_product ? -1 : left_product > right_product ? 1 :
                                                                                0;
    }

    /** @brief Return true if multiplying two unsigned values would overflow. */
    bool multiply_overflows(std::uint64_t left, std::uint64_t right) noexcept {
      return right != 0 && left > std::numeric_limits<std::uint64_t>::max() / right;
    }

    /** @brief Return true if a driver state describes an active generation. */
    bool active_driver_state(const driver_state_t &state) noexcept {
      return state.generation != 0 || state.owner_process_id != 0 || state.monitor_started;
    }

#ifdef _WIN32
    /** @brief Pack a DisplayConfig adapter LUID without changing its signed high bits. */
    std::uint64_t pack_display_luid(const LUID &luid) noexcept {
      return static_cast<std::uint64_t>(static_cast<std::uint32_t>(luid.HighPart)) << 32U |
             static_cast<std::uint64_t>(luid.LowPart);
    }

    /** @brief Restore a DisplayConfig adapter LUID from its snapshot representation. */
    LUID unpack_display_luid(const std::uint64_t packed) noexcept {
      return {
        static_cast<DWORD>(packed),
        static_cast<LONG>(static_cast<std::uint32_t>(packed >> 32U)),
      };
    }

    /** @brief Query one exact target's documented Advanced Color state. */
    std::optional<advanced_color_state_e> query_advanced_color_state(
      const LUID adapter_id,
      const std::uint32_t target_id
    ) noexcept {
      DISPLAYCONFIG_GET_ADVANCED_COLOR_INFO info {};
      info.header.type = DISPLAYCONFIG_DEVICE_INFO_GET_ADVANCED_COLOR_INFO;
      info.header.size = sizeof(info);
      info.header.adapterId = adapter_id;
      info.header.id = target_id;
      const auto status = DisplayConfigGetDeviceInfo(&info.header);
      if (status == ERROR_NOT_SUPPORTED) {
        return advanced_color_state_e::api_unavailable;
      }
      if (status != ERROR_SUCCESS) {
        return std::nullopt;
      }
      if (!info.advancedColorSupported || info.advancedColorForceDisabled) {
        return advanced_color_state_e::unsupported;
      }
      return info.advancedColorEnabled ?
               advanced_color_state_e::enabled :
               advanced_color_state_e::disabled;
    }

    /** @brief Apply one documented target-scoped Advanced Color state. */
    bool set_advanced_color_state(
      const LUID adapter_id,
      const std::uint32_t target_id,
      const bool enabled
    ) noexcept {
      DISPLAYCONFIG_SET_ADVANCED_COLOR_STATE state {};
      state.header.type = DISPLAYCONFIG_DEVICE_INFO_SET_ADVANCED_COLOR_STATE;
      state.header.size = sizeof(state);
      state.header.adapterId = adapter_id;
      state.header.id = target_id;
      state.enableAdvancedColor = enabled ? 1U : 0U;
      return DisplayConfigSetDeviceInfo(&state.header) == ERROR_SUCCESS;
    }

    /** @brief Match one DisplayConfig monitor interface to its stable PnP container identity. */
    bool monitor_interface_has_container_id(const std::wstring &path, const GUID &expected) noexcept {
      constexpr std::wstring_view device_path_prefix {L"\\\\?\\"};
      if (!path.starts_with(device_path_prefix)) {
        return false;
      }
      const auto class_suffix = path.rfind(L"#{");
      if (class_suffix == std::wstring::npos || class_suffix <= device_path_prefix.size()) {
        return false;
      }
      std::wstring instance_id = path.substr(device_path_prefix.size(), class_suffix - device_path_prefix.size());
      std::ranges::replace(instance_id, L'#', L'\\');
      DEVINST device = 0;
      if (CM_Locate_DevNodeW(&device, instance_id.data(), CM_LOCATE_DEVNODE_PHANTOM) != CR_SUCCESS) {
        return false;
      }
      GUID observed {};
      DEVPROPTYPE property_type = 0;
      ULONG size = sizeof(observed);
      return CM_Get_DevNode_PropertyW(
               device,
               &DEVPKEY_Device_ContainerId,
               &property_type,
               reinterpret_cast<PBYTE>(&observed),
               &size,
               0
             ) == CR_SUCCESS &&
             property_type == DEVPROP_TYPE_GUID && size == sizeof(observed) && IsEqualGUID(observed, expected);
    }
#endif
  }  // namespace

  std::optional<std::size_t> unique_matching_index(
    const std::span<const std::uint8_t> matches
  ) noexcept {
    std::optional<std::size_t> selected;
    for (std::size_t index = 0; index < matches.size(); ++index) {
      if (matches[index] == 0) {
        continue;
      }
      if (selected) {
        return std::nullopt;
      }
      selected = index;
    }
    return selected;
  }

  std::vector<advanced_color_path_t> active_advanced_color_targets(
    const std::span<const advanced_color_path_t> paths
  ) {
    std::vector<advanced_color_path_t> selected;
    selected.reserve(paths.size());
    for (const auto &path : paths) {
      if (!path.active || !path.target_available) {
        continue;
      }
      const auto duplicate = std::ranges::find_if(selected, [&](const auto &existing) {
        return existing.adapter_luid == path.adapter_luid && existing.target_id == path.target_id;
      });
      if (duplicate == selected.end()) {
        selected.push_back(path);
      }
    }
    return selected;
  }

  bool valid_render_adapter_identity(const render_adapter_identity_t &identity) noexcept {
    return identity.adapter_luid != 0 && identity.vendor_id != 0 && identity.device_id != 0 &&
           identity.driver_version != 0;
  }

  std::optional<rational_t> rational_t::normalized() const noexcept {
    if (numerator == 0 || denominator == 0) {
      return std::nullopt;
    }
    const auto divisor = std::gcd(numerator, denominator);
    return rational_t {numerator / divisor, denominator / divisor};
  }

  validation_error_e validate_mode(
    const mode_t &mode,
    const mode_limits_t &limits,
    fidelity_e required_fidelity
  ) noexcept {
    const auto normalized_refresh = mode.refresh.normalized();
    const auto normalized_minimum = limits.minimum_refresh.normalized();
    const auto normalized_maximum = limits.maximum_refresh.normalized();
    if (!normalized_refresh || !normalized_minimum || !normalized_maximum || *normalized_refresh != mode.refresh) {
      return validation_error_e::zero_or_unreduced_refresh;
    }
    if (limits.require_even_dimensions && ((mode.width & 1U) != 0 || (mode.height & 1U) != 0)) {
      return validation_error_e::odd_dimensions;
    }
    if (mode.width < limits.minimum_width || mode.width > limits.maximum_width ||
        mode.height < limits.minimum_height || mode.height > limits.maximum_height) {
      return validation_error_e::dimensions_out_of_range;
    }
    if (compare(mode.refresh, *normalized_minimum) < 0 || compare(mode.refresh, *normalized_maximum) > 0) {
      return validation_error_e::refresh_out_of_range;
    }
    if (multiply_overflows(mode.width, mode.height)) {
      return validation_error_e::pixel_count_overflow;
    }
    const auto pixels = static_cast<std::uint64_t>(mode.width) * mode.height;
    if (pixels > limits.maximum_pixels) {
      return validation_error_e::pixel_count_overflow;
    }
    if (multiply_overflows(pixels, mode.refresh.numerator) ||
        multiply_overflows(limits.maximum_pixel_rate, mode.refresh.denominator)) {
      return validation_error_e::pixel_rate_overflow;
    }
    if (pixels * mode.refresh.numerator > limits.maximum_pixel_rate * mode.refresh.denominator) {
      return validation_error_e::pixel_rate_overflow;
    }
    if (mode.dynamic_range != dynamic_range_e::sdr && mode.dynamic_range != dynamic_range_e::hdr10) {
      return validation_error_e::unsupported_dynamic_range;
    }
    if (mode.dynamic_range == dynamic_range_e::hdr10 && !limits.supports_hdr10) {
      return validation_error_e::unsupported_dynamic_range;
    }
    if ((mode.bits_per_channel == 10 && !limits.supports_10bit) ||
        (mode.bits_per_channel != 8 && mode.bits_per_channel != 10) ||
        (mode.dynamic_range == dynamic_range_e::hdr10 && mode.bits_per_channel != 10) ||
        (mode.dynamic_range == dynamic_range_e::sdr && mode.bits_per_channel != 8)) {
      return validation_error_e::unsupported_bit_depth;
    }
    if (required_fidelity != fidelity_e::lossless && required_fidelity != fidelity_e::visually_lossless) {
      return validation_error_e::unsupported_fidelity;
    }
    if ((required_fidelity == fidelity_e::lossless && !limits.supports_lossless) ||
        (required_fidelity == fidelity_e::visually_lossless && !limits.supports_visually_lossless)) {
      return validation_error_e::unsupported_fidelity;
    }
    return validation_error_e::none;
  }

  std::optional<mode_limits_t> intersect_limits(
    const mode_limits_t &left,
    const mode_limits_t &right
  ) noexcept {
    const auto left_minimum = left.minimum_refresh.normalized();
    const auto left_maximum = left.maximum_refresh.normalized();
    const auto right_minimum = right.minimum_refresh.normalized();
    const auto right_maximum = right.maximum_refresh.normalized();
    if (!left_minimum || !left_maximum || !right_minimum || !right_maximum) {
      return std::nullopt;
    }

    mode_limits_t result;
    result.minimum_width = std::max(left.minimum_width, right.minimum_width);
    result.maximum_width = std::min(left.maximum_width, right.maximum_width);
    result.minimum_height = std::max(left.minimum_height, right.minimum_height);
    result.maximum_height = std::min(left.maximum_height, right.maximum_height);
    result.minimum_refresh = compare(*left_minimum, *right_minimum) >= 0 ? *left_minimum : *right_minimum;
    result.maximum_refresh = compare(*left_maximum, *right_maximum) <= 0 ? *left_maximum : *right_maximum;
    result.maximum_pixels = std::min(left.maximum_pixels, right.maximum_pixels);
    result.maximum_pixel_rate = std::min(left.maximum_pixel_rate, right.maximum_pixel_rate);
    result.require_even_dimensions = left.require_even_dimensions || right.require_even_dimensions;
    result.supports_hdr10 = left.supports_hdr10 && right.supports_hdr10;
    result.supports_10bit = left.supports_10bit && right.supports_10bit;
    result.supports_lossless = left.supports_lossless && right.supports_lossless;
    result.supports_visually_lossless = left.supports_visually_lossless && right.supports_visually_lossless;

    if (result.minimum_width > result.maximum_width || result.minimum_height > result.maximum_height ||
        compare(result.minimum_refresh, result.maximum_refresh) > 0 || result.maximum_pixels == 0 ||
        result.maximum_pixel_rate == 0) {
      return std::nullopt;
    }
    return result;
  }

  stream_request_t legacy_game_stream_request(
    std::uint64_t session_id,
    std::uint32_t width,
    std::uint32_t height,
    std::uint32_t frames_per_second,
    delivery_policy_e delivery_policy
  ) noexcept {
    return {
      session_id,
      {width, height, {frames_per_second, 1}, dynamic_range_e::sdr, 8},
      delivery_policy,
      fidelity_e::lossless,
    };
  }

  stream_request_t modern_stream_request(
    std::uint64_t session_id,
    mode_t mode,
    delivery_policy_e delivery_policy,
    fidelity_e minimum_fidelity
  ) noexcept {
    return {session_id, mode, delivery_policy, minimum_fidelity};
  }

  coordinator_t::coordinator_t(
    std::shared_ptr<control_channel_t> channel,
    std::shared_ptr<display_config_t> display
  ):
      channel_(std::move(channel)),
      display_(std::move(display)) {
    if (!channel_ || !display_) {
      throw std::invalid_argument("Virtual display coordinator requires driver and DisplayConfig backends");
    }
  }

  coordinator_t::~coordinator_t() {
    std::lock_guard lock(mutex_);
    if (active_) {
      static_cast<void>(rollback_locked(active_->selection.generation, &active_->snapshot));
      active_.reset();
    }
    if (pending_cleanup_) {
      static_cast<void>(rollback_locked(pending_cleanup_->generation, &pending_cleanup_->snapshot));
      pending_cleanup_.reset();
    }
    channel_->close();
  }

  start_result_t coordinator_t::start(
    const stream_request_t &request,
    const mode_limits_t &system_limits
  ) {
    std::lock_guard lock(mutex_);
    if (request.session_id == 0) {
      return {start_error_e::invalid_session, validation_error_e::none, std::nullopt};
    }
    if (request.delivery_policy != delivery_policy_e::latency && request.delivery_policy != delivery_policy_e::quality) {
      return {start_error_e::invalid_mode, validation_error_e::unsupported_delivery_policy, std::nullopt};
    }
    if (active_) {
      if (active_->selection.session_id == request.session_id &&
          active_->selection.requested_mode == request.mode &&
          active_->selection.delivery_policy == request.delivery_policy &&
          active_->selection.fidelity == request.minimum_fidelity &&
          active_->selection.render_adapter == request.render_adapter) {
        return {start_error_e::none, validation_error_e::none, active_->selection};
      }
      return {start_error_e::busy, validation_error_e::none, std::nullopt};
    }
    if (pending_cleanup_) {
      return {start_error_e::busy, validation_error_e::none, std::nullopt};
    }

    if (!channel_->open()) {
      return {start_error_e::driver_unavailable, validation_error_e::none, std::nullopt};
    }
    mode_limits_t driver_limits;
    if (!channel_->query_limits(driver_limits)) {
      channel_->close();
      return {start_error_e::driver_unavailable, validation_error_e::none, std::nullopt};
    }
    const auto effective_limits = intersect_limits(driver_limits, system_limits);
    if (!effective_limits) {
      channel_->close();
      return {start_error_e::invalid_mode, validation_error_e::dimensions_out_of_range, std::nullopt};
    }
    const auto validation = validate_mode(request.mode, *effective_limits, request.minimum_fidelity);
    if (validation != validation_error_e::none) {
      channel_->close();
      return {start_error_e::invalid_mode, validation, std::nullopt};
    }

    driver_state_t driver_state;
    if (!channel_->query_state(driver_state)) {
      channel_->close();
      return {start_error_e::driver_unavailable, validation_error_e::none, std::nullopt};
    }
    if (active_driver_state(driver_state)) {
      if (!channel_->recover_stale(driver_state.generation)) {
        channel_->close();
        return {start_error_e::stale_recovery_failed, validation_error_e::none, std::nullopt};
      }
    }

    display_snapshot_t snapshot;
    if (!display_->snapshot(snapshot)) {
      channel_->close();
      return {start_error_e::display_snapshot_failed, validation_error_e::none, std::nullopt};
    }

    const auto driver_floor = std::max(driver_state.generation, driver_state.last_generation);
    if (driver_floor == std::numeric_limits<std::uint64_t>::max()) {
      channel_->close();
      return {start_error_e::driver_prepare_failed, validation_error_e::none, std::nullopt};
    }
    const auto generation_floor = std::max(next_generation_, driver_floor + 1);
    if (generation_floor == 0) {
      channel_->close();
      return {start_error_e::driver_prepare_failed, validation_error_e::none, std::nullopt};
    }
    const auto generation = generation_floor;
    next_generation_ = generation == std::numeric_limits<std::uint64_t>::max() ? generation : generation + 1;

    prepared_mode_t prepared;
    const auto preferred_render_adapter_luid = request.render_adapter ? request.render_adapter->adapter_luid : 0;
    if (!channel_->prepare_mode(
          generation,
          request.mode,
          request.delivery_policy,
          request.minimum_fidelity,
          preferred_render_adapter_luid,
          prepared
        )) {
      return fail_transaction_locked(start_error_e::driver_prepare_failed, request.session_id, generation, std::move(snapshot));
    }
    if (prepared.mode != request.mode || prepared.fidelity != request.minimum_fidelity ||
        prepared.preferred_render_adapter_luid != preferred_render_adapter_luid) {
      return fail_transaction_locked(start_error_e::implicit_adjustment_rejected, request.session_id, generation, std::move(snapshot));
    }
    if (!channel_->start_monitor(generation)) {
      return fail_transaction_locked(start_error_e::driver_start_failed, request.session_id, generation, std::move(snapshot));
    }

    display_commit_t committed;
    if (!display_->commit(prepared.connector_id, request.mode, committed)) {
      return fail_transaction_locked(start_error_e::display_commit_failed, request.session_id, generation, std::move(snapshot));
    }
    if (committed.mode != request.mode) {
      return fail_transaction_locked(start_error_e::implicit_adjustment_rejected, request.session_id, generation, std::move(snapshot));
    }
    if (!display_->await_stable(committed.capture_name, committed.mode, std::chrono::milliseconds {2500})) {
      return fail_transaction_locked(start_error_e::display_unstable, request.session_id, generation, std::move(snapshot));
    }

    stream_selection_t selection {
      request.session_id,
      generation,
      request.mode,
      committed.mode,
      std::move(committed.capture_name),
      request.delivery_policy,
      prepared.fidelity,
      committed.mode != request.mode,
      request.render_adapter,
      prepared.render_adapter_preference_submitted,
    };
    active_ = active_t {selection, std::move(snapshot)};
    return {start_error_e::none, validation_error_e::none, std::move(selection)};
  }

  bool coordinator_t::stop(std::uint64_t session_id) noexcept {
    std::lock_guard lock(mutex_);
    if (pending_cleanup_) {
      if (session_id == 0 || session_id != pending_cleanup_->session_id) {
        return false;
      }
      const auto stopped = rollback_locked(pending_cleanup_->generation, &pending_cleanup_->snapshot);
      if (stopped) {
        pending_cleanup_.reset();
      }
      return stopped;
    }
    if (!active_) {
      return true;
    }
    if (session_id == 0 || session_id != active_->selection.session_id) {
      return false;
    }
    const auto stopped = rollback_locked(active_->selection.generation, &active_->snapshot);
    if (stopped) {
      active_.reset();
    }
    return stopped;
  }

  std::optional<stream_selection_t> coordinator_t::active_selection() const {
    std::lock_guard lock(mutex_);
    return active_ ? std::optional {active_->selection} : std::nullopt;
  }

  session_lease_t::session_lease_t(
    std::shared_ptr<activation_backend_t> backend,
    const std::uint64_t session_id,
    const std::uint64_t token
  ):
      backend_(std::move(backend)),
      session_id_(session_id),
      token_(token) {
    if (!backend_ || session_id_ == 0 || token_ == 0) {
      throw std::invalid_argument("Virtual display lease requires a backend, session, and token");
    }
  }

  session_lease_t::~session_lease_t() {
    static_cast<void>(release());
  }

  bool session_lease_t::release() noexcept {
    std::lock_guard lock(mutex_);
    if (released_) {
      return true;
    }
    released_ = backend_->release_lease(session_id_, token_, owner_released_);
    return released_;
  }

  bool session_lease_t::released() const noexcept {
    std::lock_guard lock(mutex_);
    return released_;
  }

  std::shared_ptr<session_lease_t> activation_backend_t::acquire_lease(const std::uint64_t session_id) {
    std::lock_guard lock(lease_mutex_);
    return acquire_lease_locked(session_id);
  }

  std::shared_ptr<session_lease_t> activation_backend_t::acquire_lease_locked(const std::uint64_t session_id) {
    if (session_id == 0 || next_lease_token_ == 0) {
      throw std::invalid_argument("Virtual display lease registry requires a nonzero session and token");
    }
    if (auto it = leases_.find(session_id); it != leases_.end()) {
      if (it->second.cleanup_pending || it->second.owners == 0) {
        throw std::logic_error("Virtual display cleanup must complete before reacquisition");
      }
      auto lease = std::make_shared<session_lease_t>(shared_from_this(), session_id, it->second.token);
      ++it->second.owners;
      return lease;
    }
    const auto token = next_lease_token_;
    leases_.emplace(session_id, lease_record_t {token, 1, false});
    std::shared_ptr<session_lease_t> lease;
    try {
      lease = std::make_shared<session_lease_t>(shared_from_this(), session_id, token);
    } catch (...) {
      leases_.erase(session_id);
      throw;
    }
    ++next_lease_token_;
    return lease;
  }

  bool activation_backend_t::cleanup_pending_locked() noexcept {
    constexpr auto maximum_cleanup_attempts = 3;
    for (auto it = leases_.begin(); it != leases_.end();) {
      if (!it->second.cleanup_pending) {
        ++it;
        continue;
      }
      if (it->second.owners != 0) {
        return false;
      }
      bool cleaned = false;
      for (int attempt = 0; attempt < maximum_cleanup_attempts && !cleaned; ++attempt) {
        cleaned = stop(it->first);
      }
      if (!cleaned) {
        return false;
      }
      it = leases_.erase(it);
    }
    return true;
  }

  void activation_backend_t::retain_cleanup_obligation_locked(const std::uint64_t session_id) {
    if (auto existing = leases_.find(session_id); existing != leases_.end()) {
      existing->second.cleanup_pending = true;
      return;
    }
    const auto token = next_lease_token_;
    leases_.emplace(session_id, lease_record_t {token, 0, true});
    if (next_lease_token_ != 0) {
      ++next_lease_token_;
    }
  }

  owned_start_result_t activation_backend_t::start_owned(
    const stream_request_t &request,
    const mode_limits_t &limits
  ) {
    std::lock_guard lock(lease_mutex_);
    if (!cleanup_pending_locked()) {
      return {{start_error_e::rollback_failed, validation_error_e::none, std::nullopt}, {}};
    }
    auto started = start(request, limits);
    if (started.error != start_error_e::none) {
      if (started.error == start_error_e::rollback_failed) {
        retain_cleanup_obligation_locked(request.session_id);
      }
      return {std::move(started), {}};
    }
    if (!started.selection) {
      const auto stopped = stop(request.session_id);
      if (!stopped) {
        retain_cleanup_obligation_locked(request.session_id);
      }
      return {
        {
          stopped ? start_error_e::implicit_adjustment_rejected : start_error_e::rollback_failed,
          started.validation_error,
          std::nullopt,
        },
        {},
      };
    }
    try {
      auto lease = acquire_lease_locked(request.session_id);
      return {std::move(started), std::move(lease)};
    } catch (...) {
      if (const auto existing = leases_.find(request.session_id);
          existing != leases_.end() && existing->second.owners != 0) {
        return {
          {
            start_error_e::implicit_adjustment_rejected,
            validation_error_e::none,
            std::nullopt,
          },
          {},
        };
      }
      const auto stopped = stop(request.session_id);
      if (!stopped) {
        retain_cleanup_obligation_locked(request.session_id);
      }
      return {
        {
          stopped ? start_error_e::implicit_adjustment_rejected : start_error_e::rollback_failed,
          validation_error_e::none,
          std::nullopt,
        },
        {},
      };
    }
  }

  bool activation_backend_t::release_lease(
    const std::uint64_t session_id,
    const std::uint64_t token,
    bool &owner_released
  ) noexcept {
    std::lock_guard lock(lease_mutex_);
    const auto it = leases_.find(session_id);
    if (it == leases_.end() || it->second.token != token) {
      owner_released = true;
      return true;
    }
    if (!owner_released) {
      if (it->second.owners == 0) {
        return false;
      }
      --it->second.owners;
      owner_released = true;
    }
    if (it->second.owners != 0) {
      return true;
    }
    if (!stop(session_id)) {
      it->second.cleanup_pending = true;
      return false;
    }
    leases_.erase(it);
    return true;
  }

  session_prepare_result_t prepare_stream_session(
    const activation_policy_e policy,
    const stream_request_t &request,
    const mode_limits_t &limits,
    std::string physical_capture,
    std::shared_ptr<activation_backend_t> backend
  ) {
    const auto permits_physical_fallback = [](const start_error_e diagnostic) {
      switch (diagnostic) {
        case start_error_e::invalid_mode:
        case start_error_e::driver_unavailable:
        case start_error_e::driver_prepare_failed:
        case start_error_e::driver_start_failed:
        case start_error_e::display_snapshot_failed:
        case start_error_e::display_commit_failed:
        case start_error_e::display_unstable:
        case start_error_e::implicit_adjustment_rejected:
          return true;
        case start_error_e::none:
        case start_error_e::invalid_session:
        case start_error_e::busy:
        case start_error_e::stale_recovery_failed:
        case start_error_e::rollback_failed:
          return false;
      }
      return false;
    };
    const auto physical = [&physical_capture](
                            const start_error_e diagnostic = start_error_e::none,
                            const validation_error_e validation = validation_error_e::none
                          ) {
      return session_prepare_result_t {
        session_prepare_e::physical,
        std::move(physical_capture),
        std::nullopt,
        {},
        diagnostic,
        validation,
      };
    };
    const auto rejected = [&physical_capture](
                            const start_error_e diagnostic,
                            const validation_error_e validation = validation_error_e::none
                          ) {
      return session_prepare_result_t {
        session_prepare_e::rejected,
        std::move(physical_capture),
        std::nullopt,
        {},
        diagnostic,
        validation,
      };
    };

    if (policy == activation_policy_e::disabled) {
      return physical();
    }
    if (policy != activation_policy_e::optional && policy != activation_policy_e::required) {
      return rejected(start_error_e::invalid_mode);
    }
    if (request.session_id == 0) {
      return rejected(start_error_e::invalid_session);
    }
    if (request.delivery_policy != delivery_policy_e::latency && request.delivery_policy != delivery_policy_e::quality) {
      return policy == activation_policy_e::optional ?
               physical(start_error_e::invalid_mode, validation_error_e::unsupported_delivery_policy) :
               rejected(start_error_e::invalid_mode, validation_error_e::unsupported_delivery_policy);
    }
    const auto validation = validate_mode(request.mode, limits, request.minimum_fidelity);
    if (validation != validation_error_e::none) {
      return policy == activation_policy_e::optional ?
               physical(start_error_e::invalid_mode, validation) :
               rejected(start_error_e::invalid_mode, validation);
    }
    if (!backend) {
      return policy == activation_policy_e::optional ?
               physical(start_error_e::driver_unavailable) :
               rejected(start_error_e::driver_unavailable);
    }
    auto owned_start = backend->start_owned(request, limits);
    auto &started = owned_start.started;
    if (started.error != start_error_e::none) {
      if (policy == activation_policy_e::optional && permits_physical_fallback(started.error)) {
        return physical(started.error, started.validation_error);
      }
      return rejected(started.error, started.validation_error);
    }
    if (!started.selection || !owned_start.lease) {
      return rejected(start_error_e::implicit_adjustment_rejected);
    }

    const auto &selection = *started.selection;
    const auto valid_selection =
      selection.session_id == request.session_id &&
      selection.requested_mode == request.mode &&
      selection.selected_mode == request.mode &&
      selection.delivery_policy == request.delivery_policy &&
      selection.fidelity == request.minimum_fidelity &&
      !selection.adjusted &&
      !selection.capture_name.empty();
    if (!valid_selection) {
      const auto safely_released = owned_start.lease->release();
      if (!safely_released || policy == activation_policy_e::required) {
        return rejected(
          safely_released ? start_error_e::implicit_adjustment_rejected : start_error_e::rollback_failed
        );
      }
      return physical(start_error_e::implicit_adjustment_rejected);
    }

    return {
      session_prepare_e::virtual_display,
      selection.capture_name,
      std::move(started.selection),
      std::move(owned_start.lease),
      start_error_e::none,
      validation_error_e::none,
    };
  }

  bool coordinator_t::rollback_locked(
    std::uint64_t generation,
    const display_snapshot_t *snapshot
  ) noexcept {
    const auto display_restored = snapshot == nullptr || display_->restore(*snapshot);
    const auto channel_open = static_cast<bool>(channel_->open());
    const auto driver_stopped = channel_open && static_cast<bool>(channel_->stop_monitor(generation));
    if (driver_stopped) {
      channel_->close();
    }
    return display_restored && driver_stopped;
  }

  start_result_t coordinator_t::fail_transaction_locked(
    start_error_e error,
    std::uint64_t session_id,
    std::uint64_t generation,
    display_snapshot_t snapshot
  ) {
    if (rollback_locked(generation, &snapshot)) {
      return {error, validation_error_e::none, std::nullopt};
    }
    pending_cleanup_ = pending_cleanup_t {session_id, generation, std::move(snapshot)};
    return {start_error_e::rollback_failed, validation_error_e::none, std::nullopt};
  }

#ifdef _WIN32
  namespace {
    std::optional<mode_t> from_abi(const LUMEN_VDD_MODE &mode) {
      if ((mode.dynamic_range != LUMEN_VDD_DYNAMIC_RANGE_SDR && mode.dynamic_range != LUMEN_VDD_DYNAMIC_RANGE_HDR10) ||
          (mode.bits_per_channel != 8 && mode.bits_per_channel != 10) ||
          (mode.delivery_policy != LUMEN_VDD_POLICY_LATENCY && mode.delivery_policy != LUMEN_VDD_POLICY_QUALITY) ||
          (mode.minimum_fidelity != LUMEN_VDD_FIDELITY_LOSSLESS &&
           mode.minimum_fidelity != LUMEN_VDD_FIDELITY_VISUALLY_LOSSLESS)) {
        return std::nullopt;
      }
      mode_t converted {
        mode.width,
        mode.height,
        {mode.refresh_numerator, mode.refresh_denominator},
        mode.dynamic_range == LUMEN_VDD_DYNAMIC_RANGE_HDR10 ? dynamic_range_e::hdr10 : dynamic_range_e::sdr,
        mode.bits_per_channel,
      };
      const auto shape = lumen::protocol_v3::start_mode::admit_shape({
        converted.width,
        converted.height,
        converted.refresh.numerator,
        converted.refresh.denominator,
      });
      const auto exact_color_mode =
        (converted.dynamic_range == dynamic_range_e::sdr && converted.bits_per_channel == 8) ||
        (converted.dynamic_range == dynamic_range_e::hdr10 && converted.bits_per_channel == 10);
      if (shape != lumen::protocol_v3::start_mode::AdmissionError::none || !exact_color_mode ||
          converted.refresh.normalized() != converted.refresh) {
        return std::nullopt;
      }
      return converted;
    }

    LUMEN_VDD_MODE to_abi(const mode_t &mode, delivery_policy_e policy, fidelity_e fidelity) {
      return {
        mode.width,
        mode.height,
        mode.refresh.numerator,
        mode.refresh.denominator,
        static_cast<std::uint8_t>(mode.dynamic_range == dynamic_range_e::hdr10 ? LUMEN_VDD_DYNAMIC_RANGE_HDR10 : LUMEN_VDD_DYNAMIC_RANGE_SDR),
        mode.bits_per_channel,
        static_cast<std::uint8_t>(policy == delivery_policy_e::latency ? LUMEN_VDD_POLICY_LATENCY : LUMEN_VDD_POLICY_QUALITY),
        static_cast<std::uint8_t>(fidelity == fidelity_e::lossless ? LUMEN_VDD_FIDELITY_LOSSLESS : LUMEN_VDD_FIDELITY_VISUALLY_LOSSLESS),
      };
    }

    class system_control_channel_t final: public control_channel_t {
    public:
      ~system_control_channel_t() override {
        close();
      }

      channel_result_t open() override {
        if (handle_ != INVALID_HANDLE_VALUE) {
          return {};
        }
        HDEVINFO devices = SetupDiGetClassDevsW(
          &GUID_DEVINTERFACE_LUMEN_VIRTUAL_DISPLAY,
          nullptr,
          nullptr,
          DIGCF_DEVICEINTERFACE | DIGCF_PRESENT
        );
        if (devices == INVALID_HANDLE_VALUE) {
          return {false, GetLastError()};
        }
        SP_DEVICE_INTERFACE_DATA interface_data {sizeof(interface_data)};
        if (!SetupDiEnumDeviceInterfaces(devices, nullptr, &GUID_DEVINTERFACE_LUMEN_VIRTUAL_DISPLAY, 0, &interface_data)) {
          const auto error = GetLastError();
          SetupDiDestroyDeviceInfoList(devices);
          return {false, error};
        }
        SP_DEVICE_INTERFACE_DATA duplicate_interface {sizeof(duplicate_interface)};
        if (SetupDiEnumDeviceInterfaces(
              devices,
              nullptr,
              &GUID_DEVINTERFACE_LUMEN_VIRTUAL_DISPLAY,
              1,
              &duplicate_interface
            )) {
          SetupDiDestroyDeviceInfoList(devices);
          return {false, ERROR_DUP_NAME};
        }
        if (GetLastError() != ERROR_NO_MORE_ITEMS) {
          const auto error = GetLastError();
          SetupDiDestroyDeviceInfoList(devices);
          return {false, error};
        }
        DWORD required = 0;
        SetupDiGetDeviceInterfaceDetailW(devices, &interface_data, nullptr, 0, &required, nullptr);
        if (required < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)) {
          const auto error = GetLastError();
          SetupDiDestroyDeviceInfoList(devices);
          return {false, error};
        }
        std::vector<std::byte> detail_storage(required);
        auto *detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W *>(detail_storage.data());
        detail->cbSize = sizeof(*detail);
        if (!SetupDiGetDeviceInterfaceDetailW(devices, &interface_data, detail, required, nullptr, nullptr)) {
          const auto error = GetLastError();
          SetupDiDestroyDeviceInfoList(devices);
          return {false, error};
        }
        handle_ = CreateFileW(
          detail->DevicePath,
          GENERIC_READ | GENERIC_WRITE,
          FILE_SHARE_READ | FILE_SHARE_WRITE,
          nullptr,
          OPEN_EXISTING,
          FILE_ATTRIBUTE_NORMAL,
          nullptr
        );
        const auto error = handle_ == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        SetupDiDestroyDeviceInfoList(devices);
        return handle_ == INVALID_HANDLE_VALUE ? channel_result_t {false, error} : channel_result_t {};
      }

      channel_result_t query_limits(mode_limits_t &limits) override {
        LUMEN_VDD_QUERY_ABI_RESPONSE response {};
        auto result = ioctl(IOCTL_LUMEN_VDD_QUERY_ABI, nullptr, 0, &response, sizeof(response));
        if (!result) {
          return result;
        }
        if (response.abi_version != LUMEN_VDD_ABI_VERSION ||
            (response.capability_flags & (LUMEN_VDD_CAP_DYNAMIC_MODES | LUMEN_VDD_CAP_SDR8)) !=
              (LUMEN_VDD_CAP_DYNAMIC_MODES | LUMEN_VDD_CAP_SDR8)) {
          return {false, ERROR_REVISION_MISMATCH};
        }
        limits = {
          response.minimum_width,
          response.maximum_width,
          response.minimum_height,
          response.maximum_height,
          {response.minimum_refresh_numerator, response.minimum_refresh_denominator},
          {response.maximum_refresh_numerator, response.maximum_refresh_denominator},
          response.maximum_pixels,
          response.maximum_pixel_rate,
          true,
          (response.capability_flags & LUMEN_VDD_CAP_HDR10) != 0,
          (response.capability_flags & LUMEN_VDD_CAP_10BIT) != 0,
          (response.capability_flags & LUMEN_VDD_CAP_LOSSLESS) != 0,
          (response.capability_flags & LUMEN_VDD_CAP_VISUALLY_LOSSLESS) != 0,
        };
        return {};
      }

      channel_result_t query_state(driver_state_t &state) override {
        LUMEN_VDD_QUERY_STATE_RESPONSE response {};
        auto result = ioctl(IOCTL_LUMEN_VDD_QUERY_STATE, nullptr, 0, &response, sizeof(response));
        if (!result) {
          return result;
        }
        if (response.monitor_started > 1 || response.render_adapter_preference_submitted > 1 || response.reserved != 0 ||
            response.last_generation < response.generation ||
            (response.generation == 0 &&
             (response.owner_process_id != 0 || response.monitor_started != 0 ||
              response.preferred_render_adapter_luid != 0 || response.assigned_render_adapter_luid != 0 ||
              response.render_adapter_preference_submitted != 0)) ||
            (response.generation != 0 &&
             (response.owner_process_id == 0 || response.preferred_render_adapter_luid == 0))) {
          return {false, ERROR_INVALID_DATA};
        }
        mode_t active_mode;
        std::optional<delivery_policy_e> active_delivery_policy;
        if (response.generation != 0) {
          const auto converted = from_abi(response.mode);
          if (!converted) {
            return {false, ERROR_INVALID_DATA};
          }
          active_mode = *converted;
          active_delivery_policy = response.mode.delivery_policy == LUMEN_VDD_POLICY_LATENCY ?
                                     delivery_policy_e::latency :
                                     delivery_policy_e::quality;
        }
        state = {
          response.generation,
          response.owner_process_id,
          response.monitor_started != 0,
          active_mode,
          response.last_generation,
          response.preferred_render_adapter_luid,
          response.assigned_render_adapter_luid,
          response.render_adapter_preference_submitted != 0,
          active_delivery_policy,
        };
        return {};
      }

      channel_result_t recover_stale(std::uint64_t generation) override {
        driver_state_t state;
        auto result = query_state(state);
        if (!result || state.generation != generation || state.owner_process_id == 0) {
          return {false, ERROR_INVALID_STATE};
        }
        HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, state.owner_process_id);
        if (process != nullptr) {
          const auto wait = WaitForSingleObject(process, 0);
          CloseHandle(process);
          if (wait == WAIT_TIMEOUT) {
            return {false, ERROR_BUSY};
          }
          if (wait != WAIT_OBJECT_0) {
            return {false, ERROR_INVALID_STATE};
          }
        } else {
          const auto error = GetLastError();
          if (error != ERROR_INVALID_PARAMETER) {
            return {false, error};
          }
        }
        const LUMEN_VDD_GENERATION_REQUEST request {generation};
        return ioctl(IOCTL_LUMEN_VDD_RECOVER_STALE, &request, sizeof(request), nullptr, 0);
      }

      channel_result_t prepare_mode(
        std::uint64_t generation,
        const mode_t &mode,
        delivery_policy_e delivery_policy,
        fidelity_e minimum_fidelity,
        const std::uint64_t preferred_render_adapter_luid,
        prepared_mode_t &prepared
      ) override {
        const LUMEN_VDD_PREPARE_MODE_REQUEST request {
          generation,
          GetCurrentProcessId(),
          0,
          preferred_render_adapter_luid,
          to_abi(mode, delivery_policy, minimum_fidelity),
        };
        LUMEN_VDD_PREPARE_MODE_RESPONSE response {};
        const auto result = ioctl(IOCTL_LUMEN_VDD_PREPARE_MODE, &request, sizeof(request), &response, sizeof(response));
        if (!result) {
          return result;
        }
        const auto terminator = std::find(std::begin(response.connector_id_utf8), std::end(response.connector_id_utf8), '\0');
        const auto converted = from_abi(response.mode);
        const auto valid_reserved = std::ranges::all_of(response.reserved, [](std::uint8_t value) {
          return value == 0;
        });
        const auto expected_policy = delivery_policy == delivery_policy_e::latency ? LUMEN_VDD_POLICY_LATENCY : LUMEN_VDD_POLICY_QUALITY;
        const auto expected_fidelity = minimum_fidelity == fidelity_e::lossless ?
                                         LUMEN_VDD_FIDELITY_LOSSLESS :
                                         LUMEN_VDD_FIDELITY_VISUALLY_LOSSLESS;
        if (!converted || !valid_reserved || response.render_adapter_preference_submitted > 1 ||
            response.preferred_render_adapter_luid != preferred_render_adapter_luid ||
            response.mode.delivery_policy != expected_policy ||
            response.mode.minimum_fidelity != expected_fidelity ||
            (response.fidelity != LUMEN_VDD_FIDELITY_LOSSLESS &&
             response.fidelity != LUMEN_VDD_FIDELITY_VISUALLY_LOSSLESS) ||
            terminator == std::begin(response.connector_id_utf8) || terminator == std::end(response.connector_id_utf8)) {
          return {false, ERROR_INVALID_DATA};
        }
        prepared = {
          *converted,
          std::string(response.connector_id_utf8, terminator),
          response.fidelity == LUMEN_VDD_FIDELITY_VISUALLY_LOSSLESS ? fidelity_e::visually_lossless : fidelity_e::lossless,
          response.preferred_render_adapter_luid,
          response.render_adapter_preference_submitted != 0,
        };
        return {};
      }

      channel_result_t start_monitor(std::uint64_t generation) override {
        const LUMEN_VDD_GENERATION_REQUEST request {generation};
        return ioctl(IOCTL_LUMEN_VDD_START_MONITOR, &request, sizeof(request), nullptr, 0);
      }

      channel_result_t stop_monitor(std::uint64_t generation) override {
        const LUMEN_VDD_GENERATION_REQUEST request {generation};
        return ioctl(IOCTL_LUMEN_VDD_STOP_MONITOR, &request, sizeof(request), nullptr, 0);
      }

      void close() noexcept override {
        if (handle_ != INVALID_HANDLE_VALUE) {
          CloseHandle(std::exchange(handle_, INVALID_HANDLE_VALUE));
        }
      }

    private:
      channel_result_t ioctl(DWORD code, const void *input, DWORD input_size, void *output, DWORD output_size) {
        if (handle_ == INVALID_HANDLE_VALUE) {
          return {false, ERROR_INVALID_HANDLE};
        }
        DWORD transferred = 0;
        if (!DeviceIoControl(handle_, code, const_cast<void *>(input), input_size, output, output_size, &transferred, nullptr)) {
          return {false, GetLastError()};
        }
        return transferred == output_size ? channel_result_t {} : channel_result_t {false, ERROR_INVALID_DATA};
      }

      HANDLE handle_ {INVALID_HANDLE_VALUE};
    };

    class system_display_config_t final: public display_config_t {
    public:
      bool snapshot(display_snapshot_t &snapshot) override {
        std::vector<DISPLAYCONFIG_PATH_INFO> paths;
        std::vector<DISPLAYCONFIG_MODE_INFO> modes;
        if (!query(QDC_ONLY_ACTIVE_PATHS, paths, modes)) {
          return false;
        }
        snapshot.paths.resize(paths.size() * sizeof(paths.front()));
        snapshot.modes.resize(modes.size() * sizeof(modes.front()));
        if (!paths.empty()) {
          std::memcpy(snapshot.paths.data(), paths.data(), snapshot.paths.size());
        }
        if (!modes.empty()) {
          std::memcpy(snapshot.modes.data(), modes.data(), snapshot.modes.size());
        }
        snapshot.advanced_color.clear();
        std::vector<advanced_color_path_t> color_paths;
        color_paths.reserve(paths.size());
        for (const auto &path : paths) {
          color_paths.push_back({
            pack_display_luid(path.targetInfo.adapterId),
            path.targetInfo.id,
            (path.flags & DISPLAYCONFIG_PATH_ACTIVE) != 0,
            path.targetInfo.targetAvailable != FALSE,
          });
        }
        for (const auto &target : active_advanced_color_targets(color_paths)) {
          const auto adapter_id = unpack_display_luid(target.adapter_luid);
          const auto state = query_advanced_color_state(adapter_id, target.target_id);
          if (!state) {
            return false;
          }
          snapshot.advanced_color.push_back({target.adapter_luid, target.target_id, *state});
        }
        return true;
      }

      bool commit(const std::string &connector_id, const mode_t &mode, display_commit_t &applied) override {
        std::vector<DISPLAYCONFIG_PATH_INFO> paths;
        std::vector<DISPLAYCONFIG_MODE_INFO> modes;
        if (!query(QDC_ALL_PATHS, paths, modes)) {
          return false;
        }
        const auto matches_connector = [&connector_id](const DISPLAYCONFIG_PATH_INFO &path) {
          if (connector_id != "LUM0001") {
            return false;
          }
          DISPLAYCONFIG_TARGET_DEVICE_NAME target {};
          target.header.type = DISPLAYCONFIG_DEVICE_INFO_GET_TARGET_NAME;
          target.header.size = sizeof(target);
          target.header.adapterId = path.targetInfo.adapterId;
          target.header.id = path.targetInfo.id;
          if (DisplayConfigGetDeviceInfo(&target.header) != ERROR_SUCCESS) {
            return false;
          }
          return monitor_interface_has_container_id(
            target.monitorDevicePath,
            GUID_CONTAINERID_LUMEN_VIRTUAL_DISPLAY_MONITOR
          );
        };
        std::vector<std::uint8_t> connector_matches;
        connector_matches.reserve(paths.size());
        for (const auto &path : paths) {
          connector_matches.push_back(matches_connector(path) ? 1U : 0U);
        }
        const auto connector_index = unique_matching_index(connector_matches);
        if (!connector_index) {
          return false;
        }
        std::vector<DISPLAYCONFIG_PATH_INFO> configured_paths;
        std::vector<DISPLAYCONFIG_MODE_INFO> configured_modes;
        if (!query(QDC_ONLY_ACTIVE_PATHS, configured_paths, configured_modes)) {
          return false;
        }
        auto path = paths[*connector_index];
        path.flags |= DISPLAYCONFIG_PATH_ACTIVE;
        path.targetInfo.refreshRate = {mode.refresh.numerator, mode.refresh.denominator};
        path.targetInfo.scanLineOrdering = DISPLAYCONFIG_SCANLINE_ORDERING_PROGRESSIVE;
        path.sourceInfo.modeInfoIdx = DISPLAYCONFIG_PATH_MODE_IDX_INVALID;
        path.targetInfo.modeInfoIdx = DISPLAYCONFIG_PATH_MODE_IDX_INVALID;

        LONG right_edge = 0;
        for (const auto &active_path : configured_paths) {
          if (active_path.sourceInfo.modeInfoIdx != DISPLAYCONFIG_PATH_MODE_IDX_INVALID &&
              active_path.sourceInfo.modeInfoIdx < configured_modes.size()) {
            const auto &active_mode = configured_modes[active_path.sourceInfo.modeInfoIdx];
            if (active_mode.infoType == DISPLAYCONFIG_MODE_INFO_TYPE_SOURCE) {
              right_edge = std::max(
                right_edge,
                active_mode.sourceMode.position.x + static_cast<LONG>(active_mode.sourceMode.width)
              );
            }
          }
        }

        DISPLAYCONFIG_MODE_INFO source_mode {};
        source_mode.infoType = DISPLAYCONFIG_MODE_INFO_TYPE_SOURCE;
        source_mode.id = path.sourceInfo.id;
        source_mode.adapterId = path.sourceInfo.adapterId;
        source_mode.sourceMode.width = mode.width;
        source_mode.sourceMode.height = mode.height;
        source_mode.sourceMode.pixelFormat = DISPLAYCONFIG_PIXELFORMAT_32BPP;
        source_mode.sourceMode.position = {right_edge, 0};
        path.sourceInfo.modeInfoIdx = static_cast<UINT32>(configured_modes.size());
        configured_modes.push_back(source_mode);

        DISPLAYCONFIG_MODE_INFO target_mode {};
        target_mode.infoType = DISPLAYCONFIG_MODE_INFO_TYPE_TARGET;
        target_mode.id = path.targetInfo.id;
        target_mode.adapterId = path.targetInfo.adapterId;
        target_mode.targetMode.targetVideoSignalInfo.activeSize = {mode.width, mode.height};
        target_mode.targetMode.targetVideoSignalInfo.totalSize = {mode.width, mode.height};
        target_mode.targetMode.targetVideoSignalInfo.vSyncFreq = {mode.refresh.numerator, mode.refresh.denominator};
        const auto scan_lines_per_second =
          (static_cast<std::uint64_t>(mode.refresh.numerator) * mode.height + mode.refresh.denominator / 2U) /
          mode.refresh.denominator;
        target_mode.targetMode.targetVideoSignalInfo.hSyncFreq = {
          static_cast<UINT32>(scan_lines_per_second),
          1,
        };
        target_mode.targetMode.targetVideoSignalInfo.pixelRate =
          (static_cast<UINT64>(mode.width) * mode.height * mode.refresh.numerator + mode.refresh.denominator / 2U) /
          mode.refresh.denominator;
        target_mode.targetMode.targetVideoSignalInfo.scanLineOrdering = DISPLAYCONFIG_SCANLINE_ORDERING_PROGRESSIVE;
        target_mode.targetMode.targetVideoSignalInfo.AdditionalSignalInfo.videoStandard = 255;
        target_mode.targetMode.targetVideoSignalInfo.AdditionalSignalInfo.vSyncFreqDivider = 1;
        path.targetInfo.modeInfoIdx = static_cast<UINT32>(configured_modes.size());
        configured_modes.push_back(target_mode);
        configured_paths.push_back(path);

        if (SetDisplayConfig(
              static_cast<UINT32>(configured_paths.size()),
              configured_paths.data(),
              static_cast<UINT32>(configured_modes.size()),
              configured_modes.data(),
              SDC_APPLY | SDC_USE_SUPPLIED_DISPLAY_CONFIG | SDC_ALLOW_CHANGES
            ) != ERROR_SUCCESS) {
          return false;
        }
        const auto observed_color = query_advanced_color_state(path.targetInfo.adapterId, path.targetInfo.id);
        if (!observed_color) {
          return false;
        }
        switch (advanced_color_action(mode.dynamic_range, *observed_color)) {
          case advanced_color_action_e::enable:
            if (!set_advanced_color_state(path.targetInfo.adapterId, path.targetInfo.id, true)) {
              return false;
            }
            break;
          case advanced_color_action_e::disable:
            if (!set_advanced_color_state(path.targetInfo.adapterId, path.targetInfo.id, false)) {
              return false;
            }
            break;
          case advanced_color_action_e::none:
            break;
          case advanced_color_action_e::reject:
            return false;
        }
        DISPLAYCONFIG_SOURCE_DEVICE_NAME source {};
        source.header.type = DISPLAYCONFIG_DEVICE_INFO_GET_SOURCE_NAME;
        source.header.size = sizeof(source);
        source.header.adapterId = path.sourceInfo.adapterId;
        source.header.id = path.sourceInfo.id;
        if (DisplayConfigGetDeviceInfo(&source.header) != ERROR_SUCCESS) {
          return false;
        }
        const std::wstring capture {source.viewGdiDeviceName};
        if (capture.empty()) {
          return false;
        }
        applied = {mode, std::string(capture.begin(), capture.end())};
        return true;
      }

      bool await_stable(const std::string &capture_name, const mode_t &mode, std::chrono::milliseconds timeout) override {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        do {
          std::vector<DISPLAYCONFIG_PATH_INFO> paths;
          std::vector<DISPLAYCONFIG_MODE_INFO> modes;
          if (query(QDC_ONLY_ACTIVE_PATHS, paths, modes)) {
            for (const auto &path : paths) {
              DISPLAYCONFIG_SOURCE_DEVICE_NAME source {};
              source.header.type = DISPLAYCONFIG_DEVICE_INFO_GET_SOURCE_NAME;
              source.header.size = sizeof(source);
              source.header.adapterId = path.sourceInfo.adapterId;
              source.header.id = path.sourceInfo.id;
              if (DisplayConfigGetDeviceInfo(&source.header) != ERROR_SUCCESS) {
                continue;
              }
              const std::wstring observed_name {source.viewGdiDeviceName};
              if (std::string(observed_name.begin(), observed_name.end()) != capture_name ||
                  path.targetInfo.modeInfoIdx == DISPLAYCONFIG_PATH_MODE_IDX_INVALID ||
                  path.targetInfo.modeInfoIdx >= modes.size()) {
                continue;
              }
              const auto &target = modes[path.targetInfo.modeInfoIdx];
              if (target.infoType != DISPLAYCONFIG_MODE_INFO_TYPE_TARGET) {
                continue;
              }
              const auto &signal = target.targetMode.targetVideoSignalInfo;
              const rational_t observed_refresh {
                path.targetInfo.refreshRate.Numerator,
                path.targetInfo.refreshRate.Denominator,
              };
              if (signal.activeSize.cx == mode.width && signal.activeSize.cy == mode.height &&
                  observed_refresh.normalized() == mode.refresh) {
                const auto color = query_advanced_color_state(path.targetInfo.adapterId, path.targetInfo.id);
                if (color && advanced_color_matches(mode.dynamic_range, *color)) {
                  return true;
                }
              }
            }
          }
          Sleep(20);
        } while (std::chrono::steady_clock::now() < deadline);
        return false;
      }

      bool restore(const display_snapshot_t &snapshot) noexcept override {
        if (snapshot.paths.size() % sizeof(DISPLAYCONFIG_PATH_INFO) != 0 ||
            snapshot.modes.size() % sizeof(DISPLAYCONFIG_MODE_INFO) != 0) {
          return false;
        }
        const auto path_count = static_cast<UINT32>(snapshot.paths.size() / sizeof(DISPLAYCONFIG_PATH_INFO));
        const auto mode_count = static_cast<UINT32>(snapshot.modes.size() / sizeof(DISPLAYCONFIG_MODE_INFO));
        auto *paths = reinterpret_cast<DISPLAYCONFIG_PATH_INFO *>(const_cast<std::byte *>(snapshot.paths.data()));
        auto *modes = reinterpret_cast<DISPLAYCONFIG_MODE_INFO *>(const_cast<std::byte *>(snapshot.modes.data()));
        if (SetDisplayConfig(
              path_count,
              paths,
              mode_count,
              modes,
              SDC_APPLY | SDC_USE_SUPPLIED_DISPLAY_CONFIG
            ) != ERROR_SUCCESS) {
          return false;
        }
        return restore_all_advanced_color_states(snapshot.advanced_color, [&](const auto &saved, const bool enabled) {
          const auto adapter_id = unpack_display_luid(saved.adapter_luid);
          const auto before = query_advanced_color_state(adapter_id, saved.target_id);
          if (!before) {
            return false;
          }
          if (*before == saved.state) {
            return true;
          }
          if (!set_advanced_color_state(adapter_id, saved.target_id, enabled)) {
            return false;
          }
          const auto observed = query_advanced_color_state(adapter_id, saved.target_id);
          return observed && *observed == saved.state;
        });
      }

    private:
      static bool query(
        UINT32 flags,
        std::vector<DISPLAYCONFIG_PATH_INFO> &paths,
        std::vector<DISPLAYCONFIG_MODE_INFO> &modes
      ) {
        for (int attempt = 0; attempt < 4; ++attempt) {
          UINT32 path_count = 0;
          UINT32 mode_count = 0;
          if (GetDisplayConfigBufferSizes(flags, &path_count, &mode_count) != ERROR_SUCCESS) {
            return false;
          }
          paths.resize(path_count);
          modes.resize(mode_count);
          const auto status = QueryDisplayConfig(flags, &path_count, paths.data(), &mode_count, modes.data(), nullptr);
          if (status == ERROR_INSUFFICIENT_BUFFER) {
            continue;
          }
          if (status != ERROR_SUCCESS) {
            return false;
          }
          paths.resize(path_count);
          modes.resize(mode_count);
          return true;
        }
        return false;
      }
    };

    coordinator_t *system_coordinator() {
      static const auto channel = make_system_control_channel();
      static const auto display = make_system_display_config();
      static const auto coordinator = channel && display ?
                                        std::make_unique<coordinator_t>(channel, display) :
                                        nullptr;
      return coordinator.get();
    }
  }  // namespace

  std::shared_ptr<control_channel_t> make_system_control_channel() {
    return std::make_shared<system_control_channel_t>();
  }

  std::shared_ptr<display_config_t> make_system_display_config() {
    return std::make_shared<system_display_config_t>();
  }

  system_activation_result_t activate_system_stream(
    const stream_request_t &request,
    const mode_limits_t &limits
  ) {
    auto *coordinator = system_coordinator();
    if (coordinator == nullptr) {
      return {};
    }
    auto result = coordinator->start(request, limits);
    if (result.error != start_error_e::none || !result.selection) {
      return {system_activation_e::fallback, std::nullopt, result.error};
    }
    return {system_activation_e::active, std::move(result.selection), start_error_e::none};
  }

  bool deactivate_system_stream(std::uint64_t session_id) noexcept {
    auto *coordinator = system_coordinator();
    return coordinator == nullptr || coordinator->stop(session_id);
  }
#else
  std::shared_ptr<control_channel_t> make_system_control_channel() {
    return {};
  }

  std::shared_ptr<display_config_t> make_system_display_config() {
    return {};
  }

  system_activation_result_t activate_system_stream(const stream_request_t &, const mode_limits_t &) {
    return {};
  }

  bool deactivate_system_stream(std::uint64_t) noexcept {
    return true;
  }
#endif

  namespace {
    /** @brief Adapter from the production singleton coordinator to the transport-neutral seam. */
    class system_activation_backend_t final: public activation_backend_t {
    public:
      start_result_t start(const stream_request_t &request, const mode_limits_t &limits) override {
        auto bound_request = request;
#ifdef _WIN32
        const auto probe = ::video::active_encoder_probe_device_identity();
        if (!probe) {
          return {start_error_e::driver_unavailable, validation_error_e::none, std::nullopt};
        }
        const render_adapter_identity_t identity {
          probe->adapter_luid,
          probe->vendor_id,
          probe->device_id,
          probe->subsystem_id,
          probe->revision,
          probe->driver_version,
        };
        if (!valid_render_adapter_identity(identity)) {
          return {start_error_e::driver_unavailable, validation_error_e::none, std::nullopt};
        }
        bound_request.render_adapter = identity;
#endif
        auto activated = activate_system_stream(bound_request, limits);
        if (activated.outcome != system_activation_e::active || !activated.selection) {
          return {activated.diagnostic, validation_error_e::none, std::nullopt};
        }
        return {start_error_e::none, validation_error_e::none, std::move(activated.selection)};
      }

      bool stop(const std::uint64_t session_id) noexcept override {
        return deactivate_system_stream(session_id);
      }
    };
  }  // namespace

  session_prepare_result_t prepare_system_stream_session(
    const activation_policy_e policy,
    const stream_request_t &request,
    const mode_limits_t &limits,
    std::string physical_capture
  ) {
    static const auto backend = std::make_shared<system_activation_backend_t>();
    return prepare_stream_session(policy, request, limits, std::move(physical_capture), backend);
  }
}  // namespace platf::virtual_display
