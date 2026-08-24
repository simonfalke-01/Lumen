/**
 * @file LumenSingleDeleteOwner.h
 * @brief Atomic single-delete ownership used by the IddCx worker boundary.
 */
#pragma once

#include <atomic>
#include <utility>

namespace lumen::vdd {
  template<class Handle, class Deleter>
  class single_delete_owner_t {
  public:
    single_delete_owner_t() noexcept = default;

    explicit single_delete_owner_t(Handle handle, Deleter deleter = {}) noexcept:
        handle_(handle),
        deleter_(std::move(deleter)) {}

    ~single_delete_owner_t() {
      reset();
    }

    single_delete_owner_t(const single_delete_owner_t &) = delete;
    single_delete_owner_t &operator=(const single_delete_owner_t &) = delete;

    [[nodiscard]] Handle get() const noexcept {
      return handle_.load(std::memory_order_acquire);
    }

    [[nodiscard]] Handle release() noexcept {
      return handle_.exchange(Handle {}, std::memory_order_acq_rel);
    }

    void reset() noexcept {
      const auto handle = handle_.exchange(Handle {}, std::memory_order_acq_rel);
      if (handle != Handle {}) {
        deleter_(handle);
      }
    }

  private:
    std::atomic<Handle> handle_ {};
    [[no_unique_address]] Deleter deleter_;
  };
}  // namespace lumen::vdd
