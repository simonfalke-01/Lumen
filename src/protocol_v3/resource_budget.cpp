/**
 * @file src/protocol_v3/resource_budget.cpp
 * @brief Host-wide protocol-v3 resource admission accounting implementation.
 */

#include "resource_budget.h"

#include <algorithm>
#include <utility>

namespace lumen::protocol_v3::resource_budget {
  struct ResourceBudgetCoordinator::SharedCharge {
    SharedCharge() = default;

    SharedCharge(const ResourceClass resource_class, Lease lease) noexcept:
        resource_class {resource_class},
        lease {std::move(lease)} {
    }

    ResourceClass resource_class {ResourceClass::unclassified};
    Lease lease;
  };

  ResourceBudgetCoordinator::Lease::Lease(
    ResourceBudgetCoordinator *const owner,
    const ResourceClass resource_class,
    const std::size_t bytes
  ) noexcept:
      owner_ {owner},
      resource_class_ {resource_class},
      bytes_ {bytes} {
  }

  ResourceBudgetCoordinator::Lease::Lease(Lease &&other) noexcept:
      owner_ {std::exchange(other.owner_, nullptr)},
      resource_class_ {other.resource_class_},
      bytes_ {std::exchange(other.bytes_, 0)} {
  }

  ResourceBudgetCoordinator::Lease &ResourceBudgetCoordinator::Lease::operator=(Lease &&other) noexcept {
    if (this != &other) {
      release();
      owner_ = std::exchange(other.owner_, nullptr);
      resource_class_ = other.resource_class_;
      bytes_ = std::exchange(other.bytes_, 0);
    }
    return *this;
  }

  ResourceBudgetCoordinator::Lease::~Lease() {
    release();
  }

  bool ResourceBudgetCoordinator::Lease::resize(const std::size_t bytes) noexcept {
    return owner_ ? owner_->resize(*this, bytes) : bytes == 0;
  }

  void ResourceBudgetCoordinator::Lease::release() noexcept {
    if (owner_) {
      owner_->release(*this);
    }
  }

  std::size_t ResourceBudgetCoordinator::Lease::bytes() const noexcept {
    return bytes_;
  }

  ResourceClass ResourceBudgetCoordinator::Lease::resource_class() const noexcept {
    return resource_class_;
  }

  ResourceBudgetCoordinator::Lease::operator bool() const noexcept {
    return owner_ != nullptr;
  }

  ResourceBudgetCoordinator::SharedLease::SharedLease(
    std::shared_ptr<const void> owner,
    std::shared_ptr<SharedCharge> charge
  ) noexcept:
      owner_ {std::move(owner)},
      charge_ {std::move(charge)} {
  }

  std::size_t ResourceBudgetCoordinator::SharedLease::bytes() const noexcept {
    return charge_ ? charge_->lease.bytes() : 0;
  }

  ResourceClass ResourceBudgetCoordinator::SharedLease::resource_class() const noexcept {
    return charge_ ? charge_->resource_class : ResourceClass::unclassified;
  }

  ResourceBudgetCoordinator::SharedLease::operator bool() const noexcept {
    return charge_ != nullptr;
  }

  std::optional<ResourceBudgetCoordinator::Lease> ResourceBudgetCoordinator::reserve(
    const ResourceClass resource_class,
    const std::size_t bytes
  ) noexcept {
    const auto class_index = index(resource_class);
    if (class_index >= class_ceilings.size()) {
      return std::nullopt;
    }

    std::lock_guard lock {mutex_};
    if (bytes > class_ceilings[class_index] - class_current_[class_index] ||
        bytes > maximum_total_bytes - current_) {
      ++refusals_;
      ++class_refusals_[class_index];
      return std::nullopt;
    }
    current_ += bytes;
    class_current_[class_index] += bytes;
    high_water_ = std::max(high_water_, current_);
    class_high_water_[class_index] = std::max(class_high_water_[class_index], class_current_[class_index]);
    return Lease {this, resource_class, bytes};
  }

  bool ResourceBudgetCoordinator::resize(Lease &lease, const std::size_t bytes) noexcept {
    const auto class_index = index(lease.resource_class_);
    if (class_index >= class_ceilings.size()) {
      return false;
    }
    std::lock_guard lock {mutex_};
    if (bytes > lease.bytes_) {
      const auto growth = bytes - lease.bytes_;
      if (growth > class_ceilings[class_index] - class_current_[class_index] ||
          growth > maximum_total_bytes - current_) {
        ++refusals_;
        ++class_refusals_[class_index];
        return false;
      }
      current_ += growth;
      class_current_[class_index] += growth;
      high_water_ = std::max(high_water_, current_);
      class_high_water_[class_index] = std::max(class_high_water_[class_index], class_current_[class_index]);
    } else {
      const auto shrink = lease.bytes_ - bytes;
      current_ -= shrink;
      class_current_[class_index] -= shrink;
    }
    lease.bytes_ = bytes;
    return true;
  }

  void ResourceBudgetCoordinator::release(Lease &lease) noexcept {
    const auto class_index = index(lease.resource_class_);
    std::lock_guard lock {mutex_};
    if (class_index < class_current_.size()) {
      current_ -= std::min(current_, lease.bytes_);
      class_current_[class_index] -= std::min(class_current_[class_index], lease.bytes_);
    }
    lease.bytes_ = 0;
    lease.owner_ = nullptr;
  }

  std::optional<ResourceBudgetCoordinator::SharedLease> ResourceBudgetCoordinator::reserve_shared_erased(
    const ResourceClass resource_class,
    std::shared_ptr<const void> owner,
    const std::size_t bytes
  ) {
    if (!owner) {
      return std::nullopt;
    }

    std::lock_guard lock {mutex_};
    for (auto it = shared_.begin(); it != shared_.end();) {
      if (it->first.expired() || it->second.expired()) {
        it = shared_.erase(it);
      } else {
        ++it;
      }
    }

    const std::weak_ptr<const void> key {owner};
    if (const auto found = shared_.find(key); found != shared_.end()) {
      if (const auto existing = found->second.lock()) {
        if (bytes > existing->lease.bytes()) {
          return std::nullopt;
        }
        return SharedLease {std::move(owner), std::move(existing)};
      }
    }

    const auto class_index = index(resource_class);
    if (class_index >= class_ceilings.size() ||
        bytes > class_ceilings[class_index] - class_current_[class_index] ||
        bytes > maximum_total_bytes - current_) {
      ++refusals_;
      if (class_index < class_refusals_.size()) {
        ++class_refusals_[class_index];
      }
      return std::nullopt;
    }
    auto charge = std::make_shared<SharedCharge>();
    const auto [entry, inserted] = shared_.try_emplace(key);
    static_cast<void>(inserted);
    current_ += bytes;
    class_current_[class_index] += bytes;
    high_water_ = std::max(high_water_, current_);
    class_high_water_[class_index] = std::max(class_high_water_[class_index], class_current_[class_index]);
    charge->resource_class = resource_class;
    charge->lease = Lease {this, resource_class, bytes};
    entry->second = charge;
    return SharedLease {std::move(owner), std::move(charge)};
  }

  std::optional<ResourceBudgetCoordinator::SharedLease> ResourceBudgetCoordinator::adopt_shared_erased(
    std::shared_ptr<const void> owner,
    Lease &&lease
  ) {
    if (!owner || lease.owner_ != this || lease.bytes_ == 0) {
      return std::nullopt;
    }
    std::lock_guard lock {mutex_};
    for (auto it = shared_.begin(); it != shared_.end();) {
      if (it->first.expired() || it->second.expired()) {
        it = shared_.erase(it);
      } else {
        ++it;
      }
    }
    const std::weak_ptr<const void> key {owner};
    if (const auto found = shared_.find(key); found != shared_.end() && !found->second.expired()) {
      return std::nullopt;
    }
    auto charge = std::make_shared<SharedCharge>(lease.resource_class_, std::move(lease));
    shared_[key] = charge;
    return SharedLease {std::move(owner), std::move(charge)};
  }

  Snapshot ResourceBudgetCoordinator::snapshot() const noexcept {
    std::lock_guard lock {mutex_};
    Snapshot result {
      .current = current_,
      .high_water = high_water_,
      .refusals = refusals_,
    };
    for (std::size_t class_index = 0; class_index < result.classes.size(); ++class_index) {
      result.classes[class_index] = {
        .ceiling = class_ceilings[class_index],
        .current = class_current_[class_index],
        .high_water = class_high_water_[class_index],
        .refusals = class_refusals_[class_index],
      };
    }
    return result;
  }
}  // namespace lumen::protocol_v3::resource_budget
