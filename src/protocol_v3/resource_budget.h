/**
 * @file src/protocol_v3/resource_budget.h
 * @brief Thread-safe host-wide protocol-v3 resource admission accounting.
 */

#pragma once

#include <array>
#include <cstddef>
#include <map>
#include <memory>
#include <mutex>
#include <optional>

namespace lumen::protocol_v3::resource_budget {
  /** @brief Independently reserved host-memory classes. */
  enum class ResourceClass : std::size_t {
    critical,
    cached_responses,
    operation_outcomes,
    bulk,
    media,
    metadata,
    unclassified,
    count,
  };

  inline constexpr std::size_t mib = 1024U * 1024U;
  inline constexpr std::size_t maximum_total_bytes = 512U * mib;
  inline constexpr std::array<std::size_t, static_cast<std::size_t>(ResourceClass::count)> class_ceilings {
    16U * mib,   // critical
    8U * mib,    // cached_responses
    8U * mib,    // operation_outcomes
    64U * mib,   // bulk
    400U * mib,  // media
    8U * mib,    // metadata
    8U * mib,    // unclassified
  };

  /** @brief Read-only accounting for one independently reserved class. */
  struct ClassSnapshot {
    std::size_t ceiling {};
    std::size_t current {};
    std::size_t high_water {};
    std::size_t refusals {};
  };

  /** @brief Read-only host-wide accounting snapshot. */
  struct Snapshot {
    std::size_t ceiling {maximum_total_bytes};
    std::size_t current {};
    std::size_t high_water {};
    std::size_t refusals {};
    std::array<ClassSnapshot, static_cast<std::size_t>(ResourceClass::count)> classes {};
  };

  /**
   * @brief Host-wide byte admission coordinator with non-borrowable class reserves.
   *
   * A lease is the only way to hold admitted bytes. Its destructor releases the
   * exact remaining charge once, including during exception unwinding.
   */
  class ResourceBudgetCoordinator {
  private:
    struct SharedCharge;

  public:
    class Lease {
    public:
      Lease() noexcept = default;
      Lease(const Lease &) = delete;
      Lease &operator=(const Lease &) = delete;
      Lease(Lease &&other) noexcept;
      Lease &operator=(Lease &&other) noexcept;
      ~Lease();

      /** @brief Grow or shrink this charge atomically; growth can be refused. */
      [[nodiscard]] bool resize(std::size_t bytes) noexcept;
      /** @brief Explicitly release the remaining charge; repeated calls are inert. */
      void release() noexcept;
      [[nodiscard]] std::size_t bytes() const noexcept;
      [[nodiscard]] ResourceClass resource_class() const noexcept;
      [[nodiscard]] explicit operator bool() const noexcept;

    private:
      friend class ResourceBudgetCoordinator;
      Lease(ResourceBudgetCoordinator *owner, ResourceClass resource_class, std::size_t bytes) noexcept;

      ResourceBudgetCoordinator *owner_ {};
      ResourceClass resource_class_ {ResourceClass::unclassified};
      std::size_t bytes_ {};
    };

    /**
     * @brief Copyable ownership token for a buffer charged exactly once.
     *
     * Every token retaining the same shared buffer control block shares one
     * backing Lease. The charge leaves the budget when the final token drops.
     */
    class SharedLease {
    public:
      SharedLease() noexcept = default;
      [[nodiscard]] std::size_t bytes() const noexcept;
      [[nodiscard]] ResourceClass resource_class() const noexcept;
      [[nodiscard]] explicit operator bool() const noexcept;

    private:
      friend class ResourceBudgetCoordinator;
      SharedLease(std::shared_ptr<const void> owner, std::shared_ptr<SharedCharge> charge) noexcept;

      std::shared_ptr<const void> owner_;
      std::shared_ptr<SharedCharge> charge_;
    };

    ResourceBudgetCoordinator() = default;
    ResourceBudgetCoordinator(const ResourceBudgetCoordinator &) = delete;
    ResourceBudgetCoordinator &operator=(const ResourceBudgetCoordinator &) = delete;

    /** @brief Reserve bytes in one class, refusing rather than borrowing another class's capacity. */
    [[nodiscard]] std::optional<Lease> reserve(ResourceClass resource_class, std::size_t bytes) noexcept;

    /** @brief Charge a shared owner once by identity of its shared_ptr control block. */
    template<typename T>
    [[nodiscard]] std::optional<SharedLease> reserve_shared(
      const ResourceClass resource_class,
      std::shared_ptr<T> owner,
      const std::size_t bytes
    ) {
      return reserve_shared_erased(
        resource_class,
        std::shared_ptr<const void> {std::move(owner)},
        bytes
      );
    }

    /** @brief Convert an already-admitted lease into one shared-owner charge without double accounting. */
    template<typename T>
    [[nodiscard]] std::optional<SharedLease> adopt_shared(
      std::shared_ptr<T> owner,
      Lease &&lease
    ) {
      return adopt_shared_erased(
        std::shared_ptr<const void> {std::move(owner)},
        std::move(lease)
      );
    }

    /** @brief Return current, high-water, and refusal accounting without mutating state. */
    [[nodiscard]] Snapshot snapshot() const noexcept;

  private:
    static constexpr std::size_t index(const ResourceClass resource_class) noexcept {
      return static_cast<std::size_t>(resource_class);
    }

    [[nodiscard]] bool resize(Lease &lease, std::size_t bytes) noexcept;
    void release(Lease &lease) noexcept;
    [[nodiscard]] std::optional<SharedLease> reserve_shared_erased(
      ResourceClass resource_class,
      std::shared_ptr<const void> owner,
      std::size_t bytes
    );
    [[nodiscard]] std::optional<SharedLease> adopt_shared_erased(
      std::shared_ptr<const void> owner,
      Lease &&lease
    );

    mutable std::mutex mutex_;
    std::size_t current_ {};
    std::size_t high_water_ {};
    std::size_t refusals_ {};
    std::array<std::size_t, class_ceilings.size()> class_current_ {};
    std::array<std::size_t, class_ceilings.size()> class_high_water_ {};
    std::array<std::size_t, class_ceilings.size()> class_refusals_ {};
    std::map<std::weak_ptr<const void>, std::weak_ptr<SharedCharge>, std::owner_less<std::weak_ptr<const void>>> shared_;
  };
}  // namespace lumen::protocol_v3::resource_budget
