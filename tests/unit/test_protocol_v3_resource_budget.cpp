/**
 * @file tests/unit/test_protocol_v3_resource_budget.cpp
 * @brief Host-wide protocol-v3 resource budget regression tests.
 */

#include "src/protocol_v3/resource_budget.h"

#include <atomic>
#include <gtest/gtest.h>
#include <memory>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {
  namespace budget = lumen::protocol_v3::resource_budget;

  constexpr std::size_t index(const budget::ResourceClass resource_class) {
    return static_cast<std::size_t>(resource_class);
  }

  TEST(ProtocolV3ResourceBudget, EnforcesEveryClassAndTheExactHostCeiling) {
    budget::ResourceBudgetCoordinator coordinator;
    std::vector<budget::ResourceBudgetCoordinator::Lease> leases;
    for (std::size_t class_index = 0; class_index < budget::class_ceilings.size(); ++class_index) {
      const auto resource_class = static_cast<budget::ResourceClass>(class_index);
      auto lease = coordinator.reserve(resource_class, budget::class_ceilings[class_index]);
      ASSERT_TRUE(lease);
      leases.push_back(std::move(*lease));
    }

    const auto at_ceiling = coordinator.snapshot();
    EXPECT_EQ(at_ceiling.current, budget::maximum_total_bytes);
    EXPECT_EQ(at_ceiling.high_water, budget::maximum_total_bytes);
    EXPECT_FALSE(coordinator.reserve(budget::ResourceClass::critical, 1));
    EXPECT_EQ(coordinator.snapshot().refusals, 1U);
  }

  TEST(ProtocolV3ResourceBudget, CriticalReserveIsNotBorrowableByMedia) {
    budget::ResourceBudgetCoordinator coordinator;
    auto media = coordinator.reserve(budget::ResourceClass::media, 400U * budget::mib);
    ASSERT_TRUE(media);
    EXPECT_FALSE(coordinator.reserve(budget::ResourceClass::media, 1));
    auto critical = coordinator.reserve(budget::ResourceClass::critical, 16U * budget::mib);
    ASSERT_TRUE(critical);
    EXPECT_EQ(coordinator.snapshot().classes[index(budget::ResourceClass::critical)].current, 16U * budget::mib);
  }

  TEST(ProtocolV3ResourceBudget, LeaseMovesResizesAndReleasesExactlyOnce) {
    budget::ResourceBudgetCoordinator coordinator;
    auto first = coordinator.reserve(budget::ResourceClass::bulk, 4U * budget::mib);
    ASSERT_TRUE(first);
    auto moved = std::move(*first);
    EXPECT_FALSE(*first);
    EXPECT_TRUE(moved.resize(6U * budget::mib));
    EXPECT_TRUE(moved.resize(2U * budget::mib));
    EXPECT_EQ(coordinator.snapshot().current, 2U * budget::mib);
    moved.release();
    moved.release();
    EXPECT_EQ(coordinator.snapshot().current, 0U);
  }

  TEST(ProtocolV3ResourceBudget, ExceptionUnwindingReleasesTheLease) {
    budget::ResourceBudgetCoordinator coordinator;
    EXPECT_THROW(
      {
        auto lease = coordinator.reserve(budget::ResourceClass::metadata, 1U * budget::mib);
        ASSERT_TRUE(lease);
        throw std::runtime_error("test unwind");
      },
      std::runtime_error
    );
    EXPECT_EQ(coordinator.snapshot().current, 0U);
  }

  TEST(ProtocolV3ResourceBudget, SharedOwnerIsChargedOnceUntilItsFinalLeaseDrops) {
    budget::ResourceBudgetCoordinator coordinator;
    auto bytes = std::make_shared<std::vector<std::uint8_t>>(2U * budget::mib);
    auto first = coordinator.reserve_shared(budget::ResourceClass::cached_responses, bytes, bytes->size());
    ASSERT_TRUE(first);
    auto second = coordinator.reserve_shared(budget::ResourceClass::cached_responses, bytes, bytes->size());
    ASSERT_TRUE(second);
    EXPECT_EQ(coordinator.snapshot().current, bytes->size());
    auto borrower = coordinator.reserve_shared(budget::ResourceClass::metadata, bytes, bytes->size());
    ASSERT_TRUE(borrower);
    EXPECT_EQ(coordinator.snapshot().current, bytes->size());
    borrower.reset();
    first.reset();
    EXPECT_EQ(coordinator.snapshot().current, bytes->size());
    second.reset();
    EXPECT_EQ(coordinator.snapshot().current, 0U);
  }

  TEST(ProtocolV3ResourceBudget, AdoptedReservationCanBeBorrowedByAnotherClassWithoutDoubleCharge) {
    budget::ResourceBudgetCoordinator coordinator;
    auto bytes = std::make_shared<std::vector<std::uint8_t>>(128, 0x42);
    auto reservation = coordinator.reserve(budget::ResourceClass::cached_responses, 384);
    ASSERT_TRUE(reservation);
    auto owner = coordinator.adopt_shared(bytes, std::move(*reservation));
    ASSERT_TRUE(owner);
    auto borrower = coordinator.reserve_shared(budget::ResourceClass::critical, bytes, bytes->size());
    ASSERT_TRUE(borrower);
    EXPECT_EQ(coordinator.snapshot().current, 384U);
    owner.reset();
    EXPECT_EQ(coordinator.snapshot().current, 384U);
    borrower.reset();
    EXPECT_EQ(coordinator.snapshot().current, 0U);
  }

  TEST(ProtocolV3ResourceBudget, SixtyFourConnectionHostileReservationsNeverExceedHostOrClassCeilings) {
    budget::ResourceBudgetCoordinator coordinator;
    constexpr std::size_t request = 8U * budget::mib;
    constexpr std::size_t thread_count = 64;
    std::atomic_size_t ready {};
    std::atomic_size_t attempted {};
    std::atomic_size_t reserved {};
    std::atomic_bool start {};
    std::atomic_bool release {};
    std::vector<std::thread> threads;
    threads.reserve(thread_count);
    for (std::size_t index = 0; index < thread_count; ++index) {
      threads.emplace_back([&] {
        ready.fetch_add(1, std::memory_order_release);
        while (!start.load(std::memory_order_acquire)) {
          std::this_thread::yield();
        }
        auto lease = coordinator.reserve(budget::ResourceClass::media, request);
        attempted.fetch_add(1, std::memory_order_release);
        if (lease) {
          reserved.fetch_add(1, std::memory_order_release);
          while (!release.load(std::memory_order_acquire)) {
            std::this_thread::yield();
          }
        }
      });
    }
    while (ready.load(std::memory_order_acquire) != thread_count) {
      std::this_thread::yield();
    }
    start.store(true, std::memory_order_release);
    while (attempted.load(std::memory_order_acquire) != thread_count) {
      std::this_thread::yield();
    }
    const auto snapshot = coordinator.snapshot();
    EXPECT_EQ(snapshot.current, 400U * budget::mib);
    EXPECT_EQ(snapshot.classes[index(budget::ResourceClass::media)].current, 400U * budget::mib);
    EXPECT_LE(snapshot.high_water, budget::maximum_total_bytes);
    EXPECT_EQ(snapshot.refusals, thread_count - 50U);
    release.store(true, std::memory_order_release);
    for (auto &thread : threads) {
      thread.join();
    }
    EXPECT_EQ(coordinator.snapshot().current, 0U);
  }
}  // namespace
