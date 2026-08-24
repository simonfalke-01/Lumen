/**
 * @file tests/unit/test_ordered_input_dispatcher.cpp
 * @brief Unit tests for the per-session ordered input dispatcher.
 */

// standard includes
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>
#include <stdexcept>
#include <vector>

// lib includes
#include <gtest/gtest.h>

// local includes
#include "src/input_state.h"
#include "src/ordered_input_dispatcher.h"

using namespace std::literals;

namespace {
  /**
   * @brief Test item distinguishing pressure-droppable motion from ordered edges.
   */
  struct input_item_t {
    int value {};  ///< Observable dispatch value.
    bool motion {false};  ///< Whether the item is safe to coalesce or pressure-drop.
  };

  /**
   * @brief Manually advanced monotonic clock for deterministic age tests.
   */
  struct manual_clock_t {
    using rep = std::chrono::steady_clock::rep;  ///< Tick representation.
    using period = std::chrono::steady_clock::period;  ///< Tick period.
    using duration = std::chrono::steady_clock::duration;  ///< Clock duration.
    using time_point = std::chrono::time_point<manual_clock_t>;  ///< Clock time point.
    [[maybe_unused]] static constexpr bool is_steady = true;  ///< Manual clock never moves backward.

    /**
     * @brief Return the current manually controlled time.
     */
    static time_point now() noexcept {
      return time_point {duration {ticks.load()}};
    }

    static std::atomic<rep> ticks;  ///< Current test-controlled tick count.
  };

  std::atomic<manual_clock_t::rep> manual_clock_t::ticks {0};

  /**
   * @brief Synchronization gate that holds the dedicated consumer at a known item.
   */
  class consumer_gate_t {
  public:
    /**
     * @brief Block until release() is called and expose entry to the test thread.
     */
    void wait() {
      std::unique_lock lock(mutex_);
      entered_ = true;
      cv_.notify_all();
      cv_.wait(lock, [this]() {
        return released_;
      });
    }

    /**
     * @brief Wait until the consumer reaches the gate.
     */
    void wait_until_entered() {
      std::unique_lock lock(mutex_);
      cv_.wait(lock, [this]() {
        return entered_;
      });
    }

    /**
     * @brief Release the blocked consumer.
     */
    void release() {
      std::lock_guard lock(mutex_);
      released_ = true;
      cv_.notify_all();
    }

  private:
    std::mutex mutex_;  ///< Gate state mutex.
    std::condition_variable cv_;  ///< Gate entry and release condition.
    bool entered_ {false};  ///< Whether the consumer reached the gate.
    bool released_ {false};  ///< Whether the test released the consumer.
  };

  /**
   * @brief Merge consecutive motion values for dispatcher-policy tests.
   */
  bool coalesce_motion(input_item_t &destination, input_item_t &source) {
    if (!destination.motion || !source.motion) {
      return false;
    }
    destination.value += source.value;
    return true;
  }

  /**
   * @brief Identify motion as the only pressure-droppable test work.
   */
  bool is_motion(const input_item_t &item) {
    return item.motion;
  }

  /**
   * @brief Legacy pointer packet model for move-to-click causality tests.
   */
  struct pointer_packet_t {
    /**
     * @brief Packet role in the ordered pointer stream.
     */
    enum class kind_e {
      barrier,  ///< Test-only blocked active callback.
      relative,  ///< Relative pointer motion.
      absolute,  ///< Absolute pointer position.
      button  ///< Dependent button edge.
    };

    kind_e kind {kind_e::barrier};  ///< Packet role.
    int value {0};  ///< Delta, absolute position, or button marker.
  };

  /**
   * @brief Coalesce only consecutive compatible legacy pointer motion.
   */
  bool coalesce_pointer(pointer_packet_t &destination, pointer_packet_t &source) {
    if (destination.kind != source.kind) {
      return false;
    }
    if (destination.kind == pointer_packet_t::kind_e::relative) {
      destination.value += source.value;
      return true;
    }
    if (destination.kind == pointer_packet_t::kind_e::absolute) {
      destination.value = source.value;
      return true;
    }
    return false;
  }

  /**
   * @brief Preserve legacy pointer motion because a later edge may depend on its target.
   */
  bool preserve_pointer(const pointer_packet_t &) {
    return false;
  }
}  // namespace

TEST(OrderedInputDispatcher, PreservesPacketAndFenceOrder) {
  using dispatcher_t = input::detail::ordered_input_dispatcher_t<input_item_t>;
  std::vector<int> observed;
  dispatcher_t dispatcher {
    [&observed](input_item_t &&item) {
      observed.push_back(item.value);
    },
    coalesce_motion,
    is_motion,
    {},
    {.max_packets = 8, .max_timers = 4, .max_droppable_age = 1h}
  };

  EXPECT_EQ(dispatcher.enqueue({1, false}), dispatcher_t::enqueue_result_e::queued);
  EXPECT_EQ(dispatcher.enqueue({2, false}), dispatcher_t::enqueue_result_e::queued);
  EXPECT_EQ(dispatcher.enqueue_fence([&observed]() {
    observed.push_back(3);
  }),
            dispatcher_t::enqueue_result_e::queued);
  EXPECT_EQ(dispatcher.enqueue({4, false}), dispatcher_t::enqueue_result_e::queued);
  dispatcher.close(true);

  EXPECT_EQ(observed, (std::vector<int> {1, 2, 3, 4}));
}

TEST(OrderedInputDispatcher, SupersedesStateWithoutAdvancingCausalityBeforeInjection) {
  using dispatcher_t = input::detail::ordered_input_dispatcher_t<input_item_t>;
  consumer_gate_t gate;
  input::detail::causal_watermark_t watermark;
  std::vector<int> injected;
  dispatcher_t dispatcher {
    [&gate](input_item_t &&item) {
      if (item.value == 100) {
        gate.wait();
      }
    },
    coalesce_motion,
    is_motion,
    {},
    {.max_packets = 2, .max_timers = 4, .max_droppable_age = 1h}
  };

  dispatcher.enqueue({100, false});
  gate.wait_until_entered();
  for (std::uint64_t sequence = 1; sequence <= 512; ++sequence) {
    ASSERT_TRUE(watermark.reserve(sequence, 0));
    const auto result = dispatcher.enqueue_operation(
      [&injected, &watermark, sequence]() {
        injected.push_back(static_cast<int>(sequence));
        EXPECT_TRUE(watermark.mark_applied(sequence, 0));
      },
      true
    );
    EXPECT_EQ(
      result,
      sequence == 1 ? dispatcher_t::enqueue_result_e::queued : dispatcher_t::enqueue_result_e::coalesced
    );
  }
  EXPECT_EQ(watermark.capture(), (input::detail::causal_watermark_value_t {}));

  gate.release();
  dispatcher.close(true);

  EXPECT_EQ(injected, (std::vector<int> {512}));
  EXPECT_EQ(watermark.capture(), (input::detail::causal_watermark_value_t {512, 0}));
}

TEST(OrderedInputDispatcher, PreservesEveryEdgeBetweenSupersedableStates) {
  using dispatcher_t = input::detail::ordered_input_dispatcher_t<input_item_t>;
  consumer_gate_t gate;
  std::vector<int> observed;
  dispatcher_t dispatcher {
    [&gate](input_item_t &&item) {
      if (item.value == 100) {
        gate.wait();
      }
    },
    coalesce_motion,
    is_motion,
    {},
    {.max_packets = 8, .max_timers = 4, .max_droppable_age = 1h}
  };

  dispatcher.enqueue({100, false});
  gate.wait_until_entered();
  dispatcher.enqueue_operation([&observed]() {
    observed.push_back(1);
  }, true);
  dispatcher.enqueue_operation([&observed]() {
    observed.push_back(2);
  }, true);
  dispatcher.enqueue_operation([&observed]() {
    observed.push_back(10);
  }, false);
  dispatcher.enqueue_operation([&observed]() {
    observed.push_back(3);
  }, true);
  dispatcher.enqueue_operation([&observed]() {
    observed.push_back(4);
  }, true);
  dispatcher.enqueue_operation([&observed]() {
    observed.push_back(20);
  }, false);

  gate.release();
  dispatcher.close(true);

  EXPECT_EQ(observed, (std::vector<int> {2, 10, 4, 20}));
}

TEST(OrderedInputDispatcher, EdgePressureEvictsStateButNeverAnEdge) {
  using dispatcher_t = input::detail::ordered_input_dispatcher_t<input_item_t>;
  consumer_gate_t gate;
  std::vector<int> observed;
  dispatcher_t dispatcher {
    [&gate](input_item_t &&item) {
      if (item.value == 100) {
        gate.wait();
      }
    },
    coalesce_motion,
    is_motion,
    {},
    {.max_packets = 2, .max_timers = 4, .max_droppable_age = 1h}
  };

  dispatcher.enqueue({100, false});
  gate.wait_until_entered();
  dispatcher.enqueue_operation([&observed]() {
    observed.push_back(1);
  }, true);
  dispatcher.enqueue_operation([&observed]() {
    observed.push_back(10);
  }, false);
  const auto edge_result = dispatcher.enqueue_operation([&observed]() {
    observed.push_back(20);
  }, false);
  EXPECT_EQ(edge_result, dispatcher_t::enqueue_result_e::queued);

  gate.release();
  dispatcher.close(true);

  EXPECT_EQ(observed, (std::vector<int> {10, 20}));
  EXPECT_EQ(dispatcher.dropped_packets(), 1u);
}

TEST(OrderedInputDispatcher, DropsStateInsteadOfBlockingBehindFullEdgeBacklog) {
  using dispatcher_t = input::detail::ordered_input_dispatcher_t<input_item_t>;
  consumer_gate_t gate;
  bool state_injected = false;
  dispatcher_t dispatcher {
    [&gate](input_item_t &&item) {
      if (item.value == 100) {
        gate.wait();
      }
    },
    coalesce_motion,
    is_motion,
    {},
    {.max_packets = 1, .max_timers = 4, .max_droppable_age = 1h}
  };

  dispatcher.enqueue({100, false});
  gate.wait_until_entered();
  ASSERT_EQ(dispatcher.enqueue_operation([]() {}, false), dispatcher_t::enqueue_result_e::queued);
  const auto state_result = dispatcher.enqueue_operation([&state_injected]() {
    state_injected = true;
  }, true);
  EXPECT_EQ(state_result, dispatcher_t::enqueue_result_e::dropped);

  gate.release();
  dispatcher.close(true);

  EXPECT_FALSE(state_injected);
  EXPECT_EQ(dispatcher.dropped_packets(), 1u);
}

TEST(OrderedInputDispatcher, ExpiresStateWithoutRunningItsCausalCompletion) {
  using dispatcher_t = input::detail::ordered_input_dispatcher_t<input_item_t, manual_clock_t>;
  manual_clock_t::ticks = 0;
  consumer_gate_t gate;
  input::detail::causal_watermark_t watermark;
  dispatcher_t dispatcher {
    [&gate](input_item_t &&item) {
      if (item.value == 100) {
        gate.wait();
      }
    },
    coalesce_motion,
    is_motion,
    {},
    {.max_packets = 4, .max_timers = 4, .max_droppable_age = 4ms}
  };

  dispatcher.enqueue({100, false});
  gate.wait_until_entered();
  ASSERT_TRUE(watermark.reserve(1, 0));
  dispatcher.enqueue_operation([&watermark]() {
    EXPECT_TRUE(watermark.mark_applied(1, 0));
  }, true);
  manual_clock_t::ticks = std::chrono::duration_cast<manual_clock_t::duration>(3ms).count();
  ASSERT_TRUE(watermark.reserve(2, 0));
  const auto replacement_result = dispatcher.enqueue_operation([&watermark]() {
    EXPECT_TRUE(watermark.mark_applied(2, 0));
  }, true);
  EXPECT_EQ(replacement_result, dispatcher_t::enqueue_result_e::coalesced);
  manual_clock_t::ticks = std::chrono::duration_cast<manual_clock_t::duration>(5ms).count();
  dispatcher.enqueue_operation([]() {}, false);

  gate.release();
  dispatcher.close(true);

  EXPECT_EQ(watermark.capture(), (input::detail::causal_watermark_value_t {}));
  EXPECT_EQ(dispatcher.dropped_packets(), 1u);
}

TEST(OrderedInputDispatcher, CoalescesOnlyConsecutiveMotion) {
  using dispatcher_t = input::detail::ordered_input_dispatcher_t<input_item_t>;
  consumer_gate_t gate;
  std::vector<int> observed;
  dispatcher_t dispatcher {
    [&gate, &observed](input_item_t &&item) {
      if (item.value == 100) {
        gate.wait();
      }
      observed.push_back(item.value);
    },
    coalesce_motion,
    is_motion,
    {},
    {.max_packets = 8, .max_timers = 4, .max_droppable_age = 1h}
  };

  dispatcher.enqueue({100, false});
  gate.wait_until_entered();
  EXPECT_EQ(dispatcher.enqueue({1, true}), dispatcher_t::enqueue_result_e::queued);
  EXPECT_EQ(dispatcher.enqueue({2, true}), dispatcher_t::enqueue_result_e::coalesced);
  EXPECT_EQ(dispatcher.enqueue({10, false}), dispatcher_t::enqueue_result_e::queued);
  EXPECT_EQ(dispatcher.enqueue({4, true}), dispatcher_t::enqueue_result_e::queued);
  EXPECT_EQ(dispatcher.enqueue({5, true}), dispatcher_t::enqueue_result_e::coalesced);
  gate.release();
  dispatcher.close(true);

  EXPECT_EQ(observed, (std::vector<int> {100, 3, 10, 9}));
}

TEST(OrderedInputDispatcher, BackpressureDropsMotionAndPreservesReleaseEdge) {
  using dispatcher_t = input::detail::ordered_input_dispatcher_t<input_item_t>;
  consumer_gate_t gate;
  std::vector<int> observed;
  dispatcher_t dispatcher {
    [&gate, &observed](input_item_t &&item) {
      if (item.value == 100) {
        gate.wait();
      }
      observed.push_back(item.value);
    },
    coalesce_motion,
    is_motion,
    {},
    {.max_packets = 3, .max_timers = 4, .max_droppable_age = 1h}
  };

  dispatcher.enqueue({100, false});
  gate.wait_until_entered();
  dispatcher.enqueue({1, true});
  dispatcher.enqueue({2, false});  // button/key down edge
  dispatcher.enqueue({3, true});
  EXPECT_EQ(dispatcher.enqueue({4, false}), dispatcher_t::enqueue_result_e::queued);  // release edge
  gate.release();
  dispatcher.close(true);

  EXPECT_EQ(observed, (std::vector<int> {100, 2, 3, 4}));
  EXPECT_EQ(dispatcher.dropped_packets(), 1u);
}

TEST(OrderedInputDispatcher, BackpressureWaitsRatherThanDroppingReleaseEdge) {
  using dispatcher_t = input::detail::ordered_input_dispatcher_t<input_item_t>;
  consumer_gate_t gate;
  std::vector<int> observed;
  dispatcher_t dispatcher {
    [&gate, &observed](input_item_t &&item) {
      if (item.value == 100) {
        gate.wait();
      }
      observed.push_back(item.value);
    },
    coalesce_motion,
    is_motion,
    {},
    {.max_packets = 1, .max_timers = 4, .max_droppable_age = 1h}
  };

  dispatcher.enqueue({100, false});
  gate.wait_until_entered();
  dispatcher.enqueue({1, false});  // key/button down edge fills the FIFO
  auto release_enqueue = std::async(std::launch::async, [&dispatcher]() {
    return dispatcher.enqueue({2, false});  // corresponding release edge
  });
  EXPECT_EQ(release_enqueue.wait_for(10ms), std::future_status::timeout);
  gate.release();
  EXPECT_EQ(release_enqueue.get(), dispatcher_t::enqueue_result_e::queued);
  dispatcher.close(true);

  EXPECT_EQ(observed, (std::vector<int> {100, 1, 2}));
  EXPECT_EQ(dispatcher.dropped_packets(), 0u);
}

TEST(OrderedInputDispatcher, BeginCloseWakesBlockedProducerBeforeResetJoin) {
  using dispatcher_t = input::detail::ordered_input_dispatcher_t<input_item_t>;
  consumer_gate_t gate;
  std::vector<int> observed;
  int neutralizations = 0;
  dispatcher_t dispatcher {
    [&gate, &observed](input_item_t &&item) {
      if (item.value == 100) {
        gate.wait();
      }
      observed.push_back(item.value);
    },
    coalesce_motion,
    [](const input_item_t &) {
      return false;
    },
    {},
    {.max_packets = 1, .max_timers = 4, .max_droppable_age = 1h}
  };

  dispatcher.enqueue({100, false});
  gate.wait_until_entered();
  dispatcher.enqueue({1, false});
  auto blocked_release = std::async(std::launch::async, [&dispatcher]() {
    return dispatcher.enqueue({2, false});
  });
  ASSERT_EQ(blocked_release.wait_for(10ms), std::future_status::timeout);

  dispatcher.begin_close();
  EXPECT_EQ(blocked_release.get(), dispatcher_t::enqueue_result_e::closed);
  gate.release();
  dispatcher.close_after_fence([&neutralizations]() {
    ++neutralizations;
  });

  EXPECT_EQ(observed, (std::vector<int> {100, 1}));
  EXPECT_EQ(neutralizations, 1);
}

TEST(OrderedInputDispatcher, CancelCloseDiscardsPendingWorkWithoutReorderingActiveWork) {
  using dispatcher_t = input::detail::ordered_input_dispatcher_t<input_item_t>;
  consumer_gate_t gate;
  std::vector<int> observed;
  dispatcher_t dispatcher {
    [&gate, &observed](input_item_t &&item) {
      if (item.value == 100) {
        gate.wait();
      }
      observed.push_back(item.value);
    },
    coalesce_motion,
    is_motion,
    {},
    {.max_packets = 8, .max_timers = 4, .max_droppable_age = 1h}
  };

  dispatcher.enqueue({100, false});
  gate.wait_until_entered();
  dispatcher.enqueue({1, false});
  dispatcher.enqueue({2, false});
  auto closing = std::async(std::launch::async, [&dispatcher]() {
    dispatcher.close(false);
  });
  EXPECT_EQ(closing.wait_for(10ms), std::future_status::timeout);
  gate.release();
  closing.get();

  EXPECT_EQ(observed, (std::vector<int> {100}));
}

TEST(OrderedInputDispatcher, CallbackExceptionFailsClosedAndNeutralizesOnce) {
  using dispatcher_t = input::detail::ordered_input_dispatcher_t<input_item_t>;
  std::vector<int> observed;
  std::promise<void> failure_observed;
  auto failure_future = failure_observed.get_future();
  std::atomic<int> neutralizations {0};
  dispatcher_t dispatcher {
    [&observed](input_item_t &&item) {
      if (item.value == 1) {
        throw std::runtime_error("injected callback failure");
      }
      observed.push_back(item.value);
    },
    coalesce_motion,
    is_motion,
    {},
    {.max_packets = 8, .max_timers = 4, .max_droppable_age = 1h},
    [&failure_observed, &neutralizations](std::exception_ptr failure) {
      EXPECT_NE(failure, nullptr);
      ++neutralizations;
      failure_observed.set_value();
    }
  };

  dispatcher.enqueue({1, false});
  dispatcher.enqueue({2, false});
  ASSERT_EQ(failure_future.wait_for(1s), std::future_status::ready);
  dispatcher.close(false);
  dispatcher.close(false);

  EXPECT_TRUE(observed.empty());
  EXPECT_TRUE(dispatcher.failed());
  EXPECT_EQ(dispatcher.callback_failures(), 1u);
  EXPECT_EQ(neutralizations, 1);
  EXPECT_EQ(dispatcher.enqueue({3, false}), dispatcher_t::enqueue_result_e::closed);
}

TEST(OrderedInputDispatcher, ThreadSetupExceptionFailsClosedAndNeutralizesOnce) {
  using dispatcher_t = input::detail::ordered_input_dispatcher_t<input_item_t>;
  std::promise<void> failure_observed;
  auto failure_future = failure_observed.get_future();
  std::atomic<int> neutralizations {0};
  std::atomic<bool> owner_assigned {false};
  input::detail::input_session_reset_gate_t session_gate;
  const auto registration = session_gate.register_session();
  dispatcher_t dispatcher {
    [](input_item_t &&) {
    },
    coalesce_motion,
    is_motion,
    []() {
      throw std::runtime_error("injected setup failure");
    },
    {.max_packets = 8, .max_timers = 4, .max_droppable_age = 1h},
    [&failure_observed, &neutralizations, &owner_assigned, &session_gate, registration](std::exception_ptr failure) {
      EXPECT_NE(failure, nullptr);
      EXPECT_TRUE(owner_assigned);
      EXPECT_TRUE(session_gate.unregister_session(registration, [&neutralizations]() {
        ++neutralizations;
      }));
      failure_observed.set_value();
    },
    false
  };
  owner_assigned = true;
  dispatcher.start();

  ASSERT_EQ(failure_future.wait_for(1s), std::future_status::ready);
  dispatcher.close(false);
  dispatcher.close(false);

  EXPECT_TRUE(dispatcher.failed());
  EXPECT_EQ(dispatcher.callback_failures(), 1u);
  EXPECT_EQ(neutralizations, 1);
  EXPECT_EQ(session_gate.active_sessions(), 0u);
  EXPECT_EQ(dispatcher.enqueue({1, false}), dispatcher_t::enqueue_result_e::closed);
}

TEST(OrderedInputDispatcher, ConsumerThreadCloseDefersJoinWithoutDeadlock) {
  using dispatcher_t = input::detail::ordered_input_dispatcher_t<input_item_t>;
  dispatcher_t *dispatcher_pointer = nullptr;
  std::promise<void> callback_returned;
  dispatcher_t dispatcher {
    [&dispatcher_pointer, &callback_returned](input_item_t &&) {
      dispatcher_pointer->close(false);
      callback_returned.set_value();
    },
    coalesce_motion,
    is_motion,
    {},
    {.max_packets = 8, .max_timers = 4, .max_droppable_age = 1h}
  };
  dispatcher_pointer = &dispatcher;

  dispatcher.enqueue({1, false});
  EXPECT_EQ(callback_returned.get_future().wait_for(1s), std::future_status::ready);
  dispatcher.close(false);
}

TEST(OrderedInputDispatcher, CancelledTimerCannotInjectAfterResetFence) {
  using dispatcher_t = input::detail::ordered_input_dispatcher_t<input_item_t>;
  bool timer_ran = false;
  bool fence_ran = false;
  dispatcher_t dispatcher {
    [](input_item_t &&) {
    },
    coalesce_motion,
    is_motion,
    {},
    {.max_packets = 8, .max_timers = 4, .max_droppable_age = 1h}
  };

  const auto timer = dispatcher.schedule([&timer_ran]() {
    timer_ran = true;
  },
                                         1h);
  ASSERT_NE(timer, 0u);
  EXPECT_TRUE(dispatcher.cancel(timer));
  dispatcher.close_after_fence([&fence_ran]() {
    fence_ran = true;
  });

  EXPECT_FALSE(timer_ran);
  EXPECT_TRUE(fence_ran);
  EXPECT_EQ(dispatcher.enqueue({1, false}), dispatcher_t::enqueue_result_e::closed);
}

TEST(OrderedInputDispatcher, DueTimerPreemptsContinuousPacketBacklog) {
  using dispatcher_t = input::detail::ordered_input_dispatcher_t<input_item_t>;
  consumer_gate_t gate;
  std::mutex observed_mutex;
  std::condition_variable observed_cv;
  std::vector<int> observed;
  bool timer_ran = false;
  dispatcher_t dispatcher {
    [&gate, &observed_mutex, &observed](input_item_t &&item) {
      if (item.value == 100) {
        gate.wait();
      }
      std::lock_guard lock(observed_mutex);
      observed.push_back(item.value);
    },
    coalesce_motion,
    is_motion,
    {},
    {.max_packets = 64, .max_timers = 4, .max_droppable_age = 1h}
  };

  dispatcher.enqueue({100, false});
  gate.wait_until_entered();
  for (int packet = 1; packet <= 32; ++packet) {
    dispatcher.enqueue({packet, false});
  }
  dispatcher.schedule([&observed_mutex, &observed_cv, &observed, &timer_ran]() {
    std::lock_guard lock(observed_mutex);
    observed.push_back(999);
    timer_ran = true;
    observed_cv.notify_all();
  },
                      0ms);
  gate.release();

  {
    std::unique_lock lock(observed_mutex);
    ASSERT_TRUE(observed_cv.wait_for(lock, 1s, [&timer_ran]() {
      return timer_ran;
    }));
  }
  dispatcher.close(true);

  ASSERT_GE(observed.size(), 2u);
  EXPECT_EQ(observed[0], 100);
  EXPECT_EQ(observed[1], 999);
}

TEST(OrderedInputDispatcher, CoalescingRetainsOldestAgeForGenericDroppableSample) {
  using dispatcher_t = input::detail::ordered_input_dispatcher_t<input_item_t, manual_clock_t>;
  manual_clock_t::ticks = 0;
  consumer_gate_t gate;
  std::vector<int> observed;
  dispatcher_t dispatcher {
    [&gate, &observed](input_item_t &&item) {
      if (item.value == 100) {
        gate.wait();
      }
      observed.push_back(item.value);
    },
    coalesce_motion,
    is_motion,
    {},
    {.max_packets = 8, .max_timers = 4, .max_droppable_age = 4ms}
  };

  dispatcher.enqueue({100, false});
  gate.wait_until_entered();
  dispatcher.enqueue({1, true});
  manual_clock_t::ticks = std::chrono::duration_cast<manual_clock_t::duration>(3ms).count();
  EXPECT_EQ(dispatcher.enqueue({2, true}), dispatcher_t::enqueue_result_e::coalesced);
  manual_clock_t::ticks = std::chrono::duration_cast<manual_clock_t::duration>(5ms).count();
  dispatcher.enqueue({9, false});
  gate.release();
  dispatcher.close(true);

  EXPECT_EQ(observed, (std::vector<int> {100, 9}));
  EXPECT_EQ(dispatcher.dropped_packets(), 1u);
}

TEST(OrderedInputDispatcher, RelativeMoveSurvivesAgeLimitBeforeDependentClick) {
  using dispatcher_t = input::detail::ordered_input_dispatcher_t<pointer_packet_t, manual_clock_t>;
  using kind_e = pointer_packet_t::kind_e;
  manual_clock_t::ticks = 0;
  consumer_gate_t gate;
  std::vector<pointer_packet_t> observed;
  dispatcher_t dispatcher {
    [&gate, &observed](pointer_packet_t &&packet) {
      if (packet.kind == kind_e::barrier) {
        gate.wait();
      }
      observed.push_back(packet);
    },
    coalesce_pointer,
    preserve_pointer,
    {},
    {.max_packets = 8, .max_timers = 4, .max_droppable_age = 4ms}
  };

  dispatcher.enqueue({kind_e::barrier, 0});
  gate.wait_until_entered();
  dispatcher.enqueue({kind_e::relative, 4});
  manual_clock_t::ticks = std::chrono::duration_cast<manual_clock_t::duration>(3ms).count();
  EXPECT_EQ(dispatcher.enqueue({kind_e::relative, 6}), dispatcher_t::enqueue_result_e::coalesced);
  manual_clock_t::ticks = std::chrono::duration_cast<manual_clock_t::duration>(8ms).count();
  dispatcher.enqueue({kind_e::button, 1});
  gate.release();
  dispatcher.close(true);

  ASSERT_EQ(observed.size(), 3u);
  EXPECT_EQ(observed[1].kind, kind_e::relative);
  EXPECT_EQ(observed[1].value, 10);
  EXPECT_EQ(observed[2].kind, kind_e::button);
  EXPECT_EQ(dispatcher.dropped_packets(), 0u);
}

TEST(OrderedInputDispatcher, AbsolutePositionSurvivesAgeLimitBeforeDependentClick) {
  using dispatcher_t = input::detail::ordered_input_dispatcher_t<pointer_packet_t, manual_clock_t>;
  using kind_e = pointer_packet_t::kind_e;
  manual_clock_t::ticks = 0;
  consumer_gate_t gate;
  std::vector<pointer_packet_t> observed;
  dispatcher_t dispatcher {
    [&gate, &observed](pointer_packet_t &&packet) {
      if (packet.kind == kind_e::barrier) {
        gate.wait();
      }
      observed.push_back(packet);
    },
    coalesce_pointer,
    preserve_pointer,
    {},
    {.max_packets = 8, .max_timers = 4, .max_droppable_age = 4ms}
  };

  dispatcher.enqueue({kind_e::barrier, 0});
  gate.wait_until_entered();
  dispatcher.enqueue({kind_e::absolute, 20});
  manual_clock_t::ticks = std::chrono::duration_cast<manual_clock_t::duration>(3ms).count();
  EXPECT_EQ(dispatcher.enqueue({kind_e::absolute, 45}), dispatcher_t::enqueue_result_e::coalesced);
  manual_clock_t::ticks = std::chrono::duration_cast<manual_clock_t::duration>(8ms).count();
  dispatcher.enqueue({kind_e::button, 1});
  gate.release();
  dispatcher.close(true);

  ASSERT_EQ(observed.size(), 3u);
  EXPECT_EQ(observed[1].kind, kind_e::absolute);
  EXPECT_EQ(observed[1].value, 45);
  EXPECT_EQ(observed[2].kind, kind_e::button);
  EXPECT_EQ(dispatcher.dropped_packets(), 0u);
}
