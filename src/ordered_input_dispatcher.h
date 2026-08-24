/**
 * @file src/ordered_input_dispatcher.h
 * @brief Dedicated ordered dispatcher for latency-sensitive per-session input work.
 */
#pragma once

// standard includes
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <functional>
#include <list>
#include <mutex>
#include <thread>
#include <utility>

namespace input::detail {
  /**
   * @brief Single-consumer dispatcher with bounded packet backlog and cancellable timers.
   *
   * @tparam Item Packet or state object consumed in FIFO order.
   * @tparam Clock Monotonic clock used for packet age and delayed work.
   */
  template<class Item, class Clock = std::chrono::steady_clock>
  class ordered_input_dispatcher_t {
  public:
    using consumer_t = std::function<void(Item &&)>;  ///< Callback that injects one ordered packet.
    using coalescer_t = std::function<bool(Item &, Item &)>;  ///< Consecutive-packet coalescing policy.
    using droppable_t = std::function<bool(const Item &)>;  ///< Backpressure eligibility policy.
    using thread_setup_t = std::function<void()>;  ///< Consumer-thread initialization callback.
    using task_t = std::function<void()>;  ///< Ordered fence or delayed task callback.
    using failure_handler_t = std::function<void(std::exception_ptr)>;  ///< Fail-closed callback invoked once on the consumer thread.
    using task_id_t = std::uint64_t;  ///< Cancellable delayed-task identifier.
    using duration_t = typename Clock::duration;  ///< Dispatcher clock duration.

    /**
     * @brief Result of an enqueue operation.
     */
    enum class enqueue_result_e {
      queued,  ///< Work was added to the FIFO.
      coalesced,  ///< Work was merged into the consecutive tail packet.
      dropped,  ///< Droppable work was discarded under age or size pressure.
      closed  ///< The dispatcher no longer accepts work.
    };

    /**
     * @brief Dispatcher resource and latency bounds.
     */
    struct limits_t {
      std::size_t max_packets {256};  ///< Maximum ready packets and fences.
      std::size_t max_timers {64};  ///< Maximum delayed callbacks.
      duration_t max_droppable_age {std::chrono::milliseconds(4)};  ///< Maximum queued age for motion-like work.
    };

    /**
     * @brief Start a dedicated consumer thread.
     *
     * @param consumer Packet consumer invoked on the dedicated thread.
     * @param coalescer Policy that may merge only the ready FIFO tail.
     * @param droppable Policy identifying state-neutral work eligible for pressure drops.
     * @param thread_setup Initialization run once on the dedicated thread.
     * @param limits Queue, timer, and age bounds.
     * @param failure_handler Observable fail-closed callback for setup or work exceptions.
     * @param start_immediately Whether to start before returning from construction.
     */
    ordered_input_dispatcher_t(
      consumer_t consumer,
      coalescer_t coalescer,
      droppable_t droppable,
      thread_setup_t thread_setup = {},
      limits_t limits = {},
      failure_handler_t failure_handler = {},
      bool start_immediately = true
    ):
        consumer_ {std::move(consumer)},
        coalescer_ {std::move(coalescer)},
        droppable_ {std::move(droppable)},
        thread_setup_ {std::move(thread_setup)},
        limits_ {limits},
        failure_handler_ {std::move(failure_handler)} {
      if (start_immediately) {
        start();
      }
    }

    ordered_input_dispatcher_t(const ordered_input_dispatcher_t &) = delete;
    ordered_input_dispatcher_t &operator=(const ordered_input_dispatcher_t &) = delete;

    /**
     * @brief Cancel pending work and join the consumer thread.
     */
    ~ordered_input_dispatcher_t() {
      close(false);
    }

    /**
     * @brief Start the dedicated consumer after its owner has published this dispatcher.
     */
    void start() {
      std::lock_guard lock(mutex_);
      if (started_ || stopping_) {
        return;
      }
      worker_ = std::thread([this]() {
        run();
      });
      started_ = true;
    }

    /**
     * @brief Queue one packet while preserving all non-droppable FIFO edges.
     *
     * @param item Packet to queue or coalesce.
     * @return Queue disposition.
     */
    enqueue_result_e enqueue(Item item) {
      std::unique_lock lock(mutex_);
      if (!accepting_) {
        return enqueue_result_e::closed;
      }

      const auto now = Clock::now();
      discard_expired_locked(now);
      if (!ready_.empty() && ready_.back().has_item && coalescer_(ready_.back().item, item)) {
        return enqueue_result_e::coalesced;
      }

      while (ready_.size() >= limits_.max_packets) {
        const auto droppable = std::find_if(ready_.begin(), ready_.end(), [this](const ready_entry_t &entry) {
          return entry.supersedable || (entry.has_item && droppable_(entry.item));
        });
        if (droppable != ready_.end()) {
          ready_.erase(droppable);
          ++dropped_packets_;
          break;
        }
        if (droppable_(item)) {
          ++dropped_packets_;
          return enqueue_result_e::dropped;
        }

        space_cv_.wait(lock, [this]() {
          return !accepting_ || ready_.size() < limits_.max_packets;
        });
        if (!accepting_) {
          return enqueue_result_e::closed;
        }
      }

      ready_.push_back(ready_entry_t::packet(std::move(item), now));
      work_cv_.notify_one();
      return enqueue_result_e::queued;
    }

    /**
     * @brief Queue a non-droppable fence behind every packet already accepted.
     *
     * @param task Fence callback executed by the same consumer thread.
     * @return Queue disposition.
     */
    enqueue_result_e enqueue_fence(task_t task) {
      return enqueue_operation(std::move(task), false);
    }

    /**
     * @brief Queue ordered state work, optionally superseding a stale tail state.
     *
     * Supersedable work is pressure- and age-droppable and never waits for FIFO
     * space. Non-supersedable work preserves the same blocking FIFO semantics as
     * an input edge or fence.
     *
     * @param task Consumer-thread operation.
     * @param supersedable Whether a newer consecutive state may replace this work.
     * @return Queue disposition.
     */
    enqueue_result_e enqueue_operation(task_t task, bool supersedable) {
      std::unique_lock lock(mutex_);
      if (!accepting_) {
        return enqueue_result_e::closed;
      }

      const auto now = Clock::now();
      discard_expired_locked(now);
      if (supersedable && !ready_.empty() && ready_.back().supersedable) {
        ready_.back().task = std::move(task);
        return enqueue_result_e::coalesced;
      }

      while (accepting_ && ready_.size() >= limits_.max_packets) {
        const auto droppable = std::find_if(ready_.begin(), ready_.end(), [this](const ready_entry_t &entry) {
          return entry.supersedable || (entry.has_item && droppable_(entry.item));
        });
        if (droppable != ready_.end()) {
          ready_.erase(droppable);
          ++dropped_packets_;
          break;
        }
        if (supersedable) {
          ++dropped_packets_;
          return enqueue_result_e::dropped;
        }
        space_cv_.wait(lock);
      }
      if (!accepting_) {
        return enqueue_result_e::closed;
      }

      ready_.push_back(
        supersedable ? ready_entry_t::state(std::move(task), now) :
                      ready_entry_t::fence(std::move(task), now)
      );
      work_cv_.notify_one();
      return enqueue_result_e::queued;
    }

    /**
     * @brief Schedule a callback that will re-enter the same ordered consumer.
     *
     * @tparam Rep Delay representation.
     * @tparam Period Delay tick period.
     * @param task Callback to run.
     * @param delay Minimum delay before the callback becomes runnable.
     * @return Cancellable identifier, or zero when closed or timer-bounded.
     */
    template<class Rep, class Period>
    task_id_t schedule(task_t task, std::chrono::duration<Rep, Period> delay) {
      std::lock_guard lock(mutex_);
      if (!accepting_ || timers_.size() >= limits_.max_timers) {
        return 0;
      }

      const auto id = next_task_id_++;
      const timer_entry_t entry {Clock::now() + std::chrono::duration_cast<duration_t>(delay), id, std::move(task)};
      const auto position = std::find_if(timers_.begin(), timers_.end(), [&entry](const timer_entry_t &queued) {
        return queued.due_at > entry.due_at || (queued.due_at == entry.due_at && queued.id > entry.id);
      });
      timers_.insert(position, std::move(entry));
      work_cv_.notify_one();
      return id;
    }

    /**
     * @brief Cancel delayed work that has not started.
     *
     * @param id Identifier returned by schedule().
     * @return True when a pending timer was removed.
     */
    bool cancel(task_id_t id) {
      if (id == 0) {
        return false;
      }
      std::lock_guard lock(mutex_);
      const auto timer = std::find_if(timers_.begin(), timers_.end(), [id](const timer_entry_t &entry) {
        return entry.id == id;
      });
      if (timer == timers_.end()) {
        return false;
      }
      timers_.erase(timer);
      space_cv_.notify_all();
      return true;
    }

    /**
     * @brief Seal producers and timers without stopping the consumer before its reset fence.
     *
     * This wakes any producer blocked on a full non-droppable queue, allowing the control
     * stream to terminate before close_after_fence() requests final consumer shutdown.
     */
    void begin_close() {
      std::lock_guard lock(mutex_);
      accepting_ = false;
      timers_.clear();
      work_cv_.notify_all();
      space_cv_.notify_all();
    }

    /**
     * @brief Close the dispatcher and join its dedicated consumer.
     *
     * Delayed callbacks are cancelled in both modes. Drain mode finishes the ready FIFO,
     * including a previously queued reset fence; cancel mode discards it.
     *
     * @param drain_ready Whether to drain already-ready packets and fences.
     */
    void close(bool drain_ready) {
      {
        std::lock_guard lock(mutex_);
        if (!accepting_ && joined_) {
          return;
        }
        accepting_ = false;
        stopping_ = true;
        timers_.clear();
        terminal_fence_ = {};
        if (!drain_ready) {
          ready_.clear();
        }
        work_cv_.notify_all();
        space_cv_.notify_all();
      }
      if (worker_.get_id() == std::this_thread::get_id()) {
        return;
      }
      if (worker_.joinable()) {
        worker_.join();
      }
      std::lock_guard lock(mutex_);
      joined_ = true;
    }

    /**
     * @brief Atomically reject new producers, drain accepted packets, run a terminal fence, and join.
     *
     * The terminal fence has a reserved slot outside the bounded packet FIFO so teardown never
     * drops a state edge or races a packet accepted after neutralization.
     *
     * @param task Final neutralization callback.
     */
    void close_after_fence(task_t task) {
      {
        std::lock_guard lock(mutex_);
        if (!accepting_ && joined_) {
          return;
        }
        accepting_ = false;
        stopping_ = true;
        timers_.clear();
        terminal_fence_ = std::move(task);
        work_cv_.notify_all();
        space_cv_.notify_all();
      }
      if (worker_.get_id() == std::this_thread::get_id()) {
        return;
      }
      if (worker_.joinable()) {
        worker_.join();
      }
      std::lock_guard lock(mutex_);
      joined_ = true;
    }

    /**
     * @brief Wait until the ready FIFO and current callback are empty.
     */
    void flush_ready() {
      std::unique_lock lock(mutex_);
      idle_cv_.wait(lock, [this]() {
        return ready_.empty() && !active_;
      });
    }

    /**
     * @brief Return the number of pressure- or age-dropped packets.
     */
    std::size_t dropped_packets() const {
      std::lock_guard lock(mutex_);
      return dropped_packets_;
    }

    /**
     * @brief Return the number of callbacks that terminated with an exception.
     */
    std::size_t callback_failures() const {
      std::lock_guard lock(mutex_);
      return callback_failures_;
    }

    /**
     * @brief Check whether setup or work failed and closed the dispatcher.
     */
    bool failed() const {
      std::lock_guard lock(mutex_);
      return failed_;
    }

  private:
    using time_point_t = typename Clock::time_point;  ///< Dispatcher clock time point.

    /**
     * @brief Ready FIFO entry holding either a packet or a fence.
     */
    struct ready_entry_t {
      Item item {};  ///< Packet payload when has_item is true.
      task_t task {};  ///< Fence callback when has_item is false.
      time_point_t queued_at {};  ///< Enqueue timestamp used for motion age bounds.
      bool has_item {false};  ///< Distinguishes packet payloads from fence callbacks.
      bool supersedable {false};  ///< Whether newer state may replace or expire this entry.

      /**
       * @brief Construct a packet FIFO entry.
       */
      static ready_entry_t packet(Item item, time_point_t queued_at) {
        return ready_entry_t {std::move(item), {}, queued_at, true, false};
      }

      /**
       * @brief Construct a fence FIFO entry.
       */
      static ready_entry_t fence(task_t task, time_point_t queued_at) {
        return ready_entry_t {{}, std::move(task), queued_at, false, false};
      }

      /**
       * @brief Construct supersedable state work.
       */
      static ready_entry_t state(task_t task, time_point_t queued_at) {
        return ready_entry_t {{}, std::move(task), queued_at, false, true};
      }
    };

    /**
     * @brief Delayed callback ordered by due time and task identifier.
     */
    struct timer_entry_t {
      time_point_t due_at;  ///< Earliest runnable time.
      task_id_t id;  ///< Stable cancellation and tie-break identifier.
      task_t task;  ///< Callback executed on the consumer thread.
    };

    /**
     * @brief Discard only expired state-neutral packets or state operations.
     *
     * @param now Current dispatcher time.
     */
    void discard_expired_locked(time_point_t now) {
      const auto previous_size = ready_.size();
      std::erase_if(ready_, [this, now](const ready_entry_t &entry) {
        return (entry.supersedable || (entry.has_item && droppable_(entry.item))) &&
               now - entry.queued_at > limits_.max_droppable_age;
      });
      dropped_packets_ += previous_size - ready_.size();
    }

    /**
     * @brief Atomically fail closed, discard pending work, and invoke neutralization once.
     *
     * @param failure Captured setup or callback exception.
     */
    void fail_closed(std::exception_ptr failure) noexcept {
      {
        std::lock_guard lock(mutex_);
        if (failed_) {
          return;
        }
        failed_ = true;
        accepting_ = false;
        stopping_ = true;
        active_ = false;
        ++callback_failures_;
        ready_.clear();
        timers_.clear();
        terminal_fence_ = {};
        work_cv_.notify_all();
        space_cv_.notify_all();
        idle_cv_.notify_all();
      }
      if (failure_handler_) {
        try {
          failure_handler_(failure);
        } catch (...) {
          // A failure handler must not escape the dedicated thread boundary.
        }
      }
    }

    /**
     * @brief Run the dedicated FIFO and timer loop.
     */
    void run() {
      try {
        if (thread_setup_) {
          thread_setup_();
        }
      } catch (...) {
        fail_closed(std::current_exception());
        return;
      }

      while (true) {
        ready_entry_t ready;
        task_t timer_task;
        {
          std::unique_lock lock(mutex_);
          while (true) {
            const auto now = Clock::now();
            discard_expired_locked(now);
            if (!timers_.empty() && timers_.front().due_at <= now) {
              timer_task = std::move(timers_.front().task);
              timers_.pop_front();
              active_ = true;
              space_cv_.notify_all();
              break;
            }
            if (!ready_.empty()) {
              ready = std::move(ready_.front());
              ready_.pop_front();
              active_ = true;
              space_cv_.notify_all();
              break;
            }
            if (stopping_) {
              if (terminal_fence_) {
                timer_task = std::move(terminal_fence_);
                terminal_fence_ = {};
                active_ = true;
                break;
              }
              idle_cv_.notify_all();
              return;
            }
            if (!timers_.empty()) {
              work_cv_.wait_until(lock, timers_.front().due_at);
            } else {
              work_cv_.wait(lock);
            }
          }
        }

        try {
          if (timer_task) {
            timer_task();
          } else if (ready.has_item) {
            consumer_(std::move(ready.item));
          } else if (ready.task) {
            ready.task();
          }
        } catch (...) {
          fail_closed(std::current_exception());
          return;
        }

        {
          std::lock_guard lock(mutex_);
          active_ = false;
          if (ready_.empty()) {
            idle_cv_.notify_all();
          }
        }
      }
    }

    consumer_t consumer_;  ///< Packet injection callback.
    coalescer_t coalescer_;  ///< Consecutive-packet coalescing callback.
    droppable_t droppable_;  ///< State-neutral packet classification callback.
    thread_setup_t thread_setup_;  ///< Dedicated-thread setup callback.
    limits_t limits_;  ///< Queue, timer, and age limits.
    failure_handler_t failure_handler_;  ///< Observable production fail-closed callback.
    mutable std::mutex mutex_;  ///< Dispatcher state mutex.
    std::condition_variable work_cv_;  ///< New-work and timer wakeup condition.
    std::condition_variable space_cv_;  ///< Backpressure wakeup condition.
    std::condition_variable idle_cv_;  ///< Ready-FIFO drain condition.
    std::deque<ready_entry_t> ready_;  ///< Ordered packet and fence FIFO.
    std::list<timer_entry_t> timers_;  ///< Due-time ordered delayed callbacks.
    task_t terminal_fence_;  ///< Reserved teardown fence run after the ready FIFO drains.
    task_id_t next_task_id_ {1};  ///< Next nonzero timer identifier.
    std::size_t dropped_packets_ {0};  ///< Pressure- and age-drop count.
    std::size_t callback_failures_ {0};  ///< Callback exceptions contained at the thread boundary.
    bool accepting_ {true};  ///< Whether producers may add work.
    bool stopping_ {false};  ///< Whether the consumer may exit after draining ready work.
    bool active_ {false};  ///< Whether the consumer is inside a callback.
    bool joined_ {false};  ///< Whether the dedicated thread has joined.
    bool failed_ {false};  ///< Whether setup or callback execution failed closed.
    bool started_ {false};  ///< Whether the dedicated thread was created.
    std::thread worker_;  ///< Dedicated single consumer.
  };
}  // namespace input::detail
