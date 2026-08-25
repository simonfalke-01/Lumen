/**
 * @file src/protocol_v3/operation_outcomes.h
 * @brief Bounded, connection-independent replay store for v3 START and STOP outcomes.
 */

#pragma once

#include "control_session.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <memory>
#include <optional>
#include <vector>

namespace lumen::protocol_v3::operation_outcomes {
  using Identifier = control_session::Identifier;
  using Digest = control_session::Bytes32;
  using Clock = std::chrono::steady_clock;

  /** Semantic operation namespace. START intent IDs and STOP tokens may coincide. */
  enum class Operation : std::uint8_t {
    start,
    stop,
  };

  /** Durable outcome state. Active records are never time-evicted. */
  enum class State : std::uint8_t {
    active,
    terminal,
    expired,
  };

  /** Result of a lookup or claim attempt. */
  enum class Match : std::uint8_t {
    inserted,
    exact,
    conflict,
    missing,
    saturated,
  };

  /** Exact immutable replay payload retained for a terminal operation. */
  struct Replay {
    control_session::cbor::Value::Map fields;
    std::size_t encoded_bytes {};  ///< Exact already-encoded ULC3 payload byte count.
  };

  /** A copy-out result; it never exposes store-owned mutable state. */
  struct Lookup {
    Match match {Match::missing};
    State state {State::active};
    std::optional<Replay> replay;
  };

  /**
   * Thread-safe fixed-limit operation outcome store.
   *
   * A START claim reserves one additional future STOP slot for its client/session.
   * Reservations count toward the record limit, but not the encoded-replay-byte
   * limit. They are consumed by begin_stop() and released by end_session().
   */
  class Store final {
  public:
    static constexpr std::size_t maximum_records = 256;
    static constexpr std::size_t maximum_replay_bytes = 8U * 1024U * 1024U;
    static constexpr auto terminal_ttl = std::chrono::seconds {600};
    static constexpr std::size_t fixed_record_charge = 256;
    static constexpr std::size_t maximum_start_replay_reservation = 1U * 1024U * 1024U - fixed_record_charge;
    static constexpr std::size_t maximum_stop_replay_reservation = 64U * 1024U;

    explicit Store(
      std::shared_ptr<resource_budget::ResourceBudgetCoordinator> resource_budget =
        std::make_shared<resource_budget::ResourceBudgetCoordinator>()
    );

    /** Claim a START intent and reserve its matching future STOP capacity. */
    Lookup begin_start(
      const Identifier &client,
      const Identifier &intent,
      const Digest &digest,
      const Identifier &session,
      Clock::time_point now,
      std::size_t reserved_replay_bytes = maximum_start_replay_reservation
    );

    /** Claim a STOP token; a matching START reservation is consumed when present. */
    Lookup begin_stop(
      const Identifier &client,
      const Identifier &token,
      const Digest &digest,
      const Identifier &session,
      Clock::time_point now
    );

    /** @brief Bind the session selected after a pre-side-effect START claim. */
    bool bind_start_session(
      const Identifier &client,
      const Identifier &intent,
      const Digest &digest,
      const Identifier &session
    );

    /** Look up an outcome independent of connection authority. */
    Lookup lookup(
      Operation operation,
      const Identifier &client,
      const Identifier &intent_or_token,
      const Digest &digest,
      Clock::time_point now
    );

    /** Commit an exact terminal replay. Saturation leaves the active record unchanged. */
    bool complete(
      Operation operation,
      const Identifier &client,
      const Identifier &intent_or_token,
      const Digest &digest,
      Replay replay,
      Clock::time_point now
    );

    /** @brief Publish a successful START replay while keeping the record active/non-evictable. */
    bool publish_active(
      Operation operation,
      const Identifier &client,
      const Identifier &intent_or_token,
      const Digest &digest,
      Replay replay
    );

    /** Terminalize every active record belonging to a completed/failed session. */
    void end_session(const Identifier &session, Clock::time_point now);

    [[nodiscard]] std::size_t size() const noexcept;
    [[nodiscard]] std::size_t reserved_stop_slots() const noexcept;
    [[nodiscard]] std::size_t replay_bytes() const noexcept;

  private:
    struct Key {
      Operation operation {};
      Identifier client {};
      Identifier semantic_id {};
    };

    struct Entry {
      Key key;
      Digest digest {};
      Identifier session {};
      State state {State::active};
      std::optional<Replay> replay;
      resource_budget::ResourceBudgetCoordinator::Lease budget;
      Clock::time_point terminal_at {};
      std::uint64_t ordinal {};
    };

    struct Reservation {
      Identifier client {};
      Identifier start_intent {};
      Identifier session {};
      resource_budget::ResourceBudgetCoordinator::Lease budget;
      std::uint64_t ordinal {};
    };

    static bool equal(const Identifier &left, const Identifier &right) noexcept;
    static bool equal(const Digest &left, const Digest &right) noexcept;
    static bool equal(const Key &left, const Key &right) noexcept;
    static bool zero(const Identifier &value) noexcept;

    Lookup begin(
      Operation operation,
      const Identifier &client,
      const Identifier &semantic_id,
      const Digest &digest,
      const Identifier &session,
      bool reserve_stop,
      std::size_t reserved_replay_bytes,
      Clock::time_point now
    );
    void expire_terminals_locked(Clock::time_point now);
    bool make_room_locked(std::size_t required_slots, Clock::time_point now);
    std::vector<Entry>::iterator find_locked(const Key &key);
    std::vector<Entry>::const_iterator find_locked(const Key &key) const;

    std::shared_ptr<resource_budget::ResourceBudgetCoordinator> budget_;
    mutable std::mutex mutex_;
    std::vector<Entry> entries_;
    std::vector<Reservation> reservations_;
    std::size_t replay_bytes_ {};
    std::uint64_t next_ordinal_ {1};
  };
}  // namespace lumen::protocol_v3::operation_outcomes
