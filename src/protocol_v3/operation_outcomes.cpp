#include "operation_outcomes.h"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace lumen::protocol_v3::operation_outcomes {
  Store::Store(std::shared_ptr<resource_budget::ResourceBudgetCoordinator> resource_budget):
      budget_ {std::move(resource_budget)} {
    if (!budget_) {
      throw std::invalid_argument {"v3 operation outcome resource budget"};
    }
    entries_.reserve(maximum_records);
    reservations_.reserve(maximum_records);
  }

  bool Store::equal(const Identifier &left, const Identifier &right) noexcept {
    return left == right;
  }

  bool Store::equal(const Digest &left, const Digest &right) noexcept {
    return left == right;
  }

  bool Store::equal(const Key &left, const Key &right) noexcept {
    return left.operation == right.operation && equal(left.client, right.client) &&
           equal(left.semantic_id, right.semantic_id);
  }

  bool Store::zero(const Identifier &value) noexcept {
    return std::ranges::all_of(value, [](const std::uint8_t byte) { return byte == 0; });
  }

  std::vector<Store::Entry>::iterator Store::find_locked(const Key &key) {
    return std::find_if(entries_.begin(), entries_.end(), [&](const Entry &entry) {
      return equal(entry.key, key);
    });
  }

  std::vector<Store::Entry>::const_iterator Store::find_locked(const Key &key) const {
    return std::find_if(entries_.cbegin(), entries_.cend(), [&](const Entry &entry) {
      return equal(entry.key, key);
    });
  }

  void Store::expire_terminals_locked(const Clock::time_point now) {
    for (auto it = entries_.begin(); it != entries_.end();) {
      if (it->state != State::active && now - it->terminal_at >= terminal_ttl) {
        replay_bytes_ -= it->replay ? it->replay->encoded_bytes : 0;
        it = entries_.erase(it);
      } else {
        ++it;
      }
    }
  }

  bool Store::make_room_locked(const std::size_t required_slots, const Clock::time_point now) {
    expire_terminals_locked(now);
    while (entries_.size() + reservations_.size() + required_slots > maximum_records) {
      const auto victim = std::min_element(
        entries_.begin(),
        entries_.end(),
        [](const Entry &left, const Entry &right) {
          const bool left_eligible = left.state != State::active;
          const bool right_eligible = right.state != State::active;
          if (left_eligible != right_eligible) {
            return left_eligible;
          }
          if (!left_eligible) {
            return false;
          }
          return left.terminal_at != right.terminal_at ? left.terminal_at < right.terminal_at :
                                                         left.ordinal < right.ordinal;
        }
      );
      if (victim == entries_.end() || victim->state == State::active) {
        return false;
      }
      replay_bytes_ -= victim->replay ? victim->replay->encoded_bytes : 0;
      entries_.erase(victim);
    }
    return true;
  }

  Lookup Store::begin(
    const Operation operation,
    const Identifier &client,
    const Identifier &semantic_id,
    const Digest &digest,
    const Identifier &session,
    const bool reserve_stop,
    const std::size_t reserved_replay_bytes,
    const Clock::time_point now
  ) {
    if (zero(client) || zero(semantic_id) || (operation == Operation::stop && zero(session))) {
      return {.match = Match::conflict};
    }
    std::lock_guard lock {mutex_};
    expire_terminals_locked(now);
    const Key key {.operation = operation, .client = client, .semantic_id = semantic_id};
    if (const auto found = find_locked(key); found != entries_.end()) {
      if (!equal(found->digest, digest)) {
        return {.match = Match::conflict, .state = found->state};
      }
      return {.match = Match::exact, .state = found->state, .replay = found->replay};
    }

    auto reservation = reservations_.end();
    if (operation == Operation::stop) {
      reservation = std::find_if(reservations_.begin(), reservations_.end(), [&](const Reservation &item) {
        return equal(item.client, client) && equal(item.session, session);
      });
    }
    const bool consumes_reservation = reservation != reservations_.end();
    const std::size_t required_slots = reserve_stop ? 2 : (consumes_reservation ? 0 : 1);
    if (!make_room_locked(required_slots, now)) {
      return {.match = Match::saturated};
    }
    const auto reserve_record = [&](const std::size_t replay_reservation) ->
      std::optional<resource_budget::ResourceBudgetCoordinator::Lease> {
      if (replay_reservation > maximum_replay_bytes ||
          replay_reservation > SIZE_MAX - fixed_record_charge) {
        return std::nullopt;
      }
      while (true) {
        if (auto lease = budget_->reserve(
              resource_budget::ResourceClass::operation_outcomes,
              fixed_record_charge + replay_reservation
            )) {
          return lease;
        }
        const auto victim = std::min_element(
          entries_.begin(),
          entries_.end(),
          [](const Entry &left, const Entry &right) {
            const bool left_eligible = left.state != State::active;
            const bool right_eligible = right.state != State::active;
            if (left_eligible != right_eligible) {
              return left_eligible;
            }
            if (!left_eligible) {
              return false;
            }
            return left.terminal_at != right.terminal_at ? left.terminal_at < right.terminal_at :
                                                           left.ordinal < right.ordinal;
          }
        );
        if (victim == entries_.end() || victim->state == State::active) {
          return std::nullopt;
        }
        replay_bytes_ -= victim->replay ? victim->replay->encoded_bytes : 0;
        entries_.erase(victim);
      }
    };
    auto entry_budget = consumes_reservation ?
                          std::optional {std::move(reservation->budget)} :
                          reserve_record(reserved_replay_bytes);
    if (!entry_budget) {
      return {.match = Match::saturated};
    }
    auto stop_budget = reserve_stop ? reserve_record(maximum_stop_replay_reservation) :
                                      std::optional<resource_budget::ResourceBudgetCoordinator::Lease> {};
    if (reserve_stop && !stop_budget) {
      return {.match = Match::saturated};
    }
    if (consumes_reservation) {
      reservations_.erase(reservation);
    }
    entries_.push_back({
      .key = key,
      .digest = digest,
      .session = session,
      .state = State::active,
      .replay = std::nullopt,
      .budget = std::move(*entry_budget),
      .terminal_at = {},
      .ordinal = next_ordinal_++,
    });
    if (reserve_stop) {
      reservations_.push_back({
        .client = client,
        .start_intent = semantic_id,
        .session = session,
        .budget = std::move(*stop_budget),
        .ordinal = next_ordinal_++,
      });
    }
    return {.match = Match::inserted, .state = State::active};
  }

  Lookup Store::begin_start(
    const Identifier &client,
    const Identifier &intent,
    const Digest &digest,
    const Identifier &session,
    const Clock::time_point now,
    const std::size_t reserved_replay_bytes
  ) {
    return begin(Operation::start, client, intent, digest, session, true, reserved_replay_bytes, now);
  }

  Lookup Store::begin_stop(
    const Identifier &client,
    const Identifier &token,
    const Digest &digest,
    const Identifier &session,
    const Clock::time_point now
  ) {
    return begin(Operation::stop, client, token, digest, session, false, 0, now);
  }

  bool Store::bind_start_session(
    const Identifier &client,
    const Identifier &intent,
    const Digest &digest,
    const Identifier &session
  ) {
    if (zero(session)) {
      return false;
    }
    std::lock_guard lock {mutex_};
    const Key key {.operation = Operation::start, .client = client, .semantic_id = intent};
    const auto found = find_locked(key);
    if (found == entries_.end() || found->state != State::active || !equal(found->digest, digest)) {
      return false;
    }
    found->session = session;
    const auto reservation = std::find_if(reservations_.begin(), reservations_.end(), [&](const Reservation &item) {
      return equal(item.client, client) && equal(item.start_intent, intent) && zero(item.session);
    });
    if (reservation == reservations_.end()) {
      return false;
    }
    reservation->session = session;
    return true;
  }

  Lookup Store::lookup(
    const Operation operation,
    const Identifier &client,
    const Identifier &intent_or_token,
    const Digest &digest,
    const Clock::time_point now
  ) {
    std::lock_guard lock {mutex_};
    expire_terminals_locked(now);
    const Key key {.operation = operation, .client = client, .semantic_id = intent_or_token};
    auto found = find_locked(key);
    if (found == entries_.end()) {
      return {.match = Match::missing};
    }
    if (!equal(found->digest, digest)) {
      return {.match = Match::conflict, .state = found->state};
    }
    return {.match = Match::exact, .state = found->state, .replay = found->replay};
  }

  bool Store::publish_active(
    const Operation operation,
    const Identifier &client,
    const Identifier &intent_or_token,
    const Digest &digest,
    Replay replay
  ) {
    if (replay.encoded_bytes > maximum_replay_bytes ||
        replay.encoded_bytes > SIZE_MAX - fixed_record_charge) {
      return false;
    }
    std::lock_guard lock {mutex_};
    const Key key {.operation = operation, .client = client, .semantic_id = intent_or_token};
    const auto found = find_locked(key);
    if (found == entries_.end() || found->state != State::active || !equal(found->digest, digest)) {
      return false;
    }
    const auto prior = found->replay ? found->replay->encoded_bytes : 0;
    if (replay.encoded_bytes > maximum_replay_bytes - (replay_bytes_ - std::min(replay_bytes_, prior)) ||
        !found->budget.resize(fixed_record_charge + replay.encoded_bytes)) {
      return false;
    }
    replay_bytes_ -= std::min(replay_bytes_, prior);
    replay_bytes_ += replay.encoded_bytes;
    found->replay = std::move(replay);
    return true;
  }

  bool Store::complete(
    const Operation operation,
    const Identifier &client,
    const Identifier &intent_or_token,
    const Digest &digest,
    Replay replay,
    const Clock::time_point now
  ) {
    if (replay.encoded_bytes > maximum_replay_bytes) {
      return false;
    }
    std::lock_guard lock {mutex_};
    expire_terminals_locked(now);
    const Key key {.operation = operation, .client = client, .semantic_id = intent_or_token};
    auto found = find_locked(key);
    if (found == entries_.end() || !equal(found->digest, digest)) {
      return false;
    }
    if (found->state != State::active) {
      return found->replay && found->replay->encoded_bytes == replay.encoded_bytes &&
             found->replay->fields == replay.fields;
    }
    if (replay.encoded_bytes > maximum_replay_bytes - replay_bytes_ ||
        replay.encoded_bytes > SIZE_MAX - fixed_record_charge) {
      return false;
    }
    while (!found->budget.resize(fixed_record_charge + replay.encoded_bytes)) {
      const auto victim = std::min_element(
        entries_.begin(),
        entries_.end(),
        [&](const Entry &left, const Entry &right) {
          if (&left == &*found) {
            return false;
          }
          if (&right == &*found) {
            return true;
          }
          const bool left_eligible = left.state != State::active;
          const bool right_eligible = right.state != State::active;
          if (left_eligible != right_eligible) {
            return left_eligible;
          }
          if (!left_eligible) {
            return false;
          }
          return left.terminal_at != right.terminal_at ? left.terminal_at < right.terminal_at :
                                                         left.ordinal < right.ordinal;
        }
      );
      if (victim == entries_.end() || victim == found || victim->state == State::active) {
        return false;
      }
      replay_bytes_ -= victim->replay ? victim->replay->encoded_bytes : 0;
      entries_.erase(victim);
      found = find_locked(key);
      if (found == entries_.end()) {
        return false;
      }
    }
    found->state = State::terminal;
    found->terminal_at = now;
    replay_bytes_ += replay.encoded_bytes;
    found->replay = std::move(replay);
    if (operation == Operation::start) {
      std::erase_if(reservations_, [&](const Reservation &item) {
        return equal(item.client, client) && equal(item.start_intent, intent_or_token);
      });
    }
    return true;
  }

  void Store::end_session(const Identifier &session, const Clock::time_point now) {
    std::lock_guard lock {mutex_};
    for (auto &entry : entries_) {
      if (entry.state == State::active && equal(entry.session, session)) {
        entry.state = State::expired;
        entry.terminal_at = now;
      }
    }
    std::erase_if(reservations_, [&](const Reservation &item) { return equal(item.session, session); });
    expire_terminals_locked(now);
  }

  std::size_t Store::size() const noexcept {
    std::lock_guard lock {mutex_};
    return entries_.size();
  }

  std::size_t Store::reserved_stop_slots() const noexcept {
    std::lock_guard lock {mutex_};
    return reservations_.size();
  }

  std::size_t Store::replay_bytes() const noexcept {
    std::lock_guard lock {mutex_};
    return replay_bytes_;
  }
}  // namespace lumen::protocol_v3::operation_outcomes
