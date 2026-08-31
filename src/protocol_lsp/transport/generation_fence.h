/**
 * @file src/protocol_lsp/transport/generation_fence.h
 * @brief Fresh-association reconnect and rekey authority fence.
 */

#pragma once

#include <cstdint>

namespace lumen::lsp::transport {
  /** @brief Fresh DTLS association transfer lifecycle. */
  enum class generation_fence_phase : std::uint8_t {
    uninitialized,  ///< No authoritative association is installed.
    authoritative,  ///< Active connection and input generations accept packets.
    candidate_handshake,  ///< Fresh DTLS association exists but is not fully authenticated.
    candidate_authenticated,  ///< Fresh association is authenticated but old input remains authoritative.
    old_input_neutralized,  ///< Held old input is released and authority may transfer through ATTACH.
  };

  /** @brief Typed reconnect/rekey generation-fence transition result. */
  enum class generation_fence_result : std::uint8_t {
    accepted,  ///< Transition completed successfully.
    invalid_generation,  ///< A generation is zero, non-increasing, or would wrap.
    wrong_phase,  ///< Operation violates fresh-association transfer ordering.
    candidate_mismatch,  ///< Authentication completion names a different candidate generation.
    input_not_neutralized,  ///< Authority transfer was attempted before old held input was released.
  };

  /** @brief Snapshot of active and candidate connection/input authority generations. */
  struct generation_fence_snapshot {
    generation_fence_phase phase = generation_fence_phase::uninitialized;  ///< Current authority-transfer phase.
    std::uint32_t active_connection_generation = 0;  ///< Currently authoritative connection generation.
    std::uint32_t active_input_generation = 0;  ///< Currently authoritative input generation.
    std::uint32_t candidate_connection_generation = 0;  ///< Fresh association generation before ATTACH commit.
    bool old_input_neutralized = false;  ///< Whether held old input was atomically released.
    bool baseline_required = false;  ///< Whether canceled transfer requires a fresh old-association baseline.
  };

  /**
   * @brief Fail-closed generation fence for fresh-DTLS reconnect and planned rekey.
   *
   * The old association remains authoritative while the candidate handshakes and authenticates.
   * Input authority transfers only after explicit neutralization and an authenticated ATTACH commit.
   * Once committed, packets from every older connection or input generation are rejected.
   */
  class reconnect_generation_fence {
  public:
    /**
     * @brief Install the first authenticated association and input authority.
     *
     * @param connection_generation Nonzero initial connection generation.
     * @param input_generation Nonzero initial input authority generation.
     * @return Typed transition result.
     */
    constexpr generation_fence_result initialize(
      const std::uint32_t connection_generation,
      const std::uint32_t input_generation
    ) noexcept {
      if (phase_ != generation_fence_phase::uninitialized) {
        return generation_fence_result::wrong_phase;
      }
      if (connection_generation == 0 || input_generation == 0) {
        return generation_fence_result::invalid_generation;
      }
      active_connection_generation_ = connection_generation;
      active_input_generation_ = input_generation;
      baseline_required_ = false;
      phase_ = generation_fence_phase::authoritative;
      return generation_fence_result::accepted;
    }

    /**
     * @brief Begin a fresh DTLS association for reconnect or planned rekey.
     *
     * @param candidate_connection_generation Strictly newer nonzero connection generation.
     * @return Typed transition result.
     */
    constexpr generation_fence_result begin_fresh_association(
      const std::uint32_t candidate_connection_generation
    ) noexcept {
      if (phase_ != generation_fence_phase::authoritative) {
        return generation_fence_result::wrong_phase;
      }
      if (candidate_connection_generation == 0 ||
          active_connection_generation_ == UINT32_MAX ||
          candidate_connection_generation <= active_connection_generation_) {
        return generation_fence_result::invalid_generation;
      }
      candidate_connection_generation_ = candidate_connection_generation;
      old_input_neutralized_ = false;
      phase_ = generation_fence_phase::candidate_handshake;
      return generation_fence_result::accepted;
    }

    /**
     * @brief Mark the fresh DTLS association, identities, and authorization fully authenticated.
     *
     * @param candidate_connection_generation Candidate named by the completed handshake.
     * @return Typed transition result.
     */
    constexpr generation_fence_result mark_candidate_authenticated(
      const std::uint32_t candidate_connection_generation
    ) noexcept {
      if (phase_ != generation_fence_phase::candidate_handshake) {
        return generation_fence_result::wrong_phase;
      }
      if (candidate_connection_generation != candidate_connection_generation_) {
        return generation_fence_result::candidate_mismatch;
      }
      phase_ = generation_fence_phase::candidate_authenticated;
      return generation_fence_result::accepted;
    }

    /**
     * @brief Record atomic release of every held key, button, touch, pen, and controller.
     *
     * @return Typed transition result.
     */
    constexpr generation_fence_result neutralize_old_input() noexcept {
      if (phase_ != generation_fence_phase::candidate_authenticated) {
        return generation_fence_result::wrong_phase;
      }
      old_input_neutralized_ = true;
      phase_ = generation_fence_phase::old_input_neutralized;
      return generation_fence_result::accepted;
    }

    /**
     * @brief Commit authenticated ATTACH authority to the fresh association.
     *
     * @param new_input_generation Strictly newer nonzero input authority generation.
     * @return Typed transition result.
     */
    constexpr generation_fence_result commit_attach(
      const std::uint32_t new_input_generation
    ) noexcept {
      if (phase_ != generation_fence_phase::old_input_neutralized || !old_input_neutralized_) {
        return generation_fence_result::input_not_neutralized;
      }
      if (new_input_generation == 0 ||
          active_input_generation_ == UINT32_MAX ||
          new_input_generation <= active_input_generation_) {
        return generation_fence_result::invalid_generation;
      }
      active_connection_generation_ = candidate_connection_generation_;
      active_input_generation_ = new_input_generation;
      candidate_connection_generation_ = 0;
      old_input_neutralized_ = false;
      baseline_required_ = false;
      phase_ = generation_fence_phase::authoritative;
      return generation_fence_result::accepted;
    }

    /**
     * @brief Cancel a failed fresh association while leaving old authority installed.
     *
     * @return Typed transition result.
     */
    constexpr generation_fence_result cancel_candidate() noexcept {
      if (phase_ == generation_fence_phase::uninitialized ||
          phase_ == generation_fence_phase::authoritative) {
        return generation_fence_result::wrong_phase;
      }
      baseline_required_ = old_input_neutralized_;
      candidate_connection_generation_ = 0;
      phase_ = generation_fence_phase::authoritative;
      return generation_fence_result::accepted;
    }

    /**
     * @brief Restore old-association input only after a complete post-neutralization baseline.
     *
     * @param new_input_generation Strictly newer input authority generation bound to the baseline.
     * @return Typed transition result.
     */
    constexpr generation_fence_result restore_old_authority_after_baseline(
      const std::uint32_t new_input_generation
    ) noexcept {
      if (phase_ != generation_fence_phase::authoritative || !baseline_required_) {
        return generation_fence_result::wrong_phase;
      }
      if (new_input_generation == 0 ||
          active_input_generation_ == UINT32_MAX ||
          new_input_generation <= active_input_generation_) {
        return generation_fence_result::invalid_generation;
      }
      active_input_generation_ = new_input_generation;
      old_input_neutralized_ = false;
      baseline_required_ = false;
      return generation_fence_result::accepted;
    }

    /**
     * @brief Return whether an authenticated control/media packet has current authority.
     *
     * Candidate packets do not become authoritative before ATTACH commits.
     *
     * @param connection_generation Packet connection generation.
     * @return `true` only for the active association generation.
     */
    [[nodiscard]] constexpr bool accepts_connection_packet(
      const std::uint32_t connection_generation
    ) const noexcept {
      return phase_ != generation_fence_phase::uninitialized &&
             connection_generation != 0 &&
             connection_generation == active_connection_generation_;
    }

    /**
     * @brief Return whether an authenticated input packet has current connection and input authority.
     *
     * Input is rejected during the neutralized pre-ATTACH gap even if it names the old generation.
     *
     * @param connection_generation Packet connection generation.
     * @param input_generation Packet input authority generation.
     * @return `true` only for the current non-neutralized authority pair.
     */
    [[nodiscard]] constexpr bool accepts_input_packet(
      const std::uint32_t connection_generation,
      const std::uint32_t input_generation
    ) const noexcept {
      return !old_input_neutralized_ && !baseline_required_ &&
             accepts_connection_packet(connection_generation) &&
             input_generation != 0 &&
             input_generation == active_input_generation_;
    }

    /**
     * @brief Return current generation-fence state.
     *
     * @return Immutable authority snapshot.
     */
    [[nodiscard]] constexpr generation_fence_snapshot snapshot() const noexcept {
      return {
        .phase = phase_,
        .active_connection_generation = active_connection_generation_,
        .active_input_generation = active_input_generation_,
        .candidate_connection_generation = candidate_connection_generation_,
        .old_input_neutralized = old_input_neutralized_,
        .baseline_required = baseline_required_,
      };
    }

  private:
    generation_fence_phase phase_ = generation_fence_phase::uninitialized;  ///< Authority-transfer lifecycle phase.
    std::uint32_t active_connection_generation_ = 0;  ///< Authoritative connection generation.
    std::uint32_t active_input_generation_ = 0;  ///< Authoritative input generation.
    std::uint32_t candidate_connection_generation_ = 0;  ///< Pending fresh association generation.
    bool old_input_neutralized_ = false;  ///< Whether old held state was atomically released.
    bool baseline_required_ = false;  ///< Whether old association needs a fresh complete input baseline.
  };
}  // namespace lumen::lsp::transport
