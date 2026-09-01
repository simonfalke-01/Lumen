/**
 * @file src/lsp/transport/generation_fence.h
 * @brief Fresh-association reconnect and rekey authority fence.
 */

#pragma once

#include <cstdint>

namespace lumen::lsp::transport {
  /** @brief Fresh DTLS association transfer lifecycle. */
  enum class generation_fence_phase : std::uint8_t {
    uninitialized,  ///< No authoritative association is installed.
    authoritative,  ///< One association and input authority are active.
    candidate_handshake,  ///< One fresh DTLS association is handshaking.
    candidate_authenticated,  ///< The fresh association is authenticated while old input remains active.
    old_input_neutralized,  ///< Old input is neutralized and awaits a definite ATTACH outcome.
    rollback_baseline_pending,  ///< A definite ATTACH rejection awaits the old association's fresh neutral baseline ACK.
    attach_committed,  ///< New authority is committed while the old association awaits retirement.
    attach_outcome_ambiguous,  ///< ATTACH might have committed, so all authority is terminally fenced closed.
  };

  /** @brief Typed reconnect/rekey generation-fence transition result. */
  enum class generation_fence_result : std::uint8_t {
    accepted,  ///< Transition completed successfully.
    invalid_generation,  ///< A generation is zero, non-increasing, reused, or would wrap.
    wrong_phase,  ///< Operation violates fresh-association transfer ordering.
    candidate_mismatch,  ///< A callback names a different candidate connection generation.
    input_not_neutralized,  ///< ATTACH commit was attempted before old held input was released.
    active_authority_mismatch,  ///< A rollback baseline ACK names a different old authority pair.
    baseline_mismatch,  ///< A rollback baseline identifier is zero or does not match the required fresh baseline.
    retiring_mismatch,  ///< A retirement callback names a different old connection generation.
  };

  /** @brief Snapshot of active, candidate, rollback, and retiring authority state. */
  struct generation_fence_snapshot {
    generation_fence_phase phase = generation_fence_phase::uninitialized;  ///< Current authority-transfer phase.
    std::uint32_t active_connection_generation = 0;  ///< Currently authoritative connection generation.
    std::uint32_t active_input_generation = 0;  ///< Current wire input generation, retained across rejected ATTACH rollback.
    std::uint32_t input_authority_epoch = 0;  ///< Local callback epoch that changes whenever input authority is reopened or replaced.
    std::uint32_t connection_generation_high_watermark = 0;  ///< Greatest connection generation ever admitted as active or candidate.
    std::uint32_t candidate_connection_generation = 0;  ///< Sole fresh association before a definite ATTACH outcome.
    std::uint32_t rollback_connection_generation = 0;  ///< Rejected candidate generation binding the rollback baseline request.
    std::uint32_t retiring_connection_generation = 0;  ///< Old committed connection awaiting explicit retirement.
    std::uint64_t required_rollback_baseline_id = 0;  ///< Fresh neutral baseline ID whose authenticated ACK may reopen old input.
    bool old_input_neutralized = false;  ///< Whether held old input was atomically released and remains fenced.
    bool baseline_required = false;  ///< Whether a definite rejection is waiting for its bound neutral baseline ACK.
  };

  /**
   * @brief Fail-closed generation fence for fresh-DTLS reconnect and planned rekey.
   *
   * The old association remains authoritative while the sole candidate handshakes and authenticates.
   * Input authority transfers only after explicit neutralization and a definite authenticated ATTACH
   * commit. A definitely rejected ATTACH may reopen the unchanged old wire input generation only after
   * the exact fresh neutral baseline is acknowledged. A committed or ambiguous ATTACH can never roll
   * back, and the old association is retired only after commit.
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
      input_authority_epoch_ = connection_generation;
      connection_generation_high_watermark_ = connection_generation;
      phase_ = generation_fence_phase::authoritative;
      return generation_fence_result::accepted;
    }

    /**
     * @brief Begin the sole fresh DTLS association for reconnect or planned rekey.
     *
     * Canceled and rejected candidate generations remain consumed so a late callback can never name a
     * later candidate successfully.
     *
     * @param candidate_connection_generation Strictly newer, never-before-used connection generation.
     * @return Typed transition result.
     */
    constexpr generation_fence_result begin_fresh_association(
      const std::uint32_t candidate_connection_generation
    ) noexcept {
      if (phase_ != generation_fence_phase::authoritative) {
        return generation_fence_result::wrong_phase;
      }
      if (candidate_connection_generation == 0 ||
          connection_generation_high_watermark_ == UINT32_MAX ||
          candidate_connection_generation <= connection_generation_high_watermark_) {
        return generation_fence_result::invalid_generation;
      }
      candidate_connection_generation_ = candidate_connection_generation;
      connection_generation_high_watermark_ = candidate_connection_generation;
      phase_ = generation_fence_phase::candidate_handshake;
      return generation_fence_result::accepted;
    }

    /**
     * @brief Mark the fresh DTLS association, identities, and authorization fully authenticated.
     *
     * @param candidate_connection_generation Candidate named by the completed handshake callback.
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
     * @brief Cancel a candidate before old input has been neutralized.
     *
     * Candidate cancellation after neutralization is intentionally forbidden because only a definite
     * ATTACH rejection can authorize rollback from that point.
     *
     * @param candidate_connection_generation Candidate named by the cancellation callback.
     * @return Typed transition result.
     */
    constexpr generation_fence_result cancel_candidate(
      const std::uint32_t candidate_connection_generation
    ) noexcept {
      if (phase_ != generation_fence_phase::candidate_handshake &&
          phase_ != generation_fence_phase::candidate_authenticated) {
        return generation_fence_result::wrong_phase;
      }
      if (candidate_connection_generation != candidate_connection_generation_) {
        return generation_fence_result::candidate_mismatch;
      }
      candidate_connection_generation_ = 0;
      phase_ = generation_fence_phase::authoritative;
      return generation_fence_result::accepted;
    }

    /**
     * @brief Record atomic release of every held key, button, touch, pen, and controller.
     *
     * @param candidate_connection_generation Authenticated candidate for which neutralization completed.
     * @return Typed transition result.
     */
    constexpr generation_fence_result neutralize_old_input(
      const std::uint32_t candidate_connection_generation
    ) noexcept {
      if (phase_ != generation_fence_phase::candidate_authenticated) {
        return generation_fence_result::wrong_phase;
      }
      if (candidate_connection_generation != candidate_connection_generation_) {
        return generation_fence_result::candidate_mismatch;
      }
      old_input_neutralized_ = true;
      phase_ = generation_fence_phase::old_input_neutralized;
      return generation_fence_result::accepted;
    }

    /**
     * @brief Commit a definitely accepted authenticated ATTACH to the fresh association.
     *
     * The newly active association immediately rejects old packets, while the old connection generation
     * remains named in the snapshot until its resources are explicitly retired.
     *
     * @param candidate_connection_generation Candidate named by the definite commit callback.
     * @param new_input_generation Strictly newer nonzero wire input authority generation.
     * @return Typed transition result.
     */
    constexpr generation_fence_result commit_attach(
      const std::uint32_t candidate_connection_generation,
      const std::uint32_t new_input_generation
    ) noexcept {
      if (phase_ != generation_fence_phase::old_input_neutralized) {
        return phase_ == generation_fence_phase::candidate_authenticated ?
                 generation_fence_result::input_not_neutralized :
                 generation_fence_result::wrong_phase;
      }
      if (candidate_connection_generation != candidate_connection_generation_) {
        return generation_fence_result::candidate_mismatch;
      }
      if (new_input_generation == 0 ||
          active_input_generation_ == UINT32_MAX ||
          new_input_generation <= active_input_generation_) {
        return generation_fence_result::invalid_generation;
      }
      retiring_connection_generation_ = active_connection_generation_;
      active_connection_generation_ = candidate_connection_generation_;
      active_input_generation_ = new_input_generation;
      input_authority_epoch_ = candidate_connection_generation_;
      candidate_connection_generation_ = 0;
      old_input_neutralized_ = false;
      phase_ = generation_fence_phase::attach_committed;
      return generation_fence_result::accepted;
    }

    /**
     * @brief Record a definite pre-commit ATTACH rejection and bind its rollback baseline.
     *
     * @param candidate_connection_generation Candidate named by the authenticated rejection.
     * @param required_baseline_id Fresh random nonzero neutral baseline ID requested from the old association.
     * @return Typed transition result.
     */
    constexpr generation_fence_result reject_attach(
      const std::uint32_t candidate_connection_generation,
      const std::uint64_t required_baseline_id
    ) noexcept {
      if (phase_ != generation_fence_phase::old_input_neutralized) {
        return generation_fence_result::wrong_phase;
      }
      if (candidate_connection_generation != candidate_connection_generation_) {
        return generation_fence_result::candidate_mismatch;
      }
      if (required_baseline_id == 0) {
        return generation_fence_result::baseline_mismatch;
      }
      rollback_connection_generation_ = candidate_connection_generation_;
      required_rollback_baseline_id_ = required_baseline_id;
      candidate_connection_generation_ = 0;
      phase_ = generation_fence_phase::rollback_baseline_pending;
      return generation_fence_result::accepted;
    }

    /**
     * @brief Fence all authority when an ATTACH outcome might already have committed.
     *
     * This phase is terminal for the object. The caller must tear down both associations and construct a
     * new fence rather than guessing which side owns the session.
     *
     * @param candidate_connection_generation Candidate whose ATTACH outcome became ambiguous.
     * @return Typed transition result.
     */
    constexpr generation_fence_result mark_attach_outcome_ambiguous(
      const std::uint32_t candidate_connection_generation
    ) noexcept {
      if (phase_ != generation_fence_phase::old_input_neutralized) {
        return generation_fence_result::wrong_phase;
      }
      if (candidate_connection_generation != candidate_connection_generation_) {
        return generation_fence_result::candidate_mismatch;
      }
      phase_ = generation_fence_phase::attach_outcome_ambiguous;
      return generation_fence_result::accepted;
    }

    /**
     * @brief Reopen old input after its exact fresh neutral baseline was authenticated and acknowledged.
     *
     * The wire input generation deliberately remains unchanged. The local input-authority epoch advances
     * to the consumed rejected candidate generation so callbacks captured before neutralization remain stale.
     *
     * @param connection_generation Old association generation named by the baseline ACK.
     * @param input_generation Unchanged old wire input generation named by the baseline ACK.
     * @param accepted_baseline_id Authenticated fresh neutral baseline ID named by the ACK.
     * @return Typed transition result.
     */
    constexpr generation_fence_result acknowledge_old_neutral_baseline(
      const std::uint32_t connection_generation,
      const std::uint32_t input_generation,
      const std::uint64_t accepted_baseline_id
    ) noexcept {
      if (phase_ != generation_fence_phase::rollback_baseline_pending) {
        return generation_fence_result::wrong_phase;
      }
      if (connection_generation != active_connection_generation_ ||
          input_generation != active_input_generation_) {
        return generation_fence_result::active_authority_mismatch;
      }
      if (accepted_baseline_id == 0 || accepted_baseline_id != required_rollback_baseline_id_) {
        return generation_fence_result::baseline_mismatch;
      }
      input_authority_epoch_ = rollback_connection_generation_;
      rollback_connection_generation_ = 0;
      required_rollback_baseline_id_ = 0;
      old_input_neutralized_ = false;
      phase_ = generation_fence_phase::authoritative;
      return generation_fence_result::accepted;
    }

    /**
     * @brief Complete post-commit retirement of the old association and its resources.
     *
     * @param retiring_connection_generation Old connection named by the completed retirement callback.
     * @return Typed transition result.
     */
    constexpr generation_fence_result retire_old_association(
      const std::uint32_t retiring_connection_generation
    ) noexcept {
      if (phase_ != generation_fence_phase::attach_committed) {
        return generation_fence_result::wrong_phase;
      }
      if (retiring_connection_generation != retiring_connection_generation_) {
        return generation_fence_result::retiring_mismatch;
      }
      retiring_connection_generation_ = 0;
      phase_ = generation_fence_phase::authoritative;
      return generation_fence_result::accepted;
    }

    /**
     * @brief Return whether an authenticated control or media packet has definite current authority.
     *
     * Candidate packets do not become authoritative before ATTACH commits, and an ambiguous ATTACH
     * rejects both associations.
     *
     * @param connection_generation Packet connection generation.
     * @return `true` only for the definitely active association generation.
     */
    [[nodiscard]] constexpr bool accepts_connection_packet(
      const std::uint32_t connection_generation
    ) const noexcept {
      return has_definite_connection_authority() &&
             connection_generation != 0 &&
             connection_generation == active_connection_generation_;
    }

    /**
     * @brief Return whether an authenticated input callback still has current authority.
     *
     * The local epoch is captured with a received packet before asynchronous dispatch. It prevents an old
     * callback from becoming valid again when definite rejection reopens the same wire input generation.
     *
     * @param connection_generation Packet connection generation.
     * @param input_generation Packet wire input authority generation.
     * @param input_authority_epoch Local authority epoch captured with the callback.
     * @return `true` only for the current non-neutralized authority tuple and callback epoch.
     */
    [[nodiscard]] constexpr bool accepts_input_packet(
      const std::uint32_t connection_generation,
      const std::uint32_t input_generation,
      const std::uint32_t input_authority_epoch
    ) const noexcept {
      return !old_input_neutralized_ &&
             accepts_connection_packet(connection_generation) &&
             input_generation != 0 &&
             input_generation == active_input_generation_ &&
             input_authority_epoch != 0 &&
             input_authority_epoch == input_authority_epoch_;
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
        .input_authority_epoch = input_authority_epoch_,
        .connection_generation_high_watermark = connection_generation_high_watermark_,
        .candidate_connection_generation = candidate_connection_generation_,
        .rollback_connection_generation = rollback_connection_generation_,
        .retiring_connection_generation = retiring_connection_generation_,
        .required_rollback_baseline_id = required_rollback_baseline_id_,
        .old_input_neutralized = old_input_neutralized_,
        .baseline_required = phase_ == generation_fence_phase::rollback_baseline_pending,
      };
    }

  private:
    /**
     * @brief Return whether one connection generation is definitely authoritative in the current phase.
     *
     * @return `false` before initialization and after an ambiguous ATTACH outcome.
     */
    [[nodiscard]] constexpr bool has_definite_connection_authority() const noexcept {
      return phase_ != generation_fence_phase::uninitialized &&
             phase_ != generation_fence_phase::attach_outcome_ambiguous;
    }

    generation_fence_phase phase_ = generation_fence_phase::uninitialized;  ///< Authority-transfer lifecycle phase.
    std::uint32_t active_connection_generation_ = 0;  ///< Definitely authoritative connection generation.
    std::uint32_t active_input_generation_ = 0;  ///< Active wire input generation.
    std::uint32_t input_authority_epoch_ = 0;  ///< Local same-generation rollback callback fence.
    std::uint32_t connection_generation_high_watermark_ = 0;  ///< Greatest consumed connection generation.
    std::uint32_t candidate_connection_generation_ = 0;  ///< Sole pending or ambiguous fresh association.
    std::uint32_t rollback_connection_generation_ = 0;  ///< Rejected candidate binding the rollback ACK.
    std::uint32_t retiring_connection_generation_ = 0;  ///< Old committed association pending retirement.
    std::uint64_t required_rollback_baseline_id_ = 0;  ///< Exact fresh neutral baseline required for rollback.
    bool old_input_neutralized_ = false;  ///< Whether old input remains fenced after neutralization.
  };
}  // namespace lumen::lsp::transport
