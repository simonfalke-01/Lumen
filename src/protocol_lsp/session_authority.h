/**
 * @file src/protocol_lsp/session_authority.h
 * @brief LSP START, ATTACH, STOP, generation, and input-authority state.
 */

#pragma once

#include "types.h"

#include <cstdint>

namespace lumen::lsp {
  /**
   * @brief Authenticated client authority supplied after DTLS and application authentication.
   */
  struct AuthenticatedClient {
    Identifier128 client_id {};  ///< Stable paired client identifier.
    std::uint32_t connection_generation {};  ///< Nonzero DTLS association authority generation.
    std::uint32_t revocation_generation {};  ///< Nonzero permission-revocation generation.
    PermissionSet permissions {};  ///< Effective authenticated permissions.

    /**
     * @brief Validate required authenticated-client fields.
     *
     * @return True when identifiers and generations are nonzero.
     */
    [[nodiscard]] bool valid() const noexcept;
  };

  /**
   * @brief Cryptographically random material supplied to an accepted START.
   *
   * Generation and randomness production are deliberately outside this class;
   * product integration must supply them from an authenticated provider.
   */
  struct StartAuthority {
    Identifier128 session_id {};  ///< Random nonzero stream-session identifier.
    Secret256 attach_token {};  ///< Random nonzero 256-bit attach token.
    Generations generations {};  ///< Exact nonzero selected generations.

    /**
     * @brief Validate START authority values.
     *
     * @return True when identifiers, secret, and generations are nonzero.
     */
    [[nodiscard]] bool valid() const noexcept;
  };

  /**
   * @brief Reason that all held platform input must be released.
   */
  enum class NeutralizationReason : std::uint8_t {
    transport_loss,  ///< Authoritative DTLS association was lost.
    permission_revoked,  ///< Raw-input permission is being revoked.
    explicit_stop,  ///< Stream owner or host requested STOP.
    service_shutdown,  ///< Host service is shutting down.
  };

  /**
   * @brief Immutable context for one platform-input neutralization call.
   */
  struct NeutralizationRequest {
    NeutralizationReason reason {NeutralizationReason::transport_loss};  ///< Cause of the release.
    Identifier128 client_id {};  ///< Client whose held devices must be released.
    Identifier128 session_id {};  ///< Session losing input authority.
    Generations generations {};  ///< Last authoritative generations being neutralized.
  };

  /**
   * @brief Platform callback contract for synchronously releasing held input.
   *
   * Implementations must release keyboard keys, pointer buttons, controller
   * buttons, touch contacts, and other held state before returning true. The
   * callback must be bounded, noexcept, and safe to call once per authority
   * epoch. Returning false prevents ATTACH and leaves the session fail-closed.
   */
  class InputNeutralizer {
  public:
    virtual ~InputNeutralizer() = default;

    /**
     * @brief Release every held input state for an authority epoch.
     *
     * @param request Exact authority and reason being neutralized.
     * @return True only after all held state is released.
     */
    virtual bool neutralize(const NeutralizationRequest &request) noexcept = 0;
  };

  /**
   * @brief Constant-time attach-token verification provider.
   *
   * Product integration must inject a cryptographic implementation. The
   * authority state machine does not emulate constant-time secret comparison.
   */
  class AttachTokenVerifier {
  public:
    virtual ~AttachTokenVerifier() = default;

    /**
     * @brief Compare a presented token to the stored token without timing leakage.
     *
     * @param presented Token received on the authenticated ATTACH request.
     * @param expected Token issued by START.
     * @return True only when both 256-bit tokens match.
     */
    [[nodiscard]] virtual bool matches(
      const Secret256 &presented,
      const Secret256 &expected
    ) const noexcept = 0;
  };

  /**
   * @brief Host-side session authority state.
   */
  enum class SessionState : std::uint8_t {
    ready,  ///< No active session; START may be accepted.
    streaming,  ///< One authenticated connection owns the active session.
    detached,  ///< Input is neutralized and the session is held for ATTACH.
    faulted,  ///< Neutralization failed; input and ATTACH remain denied.
  };

  /**
   * @brief Typed result of an authority transition.
   */
  enum class AuthorityResult : std::uint8_t {
    accepted,  ///< Transition completed.
    invalid_state,  ///< Transition is not valid from the current state.
    malformed,  ///< Required identifier, secret, or generation is zero.
    permission_denied,  ///< Authenticated client lacks the exact permission.
    not_owner,  ///< Client or session does not own the active stream.
    stale_generation,  ///< Connection, stream, or input generation is stale or unexpected.
    token_mismatch,  ///< ATTACH token does not match the active session.
    security_provider_unavailable,  ///< Required constant-time secret verifier was not injected.
    generation_exhausted,  ///< Required connection or input generation cannot advance without wrapping.
    baseline_required,  ///< Input cannot be accepted until a complete baseline is committed.
    neutralization_failed,  ///< Platform input release failed and authority remains fail-closed.
  };

  /**
   * @brief Read-only active-session authority snapshot.
   */
  struct SessionSnapshot {
    SessionState state {SessionState::ready};  ///< Current authority state.
    Identifier128 owner_client_id {};  ///< Owning client, or zero while ready.
    Identifier128 session_id {};  ///< Active session, or zero while ready.
    Generations generations {};  ///< Current active generations.
    PermissionSet effective_permissions {};  ///< Current owner permissions.
    bool input_baseline_complete {};  ///< Whether input edges may be accepted.
  };

  /**
   * @brief Pure host authority state machine for one active LSP stream.
   *
   * The class owns no process, media, socket, DTLS, SRTP, or random-number
   * implementation. Product integration commits those resources before calling
   * a transition and uses this state machine to guard their authority.
   */
  class SessionAuthority {
  public:
    /**
     * @brief Construct a ready authority state.
     *
     * @param neutralizer Platform release callback that outlives this object.
     * @param token_verifier Constant-time verifier that outlives this object, or null to deny ATTACH.
     */
    explicit SessionAuthority(
      InputNeutralizer &neutralizer,
      const AttachTokenVerifier *token_verifier
    ) noexcept;

    /**
     * @brief Accept START for an authenticated client.
     *
     * @param client Authenticated connection and effective permissions.
     * @param authority Random session material and selected generations.
     * @return Exact transition result.
     */
    AuthorityResult start(const AuthenticatedClient &client, const StartAuthority &authority) noexcept;

    /**
     * @brief Neutralize input and hold the stream after transport loss.
     *
     * @param connection_generation Lost authoritative connection generation.
     * @return Exact transition result.
     */
    AuthorityResult transport_lost(std::uint32_t connection_generation) noexcept;

    /**
     * @brief Transfer a held session to a fresh authenticated connection.
     *
     * The supplied connection generation must be strictly newer. This permits
     * unrelated authenticated connections to consume host-wide generation
     * values without weakening stale-association fencing. Input generation
     * advances internally, and input remains blocked until a new complete
     * baseline is committed. A valid ATTACH on a still-live association first
     * neutralizes the old input authority for planned rekey.
     *
     * @param client Fresh authenticated connection for the same owner.
     * @param session_id Session identifier returned by START.
     * @param attach_token Secret returned by START.
     * @param successor_attach_token Fresh nonzero token that atomically retires the presented token on success.
     * @return Exact transition result.
     */
    AuthorityResult attach(
      const AuthenticatedClient &client,
      const Identifier128 &session_id,
      const Secret256 &attach_token,
      const Secret256 &successor_attach_token
    ) noexcept;

    /**
     * @brief Validate ATTACH identity, token, permission, and generation without mutation.
     *
     * Product integration uses this preflight to prepare every fallible SSRC,
     * queue, and mapping resource before committing authority/token rotation.
     *
     * @param client Fresh authenticated connection for the same owner.
     * @param session_id Existing session identifier.
     * @param attach_token Presented current token.
     * @param successor_attach_token Required nonzero replacement token distinct from the presented token.
     * @return Exact result that `attach()` will return absent an intervening mutation or neutralization failure.
     */
    [[nodiscard]] AuthorityResult prepare_attach(
      const AuthenticatedClient &client,
      const Identifier128 &session_id,
      const Secret256 &attach_token,
      const Secret256 &successor_attach_token
    ) const noexcept;

    /**
     * @brief Commit the complete multipart input baseline for an authority.
     *
     * @param client Authenticated session owner.
     * @param session_generation Exact active stream generation.
     * @param input_generation Exact active input generation.
     * @return Exact transition result.
     */
    AuthorityResult commit_input_baseline(
      const AuthenticatedClient &client,
      std::uint32_t session_generation,
      std::uint32_t input_generation
    ) noexcept;

    /**
     * @brief Check whether one input packet has current authority.
     *
     * @param client_id Stable authenticated client identifier.
     * @param connection_generation Packet connection generation.
     * @param session_generation Packet stream generation.
     * @param input_generation Packet input generation.
     * @return Accepted only after the exact current baseline; otherwise a typed rejection.
     */
    [[nodiscard]] AuthorityResult authorize_input(
      const Identifier128 &client_id,
      std::uint32_t connection_generation,
      std::uint32_t session_generation,
      std::uint32_t input_generation
    ) const noexcept;

    /**
     * @brief Revoke a subset of the current owner's permissions.
     *
     * Raw-input removal disables packet admission before synchronously
     * neutralizing held state. The caller must not acknowledge revocation until
     * this function returns.
     *
     * @param client Authenticated current owner.
     * @param revoked Permissions to remove.
     * @return Exact transition result.
     */
    AuthorityResult revoke_permissions(
      const AuthenticatedClient &client,
      PermissionSet revoked
    ) noexcept;

    /**
     * @brief Stop a session at the authenticated owner's request.
     *
     * @param client Authenticated current owner with stop permission.
     * @param session_id Exact active session identifier.
     * @return Exact transition result.
     */
    AuthorityResult stop_owned(
      const AuthenticatedClient &client,
      const Identifier128 &session_id
    ) noexcept;

    /**
     * @brief Stop the active session under trusted host authority.
     *
     * @param reason Neutralization reason, normally explicit stop or shutdown.
     * @return Accepted after clearing authority, or neutralization_failed after clearing authority fail-closed.
     */
    AuthorityResult stop_from_host(NeutralizationReason reason) noexcept;

    /**
     * @brief Return a read-only copy of current authority state.
     *
     * @return Current snapshot.
     */
    [[nodiscard]] SessionSnapshot snapshot() const noexcept;

  private:
    bool same_owner(const AuthenticatedClient &client) const noexcept;
    bool exact_generations(
      std::uint32_t connection_generation,
      std::uint32_t session_generation,
      std::uint32_t input_generation
    ) const noexcept;
    bool neutralize(NeutralizationReason reason) noexcept;
    void clear() noexcept;

    InputNeutralizer &neutralizer_;
    const AttachTokenVerifier *token_verifier_ {};
    SessionState state_ {SessionState::ready};
    Identifier128 owner_client_id_ {};
    Identifier128 session_id_ {};
    Secret256 attach_token_ {};
    Generations generations_ {};
    PermissionSet effective_permissions_ {};
    std::uint32_t revocation_generation_ {};
    bool input_baseline_complete_ {};
    bool input_neutralized_ {true};
  };
}  // namespace lumen::lsp
