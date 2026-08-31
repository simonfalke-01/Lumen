/**
 * @file src/protocol_lsp/session_authority.cpp
 * @brief LSP START, ATTACH, STOP, generation, and input-authority state.
 */

#include "session_authority.h"

#include <algorithm>
#include <limits>

namespace lumen::lsp {
  bool AuthenticatedClient::valid() const noexcept {
    return !is_zero(client_id) && connection_generation != 0 && revocation_generation != 0;
  }

  bool StartAuthority::valid() const noexcept {
    return !is_zero(session_id) && !is_zero(attach_token) && generations.valid();
  }

  SessionAuthority::SessionAuthority(
    InputNeutralizer &neutralizer,
    const AttachTokenVerifier *token_verifier
  ) noexcept:
      neutralizer_ {neutralizer},
      token_verifier_ {token_verifier} {
  }

  AuthorityResult SessionAuthority::start(
    const AuthenticatedClient &client,
    const StartAuthority &authority
  ) noexcept {
    if (state_ != SessionState::ready) {
      return AuthorityResult::invalid_state;
    }
    if (!client.valid() || !authority.valid()) {
      return AuthorityResult::malformed;
    }
    if (!client.permissions.contains(Permission::start_attach)) {
      return AuthorityResult::permission_denied;
    }
    if (client.connection_generation != authority.generations.connection) {
      return AuthorityResult::stale_generation;
    }

    state_ = SessionState::streaming;
    owner_client_id_ = client.client_id;
    session_id_ = authority.session_id;
    attach_token_ = authority.attach_token;
    generations_ = authority.generations;
    effective_permissions_ = client.permissions;
    revocation_generation_ = client.revocation_generation;
    input_baseline_complete_ = false;
    input_neutralized_ = true;
    return AuthorityResult::accepted;
  }

  AuthorityResult SessionAuthority::transport_lost(const std::uint32_t connection_generation) noexcept {
    if (state_ != SessionState::streaming) {
      return AuthorityResult::invalid_state;
    }
    if (connection_generation == 0 || connection_generation != generations_.connection) {
      return AuthorityResult::stale_generation;
    }

    input_baseline_complete_ = false;
    if (!neutralize(NeutralizationReason::transport_loss)) {
      state_ = SessionState::faulted;
      return AuthorityResult::neutralization_failed;
    }
    state_ = SessionState::detached;
    return AuthorityResult::accepted;
  }

  AuthorityResult SessionAuthority::attach(
    const AuthenticatedClient &client,
    const Identifier128 &session_id,
    const Secret256 &attach_token,
    const std::optional<Secret256> replacement_attach_token
  ) noexcept {
    const auto prepared = prepare_attach(client, session_id, attach_token, replacement_attach_token);
    if (prepared != AuthorityResult::accepted) {
      return prepared;
    }
    if (state_ == SessionState::streaming) {
      input_baseline_complete_ = false;
      if (!neutralize(NeutralizationReason::transport_loss)) {
        state_ = SessionState::faulted;
        return AuthorityResult::neutralization_failed;
      }
      state_ = SessionState::detached;
    }
    if (!input_neutralized_) {
      state_ = SessionState::faulted;
      return AuthorityResult::neutralization_failed;
    }

    generations_.connection = client.connection_generation;
    ++generations_.input;
    ++generations_.video;
    ++generations_.audio;
    ++generations_.microphone;
    if (replacement_attach_token) {
      attach_token_ = *replacement_attach_token;
    }
    effective_permissions_ = client.permissions;
    revocation_generation_ = client.revocation_generation;
    input_baseline_complete_ = false;
    state_ = SessionState::streaming;
    return AuthorityResult::accepted;
  }

  AuthorityResult SessionAuthority::prepare_attach(
    const AuthenticatedClient &client,
    const Identifier128 &session_id,
    const Secret256 &attach_token,
    const std::optional<Secret256> &replacement_attach_token
  ) const noexcept {
    if (state_ != SessionState::detached && state_ != SessionState::streaming) {
      return AuthorityResult::invalid_state;
    }
    if (!client.valid() || is_zero(session_id) || is_zero(attach_token) ||
        (replacement_attach_token && is_zero(*replacement_attach_token))) {
      return AuthorityResult::malformed;
    }
    if (!client.permissions.contains(Permission::start_attach)) {
      return AuthorityResult::permission_denied;
    }
    if (client.client_id != owner_client_id_ || session_id != session_id_) {
      return AuthorityResult::not_owner;
    }
    if (token_verifier_ == nullptr) {
      return AuthorityResult::security_provider_unavailable;
    }
    if (!token_verifier_->matches(attach_token, attach_token_)) {
      return AuthorityResult::token_mismatch;
    }
    if (generations_.connection == std::numeric_limits<std::uint32_t>::max() ||
        generations_.input == std::numeric_limits<std::uint32_t>::max() ||
        generations_.video == std::numeric_limits<std::uint32_t>::max() ||
        generations_.audio == std::numeric_limits<std::uint32_t>::max() ||
        generations_.microphone == std::numeric_limits<std::uint32_t>::max()) {
      return AuthorityResult::generation_exhausted;
    }
    if (client.connection_generation <= generations_.connection) {
      return AuthorityResult::stale_generation;
    }
    return AuthorityResult::accepted;
  }

  AuthorityResult SessionAuthority::commit_input_baseline(
    const AuthenticatedClient &client,
    const std::uint32_t session_generation,
    const std::uint32_t input_generation
  ) noexcept {
    if (state_ != SessionState::streaming) {
      return AuthorityResult::invalid_state;
    }
    if (!same_owner(client)) {
      return AuthorityResult::not_owner;
    }
    if (!effective_permissions_.contains(Permission::input)) {
      return AuthorityResult::permission_denied;
    }
    if (!exact_generations(client.connection_generation, session_generation, input_generation)) {
      return AuthorityResult::stale_generation;
    }
    input_baseline_complete_ = true;
    input_neutralized_ = false;
    return AuthorityResult::accepted;
  }

  AuthorityResult SessionAuthority::authorize_input(
    const Identifier128 &client_id,
    const std::uint32_t connection_generation,
    const std::uint32_t session_generation,
    const std::uint32_t input_generation
  ) const noexcept {
    if (state_ != SessionState::streaming) {
      return AuthorityResult::invalid_state;
    }
    if (client_id != owner_client_id_) {
      return AuthorityResult::not_owner;
    }
    if (!effective_permissions_.contains(Permission::input)) {
      return AuthorityResult::permission_denied;
    }
    if (!exact_generations(connection_generation, session_generation, input_generation)) {
      return AuthorityResult::stale_generation;
    }
    return input_baseline_complete_ ? AuthorityResult::accepted : AuthorityResult::baseline_required;
  }

  AuthorityResult SessionAuthority::revoke_permissions(
    const AuthenticatedClient &client,
    const PermissionSet revoked
  ) noexcept {
    if (state_ != SessionState::streaming) {
      return AuthorityResult::invalid_state;
    }
    if (!same_owner(client)) {
      return AuthorityResult::not_owner;
    }
    if (client.revocation_generation <= revocation_generation_) {
      return AuthorityResult::stale_generation;
    }

    const auto revoke_input = revoked.contains(Permission::input) && effective_permissions_.contains(Permission::input);
    effective_permissions_.revoke(revoked);
    revocation_generation_ = client.revocation_generation;
    if (!revoke_input) {
      return AuthorityResult::accepted;
    }

    input_baseline_complete_ = false;
    if (!neutralize(NeutralizationReason::permission_revoked)) {
      state_ = SessionState::faulted;
      return AuthorityResult::neutralization_failed;
    }
    return AuthorityResult::accepted;
  }

  AuthorityResult SessionAuthority::stop_owned(
    const AuthenticatedClient &client,
    const Identifier128 &session_id
  ) noexcept {
    if (state_ != SessionState::streaming && state_ != SessionState::detached) {
      return AuthorityResult::invalid_state;
    }
    if (!same_owner(client) || session_id != session_id_) {
      return AuthorityResult::not_owner;
    }
    if (!effective_permissions_.contains(Permission::stop_own_stream)) {
      return AuthorityResult::permission_denied;
    }
    return stop_from_host(NeutralizationReason::explicit_stop);
  }

  AuthorityResult SessionAuthority::stop_from_host(const NeutralizationReason reason) noexcept {
    if (state_ == SessionState::ready) {
      return AuthorityResult::invalid_state;
    }
    const auto neutralized = neutralize(reason);
    clear();
    return neutralized ? AuthorityResult::accepted : AuthorityResult::neutralization_failed;
  }

  SessionSnapshot SessionAuthority::snapshot() const noexcept {
    return {
      .state = state_,
      .owner_client_id = owner_client_id_,
      .session_id = session_id_,
      .generations = generations_,
      .effective_permissions = effective_permissions_,
      .input_baseline_complete = input_baseline_complete_,
    };
  }

  bool SessionAuthority::same_owner(const AuthenticatedClient &client) const noexcept {
    return client.valid() && client.client_id == owner_client_id_ &&
           client.connection_generation == generations_.connection;
  }

  bool SessionAuthority::exact_generations(
    const std::uint32_t connection_generation,
    const std::uint32_t session_generation,
    const std::uint32_t input_generation
  ) const noexcept {
    return connection_generation == generations_.connection && session_generation == generations_.stream &&
           input_generation == generations_.input;
  }

  bool SessionAuthority::neutralize(const NeutralizationReason reason) noexcept {
    if (input_neutralized_) {
      return true;
    }
    input_neutralized_ = neutralizer_.neutralize({
      .reason = reason,
      .client_id = owner_client_id_,
      .session_id = session_id_,
      .generations = generations_,
    });
    return input_neutralized_;
  }

  void SessionAuthority::clear() noexcept {
    state_ = SessionState::ready;
    std::ranges::fill(owner_client_id_, 0);
    std::ranges::fill(session_id_, 0);
    std::ranges::fill(attach_token_, 0);
    generations_ = {};
    effective_permissions_ = {};
    revocation_generation_ = 0;
    input_baseline_complete_ = false;
    input_neutralized_ = true;
  }
}  // namespace lumen::lsp
