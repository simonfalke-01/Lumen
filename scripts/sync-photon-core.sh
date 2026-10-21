#!/usr/bin/env bash

set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_directory
lumen_root="$(cd -- "${script_directory}/.." && pwd)"
readonly lumen_root
readonly local_source_root="${lumen_root}/src/protocol_lsp"
readonly local_lock="${local_source_root}/photon.lock"
readonly local_manifest="${local_source_root}/photon-source-manifest.txt"
readonly local_digest="${local_source_root}/photon-source-digest.sha256"
sibling_photon="$(cd -- "${lumen_root}/.." && pwd)/Photon"
readonly sibling_photon
readonly pinned_repository="git@github.com:simonfalke-01/Photon.git"
readonly pinned_commit="9f8a869f09252930f0b4ea749c2c2be43401a9d0"
readonly pinned_digest="4269791d293364a451270df9923d64820377a239a17fc1eaa985a57bb58fcc17"
readonly expected_lock="repository=${pinned_repository}
commit=${pinned_commit}
digest=${pinned_digest}"

usage() {
  printf 'Usage: %s --check|--sync\n' "$0" >&2
}

fail() {
  printf 'sync-photon-core: %s\n' "$*" >&2
  exit 1
}

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "$file" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -- "$file" | awk '{print tolower($1)}'
  else
    cmake -E sha256sum "$file" | awk '{print tolower($1)}'
  fi
}

validate_manifest_entry() {
  local relative_file="$1"
  [[ "$relative_file" =~ ^(core|input_plane|media|transport)/[a-z0-9_]+\.h$ ]] \
    || fail "invalid Photon manifest entry: ${relative_file}"
}

compute_digest() {
  local source_root="$1"
  local manifest="$2"
  local digest_input="${temporary_directory}/digest-input-$RANDOM"
  : >"$digest_input"
  while IFS= read -r relative_file || [[ -n "$relative_file" ]]; do
    [[ -n "$relative_file" ]] || fail "blank Photon manifest entry in ${manifest}"
    validate_manifest_entry "$relative_file"
    [[ -f "${source_root}/${relative_file}" ]] || fail "missing Photon source: ${source_root}/${relative_file}"
    printf '%s\n%s\n' "$relative_file" "$(sha256_file "${source_root}/${relative_file}")" >>"$digest_input"
  done <"$manifest"
  sha256_file "$digest_input"
}

verify_source_set() {
  local source_root="$1"
  local manifest="$2"
  local expected_headers="${temporary_directory}/expected-headers-$RANDOM"
  local present_headers="${temporary_directory}/present-headers-$RANDOM"
  LC_ALL=C sort "$manifest" >"$expected_headers"
  find "${source_root}/core" "${source_root}/input_plane" "${source_root}/media" "${source_root}/transport" \
    -type f -name '*.h' -print \
    | sed "s#^${source_root}/##" \
    | LC_ALL=C sort >"$present_headers"
  cmp -s "$expected_headers" "$present_headers" || fail "Photon source set differs from ${manifest}"
}

verify_lock() {
  [[ -f "$local_lock" ]] || fail "missing Photon lock: ${local_lock}"
  [[ "$(<"$local_lock")" == "$expected_lock" ]] || fail "Photon lock does not match the pinned repository, commit, and digest"
}

verify_local_mirror() {
  [[ -f "$local_manifest" ]] || fail "missing local Photon manifest: ${local_manifest}"
  [[ -f "$local_digest" ]] || fail "missing local Photon digest: ${local_digest}"
  verify_source_set "$local_source_root" "$local_manifest"
  local recorded_digest
  recorded_digest="$(tr '[:upper:]' '[:lower:]' <"$local_digest" | tr -d '[:space:]')"
  [[ "$recorded_digest" == "$pinned_digest" ]] || fail "local Photon digest file does not match photon.lock"
  local computed_digest
  computed_digest="$(compute_digest "$local_source_root" "$local_manifest")"
  [[ "$computed_digest" == "$pinned_digest" ]] || fail "local Photon sources have digest ${computed_digest}, expected ${pinned_digest}"
}

verify_checkout() {
  local checkout="$1"
  [[ -d "${checkout}/.git" ]] || fail "Photon checkout is not a Git repository: ${checkout}"
  local checkout_origin
  checkout_origin="$(git -C "$checkout" remote get-url origin 2>/dev/null || true)"
  [[ "$checkout_origin" == "$pinned_repository" ]] \
    || fail "Photon checkout ${checkout} has origin ${checkout_origin:-<none>}, expected ${pinned_repository}"
  local checkout_commit
  checkout_commit="$(git -C "$checkout" rev-parse HEAD)"
  [[ "$checkout_commit" == "$pinned_commit" ]] || fail "Photon checkout ${checkout} is at ${checkout_commit}, expected ${pinned_commit}"
  [[ -f "${checkout}/source-manifest.txt" ]] || fail "Photon checkout is missing source-manifest.txt: ${checkout}"
  [[ -f "${checkout}/source-digest.sha256" ]] || fail "Photon checkout is missing source-digest.sha256: ${checkout}"
  local checkout_recorded_digest
  checkout_recorded_digest="$(tr '[:upper:]' '[:lower:]' <"${checkout}/source-digest.sha256" | tr -d '[:space:]')"
  [[ "$checkout_recorded_digest" == "$pinned_digest" ]] || fail "Photon checkout digest file does not match photon.lock"
  verify_source_set "${checkout}/src/lsp" "${checkout}/source-manifest.txt"
  local checkout_computed_digest
  checkout_computed_digest="$(compute_digest "${checkout}/src/lsp" "${checkout}/source-manifest.txt")"
  [[ "$checkout_computed_digest" == "$pinned_digest" ]] || fail "Photon checkout has digest ${checkout_computed_digest}, expected ${pinned_digest}"
}

verify_checkout_identity() {
  local checkout="$1"
  verify_checkout "$checkout"
  cmp -s "${checkout}/source-manifest.txt" "$local_manifest" || fail "local Photon manifest differs from ${checkout}/source-manifest.txt"
  while IFS= read -r relative_file || [[ -n "$relative_file" ]]; do
    cmp -s "${checkout}/src/lsp/${relative_file}" "${local_source_root}/${relative_file}" \
      || fail "local Photon source differs from checkout: ${relative_file}"
  done <"$local_manifest"
}

select_local_checkout() {
  if [[ -n "${PHOTON_REPOSITORY:-}" ]]; then
    if [[ -d "${PHOTON_REPOSITORY}" ]]; then
      printf '%s\n' "$(cd -- "${PHOTON_REPOSITORY}" && pwd)"
    fi
    return
  fi
  if [[ -d "$sibling_photon" ]]; then
    printf '%s\n' "$sibling_photon"
  fi
}

verify_available_checkouts() {
  local explicit_checkout=""
  if [[ -n "${PHOTON_REPOSITORY:-}" && -d "${PHOTON_REPOSITORY}" ]]; then
    explicit_checkout="$(cd -- "${PHOTON_REPOSITORY}" && pwd)"
    verify_checkout_identity "$explicit_checkout"
  fi
  if [[ -d "$sibling_photon" && "$sibling_photon" != "$explicit_checkout" ]]; then
    verify_checkout_identity "$sibling_photon"
  fi
}

clone_pinned_checkout() {
  local checkout="${temporary_directory}/Photon"
  git init --quiet "$checkout"
  git -C "$checkout" remote add origin "$pinned_repository"
  git -C "$checkout" fetch --quiet --depth=1 origin "$pinned_commit"
  git -C "$checkout" checkout --quiet --detach FETCH_HEAD
  printf '%s\n' "$checkout"
}

sync_from_checkout() {
  local checkout="$1"
  verify_checkout "$checkout"
  cp -- "${checkout}/source-manifest.txt" "$local_manifest"
  while IFS= read -r relative_file || [[ -n "$relative_file" ]]; do
    mkdir -p -- "$(dirname -- "${local_source_root}/${relative_file}")"
    cp -- "${checkout}/src/lsp/${relative_file}" "${local_source_root}/${relative_file}"
  done <"${checkout}/source-manifest.txt"
  while IFS= read -r -d '' present_file; do
    local relative_file="${present_file#"${local_source_root}"/}"
    if ! grep -Fqx -- "$relative_file" "$local_manifest"; then
      rm -f -- "$present_file"
    fi
  done < <(find "${local_source_root}/core" "${local_source_root}/input_plane" "${local_source_root}/media" \
    "${local_source_root}/transport" -type f -name '*.h' -print0)
  cp -- "${checkout}/source-digest.sha256" "$local_digest"
  verify_local_mirror
}

[[ $# -eq 1 ]] || {
  usage
  exit 2
}
readonly mode="$1"
[[ "$mode" == "--check" || "$mode" == "--sync" ]] || {
  usage
  exit 2
}

temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/lumen-photon-sync.XXXXXX")"
readonly temporary_directory
trap 'rm -rf -- "$temporary_directory"' EXIT

verify_lock

if [[ "$mode" == "--check" ]]; then
  verify_local_mirror
  verify_available_checkouts
  printf 'Photon mirror verified at %s (%s).\n' "$pinned_commit" "$pinned_digest"
  exit 0
fi

photon_checkout="$(select_local_checkout)"
if [[ -z "$photon_checkout" ]]; then
  photon_checkout="$(clone_pinned_checkout)"
fi
sync_from_checkout "$photon_checkout"
verify_available_checkouts
printf 'Photon mirror synchronized at %s (%s).\n' "$pinned_commit" "$pinned_digest"
