#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

if [[ -f .env.live-e2e.local ]]; then
  set -a
  # shellcheck disable=SC1091
  source ./.env.live-e2e.local
  set +a
fi

resolve_var() {
  local name="$1"
  local file_name="${name}_FILE"
  local value="${!name-}"
  local file="${!file_name-}"

  if [[ -n "$value" && -n "$file" ]]; then
    printf 'Set either %s or %s, not both.\n' "$name" "$file_name" >&2
    exit 1
  fi

  if [[ -n "$file" ]]; then
    if [[ ! -r "$file" ]]; then
      printf 'Secret file for %s is not readable: %s\n' "$name" "$file" >&2
      exit 1
    fi
    export "$name"="$(<"$file")"
  fi

  if [[ -z "${!name-}" ]]; then
    printf 'Missing required live e2e setting: %s\n' "$name" >&2
    exit 1
  fi
}

resolve_var "VW_LIVE_E2E_SERVER"
resolve_var "VW_LIVE_E2E_CLIENT_ID"
resolve_var "VW_LIVE_E2E_CLIENT_SECRET"
resolve_var "VW_LIVE_E2E_MASTER_PASSWORD"

export VW_LIVE_E2E_NAMESPACE="${VW_LIVE_E2E_NAMESPACE:-default}"
export VW_LIVE_E2E_FIXTURE_FILE="${VW_LIVE_E2E_FIXTURE_FILE:-.live-e2e/fixture.json}"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"

if [[ ! -r "$VW_LIVE_E2E_FIXTURE_FILE" ]]; then
  printf 'Live e2e fixture file is not readable: %s\n' "$VW_LIVE_E2E_FIXTURE_FILE" >&2
  exit 1
fi

cargo test --test live_e2e "$@" -- --ignored --nocapture
