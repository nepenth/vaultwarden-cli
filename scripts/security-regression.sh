#!/usr/bin/env bash
set -euo pipefail

cargo test --test agent_first_cli

help_output="$(cargo run --quiet -- --help)"
login_help_output="$(cargo run --quiet -- login --help)"

if [[ "$help_output" != *"--password-stdin"* ]]; then
  echo "Expected --password-stdin in global help output" >&2
  exit 1
fi

if [[ "$help_output" == *"--password "* ]]; then
  echo "Unexpected legacy --password flag in global help output" >&2
  exit 1
fi

if [[ "$login_help_output" != *"--client-secret-stdin"* ]]; then
  echo "Expected --client-secret-stdin in login help output" >&2
  exit 1
fi

if [[ "$login_help_output" == *"--client-secret "* ]]; then
  echo "Unexpected legacy --client-secret flag in login help output" >&2
  exit 1
fi
