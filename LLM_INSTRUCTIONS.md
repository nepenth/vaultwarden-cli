# LLM Instructions (Agent-First)

This document is intended for a master/orchestrator AI agent that installs and governs `vaultwarden-cli` for other agents.

## Machine-Readable Bootstrap Spec (v1)

```yaml
spec_version: 1
project: vaultwarden-cli
repo:
  url: https://github.com/nepenth/vaultwarden-cli.git
  branch: main
platforms:
  supported: [linux, macos]
  unsupported: [windows]
prerequisites:
  required_tools: [git, cargo]
  rust_toolchain: stable
build:
  command: cargo build --release
  artifact: target/release/vaultwarden-cli
install:
  mode: user-local
  target_dir: $HOME/.local/bin
  command: install -m 0755 target/release/vaultwarden-cli $HOME/.local/bin/vaultwarden-cli
verification:
  commands:
    - vaultwarden-cli --version
    - cargo test
auth:
  login_mode: oauth2_client_credentials
  login_inputs: [server, client_id, client_secret]
  runtime_inputs: [master_password]
  secret_ingress:
    client_secret: stdin_via_client_secret_stdin
    master_password: stdin_via_password_stdin
status_gate:
  logged_in: true
  token_expired: false
  action_if_not_ready: re_authenticate_with_login
profile_tenancy:
  required: true
  rule: one_profile_per_agent
  profile_regex: '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
write_contracts:
  input_schema: docs/schemas/write-input-v1.json
  output_schema: docs/schemas/write-output-v1.json
  error_schema: docs/schemas/write-error-codes.json
  supported_types_v1: [login, note]
  stable_error_codes:
    - VALIDATION_ERROR
    - AUTH_ERROR
    - PERMISSION_DENIED
    - NOT_FOUND
    - CONFLICT_STALE_REVISION
    - AMBIGUOUS_MATCH
    - SERVER_ERROR
security_rules:
  - never_put_secrets_in_cli_args
  - do_not_log_plaintext_payloads_or_decrypted_values
  - treat_ambiguous_or_stale_write_errors_as_hard_stops
  - isolate_profiles_per_agent_identity
  - prefer_https_except_for_loopback_test_servers
```

## Hard Rules (Do Not Violate)

1. Always pass `--profile <agent-id>`.
2. Never pass secrets in CLI arguments.
3. Use stdin for secrets only:
- master password: `--password-stdin`
- OAuth client secret: `--client-secret-stdin`
4. Do not log plaintext payloads, decrypted values, passwords, tokens, or client secrets.
5. Treat `AMBIGUOUS_MATCH` and `CONFLICT_STALE_REVISION` as safety stops, not soft warnings.
6. Use `https://` server URLs unless the target is a localhost or loopback test server.

## Master Agent Setup Workflow

1. Clone and build:

```bash
git clone https://github.com/nepenth/vaultwarden-cli.git
cd vaultwarden-cli
cargo build --release
```

2. Install for agent runtimes (user-local recommended):

```bash
mkdir -p "$HOME/.local/bin"
install -m 0755 target/release/vaultwarden-cli "$HOME/.local/bin/vaultwarden-cli"
export PATH="$HOME/.local/bin:$PATH"
```

3. Verify build and contracts:

```bash
vaultwarden-cli --version
cargo test
```

4. Register command path for downstream agents:
- preferred binary path: `$HOME/.local/bin/vaultwarden-cli`
- fallback path: `<repo>/target/release/vaultwarden-cli`

5. Provision one profile per agent identity:
- Example profile format: `team-env-agent-01`
- Never reuse the same profile across unrelated agents.

## Authentication Model

- Session login is OAuth2 client credentials (`client_id` + `client_secret`).
- Master password is required at runtime for decrypt/read/write operations.
- Username/password login is not the primary auth contract.

Login template:

```bash
secure_client_secret_source | \
  vaultwarden-cli --profile agent-a login \
    --server "$VW_SERVER" \
    --client-id "$VW_CLIENT_ID" \
    --client-secret-stdin
```

Status check:

```bash
vaultwarden-cli --profile agent-a status
```

Wrapper/orchestrator gate:
- Only skip re-auth when `logged_in=true` and `token_expired=false`.
- If `token_expired=true`, re-run `login` before secret operations.

## Read Flow

List items:

```bash
secure_master_password_source | \
  vaultwarden-cli --profile agent-a --password-stdin list
```

Get by id or exact name:

```bash
secure_master_password_source | \
  vaultwarden-cli --profile agent-a --password-stdin get "$CIPHER_ID_OR_NAME"
```

If name or URI-based lookup is ambiguous, stop and narrow the selector or switch to the exact cipher ID.

## Write Flow (JSON v1)

Supported initial write types:
- `login`
- `note`

For `write ... --input -` with `--password-stdin`:
- stdin line 1: master password
- stdin remainder: JSON payload

Create:

```bash
{
  secure_master_password_source_with_newline
  cat payload.json
} | vaultwarden-cli --profile agent-a --password-stdin write create --input -
```

Update (requires revision guard):

```bash
{
  secure_master_password_source_with_newline
  cat payload.json
} | vaultwarden-cli --profile agent-a --password-stdin \
      write update --id "$CIPHER_ID" --if-revision "$REVISION_DATE" --input -
```

Upsert (deterministic):

```bash
{
  secure_master_password_source_with_newline
  cat payload.json
} | vaultwarden-cli --profile agent-a --password-stdin \
      write upsert --match name_uri --scope personal --input -
```

Org scope example:

```bash
... write upsert --match name_uri --scope org:$ORG_ID --input -
```

## Skill/Tool Contract for Downstream Agents

Master agent should publish a minimal callable interface that wraps `vaultwarden-cli`:

```json
{
  "tool": "vaultwarden-cli",
  "required_args": ["profile"],
  "operations": {
    "login": {
      "secret_inputs": ["client_secret"],
      "args": ["server", "client_id"]
    },
    "status": {
      "secret_inputs": []
    },
    "list": {
      "secret_inputs": ["master_password"]
    },
    "get": {
      "secret_inputs": ["master_password"],
      "args": ["id_or_name"]
    },
    "write_create": {
      "secret_inputs": ["master_password"],
      "args": ["payload_json"]
    },
    "write_update": {
      "secret_inputs": ["master_password"],
      "args": ["id", "if_revision", "payload_json"]
    },
    "write_upsert": {
      "secret_inputs": ["master_password"],
      "args": ["scope", "payload_json"],
      "defaults": {"match": "name_uri"}
    }
  }
}
```

Operational requirement for wrappers:
- pass secrets only through stdin pipes.
- parse output as JSON for write operations.
- enforce bounded retries only when `retryable=true`.

## JSON Contracts

- Input schema: `docs/schemas/write-input-v1.json`
- Output schema: `docs/schemas/write-output-v1.json`
- Error code schema: `docs/schemas/write-error-codes.json`

Agents should validate payloads against schema before write calls.

## Error Handling Contract

Policy:

1. If `ok=true`, continue.
2. If `error.code == CONFLICT_STALE_REVISION`, resync item and retry with fresh revision.
3. Retry only when `retryable=true`, with bounded retries + jitter.
4. If `AMBIGUOUS_MATCH`, do not guess; narrow selectors or switch to explicit `id`.

## Multi-Agent Tenancy Guidance

1. Use a unique profile per agent (for example: `team1-agent-build-01`).
2. Never share a profile between unrelated agents.
3. Isolate agent runtime storage at OS level when possible.
4. Keep profile names safe: ASCII letters/numbers, plus `.`, `_`, `-`.

## Rollout Gates Before Broad Deployment

1. `cargo test` passes on target runtime.
2. Login with client credentials succeeds for each tenant profile.
3. Read and write smoke tests pass per agent scope (personal/org).
4. No workflow logs plaintext secrets or full secret payloads.
5. Agent wrappers enforce profile-per-agent mapping.

For extended guidance, see `README.md` and `AGENT_GUIDE.md`.
