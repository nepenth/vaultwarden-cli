# vaultwarden-cli

Agent-first, Rust-native CLI for [Vaultwarden](https://github.com/dani-garcia/vaultwarden), scoped to secure multi-agent workflows.

## Scope

- Platforms: Linux and macOS
- Out of scope: Windows
- Backward compatibility: not guaranteed (agent-first behavior has priority)
- Multi-tenant execution: one profile per agent identity

## Security Model

1. Explicit profile tenancy
- Every command requires `--profile` (or `VAULTWARDEN_PROFILE`).
- Profile state is isolated under per-profile directories.

2. No keyring support
- OS keyrings are not used.
- Client secrets are never persisted to keyring backends.

3. Runtime-only decryption keys
- Decrypted vault keys are not persisted to disk.
- Runtime decryption uses master password provided via stdin.

4. Secret ingress hardening
- Secret-bearing CLI flags were removed.
- Use `--password-stdin` and `--client-secret-stdin`.
- Write commands with `--input -` expect:
  - stdin line 1: master password
  - stdin remainder: write JSON payload

5. Profile state safety
- Per-profile file locking prevents concurrent session corruption.
- Config updates use atomic write/rename semantics.

6. Transport guardrails
- Server URLs must use `https://` unless they target localhost or another loopback address for local testing.
- HTTP requests use bounded connect/request timeouts so stalled agent workflows fail instead of hanging indefinitely.

## Installation

```bash
git clone https://github.com/nepenth/vaultwarden-cli.git
cd vaultwarden-cli
cargo build --release
```

Binary:

```bash
target/release/vaultwarden-cli
```

## Authentication

Login with client secret from stdin:

```bash
printf '%s' "$VAULTWARDEN_CLIENT_SECRET" | \
  vaultwarden-cli \
    --profile agent-alpha \
    login \
    --server https://vault.example.com \
    --client-id "$VAULTWARDEN_CLIENT_ID" \
    --client-secret-stdin
```

Logout:

```bash
vaultwarden-cli --profile agent-alpha logout
```

Status:

```bash
vaultwarden-cli --profile agent-alpha status
```

## Retrieval Commands

Lookup commands fail closed on ambiguity. If multiple items share the same exact name or URI substring match, narrow the selector or use the cipher ID.

Provide master password on stdin:

```bash
printf '%s' "$VAULTWARDEN_PASSWORD" | \
  vaultwarden-cli --profile agent-alpha --password-stdin list
```

Get one item:

```bash
printf '%s' "$VAULTWARDEN_PASSWORD" | \
  vaultwarden-cli --profile agent-alpha --password-stdin get "My Login"
```

Run with injected env vars:

```bash
printf '%s' "$VAULTWARDEN_PASSWORD" | \
  vaultwarden-cli --profile agent-alpha --password-stdin run --name "My Login" -- ./deploy.sh
```

## Write Commands (JSON v1)

Supported types in initial write GA:
- `login`
- `note`

### Create

```bash
{
  printf '%s\n' "$VAULTWARDEN_PASSWORD"
  cat <<'JSON'
{"type":"login","name":"svc/github","login":{"username":"bot","password":"pw","uris":[{"uri":"https://github.com"}]}}
JSON
} | vaultwarden-cli --profile agent-alpha --password-stdin write create --input -
```

### Update

```bash
{
  printf '%s\n' "$VAULTWARDEN_PASSWORD"
  cat <<'JSON'
{"type":"note","name":"runtime/flag","note":{"secure_note_type":0},"notes":"rotated"}
JSON
} | vaultwarden-cli --profile agent-alpha --password-stdin \
      write update --id "<cipher_id>" --if-revision "<revisionDate>" --input -
```

### Upsert

```bash
{
  printf '%s\n' "$VAULTWARDEN_PASSWORD"
  cat <<'JSON'
{"type":"login","name":"svc/github","login":{"username":"bot","password":"pw","uris":[{"uri":"https://github.com"}]}}
JSON
} | vaultwarden-cli --profile agent-alpha --password-stdin \
      write upsert --match name_uri --scope personal --input -
```

### Helper Mutations

Rotate password:

```bash
{
  printf '%s\n' "$VAULTWARDEN_PASSWORD"
  echo '{"new_password":"new-secret"}'
} | vaultwarden-cli --profile agent-alpha --password-stdin \
      write rotate-password --id "<cipher_id>" --if-revision "<revisionDate>" --input -
```

Patch fields:

```bash
{
  printf '%s\n' "$VAULTWARDEN_PASSWORD"
  echo '{"fields":[{"name":"api_key","value":"abc","field_type":1}]}'
} | vaultwarden-cli --profile agent-alpha --password-stdin \
      write patch-fields --id "<cipher_id>" --if-revision "<revisionDate>" --input -
```

Move/favorite patch:

```bash
printf '%s' "$VAULTWARDEN_PASSWORD" | \
  vaultwarden-cli --profile agent-alpha --password-stdin \
    write move --id "<cipher_id>" --if-revision "<revisionDate>" --folder-id "<folder_id>" --favorite true
```

## Write Output Contract

Success:

```json
{
  "ok": true,
  "operation": "create",
  "id": "cipher-id",
  "revision_date": "2026-04-21T12:00:00.000000Z",
  "organization_id": null,
  "warnings": []
}
```

Failure:

```json
{
  "ok": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "...",
    "retryable": false,
    "action": "fix_input"
  }
}
```

Stable write error codes:
- `VALIDATION_ERROR`
- `AUTH_ERROR`
- `PERMISSION_DENIED`
- `NOT_FOUND`
- `CONFLICT_STALE_REVISION`
- `AMBIGUOUS_MATCH`
- `SERVER_ERROR`

## LLM/Agent Hints

- Use one profile per agent identity.
- Never pass secrets in CLI args.
- Use stdin only for secrets.
- Expect `get`, `get-uri`, `run`, and `run-uri` to fail on ambiguous matches; use unique IDs or stricter filters.
- On `CONFLICT_STALE_REVISION`: resync, then retry.
- Retry only when `retryable=true`.
- Avoid logging full write input payloads.

See [AGENT_GUIDE.md](AGENT_GUIDE.md) for detailed automation guidance.

## Development

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Local live end-to-end testing against a real Vaultwarden account is available through an ignored integration test plus a wrapper script that reads runtime-only configuration from env vars, local secret files, and an untracked fixture file:

```bash
./scripts/live-e2e.sh
```

See [docs/live-e2e.md](docs/live-e2e.md) for setup and safety guidance. Use the committed [.env.live-e2e.example](.env.live-e2e.example) and [docs/live-e2e.fixture.example.json](docs/live-e2e.fixture.example.json) as templates, and keep your real `.env.live-e2e.local` and `.live-e2e/fixture.json` untracked.

Optional pre-commit hook:

```bash
git config core.hooksPath .githooks
```

## License

MIT
