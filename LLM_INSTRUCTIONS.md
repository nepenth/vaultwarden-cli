# LLM Instructions (Agent-First)

This file is a one-page runbook for AI agents using `vaultwarden-cli` safely in production.

## Purpose and Scope

- Use this CLI for runtime secret retrieval and secret writes to Vaultwarden.
- Platforms: Linux and macOS only.
- Windows is out of scope.
- Multi-agent model: one profile per agent identity.

## Hard Rules (Do Not Violate)

1. Always pass `--profile <agent-id>`.
2. Never pass secrets in CLI arguments.
3. Use stdin for secrets only:
- master password: `--password-stdin`
- OAuth client secret: `--client-secret-stdin`
4. Do not log plaintext payloads, decrypted values, passwords, tokens, or client secrets.
5. Treat `AMBIGUOUS_MATCH` and `CONFLICT_STALE_REVISION` as safety stops, not soft warnings.

## Authentication Model

- Session login is OAuth2 client credentials (`client_id` + `client_secret`) against Vaultwarden identity.
- Master password is still required at runtime for decrypt/read/write operations.
- Username/password login is not the primary auth contract in this CLI.

Login template:

```bash
printf '%s' "$VW_CLIENT_SECRET" | \
  vaultwarden-cli --profile agent-a login \
    --server "$VW_SERVER" \
    --client-id "$VW_CLIENT_ID" \
    --client-secret-stdin
```

Status check:

```bash
vaultwarden-cli --profile agent-a status
```

## Read Flow

List items:

```bash
printf '%s' "$VW_MASTER_PASSWORD" | \
  vaultwarden-cli --profile agent-a --password-stdin list
```

Get by id or exact name:

```bash
printf '%s' "$VW_MASTER_PASSWORD" | \
  vaultwarden-cli --profile agent-a --password-stdin get "$CIPHER_ID_OR_NAME"
```

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
  printf '%s\n' "$VW_MASTER_PASSWORD"
  cat payload.json
} | vaultwarden-cli --profile agent-a --password-stdin write create --input -
```

Update (requires revision guard):

```bash
{
  printf '%s\n' "$VW_MASTER_PASSWORD"
  cat payload.json
} | vaultwarden-cli --profile agent-a --password-stdin \
      write update --id "$CIPHER_ID" --if-revision "$REVISION_DATE" --input -
```

Upsert (deterministic):

```bash
{
  printf '%s\n' "$VW_MASTER_PASSWORD"
  cat payload.json
} | vaultwarden-cli --profile agent-a --password-stdin \
      write upsert --match name_uri --scope personal --input -
```

Org scope example:

```bash
... write upsert --match name_uri --scope org:$ORG_ID --input -
```

## JSON Contracts

- Input schema: `docs/schemas/write-input-v1.json`
- Output schema: `docs/schemas/write-output-v1.json`
- Error code schema: `docs/schemas/write-error-codes.json`

Require strict JSON parsing in agents.

## Error Handling Contract

Stable write error codes:
- `VALIDATION_ERROR`
- `AUTH_ERROR`
- `PERMISSION_DENIED`
- `NOT_FOUND`
- `CONFLICT_STALE_REVISION`
- `AMBIGUOUS_MATCH`
- `SERVER_ERROR`

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

## Pre-Deployment Checks

1. `cargo test` must pass.
2. Verify no workflow sends secrets via argv/env logs.
3. Validate org writes include correct `organization_id` and `collection_ids`.
4. Confirm agent logic handles stale revision and ambiguity paths.

For longer operational guidance, see `AGENT_GUIDE.md` and `README.md`.
