# Agent Guide

This guide is for orchestrators/LLM agents using `vaultwarden-cli` in automated workflows.

## Tenancy and Isolation

- Use one `--profile` per agent identity.
- Never share a profile across unrelated agents.
- Keep agent home/runtime storage isolated at the OS level.

## Secret Handling Rules

- Do not use CLI arguments for secrets.
- Provide:
  - master password via `--password-stdin`
  - client secret via `--client-secret-stdin`
- Use `https://` server URLs unless you are explicitly talking to a localhost or other loopback test instance.
- For write commands with `--input -`:
  - stdin line 1 must be master password
  - stdin remainder must be JSON payload

## Read/Run Selection Rules

- Treat name and URI lookup ambiguity as a hard stop.
- If `get`, `get-uri`, `run`, or `run-uri` reports multiple matches, narrow the selector or switch to an exact cipher ID.

## Write Retry Strategy

1. Parse JSON response.
2. If `ok=true`, proceed.
3. If `ok=false` and `error.code == "CONFLICT_STALE_REVISION"`:
  - resync
  - retry with fresh revision date.
4. If `retryable=true`, bounded retry with jitter.
5. If `retryable=false`, require operator or policy intervention.

## Deterministic Upsert Strategy

- Use `write upsert --match name_uri`.
- Keep `name` and first URI stable for deterministic matching.
- If `AMBIGUOUS_MATCH`, do not guess; narrow scope or match criteria.

## Logging and Telemetry

- Log operation metadata only (profile, command, cipher ID, code).
- Do not log plaintext write payloads.
- Do not log decrypted secrets.

## Supported Write Input v1 (Initial GA)

- Types:
  - `login`
  - `note`
- Common fields:
  - `name`, `notes`, `folder_id`, `organization_id`, `collection_ids`
  - `favorite`, `reprompt`, `fields`
- Type blocks:
  - `login`: `username`, `password`, `totp`, `uris[]`
  - `note`: `secure_note_type`

Formal schemas:
- `docs/schemas/write-input-v1.json`
- `docs/schemas/write-output-v1.json`
- `docs/schemas/write-error-codes.json`
