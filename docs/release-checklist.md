# Release Checklist (Agent-First Write GA)

## Required Quality Gates

- `cargo fmt --all`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test`
- `cargo test --test agent_first_cli`

## Security Gates

- No HIGH findings from security regression suite.
- Secret-bearing flags remain absent (`--password`, `--client-secret`).
- Write command failures emit structured JSON without plaintext payload leakage.
- Profile lock and atomic config write tests pass.
- Conflict and permission-negative write tests pass.

## Docs Gates

- README reflects current CLI interface and stdin secret handling.
- AGENT_GUIDE.md reflects current write retry and tenancy behavior.
- JSON schemas under `docs/schemas/` match live output contracts.

## Residual Risk Acknowledgment

- Cryptographic correctness relies on compatibility with Vaultwarden encryption string format.
- Organization write behavior depends on server-side permissions and policy enforcement.
- Bulk import/share/attachments are intentionally out of initial write GA scope.
