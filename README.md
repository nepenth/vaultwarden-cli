# vaultwarden-cli

Agent-first, Rust-native CLI for [Vaultwarden](https://github.com/dani-garcia/vaultwarden).

This project is now intentionally scoped to autonomous agent workflows with explicit tenant isolation, runtime decryption, and Linux/macOS support only.

## Scope (Current Direction)

- Target platforms: Linux and macOS
- Out of scope: Windows support
- Backward compatibility: not guaranteed (agent-first behavior takes priority)
- Retrieval-first today; write support is the next implementation phase

## Agent-First Design

### 1. Explicit profile tenancy

Every invocation must provide a profile (`--profile` or `VAULTWARDEN_PROFILE`).

Profiles are stored independently:

- Linux: `~/.config/vaultwarden-cli/profiles/<profile>/config.json`
- macOS: `~/Library/Application Support/com.vaultwarden.vaultwarden-cli/profiles/<profile>/config.json`

### 2. No keyring usage

This CLI does not use OS keyrings. Client secrets are not persisted in keyring backends.

### 3. Runtime-only vault decryption

The CLI does not persist decrypted vault keys to disk. For retrieval commands, you provide the master password at runtime (`--password` or `VAULTWARDEN_PASSWORD`).

### 4. Machine-parseable outputs

Session/status and list outputs are JSON by default for agent orchestration.

## Installation

### From source

```bash
git clone https://github.com/nepenth/vaultwarden-cli.git
cd vaultwarden-cli
cargo build --release
```

Binary path:

```bash
target/release/vaultwarden-cli
```

## Usage

## Authentication

```bash
vaultwarden-cli \
  --profile agent-alpha \
  login \
  --server https://vault.example.com \
  --client-id "$VAULTWARDEN_CLIENT_ID" \
  --client-secret "$VAULTWARDEN_CLIENT_SECRET"
```

## Status

```bash
vaultwarden-cli --profile agent-alpha status
```

Returns JSON.

## List secrets (JSON)

```bash
vaultwarden-cli \
  --profile agent-alpha \
  --password "$VAULTWARDEN_PASSWORD" \
  list
```

Optional filters:

```bash
vaultwarden-cli --profile agent-alpha --password "$VAULTWARDEN_PASSWORD" list --type login
vaultwarden-cli --profile agent-alpha --password "$VAULTWARDEN_PASSWORD" list --search github
vaultwarden-cli --profile agent-alpha --password "$VAULTWARDEN_PASSWORD" list --org "Engineering"
vaultwarden-cli --profile agent-alpha --password "$VAULTWARDEN_PASSWORD" list --collection "Production"
```

## Get one secret

```bash
vaultwarden-cli --profile agent-alpha --password "$VAULTWARDEN_PASSWORD" get "My Login"
vaultwarden-cli --profile agent-alpha --password "$VAULTWARDEN_PASSWORD" get "My Login" --format value
vaultwarden-cli --profile agent-alpha --password "$VAULTWARDEN_PASSWORD" get "My Login" --format username
vaultwarden-cli --profile agent-alpha --password "$VAULTWARDEN_PASSWORD" get "My Login" --format env
```

Get by URI substring:

```bash
vaultwarden-cli --profile agent-alpha --password "$VAULTWARDEN_PASSWORD" get-uri github.com
```

## Run a process with injected secrets

```bash
vaultwarden-cli \
  --profile agent-alpha \
  --password "$VAULTWARDEN_PASSWORD" \
  run --name "My Login" -- ./deploy.sh
```

Preview injected environment variable names only:

```bash
vaultwarden-cli \
  --profile agent-alpha \
  --password "$VAULTWARDEN_PASSWORD" \
  run --name "My Login" --info
```

## Logout

```bash
vaultwarden-cli --profile agent-alpha logout
```

## Security Notes

- Tenant isolation is profile-scoped. Use a unique profile per agent identity.
- Decryption keys are runtime-only and not persisted to disk.
- Session material is stored in profile-local config with restrictive file permissions on Unix-like systems.
- Secret exposure control is still your responsibility at orchestration boundaries (logs, shell history, process introspection).

## Development

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Optional pre-commit hook:

```bash
git config core.hooksPath .githooks
```

## Next Milestone

Planned next major implementation: write support (create/update secrets) for agent workflows.

## License

MIT
