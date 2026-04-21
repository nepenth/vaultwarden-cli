# Live End-to-End Testing

This repository includes a local-only live integration harness that exercises `vaultwarden-cli` against a real Vaultwarden account without committing the vault URL, client credentials, master password, or fixture IDs to git.

The harness is intentionally designed for manual runs on a developer machine. It is not wired into GitHub Actions or any CI/CD workflow.

## What The Live Suite Covers

The ignored `tests/live_e2e.rs` suite targets the full supported CLI surface against a dedicated test user:

- `login`
- `logout`
- `status`
- `list`
  - unfiltered
  - `--type`
  - `--search`
  - `--org` by name and ID
  - `--collection` by name and ID
- `get`
  - by ID
  - by exact name
  - JSON, env, username, and password outputs
  - org and collection filters
- `get-uri`
  - JSON, username, and password outputs
  - org and collection filters
- `run`
  - positional selectors
  - `--name`
  - `--folder`
  - `--org`
  - `--collection`
  - `--info`
  - actual env injection into a child process
- `run-uri`
  - `--info`
  - actual env injection into a child process
- `write create`
  - personal and org scope
  - `--dry-run`
- `write update`
  - login and note items
  - `--dry-run`
- `write upsert`
  - personal scope create/update
  - org scope create/update
  - `--dry-run`
- `write rotate-password`
  - mutation path
  - `--dry-run`
- `write patch-fields`
  - mutation path
  - `--dry-run`
- `write move`
  - folder assignment and favorite patch
  - `--dry-run`

## Safety Model

- Runtime secrets are supplied through environment variables or `*_FILE` indirection only.
- `.env.live-e2e.local` and `.live-e2e/` are gitignored.
- The suite runs the compiled CLI as a subprocess with a temporary `HOME` and `XDG_CONFIG_HOME`.
- The suite only mutates items it creates itself under the configured namespace.
- The suite stays within the provided live test user and any explicitly configured org/collection fixtures for that same user.
- Read-only fixture items are never modified.
- Cleanup deletes created items through the Vaultwarden API at the end of the run.
- Do not run two live suites at the same time with the same namespace.

## Required Runtime Settings

Required:

- `VW_LIVE_E2E_SERVER`
- `VW_LIVE_E2E_CLIENT_ID`
- `VW_LIVE_E2E_CLIENT_SECRET` or `VW_LIVE_E2E_CLIENT_SECRET_FILE`
- `VW_LIVE_E2E_MASTER_PASSWORD` or `VW_LIVE_E2E_MASTER_PASSWORD_FILE`

Optional:

- `VW_LIVE_E2E_NAMESPACE`
  - default: `default`
- `VW_LIVE_E2E_FIXTURE_FILE`
  - default: `.live-e2e/fixture.json`

## Fixture File Contract

The live suite needs a small local JSON file describing stable resources that already exist inside the live test account:

- one personal folder
- one organization the test user belongs to
- one collection inside that organization
- one read-only card item
- one read-only identity item
- one read-only SSH item

The JSON shape is:

```json
{
  "personal": {
    "folder": {
      "id": "folder-id",
      "name": "folder-name"
    }
  },
  "organization": {
    "id": "org-id",
    "name": "org-name",
    "collection": {
      "id": "collection-id",
      "name": "collection-name"
    }
  },
  "readonly_items": {
    "card": {
      "id": "card-id",
      "name": "card-name"
    },
    "identity": {
      "id": "identity-id",
      "name": "identity-name"
    },
    "ssh": {
      "id": "ssh-id",
      "name": "ssh-name"
    }
  }
}
```

A committed template is available at `docs/live-e2e.fixture.example.json`.

## Local Setup

1. Create local secret storage and config files:

```bash
cp .env.live-e2e.example .env.live-e2e.local
mkdir -p .live-e2e
cp docs/live-e2e.fixture.example.json .live-e2e/fixture.json
printf '%s' 'your-client-secret' > .live-e2e/client-secret
printf '%s' 'your-master-password' > .live-e2e/master-password
chmod 600 .live-e2e/client-secret .live-e2e/master-password
```

2. Edit `.env.live-e2e.local`:

- set `VW_LIVE_E2E_SERVER`
- set `VW_LIVE_E2E_CLIENT_ID`
- point `VW_LIVE_E2E_CLIENT_SECRET_FILE` and `VW_LIVE_E2E_MASTER_PASSWORD_FILE` at your local files
- set `VW_LIVE_E2E_NAMESPACE`
- fill `.live-e2e/fixture.json` with real IDs and names from the live test account

3. Run the harness:

```bash
./scripts/live-e2e.sh
```

Or with `just`:

```bash
just test-live-e2e
```

You can pass normal `cargo test` build flags through the wrapper:

```bash
./scripts/live-e2e.sh --release
```

## Operational Notes

- Use a dedicated test account, not a human operator account.
- Reuse a namespace for stable reruns against the same environment.
- Pick a different namespace for a second environment or concurrent manual testing.
- If the wrapper reports that the fixture file is unreadable, check `VW_LIVE_E2E_FIXTURE_FILE` and local file permissions first.
- If the suite fails on ambiguity, remove the duplicate names/URIs for that namespace or choose a fresh namespace.
- If cleanup fails, inspect the reported cipher IDs and remove the leftovers before the next run.
