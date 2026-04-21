test:
    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features -- -D warnings
    cargo audit
    cargo deny check all
    cargo test
    ./scripts/security-regression.sh

pre-commit:
    ./scripts/scan-staged-secrets.sh
    cargo fmt --all
    cargo clippy --all-targets --all-features -- -D warnings
    cargo audit
    cargo deny check all
    cargo test
    ./scripts/security-regression.sh

release *args:
    git pull --rebase
    cargo release {{args}}

install:
    cargo install --path .

test-live-e2e *args:
    ./scripts/live-e2e.sh {{args}}
