use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn cli_requires_profile_for_tenant_isolation() {
    Command::cargo_bin("vaultwarden-cli")
        .expect("binary should build")
        .arg("status")
        .assert()
        .failure()
        .stderr(predicate::str::contains("--profile"));
}

#[test]
fn login_requires_client_secret_without_keyring_fallback() {
    Command::cargo_bin("vaultwarden-cli")
        .expect("binary should build")
        .args([
            "--profile",
            "agent-alpha",
            "login",
            "--server",
            "https://vault.example.com",
            "--client-id",
            "user.abc",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Client secret is required"));
}

#[test]
fn status_emits_machine_readable_json() {
    Command::cargo_bin("vaultwarden-cli")
        .expect("binary should build")
        .args(["--profile", "agent-alpha", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"profile\": \"agent-alpha\""))
        .stdout(predicate::str::contains("\"logged_in\": false"));
}
