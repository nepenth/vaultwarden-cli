use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn command_with_temp_home() -> (Command, TempDir) {
    let tmp = TempDir::new().expect("temp dir should be created");
    let mut cmd = Command::cargo_bin("vaultwarden-cli").expect("binary should build");
    cmd.env("HOME", tmp.path());
    cmd.env("XDG_CONFIG_HOME", tmp.path());
    (cmd, tmp)
}

#[test]
fn cli_requires_profile_for_tenant_isolation() {
    let (mut cmd, _tmp) = command_with_temp_home();
    cmd.arg("status")
        .assert()
        .failure()
        .stderr(predicate::str::contains("--profile"));
}

#[test]
fn login_requires_client_secret_without_keyring_fallback() {
    let (mut cmd, _tmp) = command_with_temp_home();
    cmd.args([
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
fn login_rejects_secret_cli_flag() {
    let (mut cmd, _tmp) = command_with_temp_home();
    cmd.args([
        "--profile",
        "agent-alpha",
        "login",
        "--server",
        "https://vault.example.com",
        "--client-id",
        "user.abc",
        "--client-secret",
        "dont-allow-this",
    ])
    .assert()
    .failure()
    .stderr(predicate::str::contains(
        "unexpected argument '--client-secret'",
    ));
}

#[test]
fn status_emits_machine_readable_json() {
    let (mut cmd, _tmp) = command_with_temp_home();
    cmd.args(["--profile", "agent-alpha", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"profile\": \"agent-alpha\""))
        .stdout(predicate::str::contains("\"logged_in\": false"))
        .stdout(predicate::str::contains("\"token_expired\": false"));
}

#[test]
fn cli_rejects_password_flag_instead_of_stdin_mode() {
    let (mut cmd, _tmp) = command_with_temp_home();
    cmd.args(["--profile", "agent-alpha", "--password", "secret", "status"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument '--password'"));
}

#[test]
fn write_create_requires_password_stdin_with_stdin_input() {
    let (mut cmd, _tmp) = command_with_temp_home();
    cmd.args([
        "--profile",
        "agent-alpha",
        "write",
        "create",
        "--input",
        "-",
    ])
    .assert()
    .failure()
    .stdout(predicate::str::contains("\"code\": \"VALIDATION_ERROR\""))
    .stdout(predicate::str::contains("--password-stdin is required"));
}
