mod support;

use predicates::prelude::*;
use support::{encrypted_user_key, env_lock, test_crypto_keys, TestContext};
use vaultwarden_cli::config::Config;

#[test]
fn status_reports_logged_out_when_no_config_exists() {
    let ctx = TestContext::new();

    ctx.binary()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Status: Not logged in"));
}

#[test]
fn logout_is_a_no_op_when_not_logged_in() {
    let ctx = TestContext::new();

    ctx.binary()
        .arg("logout")
        .assert()
        .success()
        .stdout(predicate::str::contains("Not currently logged in."));
}

#[test]
fn run_requires_a_selector_when_not_searching_by_uri() {
    let ctx = TestContext::new();

    ctx.binary()
        .arg("run")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "At least one of --name, --org, --folder, or --collection must be specified.",
        ));
}

#[test]
fn status_reports_logged_in_locked_details_from_saved_config() {
    let ctx = TestContext::new();
    ctx.write_config(&Config {
        server: Some("https://vault.example.com".to_string()),
        client_id: Some("client-id".to_string()),
        email: Some("user@example.com".to_string()),
        access_token: Some("token".to_string()),
        token_expiry: Some(1),
        ..Default::default()
    })
    .unwrap();

    ctx.binary()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Status: Logged in"))
        .stdout(predicate::str::contains(
            "Server: https://vault.example.com",
        ))
        .stdout(predicate::str::contains("Client ID: client-id"))
        .stdout(predicate::str::contains("Email: user@example.com"))
        .stdout(predicate::str::contains("Token: Expired"))
        .stdout(predicate::str::contains("Vault: Locked"));
}

#[test]
fn status_reports_unlocked_when_saved_keys_exist() {
    let ctx = TestContext::new();
    ctx.write_config(&Config {
        server: Some("https://vault.example.com".to_string()),
        access_token: Some("token".to_string()),
        ..Default::default()
    })
    .unwrap();
    ctx.write_saved_user_keys(&test_crypto_keys()).unwrap();

    ctx.binary()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Status: Logged in"))
        .stdout(predicate::str::contains("Vault: Unlocked"));
}

#[test]
fn unlock_reads_password_from_environment() {
    let _env_guard = env_lock();
    let ctx = TestContext::new();
    ctx.set_process_env();
    let email = "user@example.com";
    let password = "MySecurePassword123!";
    let keys = test_crypto_keys();

    ctx.write_config(&Config {
        server: Some("https://vault.example.com".to_string()),
        email: Some(email.to_string()),
        access_token: Some("token".to_string()),
        token_expiry: Some(i64::MAX),
        encrypted_key: Some(encrypted_user_key(password, email, 600000, &keys)),
        kdf_iterations: Some(600000),
        ..Default::default()
    })
    .unwrap();

    ctx.binary()
        .arg("unlock")
        .env("VAULTWARDEN_PASSWORD", password)
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault unlocked successfully!"));

    let saved = Config::load().unwrap();
    let saved_keys = saved.crypto_keys.expect("saved user keys");
    assert_eq!(saved_keys.enc_key, keys.enc_key);
    assert_eq!(saved_keys.mac_key, keys.mac_key);
}
