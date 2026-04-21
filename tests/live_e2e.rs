use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::TempDir;
use vaultwarden_cli::api::ApiClient;

const PERSONAL_LOGIN_PASSWORD: &str = "vaultwarden-cli-e2e-personal-login";
const PERSONAL_LOGIN_ROTATED_PASSWORD: &str = "vaultwarden-cli-e2e-personal-rotated";
const ORG_LOGIN_PASSWORD: &str = "vaultwarden-cli-e2e-org-login";
const ORG_UPSERT_LOGIN_PASSWORD: &str = "vaultwarden-cli-e2e-org-upsert-login";
const ORG_UPSERT_LOGIN_ROTATED_PASSWORD: &str = "vaultwarden-cli-e2e-org-upsert-rotated";
const UPSERT_LOGIN_PASSWORD: &str = "vaultwarden-cli-e2e-upsert-login";
const UPSERT_LOGIN_ROTATED_PASSWORD: &str = "vaultwarden-cli-e2e-upsert-rotated";
const PATCHED_FIELD_NAME: &str = "api_key";
const PATCHED_FIELD_VALUE: &str = "field-live-value";

#[derive(Clone)]
struct LiveE2eConfig {
    server: String,
    client_id: String,
    client_secret: String,
    master_password: String,
    namespace: String,
    fixture_file: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
struct FixtureFile {
    personal: PersonalFixtures,
    organization: OrganizationFixtures,
    readonly_items: ReadonlyFixtures,
}

#[derive(Debug, Clone, Deserialize)]
struct PersonalFixtures {
    folder: NamedFixture,
}

#[derive(Debug, Clone, Deserialize)]
struct OrganizationFixtures {
    id: String,
    name: String,
    collection: NamedFixture,
}

#[derive(Debug, Clone, Deserialize)]
struct ReadonlyFixtures {
    card: CipherFixture,
    identity: CipherFixture,
    ssh: CipherFixture,
}

#[derive(Debug, Clone, Deserialize)]
struct NamedFixture {
    id: String,
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct CipherFixture {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct LoginResponse {
    ok: bool,
    profile: String,
}

#[derive(Deserialize)]
struct LogoutResponse {
    ok: bool,
    had_session: bool,
}

#[derive(Deserialize)]
struct StatusResponse {
    profile: String,
    logged_in: bool,
    token_expired: bool,
}

#[derive(Debug, Deserialize)]
struct WriteSuccess {
    ok: bool,
    operation: String,
    id: String,
    revision_date: Option<String>,
    warnings: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DecryptedField {
    name: String,
    value: String,
    hidden: bool,
}

#[derive(Debug, Deserialize)]
struct DecryptedCipher {
    id: String,
    #[serde(rename = "type")]
    cipher_type: String,
    name: String,
    folder_id: Option<String>,
    favorite: Option<bool>,
    username: Option<String>,
    password: Option<String>,
    uri: Option<String>,
    notes: Option<String>,
    fields: Option<Vec<DecryptedField>>,
    ssh_public_key: Option<String>,
    ssh_private_key: Option<String>,
    ssh_fingerprint: Option<String>,
}

#[derive(Default)]
struct CleanupGuard {
    server: Option<String>,
    access_token: Option<String>,
    created_cipher_ids: Vec<String>,
}

impl CleanupGuard {
    fn new() -> Self {
        Self {
            server: None,
            access_token: None,
            created_cipher_ids: Vec::new(),
        }
    }

    fn cache_session(&mut self, server: &str, access_token: &str) {
        self.server = Some(server.to_string());
        self.access_token = Some(access_token.to_string());
    }

    fn register_cipher(&mut self, cipher_id: &str) {
        if !self.created_cipher_ids.iter().any(|id| id == cipher_id) {
            self.created_cipher_ids.push(cipher_id.to_string());
        }
    }

    fn cleanup(&mut self) -> Result<()> {
        if self.created_cipher_ids.is_empty() {
            return Ok(());
        }

        let server = self
            .server
            .clone()
            .context("Cleanup is missing a cached server URL")?;
        let access_token = self
            .access_token
            .clone()
            .context("Cleanup is missing a cached access token")?;

        let api = ApiClient::new(&server)?;
        let runtime = tokio::runtime::Runtime::new().context("Failed to create cleanup runtime")?;

        for cipher_id in self.created_cipher_ids.drain(..).rev() {
            runtime
                .block_on(api.delete_cipher(&access_token, &cipher_id))
                .with_context(|| format!("Failed to delete live e2e cipher {}", cipher_id))?;
        }

        Ok(())
    }
}

impl LiveE2eConfig {
    fn from_env() -> Result<Self> {
        let fixture_file = std::env::var("VW_LIVE_E2E_FIXTURE_FILE")
            .unwrap_or_else(|_| ".live-e2e/fixture.json".to_string());

        Ok(Self {
            server: required_env("VW_LIVE_E2E_SERVER")?,
            client_id: required_env("VW_LIVE_E2E_CLIENT_ID")?,
            client_secret: required_env("VW_LIVE_E2E_CLIENT_SECRET")?,
            master_password: required_env("VW_LIVE_E2E_MASTER_PASSWORD")?,
            namespace: normalize_component(
                &std::env::var("VW_LIVE_E2E_NAMESPACE").unwrap_or_else(|_| "default".to_string()),
            ),
            fixture_file: PathBuf::from(fixture_file),
        })
    }

    fn load_fixtures(&self) -> Result<FixtureFile> {
        let raw = std::fs::read_to_string(&self.fixture_file).with_context(|| {
            format!(
                "Failed to read live e2e fixture file {}",
                self.fixture_file.display()
            )
        })?;
        serde_json::from_str(&raw).with_context(|| {
            format!(
                "Failed to parse live e2e fixture file {}",
                self.fixture_file.display()
            )
        })
    }

    fn profile(&self) -> String {
        format!("live-e2e-{}", self.namespace)
    }

    fn personal_login_name(&self) -> String {
        format!("vaultwarden-cli-e2e-personal-login-{}", self.namespace)
    }

    fn personal_note_name(&self) -> String {
        format!("vaultwarden-cli-e2e-personal-note-{}", self.namespace)
    }

    fn org_login_name(&self) -> String {
        format!("vaultwarden-cli-e2e-org-login-{}", self.namespace)
    }

    fn org_note_name(&self) -> String {
        format!("vaultwarden-cli-e2e-org-note-{}", self.namespace)
    }

    fn org_upsert_login_name(&self) -> String {
        format!("vaultwarden-cli-e2e-org-upsert-login-{}", self.namespace)
    }

    fn upsert_login_name(&self) -> String {
        format!("vaultwarden-cli-e2e-upsert-login-{}", self.namespace)
    }

    fn personal_login_uri(&self) -> String {
        format!(
            "https://vaultwarden-cli.invalid/live-e2e/personal-login/{}",
            self.namespace
        )
    }

    fn org_login_uri(&self) -> String {
        format!(
            "https://vaultwarden-cli.invalid/live-e2e/org-login/{}",
            self.namespace
        )
    }

    fn org_upsert_login_uri(&self) -> String {
        format!(
            "https://vaultwarden-cli.invalid/live-e2e/org-upsert-login/{}",
            self.namespace
        )
    }

    fn upsert_login_uri(&self) -> String {
        format!(
            "https://vaultwarden-cli.invalid/live-e2e/upsert-login/{}",
            self.namespace
        )
    }

    fn personal_username(&self) -> String {
        format!("personal-{}", self.namespace)
    }

    fn org_username(&self) -> String {
        format!("org-{}", self.namespace)
    }

    fn org_upsert_username(&self) -> String {
        format!("org-upsert-{}", self.namespace)
    }

    fn upsert_username(&self) -> String {
        format!("upsert-{}", self.namespace)
    }
}

fn required_env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("Missing required environment variable {name}"))
}

fn normalize_component(raw: &str) -> String {
    let mut normalized = String::new();
    let mut last_was_dash = false;

    for ch in raw.chars() {
        let mapped = if ch.is_ascii_alphanumeric() {
            last_was_dash = false;
            ch.to_ascii_lowercase()
        } else if last_was_dash {
            continue;
        } else {
            last_was_dash = true;
            '-'
        };
        normalized.push(mapped);
        if normalized.len() >= 24 {
            break;
        }
    }

    let trimmed = normalized.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "default".to_string()
    } else {
        trimmed
    }
}

fn sanitize_env_name(name: &str) -> String {
    let raw: String = name
        .to_ascii_uppercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();

    let mut normalized = raw.trim_matches('_').to_string();
    if normalized.is_empty() {
        normalized.push_str("SECRET");
    }

    if normalized
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_digit())
    {
        normalized.insert(0, '_');
    }

    normalized
}

fn stdin_secret(secret: &str) -> String {
    format!("{secret}\n")
}

fn stdin_secret_and_json(secret: &str, payload: serde_json::Value) -> Result<String> {
    Ok(format!(
        "{secret}\n{}",
        serde_json::to_string(&payload).context("Failed to serialize live e2e payload")?
    ))
}

fn parse_json<T: DeserializeOwned>(label: &str, stdout: &str) -> Result<T> {
    serde_json::from_str(stdout).with_context(|| format!("Failed to parse {label} JSON output"))
}

fn require_revision(output: &WriteSuccess, label: &str) -> Result<String> {
    output
        .revision_date
        .clone()
        .with_context(|| format!("{label} did not return a revision date"))
}

fn ensure_no_warnings(output: &WriteSuccess, label: &str) -> Result<()> {
    ensure(
        output.warnings.is_empty(),
        &format!("{label} returned unexpected warnings"),
    )
}

fn ensure_warnings_eq(output: &WriteSuccess, expected: &[&str], label: &str) -> Result<()> {
    let expected: Vec<String> = expected.iter().map(|value| (*value).to_string()).collect();
    ensure(
        output.warnings == expected,
        &format!("{label} returned unexpected warnings"),
    )
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        bail!(message.to_string())
    }
}

fn ensure_text_eq(actual: &str, expected: &str, label: &str) -> Result<()> {
    if actual.trim_end_matches(['\n', '\r']) == expected {
        Ok(())
    } else {
        bail!("{label} mismatch")
    }
}

fn resolve_cli_binary() -> Result<PathBuf> {
    for key in [
        "CARGO_BIN_EXE_vaultwarden-cli",
        "CARGO_BIN_EXE_vaultwarden_cli",
    ] {
        if let Some(value) = std::env::var_os(key) {
            if !value.is_empty() {
                return Ok(PathBuf::from(value));
            }
        }
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for candidate in [
        manifest_dir.join("target/debug/vaultwarden-cli"),
        manifest_dir.join("target/release/vaultwarden-cli"),
    ] {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    bail!(
        "Missing CARGO_BIN_EXE_vaultwarden-cli/CARGO_BIN_EXE_vaultwarden_cli and no local target binary was found"
    )
}

fn run_cli(
    temp_home: &TempDir,
    label: &str,
    args: &[String],
    stdin_data: Option<&str>,
    extra_env: &[(String, String)],
) -> Result<String> {
    let binary = resolve_cli_binary()?;

    let mut command = Command::new(binary);
    command.args(args);
    command.env("HOME", temp_home.path());
    command.env("XDG_CONFIG_HOME", temp_home.path());
    command.env_remove("VAULTWARDEN_PROFILE");

    for (key, value) in extra_env {
        command.env(key, value);
    }

    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    if stdin_data.is_some() {
        command.stdin(Stdio::piped());
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("Failed to spawn {label} command"))?;

    if let Some(input) = stdin_data {
        child
            .stdin
            .as_mut()
            .context("Failed to acquire child stdin for live e2e command")?
            .write_all(input.as_bytes())
            .with_context(|| format!("Failed to write stdin for {label} command"))?;
    }

    let output = child
        .wait_with_output()
        .with_context(|| format!("Failed to wait for {label} command"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

        if !stderr.is_empty() || !stdout.is_empty() {
            bail!(
                "{label} command failed with status {} (stderr: {:?}, stdout: {:?})",
                output.status,
                stderr,
                stdout
            );
        }

        bail!("{label} command failed with status {}", output.status);
    }

    String::from_utf8(output.stdout).with_context(|| format!("Non-utf8 stdout from {label}"))
}

fn login_and_cache_session(
    temp_home: &TempDir,
    cfg: &LiveE2eConfig,
    cleanup: &mut CleanupGuard,
) -> Result<String> {
    let profile = cfg.profile();
    let login: LoginResponse = parse_json(
        "login",
        &run_cli(
            temp_home,
            "login",
            &[
                "--profile".to_string(),
                profile.clone(),
                "login".to_string(),
                "--server".to_string(),
                cfg.server.clone(),
                "--client-id".to_string(),
                cfg.client_id.clone(),
                "--client-secret-stdin".to_string(),
            ],
            Some(&stdin_secret(&cfg.client_secret)),
            &[],
        )?,
    )?;
    ensure(login.ok, "login did not report success")?;
    ensure(
        login.profile == profile,
        "login returned an unexpected profile",
    )?;

    cleanup.cache_session(&cfg.server, &load_access_token(temp_home.path(), &profile)?);
    Ok(profile)
}

fn load_access_token(temp_home: &Path, profile: &str) -> Result<String> {
    let config_path = find_profile_config_path(temp_home, profile)
        .with_context(|| format!("Failed to locate cached config for profile {profile}"))?;
    let raw = std::fs::read_to_string(&config_path).with_context(|| {
        format!(
            "Failed to read cached config from {}",
            config_path.display()
        )
    })?;
    let config: vaultwarden_cli::config::Config =
        serde_json::from_str(&raw).context("Failed to parse cached profile config")?;
    config
        .access_token
        .context("Missing access token in cached live e2e profile config")
}

fn find_profile_config_path(root: &Path, profile: &str) -> Result<PathBuf> {
    let expected_suffix = Path::new("profiles").join(profile).join("config.json");
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("Failed to read directory {}", dir.display()))?
        {
            let entry =
                entry.with_context(|| format!("Failed to inspect directory {}", dir.display()))?;
            let path = entry.path();
            let file_type = entry.file_type().with_context(|| {
                format!(
                    "Failed to read file type for directory entry {}",
                    path.display()
                )
            })?;

            if file_type.is_dir() {
                stack.push(path);
                continue;
            }

            if file_type.is_file() && path.ends_with(&expected_suffix) {
                return Ok(path);
            }
        }
    }

    bail!(
        "No cached config.json found under {} for profile {}",
        root.display(),
        profile
    )
}

fn status(temp_home: &TempDir, profile: &str, label: &str) -> Result<StatusResponse> {
    parse_json(
        label,
        &run_cli(
            temp_home,
            label,
            &[
                "--profile".to_string(),
                profile.to_string(),
                "status".to_string(),
            ],
            None,
            &[],
        )?,
    )
}

fn list_ciphers(
    temp_home: &TempDir,
    profile: &str,
    master_password: &str,
    label: &str,
    extra_args: &[String],
) -> Result<Vec<DecryptedCipher>> {
    let mut args = vec![
        "--profile".to_string(),
        profile.to_string(),
        "--password-stdin".to_string(),
        "list".to_string(),
    ];
    args.extend(extra_args.iter().cloned());

    parse_json(
        label,
        &run_cli(
            temp_home,
            label,
            &args,
            Some(&stdin_secret(master_password)),
            &[],
        )?,
    )
}

fn get_cipher_json(
    temp_home: &TempDir,
    profile: &str,
    master_password: &str,
    label: &str,
    item: &str,
    extra_args: &[String],
) -> Result<DecryptedCipher> {
    let mut args = vec![
        "--profile".to_string(),
        profile.to_string(),
        "--password-stdin".to_string(),
        "get".to_string(),
        item.to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    args.extend(extra_args.iter().cloned());

    parse_json(
        label,
        &run_cli(
            temp_home,
            label,
            &args,
            Some(&stdin_secret(master_password)),
            &[],
        )?,
    )
}

fn get_uri_json(
    temp_home: &TempDir,
    profile: &str,
    master_password: &str,
    label: &str,
    uri: &str,
    extra_args: &[String],
) -> Result<DecryptedCipher> {
    let mut args = vec![
        "--profile".to_string(),
        profile.to_string(),
        "--password-stdin".to_string(),
        "get-uri".to_string(),
        uri.to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    args.extend(extra_args.iter().cloned());

    parse_json(
        label,
        &run_cli(
            temp_home,
            label,
            &args,
            Some(&stdin_secret(master_password)),
            &[],
        )?,
    )
}

fn get_text(
    temp_home: &TempDir,
    profile: &str,
    master_password: &str,
    label: &str,
    item: &str,
    extra_args: &[String],
) -> Result<String> {
    let mut args = vec![
        "--profile".to_string(),
        profile.to_string(),
        "--password-stdin".to_string(),
        "get".to_string(),
        item.to_string(),
    ];
    args.extend(extra_args.iter().cloned());

    run_cli(
        temp_home,
        label,
        &args,
        Some(&stdin_secret(master_password)),
        &[],
    )
}

fn get_uri_text(
    temp_home: &TempDir,
    profile: &str,
    master_password: &str,
    label: &str,
    uri: &str,
    extra_args: &[String],
) -> Result<String> {
    let mut args = vec![
        "--profile".to_string(),
        profile.to_string(),
        "--password-stdin".to_string(),
        "get-uri".to_string(),
        uri.to_string(),
    ];
    args.extend(extra_args.iter().cloned());

    run_cli(
        temp_home,
        label,
        &args,
        Some(&stdin_secret(master_password)),
        &[],
    )
}

fn run_info(
    temp_home: &TempDir,
    profile: &str,
    master_password: &str,
    label: &str,
    selector_args: &[String],
) -> Result<Vec<String>> {
    let mut args = vec![
        "--profile".to_string(),
        profile.to_string(),
        "--password-stdin".to_string(),
        "run".to_string(),
    ];
    args.extend(selector_args.iter().cloned());
    args.push("--info".to_string());

    parse_json(
        label,
        &run_cli(
            temp_home,
            label,
            &args,
            Some(&stdin_secret(master_password)),
            &[],
        )?,
    )
}

fn run_command(
    temp_home: &TempDir,
    profile: &str,
    master_password: &str,
    label: &str,
    selector_args: &[String],
    command_args: &[String],
    extra_env: &[(String, String)],
) -> Result<()> {
    let mut args = vec![
        "--profile".to_string(),
        profile.to_string(),
        "--password-stdin".to_string(),
        "run".to_string(),
    ];
    args.extend(selector_args.iter().cloned());
    args.push("--".to_string());
    args.extend(command_args.iter().cloned());

    run_cli(
        temp_home,
        label,
        &args,
        Some(&stdin_secret(master_password)),
        extra_env,
    )?;
    Ok(())
}

fn run_uri_info(
    temp_home: &TempDir,
    profile: &str,
    master_password: &str,
    label: &str,
    uri: &str,
) -> Result<Vec<String>> {
    parse_json(
        label,
        &run_cli(
            temp_home,
            label,
            &[
                "--profile".to_string(),
                profile.to_string(),
                "--password-stdin".to_string(),
                "run-uri".to_string(),
                uri.to_string(),
                "--info".to_string(),
            ],
            Some(&stdin_secret(master_password)),
            &[],
        )?,
    )
}

fn run_uri_command(
    temp_home: &TempDir,
    profile: &str,
    master_password: &str,
    label: &str,
    uri: &str,
    command_args: &[String],
    extra_env: &[(String, String)],
) -> Result<()> {
    let mut args = vec![
        "--profile".to_string(),
        profile.to_string(),
        "--password-stdin".to_string(),
        "run-uri".to_string(),
        uri.to_string(),
        "--".to_string(),
    ];
    args.extend(command_args.iter().cloned());

    run_cli(
        temp_home,
        label,
        &args,
        Some(&stdin_secret(master_password)),
        extra_env,
    )?;
    Ok(())
}

fn write_json(
    temp_home: &TempDir,
    profile: &str,
    master_password: &str,
    label: &str,
    command_parts: &[String],
    payload: serde_json::Value,
) -> Result<WriteSuccess> {
    let mut args = vec![
        "--profile".to_string(),
        profile.to_string(),
        "--password-stdin".to_string(),
    ];
    args.extend(command_parts.iter().cloned());
    args.push("--input".to_string());
    args.push("-".to_string());

    parse_json(
        label,
        &run_cli(
            temp_home,
            label,
            &args,
            Some(&stdin_secret_and_json(master_password, payload)?),
            &[],
        )?,
    )
}

fn write_move(
    temp_home: &TempDir,
    profile: &str,
    master_password: &str,
    label: &str,
    extra_args: &[String],
) -> Result<WriteSuccess> {
    let mut args = vec![
        "--profile".to_string(),
        profile.to_string(),
        "--password-stdin".to_string(),
        "write".to_string(),
        "move".to_string(),
    ];
    args.extend(extra_args.iter().cloned());

    parse_json(
        label,
        &run_cli(
            temp_home,
            label,
            &args,
            Some(&stdin_secret(master_password)),
            &[],
        )?,
    )
}

fn verify_login_cipher(
    cipher: &DecryptedCipher,
    expected_name: &str,
    expected_username: &str,
    expected_password: &str,
    expected_uri: &str,
) -> Result<()> {
    ensure(cipher.cipher_type == "login", "expected a login cipher")?;
    ensure(cipher.name == expected_name, "unexpected login item name")?;
    ensure(
        cipher.username.as_deref() == Some(expected_username),
        "unexpected login username",
    )?;
    ensure(
        cipher.password.as_deref() == Some(expected_password),
        "unexpected login password",
    )?;
    ensure(
        cipher.uri.as_deref() == Some(expected_uri),
        "unexpected login URI",
    )
}

fn verify_note_cipher(
    cipher: &DecryptedCipher,
    expected_name: &str,
    expected_notes: &str,
) -> Result<()> {
    ensure(cipher.cipher_type == "note", "expected a note cipher")?;
    ensure(cipher.name == expected_name, "unexpected note item name")?;
    ensure(
        cipher.notes.as_deref() == Some(expected_notes),
        "unexpected note contents",
    )
}

fn assert_cipher_id_in_list(
    ciphers: &[DecryptedCipher],
    expected_id: &str,
    label: &str,
) -> Result<()> {
    ensure(ciphers.iter().any(|cipher| cipher.id == expected_id), label)
}

fn run_full_flow(
    cfg: &LiveE2eConfig,
    fixtures: &FixtureFile,
    temp_home: &TempDir,
    cleanup: &mut CleanupGuard,
) -> Result<()> {
    let profile = cfg.profile();

    let initial_status = status(temp_home, &profile, "status before login")?;
    ensure(
        initial_status.profile == profile,
        "pre-login status returned wrong profile",
    )?;
    ensure(
        !initial_status.logged_in,
        "pre-login status should be logged out",
    )?;

    let profile = login_and_cache_session(temp_home, cfg, cleanup)?;

    let post_login_status = status(temp_home, &profile, "status after login")?;
    ensure(
        post_login_status.logged_in,
        "post-login status should be logged in",
    )?;
    ensure(
        !post_login_status.token_expired,
        "post-login status should not report token expiry",
    )?;

    let personal_login_name = cfg.personal_login_name();
    let personal_login_uri = cfg.personal_login_uri();
    let personal_username = cfg.personal_username();
    let personal_note_name = cfg.personal_note_name();
    let org_login_name = cfg.org_login_name();
    let org_login_uri = cfg.org_login_uri();
    let org_username = cfg.org_username();
    let org_note_name = cfg.org_note_name();
    let org_upsert_login_name = cfg.org_upsert_login_name();
    let org_upsert_login_uri = cfg.org_upsert_login_uri();
    let org_upsert_username = cfg.org_upsert_username();
    let upsert_login_name = cfg.upsert_login_name();
    let upsert_login_uri = cfg.upsert_login_uri();
    let upsert_username = cfg.upsert_username();
    let dry_run_create_name = format!("vaultwarden-cli-e2e-dry-run-create-{}", cfg.namespace);
    let dry_run_upsert_name = format!("vaultwarden-cli-e2e-dry-run-upsert-{}", cfg.namespace);
    let dry_run_upsert_uri = format!(
        "https://vaultwarden-cli.invalid/live-e2e/dry-run-upsert/{}",
        cfg.namespace
    );

    let dry_run_create = write_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "dry-run create",
        &[
            "write".to_string(),
            "create".to_string(),
            "--dry-run".to_string(),
        ],
        json!({
            "type": "note",
            "name": dry_run_create_name.clone(),
            "notes": "dry run create should not persist",
            "note": {"secure_note_type": 0}
        }),
    )?;
    ensure(dry_run_create.ok, "dry-run create did not report success")?;
    ensure(
        dry_run_create.operation == "create",
        "dry-run create returned the wrong operation",
    )?;
    ensure_no_warnings(&dry_run_create, "dry-run create")?;
    ensure(
        dry_run_create.id == "dry-run",
        "dry-run create should return the synthetic dry-run id",
    )?;

    let dry_run_create_search = list_ciphers(
        temp_home,
        &profile,
        &cfg.master_password,
        "list search for dry-run create",
        &["--search".to_string(), dry_run_create_name.clone()],
    )?;
    ensure(
        dry_run_create_search.is_empty(),
        "dry-run create unexpectedly persisted an item",
    )?;

    let personal_login_create = write_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "personal login create",
        &["write".to_string(), "create".to_string()],
        json!({
            "type": "login",
            "name": personal_login_name.clone(),
            "notes": "personal login baseline",
            "login": {
                "username": personal_username.clone(),
                "password": PERSONAL_LOGIN_PASSWORD,
                "uris": [{"uri": personal_login_uri.clone()}]
            }
        }),
    )?;
    ensure(
        personal_login_create.ok,
        "personal login create did not report success",
    )?;
    ensure(
        personal_login_create.operation == "create",
        "personal login create returned wrong operation",
    )?;
    ensure_no_warnings(&personal_login_create, "personal login create")?;
    cleanup.register_cipher(&personal_login_create.id);
    let mut personal_login_revision =
        require_revision(&personal_login_create, "personal login create")?;

    let personal_note_create = write_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "personal note create",
        &["write".to_string(), "create".to_string()],
        json!({
            "type": "note",
            "name": personal_note_name.clone(),
            "notes": "personal note baseline",
            "note": {"secure_note_type": 0}
        }),
    )?;
    ensure(
        personal_note_create.ok,
        "personal note create did not report success",
    )?;
    ensure_no_warnings(&personal_note_create, "personal note create")?;
    cleanup.register_cipher(&personal_note_create.id);
    let personal_note_revision = require_revision(&personal_note_create, "personal note create")?;

    let org_login_create = write_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "org login create",
        &["write".to_string(), "create".to_string()],
        json!({
            "type": "login",
            "name": org_login_name.clone(),
            "organization_id": fixtures.organization.id,
            "collection_ids": [fixtures.organization.collection.id.clone()],
            "notes": "org login baseline",
            "login": {
                "username": org_username.clone(),
                "password": ORG_LOGIN_PASSWORD,
                "uris": [{"uri": org_login_uri.clone()}]
            }
        }),
    )?;
    ensure(
        org_login_create.ok,
        "org login create did not report success",
    )?;
    ensure_no_warnings(&org_login_create, "org login create")?;
    cleanup.register_cipher(&org_login_create.id);
    let org_login_revision = require_revision(&org_login_create, "org login create")?;

    let org_note_create = write_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "org note create",
        &["write".to_string(), "create".to_string()],
        json!({
            "type": "note",
            "name": org_note_name.clone(),
            "organization_id": fixtures.organization.id,
            "collection_ids": [fixtures.organization.collection.id.clone()],
            "notes": "org note baseline",
            "note": {"secure_note_type": 0}
        }),
    )?;
    ensure(org_note_create.ok, "org note create did not report success")?;
    ensure_no_warnings(&org_note_create, "org note create")?;
    cleanup.register_cipher(&org_note_create.id);

    let upsert_create = write_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "upsert create",
        &[
            "write".to_string(),
            "upsert".to_string(),
            "--match".to_string(),
            "name_uri".to_string(),
            "--scope".to_string(),
            "personal".to_string(),
        ],
        json!({
            "type": "login",
            "name": upsert_login_name.clone(),
            "notes": "upsert create baseline",
            "login": {
                "username": upsert_username.clone(),
                "password": UPSERT_LOGIN_PASSWORD,
                "uris": [{"uri": upsert_login_uri.clone()}]
            }
        }),
    )?;
    ensure(
        upsert_create.operation == "upsert_create",
        "initial upsert should create a new item",
    )?;
    ensure_no_warnings(&upsert_create, "upsert create")?;
    cleanup.register_cipher(&upsert_create.id);
    let _ = require_revision(&upsert_create, "upsert create")?;

    let dry_run_upsert = write_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "dry-run upsert",
        &[
            "write".to_string(),
            "upsert".to_string(),
            "--match".to_string(),
            "name_uri".to_string(),
            "--scope".to_string(),
            "personal".to_string(),
            "--dry-run".to_string(),
        ],
        json!({
            "type": "login",
            "name": dry_run_upsert_name.clone(),
            "notes": "dry run upsert should not persist",
            "login": {
                "username": format!("dry-upsert-{}", cfg.namespace),
                "password": "vaultwarden-cli-e2e-dry-run-upsert",
                "uris": [{"uri": dry_run_upsert_uri.clone()}]
            }
        }),
    )?;
    ensure(dry_run_upsert.ok, "dry-run upsert did not report success")?;
    ensure(
        dry_run_upsert.operation == "upsert_create",
        "dry-run upsert should report the create path",
    )?;
    ensure_no_warnings(&dry_run_upsert, "dry-run upsert")?;

    let dry_run_upsert_search = list_ciphers(
        temp_home,
        &profile,
        &cfg.master_password,
        "list search for dry-run upsert",
        &["--search".to_string(), dry_run_upsert_name.clone()],
    )?;
    ensure(
        dry_run_upsert_search.is_empty(),
        "dry-run upsert unexpectedly persisted an item",
    )?;

    let org_upsert_create = write_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "org upsert create",
        &[
            "write".to_string(),
            "upsert".to_string(),
            "--match".to_string(),
            "name_uri".to_string(),
            "--scope".to_string(),
            format!("org:{}", fixtures.organization.id),
        ],
        json!({
            "type": "login",
            "name": org_upsert_login_name.clone(),
            "collection_ids": [fixtures.organization.collection.id.clone()],
            "notes": "org upsert create baseline",
            "login": {
                "username": org_upsert_username.clone(),
                "password": ORG_UPSERT_LOGIN_PASSWORD,
                "uris": [{"uri": org_upsert_login_uri.clone()}]
            }
        }),
    )?;
    ensure(
        org_upsert_create.operation == "upsert_create",
        "org upsert should create a new item on first run",
    )?;
    ensure_no_warnings(&org_upsert_create, "org upsert create")?;
    cleanup.register_cipher(&org_upsert_create.id);
    let _ = require_revision(&org_upsert_create, "org upsert create")?;

    let all_items = list_ciphers(temp_home, &profile, &cfg.master_password, "list all", &[])?;
    assert_cipher_id_in_list(
        &all_items,
        &personal_login_create.id,
        "list all missing personal login",
    )?;
    assert_cipher_id_in_list(
        &all_items,
        &personal_note_create.id,
        "list all missing personal note",
    )?;
    assert_cipher_id_in_list(
        &all_items,
        &org_login_create.id,
        "list all missing org login",
    )?;
    assert_cipher_id_in_list(&all_items, &org_note_create.id, "list all missing org note")?;
    assert_cipher_id_in_list(
        &all_items,
        &org_upsert_create.id,
        "list all missing org upsert login",
    )?;

    let login_items = list_ciphers(
        temp_home,
        &profile,
        &cfg.master_password,
        "list logins",
        &["--type".to_string(), "login".to_string()],
    )?;
    assert_cipher_id_in_list(
        &login_items,
        &personal_login_create.id,
        "list --type login missing personal login",
    )?;
    assert_cipher_id_in_list(
        &login_items,
        &org_login_create.id,
        "list --type login missing org login",
    )?;
    assert_cipher_id_in_list(
        &login_items,
        &org_upsert_create.id,
        "list --type login missing org upsert login",
    )?;

    let note_items = list_ciphers(
        temp_home,
        &profile,
        &cfg.master_password,
        "list notes",
        &["--type".to_string(), "note".to_string()],
    )?;
    assert_cipher_id_in_list(
        &note_items,
        &personal_note_create.id,
        "list --type note missing personal note",
    )?;
    assert_cipher_id_in_list(
        &note_items,
        &org_note_create.id,
        "list --type note missing org note",
    )?;

    let card_items = list_ciphers(
        temp_home,
        &profile,
        &cfg.master_password,
        "list cards",
        &["--type".to_string(), "card".to_string()],
    )?;
    assert_cipher_id_in_list(
        &card_items,
        &fixtures.readonly_items.card.id,
        "list --type card missing configured fixture",
    )?;

    let identity_items = list_ciphers(
        temp_home,
        &profile,
        &cfg.master_password,
        "list identities",
        &["--type".to_string(), "identity".to_string()],
    )?;
    assert_cipher_id_in_list(
        &identity_items,
        &fixtures.readonly_items.identity.id,
        "list --type identity missing configured fixture",
    )?;

    let ssh_items = list_ciphers(
        temp_home,
        &profile,
        &cfg.master_password,
        "list ssh",
        &["--type".to_string(), "ssh".to_string()],
    )?;
    assert_cipher_id_in_list(
        &ssh_items,
        &fixtures.readonly_items.ssh.id,
        "list --type ssh missing configured fixture",
    )?;

    let search_items = list_ciphers(
        temp_home,
        &profile,
        &cfg.master_password,
        "list search",
        &["--search".to_string(), personal_login_name.clone()],
    )?;
    assert_cipher_id_in_list(
        &search_items,
        &personal_login_create.id,
        "list --search missing the personal login",
    )?;

    let org_items_by_name = list_ciphers(
        temp_home,
        &profile,
        &cfg.master_password,
        "list org by name",
        &["--org".to_string(), fixtures.organization.name.clone()],
    )?;
    assert_cipher_id_in_list(
        &org_items_by_name,
        &org_login_create.id,
        "list --org by name missing org login",
    )?;
    assert_cipher_id_in_list(
        &org_items_by_name,
        &org_upsert_create.id,
        "list --org by name missing org upsert login",
    )?;

    let org_items_by_id = list_ciphers(
        temp_home,
        &profile,
        &cfg.master_password,
        "list org by id",
        &["--org".to_string(), fixtures.organization.id.clone()],
    )?;
    assert_cipher_id_in_list(
        &org_items_by_id,
        &org_note_create.id,
        "list --org by id missing org note",
    )?;
    assert_cipher_id_in_list(
        &org_items_by_id,
        &org_upsert_create.id,
        "list --org by id missing org upsert login",
    )?;

    let collection_items_by_name = list_ciphers(
        temp_home,
        &profile,
        &cfg.master_password,
        "list collection by name",
        &[
            "--collection".to_string(),
            fixtures.organization.collection.name.clone(),
        ],
    )?;
    assert_cipher_id_in_list(
        &collection_items_by_name,
        &org_login_create.id,
        "list --collection by name missing org login",
    )?;
    assert_cipher_id_in_list(
        &collection_items_by_name,
        &org_upsert_create.id,
        "list --collection by name missing org upsert login",
    )?;

    let collection_items_by_id = list_ciphers(
        temp_home,
        &profile,
        &cfg.master_password,
        "list collection by id",
        &[
            "--collection".to_string(),
            fixtures.organization.collection.id.clone(),
        ],
    )?;
    assert_cipher_id_in_list(
        &collection_items_by_id,
        &org_note_create.id,
        "list --collection by id missing org note",
    )?;
    assert_cipher_id_in_list(
        &collection_items_by_id,
        &org_upsert_create.id,
        "list --collection by id missing org upsert login",
    )?;

    let personal_login = get_cipher_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "get personal login by id",
        &personal_login_create.id,
        &[],
    )?;
    verify_login_cipher(
        &personal_login,
        &personal_login_name,
        &personal_username,
        PERSONAL_LOGIN_PASSWORD,
        &personal_login_uri,
    )?;

    let personal_note = get_cipher_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "get personal note by id",
        &personal_note_create.id,
        &[],
    )?;
    verify_note_cipher(
        &personal_note,
        &personal_note_name,
        "personal note baseline",
    )?;

    let org_login = get_cipher_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "get org login by id",
        &org_login_create.id,
        &[
            "--org".to_string(),
            fixtures.organization.name.clone(),
            "--collection".to_string(),
            fixtures.organization.collection.name.clone(),
        ],
    )?;
    verify_login_cipher(
        &org_login,
        &org_login_name,
        &org_username,
        ORG_LOGIN_PASSWORD,
        &org_login_uri,
    )?;

    let org_login_by_uri = get_uri_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "get-uri org login",
        &format!("org-login/{}", cfg.namespace),
        &[
            "--org".to_string(),
            fixtures.organization.id.clone(),
            "--collection".to_string(),
            fixtures.organization.collection.id.clone(),
        ],
    )?;
    ensure(
        org_login_by_uri.id == org_login_create.id,
        "get-uri org login returned the wrong cipher",
    )?;

    let card = get_cipher_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "get card fixture",
        &fixtures.readonly_items.card.id,
        &[],
    )?;
    ensure(
        card.cipher_type == "card",
        "configured card fixture is not a card",
    )?;
    ensure(
        card.name == fixtures.readonly_items.card.name,
        "configured card fixture returned wrong name",
    )?;

    let identity = get_cipher_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "get identity fixture",
        &fixtures.readonly_items.identity.id,
        &[],
    )?;
    ensure(
        identity.cipher_type == "identity",
        "configured identity fixture is not an identity",
    )?;
    ensure(
        identity.name == fixtures.readonly_items.identity.name,
        "configured identity fixture returned wrong name",
    )?;

    let ssh = get_cipher_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "get ssh fixture",
        &fixtures.readonly_items.ssh.id,
        &[],
    )?;
    ensure(
        ssh.cipher_type == "ssh",
        "configured ssh fixture is not an ssh item",
    )?;
    ensure(
        ssh.name == fixtures.readonly_items.ssh.name,
        "configured ssh fixture returned wrong name",
    )?;
    ensure(
        ssh.ssh_public_key.as_deref().is_some_and(|v| !v.is_empty()),
        "configured ssh fixture did not expose a public key",
    )?;
    ensure(
        ssh.ssh_private_key
            .as_deref()
            .is_some_and(|v| !v.is_empty()),
        "configured ssh fixture did not expose a private key",
    )?;
    ensure(
        ssh.ssh_fingerprint
            .as_deref()
            .is_some_and(|v| !v.is_empty()),
        "configured ssh fixture did not expose a fingerprint",
    )?;

    let username_output = get_text(
        temp_home,
        &profile,
        &cfg.master_password,
        "get username via exact name",
        &personal_login_name,
        &["-u".to_string()],
    )?;
    ensure_text_eq(
        &username_output,
        &personal_username,
        "get username via exact name",
    )?;

    let password_by_get = get_text(
        temp_home,
        &profile,
        &cfg.master_password,
        "get password via exact name",
        &personal_login_name,
        &["-p".to_string()],
    )?;
    ensure_text_eq(
        &password_by_get,
        PERSONAL_LOGIN_PASSWORD,
        "get password via exact name",
    )?;

    let password_output = get_uri_text(
        temp_home,
        &profile,
        &cfg.master_password,
        "get password via uri",
        &format!("personal-login/{}", cfg.namespace),
        &["-p".to_string()],
    )?;
    ensure_text_eq(
        &password_output,
        PERSONAL_LOGIN_PASSWORD,
        "get password via uri",
    )?;

    let username_by_uri = get_uri_text(
        temp_home,
        &profile,
        &cfg.master_password,
        "get username via uri",
        &format!("personal-login/{}", cfg.namespace),
        &["-u".to_string()],
    )?;
    ensure_text_eq(&username_by_uri, &personal_username, "get username via uri")?;

    let env_output = get_text(
        temp_home,
        &profile,
        &cfg.master_password,
        "get env format",
        &personal_login_create.id,
        &["--format".to_string(), "env".to_string()],
    )?;
    let personal_env_prefix = sanitize_env_name(&personal_login_name);
    ensure(
        env_output.contains(&format!(
            "export {}_USERNAME=\"{}\"",
            personal_env_prefix, personal_username
        )),
        "get --format env did not include the expected username export",
    )?;
    ensure(
        env_output.contains(&format!(
            "export {}_PASSWORD=\"{}\"",
            personal_env_prefix, PERSONAL_LOGIN_PASSWORD
        )),
        "get --format env did not include the expected password export",
    )?;

    let run_positional_info = run_info(
        temp_home,
        &profile,
        &cfg.master_password,
        "run positional --info",
        std::slice::from_ref(&personal_login_name),
    )?;
    ensure(
        run_positional_info.contains(&format!("{}_PASSWORD", personal_env_prefix)),
        "run positional --info did not return the expected password env var",
    )?;

    let verifier = format!(
        "test \"${0}_USERNAME\" = \"$EXPECTED_USERNAME\" && test \"${0}_PASSWORD\" = \"$EXPECTED_PASSWORD\"",
        personal_env_prefix
    );
    run_command(
        temp_home,
        &profile,
        &cfg.master_password,
        "run secret injection",
        &["--name".to_string(), personal_login_name.clone()],
        &["/bin/sh".to_string(), "-c".to_string(), verifier.clone()],
        &[
            ("EXPECTED_USERNAME".to_string(), personal_username.clone()),
            (
                "EXPECTED_PASSWORD".to_string(),
                PERSONAL_LOGIN_PASSWORD.to_string(),
            ),
        ],
    )?;

    let run_uri_info_output = run_uri_info(
        temp_home,
        &profile,
        &cfg.master_password,
        "run-uri --info",
        &format!("personal-login/{}", cfg.namespace),
    )?;
    ensure(
        run_uri_info_output.contains(&format!("{}_PASSWORD", personal_env_prefix)),
        "run-uri --info did not return the expected password env var",
    )?;

    run_uri_command(
        temp_home,
        &profile,
        &cfg.master_password,
        "run-uri secret injection",
        &format!("personal-login/{}", cfg.namespace),
        &["/bin/sh".to_string(), "-c".to_string(), verifier],
        &[
            ("EXPECTED_USERNAME".to_string(), personal_username.clone()),
            (
                "EXPECTED_PASSWORD".to_string(),
                PERSONAL_LOGIN_PASSWORD.to_string(),
            ),
        ],
    )?;

    let personal_login_update = write_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "personal login update",
        &[
            "write".to_string(),
            "update".to_string(),
            "--id".to_string(),
            personal_login_create.id.clone(),
            "--if-revision".to_string(),
            personal_login_revision.clone(),
        ],
        json!({
            "type": "login",
            "name": personal_login_name.clone(),
            "notes": "personal login updated",
            "login": {
                "username": personal_username.clone(),
                "password": PERSONAL_LOGIN_PASSWORD,
                "uris": [{"uri": personal_login_uri.clone()}]
            }
        }),
    )?;
    ensure(
        personal_login_update.operation == "update",
        "personal login update returned wrong operation",
    )?;
    ensure_no_warnings(&personal_login_update, "personal login update")?;
    personal_login_revision = require_revision(&personal_login_update, "personal login update")?;

    let dry_run_personal_note_update = write_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "dry-run personal note update",
        &[
            "write".to_string(),
            "update".to_string(),
            "--id".to_string(),
            personal_note_create.id.clone(),
            "--if-revision".to_string(),
            personal_note_revision.clone(),
            "--dry-run".to_string(),
        ],
        json!({
            "type": "note",
            "name": personal_note_name.clone(),
            "notes": "personal note dry run",
            "note": {"secure_note_type": 0}
        }),
    )?;
    ensure(
        dry_run_personal_note_update.operation == "update",
        "dry-run personal note update returned wrong operation",
    )?;
    ensure_no_warnings(
        &dry_run_personal_note_update,
        "dry-run personal note update",
    )?;

    let note_after_dry_run_update = get_cipher_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "get personal note after dry-run update",
        &personal_note_create.id,
        &[],
    )?;
    verify_note_cipher(
        &note_after_dry_run_update,
        &personal_note_name,
        "personal note baseline",
    )?;

    let personal_note_update = write_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "personal note update",
        &[
            "write".to_string(),
            "update".to_string(),
            "--id".to_string(),
            personal_note_create.id.clone(),
            "--if-revision".to_string(),
            personal_note_revision.clone(),
        ],
        json!({
            "type": "note",
            "name": personal_note_name.clone(),
            "notes": "personal note updated",
            "note": {"secure_note_type": 0}
        }),
    )?;
    ensure(
        personal_note_update.operation == "update",
        "personal note update returned wrong operation",
    )?;
    ensure_no_warnings(&personal_note_update, "personal note update")?;

    let org_login_update = write_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "org login update",
        &[
            "write".to_string(),
            "update".to_string(),
            "--id".to_string(),
            org_login_create.id.clone(),
            "--if-revision".to_string(),
            org_login_revision.clone(),
        ],
        json!({
            "type": "login",
            "name": org_login_name.clone(),
            "organization_id": fixtures.organization.id,
            "collection_ids": [fixtures.organization.collection.id.clone()],
            "notes": "org login updated",
            "login": {
                "username": org_username.clone(),
                "password": ORG_LOGIN_PASSWORD,
                "uris": [{"uri": org_login_uri.clone()}]
            }
        }),
    )?;
    ensure(
        org_login_update.operation == "update",
        "org login update returned wrong operation",
    )?;
    ensure_no_warnings(&org_login_update, "org login update")?;
    let _ = require_revision(&org_login_update, "org login update")?;

    let upsert_update = write_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "upsert update",
        &[
            "write".to_string(),
            "upsert".to_string(),
            "--match".to_string(),
            "name_uri".to_string(),
            "--scope".to_string(),
            "personal".to_string(),
        ],
        json!({
            "type": "login",
            "name": upsert_login_name.clone(),
            "notes": "upsert update applied",
            "login": {
                "username": upsert_username.clone(),
                "password": UPSERT_LOGIN_ROTATED_PASSWORD,
                "uris": [{"uri": upsert_login_uri.clone()}]
            }
        }),
    )?;
    ensure(
        upsert_update.operation == "upsert_update",
        "second upsert should update the existing item",
    )?;
    ensure_no_warnings(&upsert_update, "upsert update")?;
    let _ = require_revision(&upsert_update, "upsert update")?;

    let upsert_cipher = get_cipher_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "get upsert cipher",
        &upsert_create.id,
        &[],
    )?;
    verify_login_cipher(
        &upsert_cipher,
        &upsert_login_name,
        &upsert_username,
        UPSERT_LOGIN_ROTATED_PASSWORD,
        &upsert_login_uri,
    )?;

    let org_upsert_update = write_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "org upsert update",
        &[
            "write".to_string(),
            "upsert".to_string(),
            "--match".to_string(),
            "name_uri".to_string(),
            "--scope".to_string(),
            format!("org:{}", fixtures.organization.id),
        ],
        json!({
            "type": "login",
            "name": org_upsert_login_name.clone(),
            "collection_ids": [fixtures.organization.collection.id.clone()],
            "notes": "org upsert update applied",
            "login": {
                "username": org_upsert_username.clone(),
                "password": ORG_UPSERT_LOGIN_ROTATED_PASSWORD,
                "uris": [{"uri": org_upsert_login_uri.clone()}]
            }
        }),
    )?;
    ensure(
        org_upsert_update.operation == "upsert_update",
        "org upsert should update the existing item on second run",
    )?;
    ensure_no_warnings(&org_upsert_update, "org upsert update")?;
    let _ = require_revision(&org_upsert_update, "org upsert update")?;

    let org_upsert_cipher = get_cipher_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "get org upsert cipher",
        &org_upsert_create.id,
        &[
            "--org".to_string(),
            fixtures.organization.id.clone(),
            "--collection".to_string(),
            fixtures.organization.collection.id.clone(),
        ],
    )?;
    verify_login_cipher(
        &org_upsert_cipher,
        &org_upsert_login_name,
        &org_upsert_username,
        ORG_UPSERT_LOGIN_ROTATED_PASSWORD,
        &org_upsert_login_uri,
    )?;

    let dry_run_rotate_personal = write_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "dry-run rotate personal password",
        &[
            "write".to_string(),
            "rotate-password".to_string(),
            "--id".to_string(),
            personal_login_create.id.clone(),
            "--if-revision".to_string(),
            personal_login_revision.clone(),
            "--dry-run".to_string(),
        ],
        json!({"new_password": "vaultwarden-cli-e2e-dry-run-rotate"}),
    )?;
    ensure(
        dry_run_rotate_personal.operation == "rotate_password",
        "dry-run rotate-password returned wrong operation",
    )?;
    ensure_no_warnings(&dry_run_rotate_personal, "dry-run rotate personal password")?;

    let password_after_dry_run_rotate = get_text(
        temp_home,
        &profile,
        &cfg.master_password,
        "get personal password after dry-run rotate",
        &personal_login_create.id,
        &["--format".to_string(), "value".to_string()],
    )?;
    ensure_text_eq(
        &password_after_dry_run_rotate,
        PERSONAL_LOGIN_PASSWORD,
        "password after dry-run rotate",
    )?;

    let rotate_personal = write_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "rotate personal password",
        &[
            "write".to_string(),
            "rotate-password".to_string(),
            "--id".to_string(),
            personal_login_create.id.clone(),
            "--if-revision".to_string(),
            personal_login_revision.clone(),
        ],
        json!({"new_password": PERSONAL_LOGIN_ROTATED_PASSWORD}),
    )?;
    ensure(
        rotate_personal.operation == "rotate_password",
        "rotate-password returned wrong operation",
    )?;
    ensure_no_warnings(&rotate_personal, "rotate personal password")?;
    personal_login_revision = require_revision(&rotate_personal, "rotate personal password")?;

    let rotated_personal_password = get_text(
        temp_home,
        &profile,
        &cfg.master_password,
        "get rotated personal password",
        &personal_login_create.id,
        &["--format".to_string(), "value".to_string()],
    )?;
    ensure_text_eq(
        &rotated_personal_password,
        PERSONAL_LOGIN_ROTATED_PASSWORD,
        "rotated personal password",
    )?;

    let dry_run_patch_fields = write_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "dry-run patch fields",
        &[
            "write".to_string(),
            "patch-fields".to_string(),
            "--id".to_string(),
            personal_login_create.id.clone(),
            "--if-revision".to_string(),
            personal_login_revision.clone(),
            "--dry-run".to_string(),
        ],
        json!({
            "fields": [{
                "name": "dry_run_field",
                "value": "dry-run-field-value",
                "field_type": 1
            }]
        }),
    )?;
    ensure(
        dry_run_patch_fields.operation == "patch_fields",
        "dry-run patch-fields returned wrong operation",
    )?;
    ensure_no_warnings(&dry_run_patch_fields, "dry-run patch fields")?;

    let cipher_after_dry_run_patch = get_cipher_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "get personal login after dry-run patch",
        &personal_login_create.id,
        &[],
    )?;
    ensure(
        cipher_after_dry_run_patch
            .fields
            .as_ref()
            .is_none_or(|fields| fields.iter().all(|field| field.name != "dry_run_field")),
        "dry-run patch-fields unexpectedly persisted a field",
    )?;

    let patch_fields = write_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "patch fields",
        &[
            "write".to_string(),
            "patch-fields".to_string(),
            "--id".to_string(),
            personal_login_create.id.clone(),
            "--if-revision".to_string(),
            personal_login_revision.clone(),
        ],
        json!({
            "fields": [{
                "name": PATCHED_FIELD_NAME,
                "value": PATCHED_FIELD_VALUE,
                "field_type": 1
            }]
        }),
    )?;
    ensure(
        patch_fields.operation == "patch_fields",
        "patch-fields returned wrong operation",
    )?;
    ensure_no_warnings(&patch_fields, "patch fields")?;
    personal_login_revision = require_revision(&patch_fields, "patch fields")?;

    let patched_personal = get_cipher_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "get patched personal login",
        &personal_login_create.id,
        &[],
    )?;
    ensure(
        patched_personal.fields.as_ref().is_some_and(|fields| {
            fields.iter().any(|field| {
                field.name == PATCHED_FIELD_NAME
                    && field.value == PATCHED_FIELD_VALUE
                    && field.hidden
            })
        }),
        "patch-fields did not persist the expected hidden field",
    )?;

    let dry_run_move = write_move(
        temp_home,
        &profile,
        &cfg.master_password,
        "dry-run move personal login",
        &[
            "--id".to_string(),
            personal_login_create.id.clone(),
            "--if-revision".to_string(),
            personal_login_revision.clone(),
            "--folder-id".to_string(),
            fixtures.personal.folder.id.clone(),
            "--favorite".to_string(),
            "true".to_string(),
            "--dry-run".to_string(),
        ],
    )?;
    ensure(
        dry_run_move.operation == "move",
        "dry-run move returned wrong operation",
    )?;
    ensure_warnings_eq(
        &dry_run_move,
        &["dry-run: no mutation performed"],
        "dry-run move personal login",
    )?;

    let cipher_after_dry_run_move = get_cipher_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "get personal login after dry-run move",
        &personal_login_create.id,
        &[],
    )?;
    ensure(
        cipher_after_dry_run_move.folder_id.is_none(),
        "dry-run move unexpectedly changed the folder",
    )?;
    ensure(
        cipher_after_dry_run_move.favorite != Some(true),
        "dry-run move unexpectedly changed the favorite flag",
    )?;

    let move_to_folder = write_move(
        temp_home,
        &profile,
        &cfg.master_password,
        "move personal login into folder",
        &[
            "--id".to_string(),
            personal_login_create.id.clone(),
            "--if-revision".to_string(),
            personal_login_revision.clone(),
            "--folder-id".to_string(),
            fixtures.personal.folder.id.clone(),
            "--favorite".to_string(),
            "true".to_string(),
        ],
    )?;
    ensure(
        move_to_folder.operation == "move",
        "move returned wrong operation",
    )?;
    ensure_no_warnings(&move_to_folder, "move personal login into folder")?;
    let _ = require_revision(&move_to_folder, "move personal login into folder")?;

    let moved_personal = get_cipher_json(
        temp_home,
        &profile,
        &cfg.master_password,
        "get personal login after move",
        &personal_login_create.id,
        &[],
    )?;
    ensure(
        moved_personal.folder_id.as_deref() == Some(fixtures.personal.folder.id.as_str()),
        "move did not assign the expected folder",
    )?;
    ensure(
        moved_personal.favorite == Some(true),
        "move did not set favorite=true",
    )?;

    let run_folder_info_by_name = run_info(
        temp_home,
        &profile,
        &cfg.master_password,
        "run folder --info by name",
        &[
            "--name".to_string(),
            personal_login_name.clone(),
            "--folder".to_string(),
            fixtures.personal.folder.name.clone(),
        ],
    )?;
    ensure(
        run_folder_info_by_name.contains(&format!("{}_PASSWORD", personal_env_prefix)),
        "run with folder filter by name did not expose the expected password env var",
    )?;

    let run_folder_info_by_id = run_info(
        temp_home,
        &profile,
        &cfg.master_password,
        "run folder --info by id",
        &[
            "--name".to_string(),
            personal_login_name.clone(),
            "--folder".to_string(),
            fixtures.personal.folder.id.clone(),
        ],
    )?;
    ensure(
        run_folder_info_by_id.contains(&format!("{}_PASSWORD", personal_env_prefix)),
        "run with folder filter by id did not expose the expected password env var",
    )?;

    let org_env_prefix = sanitize_env_name(&org_login_name);
    let org_run_info = run_info(
        temp_home,
        &profile,
        &cfg.master_password,
        "run org collection --info",
        &[
            "--name".to_string(),
            org_login_name.clone(),
            "--org".to_string(),
            fixtures.organization.name.clone(),
            "--collection".to_string(),
            fixtures.organization.collection.name.clone(),
        ],
    )?;
    ensure(
        org_run_info.contains(&format!("{}_PASSWORD", org_env_prefix)),
        "run with org+collection filters did not expose the expected password env var",
    )?;

    let org_verifier = format!(
        "test \"${0}_USERNAME\" = \"$EXPECTED_USERNAME\" && test \"${0}_PASSWORD\" = \"$EXPECTED_PASSWORD\"",
        org_env_prefix
    );
    run_command(
        temp_home,
        &profile,
        &cfg.master_password,
        "run org login secret injection",
        &[
            "--name".to_string(),
            org_login_name.clone(),
            "--org".to_string(),
            fixtures.organization.id.clone(),
            "--collection".to_string(),
            fixtures.organization.collection.id.clone(),
        ],
        &["/bin/sh".to_string(), "-c".to_string(), org_verifier],
        &[
            ("EXPECTED_USERNAME".to_string(), org_username.clone()),
            (
                "EXPECTED_PASSWORD".to_string(),
                ORG_LOGIN_PASSWORD.to_string(),
            ),
        ],
    )?;

    let logout: LogoutResponse = parse_json(
        "logout",
        &run_cli(
            temp_home,
            "logout",
            &[
                "--profile".to_string(),
                profile.clone(),
                "logout".to_string(),
            ],
            None,
            &[],
        )?,
    )?;
    ensure(logout.ok, "logout did not report success")?;
    ensure(
        logout.had_session,
        "logout should report an existing session",
    )?;

    let final_status = status(temp_home, &profile, "status after logout")?;
    ensure(
        !final_status.logged_in,
        "post-logout status should be logged out",
    )
}

#[test]
#[ignore = "requires live vaultwarden configuration via scripts/live-e2e.sh"]
fn live_personal_and_org_cli_surface() -> Result<()> {
    let cfg = LiveE2eConfig::from_env()?;
    let fixtures = cfg.load_fixtures()?;
    let temp_home = TempDir::new().context("Failed to create temp home for live e2e test")?;
    let mut cleanup = CleanupGuard::new();

    let flow_result = run_full_flow(&cfg, &fixtures, &temp_home, &mut cleanup);
    let cleanup_result = cleanup.cleanup();

    match (flow_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(flow_err), Ok(())) => Err(flow_err),
        (Ok(()), Err(cleanup_err)) => Err(cleanup_err),
        (Err(flow_err), Err(cleanup_err)) => {
            bail!("{:#}\ncleanup also failed: {:#}", flow_err, cleanup_err)
        }
    }
}
