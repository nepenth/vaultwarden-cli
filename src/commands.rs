use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::process::Command;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::api::{ApiClient, ApiErrorDetail};
use crate::config::Config;
use crate::crypto::CryptoKeys;
use crate::models::{
    Cipher, CipherOutput, CipherType, FieldOutput, WriteCipherPayload, WriteCommandErrorBody,
    WriteCommandErrorEnvelope, WriteCommandSuccess, WriteInputV1,
};

#[derive(Debug, thiserror::Error)]
#[error("write command failed")]
pub struct WriteCliError {
    pub json: String,
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before UNIX epoch")
        .as_secs() as i64
}

fn make_write_error(
    code: &str,
    message: impl Into<String>,
    retryable: bool,
    action: &str,
) -> anyhow::Error {
    let envelope = WriteCommandErrorEnvelope {
        ok: false,
        error: WriteCommandErrorBody {
            code: code.to_string(),
            message: message.into(),
            retryable,
            action: action.to_string(),
        },
    };

    let json = serde_json::to_string_pretty(&envelope).unwrap_or_else(|_| {
        r#"{"ok":false,"error":{"code":"SERVER_ERROR","message":"Failed to serialize write error","retryable":false,"action":"retry"}}"#.to_string()
    });

    WriteCliError { json }.into()
}

fn map_write_error(err: anyhow::Error) -> anyhow::Error {
    if err.downcast_ref::<WriteCliError>().is_some() {
        return err;
    }

    if let Some(api_err) = err.downcast_ref::<ApiErrorDetail>() {
        let body_lc = api_err.body.to_lowercase();
        let message = if api_err.body.trim().is_empty() {
            api_err.to_string()
        } else {
            api_err.body.clone()
        };

        return match api_err.status {
            400 if body_lc.contains("out of date")
                || body_lc.contains("resync")
                || body_lc.contains("lastknownrevision") =>
            {
                make_write_error("CONFLICT_STALE_REVISION", message, true, "resync_and_retry")
            }
            400 => make_write_error("VALIDATION_ERROR", message, false, "fix_input"),
            401 => make_write_error("AUTH_ERROR", message, true, "re_login"),
            403 => make_write_error("PERMISSION_DENIED", message, false, "check_permissions"),
            404 => make_write_error("NOT_FOUND", message, false, "verify_target"),
            409 => make_write_error("CONFLICT_STALE_REVISION", message, true, "resync_and_retry"),
            _ => make_write_error("SERVER_ERROR", message, true, "retry"),
        };
    }

    let msg = err.to_string();
    if msg.contains("--password-stdin")
        || msg.contains("Expected password first line")
        || msg.contains("JSON payload is required")
        || msg.contains("No secret provided on stdin")
        || msg.contains("Master password line is empty")
    {
        return make_write_error("VALIDATION_ERROR", msg, false, "fix_input");
    }

    make_write_error("SERVER_ERROR", msg, false, "inspect_logs")
}

fn read_stdin_all() -> Result<String> {
    let mut data = String::new();
    std::io::stdin()
        .read_to_string(&mut data)
        .context("Failed to read stdin")?;
    Ok(data)
}

fn extract_secret(input: &str) -> Result<String> {
    let secret = input.trim_end_matches(['\n', '\r']).to_string();
    if secret.is_empty() {
        anyhow::bail!("No secret provided on stdin");
    }
    Ok(secret)
}

fn split_password_and_json(stdin: &str) -> Result<(String, String)> {
    let (password, rest) = stdin
        .split_once('\n')
        .context("Expected password first line followed by JSON payload on stdin")?;
    let password = password.trim_end_matches('\r').to_string();
    if password.is_empty() {
        anyhow::bail!("Master password line is empty");
    }
    let payload = rest.trim_start().to_string();
    if payload.is_empty() {
        anyhow::bail!("JSON payload is required after password line");
    }
    Ok((password, payload))
}

fn load_input_payload(path: &str, password_stdin: bool) -> Result<(String, String)> {
    if path == "-" {
        let stdin = read_stdin_all()?;
        if password_stdin {
            split_password_and_json(&stdin)
        } else {
            anyhow::bail!("--password-stdin is required when --input - is used")
        }
    } else {
        let payload = fs::read_to_string(path)
            .with_context(|| format!("Failed to read input file {}", path))?;
        let password = if password_stdin {
            extract_secret(&read_stdin_all()?)?
        } else {
            anyhow::bail!("--password-stdin is required for write commands")
        };
        Ok((password, payload))
    }
}

#[derive(Debug)]
struct RuntimeKeys {
    user: CryptoKeys,
    org: HashMap<String, CryptoKeys>,
}

struct SyncContext {
    sync_response: crate::models::SyncResponse,
    keys: RuntimeKeys,
}

pub async fn login(
    profile: &str,
    server: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
) -> Result<()> {
    let _lock = Config::acquire_profile_lock(profile)?;
    let mut config = Config::load(profile)?;

    let server = server
        .or_else(|| config.server.clone())
        .context("Server URL is required. Use --server.")?;
    let client_id = client_id
        .or_else(|| config.client_id.clone())
        .context("Client ID is required. Use --client-id or VAULTWARDEN_CLIENT_ID.")?;
    let client_secret = client_secret
        .context("Client secret is required. Use --client-secret or VAULTWARDEN_CLIENT_SECRET.")?;

    let api = ApiClient::new(&server)?;
    let token_response = api.login(&client_id, &client_secret).await?;

    let expiry = unix_now() + token_response.expires_in;

    config.server = Some(server);
    config.client_id = Some(client_id);
    config.access_token = Some(token_response.access_token.clone());
    config.refresh_token = token_response.refresh_token;
    config.token_expiry = Some(expiry);
    config.encrypted_key = token_response.key;
    config.kdf_iterations = token_response.kdf_iterations;

    let sync_response = api.sync(&token_response.access_token).await?;
    config.email = Some(sync_response.profile.email.clone());
    config.encrypted_private_key = sync_response.profile.private_key.clone();

    config.org_keys.clear();
    for org in &sync_response.profile.organizations {
        if let Some(key) = &org.key {
            config.org_keys.insert(org.id.clone(), key.clone());
        }
    }

    config.save(profile)?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": true,
            "profile": profile,
            "organizations": config.org_keys.len()
        }))?
    );

    Ok(())
}

pub async fn logout(profile: &str) -> Result<()> {
    let _lock = Config::acquire_profile_lock(profile)?;
    let mut config = Config::load(profile)?;
    let had_session = config.is_logged_in();
    config.clear_session();
    config.save(profile)?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": true,
            "profile": profile,
            "had_session": had_session
        }))?
    );

    Ok(())
}

pub async fn status(profile: &str) -> Result<()> {
    let config = Config::load(profile)?;

    let now = unix_now();
    let token_expired = config.token_expiry.is_some_and(|expiry| expiry <= now);

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "profile": profile,
            "logged_in": config.is_logged_in(),
            "server": config.server,
            "client_id": config.client_id,
            "email": config.email,
            "token_expiry": config.token_expiry,
            "token_expired": token_expired
        }))?
    );

    Ok(())
}

fn required_password(password: Option<&str>) -> Result<&str> {
    password
        .filter(|p| !p.trim().is_empty())
        .context("Master password is required. Use --password or VAULTWARDEN_PASSWORD.")
}

async fn ensure_valid_token(profile: &str, config: &mut Config) -> Result<String> {
    let access_token = config
        .access_token
        .clone()
        .context("Not logged in. Run login first.")?;

    let now = unix_now();

    if let Some(expiry) = config.token_expiry
        && now >= expiry - 60
    {
        if let Some(refresh_token) = &config.refresh_token {
            let api = ApiClient::from_config(config)?;
            match api.refresh_token(refresh_token).await {
                Ok(token_response) => {
                    let new_expiry = now + token_response.expires_in;
                    config.access_token = Some(token_response.access_token.clone());
                    config.refresh_token = token_response.refresh_token;
                    config.token_expiry = Some(new_expiry);
                    config.save(profile)?;
                    return Ok(token_response.access_token);
                }
                Err(_) => {
                    anyhow::bail!(
                        "Token expired and refresh failed. Run login with client credentials again."
                    );
                }
            }
        } else {
            anyhow::bail!("Token expired. Run login with client credentials again.");
        }
    }

    Ok(access_token)
}

fn derive_runtime_keys(config: &Config, password: &str) -> Result<RuntimeKeys> {
    let email = config
        .email
        .as_ref()
        .context("Email missing from profile. Run login again.")?;
    let encrypted_key = config
        .encrypted_key
        .as_ref()
        .context("Encrypted key missing from profile. Run login again.")?;

    let iterations = config.kdf_iterations.unwrap_or(600000);
    let master_key = CryptoKeys::derive_master_key(password, email, iterations);
    let user = CryptoKeys::decrypt_symmetric_key(&master_key, encrypted_key)
        .context("Failed to decrypt vault key. Check master password.")?;

    let mut org = HashMap::new();

    if let Some(encrypted_private_key) = &config.encrypted_private_key
        && let Ok(private_key) = user.decrypt_private_key(encrypted_private_key)
    {
        for (org_id, encrypted_org_key) in &config.org_keys {
            if let Ok(org_keys) = CryptoKeys::decrypt_org_key(encrypted_org_key, &private_key) {
                org.insert(org_id.clone(), org_keys);
            }
        }
    }

    Ok(RuntimeKeys { user, org })
}

async fn load_sync_context(profile: &str, password: Option<&str>) -> Result<SyncContext> {
    let lock = Config::acquire_profile_lock(profile)?;
    let mut config = Config::load(profile)?;
    let access_token = ensure_valid_token(profile, &mut config).await?;
    drop(lock);
    let password = required_password(password)?;
    let keys = derive_runtime_keys(&config, password)?;

    let api = ApiClient::from_config(&config)?;
    let mut sync_response = api.sync(&access_token).await?;
    if let Ok(cipher_list) = api.ciphers(&access_token).await {
        sync_response.ciphers = cipher_list.data;
    }

    Ok(SyncContext {
        sync_response,
        keys,
    })
}

fn resolve_org_id(profile: &crate::models::Profile, org_filter: &str) -> Result<String> {
    let matched = profile.organizations.iter().find(|o| {
        o.id == org_filter
            || o.name
                .as_deref()
                .is_some_and(|n| n.eq_ignore_ascii_case(org_filter))
    });

    Ok(matched
        .with_context(|| format!("Organization '{}' not found", org_filter))?
        .id
        .clone())
}

fn resolve_collection_id(
    collections: &[crate::models::Collection],
    runtime_keys: &RuntimeKeys,
    collection_filter: &str,
    org_id_filter: Option<&str>,
) -> Result<String> {
    if let Some(c) = collections.iter().find(|c| c.id == collection_filter) {
        return Ok(c.id.clone());
    }

    for col in collections {
        if let Some(oid) = org_id_filter
            && col.organization_id != oid
        {
            continue;
        }

        let Some(keys) = runtime_keys.org.get(&col.organization_id) else {
            continue;
        };

        if let Ok(name) = keys.decrypt_to_string(&col.name)
            && name.eq_ignore_ascii_case(collection_filter)
        {
            return Ok(col.id.clone());
        }
    }

    anyhow::bail!("Collection '{}' not found", collection_filter)
}

fn cipher_matches_filters(
    cipher: &Cipher,
    org_id_filter: Option<&str>,
    collection_id_filter: Option<&str>,
    folder_id_filter: Option<&str>,
) -> bool {
    if let Some(oid) = org_id_filter
        && cipher.organization_id.as_deref() != Some(oid)
    {
        return false;
    }

    if let Some(fid) = folder_id_filter
        && cipher.folder_id.as_deref() != Some(fid)
    {
        return false;
    }

    if let Some(cid) = collection_id_filter
        && !cipher.collection_ids.iter().any(|id| id == cid)
    {
        return false;
    }

    true
}

fn get_cipher_keys(runtime_keys: &RuntimeKeys, cipher: &Cipher) -> Result<CryptoKeys> {
    let base_keys = if let Some(org_id) = &cipher.organization_id {
        runtime_keys
            .org
            .get(org_id)
            .with_context(|| format!("Organization key unavailable for org {}", org_id))?
            .clone()
    } else {
        runtime_keys.user.clone()
    };

    if let Some(encrypted_item_key) = &cipher.key {
        let item_key_raw = base_keys
            .decrypt(encrypted_item_key)
            .context("Failed to decrypt item key")?;
        return CryptoKeys::from_symmetric_key(&item_key_raw).context("Invalid decrypted item key");
    }

    Ok(base_keys)
}

fn try_decrypt(keys: &CryptoKeys, encrypted: Option<&str>) -> Result<Option<String>> {
    encrypted.map(|e| keys.decrypt_to_string(e)).transpose()
}

fn decrypt_cipher(cipher: &Cipher, keys: &CryptoKeys) -> Result<CipherOutput> {
    let name = cipher.get_name().context("Cipher has no name")?;
    let decrypted_name = keys.decrypt_to_string(name)?;

    let decrypted_username = try_decrypt(keys, cipher.get_username())?;
    let decrypted_password = try_decrypt(keys, cipher.get_password())?;
    let decrypted_uri = try_decrypt(keys, cipher.get_uri())?;
    let decrypted_notes = try_decrypt(keys, cipher.get_notes())?;

    let decrypted_fields = cipher.get_fields().map(|fields| {
        fields
            .iter()
            .filter_map(|f| {
                let name = f
                    .name
                    .as_ref()
                    .and_then(|n| keys.decrypt_to_string(n).ok())?;
                let value = f
                    .value
                    .as_ref()
                    .and_then(|v| keys.decrypt_to_string(v).ok())
                    .unwrap_or_default();
                Some(FieldOutput {
                    name,
                    value,
                    hidden: f.r#type == 1,
                })
            })
            .collect()
    });

    let ssh_public_key = cipher
        .ssh_key
        .as_ref()
        .and_then(|s| s.public_key.as_deref())
        .and_then(|k| keys.decrypt_to_string(k).ok());
    let ssh_private_key = cipher
        .ssh_key
        .as_ref()
        .and_then(|s| s.private_key.as_deref())
        .and_then(|k| keys.decrypt_to_string(k).ok());
    let ssh_fingerprint = cipher
        .ssh_key
        .as_ref()
        .and_then(|s| s.fingerprint.as_deref())
        .and_then(|k| keys.decrypt_to_string(k).ok());

    Ok(CipherOutput {
        id: cipher.id.clone(),
        cipher_type: cipher
            .cipher_type()
            .map_or_else(|| "unknown".into(), |t| t.to_string()),
        name: decrypted_name,
        username: decrypted_username,
        password: decrypted_password,
        uri: decrypted_uri,
        notes: decrypted_notes,
        fields: decrypted_fields,
        ssh_public_key,
        ssh_private_key,
        ssh_fingerprint,
    })
}

fn find_cipher_output(
    ciphers: &[Cipher],
    runtime_keys: &RuntimeKeys,
    mut predicate: impl FnMut(&CipherOutput) -> bool,
    matches_filters: impl Fn(&Cipher) -> bool,
) -> Option<CipherOutput> {
    for cipher in ciphers {
        if !matches_filters(cipher) {
            continue;
        }

        let keys = match get_cipher_keys(runtime_keys, cipher) {
            Ok(k) => k,
            Err(_) => continue,
        };

        if let Ok(output) = decrypt_cipher(cipher, &keys)
            && predicate(&output)
        {
            return Some(output);
        }
    }

    None
}

fn output_matches_search(output: &CipherOutput, search_lower: &str) -> bool {
    output.name.to_lowercase().contains(search_lower)
        || output
            .username
            .as_ref()
            .is_some_and(|u| u.to_lowercase().contains(search_lower))
        || output
            .uri
            .as_ref()
            .is_some_and(|u| u.to_lowercase().contains(search_lower))
        || output
            .ssh_public_key
            .as_ref()
            .is_some_and(|k| k.to_lowercase().contains(search_lower))
        || output
            .ssh_fingerprint
            .as_ref()
            .is_some_and(|f| f.to_lowercase().contains(search_lower))
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

    let starts_with_digit = normalized
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_digit());
    if starts_with_digit {
        normalized.insert(0, '_');
    }

    normalized
}

fn escape_value(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for c in value.chars() {
        if matches!(c, '\\' | '"' | '$' | '`') {
            result.push('\\');
        }
        result.push(c);
    }
    result
}

fn cipher_to_env_vars(output: &CipherOutput) -> Vec<(String, String)> {
    let prefix = sanitize_env_name(&output.name);
    let mut vars: Vec<(String, String)> = Vec::new();

    if let Some(v) = &output.uri {
        vars.push((format!("{}_URI", prefix), v.clone()));
    }
    if let Some(v) = &output.username {
        vars.push((format!("{}_USERNAME", prefix), v.clone()));
    }
    if let Some(v) = &output.password {
        vars.push((format!("{}_PASSWORD", prefix), v.clone()));
    }
    if let Some(v) = &output.ssh_public_key {
        vars.push((format!("{}_SSH_PUBLIC_KEY", prefix), v.clone()));
    }
    if let Some(v) = &output.ssh_private_key {
        vars.push((format!("{}_SSH_PRIVATE_KEY", prefix), v.clone()));
    }
    if let Some(v) = &output.ssh_fingerprint {
        vars.push((format!("{}_SSH_FINGERPRINT", prefix), v.clone()));
    }
    if let Some(fields) = &output.fields {
        for field in fields {
            vars.push((
                format!("{}_{}", prefix, sanitize_env_name(&field.name)),
                field.value.clone(),
            ));
        }
    }

    vars
}

fn get_field_string(field: &Option<String>, name: &str) -> Result<String> {
    field
        .as_deref()
        .with_context(|| format!("Item has no {}", name))
        .map(|s| s.to_string())
}

fn format_cipher_output(output: &CipherOutput, format: &str) -> Result<String> {
    match format {
        "json" => Ok(serde_json::to_string_pretty(output)?),
        "env" => {
            let lines: String = cipher_to_env_vars(output)
                .into_iter()
                .map(|(name, value)| format!("export {}=\"{}\"\n", name, escape_value(&value)))
                .collect();
            Ok(lines)
        }
        "value" | "password" => get_field_string(&output.password, "password"),
        "username" => get_field_string(&output.username, "username"),
        _ => anyhow::bail!(
            "Unknown format: {}. Use: json, env, value, username",
            format
        ),
    }
}

fn print_cipher_output(output: &CipherOutput, format: &str) -> Result<()> {
    let text = format_cipher_output(output, format)?;
    match format {
        "json" => println!("{}", text),
        _ => print!("{}", text),
    }
    Ok(())
}

pub async fn list(
    profile: &str,
    password: Option<&str>,
    type_filter: Option<String>,
    search: Option<String>,
    org_filter: Option<String>,
    collection_filter: Option<String>,
) -> Result<()> {
    let ctx = load_sync_context(profile, password).await?;

    let org_id_filter = org_filter
        .as_deref()
        .map(|org| resolve_org_id(&ctx.sync_response.profile, org))
        .transpose()?;

    let collection_id_filter = collection_filter
        .as_deref()
        .map(|collection| {
            resolve_collection_id(
                &ctx.sync_response.collections,
                &ctx.keys,
                collection,
                org_id_filter.as_deref(),
            )
        })
        .transpose()?;

    let mut ciphers: Vec<&Cipher> = ctx
        .sync_response
        .ciphers
        .iter()
        .filter(|c| {
            cipher_matches_filters(
                c,
                org_id_filter.as_deref(),
                collection_id_filter.as_deref(),
                None,
            )
        })
        .collect();

    if let Some(type_str) = &type_filter {
        if let Ok(cipher_type) = CipherType::from_str(type_str) {
            ciphers.retain(|c| c.cipher_type() == Some(cipher_type));
        } else {
            anyhow::bail!(
                "Invalid type filter: {}. Use: login, note, card, identity, ssh",
                type_str
            );
        }
    }

    let search_lower = search.as_ref().map(|s| s.to_lowercase());
    let mut outputs: Vec<CipherOutput> = Vec::new();

    for cipher in ciphers {
        let keys = match get_cipher_keys(&ctx.keys, cipher) {
            Ok(k) => k,
            Err(_) => continue,
        };

        if let Ok(output) = decrypt_cipher(cipher, &keys) {
            if let Some(term) = &search_lower
                && !output_matches_search(&output, term)
            {
                continue;
            }
            outputs.push(output);
        }
    }

    println!("{}", serde_json::to_string_pretty(&outputs)?);
    Ok(())
}

pub async fn get(
    profile: &str,
    password: Option<&str>,
    item: &str,
    format: &str,
    org_filter: Option<String>,
    collection_filter: Option<String>,
) -> Result<()> {
    let ctx = load_sync_context(profile, password).await?;

    let org_id_filter = org_filter
        .as_deref()
        .map(|org| resolve_org_id(&ctx.sync_response.profile, org))
        .transpose()?;

    let collection_id_filter = collection_filter
        .as_deref()
        .map(|collection| {
            resolve_collection_id(
                &ctx.sync_response.collections,
                &ctx.keys,
                collection,
                org_id_filter.as_deref(),
            )
        })
        .transpose()?;

    let matches = |c: &Cipher| {
        cipher_matches_filters(
            c,
            org_id_filter.as_deref(),
            collection_id_filter.as_deref(),
            None,
        )
    };

    let output = if let Some(cipher) = ctx
        .sync_response
        .ciphers
        .iter()
        .find(|c| c.id == item && matches(c))
    {
        let keys = get_cipher_keys(&ctx.keys, cipher)?;
        decrypt_cipher(cipher, &keys)?
    } else {
        let item_lower = item.to_lowercase();
        find_cipher_output(
            &ctx.sync_response.ciphers,
            &ctx.keys,
            |o| o.name.to_lowercase() == item_lower,
            matches,
        )
        .with_context(|| format!("Item '{}' not found", item))?
    };

    print_cipher_output(&output, format)
}

pub async fn get_by_uri(
    profile: &str,
    password: Option<&str>,
    uri: &str,
    format: &str,
    org_filter: Option<String>,
    collection_filter: Option<String>,
) -> Result<()> {
    let ctx = load_sync_context(profile, password).await?;

    let org_id_filter = org_filter
        .as_deref()
        .map(|org| resolve_org_id(&ctx.sync_response.profile, org))
        .transpose()?;

    let collection_id_filter = collection_filter
        .as_deref()
        .map(|collection| {
            resolve_collection_id(
                &ctx.sync_response.collections,
                &ctx.keys,
                collection,
                org_id_filter.as_deref(),
            )
        })
        .transpose()?;

    let uri_lower = uri.to_lowercase();
    let output = find_cipher_output(
        &ctx.sync_response.ciphers,
        &ctx.keys,
        |o| {
            o.uri
                .as_ref()
                .map(|u| u.to_lowercase().contains(&uri_lower))
                .unwrap_or(false)
        },
        |c| {
            cipher_matches_filters(
                c,
                org_id_filter.as_deref(),
                collection_id_filter.as_deref(),
                None,
            )
        },
    )
    .with_context(|| format!("No item found with URI containing '{}'", uri))?;

    print_cipher_output(&output, format)
}

pub struct RunRequest<'a> {
    pub requested_items: &'a [String],
    pub search_by_uri: bool,
    pub org_filter: Option<&'a str>,
    pub folder_filter: Option<&'a str>,
    pub collection_filter: Option<&'a str>,
    pub info_only: bool,
    pub command: &'a [String],
}

pub async fn run_with_secrets(
    profile: &str,
    password: Option<&str>,
    request: RunRequest<'_>,
) -> Result<()> {
    if !request.search_by_uri
        && request.requested_items.is_empty()
        && request.org_filter.is_none()
        && request.folder_filter.is_none()
        && request.collection_filter.is_none()
    {
        anyhow::bail!(
            "At least one of --name, --org, --folder, or --collection must be specified."
        );
    }

    let ctx = load_sync_context(profile, password).await?;

    let org_id_filter = request
        .org_filter
        .map(|org| resolve_org_id(&ctx.sync_response.profile, org))
        .transpose()?;

    let folder_id_filter: Option<String> = if let Some(folder) = request.folder_filter {
        if let Some(f) = ctx.sync_response.folders.iter().find(|f| f.id == folder) {
            Some(f.id.clone())
        } else {
            let matched = ctx.sync_response.folders.iter().find(|f| {
                ctx.keys
                    .user
                    .decrypt_to_string(&f.name)
                    .ok()
                    .map(|n| n.eq_ignore_ascii_case(folder))
                    .unwrap_or(false)
            });

            Some(
                matched
                    .with_context(|| format!("Folder '{}' not found", folder))?
                    .id
                    .clone(),
            )
        }
    } else {
        None
    };

    let collection_id_filter = request
        .collection_filter
        .map(|col| {
            resolve_collection_id(
                &ctx.sync_response.collections,
                &ctx.keys,
                col,
                org_id_filter.as_deref(),
            )
        })
        .transpose()?;

    let matches_filters = |cipher: &Cipher| {
        cipher_matches_filters(
            cipher,
            org_id_filter.as_deref(),
            collection_id_filter.as_deref(),
            folder_id_filter.as_deref(),
        )
    };

    let find_by_name_or_id = |name_or_id: &str| -> Result<CipherOutput> {
        let cipher_by_id = ctx
            .sync_response
            .ciphers
            .iter()
            .find(|c| c.id == name_or_id && matches_filters(c));

        if let Some(cipher) = cipher_by_id {
            let keys = get_cipher_keys(&ctx.keys, cipher)?;
            return decrypt_cipher(cipher, &keys);
        }

        let item_lower = name_or_id.to_lowercase();
        find_cipher_output(
            &ctx.sync_response.ciphers,
            &ctx.keys,
            |o| o.name.to_lowercase() == item_lower,
            matches_filters,
        )
        .with_context(|| format!("Item '{}' not found", name_or_id))
    };

    let outputs: Vec<CipherOutput> = if request.search_by_uri {
        let uri = request
            .requested_items
            .first()
            .context("URI is required for URI search")?;
        let uri_lower = uri.to_lowercase();

        vec![
            find_cipher_output(
                &ctx.sync_response.ciphers,
                &ctx.keys,
                |o| {
                    o.uri
                        .as_ref()
                        .map(|u| u.to_lowercase().contains(&uri_lower))
                        .unwrap_or(false)
                },
                matches_filters,
            )
            .with_context(|| format!("No item found with URI containing '{}'", uri))?,
        ]
    } else if !request.requested_items.is_empty() {
        request
            .requested_items
            .iter()
            .map(|name| find_by_name_or_id(name))
            .collect::<Result<Vec<_>>>()?
    } else {
        let outputs: Vec<CipherOutput> = ctx
            .sync_response
            .ciphers
            .iter()
            .filter(|cipher| matches_filters(cipher))
            .filter_map(|cipher| {
                let keys = get_cipher_keys(&ctx.keys, cipher).ok()?;
                decrypt_cipher(cipher, &keys).ok()
            })
            .collect();

        if outputs.is_empty() {
            anyhow::bail!("No item found matching the specified filters");
        }

        outputs
    };

    let mut env_vars = Vec::new();
    for output in outputs {
        env_vars.extend(cipher_to_env_vars(&output));
    }

    if request.info_only {
        let names: Vec<String> = env_vars.iter().map(|(name, _)| name.clone()).collect();
        println!("{}", serde_json::to_string_pretty(&names)?);
        return Ok(());
    }

    if request.command.is_empty() {
        anyhow::bail!("No command specified. Use -- followed by the command to run.");
    }

    let mut cmd = Command::new(&request.command[0]);
    if request.command.len() > 1 {
        cmd.args(&request.command[1..]);
    }

    for (name, value) in &env_vars {
        cmd.env(name, value);
    }

    let status = cmd
        .status()
        .with_context(|| format!("Failed to execute command: {}", request.command[0]))?;

    if !status.success() {
        anyhow::bail!("Child command exited with status {}", status);
    }

    Ok(())
}

struct WriteRuntimeContext {
    _lock: crate::config::ProfileLock,
    access_token: String,
    api: ApiClient,
    sync_response: crate::models::SyncResponse,
    keys: RuntimeKeys,
}

async fn load_write_context(profile: &str, password: &str) -> Result<WriteRuntimeContext> {
    let lock = Config::acquire_profile_lock(profile)?;
    let mut config = Config::load(profile)?;
    let access_token = ensure_valid_token(profile, &mut config).await?;
    let keys = derive_runtime_keys(&config, password)?;
    let api = ApiClient::from_config(&config)?;

    let mut sync_response = api.sync(&access_token).await?;
    if let Ok(cipher_list) = api.ciphers(&access_token).await {
        sync_response.ciphers = cipher_list.data;
    }

    Ok(WriteRuntimeContext {
        _lock: lock,
        access_token,
        api,
        sync_response,
        keys,
    })
}

fn validate_item_type(input: &WriteInputV1) -> Result<CipherType> {
    let kind = CipherType::from_str(&input.item_type).map_err(|_| {
        make_write_error(
            "VALIDATION_ERROR",
            "Invalid type. Use login or note",
            false,
            "fix_input",
        )
    })?;
    match kind {
        CipherType::Login => {
            if input.login.is_none() {
                return Err(make_write_error(
                    "VALIDATION_ERROR",
                    "login payload is required for type=login",
                    false,
                    "fix_input",
                ));
            }
            if input.note.is_some() {
                return Err(make_write_error(
                    "VALIDATION_ERROR",
                    "note payload is not allowed for type=login",
                    false,
                    "fix_input",
                ));
            }
        }
        CipherType::SecureNote => {
            if input.login.is_some() {
                return Err(make_write_error(
                    "VALIDATION_ERROR",
                    "login payload is not allowed for type=note",
                    false,
                    "fix_input",
                ));
            }
        }
        _ => {
            return Err(make_write_error(
                "VALIDATION_ERROR",
                "Initial write GA supports only login and note",
                false,
                "fix_input",
            ));
        }
    }

    if let Some(reprompt) = input.reprompt
        && reprompt != 0
        && reprompt != 1
    {
        return Err(make_write_error(
            "VALIDATION_ERROR",
            "reprompt must be 0 or 1",
            false,
            "fix_input",
        ));
    }

    if let Some(fields) = &input.fields {
        for field in fields {
            if let Some(t) = field.field_type
                && t > 3
            {
                return Err(make_write_error(
                    "VALIDATION_ERROR",
                    "field_type must be 0..=3",
                    false,
                    "fix_input",
                ));
            }
        }
    }

    Ok(kind)
}

fn parse_scope(scope: &str) -> Result<Option<String>> {
    if scope.eq_ignore_ascii_case("personal") {
        return Ok(None);
    }

    let Some(org_id) = scope.strip_prefix("org:") else {
        return Err(make_write_error(
            "VALIDATION_ERROR",
            "Invalid scope. Use personal or org:<id>",
            false,
            "fix_input",
        ));
    };

    if org_id.trim().is_empty() {
        return Err(make_write_error(
            "VALIDATION_ERROR",
            "org scope requires non-empty org id",
            false,
            "fix_input",
        ));
    }

    Ok(Some(org_id.to_string()))
}

fn first_uri_from_write_input(input: &WriteInputV1) -> Option<&str> {
    input
        .login
        .as_ref()
        .and_then(|l| l.uris.as_ref())
        .and_then(|u| u.first())
        .map(|u| u.uri.as_str())
}

fn get_write_keys(runtime_keys: &RuntimeKeys, org_id: Option<&str>) -> Result<CryptoKeys> {
    if let Some(org) = org_id {
        return runtime_keys.org.get(org).cloned().ok_or_else(|| {
            make_write_error(
                "PERMISSION_DENIED",
                format!("Organization key unavailable for org {}", org),
                false,
                "check_permissions",
            )
        });
    }

    Ok(runtime_keys.user.clone())
}

fn encrypt_opt(keys: &CryptoKeys, value: Option<&str>) -> Result<Option<String>> {
    value.map(|v| keys.encrypt_string(v)).transpose()
}

fn build_write_payload(
    input: &WriteInputV1,
    keys: &CryptoKeys,
    last_known_revision_date: Option<&str>,
) -> Result<WriteCipherPayload> {
    let cipher_type = validate_item_type(input)?;
    let encrypted_name = keys.encrypt_string(&input.name)?;
    let encrypted_notes = encrypt_opt(keys, input.notes.as_deref())?;

    let fields_json = input
        .fields
        .as_ref()
        .map(|fields| {
            fields
                .iter()
                .map(|f| {
                    Ok(json!({
                        "name": keys.encrypt_string(&f.name)?,
                        "value": encrypt_opt(keys, f.value.as_deref())?,
                        "type": f.field_type.unwrap_or(0)
                    }))
                })
                .collect::<Result<Vec<Value>>>()
        })
        .transpose()?;

    let login_json = if cipher_type == CipherType::Login {
        let login = input.login.as_ref().context("login data required")?;
        let uris = login
            .uris
            .as_ref()
            .map(|uris| {
                uris.iter()
                    .map(|u| {
                        Ok(json!({
                            "uri": keys.encrypt_string(&u.uri)?,
                            "match": u.r#match
                        }))
                    })
                    .collect::<Result<Vec<Value>>>()
            })
            .transpose()?;

        Some(json!({
            "username": encrypt_opt(keys, login.username.as_deref())?,
            "password": encrypt_opt(keys, login.password.as_deref())?,
            "totp": encrypt_opt(keys, login.totp.as_deref())?,
            "uris": uris
        }))
    } else {
        None
    };

    let note_json = if cipher_type == CipherType::SecureNote {
        let note_type = input
            .note
            .as_ref()
            .and_then(|n| n.secure_note_type)
            .unwrap_or(0);
        Some(json!({ "type": note_type }))
    } else {
        None
    };

    Ok(json!({
        "folderId": input.folder_id,
        "organizationId": input.organization_id,
        "key": Value::Null,
        "type": cipher_type as u8,
        "name": encrypted_name,
        "notes": encrypted_notes,
        "fields": fields_json,
        "login": login_json,
        "secureNote": note_json,
        "card": Value::Null,
        "identity": Value::Null,
        "sshKey": Value::Null,
        "favorite": input.favorite,
        "reprompt": input.reprompt,
        "passwordHistory": Value::Null,
        "lastKnownRevisionDate": last_known_revision_date
    }))
}

fn parse_write_input_payload(
    password_stdin: bool,
    input_path: &str,
) -> Result<(String, WriteInputV1)> {
    let (password, payload) =
        load_input_payload(input_path, password_stdin).map_err(map_write_error)?;

    let input = serde_json::from_str::<WriteInputV1>(&payload).map_err(|e| {
        make_write_error(
            "VALIDATION_ERROR",
            format!("Invalid write input JSON: {}", e),
            false,
            "fix_input",
        )
    })?;

    Ok((password, input))
}

fn write_success(operation: &str, cipher: &Cipher, warnings: Vec<String>) -> Result<()> {
    let success = WriteCommandSuccess {
        ok: true,
        operation: operation.to_string(),
        id: cipher.id.clone(),
        revision_date: cipher.revision_date.clone(),
        organization_id: cipher.organization_id.clone(),
        warnings,
    };
    println!("{}", serde_json::to_string_pretty(&success)?);
    Ok(())
}

fn resolve_scope_for_input(input: &mut WriteInputV1, scope: Option<&str>) -> Result<()> {
    if let Some(scope) = scope {
        let scope_org = parse_scope(scope)?;
        match scope_org {
            None => {
                if input.organization_id.is_some() {
                    return Err(make_write_error(
                        "VALIDATION_ERROR",
                        "organization_id is not allowed for personal scope",
                        false,
                        "fix_input",
                    ));
                }
            }
            Some(org_id) => match &input.organization_id {
                Some(input_org) if input_org != &org_id => {
                    return Err(make_write_error(
                        "VALIDATION_ERROR",
                        "scope org id does not match input organization_id",
                        false,
                        "fix_input",
                    ));
                }
                _ => input.organization_id = Some(org_id),
            },
        }
    }
    Ok(())
}

async fn create_cipher_with_context(
    ctx: &WriteRuntimeContext,
    input: &WriteInputV1,
    dry_run: bool,
) -> Result<Cipher> {
    let _ = validate_item_type(input)?;
    let keys = get_write_keys(&ctx.keys, input.organization_id.as_deref())?;
    let payload = build_write_payload(input, &keys, None)?;

    if dry_run {
        return Ok(Cipher {
            id: "dry-run".to_string(),
            r#type: payload["type"].as_u64().unwrap_or(0) as u8,
            organization_id: input.organization_id.clone(),
            key: None,
            revision_date: None,
            favorite: input.favorite,
            reprompt: input.reprompt,
            name: Some(payload["name"].as_str().unwrap_or_default().to_string()),
            notes: payload["notes"].as_str().map(|s| s.to_string()),
            folder_id: input.folder_id.clone(),
            login: None,
            card: None,
            identity: None,
            secure_note: None,
            ssh_key: None,
            collection_ids: input.collection_ids.clone().unwrap_or_default(),
            fields: None,
            data: None,
        });
    }

    if input.organization_id.is_some() {
        let collection_ids = input.collection_ids.clone().ok_or_else(|| {
            make_write_error(
                "VALIDATION_ERROR",
                "collection_ids is required for org create",
                false,
                "fix_input",
            )
        })?;

        if collection_ids.is_empty() {
            return Err(make_write_error(
                "VALIDATION_ERROR",
                "collection_ids must not be empty for org create",
                false,
                "fix_input",
            ));
        }

        ctx.api
            .create_org_cipher(&ctx.access_token, &payload, &collection_ids)
            .await
    } else {
        if input.collection_ids.as_ref().is_some_and(|c| !c.is_empty()) {
            return Err(make_write_error(
                "VALIDATION_ERROR",
                "collection_ids is only valid for org scope",
                false,
                "fix_input",
            ));
        }
        ctx.api.create_cipher(&ctx.access_token, &payload).await
    }
}

async fn update_cipher_with_context(
    ctx: &WriteRuntimeContext,
    cipher_id: &str,
    if_revision: &str,
    input: &WriteInputV1,
    dry_run: bool,
) -> Result<Cipher> {
    let _ = validate_item_type(input)?;
    let existing = ctx
        .sync_response
        .ciphers
        .iter()
        .find(|c| c.id == cipher_id)
        .ok_or_else(|| make_write_error("NOT_FOUND", "Cipher not found", false, "verify_target"))?;

    if let Some(org) = &input.organization_id
        && existing.organization_id.as_deref() != Some(org)
    {
        return Err(make_write_error(
            "VALIDATION_ERROR",
            "organization_id does not match target cipher",
            false,
            "fix_input",
        ));
    }

    let keys = get_write_keys(
        &ctx.keys,
        input
            .organization_id
            .as_deref()
            .or(existing.organization_id.as_deref()),
    )?;
    let payload = build_write_payload(input, &keys, Some(if_revision))?;

    if dry_run {
        return Ok(existing.clone());
    }

    let updated = ctx
        .api
        .update_cipher(&ctx.access_token, cipher_id, &payload)
        .await?;

    if updated.organization_id.is_some()
        && let Some(collection_ids) = &input.collection_ids
        && !collection_ids.is_empty()
    {
        let _ = ctx
            .api
            .update_collections_v2(&ctx.access_token, cipher_id, collection_ids)
            .await?;
    }

    Ok(updated)
}

pub async fn write_create(
    profile: &str,
    password_stdin: bool,
    input_path: &str,
    dry_run: bool,
) -> Result<()> {
    match async {
        let (password, mut input) = parse_write_input_payload(password_stdin, input_path)?;
        resolve_scope_for_input(&mut input, None)?;
        let ctx = load_write_context(profile, &password).await?;
        let cipher = create_cipher_with_context(&ctx, &input, dry_run).await?;
        write_success("create", &cipher, vec![])
    }
    .await
    {
        Ok(()) => Ok(()),
        Err(err) => Err(map_write_error(err)),
    }
}

pub async fn write_update(
    profile: &str,
    password_stdin: bool,
    cipher_id: &str,
    if_revision: &str,
    input_path: &str,
    dry_run: bool,
) -> Result<()> {
    match async {
        let (password, mut input) = parse_write_input_payload(password_stdin, input_path)?;
        resolve_scope_for_input(&mut input, None)?;
        let ctx = load_write_context(profile, &password).await?;
        let cipher =
            update_cipher_with_context(&ctx, cipher_id, if_revision, &input, dry_run).await?;
        write_success("update", &cipher, vec![])
    }
    .await
    {
        Ok(()) => Ok(()),
        Err(err) => Err(map_write_error(err)),
    }
}

pub async fn write_upsert(
    profile: &str,
    password_stdin: bool,
    match_alg: &str,
    scope: &str,
    input_path: &str,
    dry_run: bool,
) -> Result<()> {
    match async {
        if !match_alg.eq_ignore_ascii_case("name_uri") {
            return Err(make_write_error(
                "VALIDATION_ERROR",
                "Only match=name_uri is supported",
                false,
                "fix_input",
            ));
        }

        let (password, mut input) = parse_write_input_payload(password_stdin, input_path)?;
        resolve_scope_for_input(&mut input, Some(scope))?;
        let ctx = load_write_context(profile, &password).await?;

        let target_uri = first_uri_from_write_input(&input).map(|s| s.to_string());

        let mut matches: Vec<&Cipher> = Vec::new();
        for cipher in &ctx.sync_response.ciphers {
            if input.organization_id.is_some() {
                if cipher.organization_id != input.organization_id {
                    continue;
                }
            } else if cipher.organization_id.is_some() {
                continue;
            }

            let keys = match get_cipher_keys(&ctx.keys, cipher) {
                Ok(keys) => keys,
                Err(_) => continue,
            };
            let output = match decrypt_cipher(cipher, &keys) {
                Ok(output) => output,
                Err(_) => continue,
            };

            if output.name == input.name && output.uri == target_uri {
                matches.push(cipher);
            }
        }

        if matches.len() > 1 {
            return Err(make_write_error(
                "AMBIGUOUS_MATCH",
                "Upsert match produced multiple ciphers",
                false,
                "refine_match",
            ));
        }

        if let Some(existing) = matches.first() {
            let revision = existing.revision_date.as_deref().ok_or_else(|| {
                make_write_error(
                    "CONFLICT_STALE_REVISION",
                    "Matched cipher is missing revision date",
                    true,
                    "resync_and_retry",
                )
            })?;
            let updated =
                update_cipher_with_context(&ctx, &existing.id, revision, &input, dry_run).await?;
            return write_success("upsert_update", &updated, vec![]);
        }

        let created = create_cipher_with_context(&ctx, &input, dry_run).await?;
        write_success("upsert_create", &created, vec![])
    }
    .await
    {
        Ok(()) => Ok(()),
        Err(err) => Err(map_write_error(err)),
    }
}

fn decrypt_cipher_to_write_input(cipher: &Cipher, keys: &CryptoKeys) -> Result<WriteInputV1> {
    let item_type = cipher.cipher_type().ok_or_else(|| {
        make_write_error(
            "VALIDATION_ERROR",
            "Unsupported cipher type",
            false,
            "fix_input",
        )
    })?;

    let mut input = WriteInputV1 {
        item_type: item_type.to_string(),
        name: keys
            .decrypt_to_string(cipher.get_name().context("Cipher has no name")?)
            .context("Failed to decrypt cipher name")?,
        notes: None,
        folder_id: cipher.folder_id.clone(),
        organization_id: cipher.organization_id.clone(),
        collection_ids: if cipher.collection_ids.is_empty() {
            None
        } else {
            Some(cipher.collection_ids.clone())
        },
        favorite: cipher.favorite,
        reprompt: cipher.reprompt,
        fields: None,
        login: None,
        note: None,
    };

    input.notes = cipher
        .get_notes()
        .map(|n| keys.decrypt_to_string(n))
        .transpose()
        .context("Failed to decrypt cipher notes")?;

    if let Some(fields) = cipher.get_fields() {
        let mut decrypted_fields = Vec::new();
        for field in fields {
            let Some(name) = field
                .name
                .as_ref()
                .and_then(|n| keys.decrypt_to_string(n).ok())
            else {
                continue;
            };
            let value = field
                .value
                .as_ref()
                .and_then(|v| keys.decrypt_to_string(v).ok());
            decrypted_fields.push(crate::models::WriteFieldV1 {
                name,
                value,
                field_type: Some(field.r#type),
            });
        }
        if !decrypted_fields.is_empty() {
            input.fields = Some(decrypted_fields);
        }
    }

    match item_type {
        CipherType::Login => {
            let login = cipher.login.as_ref().ok_or_else(|| {
                make_write_error(
                    "VALIDATION_ERROR",
                    "Missing login payload",
                    false,
                    "fix_input",
                )
            })?;
            let uris = login
                .uris
                .as_ref()
                .map(|uris| {
                    uris.iter()
                        .filter_map(|u| {
                            let uri = u.uri.as_ref()?;
                            let decrypted = keys.decrypt_to_string(uri).ok()?;
                            Some(crate::models::WriteUriV1 {
                                uri: decrypted,
                                r#match: u.r#match,
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .filter(|v| !v.is_empty());
            input.login = Some(crate::models::WriteLoginV1 {
                username: login
                    .username
                    .as_ref()
                    .and_then(|u| keys.decrypt_to_string(u).ok()),
                password: login
                    .password
                    .as_ref()
                    .and_then(|p| keys.decrypt_to_string(p).ok()),
                totp: login
                    .totp
                    .as_ref()
                    .and_then(|t| keys.decrypt_to_string(t).ok()),
                uris,
            });
        }
        CipherType::SecureNote => {
            input.note = Some(crate::models::WriteNoteV1 {
                secure_note_type: cipher
                    .secure_note
                    .as_ref()
                    .and_then(|n| n.r#type)
                    .or(Some(0)),
            });
        }
        _ => {
            return Err(make_write_error(
                "VALIDATION_ERROR",
                "Only login/note write helpers are currently supported",
                false,
                "fix_input",
            ));
        }
    }

    Ok(input)
}

pub async fn write_rotate_password(
    profile: &str,
    password_stdin: bool,
    cipher_id: &str,
    if_revision: &str,
    input_path: &str,
    dry_run: bool,
) -> Result<()> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RotateInput {
        new_password: String,
    }

    match async {
        let (password, payload) =
            load_input_payload(input_path, password_stdin).map_err(map_write_error)?;
        let rotate: RotateInput = serde_json::from_str(&payload).map_err(|e| {
            make_write_error(
                "VALIDATION_ERROR",
                format!("Invalid rotate-password input JSON: {}", e),
                false,
                "fix_input",
            )
        })?;

        let ctx = load_write_context(profile, &password).await?;
        let cipher = ctx
            .sync_response
            .ciphers
            .iter()
            .find(|c| c.id == cipher_id)
            .ok_or_else(|| {
                make_write_error("NOT_FOUND", "Cipher not found", false, "verify_target")
            })?;

        if cipher.cipher_type() != Some(CipherType::Login) {
            return Err(make_write_error(
                "VALIDATION_ERROR",
                "rotate-password is only supported for login items",
                false,
                "fix_input",
            ));
        }

        let keys = get_cipher_keys(&ctx.keys, cipher)?;
        let mut input = decrypt_cipher_to_write_input(cipher, &keys)?;
        let login = input.login.as_mut().ok_or_else(|| {
            make_write_error(
                "VALIDATION_ERROR",
                "Missing login block on target item",
                false,
                "fix_input",
            )
        })?;
        login.password = Some(rotate.new_password);

        let updated =
            update_cipher_with_context(&ctx, cipher_id, if_revision, &input, dry_run).await?;
        write_success("rotate_password", &updated, vec![])
    }
    .await
    {
        Ok(()) => Ok(()),
        Err(err) => Err(map_write_error(err)),
    }
}

pub async fn write_patch_fields(
    profile: &str,
    password_stdin: bool,
    cipher_id: &str,
    if_revision: &str,
    input_path: &str,
    dry_run: bool,
) -> Result<()> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PatchFieldsInput {
        fields: Vec<crate::models::WriteFieldV1>,
    }

    match async {
        let (password, payload) =
            load_input_payload(input_path, password_stdin).map_err(map_write_error)?;
        let patch: PatchFieldsInput = serde_json::from_str(&payload).map_err(|e| {
            make_write_error(
                "VALIDATION_ERROR",
                format!("Invalid patch-fields input JSON: {}", e),
                false,
                "fix_input",
            )
        })?;

        let ctx = load_write_context(profile, &password).await?;
        let cipher = ctx
            .sync_response
            .ciphers
            .iter()
            .find(|c| c.id == cipher_id)
            .ok_or_else(|| {
                make_write_error("NOT_FOUND", "Cipher not found", false, "verify_target")
            })?;
        let keys = get_cipher_keys(&ctx.keys, cipher)?;
        let mut input = decrypt_cipher_to_write_input(cipher, &keys)?;
        input.fields = Some(patch.fields);

        let updated =
            update_cipher_with_context(&ctx, cipher_id, if_revision, &input, dry_run).await?;
        write_success("patch_fields", &updated, vec![])
    }
    .await
    {
        Ok(()) => Ok(()),
        Err(err) => Err(map_write_error(err)),
    }
}

pub async fn write_move(
    profile: &str,
    password_stdin: bool,
    cipher_id: &str,
    if_revision: &str,
    folder_id: Option<&str>,
    favorite: Option<bool>,
    dry_run: bool,
) -> Result<()> {
    match async {
        if !password_stdin {
            return Err(make_write_error(
                "VALIDATION_ERROR",
                "--password-stdin is required for write commands",
                false,
                "fix_input",
            ));
        }
        let password = extract_secret(&read_stdin_all()?)
            .map_err(|e| make_write_error("VALIDATION_ERROR", e.to_string(), false, "fix_input"))?;

        let ctx = load_write_context(profile, &password).await?;
        let current = ctx
            .sync_response
            .ciphers
            .iter()
            .find(|c| c.id == cipher_id)
            .ok_or_else(|| {
                make_write_error("NOT_FOUND", "Cipher not found", false, "verify_target")
            })?;
        let current_revision = current.revision_date.as_deref().ok_or_else(|| {
            make_write_error(
                "CONFLICT_STALE_REVISION",
                "Target cipher is missing revision date; resync and retry",
                true,
                "resync_and_retry",
            )
        })?;
        if current_revision != if_revision {
            return Err(make_write_error(
                "CONFLICT_STALE_REVISION",
                "The client copy of this cipher is out of date. Resync the client and try again.",
                true,
                "resync_and_retry",
            ));
        }

        if dry_run {
            return write_success(
                "move",
                current,
                vec!["dry-run: no mutation performed".to_string()],
            );
        }

        let updated = ctx
            .api
            .update_cipher_partial(
                &ctx.access_token,
                cipher_id,
                folder_id,
                favorite.unwrap_or_else(|| current.favorite.unwrap_or(false)),
            )
            .await?;

        write_success("move", &updated, vec![])
    }
    .await
    {
        Ok(()) => Ok(()),
        Err(err) => Err(map_write_error(err)),
    }
}

#[cfg(test)]
mod write_tests {
    use super::*;

    fn test_keys() -> CryptoKeys {
        let mut raw = vec![0x42u8; 32];
        raw.extend_from_slice(&[0x43u8; 32]);
        CryptoKeys::from_symmetric_key(&raw).expect("valid key material")
    }

    #[test]
    fn split_password_and_json_requires_two_segments() {
        assert!(split_password_and_json("just-password").is_err());
        assert!(split_password_and_json("pw\n").is_err());
    }

    #[test]
    fn split_password_and_json_parses_first_line_secret() {
        let (password, payload) =
            split_password_and_json("pw123\n{\"type\":\"note\",\"name\":\"n\"}")
                .expect("split should succeed");
        assert_eq!(password, "pw123");
        assert_eq!(payload, "{\"type\":\"note\",\"name\":\"n\"}");
    }

    #[test]
    fn parse_scope_supports_personal_and_org() {
        assert_eq!(parse_scope("personal").expect("scope"), None);
        assert_eq!(
            parse_scope("org:org-123").expect("scope"),
            Some("org-123".to_string())
        );
        assert!(parse_scope("org:").is_err());
    }

    #[test]
    fn build_write_payload_encrypts_sensitive_fields() {
        let keys = test_keys();
        let input = WriteInputV1 {
            item_type: "login".to_string(),
            name: "svc/github".to_string(),
            notes: Some("hello".to_string()),
            folder_id: None,
            organization_id: None,
            collection_ids: None,
            favorite: Some(false),
            reprompt: Some(0),
            fields: None,
            login: Some(crate::models::WriteLoginV1 {
                username: Some("bot".to_string()),
                password: Some("pw".to_string()),
                totp: None,
                uris: Some(vec![crate::models::WriteUriV1 {
                    uri: "https://github.com".to_string(),
                    r#match: None,
                }]),
            }),
            note: None,
        };

        let payload = build_write_payload(&input, &keys, None).expect("payload");
        assert!(
            payload["name"]
                .as_str()
                .is_some_and(|s| s.starts_with("2."))
        );
        assert!(
            payload["login"]["password"]
                .as_str()
                .is_some_and(|s| s.starts_with("2."))
        );
    }
}
