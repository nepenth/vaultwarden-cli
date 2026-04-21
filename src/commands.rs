use anyhow::{Context, Result};
use serde_json::json;
use std::collections::HashMap;
use std::process::Command;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::api::ApiClient;
use crate::config::Config;
use crate::crypto::CryptoKeys;
use crate::models::{Cipher, CipherOutput, CipherType, FieldOutput};

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before UNIX epoch")
        .as_secs() as i64
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
    let mut config = Config::load(profile)?;
    let access_token = ensure_valid_token(profile, &mut config).await?;
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

fn get_cipher_keys<'a>(runtime_keys: &'a RuntimeKeys, cipher: &Cipher) -> Result<&'a CryptoKeys> {
    if let Some(org_id) = &cipher.organization_id {
        return runtime_keys
            .org
            .get(org_id)
            .with_context(|| format!("Organization key unavailable for org {}", org_id));
    }

    Ok(&runtime_keys.user)
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

        if let Ok(output) = decrypt_cipher(cipher, keys)
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

        if let Ok(output) = decrypt_cipher(cipher, keys) {
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
        decrypt_cipher(cipher, keys)?
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
            return decrypt_cipher(cipher, keys);
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
                decrypt_cipher(cipher, keys).ok()
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
