use anyhow::{Context, Result};
use directories::ProjectDirs;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

pub struct ProfileLock {
    file: File,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    pub server: Option<String>,
    pub client_id: Option<String>,
    pub email: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub token_expiry: Option<i64>,
    pub encrypted_key: Option<String>,
    pub encrypted_private_key: Option<String>,
    pub kdf_iterations: Option<u32>,
    #[serde(default)]
    pub org_keys: HashMap<String, String>,
}

impl Config {
    pub fn acquire_profile_lock(profile: &str) -> Result<ProfileLock> {
        let dir = Self::config_dir(profile)?;
        #[cfg(unix)]
        {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder
                .create(&dir)
                .with_context(|| format!("Failed to create config directory {:?}", dir))?;
        }

        #[cfg(not(unix))]
        {
            fs::create_dir_all(&dir)
                .with_context(|| format!("Failed to create config directory {:?}", dir))?;
        }

        let lock_path = dir.join(".lock");
        let file = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("Failed to open profile lock file {:?}", lock_path))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("Failed to set permissions on {:?}", lock_path))?;
        }

        file.lock_exclusive()
            .with_context(|| format!("Failed to acquire lock on {:?}", lock_path))?;

        Ok(ProfileLock { file })
    }

    pub fn validate_profile(profile: &str) -> Result<()> {
        if profile.is_empty() {
            anyhow::bail!("Profile must not be empty")
        }

        if profile.len() > 64 {
            anyhow::bail!("Profile must be 64 characters or fewer")
        }

        let mut chars = profile.chars();
        let first = chars.next().context("Profile must not be empty")?;
        if !first.is_ascii_alphanumeric() {
            anyhow::bail!("Profile must start with an ASCII letter or number")
        }

        if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
            anyhow::bail!("Profile may only contain ASCII letters, numbers, '.', '_', and '-'")
        }

        Ok(())
    }

    pub fn config_dir(profile: &str) -> Result<PathBuf> {
        Self::validate_profile(profile)?;

        let root = ProjectDirs::from("com", "vaultwarden", "vaultwarden-cli")
            .map(|dirs| dirs.config_dir().to_path_buf())
            .context("Failed to determine config directory")?;

        Ok(root.join("profiles").join(profile))
    }

    pub fn config_path(profile: &str) -> Result<PathBuf> {
        Ok(Self::config_dir(profile)?.join("config.json"))
    }

    pub fn load(profile: &str) -> Result<Self> {
        let path = Self::config_path(profile)?;
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config from {:?}", path))?;
        serde_json::from_str(&content).context("Failed to parse config")
    }

    pub fn save(&self, profile: &str) -> Result<()> {
        let path = Self::config_path(profile)?;
        let parent = path
            .parent()
            .context("Failed to determine config directory parent")?;

        #[cfg(unix)]
        {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder
                .create(parent)
                .with_context(|| format!("Failed to create config directory {:?}", parent))?;
        }

        #[cfg(not(unix))]
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory {:?}", parent))?;
        }

        let content = serde_json::to_vec_pretty(self)?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before UNIX epoch")
            .as_nanos();
        let tmp_path = path.with_extension(format!("json.tmp.{}", nanos));

        #[cfg(unix)]
        {
            use std::io::Write;

            let mut file = fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o600)
                .open(&tmp_path)
                .with_context(|| {
                    format!("Failed to open temp config path {:?} for writing", tmp_path)
                })?;
            file.write_all(&content)
                .with_context(|| format!("Failed to write temp config to {:?}", tmp_path))?;
            file.sync_all()
                .with_context(|| format!("Failed to sync temp config {:?}", tmp_path))?;
        }

        #[cfg(not(unix))]
        {
            fs::write(&tmp_path, content)
                .with_context(|| format!("Failed to write temp config to {:?}", tmp_path))?;
        }

        fs::rename(&tmp_path, &path).with_context(|| {
            format!(
                "Failed to atomically replace config {:?} -> {:?}",
                tmp_path, path
            )
        })?;

        Ok(())
    }

    pub fn clear_session(&mut self) {
        self.access_token = None;
        self.refresh_token = None;
        self.token_expiry = None;
        self.encrypted_key = None;
        self.encrypted_private_key = None;
        self.org_keys.clear();
    }

    pub fn is_logged_in(&self) -> bool {
        self.access_token.is_some() && self.server.is_some()
    }

    pub fn get_server(&self) -> Option<&str> {
        self.server.as_deref()
    }
}

impl Drop for ProfileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_profile_accepts_safe_values() {
        assert!(Config::validate_profile("agent-01").is_ok());
        assert!(Config::validate_profile("agent.one_two").is_ok());
    }

    #[test]
    fn validate_profile_rejects_unsafe_values() {
        assert!(Config::validate_profile("").is_err());
        assert!(Config::validate_profile("../agent").is_err());
        assert!(Config::validate_profile("agent with spaces").is_err());
    }

    #[test]
    fn config_path_is_profile_scoped() {
        let path = Config::config_path("agent-a").expect("path should resolve");
        let display = path.to_string_lossy();
        assert!(display.contains("profiles/agent-a/config.json"));
    }
}
