use crate::config::Config;
use crate::models::{Cipher, CipherListResponse, SyncResponse, TokenResponse};
use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::{Value, json};
use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
#[error("{operation} failed ({status}): {body}")]
pub struct ApiErrorDetail {
    pub operation: String,
    pub status: u16,
    pub body: String,
}

pub struct ApiClient {
    client: Client,
    base_url: String,
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

impl ApiClient {
    pub fn new(base_url: &str) -> Result<Self> {
        let parsed_url = reqwest::Url::parse(base_url).context("Invalid server URL")?;
        let scheme = parsed_url.scheme();

        if scheme == "http" {
            let host = parsed_url
                .host_str()
                .context("Server URL must include a host")?;
            if !is_loopback_host(host) {
                anyhow::bail!(
                    "Insecure http:// server URLs are only allowed for localhost or loopback addresses"
                );
            }
        } else if scheme != "https" {
            anyhow::bail!("Unsupported server URL scheme '{}'", scheme);
        }

        if !parsed_url.username().is_empty() || parsed_url.password().is_some() {
            anyhow::bail!("Server URL must not include embedded credentials");
        }

        let client = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("Failed to create HTTP client")?;

        // Normalize base URL (remove trailing slash)
        let base_url = parsed_url.as_str().trim_end_matches('/').to_string();

        Ok(Self { client, base_url })
    }

    pub fn from_config(config: &Config) -> Result<Self> {
        let server = config.get_server().context("No server configured")?;
        Self::new(server)
    }

    // OAuth2 token endpoint using client credentials
    pub async fn login(&self, client_id: &str, client_secret: &str) -> Result<TokenResponse> {
        let params = [
            ("grant_type", "client_credentials"),
            ("scope", "api"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("deviceType", "14"), // CLI device type
            ("deviceIdentifier", "vaultwarden-cli"),
            ("deviceName", "Vaultwarden CLI"),
        ];

        self.post_form(
            "/identity/connect/token",
            &params,
            "login",
            "Login",
            "Failed to parse token response",
        )
        .await
    }

    // Refresh access token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenResponse> {
        let params = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ];

        self.post_form(
            "/identity/connect/token",
            &params,
            "token refresh",
            "Token refresh",
            "Failed to parse token response",
        )
        .await
    }

    // Sync vault data
    pub async fn sync(&self, access_token: &str) -> Result<SyncResponse> {
        self.get_json(
            "/api/sync",
            access_token,
            "sync",
            "Sync",
            "Failed to parse sync response",
        )
        .await
    }

    pub async fn ciphers(&self, access_token: &str) -> Result<CipherListResponse> {
        self.get_json(
            "/api/ciphers",
            access_token,
            "cipher list",
            "Cipher list",
            "Failed to parse cipher list response",
        )
        .await
    }

    pub async fn create_cipher(&self, access_token: &str, payload: &Value) -> Result<Cipher> {
        self.post_json(
            "/api/ciphers",
            access_token,
            payload,
            "cipher create",
            "Cipher create",
            "Failed to parse cipher create response",
        )
        .await
    }

    pub async fn update_cipher(
        &self,
        access_token: &str,
        cipher_id: &str,
        payload: &Value,
    ) -> Result<Cipher> {
        self.put_json(
            &format!("/api/ciphers/{}", cipher_id),
            access_token,
            payload,
            "cipher update",
            "Cipher update",
            "Failed to parse cipher update response",
        )
        .await
    }

    pub async fn create_org_cipher(
        &self,
        access_token: &str,
        payload: &Value,
        collection_ids: &[String],
    ) -> Result<Cipher> {
        let body = json!({
            "cipher": payload,
            "collectionIds": collection_ids
        });

        self.post_json(
            "/api/ciphers/create",
            access_token,
            &body,
            "org cipher create",
            "Org cipher create",
            "Failed to parse org cipher create response",
        )
        .await
    }

    pub async fn update_collections_v2(
        &self,
        access_token: &str,
        cipher_id: &str,
        collection_ids: &[String],
    ) -> Result<Value> {
        self.put_json(
            &format!("/api/ciphers/{}/collections_v2", cipher_id),
            access_token,
            &json!({ "collectionIds": collection_ids }),
            "collections_v2 update",
            "Collections update",
            "Failed to parse collections update response",
        )
        .await
    }

    pub async fn update_cipher_partial(
        &self,
        access_token: &str,
        cipher_id: &str,
        folder_id: Option<&str>,
        favorite: bool,
    ) -> Result<Cipher> {
        self.put_json(
            &format!("/api/ciphers/{}/partial", cipher_id),
            access_token,
            &json!({
                "folderId": folder_id,
                "favorite": favorite
            }),
            "cipher partial update",
            "Cipher partial update",
            "Failed to parse partial update response",
        )
        .await
    }

    pub async fn delete_cipher(&self, access_token: &str, cipher_id: &str) -> Result<()> {
        let url = format!("{}/api/ciphers/{}", self.base_url, cipher_id);
        let response = self
            .client
            .delete(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .context("Failed to send cipher delete request")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ApiErrorDetail {
                operation: "Cipher delete".to_string(),
                status: status.as_u16(),
                body,
            }
            .into());
        }

        Ok(())
    }

    // Check server status/health
    pub async fn check_server(&self) -> Result<bool> {
        let url = format!("{}/alive", self.base_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to check server status")?;

        Ok(response.status().is_success())
    }

    async fn post_form<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        params: &[(&str, &str)],
        operation: &str,
        error_prefix: &str,
        parse_context: &str,
    ) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let response = self
            .client
            .post(&url)
            .form(params)
            .send()
            .await
            .with_context(|| format!("Failed to send {} request", operation))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ApiErrorDetail {
                operation: error_prefix.to_string(),
                status: status.as_u16(),
                body,
            }
            .into());
        }

        response
            .json::<T>()
            .await
            .with_context(|| parse_context.to_string())
    }

    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        access_token: &str,
        operation: &str,
        error_prefix: &str,
        parse_context: &str,
    ) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let response = self
            .client
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .with_context(|| format!("Failed to send {} request", operation))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ApiErrorDetail {
                operation: error_prefix.to_string(),
                status: status.as_u16(),
                body,
            }
            .into());
        }

        response
            .json::<T>()
            .await
            .with_context(|| parse_context.to_string())
    }

    async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        access_token: &str,
        payload: &Value,
        operation: &str,
        error_prefix: &str,
        parse_context: &str,
    ) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let response = self
            .client
            .post(&url)
            .bearer_auth(access_token)
            .json(payload)
            .send()
            .await
            .with_context(|| format!("Failed to send {} request", operation))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ApiErrorDetail {
                operation: error_prefix.to_string(),
                status: status.as_u16(),
                body,
            }
            .into());
        }

        response
            .json::<T>()
            .await
            .with_context(|| parse_context.to_string())
    }

    async fn put_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        access_token: &str,
        payload: &Value,
        operation: &str,
        error_prefix: &str,
        parse_context: &str,
    ) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let response = self
            .client
            .put(&url)
            .bearer_auth(access_token)
            .json(payload)
            .send()
            .await
            .with_context(|| format!("Failed to send {} request", operation))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ApiErrorDetail {
                operation: error_prefix.to_string(),
                status: status.as_u16(),
                body,
            }
            .into());
        }

        response
            .json::<T>()
            .await
            .with_context(|| parse_context.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_client_allows_https_servers() {
        assert!(ApiClient::new("https://vault.example.com").is_ok());
    }

    #[test]
    fn api_client_rejects_non_loopback_http_servers() {
        let err = ApiClient::new("http://vault.example.com")
            .err()
            .expect("non-loopback http should be rejected");
        assert!(
            err.to_string()
                .contains("Insecure http:// server URLs are only allowed")
        );
    }

    #[test]
    fn api_client_allows_loopback_http_servers() {
        assert!(ApiClient::new("http://127.0.0.1:8080").is_ok());
        assert!(ApiClient::new("http://localhost:8080").is_ok());
    }
}
