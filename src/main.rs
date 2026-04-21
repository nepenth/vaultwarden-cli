use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::Read;
use vaultwarden_cli::commands;

#[derive(Parser)]
#[command(name = "vaultwarden-cli")]
#[command(
    about = "Agent-first CLI for Vaultwarden (Linux/macOS): runtime secret retrieval and write support with profile isolation"
)]
#[command(version)]
struct Cli {
    /// Tenant profile identifier (required for multi-agent isolation)
    #[arg(long, env = "VAULTWARDEN_PROFILE")]
    profile: String,

    /// Read master password from stdin (first line). Required for secret retrieval/write.
    #[arg(long, global = true)]
    password_stdin: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Login and store session material for a tenant profile
    Login {
        /// Server URL (e.g., https://vaultwarden.example.com)
        #[arg(short, long)]
        server: Option<String>,

        /// Client ID for API authentication
        #[arg(long, env = "VAULTWARDEN_CLIENT_ID")]
        client_id: Option<String>,

        /// Read client secret from stdin
        #[arg(long)]
        client_secret_stdin: bool,
    },

    /// Remove active session material from a tenant profile
    Logout,

    /// Show current status for a tenant profile as JSON
    Status,

    /// List vault items as JSON
    List {
        /// Filter by item type (login, note, card, identity, ssh)
        #[arg(short, long)]
        r#type: Option<String>,

        /// Search term
        #[arg(short, long)]
        search: Option<String>,

        /// Filter by organization name or ID
        #[arg(long)]
        org: Option<String>,

        /// Filter by collection name or ID
        #[arg(short, long)]
        collection: Option<String>,
    },

    /// Get a specific item by ID or exact name
    Get {
        /// Item ID or exact name
        item: String,

        /// Output format (json, env, value, username)
        #[arg(short, long, default_value = "json")]
        format: String,

        /// Output only the username (shorthand for --format username)
        #[arg(short = 'u', long)]
        username_only: bool,

        /// Output only the password value (shorthand for --format value)
        #[arg(short = 'p', long)]
        password_only: bool,

        /// Filter by organization name or ID
        #[arg(long)]
        org: Option<String>,

        /// Filter by collection name or ID
        #[arg(long)]
        collection: Option<String>,
    },

    /// Get a specific item by URI substring
    #[command(name = "get-uri")]
    GetUri {
        /// URI substring to search for (e.g., github.com)
        uri: String,

        /// Output format (json, env, value, username)
        #[arg(short, long, default_value = "json")]
        format: String,

        /// Output only the username (shorthand for --format username)
        #[arg(short = 'u', long)]
        username_only: bool,

        /// Output only the password value (shorthand for --format value)
        #[arg(short = 'p', long)]
        password_only: bool,

        /// Filter by organization name or ID
        #[arg(long)]
        org: Option<String>,

        /// Filter by collection name or ID
        #[arg(long)]
        collection: Option<String>,
    },

    /// Run a command with secrets injected as environment variables
    Run {
        /// Item name or ID to inject (repeat flag or use commas for multiple)
        #[arg(long, alias = "credential-name", value_delimiter = ',')]
        name: Vec<String>,

        /// Item name or ID to inject when no selector flag is provided
        #[arg(value_delimiter = ',')]
        item: Vec<String>,

        /// Filter by organization name or ID
        #[arg(long)]
        org: Option<String>,

        /// Filter by folder name or ID
        #[arg(long)]
        folder: Option<String>,

        /// Filter by collection name or ID
        #[arg(long)]
        collection: Option<String>,

        /// Print JSON array of injected environment variable names only
        #[arg(short, long)]
        info: bool,

        /// Command to run (use -- to separate from vaultwarden-cli args)
        #[arg(last = true)]
        command: Vec<String>,
    },

    /// Run a command with secrets from URI match injected as environment variables
    #[command(name = "run-uri")]
    RunUri {
        /// URI substring to search for
        uri: String,

        /// Print JSON array of injected environment variable names only
        #[arg(short, long)]
        info: bool,

        /// Command to run (use -- to separate from vaultwarden-cli args)
        #[arg(last = true)]
        command: Vec<String>,
    },

    /// Mutating write operations for agent workflows
    Write {
        #[command(subcommand)]
        command: WriteCommands,
    },
}

#[derive(Subcommand)]
enum WriteCommands {
    /// Create a cipher from stdin JSON input
    Create {
        /// Input path or '-' for stdin. When used with --password-stdin, first stdin line is password and remainder is JSON.
        #[arg(long, default_value = "-")]
        input: String,

        /// Validate selectors/payload without mutating server state
        #[arg(long)]
        dry_run: bool,
    },

    /// Update a cipher by ID from stdin JSON input
    Update {
        /// Cipher ID
        #[arg(long)]
        id: String,

        /// Required last known revision date (ISO 8601)
        #[arg(long = "if-revision")]
        if_revision: String,

        /// Input path or '-' for stdin. When used with --password-stdin, first stdin line is password and remainder is JSON.
        #[arg(long, default_value = "-")]
        input: String,

        /// Validate selectors/payload without mutating server state
        #[arg(long)]
        dry_run: bool,
    },

    /// Upsert a cipher by deterministic match semantics
    Upsert {
        /// Match algorithm
        #[arg(long = "match", default_value = "name_uri")]
        r#match: String,

        /// Scope: personal | org:<id>
        #[arg(long, default_value = "personal")]
        scope: String,

        /// Input path or '-' for stdin. When used with --password-stdin, first stdin line is password and remainder is JSON.
        #[arg(long, default_value = "-")]
        input: String,

        /// Validate selectors/payload without mutating server state
        #[arg(long)]
        dry_run: bool,
    },

    /// Rotate only the password on a login item
    #[command(name = "rotate-password")]
    RotatePassword {
        #[arg(long)]
        id: String,

        #[arg(long = "if-revision")]
        if_revision: String,

        /// Input path or '-' for stdin. JSON: {"new_password":"..."}
        #[arg(long, default_value = "-")]
        input: String,

        #[arg(long)]
        dry_run: bool,
    },

    /// Patch custom fields for an item
    #[command(name = "patch-fields")]
    PatchFields {
        #[arg(long)]
        id: String,

        #[arg(long = "if-revision")]
        if_revision: String,

        /// Input path or '-' for stdin. JSON: {"fields":[...]}
        #[arg(long, default_value = "-")]
        input: String,

        #[arg(long)]
        dry_run: bool,
    },

    /// Move/favorite patch without rewriting all item data
    Move {
        #[arg(long)]
        id: String,

        #[arg(long = "if-revision")]
        if_revision: String,

        #[arg(long)]
        folder_id: Option<String>,

        #[arg(long)]
        favorite: Option<bool>,

        #[arg(long)]
        dry_run: bool,
    },
}

fn effective_format(format: &str, username_only: bool, password_only: bool) -> &str {
    if username_only {
        "username"
    } else if password_only {
        "value"
    } else {
        format
    }
}

fn read_secret_from_stdin() -> Result<String> {
    let mut data = String::new();
    std::io::stdin()
        .read_to_string(&mut data)
        .context("Failed to read secret from stdin")?;
    let trimmed = data.trim_end_matches(['\n', '\r']).to_string();
    if trimmed.is_empty() {
        anyhow::bail!("No secret data found on stdin");
    }
    Ok(trimmed)
}

fn maybe_password_from_stdin(enabled: bool) -> Result<Option<String>> {
    if enabled {
        Ok(Some(read_secret_from_stdin()?))
    } else {
        Ok(None)
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let profile = &cli.profile;

    let result: Result<()> = async {
        match cli.command {
            Commands::Login {
                server,
                client_id,
                client_secret_stdin,
            } => {
                let client_secret = if client_secret_stdin {
                    Some(read_secret_from_stdin()?)
                } else {
                    None
                };

                commands::login(profile, server, client_id, client_secret).await
            }
            Commands::Logout => commands::logout(profile).await,
            Commands::Status => commands::status(profile).await,
            Commands::List {
                r#type,
                search,
                org,
                collection,
            } => {
                let password = maybe_password_from_stdin(cli.password_stdin)?;
                commands::list(
                    profile,
                    password.as_deref(),
                    r#type,
                    search,
                    org,
                    collection,
                )
                .await
            }
            Commands::Get {
                item,
                format,
                username_only,
                password_only,
                org,
                collection,
            } => {
                let password = maybe_password_from_stdin(cli.password_stdin)?;
                commands::get(
                    profile,
                    password.as_deref(),
                    &item,
                    effective_format(&format, username_only, password_only),
                    org,
                    collection,
                )
                .await
            }
            Commands::GetUri {
                uri,
                format,
                username_only,
                password_only,
                org,
                collection,
            } => {
                let password = maybe_password_from_stdin(cli.password_stdin)?;
                commands::get_by_uri(
                    profile,
                    password.as_deref(),
                    &uri,
                    effective_format(&format, username_only, password_only),
                    org,
                    collection,
                )
                .await
            }
            Commands::Run {
                name,
                item,
                org,
                folder,
                collection,
                info,
                command,
            } => {
                let password = maybe_password_from_stdin(cli.password_stdin)?;
                let requested_items =
                    if name.is_empty() && org.is_none() && folder.is_none() && collection.is_none()
                    {
                        item
                    } else {
                        name
                    };

                commands::run_with_secrets(
                    profile,
                    password.as_deref(),
                    commands::RunRequest {
                        requested_items: &requested_items,
                        search_by_uri: false,
                        org_filter: org.as_deref(),
                        folder_filter: folder.as_deref(),
                        collection_filter: collection.as_deref(),
                        info_only: info,
                        command: &command,
                    },
                )
                .await
            }
            Commands::RunUri { uri, info, command } => {
                let password = maybe_password_from_stdin(cli.password_stdin)?;
                commands::run_with_secrets(
                    profile,
                    password.as_deref(),
                    commands::RunRequest {
                        requested_items: &[uri],
                        search_by_uri: true,
                        org_filter: None,
                        folder_filter: None,
                        collection_filter: None,
                        info_only: info,
                        command: &command,
                    },
                )
                .await
            }
            Commands::Write { command } => match command {
                WriteCommands::Create { input, dry_run } => {
                    commands::write_create(profile, cli.password_stdin, &input, dry_run).await
                }
                WriteCommands::Update {
                    id,
                    if_revision,
                    input,
                    dry_run,
                } => {
                    commands::write_update(
                        profile,
                        cli.password_stdin,
                        &id,
                        &if_revision,
                        &input,
                        dry_run,
                    )
                    .await
                }
                WriteCommands::Upsert {
                    r#match,
                    scope,
                    input,
                    dry_run,
                } => {
                    commands::write_upsert(
                        profile,
                        cli.password_stdin,
                        &r#match,
                        &scope,
                        &input,
                        dry_run,
                    )
                    .await
                }
                WriteCommands::RotatePassword {
                    id,
                    if_revision,
                    input,
                    dry_run,
                } => {
                    commands::write_rotate_password(
                        profile,
                        cli.password_stdin,
                        &id,
                        &if_revision,
                        &input,
                        dry_run,
                    )
                    .await
                }
                WriteCommands::PatchFields {
                    id,
                    if_revision,
                    input,
                    dry_run,
                } => {
                    commands::write_patch_fields(
                        profile,
                        cli.password_stdin,
                        &id,
                        &if_revision,
                        &input,
                        dry_run,
                    )
                    .await
                }
                WriteCommands::Move {
                    id,
                    if_revision,
                    folder_id,
                    favorite,
                    dry_run,
                } => {
                    commands::write_move(
                        profile,
                        cli.password_stdin,
                        &id,
                        &if_revision,
                        folder_id.as_deref(),
                        favorite,
                        dry_run,
                    )
                    .await
                }
            },
        }
    }
    .await;

    if let Err(e) = result {
        if let Some(write_error) = e.downcast_ref::<commands::WriteCliError>() {
            println!("{}", write_error.json);
            std::process::exit(1);
        }

        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_effective_format_username_override() {
        assert_eq!(effective_format("json", true, false), "username");
    }

    #[test]
    fn test_effective_format_password_override() {
        assert_eq!(effective_format("json", false, true), "value");
    }

    #[test]
    fn test_effective_format_no_override() {
        assert_eq!(effective_format("env", false, false), "env");
        assert_eq!(effective_format("json", false, false), "json");
    }
}
