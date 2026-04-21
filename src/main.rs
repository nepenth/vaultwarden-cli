use clap::{Parser, Subcommand};
use vaultwarden_cli::commands;

#[derive(Parser)]
#[command(name = "vaultwarden-cli")]
#[command(
    about = "Agent-first CLI for Vaultwarden (Linux/macOS): runtime secret retrieval with profile isolation"
)]
#[command(version)]
struct Cli {
    /// Tenant profile identifier (required for multi-agent isolation)
    #[arg(long, env = "VAULTWARDEN_PROFILE")]
    profile: String,

    /// Master password for runtime decryption (optional for login/status/logout)
    #[arg(long, env = "VAULTWARDEN_PASSWORD")]
    password: Option<String>,

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

        /// Client secret for API authentication
        #[arg(long, env = "VAULTWARDEN_CLIENT_SECRET")]
        client_secret: Option<String>,
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

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let profile = &cli.profile;
    let runtime_password = cli.password.as_deref();

    let result = match cli.command {
        Commands::Login {
            server,
            client_id,
            client_secret,
        } => commands::login(profile, server, client_id, client_secret).await,
        Commands::Logout => commands::logout(profile).await,
        Commands::Status => commands::status(profile).await,
        Commands::List {
            r#type,
            search,
            org,
            collection,
        } => commands::list(profile, runtime_password, r#type, search, org, collection).await,
        Commands::Get {
            item,
            format,
            username_only,
            password_only,
            org,
            collection,
        } => {
            commands::get(
                profile,
                runtime_password,
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
            commands::get_by_uri(
                profile,
                runtime_password,
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
            let requested_items =
                if name.is_empty() && org.is_none() && folder.is_none() && collection.is_none() {
                    item
                } else {
                    name
                };

            commands::run_with_secrets(
                profile,
                runtime_password,
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
            commands::run_with_secrets(
                profile,
                runtime_password,
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
    };

    if let Err(e) = result {
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
