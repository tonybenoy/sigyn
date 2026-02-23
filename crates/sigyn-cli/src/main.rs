mod commands;
mod config;
mod doctor;
mod importexport;
mod inject;
#[allow(dead_code)]
mod notifications;
mod output;
#[allow(dead_code)]
mod tui;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "sigyn",
    version,
    about = "Serverless encrypted P2P secret manager",
    long_about = "Sigyn is a serverless, encrypted, peer-to-peer secret manager.\n\n\
        Secrets are encrypted at rest with ChaCha20-Poly1305, sealed with X25519 \
        envelope encryption, and synced via git. Full RBAC with 7-level role hierarchy, \
        delegation trees with cascade revocation, hash-chained audit trails, and \
        Shamir-based disaster recovery.\n\n\
        Quick start:\n  \
        sigyn identity create --name alice\n  \
        sigyn vault create myapp\n  \
        sigyn secret set DATABASE_URL 'postgres://...' --env dev\n  \
        sigyn secret get DATABASE_URL --env dev\n  \
        sigyn run exec --env dev -- ./myapp",
    after_help = "Use 'sigyn <command> --help' for more information about a command.\n\
        Config: ~/.sigyn/config.toml"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Vault name
    #[arg(long, global = true)]
    vault: Option<String>,

    /// Environment name
    #[arg(long, global = true)]
    env: Option<String>,

    /// Identity name or fingerprint
    #[arg(long, global = true)]
    identity: Option<String>,

    /// Output as JSON
    #[arg(long, global = true)]
    json: bool,

    /// Suppress non-essential output
    #[arg(long, global = true)]
    quiet: bool,

    /// Preview changes without applying
    #[arg(long, global = true)]
    dry_run: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage identities (keypairs)
    #[command(alias = "id")]
    Identity {
        #[command(subcommand)]
        command: commands::identity::IdentityCommands,
    },
    /// Manage vaults
    Vault {
        #[command(subcommand)]
        command: commands::vault::VaultCommands,
    },
    /// Manage secrets
    Secret {
        #[command(subcommand)]
        command: commands::secret::SecretCommands,
    },
    /// Manage environments
    Env {
        #[command(subcommand)]
        command: commands::env::EnvCommands,
    },
    /// Manage access policies
    Policy {
        #[command(subcommand)]
        command: commands::policy::PolicyCommands,
    },
    /// Show current status
    Status,
    /// Run health checks
    Doctor,
    /// Initialize default config
    Init {
        /// Set default identity name
        #[arg(long)]
        identity: Option<String>,
        /// Set default vault name
        #[arg(long)]
        vault: Option<String>,
    },
    /// Sync vault with remote
    Sync {
        #[command(subcommand)]
        command: commands::sync::SyncCommands,
    },
    /// View and verify audit trail
    Audit {
        #[command(subcommand)]
        command: commands::audit::AuditCommands,
    },
    /// Manage vault forks
    Fork {
        #[command(subcommand)]
        command: commands::fork::ForkCommands,
    },
    /// Run commands with injected secrets / export secrets
    Run {
        #[command(subcommand)]
        command: commands::run::RunCommands,
    },
    /// Rotate secrets and manage lifecycle
    Rotate {
        #[command(subcommand)]
        command: commands::rotate::RotateCommands,
    },
    /// Manage delegation and invitations
    #[command(alias = "member")]
    Delegation {
        #[command(subcommand)]
        command: commands::delegation::DelegationCommands,
    },
    /// Import secrets from files or cloud providers
    Import {
        #[command(subcommand)]
        command: commands::import::ImportCommands,
    },
    /// Generate shell completions
    Completions {
        /// Shell to generate for: bash, zsh, fish, powershell
        shell: String,
    },
    /// Launch interactive TUI dashboard
    Tui,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let json = cli.json;

    match cli.command {
        Commands::Identity { command } => {
            commands::identity::handle(command, json)?;
        }
        Commands::Vault { command } => {
            commands::vault::handle(command, cli.identity.as_deref(), json)?;
        }
        Commands::Secret { command } => {
            commands::secret::handle(command, cli.vault.as_deref(), cli.identity.as_deref(), json)?;
        }
        Commands::Env { command } => {
            commands::env::handle(command, cli.vault.as_deref(), cli.identity.as_deref(), json)?;
        }
        Commands::Policy { command } => {
            commands::policy::handle(command, cli.vault.as_deref(), cli.identity.as_deref(), json)?;
        }
        Commands::Status => {
            commands::status::handle(json)?;
        }
        Commands::Doctor => {
            doctor::run_doctor()?;
        }
        Commands::Init { identity, vault } => {
            let mut cfg = config::load_config();
            if let Some(id) = identity {
                cfg.default_identity = Some(id);
            }
            if let Some(v) = vault {
                cfg.default_vault = Some(v);
            }
            config::save_config(&cfg)?;
            output::print_success("Configuration initialized");
            println!(
                "  Config: {}",
                config::sigyn_home().join("config.toml").display()
            );
        }
        Commands::Sync { command } => {
            commands::sync::handle(command, cli.vault.as_deref(), json)?;
        }
        Commands::Audit { command } => {
            commands::audit::handle(command, cli.vault.as_deref(), json)?;
        }
        Commands::Fork { command } => {
            commands::fork::handle(command, cli.vault.as_deref(), json)?;
        }
        Commands::Run { command } => {
            commands::run::handle(command, cli.vault.as_deref(), cli.identity.as_deref(), json)?;
        }
        Commands::Rotate { command } => {
            commands::rotate::handle(command, cli.vault.as_deref(), cli.identity.as_deref(), json)?;
        }
        Commands::Delegation { command } => {
            commands::delegation::handle(command, cli.vault.as_deref(), json)?;
        }
        Commands::Import { command } => {
            commands::import::handle(command, cli.vault.as_deref(), cli.identity.as_deref(), json)?;
        }
        Commands::Completions { shell } => {
            use clap::CommandFactory;
            use clap_complete::{generate, Shell};
            let shell = shell.parse::<Shell>().map_err(|_| {
                anyhow::anyhow!("unsupported shell: use bash, zsh, fish, or powershell")
            })?;
            generate(shell, &mut Cli::command(), "sigyn", &mut std::io::stdout());
        }
        Commands::Tui => {
            let vault_name = cli.vault.as_deref().unwrap_or("default");
            let env_name = cli.env.as_deref().unwrap_or("default");
            tui::run_tui(vault_name, env_name)?;
        }
    }

    Ok(())
}
