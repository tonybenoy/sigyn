#[cfg(unix)]
mod agent;
mod commands;
mod config;
mod doctor;
mod importexport;
mod inject;
mod notifications;
mod output;
mod project_config;
mod project_detect;
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
        sigyn identity create -n alice\n  \
        sigyn vault create myapp\n  \
        sigyn secret set DATABASE_URL 'postgres://...' -v myapp -e dev\n  \
        sigyn secret get DATABASE_URL -e dev\n  \
        sigyn run -e dev -- ./myapp",
    after_help = "Use 'sigyn <command> --help' for more information about a command.\n\
        Config: ~/.sigyn/config.toml"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Vault name
    #[arg(long, short = 'v', global = true)]
    vault: Option<String>,

    /// Environment name
    #[arg(long, short = 'e', global = true)]
    env: Option<String>,

    /// Identity name or fingerprint
    #[arg(long, short = 'i', global = true)]
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

    /// Show detailed config resolution and debug output
    #[arg(long, global = true)]
    verbose: bool,

    /// Skip loading project config (.sigyn.toml)
    #[arg(long, global = true)]
    no_project_config: bool,
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
    #[command(alias = "v")]
    Vault {
        #[command(subcommand)]
        command: commands::vault::VaultCommands,
    },
    /// Manage secrets
    #[command(alias = "s")]
    Secret {
        #[command(subcommand)]
        command: commands::secret::SecretCommands,
    },
    /// Manage environments
    #[command(alias = "e")]
    Env {
        #[command(subcommand)]
        command: commands::env::EnvCommands,
    },
    /// Manage access policies
    #[command(alias = "p")]
    Policy {
        #[command(subcommand)]
        command: commands::policy::PolicyCommands,
    },
    /// Manage organizations and hierarchy
    Org {
        #[command(subcommand)]
        command: commands::org::OrgCommands,
    },
    /// Manage project config (.sigyn.toml)
    Project {
        #[command(subcommand)]
        command: commands::project::ProjectCommands,
    },
    /// Set active vault/env context for the current session
    #[command(alias = "ctx")]
    Context {
        #[command(subcommand)]
        command: commands::context::ContextCommands,
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
    #[command(alias = "sy")]
    Sync {
        #[command(subcommand)]
        command: commands::sync::SyncCommands,
    },
    /// View and verify audit trail
    #[command(alias = "a")]
    Audit {
        #[command(subcommand)]
        command: commands::audit::AuditCommands,
    },
    /// Manage vault forks
    #[command(alias = "f")]
    Fork {
        #[command(subcommand)]
        command: commands::fork::ForkCommands,
    },
    /// Run commands with injected secrets / export secrets
    #[command(alias = "r")]
    Run(commands::run::RunArgs),
    /// Rotate secrets and manage lifecycle
    #[command(alias = "rot")]
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
    /// Manage TOTP-based multi-factor authentication
    Mfa {
        #[command(subcommand)]
        command: commands::mfa::MfaCommands,
    },
    /// Import secrets from files or cloud providers
    #[command(alias = "imp")]
    Import {
        #[command(subcommand)]
        command: commands::import::ImportCommands,
    },
    /// CI/CD integration helpers
    Ci {
        #[command(subcommand)]
        command: commands::ci::CiCommands,
    },
    /// Guided first-run setup wizard
    Onboard,
    /// Manage notification webhooks
    #[command(alias = "notif")]
    Notification {
        #[command(subcommand)]
        command: commands::notifications::NotificationCommands,
    },
    /// Update sigyn to the latest release
    Update(commands::update::UpdateArgs),
    /// Generate shell completions
    Completions {
        /// Shell to generate for: bash, zsh, fish, powershell
        shell: String,
    },
    /// Manage the passphrase agent (caches decrypted keys) [Unix only]
    #[cfg(unix)]
    Agent {
        #[command(subcommand)]
        command: AgentCommands,
    },
    /// Launch interactive TUI dashboard
    Tui,
    /// Get a secret (shortcut for 'secret get')
    Get {
        /// Secret key name
        key: String,
        /// Copy value to clipboard instead of printing
        #[arg(long, short)]
        copy: bool,
    },
    /// Set a secret (shortcut for 'secret set')
    Set {
        /// Secret key name
        key: String,
        /// Secret value (omit to read from stdin)
        value: Option<String>,
    },
    /// Quick list (secrets, vaults, or environments)
    Ls {
        /// Environment name (for listing secrets)
        target: Option<String>,
        /// List vaults instead of secrets
        #[arg(long)]
        vaults: bool,
        /// List environments instead of secrets
        #[arg(long)]
        envs: bool,
        /// Show decrypted values
        #[arg(long, short)]
        reveal: bool,
    },
    /// Watch for secret changes and restart command
    Watch {
        /// Poll interval in seconds
        #[arg(long, default_value = "2")]
        interval: u64,
        /// Don't inherit parent environment
        #[arg(long, short)]
        clean: bool,
        /// Command and arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
}

#[cfg(unix)]
#[derive(Subcommand)]
enum AgentCommands {
    /// Start the passphrase agent daemon
    Start {
        /// Key cache timeout in minutes
        #[arg(long, default_value = "30")]
        timeout: u64,
    },
    /// Stop the agent daemon
    Stop,
    /// Clear cached keys (keep daemon running)
    Lock,
    /// Show agent status
    Status,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let json = cli.json;

    if cli.verbose {
        std::env::set_var("SIGYN_VERBOSE", "1");
    }
    if cli.no_project_config {
        std::env::set_var("SIGYN_NO_PROJECT_CONFIG", "1");
    }

    match cli.command {
        Commands::Identity { command } => {
            commands::identity::handle(command, json)?;
        }
        Commands::Vault { command } => {
            commands::vault::handle(command, cli.identity.as_deref(), json)?;
        }
        Commands::Secret { command } => {
            commands::secret::handle(
                command,
                cli.vault.as_deref(),
                cli.identity.as_deref(),
                json,
                cli.dry_run,
            )?;
        }
        Commands::Env { command } => {
            commands::env::handle(command, cli.vault.as_deref(), cli.identity.as_deref(), json)?;
        }
        Commands::Policy { command } => {
            commands::policy::handle(command, cli.vault.as_deref(), cli.identity.as_deref(), json)?;
        }
        Commands::Org { command } => {
            commands::org::handle(command, cli.identity.as_deref(), json)?;
        }
        Commands::Project { command } => {
            commands::project::handle(command, json)?;
        }
        Commands::Context { command } => {
            commands::context::handle(command, json)?;
        }
        Commands::Status => {
            commands::status::handle(json)?;
        }
        Commands::Doctor => {
            doctor::run_doctor()?;
        }
        Commands::Init { identity, vault } => {
            let home = config::sigyn_home();
            let mut cfg = config::load_config();

            // If no identity provided and none exist, offer to create one
            let effective_identity = if let Some(id) = identity {
                Some(id)
            } else if cfg.default_identity.is_none() && config::is_interactive() {
                let store = sigyn_engine::identity::keygen::IdentityStore::new(home.clone());
                let identities = store.list().unwrap_or_default();
                if identities.is_empty() {
                    let create = dialoguer::Confirm::new()
                        .with_prompt("No identities found. Create one now?")
                        .default(true)
                        .interact()?;
                    if create {
                        let default_name = std::env::var("USER")
                            .or_else(|_| std::env::var("USERNAME"))
                            .unwrap_or_else(|_| "default".into());
                        let name: String = dialoguer::Input::new()
                            .with_prompt("Identity name")
                            .default(default_name)
                            .interact_text()?;
                        commands::identity::handle(
                            commands::identity::IdentityCommands::Create {
                                name: name.clone(),
                                email: None,
                            },
                            false,
                        )?;
                        Some(name)
                    } else {
                        None
                    }
                } else if identities.len() == 1 {
                    Some(identities[0].profile.name.clone())
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(id) = effective_identity {
                cfg.default_identity = Some(id);
            }

            // If no vault provided and none exist, offer to create one
            let effective_vault = if let Some(v) = vault {
                Some(v)
            } else if cfg.default_vault.is_none() && config::is_interactive() {
                let paths = sigyn_engine::vault::VaultPaths::new(home.clone());
                let vaults = paths.list_vaults().unwrap_or_default();
                if vaults.is_empty() {
                    let create = dialoguer::Confirm::new()
                        .with_prompt("No vaults found. Create one now?")
                        .default(true)
                        .interact()?;
                    if create {
                        let detection = project_detect::detect_project();
                        let name: String = dialoguer::Input::new()
                            .with_prompt("Vault name")
                            .default(detection.suggested_vault_name)
                            .interact_text()?;
                        commands::vault::handle(
                            commands::vault::VaultCommands::Create {
                                names: vec![name.clone()],
                                org: None,
                                split_audit: false,
                            },
                            cfg.default_identity.as_deref(),
                            false,
                        )?;
                        Some(name)
                    } else {
                        None
                    }
                } else if vaults.len() == 1 {
                    Some(vaults[0].clone())
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(v) = effective_vault {
                cfg.default_vault = Some(v);
            }

            config::save_config(&cfg)?;
            output::print_success("Configuration initialized");
            println!(
                "  Config: {}",
                config::sigyn_home().join("config.toml").display()
            );

            // Run doctor checks as a post-init summary
            if !cli.quiet {
                println!();
                doctor::run_doctor()?;
            }
        }
        Commands::Sync { command } => {
            commands::sync::handle(command, cli.vault.as_deref(), json)?;
        }
        Commands::Audit { command } => {
            commands::audit::handle(command, cli.vault.as_deref(), cli.identity.as_deref(), json)?;
        }
        Commands::Fork { command } => {
            commands::fork::handle(command, cli.vault.as_deref(), cli.identity.as_deref(), json)?;
        }
        Commands::Run(args) => {
            commands::run::handle(
                args,
                cli.vault.as_deref(),
                cli.identity.as_deref(),
                json,
                cli.dry_run,
            )?;
        }
        Commands::Rotate { command } => {
            commands::rotate::handle(
                command,
                cli.vault.as_deref(),
                cli.identity.as_deref(),
                json,
                cli.dry_run,
            )?;
        }
        Commands::Delegation { command } => {
            commands::delegation::handle(
                command,
                cli.vault.as_deref(),
                cli.identity.as_deref(),
                json,
            )?;
        }
        Commands::Mfa { command } => {
            commands::mfa::handle(command, cli.identity.as_deref(), json)?;
        }
        Commands::Import { command } => {
            commands::import::handle(command, cli.vault.as_deref(), cli.identity.as_deref(), json)?;
        }
        Commands::Ci { command } => {
            commands::ci::handle(command, json)?;
        }
        Commands::Onboard => {
            commands::onboard::handle(json)?;
        }
        Commands::Notification { command } => {
            commands::notifications::handle(command, json)?;
        }
        Commands::Update(args) => {
            commands::update::handle(args, json)?;
        }
        Commands::Completions { shell } => {
            use clap::CommandFactory;
            use clap_complete::{generate, Shell};
            let shell = shell.parse::<Shell>().map_err(|_| {
                anyhow::anyhow!("unsupported shell: use bash, zsh, fish, or powershell")
            })?;
            generate(shell, &mut Cli::command(), "sigyn", &mut std::io::stdout());
        }
        #[cfg(unix)]
        Commands::Agent { command } => match command {
            AgentCommands::Start { timeout } => {
                agent::handle_start(timeout * 60, json)?;
            }
            AgentCommands::Stop => {
                agent::handle_stop()?;
            }
            AgentCommands::Lock => {
                agent::handle_lock()?;
            }
            AgentCommands::Status => {
                agent::handle_status(json)?;
            }
        },
        Commands::Tui => {
            let vault_name = cli.vault.as_deref().unwrap_or("default");
            let env_name = cli.env.as_deref().unwrap_or("default");
            tui::run_tui(vault_name, env_name)?;
        }
        Commands::Get { key, copy } => {
            commands::secret::handle(
                commands::secret::SecretCommands::Get {
                    key,
                    env: cli.env.clone(),
                    copy,
                },
                cli.vault.as_deref(),
                cli.identity.as_deref(),
                json,
                cli.dry_run,
            )?;
        }
        Commands::Set { key, value } => {
            let args = match value {
                Some(v) => vec![format!("{}={}", key, v)],
                None => vec![key],
            };
            commands::secret::handle(
                commands::secret::SecretCommands::Set {
                    args,
                    env: cli.env.clone(),
                },
                cli.vault.as_deref(),
                cli.identity.as_deref(),
                json,
                cli.dry_run,
            )?;
        }
        Commands::Ls {
            target,
            vaults,
            envs,
            reveal,
        } => {
            if vaults {
                commands::vault::handle(
                    commands::vault::VaultCommands::List,
                    cli.identity.as_deref(),
                    json,
                )?;
            } else if envs {
                commands::env::handle(
                    commands::env::EnvCommands::List,
                    cli.vault.as_deref(),
                    cli.identity.as_deref(),
                    json,
                )?;
            } else {
                // List secrets, using target as env name (with prefix matching via unlock_vault)
                let env = target.or_else(|| cli.env.clone());
                commands::secret::handle(
                    commands::secret::SecretCommands::List { env, reveal },
                    cli.vault.as_deref(),
                    cli.identity.as_deref(),
                    json,
                    cli.dry_run,
                )?;
            }
        }
        Commands::Watch {
            interval,
            clean,
            command,
        } => {
            commands::run::handle_watch(
                cli.vault.as_deref(),
                cli.identity.as_deref(),
                cli.env.as_deref(),
                &command,
                interval,
                clean,
            )?;
        }
    }

    Ok(())
}
