use anyhow::Result;
use clap::{Args, Subcommand};
use console::style;
use sigyn_engine::policy::engine::AccessAction;
use sigyn_engine::vault::env_file;

use super::secret::{check_access, unlock_vault};
use crate::project_config::load_project_config;

#[derive(Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct RunArgs {
    #[command(subcommand)]
    pub command: Option<RunCommands>,

    #[command(flatten)]
    pub exec: ExecArgs,
}

#[derive(Args)]
pub struct ExecArgs {
    /// Environment
    #[arg(long, short)]
    pub env: Option<String>,

    /// Don't inherit parent environment
    #[arg(long, short)]
    pub clean: bool,

    /// Use production environment
    #[arg(long)]
    pub prod: bool,

    /// Use staging environment
    #[arg(long)]
    pub staging: bool,

    /// Command and arguments
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

#[derive(Subcommand)]
pub enum RunCommands {
    /// Run a command with secrets injected as env vars
    Exec(ExecArgs),
    /// Export secrets in various formats
    Export {
        /// Environment
        #[arg(long, short)]
        env: Option<String>,
        /// Output format: dotenv, json, shell, docker, k8s
        #[arg(long, short, default_value = "dotenv")]
        format: String,
        /// Name for k8s secrets
        #[arg(long, default_value = "app-secrets")]
        name: String,
    },
    /// Serve secrets over a Unix domain socket (Unix only)
    #[cfg(unix)]
    Serve {
        /// Environment
        #[arg(long, short)]
        env: Option<String>,
        /// Path for the Unix socket
        #[arg(long)]
        socket: Option<String>,
    },
}

/// Resolve the effective environment from flags and project config.
fn resolve_env(exec: &ExecArgs) -> Option<String> {
    if exec.prod {
        Some("prod".into())
    } else if exec.staging {
        Some("staging".into())
    } else {
        exec.env.clone()
    }
}

/// Try to resolve a named command from `.sigyn.toml` `[commands]` table.
fn resolve_named_command(args: &[String]) -> Option<Vec<String>> {
    if args.is_empty() {
        return None;
    }
    let project = load_project_config()?;
    let cmd_str = project.commands.get(&args[0])?;
    eprintln!(
        "{} resolved command '{}' from .sigyn.toml: {}",
        style("note:").cyan().bold(),
        args[0],
        cmd_str
    );
    // Split the command string and append any extra args
    let mut parts: Vec<String> = cmd_str.split_whitespace().map(String::from).collect();
    parts.extend_from_slice(&args[1..]);
    Some(parts)
}

/// Check whether vault resolution would succeed, and offer interactive setup if not.
///
/// Returns the vault name to use (from the freshly-created config), or None if the
/// user declined or we're non-interactive.
fn maybe_offer_setup(vault: Option<&str>) -> Result<Option<String>> {
    // If the caller already passed --vault, skip the check
    if vault.is_some() {
        return Ok(None);
    }

    // Check if project config or global config has a vault
    let project = load_project_config();
    let project_vault = project
        .as_ref()
        .and_then(|p| p.project.as_ref())
        .and_then(|p| p.vault.clone());
    if project_vault.is_some() {
        return Ok(None);
    }

    let config = crate::config::load_config();
    if config.default_vault.is_some() {
        return Ok(None);
    }

    // No vault can be resolved — offer setup or bail
    if crate::config::is_interactive() {
        let detection = crate::project_detect::detect_project();
        eprintln!(
            "{} No vault configured for this project.",
            style("note:").cyan().bold()
        );
        eprintln!(
            "  Detected project: {} (from {})",
            style(&detection.suggested_vault_name).bold(),
            detection.source
        );
        eprintln!();

        let setup = dialoguer::Confirm::new()
            .with_prompt("Set up .sigyn.toml now? (or use --vault to specify)")
            .default(true)
            .interact()?;

        if setup {
            // Run the interactive project init flow
            crate::commands::project::handle(
                crate::commands::project::ProjectCommands::Init {
                    global: false,
                    vault: None,
                    env: None,
                    identity: None,
                },
                false,
            )?;
            // Re-load the project config to get the vault name
            let new_project = load_project_config();
            let new_vault = new_project
                .as_ref()
                .and_then(|p| p.project.as_ref())
                .and_then(|p| p.vault.clone());
            return Ok(new_vault);
        }

        anyhow::bail!("no vault specified. Run 'sigyn project init' or use --vault <name>");
    }

    anyhow::bail!(
        "no vault specified; use --vault, create .sigyn.toml (sigyn project init), or set a default (sigyn init --vault <name>)"
    );
}

fn exec_with_secrets(
    exec: &ExecArgs,
    vault: Option<&str>,
    identity: Option<&str>,
    command: &[String],
    dry_run: bool,
) -> Result<()> {
    if command.is_empty() {
        let mut msg = String::from("no command specified\n\n");
        msg.push_str("Usage: sigyn run [--env <env>] -- <command>\n");
        msg.push_str("       sigyn run export [--format dotenv|json|shell|docker|k8s]\n");
        #[cfg(unix)]
        msg.push_str("       sigyn run serve [--socket <path>]\n");
        msg.push('\n');

        // Show named commands from .sigyn.toml if available
        if let Some(project) = load_project_config() {
            if !project.commands.is_empty() {
                msg.push_str("Named commands (from .sigyn.toml):\n");
                for (name, cmd_str) in &project.commands {
                    msg.push_str(&format!("  {:<8} → {}\n", name, cmd_str));
                }
                msg.push('\n');
            }
        }

        msg.push_str("Run 'sigyn run --help' for full usage.");
        anyhow::bail!(msg);
    }

    // Offer interactive setup if no vault is configured
    let setup_vault = maybe_offer_setup(vault)?;
    let effective_vault = vault.map(String::from).or(setup_vault);

    let env = resolve_env(exec);
    let ctx = unlock_vault(
        identity,
        effective_vault.as_deref().or(vault),
        env.as_deref(),
    )?;
    check_access(&ctx, AccessAction::Read, None)?;

    let env_path = ctx.paths.env_path(&ctx.vault_name, &ctx.env_name);
    if !env_path.exists() {
        anyhow::bail!("environment '{}' has no secrets", ctx.env_name);
    }

    let encrypted = env_file::read_encrypted_env(&env_path)?;
    let plaintext = env_file::decrypt_env(&encrypted, &ctx.cipher)?;

    if dry_run {
        println!(
            "[dry-run] Vault: '{}', env: '{}', secrets: {}",
            ctx.vault_name,
            ctx.env_name,
            plaintext.len()
        );
        println!("[dry-run] Command: {}", command.join(" "));
        println!(
            "[dry-run] Clean env: {}",
            if exec.clean {
                "yes"
            } else {
                "no (inheriting parent)"
            }
        );
        return Ok(());
    }

    let exit_code = crate::inject::run_with_secrets(&plaintext, command, !exec.clean)?;
    std::process::exit(exit_code);
}

pub fn handle(
    args: RunArgs,
    vault: Option<&str>,
    identity: Option<&str>,
    _json: bool,
    dry_run: bool,
) -> Result<()> {
    match args.command {
        Some(RunCommands::Exec(exec)) => {
            let command = exec.command.clone();
            exec_with_secrets(&exec, vault, identity, &command, dry_run)
        }
        Some(RunCommands::Export { env, format, name }) => {
            let setup_vault = maybe_offer_setup(vault)?;
            let effective_vault = vault.map(String::from).or(setup_vault);
            let ctx = unlock_vault(
                identity,
                effective_vault.as_deref().or(vault),
                env.as_deref(),
            )?;
            check_access(&ctx, AccessAction::Read, None)?;

            let env_path = ctx.paths.env_path(&ctx.vault_name, &ctx.env_name);
            if !env_path.exists() {
                anyhow::bail!("environment '{}' has no secrets", ctx.env_name);
            }

            let encrypted = env_file::read_encrypted_env(&env_path)?;
            let plaintext = env_file::decrypt_env(&encrypted, &ctx.cipher)?;

            let export_format = crate::inject::ExportFormat::from_str(&format)?;
            let output = crate::inject::export_secrets(&plaintext, export_format, &name)?;

            use std::io::Write;
            std::io::stdout().write_all(output.as_bytes())?;
            std::io::stdout().write_all(b"\n")?;
            Ok(())
        }
        #[cfg(unix)]
        Some(RunCommands::Serve { env, socket }) => {
            let ctx = unlock_vault(identity, vault, env.as_deref())?;
            check_access(&ctx, AccessAction::Read, None)?;

            let env_path = ctx.paths.env_path(&ctx.vault_name, &ctx.env_name);
            if !env_path.exists() {
                anyhow::bail!("environment '{}' has no secrets", ctx.env_name);
            }

            let encrypted = env_file::read_encrypted_env(&env_path)?;
            let plaintext = env_file::decrypt_env(&encrypted, &ctx.cipher)?;

            let socket_path = socket.unwrap_or_else(|| {
                let sigyn_dir = crate::config::sigyn_home();
                format!("{}/sigyn.sock", sigyn_dir.display())
            });
            crate::inject::serve_secrets(&plaintext, &socket_path)?;
            Ok(())
        }
        None => {
            // Default: exec mode. Try named command lookup first.
            let mut command = args.exec.command.clone();
            if let Some(resolved) = resolve_named_command(&command) {
                command = resolved;
            }
            exec_with_secrets(&args.exec, vault, identity, &command, dry_run)
        }
    }
}
