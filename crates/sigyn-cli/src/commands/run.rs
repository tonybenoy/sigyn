use anyhow::Result;
use clap::{Args, Subcommand};
use console::style;
use sigyn_core::policy::engine::AccessAction;
use sigyn_core::vault::env_file;

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

fn exec_with_secrets(
    exec: &ExecArgs,
    vault: Option<&str>,
    identity: Option<&str>,
    command: &[String],
) -> Result<()> {
    if command.is_empty() {
        anyhow::bail!("no command specified. Usage: sigyn run -- <command>");
    }

    let env = resolve_env(exec);
    let ctx = unlock_vault(identity, vault, env.as_deref())?;
    check_access(&ctx, AccessAction::Read, None)?;

    let env_path = ctx.paths.env_path(&ctx.vault_name, &ctx.env_name);
    if !env_path.exists() {
        anyhow::bail!("environment '{}' has no secrets", ctx.env_name);
    }

    let encrypted = env_file::read_encrypted_env(&env_path)?;
    let plaintext = env_file::decrypt_env(&encrypted, &ctx.cipher)?;

    let exit_code = crate::inject::run_with_secrets(&plaintext, command, !exec.clean)?;
    std::process::exit(exit_code);
}

pub fn handle(
    args: RunArgs,
    vault: Option<&str>,
    identity: Option<&str>,
    _json: bool,
) -> Result<()> {
    match args.command {
        Some(RunCommands::Exec(exec)) => {
            let command = exec.command.clone();
            exec_with_secrets(&exec, vault, identity, &command)
        }
        Some(RunCommands::Export { env, format, name }) => {
            let ctx = unlock_vault(identity, vault, env.as_deref())?;
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
            exec_with_secrets(&args.exec, vault, identity, &command)
        }
    }
}
