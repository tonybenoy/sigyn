use anyhow::Result;
use clap::Subcommand;
use sigyn_core::policy::engine::AccessAction;
use sigyn_core::vault::env_file;

use super::secret::{check_access, unlock_vault};

#[derive(Subcommand)]
pub enum RunCommands {
    /// Run a command with secrets injected as env vars
    Exec {
        /// Environment
        #[arg(long, short)]
        env: Option<String>,
        /// Don't inherit parent environment
        #[arg(long)]
        clean: bool,
        /// Command and arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
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
    /// Serve secrets over a Unix domain socket
    Serve {
        /// Environment
        #[arg(long, short)]
        env: Option<String>,
        /// Path for the Unix socket
        #[arg(long, default_value = "/tmp/sigyn.sock")]
        socket: String,
    },
}

pub fn handle(
    cmd: RunCommands,
    vault: Option<&str>,
    identity: Option<&str>,
    _json: bool,
) -> Result<()> {
    match cmd {
        RunCommands::Exec {
            env,
            clean,
            command,
        } => {
            if command.is_empty() {
                anyhow::bail!("no command specified. Usage: sigyn run exec -- <command>");
            }

            let ctx = unlock_vault(identity, vault, env.as_deref())?;
            check_access(&ctx, AccessAction::Read, None)?;

            let env_path = ctx.paths.env_path(&ctx.vault_name, &ctx.env_name);
            if !env_path.exists() {
                anyhow::bail!("environment '{}' has no secrets", ctx.env_name);
            }

            let encrypted = env_file::read_encrypted_env(&env_path)?;
            let plaintext = env_file::decrypt_env(&encrypted, &ctx.cipher)?;

            let exit_code = crate::inject::run_with_secrets(&plaintext, &command, !clean)?;
            std::process::exit(exit_code);
        }
        RunCommands::Export { env, format, name } => {
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

            println!("{}", output);
        }
        RunCommands::Serve { env, socket } => {
            let ctx = unlock_vault(identity, vault, env.as_deref())?;
            check_access(&ctx, AccessAction::Read, None)?;

            let env_path = ctx.paths.env_path(&ctx.vault_name, &ctx.env_name);
            if !env_path.exists() {
                anyhow::bail!("environment '{}' has no secrets", ctx.env_name);
            }

            let encrypted = env_file::read_encrypted_env(&env_path)?;
            let plaintext = env_file::decrypt_env(&encrypted, &ctx.cipher)?;

            crate::inject::serve_secrets(&plaintext, &socket)?;
        }
    }
    Ok(())
}
