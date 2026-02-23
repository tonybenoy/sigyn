use anyhow::Result;
use clap::Subcommand;
use console::style;
use sigyn_core::audit::{AuditAction, AuditLog};
use sigyn_core::audit::entry::AuditOutcome;
use sigyn_core::environment::promotion::promote_env;
use sigyn_core::policy::engine::AccessAction;
use sigyn_core::vault::{env_file, PlaintextEnv, VaultManifest, VaultPaths};

use super::secret::{unlock_vault, check_access};
use crate::config::sigyn_home;

#[derive(Subcommand)]
pub enum EnvCommands {
    /// List environments in a vault
    List,
    /// Create a new environment
    Create {
        /// Environment name
        name: String,
    },
    /// Promote secrets from one environment to another
    Promote {
        /// Source environment name
        #[arg(long)]
        from: String,
        /// Target environment name
        #[arg(long)]
        to: String,
        /// Optional comma-separated list of keys to promote
        #[arg(long, value_delimiter = ',')]
        keys: Option<Vec<String>>,
    },
}

pub fn handle(
    cmd: EnvCommands,
    vault: Option<&str>,
    identity: Option<&str>,
    json: bool,
) -> Result<()> {
    let home = sigyn_home();
    let paths = VaultPaths::new(home);
    let config = crate::config::load_config();

    let vault_name = vault
        .map(String::from)
        .or(config.default_vault)
        .ok_or_else(|| anyhow::anyhow!("no vault specified"))?;

    match cmd {
        EnvCommands::List => {
            let content = std::fs::read_to_string(paths.manifest_path(&vault_name))?;
            let manifest = VaultManifest::from_toml(&content)?;

            if json {
                crate::output::print_json(&manifest.environments)?;
            } else {
                println!(
                    "{} (vault: {})",
                    style("Environments").bold(),
                    vault_name
                );
                for env in &manifest.environments {
                    let env_path = paths.env_path(&vault_name, env);
                    let status = if env_path.exists() { "active" } else { "empty" };
                    println!("  {} ({})", style(env).cyan(), style(status).dim());
                }
            }
        }
        EnvCommands::Create { name } => {
            sigyn_core::secrets::validation::validate_env_name(&name)?;

            let ctx = unlock_vault(identity, vault, None)?;
            check_access(&ctx, AccessAction::CreateEnv, None)?;

            let manifest_path = paths.manifest_path(&vault_name);
            let content = std::fs::read_to_string(&manifest_path)?;
            let mut manifest = VaultManifest::from_toml(&content)?;

            if manifest.environments.contains(&name) {
                anyhow::bail!("environment '{}' already exists", name);
            }

            manifest.environments.push(name.clone());
            std::fs::write(&manifest_path, manifest.to_toml()?)?;

            // Audit log
            let audit_path = ctx.paths.audit_path(&ctx.vault_name);
            if let Ok(mut log) = AuditLog::open(&audit_path) {
                let _ = log.append(
                    &ctx.fingerprint,
                    AuditAction::EnvironmentCreated { name: name.clone() },
                    None,
                    AuditOutcome::Success,
                    ctx.loaded_identity.signing_key(),
                );
            }

            crate::output::print_success(&format!(
                "Created environment '{}' in vault '{}'",
                name, vault_name
            ));
        }
        EnvCommands::Promote { from, to, keys } => {
            // Unlock the vault (use source env for policy context)
            let ctx = unlock_vault(identity, vault, Some(&from))?;
            check_access(&ctx, AccessAction::Promote, None)?;

            // Read source environment
            let source_path = paths.env_path(&vault_name, &from);
            if !source_path.exists() {
                anyhow::bail!("source environment '{}' has no secrets", from);
            }
            let source_encrypted = env_file::read_encrypted_env(&source_path)?;
            let source_env = env_file::decrypt_env(&source_encrypted, &ctx.cipher)?;

            // Read target environment (or create empty)
            let target_path = paths.env_path(&vault_name, &to);
            let mut target_env = if target_path.exists() {
                let target_encrypted = env_file::read_encrypted_env(&target_path)?;
                env_file::decrypt_env(&target_encrypted, &ctx.cipher)?
            } else {
                PlaintextEnv::new()
            };

            // Perform promotion
            let filter = keys.as_deref();
            let result = promote_env(&source_env, &mut target_env, &ctx.fingerprint, filter);

            // Write target env back encrypted
            let encrypted = env_file::encrypt_env(&target_env, &ctx.cipher, &to)?;
            env_file::write_encrypted_env(&target_path, &encrypted)?;

            // Audit log
            let audit_path = ctx.paths.audit_path(&ctx.vault_name);
            if let Ok(mut log) = AuditLog::open(&audit_path) {
                let _ = log.append(
                    &ctx.fingerprint,
                    AuditAction::EnvironmentPromoted {
                        source: from.clone(),
                        target: to.clone(),
                    },
                    None,
                    AuditOutcome::Success,
                    ctx.loaded_identity.signing_key(),
                );
            }

            if json {
                crate::output::print_json(&serde_json::json!({
                    "source": from,
                    "target": to,
                    "promoted": result.promoted_keys,
                    "skipped": result.skipped_keys,
                    "overwritten": result.overwritten_keys,
                }))?;
            } else {
                crate::output::print_success(&format!(
                    "Promoted {} secret(s) from '{}' to '{}'",
                    result.promoted_keys.len(),
                    from,
                    to,
                ));
                if !result.overwritten_keys.is_empty() {
                    println!(
                        "  {} overwritten: {}",
                        style("Keys").dim(),
                        result.overwritten_keys.join(", ")
                    );
                }
                if !result.skipped_keys.is_empty() {
                    println!(
                        "  {} skipped (not in source): {}",
                        style("Keys").dim(),
                        result.skipped_keys.join(", ")
                    );
                }
            }
        }
    }
    Ok(())
}
