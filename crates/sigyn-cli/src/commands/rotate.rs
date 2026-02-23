use anyhow::Result;
use clap::Subcommand;
use console::style;

use sigyn_core::audit::entry::AuditOutcome;
use sigyn_core::audit::{AuditAction, AuditLog};
use sigyn_core::crypto::keys::KeyFingerprint;
use sigyn_core::policy::engine::AccessAction;
use sigyn_core::rotation::breach::BreachReport;
use sigyn_core::rotation::dead::find_dead_secrets;
use sigyn_core::secrets::generation::{GenerationTemplate, PasswordCharset};
use sigyn_core::secrets::types::SecretValue;
use sigyn_core::vault::env_file;

use super::secret::{check_access, unlock_vault, UnlockedVaultContext};

#[derive(Subcommand)]
pub enum RotateCommands {
    /// Rotate a specific secret
    Key {
        /// Secret key to rotate
        key: String,
        /// Environment
        #[arg(long, short)]
        env: Option<String>,
    },
    /// Show rotation schedule
    Schedule,
    /// Show secrets due for rotation
    Due {
        /// Max age in days before a secret is "due"
        #[arg(long, default_value = "90")]
        max_age: i64,
        /// Environment
        #[arg(long, short)]
        env: Option<String>,
    },
    /// Activate breach mode (rotate everything, revoke delegated)
    BreachMode {
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
    /// Check for dead (unused/stale) secrets
    DeadCheck {
        /// Max age in days
        #[arg(long, default_value = "180")]
        max_age: i64,
        /// Environment
        #[arg(long, short)]
        env: Option<String>,
    },
}

/// Append an audit entry (best-effort -- don't fail the operation on audit error)
fn audit(ctx: &UnlockedVaultContext, action: AuditAction, outcome: AuditOutcome) {
    let audit_path = ctx.paths.audit_path(&ctx.vault_name);
    if let Ok(mut log) = AuditLog::open(&audit_path) {
        let _ = log.append(
            &ctx.fingerprint,
            action,
            Some(ctx.env_name.clone()),
            outcome,
            ctx.loaded_identity.signing_key(),
        );
    }
}

pub fn handle(
    cmd: RotateCommands,
    vault: Option<&str>,
    identity: Option<&str>,
    json: bool,
) -> Result<()> {
    match cmd {
        RotateCommands::Key { key, env } => {
            let ctx = unlock_vault(identity, vault, env.as_deref())?;
            check_access(&ctx, AccessAction::Write, Some(&key))?;

            let env_path = ctx.paths.env_path(&ctx.vault_name, &ctx.env_name);
            if !env_path.exists() {
                anyhow::bail!("environment '{}' has no secrets yet", ctx.env_name);
            }

            let encrypted = env_file::read_encrypted_env(&env_path)?;
            let mut plaintext = env_file::decrypt_env(&encrypted, &ctx.cipher)?;

            let entry = plaintext.get(&key).ok_or_else(|| {
                anyhow::anyhow!("secret '{}' not found in env '{}'", key, ctx.env_name)
            })?;

            let new_value = match &entry.value {
                SecretValue::Generated(old_val) => {
                    let template = GenerationTemplate::Password {
                        length: old_val.len(),
                        charset: PasswordCharset::default(),
                    };
                    SecretValue::Generated(template.generate())
                }
                SecretValue::String(_) => {
                    let template = GenerationTemplate::Password {
                        length: 32,
                        charset: PasswordCharset::default(),
                    };
                    SecretValue::Generated(template.generate())
                }
                _ => anyhow::bail!("cannot auto-rotate this secret type"),
            };

            plaintext.set(key.clone(), new_value, &ctx.fingerprint);

            let encrypted = env_file::encrypt_env(&plaintext, &ctx.cipher, &ctx.env_name)?;
            env_file::write_encrypted_env(&env_path, &encrypted)?;

            audit(
                &ctx,
                AuditAction::SecretWritten { key: key.clone() },
                AuditOutcome::Success,
            );

            if json {
                crate::output::print_json(&serde_json::json!({
                    "action": "rotated",
                    "key": key,
                    "env": ctx.env_name,
                }))?;
            } else {
                crate::output::print_success(&format!(
                    "Rotated '{}' in env '{}'",
                    key, ctx.env_name
                ));
            }
        }
        RotateCommands::Schedule => {
            println!("{}", style("Rotation Schedules").bold());
            println!("{}", style("─".repeat(60)).dim());
            println!("  No rotation schedules configured.");
            println!("  Use: sigyn rotate schedule set <key> --cron '0 0 * * 1'");
        }
        RotateCommands::Due { max_age, env } => {
            let ctx = unlock_vault(identity, vault, env.as_deref())?;
            let env_path = ctx.paths.env_path(&ctx.vault_name, &ctx.env_name);

            if !env_path.exists() {
                println!("No secrets in env '{}'", ctx.env_name);
                return Ok(());
            }

            let encrypted = env_file::read_encrypted_env(&env_path)?;
            let plaintext = env_file::decrypt_env(&encrypted, &ctx.cipher)?;

            let dead = find_dead_secrets(&plaintext, &ctx.env_name, max_age);

            if dead.is_empty() {
                println!("No secrets due for rotation (max age: {} days)", max_age);
            } else if json {
                crate::output::print_json(&serde_json::json!({
                    "due_count": dead.len(),
                    "max_age_days": max_age,
                    "secrets": dead.iter().map(|d| serde_json::json!({
                        "key": d.key,
                        "age_days": d.age_days,
                    })).collect::<Vec<_>>(),
                }))?;
            } else {
                println!(
                    "{} secrets due for rotation (>{} days old):",
                    style(dead.len()).bold(),
                    max_age
                );
                for d in &dead {
                    println!("  {} ({} days old)", style(&d.key).yellow(), d.age_days);
                }
            }
        }
        RotateCommands::BreachMode { force } => {
            if !force {
                use dialoguer::Confirm;
                let confirmed = Confirm::new()
                    .with_prompt(
                        "BREACH MODE will rotate ALL secrets and revoke delegated access. Continue?",
                    )
                    .default(false)
                    .interact()?;
                if !confirmed {
                    println!("Aborted.");
                    return Ok(());
                }
            }

            // Unlock with the first environment (we will iterate all of them)
            let ctx = unlock_vault(identity, vault, None)?;
            check_access(&ctx, AccessAction::ManagePolicy, None)?;

            let environments = ctx.manifest.environments.clone();
            let mut all_rotated_keys: Vec<String> = Vec::new();

            // Rotate all secrets in every environment
            for env_name in &environments {
                let env_path = ctx.paths.env_path(&ctx.vault_name, env_name);
                if !env_path.exists() {
                    continue;
                }

                let encrypted = env_file::read_encrypted_env(&env_path)?;
                let mut plaintext = env_file::decrypt_env(&encrypted, &ctx.cipher)?;

                let keys: Vec<String> = plaintext.entries.keys().cloned().collect();
                for key in &keys {
                    let template = GenerationTemplate::Password {
                        length: 32,
                        charset: PasswordCharset::default(),
                    };
                    let new_value = SecretValue::Generated(template.generate());
                    plaintext.set(key.clone(), new_value, &ctx.fingerprint);
                    all_rotated_keys.push(format!("{}:{}", env_name, key));
                }

                let encrypted = env_file::encrypt_env(&plaintext, &ctx.cipher, env_name)?;
                env_file::write_encrypted_env(&env_path, &encrypted)?;
            }

            // Revoke all delegated members
            let mut policy = ctx.policy.clone();
            let delegated_fps: Vec<KeyFingerprint> = policy
                .members
                .values()
                .filter(|m| m.delegated_by.is_some())
                .map(|m| m.fingerprint.clone())
                .collect();

            for fp in &delegated_fps {
                policy.remove_member(fp);
            }

            // Save updated policy
            policy.save_encrypted(&ctx.paths.policy_path(&ctx.vault_name), &ctx.cipher)?;

            // Audit
            audit(&ctx, AuditAction::MasterKeyRotated, AuditOutcome::Success);

            // Build breach report
            let report = BreachReport {
                rotated_keys: all_rotated_keys.clone(),
                revoked_members: delegated_fps.clone(),
                new_master_key: false,
                vault_locked: false,
                timestamp: chrono::Utc::now(),
            };

            if json {
                crate::output::print_json(&serde_json::json!({
                    "action": "breach_mode",
                    "rotated_keys": report.rotated_keys,
                    "revoked_members": report.revoked_members.len(),
                    "new_master_key": report.new_master_key,
                    "vault_locked": report.vault_locked,
                    "timestamp": report.timestamp.to_rfc3339(),
                }))?;
            } else {
                crate::output::print_success("Breach mode activated");
                println!(
                    "  {} secrets rotated across {} environments",
                    style(all_rotated_keys.len()).bold(),
                    style(environments.len()).bold()
                );
                if !delegated_fps.is_empty() {
                    println!(
                        "  {} delegated members revoked",
                        style(delegated_fps.len()).bold()
                    );
                }
                println!(
                    "  Master key rotation: {}",
                    style("skipped (basic mode)").dim()
                );
            }
        }
        RotateCommands::DeadCheck { max_age, env } => {
            let ctx = unlock_vault(identity, vault, env.as_deref())?;
            let env_path = ctx.paths.env_path(&ctx.vault_name, &ctx.env_name);

            if !env_path.exists() {
                println!("No secrets in env '{}'", ctx.env_name);
                return Ok(());
            }

            let encrypted = env_file::read_encrypted_env(&env_path)?;
            let plaintext = env_file::decrypt_env(&encrypted, &ctx.cipher)?;

            let dead = find_dead_secrets(&plaintext, &ctx.env_name, max_age);

            if dead.is_empty() {
                println!("No dead secrets found (max age: {} days)", max_age);
            } else if json {
                crate::output::print_json(&serde_json::json!({
                    "dead_count": dead.len(),
                    "max_age_days": max_age,
                    "secrets": dead.iter().map(|d| serde_json::json!({
                        "key": d.key,
                        "age_days": d.age_days,
                    })).collect::<Vec<_>>(),
                }))?;
            } else {
                println!(
                    "{} dead secrets found (>{} days old):",
                    style(dead.len()).bold(),
                    max_age
                );
                for d in &dead {
                    println!("  {} ({} days old)", style(&d.key).yellow(), d.age_days);
                }
            }
        }
    }
    Ok(())
}
