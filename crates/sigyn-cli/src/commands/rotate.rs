use anyhow::Result;
use clap::Subcommand;
use console::style;

use sigyn_core::audit::entry::AuditOutcome;
use sigyn_core::audit::{AuditAction, AuditLog};
use sigyn_core::crypto::keys::KeyFingerprint;
use sigyn_core::policy::engine::AccessAction;
use sigyn_core::rotation::breach::BreachReport;
use sigyn_core::rotation::dead::find_dead_secrets;
use sigyn_core::rotation::schedule::RotationSchedule;
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
    /// Manage rotation schedules
    Schedule {
        #[command(subcommand)]
        command: ScheduleCommands,
    },
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

#[derive(Subcommand)]
pub enum ScheduleCommands {
    /// List all rotation schedules
    List,
    /// Set a rotation schedule for a key
    Set {
        /// Secret key pattern
        key: String,
        /// Cron expression (e.g. '0 0 * * * *' for hourly)
        #[arg(long)]
        cron: String,
        /// Grace period in hours before rotation is considered overdue
        #[arg(long, default_value = "24")]
        grace_hours: u32,
        /// Post-rotation hook commands
        #[arg(long)]
        hooks: Vec<String>,
    },
    /// Remove a rotation schedule
    Remove {
        /// Secret key pattern to remove schedule for
        key: String,
    },
}

/// Load rotation schedules from vault dir
fn load_schedules(
    vault_dir: &std::path::Path,
) -> std::collections::HashMap<String, RotationSchedule> {
    let path = vault_dir.join("rotation_schedules.toml");
    if path.exists() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(schedules) = toml::from_str(&content) {
                return schedules;
            }
        }
    }
    std::collections::HashMap::new()
}

/// Save rotation schedules to vault dir
fn save_schedules(
    vault_dir: &std::path::Path,
    schedules: &std::collections::HashMap<String, RotationSchedule>,
) -> Result<()> {
    let path = vault_dir.join("rotation_schedules.toml");
    let content = toml::to_string_pretty(schedules)?;
    std::fs::write(path, content)?;
    Ok(())
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
    dry_run: bool,
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

            if dry_run {
                println!("[dry-run] Would rotate '{}' in env '{}'", key, ctx.env_name);
                return Ok(());
            }

            plaintext.set(key.clone(), new_value, &ctx.fingerprint);

            let encrypted = env_file::encrypt_env(&plaintext, &ctx.cipher, &ctx.env_name)?;
            env_file::write_encrypted_env(&env_path, &encrypted)?;

            audit(
                &ctx,
                AuditAction::SecretWritten { key: key.clone() },
                AuditOutcome::Success,
            );

            // Execute rotation hooks if a schedule exists for this key
            let vault_dir = crate::config::sigyn_home()
                .join("vaults")
                .join(&ctx.vault_name);
            let schedules = load_schedules(&vault_dir);
            if let Some(schedule) = schedules.get(&key) {
                if !schedule.hooks.is_empty() {
                    match sigyn_core::rotation::hooks::execute_rotation_hooks(
                        &schedule.hooks,
                        &key,
                        &ctx.env_name,
                    ) {
                        Ok(results) => {
                            for r in &results {
                                if r.success {
                                    eprintln!("  Hook '{}': OK", r.hook);
                                } else {
                                    eprintln!(
                                        "  {} Hook '{}' failed: {}",
                                        style("warning:").yellow().bold(),
                                        r.hook,
                                        r.output.trim()
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "  {} rotation hooks failed: {}",
                                style("warning:").yellow().bold(),
                                e
                            );
                        }
                    }
                }
            }

            crate::notifications::try_notify(
                &ctx.vault_name,
                Some(&ctx.env_name),
                Some(&key),
                &ctx.fingerprint.to_hex(),
                "secret.rotated",
                &format!("Secret '{}' rotated in env '{}'", key, ctx.env_name),
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
        RotateCommands::Schedule { command } => {
            let vault_name = vault.unwrap_or("default");
            let home = crate::config::sigyn_home();
            let vault_dir = home.join("vaults").join(vault_name);

            if !vault_dir.exists() {
                anyhow::bail!("vault '{}' not found", vault_name);
            }

            match command {
                ScheduleCommands::List => {
                    let schedules = load_schedules(&vault_dir);
                    if schedules.is_empty() {
                        println!("{}", style("Rotation Schedules").bold());
                        println!("{}", style("─".repeat(60)).dim());
                        println!("  No rotation schedules configured.");
                        println!("  Use: sigyn rotate schedule set <key> --cron '0 0 * * * *'");
                    } else if json {
                        crate::output::print_json(&serde_json::json!(schedules))?;
                    } else {
                        println!("{}", style("Rotation Schedules").bold());
                        println!("{}", style("─".repeat(60)).dim());
                        for (key, sched) in &schedules {
                            println!(
                                "  {} cron={} grace={}h hooks={}",
                                style(key).bold(),
                                sched.cron_expression,
                                sched.grace_period_hours,
                                sched.hooks.len(),
                            );
                        }
                    }
                }
                ScheduleCommands::Set {
                    key,
                    cron,
                    grace_hours,
                    hooks,
                } => {
                    let mut schedules = load_schedules(&vault_dir);
                    let mut schedule = RotationSchedule::new(&cron, grace_hours);
                    schedule.key_pattern = key.clone();
                    schedule.hooks = hooks;
                    schedules.insert(key.clone(), schedule);
                    save_schedules(&vault_dir, &schedules)?;

                    if json {
                        crate::output::print_json(&serde_json::json!({
                            "action": "schedule_set",
                            "key": key,
                            "cron": cron,
                            "grace_hours": grace_hours,
                        }))?;
                    } else {
                        crate::output::print_success(&format!(
                            "Rotation schedule set for '{}' (cron: {})",
                            key, cron
                        ));
                    }
                }
                ScheduleCommands::Remove { key } => {
                    let mut schedules = load_schedules(&vault_dir);
                    if schedules.remove(&key).is_none() {
                        anyhow::bail!("no rotation schedule found for '{}'", key);
                    }
                    save_schedules(&vault_dir, &schedules)?;

                    crate::output::print_success(&format!(
                        "Removed rotation schedule for '{}'",
                        key
                    ));
                }
            }
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

            crate::notifications::try_notify(
                &ctx.vault_name,
                None,
                None,
                &ctx.fingerprint.to_hex(),
                "breach_mode",
                &format!(
                    "Breach mode activated: {} secrets rotated, {} members revoked",
                    all_rotated_keys.len(),
                    delegated_fps.len()
                ),
            );

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
