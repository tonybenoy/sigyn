use anyhow::Result;
use clap::Subcommand;
use console::style;

use sigyn_engine::audit::entry::AuditOutcome;
use sigyn_engine::audit::{AuditAction, AuditLog};
use sigyn_engine::crypto::keys::KeyFingerprint;
use sigyn_engine::policy::engine::AccessAction;
use sigyn_engine::policy::storage::VaultPolicyExt;
use sigyn_engine::rotation::breach::BreachReport;
use sigyn_engine::rotation::dead::find_dead_secrets;
use sigyn_engine::rotation::schedule::RotationSchedule;
use sigyn_engine::secrets::generation::{GenerationTemplate, PasswordCharset};
use sigyn_engine::secrets::types::SecretValue;
use sigyn_engine::vault::env_file;

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

/// Load rotation schedules from vault dir (encrypted with master key when available).
fn load_schedules(
    vault_dir: &std::path::Path,
    cipher: Option<&sigyn_engine::crypto::vault_cipher::VaultCipher>,
    vault_id: Option<uuid::Uuid>,
) -> std::collections::HashMap<String, RotationSchedule> {
    let path = vault_dir.join("rotation_schedules.toml");
    if !path.exists() {
        return std::collections::HashMap::new();
    }
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(_) => return std::collections::HashMap::new(),
    };
    if !sigyn_engine::crypto::sealed::is_sealed(&data) {
        eprintln!(
            "{} rotation_schedules.toml is not in sealed format — ignoring (possible tampering)",
            console::style("warning:").yellow().bold()
        );
        return std::collections::HashMap::new();
    }
    if let (Some(cipher), Some(vid)) = (cipher, vault_id) {
        if let Ok(rotation_cipher) = sigyn_engine::crypto::sealed::derive_file_cipher_with_salt(
            cipher.key_bytes(),
            b"sigyn-rotation-v1",
            &vid,
        ) {
            if let Ok(plaintext) = sigyn_engine::crypto::sealed::sealed_decrypt(
                &rotation_cipher,
                &data,
                b"rotation_schedules.toml",
            ) {
                if let Ok(s) = std::str::from_utf8(&plaintext) {
                    if let Ok(schedules) = toml::from_str(s) {
                        return schedules;
                    }
                }
            }
        }
    }
    std::collections::HashMap::new()
}

/// Save rotation schedules to vault dir (encrypted with master key).
fn save_schedules(
    vault_dir: &std::path::Path,
    schedules: &std::collections::HashMap<String, RotationSchedule>,
    cipher: Option<&sigyn_engine::crypto::vault_cipher::VaultCipher>,
    vault_id: Option<uuid::Uuid>,
) -> Result<()> {
    let path = vault_dir.join("rotation_schedules.toml");
    let content = toml::to_string_pretty(schedules)?;
    if let (Some(cipher), Some(vid)) = (cipher, vault_id) {
        let rotation_cipher = sigyn_engine::crypto::sealed::derive_file_cipher_with_salt(
            cipher.key_bytes(),
            b"sigyn-rotation-v1",
            &vid,
        )?;
        let sealed = sigyn_engine::crypto::sealed::sealed_encrypt(
            &rotation_cipher,
            content.as_bytes(),
            b"rotation_schedules.toml",
        )?;
        crate::config::secure_write(&path, &sealed)?;
    } else {
        crate::config::secure_write(&path, content.as_bytes())?;
    }
    Ok(())
}

/// Append an audit entry (best-effort -- don't fail the operation on audit error)
fn audit(ctx: &UnlockedVaultContext, action: AuditAction, outcome: AuditOutcome) {
    let audit_path = ctx.paths.audit_path(&ctx.vault_name);
    let audit_cipher = match sigyn_engine::crypto::sealed::derive_file_cipher_with_salt(
        ctx.vault_cipher.key_bytes(),
        b"sigyn-audit-v1",
        &ctx.manifest.vault_id,
    ) {
        Ok(c) => c,
        Err(_) => return,
    };
    if let Ok(mut log) = AuditLog::open(&audit_path, audit_cipher) {
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

            let env_cipher = ctx.current_env_cipher();
            let encrypted = env_file::read_encrypted_env(&env_path)?;
            let mut plaintext = env_file::decrypt_env(&encrypted, env_cipher)?;

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

            let encrypted = env_file::encrypt_env(&plaintext, env_cipher, &ctx.env_name)?;
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
            let schedules = load_schedules(
                &vault_dir,
                Some(&ctx.vault_cipher),
                Some(ctx.manifest.vault_id),
            );
            if let Some(schedule) = schedules.get(&key) {
                if !schedule.hooks.is_empty() {
                    match sigyn_engine::rotation::hooks::execute_rotation_hooks(
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
            let ctx = unlock_vault(identity, vault, None)?;
            let vault_dir = crate::config::sigyn_home()
                .join("vaults")
                .join(&ctx.vault_name);

            match command {
                ScheduleCommands::List => {
                    let schedules = load_schedules(
                        &vault_dir,
                        Some(&ctx.vault_cipher),
                        Some(ctx.manifest.vault_id),
                    );
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
                    let mut schedules = load_schedules(
                        &vault_dir,
                        Some(&ctx.vault_cipher),
                        Some(ctx.manifest.vault_id),
                    );
                    let mut schedule = RotationSchedule::new(&cron, grace_hours);
                    schedule.key_pattern = key.clone();
                    schedule.hooks = hooks;
                    schedules.insert(key.clone(), schedule);
                    save_schedules(
                        &vault_dir,
                        &schedules,
                        Some(&ctx.vault_cipher),
                        Some(ctx.manifest.vault_id),
                    )?;

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
                    let mut schedules = load_schedules(
                        &vault_dir,
                        Some(&ctx.vault_cipher),
                        Some(ctx.manifest.vault_id),
                    );
                    if schedules.remove(&key).is_none() {
                        anyhow::bail!("no rotation schedule found for '{}'", key);
                    }
                    save_schedules(
                        &vault_dir,
                        &schedules,
                        Some(&ctx.vault_cipher),
                        Some(ctx.manifest.vault_id),
                    )?;

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
            let plaintext = env_file::decrypt_env(&encrypted, ctx.current_env_cipher())?;

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

                let env_c = ctx
                    .cipher_for_env(env_name)
                    .ok_or_else(|| anyhow::anyhow!("no access to env '{}'", env_name))?;
                let encrypted = env_file::read_encrypted_env(&env_path)?;
                let mut plaintext = env_file::decrypt_env(&encrypted, env_c)?;

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

                let encrypted = env_file::encrypt_env(&plaintext, env_c, env_name)?;
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

            // Rotate vault key + all env keys, rebuild header
            let master_key_rotated = {
                use sigyn_engine::crypto::envelope;
                use sigyn_engine::identity::keygen::IdentityStore;

                let mut header = ctx.header.clone();

                // Remove all delegated members from slots
                for fp in &delegated_fps {
                    envelope::remove_recipient_v2(&mut header, fp);
                }

                // Rotate vault key
                let new_vault_cipher = sigyn_engine::crypto::vault_cipher::VaultCipher::generate();
                let home_for_ids = crate::config::sigyn_home();
                let id_store = IdentityStore::new(home_for_ids);
                let identities = id_store
                    .list()
                    .map_err(|e| anyhow::anyhow!("failed to list identities: {}", e))?;

                // Rebuild vault_key_slots for remaining members
                header.vault_key_slots.clear();
                envelope::add_vault_key_recipient(
                    &mut header,
                    new_vault_cipher.key_bytes(),
                    &ctx.loaded_identity.identity.encryption_pubkey,
                    ctx.manifest.vault_id,
                )?;
                for mp in policy.members.values() {
                    if let Some(id) = identities
                        .iter()
                        .find(|id| id.fingerprint == mp.fingerprint)
                    {
                        envelope::add_vault_key_recipient(
                            &mut header,
                            new_vault_cipher.key_bytes(),
                            &id.encryption_pubkey,
                            ctx.manifest.vault_id,
                        )?;
                    }
                }

                // Rotate all env keys and re-encrypt env files with new keys
                for env_name in &environments {
                    let mut remaining_pks =
                        vec![ctx.loaded_identity.identity.encryption_pubkey.clone()];
                    for mp in policy.members.values() {
                        let has_access = mp.allowed_envs.iter().any(|e| e == "*" || e == env_name);
                        if has_access {
                            if let Some(id) = identities
                                .iter()
                                .find(|id| id.fingerprint == mp.fingerprint)
                            {
                                remaining_pks.push(id.encryption_pubkey.clone());
                            }
                        }
                    }
                    let new_env_key = envelope::rotate_env_key(
                        &mut header,
                        env_name,
                        &remaining_pks,
                        ctx.manifest.vault_id,
                    )?;

                    // Re-encrypt env file with new key
                    let env_path = ctx.paths.env_path(&ctx.vault_name, env_name);
                    if env_path.exists() {
                        if let Some(old_cipher) = ctx.cipher_for_env(env_name) {
                            let encrypted = env_file::read_encrypted_env(&env_path)?;
                            let plaintext = env_file::decrypt_env(&encrypted, old_cipher)?;
                            let new_cipher =
                                sigyn_engine::crypto::vault_cipher::VaultCipher::new(new_env_key);
                            let re_encrypted =
                                env_file::encrypt_env(&plaintext, &new_cipher, env_name)?;
                            env_file::write_encrypted_env(&env_path, &re_encrypted)?;
                        }
                    }
                }

                // Re-encrypt manifest and policy with new vault key
                let manifest_path = ctx.paths.manifest_path(&ctx.vault_name);
                let sealed = ctx
                    .manifest
                    .to_sealed_bytes(&new_vault_cipher)
                    .map_err(|e| anyhow::anyhow!("failed to seal manifest: {}", e))?;
                crate::config::secure_write(&manifest_path, &sealed)?;
                policy
                    .save_encrypted(&ctx.paths.policy_path(&ctx.vault_name), &new_vault_cipher)?;

                // Save header
                let signed = envelope::sign_header(
                    &header,
                    ctx.loaded_identity.signing_key(),
                    ctx.manifest.vault_id,
                )?;
                crate::config::secure_write(&ctx.paths.members_path(&ctx.vault_name), &signed)?;

                true
            };

            // Audit
            audit(&ctx, AuditAction::MasterKeyRotated, AuditOutcome::Success);

            // Build breach report
            let report = BreachReport {
                rotated_keys: all_rotated_keys.clone(),
                revoked_members: delegated_fps.clone(),
                new_master_key: master_key_rotated,
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
                crate::output::print_info(
                    "Vault key + all env keys rotated, environments re-encrypted",
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
            let plaintext = env_file::decrypt_env(&encrypted, ctx.current_env_cipher())?;

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
