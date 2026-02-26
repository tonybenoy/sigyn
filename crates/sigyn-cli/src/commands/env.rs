use anyhow::Result;
use clap::Subcommand;
use console::style;
use sigyn_engine::audit::entry::AuditOutcome;
use sigyn_engine::audit::{AuditAction, AuditLog};
use sigyn_engine::environment::promotion::promote_env;
use sigyn_engine::policy::engine::AccessAction;
use sigyn_engine::vault::{env_file, PlaintextEnv, VaultPaths};

use super::secret::{check_access, unlock_vault};
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
    /// Compare secrets between two environments
    Diff {
        /// Source environment
        from: String,
        /// Target environment
        to: String,
        /// Show actual values (default: masked)
        #[arg(long)]
        reveal: bool,
    },
    /// Clone an environment (copy all secrets)
    Clone {
        /// Source environment name
        source: String,
        /// New environment name
        target: String,
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
            // Always requires unlock — manifests are encrypted
            let ctx = unlock_vault(identity, vault, None)?;
            let manifest = ctx.manifest;

            if json {
                crate::output::print_json(&manifest.environments)?;
            } else {
                println!("{} (vault: {})", style("Environments").bold(), vault_name);
                for env in &manifest.environments {
                    let env_path = paths.env_path(&vault_name, env);
                    let status = if env_path.exists() { "active" } else { "empty" };
                    println!("  {} ({})", style(env).cyan(), style(status).dim());
                }
            }
        }
        EnvCommands::Create { name } => {
            sigyn_engine::secrets::validation::validate_env_name(&name)?;

            let ctx = unlock_vault(identity, vault, None)?;
            check_access(&ctx, AccessAction::CreateEnv, None)?;

            let manifest_path = paths.manifest_path(&vault_name);
            let mut manifest = ctx.manifest.clone();

            if manifest.environments.contains(&name) {
                anyhow::bail!("environment '{}' already exists", name);
            }

            manifest.environments.push(name.clone());
            let sealed = manifest
                .to_sealed_bytes(&ctx.vault_cipher)
                .map_err(|e| anyhow::anyhow!("failed to seal manifest: {}", e))?;
            crate::config::secure_write(&manifest_path, &sealed)?;

            // For v2 vaults, generate a new env key and add slots
            if ctx.is_v2 {
                use sigyn_engine::crypto::envelope;
                use sigyn_engine::identity::keygen::IdentityStore;

                let mut header = ctx.header.clone();

                // Determine who gets access: members with "*" in allowed_envs, plus the creator
                let home_for_ids = crate::config::sigyn_home();
                let id_store = IdentityStore::new(home_for_ids);
                let identities = id_store
                    .list()
                    .map_err(|e| anyhow::anyhow!("failed to list identities: {}", e))?;

                let mut recipients = vec![ctx.loaded_identity.identity.encryption_pubkey.clone()];
                for mp in ctx.policy.members.values() {
                    if mp.allowed_envs.iter().any(|e| e == "*") {
                        if let Some(id) = identities
                            .iter()
                            .find(|id| id.fingerprint == mp.fingerprint)
                        {
                            if !recipients
                                .iter()
                                .any(|r| r.fingerprint() == id.encryption_pubkey.fingerprint())
                            {
                                recipients.push(id.encryption_pubkey.clone());
                            }
                        }
                    }
                }

                let new_env_key = envelope::rotate_env_key(
                    &mut header,
                    &name,
                    &recipients,
                    ctx.manifest.vault_id,
                )
                .map_err(|e| anyhow::anyhow!("failed to create env key: {}", e))?;

                // Save updated header
                let signed = envelope::sign_header(
                    &header,
                    ctx.loaded_identity.signing_key(),
                    ctx.manifest.vault_id,
                )
                .map_err(|e| anyhow::anyhow!("failed to sign header: {}", e))?;
                crate::config::secure_write(&paths.members_path(&vault_name), &signed)?;

                // Write empty env file with new key
                let empty_env = sigyn_engine::vault::PlaintextEnv::new();
                let new_cipher = sigyn_engine::crypto::vault_cipher::VaultCipher::new(new_env_key);
                let encrypted =
                    sigyn_engine::vault::env_file::encrypt_env(&empty_env, &new_cipher, &name)?;
                sigyn_engine::vault::env_file::write_encrypted_env(
                    &paths.env_path(&vault_name, &name),
                    &encrypted,
                )?;
            }

            // Audit log
            let audit_path = ctx.paths.audit_path(&ctx.vault_name);
            let audit_cipher = sigyn_engine::crypto::sealed::derive_file_cipher_with_salt(
                ctx.vault_cipher.key_bytes(),
                b"sigyn-audit-v1",
                &ctx.manifest.vault_id,
            );
            if let Ok(ac) = audit_cipher {
                if let Ok(mut log) = AuditLog::open(&audit_path, ac) {
                    let _ = log.append(
                        &ctx.fingerprint,
                        AuditAction::EnvironmentCreated { name: name.clone() },
                        None,
                        AuditOutcome::Success,
                        ctx.loaded_identity.signing_key(),
                    );
                }
            }

            crate::output::print_success(&format!(
                "Created environment '{}' in vault '{}'",
                name, vault_name
            ));
        }
        EnvCommands::Diff { from, to, reveal } => {
            let ctx = unlock_vault(identity, vault, Some(&from))?;
            check_access(&ctx, AccessAction::Read, None)?;

            let from_path = paths.env_path(&vault_name, &from);
            let to_path = paths.env_path(&vault_name, &to);

            let from_cipher = ctx
                .cipher_for_env(&from)
                .ok_or_else(|| anyhow::anyhow!("no access to env '{}'", from))?;
            let to_cipher = ctx
                .cipher_for_env(&to)
                .ok_or_else(|| anyhow::anyhow!("no access to env '{}'", to))?;

            let from_env = if from_path.exists() {
                let enc = env_file::read_encrypted_env(&from_path)?;
                env_file::decrypt_env(&enc, from_cipher)?
            } else {
                PlaintextEnv::new()
            };
            let to_env = if to_path.exists() {
                let enc = env_file::read_encrypted_env(&to_path)?;
                env_file::decrypt_env(&enc, to_cipher)?
            } else {
                PlaintextEnv::new()
            };

            let from_keys: std::collections::HashSet<&str> =
                from_env.entries.keys().map(|k| k.as_str()).collect();
            let to_keys: std::collections::HashSet<&str> =
                to_env.entries.keys().map(|k| k.as_str()).collect();

            let only_from: Vec<&str> = from_keys.difference(&to_keys).copied().collect();
            let only_to: Vec<&str> = to_keys.difference(&from_keys).copied().collect();
            let both: Vec<&str> = from_keys.intersection(&to_keys).copied().collect();

            let mut changed = Vec::new();
            for key in &both {
                let fv = from_env.get(key).unwrap().value.display_value(true);
                let tv = to_env.get(key).unwrap().value.display_value(true);
                if fv != tv {
                    changed.push(*key);
                }
            }

            if json {
                crate::output::print_json(&serde_json::json!({
                    "from": from,
                    "to": to,
                    "only_in_from": only_from,
                    "only_in_to": only_to,
                    "changed": changed,
                }))?;
            } else {
                println!(
                    "{} {} vs {}",
                    style("Env diff").bold(),
                    style(&from).cyan(),
                    style(&to).cyan()
                );
                println!("{}", style("─".repeat(60)).dim());

                if only_from.is_empty() && only_to.is_empty() && changed.is_empty() {
                    println!("  Environments are identical.");
                }

                for key in &only_from {
                    let val = if reveal {
                        from_env.get(key).unwrap().value.display_value(true)
                    } else {
                        "(removed)".into()
                    };
                    println!(
                        "  {} {} {}",
                        style("-").red(),
                        style(key).red(),
                        style(val).dim()
                    );
                }
                for key in &only_to {
                    let val = if reveal {
                        to_env.get(key).unwrap().value.display_value(true)
                    } else {
                        "(added)".into()
                    };
                    println!(
                        "  {} {} {}",
                        style("+").green(),
                        style(key).green(),
                        style(val).dim()
                    );
                }
                for key in &changed {
                    if reveal {
                        let fv = from_env.get(key).unwrap().value.display_value(true);
                        let tv = to_env.get(key).unwrap().value.display_value(true);
                        println!(
                            "  {} {} {} → {}",
                            style("~").yellow(),
                            style(key).yellow(),
                            style(fv).dim(),
                            style(tv).dim()
                        );
                    } else {
                        println!(
                            "  {} {} {}",
                            style("~").yellow(),
                            style(key).yellow(),
                            style("(changed)").dim()
                        );
                    }
                }

                println!();
                let total = only_from.len() + only_to.len() + changed.len();
                println!(
                    "  {} difference(s): {} added, {} removed, {} changed",
                    total,
                    only_to.len(),
                    only_from.len(),
                    changed.len()
                );
            }
        }
        EnvCommands::Clone { source, target } => {
            sigyn_engine::secrets::validation::validate_env_name(&target)?;

            let ctx = unlock_vault(identity, vault, Some(&source))?;
            check_access(&ctx, AccessAction::CreateEnv, None)?;

            // Verify source exists
            let source_path = paths.env_path(&vault_name, &source);
            if !source_path.exists() {
                anyhow::bail!("source environment '{}' has no secrets", source);
            }

            // Verify target does not exist
            let manifest_path = paths.manifest_path(&vault_name);
            let mut manifest = ctx.manifest.clone();

            if manifest.environments.contains(&target) {
                anyhow::bail!("target environment '{}' already exists", target);
            }

            // Decrypt source and re-encrypt as target
            let source_cipher = ctx
                .cipher_for_env(&source)
                .ok_or_else(|| anyhow::anyhow!("no access to env '{}'", source))?;
            let source_encrypted = env_file::read_encrypted_env(&source_path)?;
            let source_env = env_file::decrypt_env(&source_encrypted, source_cipher)?;
            let count = source_env.len();

            // For v2, generate a new env key for the target env
            let target_cipher;
            let target_cipher_ref;
            if ctx.is_v2 {
                use sigyn_engine::crypto::envelope;
                use sigyn_engine::identity::keygen::IdentityStore;

                let mut header = ctx.header.clone();

                // Mirror source env's recipients for the new env
                let home_for_ids = crate::config::sigyn_home();
                let id_store = IdentityStore::new(home_for_ids);
                let identities = id_store
                    .list()
                    .map_err(|e| anyhow::anyhow!("failed to list identities: {}", e))?;

                let mut recipients = vec![ctx.loaded_identity.identity.encryption_pubkey.clone()];
                // Find members who have access to source env
                for mp in ctx.policy.members.values() {
                    let has_source = mp.allowed_envs.iter().any(|e| e == "*" || e == &source);
                    if has_source {
                        if let Some(id) = identities
                            .iter()
                            .find(|id| id.fingerprint == mp.fingerprint)
                        {
                            if !recipients
                                .iter()
                                .any(|r| r.fingerprint() == id.encryption_pubkey.fingerprint())
                            {
                                recipients.push(id.encryption_pubkey.clone());
                            }
                        }
                    }
                }

                let new_env_key = envelope::rotate_env_key(
                    &mut header,
                    &target,
                    &recipients,
                    ctx.manifest.vault_id,
                )
                .map_err(|e| anyhow::anyhow!("failed to create env key: {}", e))?;

                let signed = envelope::sign_header(
                    &header,
                    ctx.loaded_identity.signing_key(),
                    ctx.manifest.vault_id,
                )
                .map_err(|e| anyhow::anyhow!("failed to sign header: {}", e))?;
                crate::config::secure_write(&paths.members_path(&vault_name), &signed)?;

                target_cipher = sigyn_engine::crypto::vault_cipher::VaultCipher::new(new_env_key);
                target_cipher_ref = &target_cipher;
            } else {
                target_cipher = sigyn_engine::crypto::vault_cipher::VaultCipher::new(
                    *source_cipher.key_bytes(),
                );
                target_cipher_ref = &target_cipher;
            }
            let target_encrypted = env_file::encrypt_env(&source_env, target_cipher_ref, &target)?;
            let target_path = paths.env_path(&vault_name, &target);
            env_file::write_encrypted_env(&target_path, &target_encrypted)?;

            // Add target env to manifest
            manifest.environments.push(target.clone());
            let sealed = manifest
                .to_sealed_bytes(&ctx.vault_cipher)
                .map_err(|e| anyhow::anyhow!("failed to seal manifest: {}", e))?;
            crate::config::secure_write(&manifest_path, &sealed)?;

            // Audit
            let audit_path = ctx.paths.audit_path(&ctx.vault_name);
            let audit_cipher = sigyn_engine::crypto::sealed::derive_file_cipher_with_salt(
                ctx.vault_cipher.key_bytes(),
                b"sigyn-audit-v1",
                &ctx.manifest.vault_id,
            );
            if let Ok(ac) = audit_cipher {
                if let Ok(mut log) = AuditLog::open(&audit_path, ac) {
                    let _ = log.append(
                        &ctx.fingerprint,
                        AuditAction::EnvironmentCreated {
                            name: target.clone(),
                        },
                        None,
                        AuditOutcome::Success,
                        ctx.loaded_identity.signing_key(),
                    );
                }
            }

            if json {
                crate::output::print_json(&serde_json::json!({
                    "action": "cloned",
                    "source": source,
                    "target": target,
                    "secrets_count": count,
                }))?;
            } else {
                crate::output::print_success(&format!(
                    "Cloned '{}' → '{}' ({} secrets)",
                    source, target, count
                ));
            }
        }
        EnvCommands::Promote { from, to, keys } => {
            // Unlock the vault (use source env for policy context)
            let ctx = unlock_vault(identity, vault, Some(&from))?;
            check_access(&ctx, AccessAction::Promote, None)?;

            // Read source environment
            let source_cipher = ctx
                .cipher_for_env(&from)
                .ok_or_else(|| anyhow::anyhow!("no access to env '{}'", from))?;
            let source_path = paths.env_path(&vault_name, &from);
            if !source_path.exists() {
                anyhow::bail!("source environment '{}' has no secrets", from);
            }
            let source_encrypted = env_file::read_encrypted_env(&source_path)?;
            let source_env = env_file::decrypt_env(&source_encrypted, source_cipher)?;

            // Read target environment (or create empty)
            let target_cipher = ctx
                .cipher_for_env(&to)
                .ok_or_else(|| anyhow::anyhow!("no access to env '{}'", to))?;
            let target_path = paths.env_path(&vault_name, &to);
            let mut target_env = if target_path.exists() {
                let target_encrypted = env_file::read_encrypted_env(&target_path)?;
                env_file::decrypt_env(&target_encrypted, target_cipher)?
            } else {
                PlaintextEnv::new()
            };

            // Perform promotion
            let filter = keys.as_deref();
            let result = promote_env(&source_env, &mut target_env, &ctx.fingerprint, filter);

            // Write target env back encrypted
            let encrypted = env_file::encrypt_env(&target_env, target_cipher, &to)?;
            env_file::write_encrypted_env(&target_path, &encrypted)?;

            // Audit log
            let audit_path = ctx.paths.audit_path(&ctx.vault_name);
            let audit_cipher = sigyn_engine::crypto::sealed::derive_file_cipher_with_salt(
                ctx.vault_cipher.key_bytes(),
                b"sigyn-audit-v1",
                &ctx.manifest.vault_id,
            );
            if let Ok(ac) = audit_cipher {
                if let Ok(mut log) = AuditLog::open(&audit_path, ac) {
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

            // Auto-sync after promote
            if crate::config::load_config().auto_sync {
                eprintln!("{} auto-syncing...", style("note:").cyan().bold());
                if let Err(e) = crate::commands::sync::auto_push(&vault_name) {
                    eprintln!(
                        "{} auto-sync failed: {}",
                        style("warning:").yellow().bold(),
                        e
                    );
                }
            }
        }
    }
    Ok(())
}
