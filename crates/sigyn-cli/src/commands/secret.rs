use anyhow::{Context, Result};
use clap::Subcommand;
use console::style;
use sigyn_core::audit::entry::AuditOutcome;
use sigyn_core::audit::{AuditAction, AuditLog};
use sigyn_core::crypto::{envelope, vault_cipher::VaultCipher};
use sigyn_core::identity::keygen::IdentityStore;
use sigyn_core::identity::LoadedIdentity;
use sigyn_core::policy::engine::AccessAction;
use sigyn_core::policy::storage::VaultPolicy;
use sigyn_core::policy::{AccessRequest, PolicyDecision, PolicyEngine};
use sigyn_core::secrets::types::SecretValue;
use sigyn_core::vault::{env_file, VaultManifest, VaultPaths};

use crate::commands::identity::load_identity;
use crate::config::sigyn_home;

#[derive(Subcommand)]
pub enum SecretCommands {
    /// Set a secret value
    Set {
        /// Secret key name
        key: String,
        /// Secret value (omit to read from stdin)
        value: Option<String>,
        /// Environment
        #[arg(long, short)]
        env: Option<String>,
    },
    /// Get a secret value
    Get {
        /// Secret key name
        key: String,
        /// Environment
        #[arg(long, short)]
        env: Option<String>,
    },
    /// List all secrets in an environment
    List {
        /// Environment
        #[arg(long, short)]
        env: Option<String>,
        /// Show values (default: hidden)
        #[arg(long, short)]
        reveal: bool,
    },
    /// Remove a secret
    #[command(alias = "rm")]
    Remove {
        /// Secret key name
        key: String,
        /// Environment
        #[arg(long, short)]
        env: Option<String>,
    },
    /// Generate a random secret
    Generate {
        /// Secret key name
        key: String,
        /// Length of generated value
        #[arg(long, short, default_value = "32")]
        length: usize,
        /// Generation type: password, uuid, hex, base64, alphanumeric
        #[arg(long, short, default_value = "password")]
        r#type: String,
        /// Environment
        #[arg(long, short)]
        env: Option<String>,
    },
}

pub struct UnlockedVaultContext {
    pub cipher: VaultCipher,
    pub vault_name: String,
    pub env_name: String,
    pub fingerprint: sigyn_core::crypto::KeyFingerprint,
    pub paths: VaultPaths,
    pub manifest: VaultManifest,
    pub policy: VaultPolicy,
    pub loaded_identity: LoadedIdentity,
}

pub fn unlock_vault(
    identity_name: Option<&str>,
    vault_name: Option<&str>,
    env_name: Option<&str>,
) -> Result<UnlockedVaultContext> {
    let home = sigyn_home();
    let store = IdentityStore::new(home.clone());
    let paths = VaultPaths::new(home);
    let config = crate::config::load_config();
    let project = crate::project_config::load_project_config();
    let project_settings = project.as_ref().and_then(|p| p.project.as_ref());

    // Priority: CLI flags > project config > global config > defaults
    if vault_name.is_none() {
        if let Some(pv) = project_settings.and_then(|p| p.vault.as_deref()) {
            eprintln!(
                "{} using vault '{}' from .sigyn.toml",
                style("note:").cyan().bold(),
                pv
            );
        }
    }
    let vault_name = vault_name
        .map(String::from)
        .or_else(|| project_settings.and_then(|p| p.vault.clone()))
        .or(config.default_vault)
        .ok_or_else(|| anyhow::anyhow!("no vault specified; use --vault or set default"))?;

    if env_name.is_none() {
        if let Some(pe) = project_settings.and_then(|p| p.env.as_deref()) {
            eprintln!(
                "{} using env '{}' from .sigyn.toml",
                style("note:").cyan().bold(),
                pe
            );
        }
    }
    let env_name = env_name
        .map(String::from)
        .or_else(|| project_settings.and_then(|p| p.env.clone()))
        .or(config.default_env)
        .unwrap_or_else(|| "dev".into());

    let identity_from_project = project_settings.and_then(|p| p.identity.clone());
    if identity_name.is_none() {
        if let Some(ref pi) = identity_from_project {
            eprintln!(
                "{} using identity '{}' from .sigyn.toml",
                style("note:").cyan().bold(),
                pi
            );
        }
    }
    let effective_identity = identity_name.or(identity_from_project.as_deref());
    let loaded = load_identity(&store, effective_identity)?;
    let fingerprint = loaded.identity.fingerprint.clone();

    let manifest_content = std::fs::read_to_string(paths.manifest_path(&vault_name))
        .context(format!("vault '{}' not found", vault_name))?;
    let manifest = VaultManifest::from_toml(&manifest_content)?;

    let header_bytes =
        std::fs::read(paths.members_path(&vault_name)).context("failed to read vault members")?;
    let header: sigyn_core::crypto::EnvelopeHeader = ciborium::from_reader(header_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("failed to decode header: {}", e))?;

    let master_key =
        envelope::unseal_master_key(&header, loaded.encryption_key(), manifest.vault_id)
            .context("failed to unseal vault (not a member or wrong key)")?;

    let cipher = VaultCipher::new(master_key);

    // Load policy (returns empty policy if file doesn't exist)
    let policy =
        VaultPolicy::load_encrypted(&paths.policy_path(&vault_name), &cipher).unwrap_or_default();

    Ok(UnlockedVaultContext {
        cipher,
        vault_name,
        env_name,
        fingerprint,
        paths,
        manifest,
        policy,
        loaded_identity: loaded,
    })
}

/// Check policy and bail on deny
pub fn check_access(
    ctx: &UnlockedVaultContext,
    action: AccessAction,
    key: Option<&str>,
) -> Result<()> {
    let engine = PolicyEngine::new(&ctx.policy, &ctx.manifest.owner);
    let request = AccessRequest {
        actor: ctx.fingerprint.clone(),
        action,
        env: ctx.env_name.clone(),
        key: key.map(String::from),
        ip: None,
        mfa_verified: false,
    };
    match engine.evaluate(&request)? {
        PolicyDecision::Allow => Ok(()),
        PolicyDecision::AllowWithWarning(msg) => {
            eprintln!("{} {}", style("WARNING").yellow().bold(), msg);
            Ok(())
        }
        PolicyDecision::Deny(reason) => {
            anyhow::bail!("access denied: {}", reason);
        }
        PolicyDecision::RequiresMfa => {
            crate::commands::mfa::prompt_and_verify_mfa(&ctx.fingerprint, &ctx.loaded_identity)?;
            // Re-evaluate with mfa_verified: true
            let verified_request = AccessRequest {
                actor: ctx.fingerprint.clone(),
                action: request.action.clone(),
                env: ctx.env_name.clone(),
                key: key.map(String::from),
                ip: None,
                mfa_verified: true,
            };
            match engine.evaluate(&verified_request)? {
                PolicyDecision::Allow => Ok(()),
                PolicyDecision::AllowWithWarning(msg) => {
                    eprintln!("{} {}", style("WARNING").yellow().bold(), msg);
                    Ok(())
                }
                PolicyDecision::Deny(reason) => {
                    anyhow::bail!("access denied: {}", reason);
                }
                PolicyDecision::RequiresMfa => {
                    unreachable!("MFA was just verified")
                }
            }
        }
    }
}

/// Append an audit entry (best-effort — warn on stderr but don't fail the operation)
fn audit(ctx: &UnlockedVaultContext, action: AuditAction, outcome: AuditOutcome) {
    let audit_path = ctx.paths.audit_path(&ctx.vault_name);
    match AuditLog::open(&audit_path) {
        Ok(mut log) => {
            if let Err(e) = log.append(
                &ctx.fingerprint,
                action,
                Some(ctx.env_name.clone()),
                outcome,
                ctx.loaded_identity.signing_key(),
            ) {
                eprintln!(
                    "{} failed to write audit entry: {}",
                    style("warning:").yellow().bold(),
                    e
                );
            }
        }
        Err(e) => {
            eprintln!(
                "{} failed to open audit log: {}",
                style("warning:").yellow().bold(),
                e
            );
        }
    }
}

pub fn handle(
    cmd: SecretCommands,
    vault: Option<&str>,
    identity: Option<&str>,
    json: bool,
) -> Result<()> {
    match cmd {
        SecretCommands::Set { key, value, env } => {
            sigyn_core::secrets::validate_key_name(&key)?;

            let ctx = unlock_vault(identity, vault, env.as_deref())?;
            check_access(&ctx, AccessAction::Write, Some(&key))?;

            let value = match value {
                Some(v) => v,
                None => {
                    use std::io::Read;
                    let mut buf = String::new();
                    std::io::stdin().read_to_string(&mut buf)?;
                    buf.trim_end().to_string()
                }
            };

            let env_path = ctx.paths.env_path(&ctx.vault_name, &ctx.env_name);
            let mut plaintext = if env_path.exists() {
                let encrypted = env_file::read_encrypted_env(&env_path)?;
                env_file::decrypt_env(&encrypted, &ctx.cipher)?
            } else {
                sigyn_core::vault::PlaintextEnv::new()
            };

            let is_update = plaintext.get(&key).is_some();
            plaintext.set(key.clone(), SecretValue::String(value), &ctx.fingerprint);

            let encrypted = env_file::encrypt_env(&plaintext, &ctx.cipher, &ctx.env_name)?;
            env_file::write_encrypted_env(&env_path, &encrypted)?;

            audit(
                &ctx,
                AuditAction::SecretWritten { key: key.clone() },
                AuditOutcome::Success,
            );

            if json {
                crate::output::print_json(&serde_json::json!({
                    "key": key,
                    "env": ctx.env_name,
                    "action": if is_update { "updated" } else { "created" }
                }))?;
            } else {
                let action = if is_update { "Updated" } else { "Set" };
                crate::output::print_success(&format!(
                    "{} '{}' in env '{}'",
                    action, key, ctx.env_name
                ));
            }
        }
        SecretCommands::Get { key, env } => {
            let ctx = unlock_vault(identity, vault, env.as_deref())?;
            check_access(&ctx, AccessAction::Read, Some(&key))?;

            let env_path = ctx.paths.env_path(&ctx.vault_name, &ctx.env_name);
            if !env_path.exists() {
                anyhow::bail!("environment '{}' has no secrets yet", ctx.env_name);
            }

            let encrypted = env_file::read_encrypted_env(&env_path)?;
            let plaintext = env_file::decrypt_env(&encrypted, &ctx.cipher)?;

            let entry = plaintext.get(&key).ok_or_else(|| {
                anyhow::anyhow!("secret '{}' not found in env '{}'", key, ctx.env_name)
            })?;

            audit(
                &ctx,
                AuditAction::SecretRead { key: key.clone() },
                AuditOutcome::Success,
            );

            if json {
                crate::output::print_json(&serde_json::json!({
                    "key": key,
                    "value": entry.value.display_value(true),
                    "type": entry.value.type_name(),
                    "env": ctx.env_name,
                    "version": entry.metadata.version,
                }))?;
            } else {
                println!("{}", entry.value.display_value(true));
            }
        }
        SecretCommands::List { env, reveal } => {
            let ctx = unlock_vault(identity, vault, env.as_deref())?;
            check_access(&ctx, AccessAction::Read, None)?;

            let env_path = ctx.paths.env_path(&ctx.vault_name, &ctx.env_name);
            if !env_path.exists() {
                println!(
                    "No secrets in env '{}'. Add one with: sigyn secret set <KEY> <VALUE> --env {}",
                    ctx.env_name, ctx.env_name
                );
                return Ok(());
            }

            let encrypted = env_file::read_encrypted_env(&env_path)?;
            let plaintext = env_file::decrypt_env(&encrypted, &ctx.cipher)?;

            if plaintext.is_empty() {
                println!("No secrets in env '{}'", ctx.env_name);
                return Ok(());
            }

            if json {
                let entries: Vec<_> = plaintext
                    .entries
                    .iter()
                    .map(|(k, e)| {
                        serde_json::json!({
                            "key": k,
                            "type": e.value.type_name(),
                            "value": e.value.display_value(reveal),
                            "version": e.metadata.version,
                        })
                    })
                    .collect();
                crate::output::print_json(&entries)?;
            } else {
                println!(
                    "{} {} (env: {})",
                    style("Secrets").bold(),
                    style(format!("({} keys)", plaintext.len())).dim(),
                    style(&ctx.env_name).cyan()
                );
                println!("{}", style("─".repeat(60)).dim());
                for (key, entry) in &plaintext.entries {
                    let val = entry.value.display_value(reveal);
                    let type_tag = style(format!("[{}]", entry.value.type_name())).dim();
                    println!("  {} {} = {}", type_tag, style(key).bold(), val);
                }
            }
        }
        SecretCommands::Remove { key, env } => {
            let ctx = unlock_vault(identity, vault, env.as_deref())?;
            check_access(&ctx, AccessAction::Delete, Some(&key))?;

            let env_path = ctx.paths.env_path(&ctx.vault_name, &ctx.env_name);
            if !env_path.exists() {
                anyhow::bail!("environment '{}' has no secrets", ctx.env_name);
            }

            let encrypted = env_file::read_encrypted_env(&env_path)?;
            let mut plaintext = env_file::decrypt_env(&encrypted, &ctx.cipher)?;

            if plaintext.remove(&key).is_none() {
                anyhow::bail!("secret '{}' not found in env '{}'", key, ctx.env_name);
            }

            let encrypted = env_file::encrypt_env(&plaintext, &ctx.cipher, &ctx.env_name)?;
            env_file::write_encrypted_env(&env_path, &encrypted)?;

            audit(
                &ctx,
                AuditAction::SecretDeleted { key: key.clone() },
                AuditOutcome::Success,
            );

            crate::output::print_success(&format!("Removed '{}' from env '{}'", key, ctx.env_name));
        }
        SecretCommands::Generate {
            key,
            length,
            r#type,
            env,
        } => {
            sigyn_core::secrets::validate_key_name(&key)?;

            let template = match r#type.as_str() {
                "password" => sigyn_core::secrets::GenerationTemplate::Password {
                    length,
                    charset: sigyn_core::secrets::generation::PasswordCharset::default(),
                },
                "uuid" => sigyn_core::secrets::GenerationTemplate::Uuid,
                "hex" => sigyn_core::secrets::GenerationTemplate::Hex { length },
                "base64" => sigyn_core::secrets::GenerationTemplate::Base64 { length },
                "alphanumeric" => sigyn_core::secrets::GenerationTemplate::Alphanumeric { length },
                other => anyhow::bail!(
                    "unknown generation type: '{}'. Use: password, uuid, hex, base64, alphanumeric",
                    other
                ),
            };

            let generated = template.generate();
            let ctx = unlock_vault(identity, vault, env.as_deref())?;
            check_access(&ctx, AccessAction::Write, Some(&key))?;

            let env_path = ctx.paths.env_path(&ctx.vault_name, &ctx.env_name);
            let mut plaintext = if env_path.exists() {
                let encrypted = env_file::read_encrypted_env(&env_path)?;
                env_file::decrypt_env(&encrypted, &ctx.cipher)?
            } else {
                sigyn_core::vault::PlaintextEnv::new()
            };

            plaintext.set(
                key.clone(),
                SecretValue::Generated(generated.clone()),
                &ctx.fingerprint,
            );

            let encrypted = env_file::encrypt_env(&plaintext, &ctx.cipher, &ctx.env_name)?;
            env_file::write_encrypted_env(&env_path, &encrypted)?;

            audit(
                &ctx,
                AuditAction::SecretWritten { key: key.clone() },
                AuditOutcome::Success,
            );

            if json {
                crate::output::print_json(&serde_json::json!({
                    "key": key,
                    "value": generated,
                    "env": ctx.env_name,
                }))?;
            } else {
                crate::output::print_success(&format!(
                    "Generated '{}' in env '{}'",
                    key, ctx.env_name
                ));
                println!("  Value: {}", generated);
            }
        }
    }
    Ok(())
}
