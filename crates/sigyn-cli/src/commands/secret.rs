use anyhow::{Context, Result};
use clap::Subcommand;
use console::style;
use sigyn_engine::audit::entry::AuditOutcome;
use sigyn_engine::audit::{AuditAction, AuditLog};
use sigyn_engine::crypto::{envelope, vault_cipher::VaultCipher};
use sigyn_engine::identity::keygen::IdentityStore;
use sigyn_engine::identity::LoadedIdentity;
use sigyn_engine::policy::engine::AccessAction;
use sigyn_engine::policy::storage::VaultPolicy;
use sigyn_engine::policy::storage::VaultPolicyExt;
use sigyn_engine::policy::{AccessRequest, PolicyDecision, PolicyEngine};
use sigyn_engine::secrets::types::SecretValue;
use sigyn_engine::vault::{env_file, VaultManifest, VaultPaths};

use crate::commands::identity::load_identity;
use crate::config::sigyn_home;

/// Simple glob matching supporting * and ? wildcards.
fn glob_match(pattern: &str, text: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let (mut star_pi, mut star_ti) = (usize::MAX, 0);

    while ti < txt.len() {
        if pi < pat.len() && (pat[pi] == '?' || pat[pi] == txt[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pat.len() && pat[pi] == '*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < pat.len() && pat[pi] == '*' {
        pi += 1;
    }
    pi == pat.len()
}

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
    /// Edit secrets in $EDITOR (batch editing)
    Edit {
        /// Environment
        #[arg(long, short)]
        env: Option<String>,
    },
    /// Search for secrets across all environments
    Search {
        /// Key pattern (glob: * and ? wildcards)
        pattern: String,
        /// Show actual values
        #[arg(long, short)]
        reveal: bool,
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
    pub fingerprint: sigyn_engine::crypto::KeyFingerprint,
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

    // Verbose config resolution logging
    if std::env::var("SIGYN_VERBOSE").is_ok() {
        eprintln!(
            "[verbose] vault: flag={:?} project={:?} global={:?}",
            vault_name,
            project_settings.and_then(|p| p.vault.as_deref()),
            config.default_vault.as_deref()
        );
    }
    let vault_name = vault_name
        .map(String::from)
        .or_else(|| project_settings.and_then(|p| p.vault.clone()))
        .or(config.default_vault)
        .ok_or_else(|| {
            let available = paths.list_vaults().unwrap_or_default();
            if available.is_empty() {
                anyhow::anyhow!(
                    "no vault specified and no vaults found\n\n  \
                     Get started:\n    \
                     sigyn identity create -n alice\n    \
                     sigyn vault create myapp\n    \
                     sigyn project init"
                )
            } else {
                anyhow::anyhow!(
                    "no vault specified\n\n  \
                     Available vaults: {}\n  \
                     Use --vault <name>, or set up a project config:\n    \
                     sigyn project init",
                    available.join(", ")
                )
            }
        })?;

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
    let header: sigyn_engine::crypto::EnvelopeHeader =
        ciborium::from_reader(header_bytes.as_slice())
            .map_err(|e| anyhow::anyhow!("failed to decode header: {}", e))?;

    let master_key =
        envelope::unseal_master_key(&header, loaded.encryption_key(), manifest.vault_id).context(
            format!(
                "failed to unseal vault '{}' (not a member or wrong key)\n\n  \
                 Check your membership: sigyn delegation tree -v {}\n  \
                 Or ask the vault owner to re-invite you.",
                vault_name, vault_name
            ),
        )?;

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

/// Check policy and bail on deny.
///
/// If the vault is linked to an org hierarchy (`manifest.org_path` is set),
/// this loads the policy chain from vault up to root org and evaluates with
/// hierarchical highest-role-wins merging. Otherwise falls back to the
/// standard single-vault policy engine.
pub fn check_access(
    ctx: &UnlockedVaultContext,
    action: AccessAction,
    key: Option<&str>,
) -> Result<()> {
    let request = AccessRequest {
        actor: ctx.fingerprint.clone(),
        action,
        env: ctx.env_name.clone(),
        key: key.map(String::from),
        mfa_verified: false,
    };

    let decision = if let Some(ref org_path_str) = ctx.manifest.org_path {
        // Hierarchical evaluation: build policy chain from vault → root org
        let home = crate::config::sigyn_home();
        let hierarchy_paths = sigyn_engine::hierarchy::path::HierarchyPaths::new(home);

        if let Ok(org_path) = sigyn_engine::hierarchy::path::OrgPath::parse(org_path_str) {
            let mut chain = Vec::new();

            // First level: vault's own policy
            chain.push(sigyn_engine::hierarchy::engine::PolicyLevel {
                owner: ctx.manifest.owner.clone(),
                policy: ctx.policy.clone(),
            });

            // Then walk up from the org node to root, collecting policies
            let mut paths_to_check = vec![org_path.clone()];
            paths_to_check.extend(org_path.ancestors().into_iter().rev());

            for cp in &paths_to_check {
                let mp = hierarchy_paths.manifest_path(cp);
                if !mp.exists() {
                    continue;
                }
                if let Ok(content) = std::fs::read_to_string(&mp) {
                    if let Ok(manifest) =
                        sigyn_engine::hierarchy::manifest::NodeManifest::from_toml(&content)
                    {
                        let members_p = hierarchy_paths.members_path(cp);
                        if members_p.exists() {
                            if let Ok(hdr_bytes) = std::fs::read(&members_p) {
                                if let Ok(header) = ciborium::from_reader::<
                                    sigyn_engine::crypto::EnvelopeHeader,
                                    _,
                                >(
                                    hdr_bytes.as_slice()
                                ) {
                                    if let Ok(mk) = envelope::unseal_master_key(
                                        &header,
                                        ctx.loaded_identity.encryption_key(),
                                        manifest.node_id,
                                    ) {
                                        let cipher =
                                            sigyn_engine::crypto::vault_cipher::VaultCipher::new(
                                                mk,
                                            );
                                        if let Ok(policy) = VaultPolicy::load_encrypted(
                                            &hierarchy_paths.policy_path(cp),
                                            &cipher,
                                        ) {
                                            chain.push(
                                                sigyn_engine::hierarchy::engine::PolicyLevel {
                                                    owner: manifest.owner.clone(),
                                                    policy,
                                                },
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            sigyn_engine::hierarchy::engine::HierarchicalPolicyEngine::evaluate(&chain, &request)?
        } else {
            // Invalid org path, fall back to standard evaluation
            let engine = PolicyEngine::new(&ctx.policy, &ctx.manifest.owner);
            engine.evaluate(&request)?
        }
    } else {
        // Standard single-vault evaluation
        let engine = PolicyEngine::new(&ctx.policy, &ctx.manifest.owner);
        engine.evaluate(&request)?
    };

    match decision {
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
                mfa_verified: true,
            };
            // For MFA re-evaluation, use the same approach
            let re_decision = if ctx.manifest.org_path.is_some() {
                // Simplified: just use standard engine for MFA re-eval since the chain
                // was already validated above. The MFA check is the only thing that changes.
                let engine = PolicyEngine::new(&ctx.policy, &ctx.manifest.owner);
                engine.evaluate(&verified_request)?
            } else {
                let engine = PolicyEngine::new(&ctx.policy, &ctx.manifest.owner);
                engine.evaluate(&verified_request)?
            };
            match re_decision {
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

/// Trigger auto-sync if enabled in config (best-effort).
fn maybe_auto_sync(vault_name: &str) {
    if crate::config::load_config().auto_sync {
        eprintln!("{} auto-syncing...", console::style("note:").cyan().bold());
        if let Err(e) = crate::commands::sync::auto_push(vault_name) {
            eprintln!(
                "{} auto-sync failed: {}",
                console::style("warning:").yellow().bold(),
                e
            );
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
    dry_run: bool,
) -> Result<()> {
    match cmd {
        SecretCommands::Set { key, value, env } => {
            sigyn_engine::secrets::validate_key_name(&key)?;

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
            let existing = if env_path.exists() {
                let encrypted = env_file::read_encrypted_env(&env_path)?;
                env_file::decrypt_env(&encrypted, &ctx.cipher)?
            } else {
                sigyn_engine::vault::PlaintextEnv::new()
            };

            let is_update = existing.get(&key).is_some();

            if dry_run {
                let action = if is_update { "update" } else { "create" };
                println!(
                    "[dry-run] Would {} '{}' in env '{}'",
                    action, key, ctx.env_name
                );
                return Ok(());
            }

            let mut plaintext = existing;
            plaintext.set(key.clone(), SecretValue::String(value), &ctx.fingerprint);

            let encrypted = env_file::encrypt_env(&plaintext, &ctx.cipher, &ctx.env_name)?;
            env_file::write_encrypted_env(&env_path, &encrypted)?;

            audit(
                &ctx,
                AuditAction::SecretWritten { key: key.clone() },
                AuditOutcome::Success,
            );

            crate::notifications::try_notify(
                &ctx.vault_name,
                Some(&ctx.env_name),
                Some(&key),
                &ctx.fingerprint.to_hex(),
                if is_update {
                    "secret.updated"
                } else {
                    "secret.created"
                },
                &format!(
                    "Secret '{}' {} in env '{}'",
                    key,
                    if is_update { "updated" } else { "created" },
                    ctx.env_name
                ),
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

            maybe_auto_sync(&ctx.vault_name);
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

            if plaintext.get(&key).is_none() {
                anyhow::bail!("secret '{}' not found in env '{}'", key, ctx.env_name);
            }

            if dry_run {
                println!(
                    "[dry-run] Would remove '{}' from env '{}'",
                    key, ctx.env_name
                );
                return Ok(());
            }

            plaintext.remove(&key);

            let encrypted = env_file::encrypt_env(&plaintext, &ctx.cipher, &ctx.env_name)?;
            env_file::write_encrypted_env(&env_path, &encrypted)?;

            audit(
                &ctx,
                AuditAction::SecretDeleted { key: key.clone() },
                AuditOutcome::Success,
            );

            crate::notifications::try_notify(
                &ctx.vault_name,
                Some(&ctx.env_name),
                Some(&key),
                &ctx.fingerprint.to_hex(),
                "secret.deleted",
                &format!("Secret '{}' removed from env '{}'", key, ctx.env_name),
            );

            crate::output::print_success(&format!("Removed '{}' from env '{}'", key, ctx.env_name));

            maybe_auto_sync(&ctx.vault_name);
        }
        SecretCommands::Edit { env } => {
            let ctx = unlock_vault(identity, vault, env.as_deref())?;
            check_access(&ctx, AccessAction::Write, None)?;

            let env_path = ctx.paths.env_path(&ctx.vault_name, &ctx.env_name);
            let original = if env_path.exists() {
                let encrypted = env_file::read_encrypted_env(&env_path)?;
                env_file::decrypt_env(&encrypted, &ctx.cipher)?
            } else {
                sigyn_engine::vault::PlaintextEnv::new()
            };

            // Write KEY=VALUE pairs to a temp file
            let tmp_dir = std::env::temp_dir();
            let tmp_path = tmp_dir.join(format!("sigyn-edit-{}.env", std::process::id()));

            let mut content = String::new();
            content.push_str(&format!(
                "# Editing env '{}' — save and close to apply changes\n",
                ctx.env_name
            ));
            content.push_str(
                "# Lines starting with # are ignored. Delete a line to remove the secret.\n\n",
            );
            for (key, entry) in &original.entries {
                let val = entry.value.display_value(true);
                // Escape newlines for safe editing
                let escaped = val.replace('\\', "\\\\").replace('\n', "\\n");
                content.push_str(&format!("{}={}\n", key, escaped));
            }
            std::fs::write(&tmp_path, &content)?;

            // Open editor
            let editor = std::env::var("VISUAL")
                .or_else(|_| std::env::var("EDITOR"))
                .unwrap_or_else(|_| "vi".into());

            let status = std::process::Command::new(&editor)
                .arg(&tmp_path)
                .status()
                .with_context(|| format!("failed to launch editor '{}'", editor))?;

            if !status.success() {
                // Clean up temp file
                let _ = std::fs::remove_file(&tmp_path);
                anyhow::bail!("editor exited with non-zero status");
            }

            // Parse edited file
            let edited_content = std::fs::read_to_string(&tmp_path)?;
            // Securely overwrite temp file
            let zeros = vec![0u8; edited_content.len()];
            let _ = std::fs::write(&tmp_path, &zeros);
            let _ = std::fs::remove_file(&tmp_path);

            let mut new_entries: indexmap::IndexMap<String, String> = indexmap::IndexMap::new();
            for line in edited_content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if let Some((k, v)) = trimmed.split_once('=') {
                    let key = k.trim().to_string();
                    let val = v.replace("\\n", "\n").replace("\\\\", "\\");
                    new_entries.insert(key, val);
                }
            }

            // Diff: find added, modified, removed
            let original_keys: std::collections::HashSet<String> =
                original.entries.keys().cloned().collect();
            let new_keys: std::collections::HashSet<String> = new_entries.keys().cloned().collect();

            let added: Vec<String> = new_keys.difference(&original_keys).cloned().collect();
            let removed: Vec<String> = original_keys.difference(&new_keys).cloned().collect();
            let mut modified = Vec::new();
            for key in original_keys.intersection(&new_keys) {
                let old_val = original.get(key).unwrap().value.display_value(true);
                if new_entries[key.as_str()] != old_val {
                    modified.push(key.clone());
                }
            }

            if added.is_empty() && removed.is_empty() && modified.is_empty() {
                println!("No changes detected.");
                return Ok(());
            }

            // Show changes and confirm
            println!("{}", style("Changes detected:").bold());
            for k in &added {
                println!("  {} {}", style("+").green(), style(k).green());
            }
            for k in &modified {
                println!("  {} {}", style("~").yellow(), style(k).yellow());
            }
            for k in &removed {
                println!("  {} {}", style("-").red(), style(k).red());
            }

            if crate::config::is_interactive() {
                let confirm = dialoguer::Confirm::new()
                    .with_prompt(format!(
                        "Apply {} change(s)?",
                        added.len() + modified.len() + removed.len()
                    ))
                    .default(true)
                    .interact()?;
                if !confirm {
                    println!("Aborted.");
                    return Ok(());
                }
            }

            // Apply changes
            let mut plaintext = original;
            for key in &removed {
                plaintext.remove(key);
            }
            for key in added.iter().chain(modified.iter()) {
                plaintext.set(
                    key.clone(),
                    SecretValue::String(new_entries[key.as_str()].clone()),
                    &ctx.fingerprint,
                );
            }

            let encrypted = env_file::encrypt_env(&plaintext, &ctx.cipher, &ctx.env_name)?;
            env_file::write_encrypted_env(&env_path, &encrypted)?;

            audit(
                &ctx,
                AuditAction::SecretWritten {
                    key: format!(
                        "batch: +{} ~{} -{}",
                        added.len(),
                        modified.len(),
                        removed.len()
                    ),
                },
                AuditOutcome::Success,
            );

            crate::output::print_success(&format!(
                "Applied {} change(s) to env '{}' ({} added, {} modified, {} removed)",
                added.len() + modified.len() + removed.len(),
                ctx.env_name,
                added.len(),
                modified.len(),
                removed.len()
            ));

            maybe_auto_sync(&ctx.vault_name);
        }
        SecretCommands::Search { pattern, reveal } => {
            let ctx = unlock_vault(identity, vault, None)?;
            check_access(&ctx, AccessAction::Read, None)?;

            let manifest_content =
                std::fs::read_to_string(ctx.paths.manifest_path(&ctx.vault_name))?;
            let manifest = sigyn_engine::vault::VaultManifest::from_toml(&manifest_content)?;

            let mut results: Vec<serde_json::Value> = Vec::new();
            let mut found_any = false;

            if !json {
                println!(
                    "{} for '{}' in vault '{}'",
                    style("Search").bold(),
                    style(&pattern).cyan(),
                    ctx.vault_name
                );
                println!("{}", style("─".repeat(60)).dim());
            }

            for env_name in &manifest.environments {
                let env_path = ctx.paths.env_path(&ctx.vault_name, env_name);
                if !env_path.exists() {
                    continue;
                }

                let encrypted = env_file::read_encrypted_env(&env_path)?;
                let plaintext = env_file::decrypt_env(&encrypted, &ctx.cipher)?;

                for (key, entry) in &plaintext.entries {
                    if glob_match(&pattern, key) {
                        found_any = true;
                        let val = entry.value.display_value(reveal);
                        if json {
                            results.push(serde_json::json!({
                                "env": env_name,
                                "key": key,
                                "value": val,
                                "type": entry.value.type_name(),
                            }));
                        } else {
                            println!(
                                "  {} {} = {}",
                                style(format!("[{}]", env_name)).dim(),
                                style(key).bold(),
                                if reveal {
                                    val
                                } else {
                                    style("••••••••").dim().to_string()
                                }
                            );
                        }
                    }
                }
            }

            if json {
                crate::output::print_json(&results)?;
            } else if !found_any {
                println!("  No secrets matching '{}' found.", pattern);
            }
        }
        SecretCommands::Generate {
            key,
            length,
            r#type,
            env,
        } => {
            sigyn_engine::secrets::validate_key_name(&key)?;

            let template = match r#type.as_str() {
                "password" => sigyn_engine::secrets::GenerationTemplate::Password {
                    length,
                    charset: sigyn_engine::secrets::generation::PasswordCharset::default(),
                },
                "uuid" => sigyn_engine::secrets::GenerationTemplate::Uuid,
                "hex" => sigyn_engine::secrets::GenerationTemplate::Hex { length },
                "base64" => sigyn_engine::secrets::GenerationTemplate::Base64 { length },
                "alphanumeric" => {
                    sigyn_engine::secrets::GenerationTemplate::Alphanumeric { length }
                }
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
                sigyn_engine::vault::PlaintextEnv::new()
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

            crate::notifications::try_notify(
                &ctx.vault_name,
                Some(&ctx.env_name),
                Some(&key),
                &ctx.fingerprint.to_hex(),
                "secret.generated",
                &format!("Secret '{}' generated in env '{}'", key, ctx.env_name),
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

            maybe_auto_sync(&ctx.vault_name);
        }
    }
    Ok(())
}
