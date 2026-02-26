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

/// Resolve an environment name by prefix matching against available environments.
/// If the input exactly matches an environment, returns it as-is. Otherwise, looks
/// for a unique prefix match. Errors on zero or multiple matches.
pub fn resolve_env_name(input: &str, manifest: &VaultManifest) -> Result<String> {
    if manifest.environments.contains(&input.to_string()) {
        return Ok(input.to_string());
    }
    let matches: Vec<_> = manifest
        .environments
        .iter()
        .filter(|e| e.starts_with(input))
        .collect();
    match matches.len() {
        1 => {
            eprintln!(
                "{} resolved '{}' \u{2192} '{}'",
                style("note:").cyan().bold(),
                input,
                matches[0]
            );
            Ok(matches[0].clone())
        }
        0 => anyhow::bail!(
            "no environment matching '{}'\n  Available: {}",
            input,
            manifest.environments.join(", ")
        ),
        _ => anyhow::bail!(
            "ambiguous '{}': matches {}",
            input,
            matches
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

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
    /// Set secret(s): KEY VALUE, KEY=VALUE, or multiple KEY=VALUE pairs
    Set {
        /// KEY VALUE or KEY=VALUE pairs
        #[arg(required = true, num_args = 1..)]
        args: Vec<String>,
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
        /// Copy value to clipboard instead of printing
        #[arg(long, short)]
        copy: bool,
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
    /// Remove secret(s)
    #[command(alias = "rm")]
    Remove {
        /// Secret key name(s)
        #[arg(required = true, num_args = 1..)]
        keys: Vec<String>,
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
    /// Import secrets from a .env file
    #[command(alias = "imp")]
    Import {
        /// Path to .env file (- for stdin)
        path: String,
        /// Environment
        #[arg(long, short)]
        env: Option<String>,
        /// Overwrite existing secrets without asking
        #[arg(long)]
        force: bool,
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
    /// Vault-level cipher (manifest/policy/audit).
    pub vault_cipher: VaultCipher,
    /// Current env's cipher (None = no access to current env).
    pub env_cipher: Option<VaultCipher>,
    /// All accessible env ciphers keyed by env name.
    pub env_ciphers: std::collections::BTreeMap<String, VaultCipher>,
    pub vault_name: String,
    pub env_name: String,
    pub fingerprint: sigyn_engine::crypto::KeyFingerprint,
    pub paths: VaultPaths,
    pub manifest: VaultManifest,
    pub policy: VaultPolicy,
    pub loaded_identity: LoadedIdentity,
    /// The envelope header, already verified against the owner's signing key.
    pub header: sigyn_engine::crypto::EnvelopeHeader,
}

impl UnlockedVaultContext {
    /// Get the cipher for the current environment.
    /// Returns the per-env cipher if available, otherwise the vault cipher.
    pub fn current_env_cipher(&self) -> &VaultCipher {
        self.env_cipher.as_ref().unwrap_or(&self.vault_cipher)
    }

    /// Get the cipher for a specific environment by name.
    /// Returns the per-env cipher (None if no access to that env).
    pub fn cipher_for_env(&self, env_name: &str) -> Option<&VaultCipher> {
        self.env_ciphers.get(env_name)
    }
}

pub fn unlock_vault(
    identity_name: Option<&str>,
    vault_name: Option<&str>,
    env_name: Option<&str>,
) -> Result<UnlockedVaultContext> {
    let home = sigyn_home();
    let store = IdentityStore::new(home.clone());
    let paths = VaultPaths::new(home.clone());
    let config = crate::config::load_config();
    let project = crate::project_config::load_project_config();
    let project_settings = project.as_ref().and_then(|p| p.project.as_ref());
    let context = crate::commands::context::load_context();

    // Priority: CLI flags > context.toml > project config > global config > defaults
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
            "[verbose] vault: flag={:?} context={:?} project={:?} global={:?}",
            vault_name,
            context.as_ref().and_then(|c| c.vault.as_deref()),
            project_settings.and_then(|p| p.vault.as_deref()),
            config.default_vault.as_deref()
        );
    }
    let vault_name = vault_name
        .map(String::from)
        .or_else(|| context.as_ref().and_then(|c| c.vault.clone()))
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
        .or_else(|| context.as_ref().and_then(|c| c.env.clone()))
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

    // Read manifest data first (gives better "vault not found" error)
    let manifest_data = std::fs::read(paths.manifest_path(&vault_name))
        .context(format!("vault '{}' not found", vault_name))?;

    let header_bytes =
        std::fs::read(paths.members_path(&vault_name)).context("failed to read vault members")?;

    // Bootstrap: extract vault_id from header (unverified — we verify below)
    let header_preview: sigyn_engine::crypto::EnvelopeHeader =
        envelope::extract_header_unverified(&header_bytes)
            .map_err(|e| anyhow::anyhow!("failed to decode header: {}", e))?;
    let vault_id = header_preview.vault_id.ok_or_else(|| {
        anyhow::anyhow!(
            "vault '{}' header missing vault_id — file may be corrupted",
            vault_name
        )
    })?;

    // Unseal keys: returns (vault_key, {env_name: env_key}).
    let (vault_key_bytes, env_key_map) = envelope::unseal_header(
        &header_preview,
        loaded.encryption_key(),
        vault_id,
        &[], // requested_envs not known yet; unseal_header tries all available slots
    )
    .context(format!(
        "failed to unseal vault '{}' (not a member or wrong key)\n\n  \
         Check your membership: sigyn delegation tree -v {}\n  \
         Or ask the vault owner to re-invite you.",
        vault_name, vault_name
    ))?;

    let vault_cipher = VaultCipher::new(vault_key_bytes);

    // Decrypt manifest (rejects plaintext — must be sealed)
    let manifest = VaultManifest::from_sealed_bytes(&vault_cipher, &manifest_data, vault_id)?;

    // Now verify the header signature using the owner's signing key from the manifest.
    // This prevents an attacker from replacing members.cbor with a crafted header.
    let store = IdentityStore::new(sigyn_home());
    let identities = store
        .list()
        .map_err(|e| anyhow::anyhow!("failed to list identities: {}", e))?;
    if let Some(owner_id) = identities
        .iter()
        .find(|id| id.fingerprint == manifest.owner)
    {
        envelope::verify_and_load_header(&header_bytes, vault_id, &owner_id.signing_pubkey)
            .map_err(|e| anyhow::anyhow!("header signature verification failed: {}", e))?;
    } else if loaded.identity.fingerprint == manifest.owner {
        // We are the owner — verify with our own signing key
        envelope::verify_and_load_header(&header_bytes, vault_id, &loaded.identity.signing_pubkey)
            .map_err(|e| anyhow::anyhow!("header signature verification failed: {}", e))?;
    } else {
        anyhow::bail!(
            "cannot verify header signature: owner identity {} not found locally.\n  \
             Import the owner's identity or ask them to re-sign the vault.",
            manifest.owner.to_hex()
        );
    }

    // --- Origin pinning (TOFU) ---
    // Check the vault owner against the pinned identity on this device.
    {
        let device_key = sigyn_engine::device::load_or_create_device_key(&home);
        if let Ok(dk) = device_key {
            if let Ok(mut pin_store) =
                sigyn_engine::vault::local_state::load_pinned_store(&home, &dk)
            {
                let local_state = pin_store.entry_mut(&vault_name);
                match &local_state.pin {
                    None => {
                        // First access: pin the owner
                        local_state.pin = Some(sigyn_engine::vault::VaultPin {
                            vault_id,
                            owner_fingerprint: manifest.owner.clone(),
                            owner_signing_pubkey_bytes: {
                                // Get owner's signing pubkey bytes
                                let owner_id = identities
                                    .iter()
                                    .find(|id| id.fingerprint == manifest.owner);
                                if let Some(oid) = owner_id {
                                    oid.signing_pubkey.to_bytes().to_vec()
                                } else if loaded.identity.fingerprint == manifest.owner {
                                    loaded.identity.signing_pubkey.to_bytes().to_vec()
                                } else {
                                    Vec::new()
                                }
                            },
                            pinned_at: chrono::Utc::now(),
                        });
                        let _ = sigyn_engine::vault::local_state::save_pinned_store(
                            &pin_store, &home, &dk,
                        );
                        eprintln!(
                            "{} vault '{}' pinned to owner {}",
                            style("pin:").cyan().bold(),
                            vault_name,
                            manifest.owner.to_hex()
                        );
                    }
                    Some(pin) => {
                        // Subsequent access: verify owner hasn't changed
                        if pin.owner_fingerprint != manifest.owner {
                            eprintln!(
                                "\n{}\n{}\n{}\n",
                                style("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                                    .red()
                                    .bold(),
                                style("@    WARNING: VAULT OWNER CHANGED        @")
                                    .red()
                                    .bold(),
                                style("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                                    .red()
                                    .bold(),
                            );
                            eprintln!(
                                "Vault '{}' now claims owner {} but was pinned to owner {}.",
                                vault_name,
                                style(manifest.owner.to_hex()).yellow(),
                                style(pin.owner_fingerprint.to_hex()).yellow(),
                            );
                            eprintln!("Someone may have copied this vault to a different repo.\n");
                            eprintln!(
                                "To accept the new owner: sigyn vault trust {} --accept-new-owner",
                                vault_name
                            );
                            anyhow::bail!(
                                "vault origin mismatch: expected owner {}, found {}",
                                pin.owner_fingerprint.to_hex(),
                                manifest.owner.to_hex()
                            );
                        }
                        // Also verify vault_id hasn't changed
                        if pin.vault_id != vault_id {
                            anyhow::bail!(
                                "vault ID mismatch: pinned {} but found {}. \
                                 The vault may have been recreated.",
                                pin.vault_id,
                                vault_id
                            );
                        }
                    }
                }
            }
        }
    }

    // Resolve env prefix matching against manifest environments
    let env_name = resolve_env_name(&env_name, &manifest)?;

    // Load policy (returns empty policy if file doesn't exist)
    let policy = VaultPolicy::load_encrypted(&paths.policy_path(&vault_name), &vault_cipher)
        .unwrap_or_default();

    // Build env ciphers map
    let mut env_ciphers = std::collections::BTreeMap::new();
    for (ename, ekey) in &env_key_map {
        env_ciphers.insert(ename.clone(), VaultCipher::new(*ekey));
    }
    let env_cipher = env_ciphers
        .get(&env_name)
        .map(|c| VaultCipher::new(*c.key_bytes()));

    Ok(UnlockedVaultContext {
        vault_cipher,
        env_cipher,
        env_ciphers,
        vault_name,
        env_name,
        fingerprint,
        paths,
        manifest,
        policy,
        loaded_identity: loaded,
        header: header_preview,
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
                if let Ok(manifest) = super::org::load_org_manifest_path(&mp) {
                    {
                        let members_p = hierarchy_paths.members_path(cp);
                        if members_p.exists() {
                            if let Ok(hdr_bytes) = std::fs::read(&members_p) {
                                // Use extract_header_unverified for org hierarchy headers
                                // (the owner's signing key may not be locally available)
                                if let Ok(header) = envelope::extract_header_unverified(&hdr_bytes)
                                {
                                    if let Ok(mk) = envelope::unseal_vault_key(
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

/// Derive the audit log cipher from the vault cipher.
fn derive_audit_cipher(
    ctx: &UnlockedVaultContext,
) -> Option<sigyn_engine::crypto::vault_cipher::VaultCipher> {
    sigyn_engine::crypto::sealed::derive_file_cipher_with_salt(
        ctx.vault_cipher.key_bytes(),
        b"sigyn-audit-v1",
        &ctx.manifest.vault_id,
    )
    .ok()
}

/// Append an audit entry (best-effort — warn on stderr but don't fail the operation)
fn audit(ctx: &UnlockedVaultContext, action: AuditAction, outcome: AuditOutcome) {
    let audit_path = ctx.paths.audit_path(&ctx.vault_name);
    let Some(audit_cipher) = derive_audit_cipher(ctx) else {
        return;
    };
    match AuditLog::open(&audit_path, audit_cipher) {
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
        SecretCommands::Set { args, env } => {
            // Parse args: either "KEY VALUE" (2 args, no '=') or "KEY=VALUE ..." pairs
            let pairs: Vec<(String, String)> = if args.len() == 1 && !args[0].contains('=') {
                // Single key, no value — read from stdin
                let key = args[0].clone();
                sigyn_engine::secrets::validate_key_name(&key)?;
                use std::io::Read;
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                vec![(key, buf.trim_end().to_string())]
            } else if args.len() == 2 && !args[0].contains('=') && !args[1].contains('=') {
                // Legacy: KEY VALUE (two positional args)
                let key = args[0].clone();
                sigyn_engine::secrets::validate_key_name(&key)?;
                vec![(key, args[1].clone())]
            } else {
                // KEY=VALUE pairs
                let mut pairs = Vec::new();
                for arg in &args {
                    let (k, v) = arg.split_once('=').ok_or_else(|| {
                        anyhow::anyhow!(
                            "invalid argument '{}': expected KEY=VALUE format when setting multiple secrets",
                            arg
                        )
                    })?;
                    sigyn_engine::secrets::validate_key_name(k)?;
                    pairs.push((k.to_string(), v.to_string()));
                }
                pairs
            };

            let ctx = unlock_vault(identity, vault, env.as_deref())?;
            let is_batch = pairs.len() > 1;

            let env_path = ctx.paths.env_path(&ctx.vault_name, &ctx.env_name);
            let mut plaintext = if env_path.exists() {
                let encrypted = env_file::read_encrypted_env(&env_path)?;
                env_file::decrypt_env(&encrypted, ctx.current_env_cipher())?
            } else {
                sigyn_engine::vault::PlaintextEnv::new()
            };

            let mut set_count = 0usize;
            let mut updated_count = 0usize;
            let mut failed = 0usize;
            let mut json_results: Vec<serde_json::Value> = Vec::new();

            for (key, value) in &pairs {
                if let Err(e) = check_access(&ctx, AccessAction::Write, Some(key)) {
                    failed += 1;
                    if json {
                        json_results.push(serde_json::json!({
                            "key": key,
                            "status": "failed",
                            "error": e.to_string(),
                        }));
                    } else {
                        crate::output::print_error(&format!("'{}': {}", key, e));
                    }
                    continue;
                }

                let is_update = plaintext.get(key).is_some();

                if dry_run {
                    let action = if is_update { "update" } else { "create" };
                    println!(
                        "[dry-run] Would {} '{}' in env '{}'",
                        action, key, ctx.env_name
                    );
                    continue;
                }

                plaintext.set(
                    key.clone(),
                    SecretValue::String(value.clone()),
                    &ctx.fingerprint,
                );

                audit(
                    &ctx,
                    AuditAction::SecretWritten { key: key.clone() },
                    AuditOutcome::Success,
                );

                if is_update {
                    updated_count += 1;
                } else {
                    set_count += 1;
                }

                if json {
                    json_results.push(serde_json::json!({
                        "key": key,
                        "env": ctx.env_name,
                        "action": if is_update { "updated" } else { "created" },
                    }));
                } else if !is_batch {
                    let action = if is_update { "Updated" } else { "Set" };
                    crate::output::print_success(&format!(
                        "{} '{}' in env '{}'",
                        action, key, ctx.env_name
                    ));
                }
            }

            if dry_run {
                return Ok(());
            }

            // Write once after all mutations
            let encrypted =
                env_file::encrypt_env(&plaintext, ctx.current_env_cipher(), &ctx.env_name)?;
            env_file::write_encrypted_env(&env_path, &encrypted)?;

            if json {
                if is_batch {
                    crate::output::print_json(&json_results)?;
                } else if let Some(result) = json_results.into_iter().next() {
                    crate::output::print_json(&result)?;
                }
            } else if is_batch {
                println!(
                    "{} set, {} updated, {} failed",
                    style(set_count).green().bold(),
                    style(updated_count).cyan(),
                    if failed > 0 {
                        style(failed).red().bold()
                    } else {
                        style(failed).dim()
                    }
                );
            }

            maybe_auto_sync(&ctx.vault_name);
        }
        SecretCommands::Get { key, env, copy } => {
            let ctx = unlock_vault(identity, vault, env.as_deref())?;
            check_access(&ctx, AccessAction::Read, Some(&key))?;

            let env_path = ctx.paths.env_path(&ctx.vault_name, &ctx.env_name);
            if !env_path.exists() {
                anyhow::bail!("environment '{}' has no secrets yet", ctx.env_name);
            }

            let encrypted = env_file::read_encrypted_env(&env_path)?;
            let plaintext = env_file::decrypt_env(&encrypted, ctx.current_env_cipher())?;

            let entry = plaintext.get(&key).ok_or_else(|| {
                anyhow::anyhow!("secret '{}' not found in env '{}'", key, ctx.env_name)
            })?;

            audit(
                &ctx,
                AuditAction::SecretRead { key: key.clone() },
                AuditOutcome::Success,
            );

            let value = entry.value.display_value(true);

            if copy {
                let mut clipboard = arboard::Clipboard::new()
                    .map_err(|e| anyhow::anyhow!("failed to access clipboard: {}", e))?;
                clipboard
                    .set_text(&value)
                    .map_err(|e| anyhow::anyhow!("failed to copy to clipboard: {}", e))?;
                if json {
                    crate::output::print_json(&serde_json::json!({
                        "key": key,
                        "env": ctx.env_name,
                        "copied": true,
                    }))?;
                } else {
                    eprintln!(
                        "{} Copied '{}' to clipboard",
                        style("\u{2713}").green().bold(),
                        key
                    );
                }
            } else if json {
                crate::output::print_json(&serde_json::json!({
                    "key": key,
                    "value": value,
                    "type": entry.value.type_name(),
                    "env": ctx.env_name,
                    "version": entry.metadata.version,
                }))?;
            } else {
                println!("{}", value);
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
            let plaintext = env_file::decrypt_env(&encrypted, ctx.current_env_cipher())?;

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
        SecretCommands::Remove { keys, env } => {
            let ctx = unlock_vault(identity, vault, env.as_deref())?;

            let env_path = ctx.paths.env_path(&ctx.vault_name, &ctx.env_name);
            if !env_path.exists() {
                anyhow::bail!("environment '{}' has no secrets", ctx.env_name);
            }

            let encrypted = env_file::read_encrypted_env(&env_path)?;
            let mut plaintext = env_file::decrypt_env(&encrypted, ctx.current_env_cipher())?;

            let is_batch = keys.len() > 1;
            let mut removed = 0usize;
            let mut failed = 0usize;

            for key in &keys {
                if let Err(e) = check_access(&ctx, AccessAction::Delete, Some(key)) {
                    failed += 1;
                    crate::output::print_error(&format!("'{}': {}", key, e));
                    continue;
                }

                if plaintext.get(key).is_none() {
                    failed += 1;
                    crate::output::print_error(&format!(
                        "secret '{}' not found in env '{}'",
                        key, ctx.env_name
                    ));
                    continue;
                }

                if dry_run {
                    println!(
                        "[dry-run] Would remove '{}' from env '{}'",
                        key, ctx.env_name
                    );
                    continue;
                }

                plaintext.remove(key);

                audit(
                    &ctx,
                    AuditAction::SecretDeleted { key: key.clone() },
                    AuditOutcome::Success,
                );

                crate::notifications::try_notify(
                    &ctx.vault_name,
                    Some(&ctx.env_name),
                    Some(key),
                    &ctx.fingerprint.to_hex(),
                    "secret.deleted",
                    &format!("Secret '{}' removed from env '{}'", key, ctx.env_name),
                );

                removed += 1;
                if !is_batch {
                    crate::output::print_success(&format!(
                        "Removed '{}' from env '{}'",
                        key, ctx.env_name
                    ));
                }
            }

            if dry_run {
                return Ok(());
            }

            if removed > 0 {
                let encrypted =
                    env_file::encrypt_env(&plaintext, ctx.current_env_cipher(), &ctx.env_name)?;
                env_file::write_encrypted_env(&env_path, &encrypted)?;
            }

            if is_batch {
                println!(
                    "{} removed, {} failed",
                    style(removed).green().bold(),
                    if failed > 0 {
                        style(failed).red().bold()
                    } else {
                        style(failed).dim()
                    }
                );
            }

            maybe_auto_sync(&ctx.vault_name);
        }
        SecretCommands::Edit { env } => {
            let ctx = unlock_vault(identity, vault, env.as_deref())?;
            check_access(&ctx, AccessAction::Write, None)?;

            let env_path = ctx.paths.env_path(&ctx.vault_name, &ctx.env_name);
            let original = if env_path.exists() {
                let encrypted = env_file::read_encrypted_env(&env_path)?;
                env_file::decrypt_env(&encrypted, ctx.current_env_cipher())?
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

            let encrypted =
                env_file::encrypt_env(&plaintext, ctx.current_env_cipher(), &ctx.env_name)?;
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

            let manifest = &ctx.manifest;

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
                let plaintext = env_file::decrypt_env(&encrypted, ctx.current_env_cipher())?;

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
                env_file::decrypt_env(&encrypted, ctx.current_env_cipher())?
            } else {
                sigyn_engine::vault::PlaintextEnv::new()
            };

            plaintext.set(
                key.clone(),
                SecretValue::Generated(generated.clone()),
                &ctx.fingerprint,
            );

            let encrypted =
                env_file::encrypt_env(&plaintext, ctx.current_env_cipher(), &ctx.env_name)?;
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
        SecretCommands::Import { path, env, force } => {
            // Read .env file content
            let content = if path == "-" {
                use std::io::Read;
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                buf
            } else {
                let p = std::path::Path::new(&path);
                if !p.exists() {
                    anyhow::bail!("file not found: {}", path);
                }
                std::fs::read_to_string(p).with_context(|| format!("failed to read '{}'", path))?
            };

            // Parse KEY=VALUE lines (skip comments and blanks)
            let mut pairs: Vec<(String, String)> = Vec::new();
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                // Support export KEY=VALUE syntax
                let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);
                if let Some((k, v)) = trimmed.split_once('=') {
                    let key = k.trim().to_string();
                    // Strip surrounding quotes from value
                    let val = v.trim();
                    let val = if (val.starts_with('"') && val.ends_with('"'))
                        || (val.starts_with('\'') && val.ends_with('\''))
                    {
                        val[1..val.len() - 1].to_string()
                    } else {
                        val.to_string()
                    };
                    if let Err(e) = sigyn_engine::secrets::validate_key_name(&key) {
                        eprintln!(
                            "{} skipping invalid key '{}': {}",
                            style("warning:").yellow().bold(),
                            key,
                            e
                        );
                        continue;
                    }
                    pairs.push((key, val));
                }
            }

            if pairs.is_empty() {
                anyhow::bail!("no valid KEY=VALUE entries found in '{}'", path);
            }

            let ctx = unlock_vault(identity, vault, env.as_deref())?;
            check_access(&ctx, AccessAction::Write, None)?;

            let env_path = ctx.paths.env_path(&ctx.vault_name, &ctx.env_name);
            let mut plaintext = if env_path.exists() {
                let encrypted = env_file::read_encrypted_env(&env_path)?;
                env_file::decrypt_env(&encrypted, ctx.current_env_cipher())?
            } else {
                sigyn_engine::vault::PlaintextEnv::new()
            };

            let mut set_count = 0usize;
            let mut updated_count = 0usize;
            let mut skipped = 0usize;

            for (key, value) in &pairs {
                let is_update = plaintext.get(key).is_some();

                if is_update && !force {
                    if crate::config::is_interactive() {
                        let confirm = dialoguer::Confirm::new()
                            .with_prompt(format!("Overwrite existing secret '{}'?", key))
                            .default(false)
                            .interact()?;
                        if !confirm {
                            skipped += 1;
                            continue;
                        }
                    } else {
                        skipped += 1;
                        continue;
                    }
                }

                plaintext.set(
                    key.clone(),
                    SecretValue::String(value.clone()),
                    &ctx.fingerprint,
                );

                audit(
                    &ctx,
                    AuditAction::SecretWritten { key: key.clone() },
                    AuditOutcome::Success,
                );

                if is_update {
                    updated_count += 1;
                } else {
                    set_count += 1;
                }
            }

            let total_written = set_count + updated_count;
            if total_written > 0 {
                let encrypted =
                    env_file::encrypt_env(&plaintext, ctx.current_env_cipher(), &ctx.env_name)?;
                env_file::write_encrypted_env(&env_path, &encrypted)?;
            }

            if json {
                crate::output::print_json(&serde_json::json!({
                    "source": path,
                    "env": ctx.env_name,
                    "created": set_count,
                    "updated": updated_count,
                    "skipped": skipped,
                }))?;
            } else {
                crate::output::print_success(&format!(
                    "Imported {} secret(s) from '{}' into env '{}'",
                    total_written, path, ctx.env_name
                ));
                if set_count > 0 {
                    println!("  {} new", set_count);
                }
                if updated_count > 0 {
                    println!("  {} updated", updated_count);
                }
                if skipped > 0 {
                    println!("  {} skipped (use --force to overwrite)", skipped);
                }
            }

            maybe_auto_sync(&ctx.vault_name);
        }
    }
    Ok(())
}
