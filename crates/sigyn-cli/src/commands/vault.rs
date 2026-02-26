use anyhow::Result;
use clap::Subcommand;
use console::style;
use sigyn_engine::audit::entry::AuditOutcome;
use sigyn_engine::audit::{AuditAction, AuditLog};
use sigyn_engine::crypto::envelope;
use sigyn_engine::crypto::vault_cipher::VaultCipher;
use sigyn_engine::identity::keygen::IdentityStore;
use sigyn_engine::policy::storage::VaultPolicyExt;
use sigyn_engine::vault::{VaultManifest, VaultPaths};

use crate::commands::identity::load_identity;
use crate::config::sigyn_home;

#[derive(Subcommand)]
pub enum VaultCommands {
    /// Create a new vault
    Create {
        /// Vault name
        name: String,
        /// Link vault to an org hierarchy path (e.g. "acme/platform/web")
        #[arg(long)]
        org: Option<String>,
        /// Create separate git repo for audit data (enables per-repo access control)
        #[arg(long)]
        split_audit: bool,
    },
    /// List all vaults
    List,
    /// Show vault info
    Info {
        /// Vault name
        name: Option<String>,
    },
    /// Link an existing vault to an org hierarchy
    Attach {
        /// Vault name
        name: String,
        /// Org path to link to
        #[arg(long)]
        org: String,
    },
    /// Unlink a vault from its org hierarchy
    Detach {
        /// Vault name
        name: String,
    },
    /// Accept a changed vault owner (after origin mismatch warning)
    Trust {
        /// Vault name
        name: String,
        /// Accept the new owner identity
        #[arg(long)]
        accept_new_owner: bool,
    },
    /// List all pinned vaults and their pinned owners
    Pins,
}

pub fn handle(cmd: VaultCommands, identity: Option<&str>, json: bool) -> Result<()> {
    let home = sigyn_home();
    let store = IdentityStore::new(home.clone());
    let paths = VaultPaths::new(home.clone());

    match cmd {
        VaultCommands::Create {
            name,
            org,
            split_audit,
        } => {
            let loaded = load_identity(&store, identity)?;
            let fingerprint = loaded.identity.fingerprint.clone();

            let vault_dir = paths.vault_dir(&name);
            if vault_dir.exists() {
                anyhow::bail!("vault '{}' already exists", name);
            }

            // If --org is set, validate the org path exists
            if let Some(ref org_path_str) = org {
                let hierarchy_paths =
                    sigyn_engine::hierarchy::path::HierarchyPaths::new(home.clone());
                let org_path = sigyn_engine::hierarchy::path::OrgPath::parse(org_path_str)
                    .map_err(|_| anyhow::anyhow!("invalid org path: {}", org_path_str))?;
                if !hierarchy_paths.manifest_path(&org_path).exists() {
                    anyhow::bail!("org node '{}' not found", org_path_str);
                }
            }

            let mut manifest = VaultManifest::new(name.clone(), fingerprint.clone());
            manifest.org_path = org.clone();
            let vault_id = manifest.vault_id;

            // Generate vault-level key (manifest/policy/audit) and per-env keys
            let vault_cipher = VaultCipher::generate();
            let recipients = std::slice::from_ref(&loaded.identity.encryption_pubkey);

            // Build per-env keys: every default env gets its own key, creator gets all slots
            let mut env_keys = std::collections::BTreeMap::new();
            let mut env_recipients = std::collections::BTreeMap::new();
            for env_name in &manifest.environments {
                let env_key = VaultCipher::generate();
                env_keys.insert(env_name.clone(), env_key);
                env_recipients.insert(env_name.clone(), recipients.to_vec());
            }
            let env_key_bytes: std::collections::BTreeMap<String, [u8; 32]> = env_keys
                .iter()
                .map(|(name, cipher)| (name.clone(), *cipher.key_bytes()))
                .collect();

            let header = envelope::seal_v2(
                vault_cipher.key_bytes(),
                &env_key_bytes,
                recipients,
                &env_recipients,
                vault_id,
            )?;

            std::fs::create_dir_all(paths.env_dir(&name))?;

            let sealed_manifest = manifest
                .to_sealed_bytes(&vault_cipher)
                .map_err(|e| anyhow::anyhow!("failed to seal manifest: {}", e))?;
            crate::config::secure_write(&paths.manifest_path(&name), &sealed_manifest)?;

            // Write encrypted org_link for org-path scanning
            if let Some(ref org_path) = org {
                let device_key = sigyn_engine::device::load_or_create_device_key(&home)?;
                let link_path = paths.vault_dir(&name).join(".org_link");
                sigyn_engine::vault::path::write_org_link(&link_path, org_path, &device_key)?;
            }

            let signed_header = envelope::sign_header(&header, loaded.signing_key(), vault_id)
                .map_err(|e| anyhow::anyhow!("failed to sign header: {}", e))?;
            crate::config::secure_write(&paths.members_path(&name), &signed_header)?;

            let policy = sigyn_engine::policy::storage::VaultPolicy::new();
            policy.save_encrypted(&paths.policy_path(&name), &vault_cipher)?;

            for env_name in &manifest.environments {
                let env = sigyn_engine::vault::PlaintextEnv::new();
                let env_cipher = env_keys.get(env_name).unwrap();
                let encrypted =
                    sigyn_engine::vault::env_file::encrypt_env(&env, env_cipher, env_name)?;
                sigyn_engine::vault::env_file::write_encrypted_env(
                    &paths.env_path(&name, env_name),
                    &encrypted,
                )?;
            }

            // If --split-audit, initialize audit sub-repo before writing audit log
            if split_audit {
                sigyn_engine::sync::vault_sync::init_audit_repo(&paths.vault_dir(&name))?;
            }

            // Audit: vault created
            if let Ok(audit_cipher) = sigyn_engine::crypto::sealed::derive_file_cipher_with_salt(
                vault_cipher.key_bytes(),
                b"sigyn-audit-v1",
                &vault_id,
            ) {
                if let Ok(mut log) = AuditLog::open(&paths.audit_path(&name), audit_cipher) {
                    let _ = log.append(
                        &fingerprint,
                        AuditAction::VaultCreated,
                        None,
                        AuditOutcome::Success,
                        loaded.signing_key(),
                    );
                }
            }

            if json {
                crate::output::print_json(&manifest)?;
            } else {
                crate::output::print_success(&format!("Vault '{}' created", name));
                println!("  ID:           {}", vault_id);
                println!("  Owner:        {}", style(fingerprint.to_hex()).cyan());
                println!("  Environments: {}", manifest.environments.join(", "));

                println!();
                println!("{}", style("Next steps:").bold());
                println!(
                    "  sigyn secret set DATABASE_URL 'postgres://...' -v {} -e dev",
                    name
                );
                println!("  sigyn project init --vault {}", name);
                println!("  sigyn run -v {} -e dev -- ./your-app", name);

                // Offer to create .sigyn.toml
                let identity_name = loaded.identity.profile.name.clone();
                let _ =
                    crate::project_config::offer_project_init(&name, Some(&identity_name), "dev");
            }
        }
        VaultCommands::List => {
            let vaults = paths.list_vaults()?;
            if vaults.is_empty() {
                println!("No vaults found. Create one with: sigyn vault create <name>");
                return Ok(());
            }

            if json {
                crate::output::print_json(&vaults)?;
            } else {
                println!("{}", style("Vaults").bold());
                println!("{}", style("─".repeat(40)).dim());
                for name in &vaults {
                    // All manifests are encrypted; show as locked (use `vault info` to decrypt)
                    println!("  {} {}", style(name).bold(), style("(locked)").dim());
                }
            }
        }
        VaultCommands::Info { name } => {
            let vault_name = name
                .or_else(|| crate::config::load_config().default_vault)
                .ok_or_else(|| anyhow::anyhow!("no vault specified and no default set"))?;

            let manifest_path = paths.manifest_path(&vault_name);
            if !manifest_path.exists() {
                anyhow::bail!("vault '{}' not found", vault_name);
            }

            // Always requires unlock — manifests are encrypted
            let ctx = super::secret::unlock_vault(identity, Some(&vault_name), None)?;
            let manifest = ctx.manifest;

            if json {
                crate::output::print_json(&manifest)?;
            } else {
                println!("{}", style("Vault Info").bold());
                println!("  Name:         {}", manifest.name);
                println!("  ID:           {}", manifest.vault_id);
                println!("  Owner:        {}", style(manifest.owner.to_hex()).cyan());
                println!("  Environments: {}", manifest.environments.join(", "));
                println!(
                    "  Created:      {}",
                    manifest.created_at.format("%Y-%m-%d %H:%M:%S UTC")
                );
                if let Some(ref org_path) = manifest.org_path {
                    println!("  Org:          {}", style(org_path).cyan());
                }
            }
        }
        VaultCommands::Attach { name, org } => {
            let manifest_path = paths.manifest_path(&name);
            if !manifest_path.exists() {
                anyhow::bail!("vault '{}' not found", name);
            }

            // Validate org path exists
            let hierarchy_paths = sigyn_engine::hierarchy::path::HierarchyPaths::new(home.clone());
            let org_path = sigyn_engine::hierarchy::path::OrgPath::parse(&org)
                .map_err(|_| anyhow::anyhow!("invalid org path: {}", org))?;
            if !hierarchy_paths.manifest_path(&org_path).exists() {
                anyhow::bail!("org node '{}' not found", org);
            }

            // Unlock vault to decrypt/re-encrypt manifest
            let ctx = super::secret::unlock_vault(identity, Some(&name), None)?;
            let mut manifest = ctx.manifest.clone();

            if manifest.org_path.is_some() {
                anyhow::bail!(
                    "vault '{}' is already linked to '{}'. Detach first.",
                    name,
                    manifest.org_path.as_deref().unwrap()
                );
            }

            manifest.org_path = Some(org.clone());
            let sealed = manifest
                .to_sealed_bytes(&ctx.vault_cipher)
                .map_err(|e| anyhow::anyhow!("failed to seal manifest: {}", e))?;
            crate::config::secure_write(&manifest_path, &sealed)?;
            {
                let device_key = sigyn_engine::device::load_or_create_device_key(&home)?;
                let link_path = paths.vault_dir(&name).join(".org_link");
                sigyn_engine::vault::path::write_org_link(&link_path, &org, &device_key)?;
            }

            if json {
                crate::output::print_json(&serde_json::json!({
                    "vault": name,
                    "org_path": org,
                }))?;
            } else {
                crate::output::print_success(&format!("Vault '{}' linked to '{}'", name, org));
            }
        }
        VaultCommands::Detach { name } => {
            let manifest_path = paths.manifest_path(&name);
            if !manifest_path.exists() {
                anyhow::bail!("vault '{}' not found", name);
            }

            // Unlock vault to decrypt/re-encrypt manifest
            let ctx = super::secret::unlock_vault(identity, Some(&name), None)?;
            let mut manifest = ctx.manifest.clone();

            if manifest.org_path.is_none() {
                anyhow::bail!("vault '{}' is not linked to any org", name);
            }

            let old_org = manifest.org_path.take();
            let sealed = manifest
                .to_sealed_bytes(&ctx.vault_cipher)
                .map_err(|e| anyhow::anyhow!("failed to seal manifest: {}", e))?;
            crate::config::secure_write(&manifest_path, &sealed)?;
            let _ = std::fs::remove_file(paths.vault_dir(&name).join(".org_link"));

            if json {
                crate::output::print_json(&serde_json::json!({
                    "vault": name,
                    "detached_from": old_org,
                }))?;
            } else {
                crate::output::print_success(&format!(
                    "Vault '{}' detached from '{}'",
                    name,
                    old_org.unwrap()
                ));
            }
        }
        VaultCommands::Trust {
            name,
            accept_new_owner,
        } => {
            if !accept_new_owner {
                anyhow::bail!(
                    "use --accept-new-owner to confirm you trust the new owner of vault '{}'",
                    name
                );
            }

            let device_key = sigyn_engine::device::load_or_create_device_key(&home)?;
            let mut pin_store =
                sigyn_engine::vault::local_state::load_pinned_store(&home, &device_key)
                    .map_err(|e| anyhow::anyhow!("failed to load pin store: {}", e))?;

            // We need to unlock the vault to get the current manifest
            // But unlock_vault will fail with origin mismatch — so we read
            // the manifest directly (header-only, unverified) to show info.
            let _manifest_data = std::fs::read(paths.manifest_path(&name))
                .map_err(|_| anyhow::anyhow!("vault '{}' not found", name))?;
            let header_bytes = std::fs::read(paths.members_path(&name))
                .map_err(|_| anyhow::anyhow!("vault '{}' has no members file", name))?;
            let header_preview =
                sigyn_engine::crypto::envelope::extract_header_unverified(&header_bytes)
                    .map_err(|e| anyhow::anyhow!("failed to decode header: {}", e))?;
            let vault_id = header_preview
                .vault_id
                .ok_or_else(|| anyhow::anyhow!("header missing vault_id"))?;

            let local_state = pin_store.entry_mut(&name);
            let old_pin = local_state.pin.as_ref();

            if let Some(old) = old_pin {
                eprintln!(
                    "Current pinned owner: {}",
                    style(old.owner_fingerprint.to_hex()).yellow()
                );
            } else {
                eprintln!("No existing pin for vault '{}'", name);
            }

            if crate::config::is_interactive() {
                let confirm = dialoguer::Confirm::new()
                    .with_prompt(format!(
                        "Accept new owner for vault '{}'? This resets the origin pin.",
                        name
                    ))
                    .default(false)
                    .interact()?;
                if !confirm {
                    println!("Aborted.");
                    return Ok(());
                }
            }

            // Clear the pin — it will be re-established on next unlock_vault()
            local_state.pin = None;
            sigyn_engine::vault::local_state::save_pinned_store(&pin_store, &home, &device_key)
                .map_err(|e| anyhow::anyhow!("failed to save pin store: {}", e))?;

            if json {
                crate::output::print_json(&serde_json::json!({
                    "vault": name,
                    "vault_id": vault_id.to_string(),
                    "pin_reset": true,
                }))?;
            } else {
                crate::output::print_success(&format!(
                    "Pin reset for vault '{}'. The owner will be re-pinned on next access.",
                    name
                ));
            }
        }
        VaultCommands::Pins => {
            let device_key = sigyn_engine::device::load_or_create_device_key(&home)?;
            let pin_store = sigyn_engine::vault::local_state::load_pinned_store(&home, &device_key)
                .map_err(|e| anyhow::anyhow!("failed to load pin store: {}", e))?;

            if pin_store.vaults.is_empty() {
                if json {
                    crate::output::print_json(&serde_json::json!([]))?;
                } else {
                    println!(
                        "No pinned vaults. Pins are created automatically on first vault access."
                    );
                }
                return Ok(());
            }

            if json {
                let entries: Vec<_> = pin_store
                    .vaults
                    .iter()
                    .filter_map(|(name, state)| {
                        state.pin.as_ref().map(|pin| {
                            serde_json::json!({
                                "vault": name,
                                "vault_id": pin.vault_id.to_string(),
                                "owner": pin.owner_fingerprint.to_hex(),
                                "pinned_at": pin.pinned_at.to_rfc3339(),
                            })
                        })
                    })
                    .collect();
                crate::output::print_json(&entries)?;
            } else {
                println!("{}", style("Pinned Vaults").bold());
                println!("{}", style("─".repeat(60)).dim());
                let mut names: Vec<_> = pin_store.vaults.keys().collect();
                names.sort();
                for name in names {
                    let state = &pin_store.vaults[name];
                    if let Some(ref pin) = state.pin {
                        println!(
                            "  {} owner={} pinned={}",
                            style(name).bold(),
                            style(pin.owner_fingerprint.to_hex()).cyan(),
                            pin.pinned_at.format("%Y-%m-%d"),
                        );
                    } else if state.checkpoint.is_some() {
                        println!(
                            "  {} {}",
                            style(name).bold(),
                            style("(checkpoint only, no pin)").dim(),
                        );
                    }
                }
            }
        }
    }
    Ok(())
}
