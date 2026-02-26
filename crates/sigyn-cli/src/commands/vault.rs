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
    /// Create a new vault (accepts multiple names for batch creation)
    Create {
        /// Vault name(s)
        #[arg(required = true, num_args = 1..)]
        names: Vec<String>,
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
    /// Delete a vault (owner only)
    Delete {
        /// Vault name
        name: String,
        /// Force deletion even if other members exist
        #[arg(long)]
        force: bool,
    },
    /// Transfer vault ownership to another member
    Transfer {
        /// Vault name
        name: String,
        /// Fingerprint of the new owner (must be an existing member)
        #[arg(long)]
        to: String,
        /// Role to downgrade the old owner to (default: admin). Use "remove" to leave the vault.
        #[arg(long, default_value = "admin")]
        downgrade_to: String,
    },
    /// Accept a pending ownership transfer
    #[command(name = "accept-transfer")]
    AcceptTransfer {
        /// Vault name
        name: String,
    },
    /// Export a vault as an encrypted tar.gz archive
    Export {
        /// Vault name
        name: String,
        /// Output file path
        #[arg(long, short)]
        output: String,
        /// Overwrite existing output file
        #[arg(long)]
        force: bool,
    },
}

fn create_single_vault(
    name: &str,
    org: &Option<String>,
    split_audit: bool,
    loaded: &sigyn_engine::identity::LoadedIdentity,
    fingerprint: &sigyn_engine::crypto::keys::KeyFingerprint,
    paths: &VaultPaths,
    home: &std::path::Path,
) -> Result<VaultManifest> {
    let vault_dir = paths.vault_dir(name);
    if vault_dir.exists() {
        anyhow::bail!("vault '{}' already exists", name);
    }

    let mut manifest = VaultManifest::new(name.to_string(), fingerprint.clone());
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
        .map(|(n, cipher)| (n.clone(), *cipher.key_bytes()))
        .collect();

    let header = envelope::seal_v2(
        vault_cipher.key_bytes(),
        &env_key_bytes,
        recipients,
        &env_recipients,
        vault_id,
    )?;

    std::fs::create_dir_all(paths.env_dir(name))?;

    let sealed_manifest = manifest
        .to_sealed_bytes(&vault_cipher)
        .map_err(|e| anyhow::anyhow!("failed to seal manifest: {}", e))?;
    crate::config::secure_write(&paths.manifest_path(name), &sealed_manifest)?;

    // Write encrypted org_link for org-path scanning
    if let Some(ref org_path) = org {
        let device_key = sigyn_engine::device::load_or_create_device_key(home)?;
        let link_path = paths.vault_dir(name).join(".org_link");
        sigyn_engine::vault::path::write_org_link(&link_path, org_path, &device_key)?;
    }

    let signed_header = envelope::sign_header(&header, loaded.signing_key(), vault_id)
        .map_err(|e| anyhow::anyhow!("failed to sign header: {}", e))?;
    crate::config::secure_write(&paths.members_path(name), &signed_header)?;

    let policy = sigyn_engine::policy::storage::VaultPolicy::new();
    policy.save_signed(
        &paths.policy_path(name),
        &vault_cipher,
        loaded.signing_key(),
        &vault_id,
    )?;

    for env_name in &manifest.environments {
        let env = sigyn_engine::vault::PlaintextEnv::new();
        let env_cipher = env_keys.get(env_name).unwrap();
        let encrypted = sigyn_engine::vault::env_file::encrypt_env(&env, env_cipher, env_name)?;
        sigyn_engine::vault::env_file::write_encrypted_env(
            &paths.env_path(name, env_name),
            &encrypted,
        )?;
    }

    // If --split-audit, initialize audit sub-repo before writing audit log
    if split_audit {
        sigyn_engine::sync::vault_sync::init_audit_repo(&paths.vault_dir(name))?;
    }

    // Audit: vault created
    if let Ok(audit_cipher) = sigyn_engine::crypto::sealed::derive_file_cipher_with_salt(
        vault_cipher.key_bytes(),
        b"sigyn-audit-v1",
        &vault_id,
    ) {
        if let Ok(mut log) = AuditLog::open(&paths.audit_path(name), audit_cipher) {
            let _ = log.append(
                fingerprint,
                AuditAction::VaultCreated,
                None,
                AuditOutcome::Success,
                loaded.signing_key(),
            );
        }
    }

    Ok(manifest)
}

pub fn handle(cmd: VaultCommands, identity: Option<&str>, json: bool) -> Result<()> {
    let home = sigyn_home();
    let store = IdentityStore::new(home.clone());
    let paths = VaultPaths::new(home.clone());

    match cmd {
        VaultCommands::Create {
            names,
            org,
            split_audit,
        } => {
            let loaded = load_identity(&store, identity)?;
            let fingerprint = loaded.identity.fingerprint.clone();
            let is_batch = names.len() > 1;

            // If --org is set, validate the org path exists (once, before the loop)
            if let Some(ref org_path_str) = org {
                let hierarchy_paths =
                    sigyn_engine::hierarchy::path::HierarchyPaths::new(home.clone());
                let org_path = sigyn_engine::hierarchy::path::OrgPath::parse(org_path_str)
                    .map_err(|_| anyhow::anyhow!("invalid org path: {}", org_path_str))?;
                if !hierarchy_paths.manifest_path(&org_path).exists() {
                    anyhow::bail!("org node '{}' not found", org_path_str);
                }
            }

            let mut created = 0usize;
            let mut failed = 0usize;
            let mut json_results: Vec<serde_json::Value> = Vec::new();

            for name in &names {
                if let Err(e) = sigyn_engine::vault::validate_name(name, "vault") {
                    failed += 1;
                    crate::output::print_error(&format!("{}", e));
                    continue;
                }
                match create_single_vault(
                    name,
                    &org,
                    split_audit,
                    &loaded,
                    &fingerprint,
                    &paths,
                    &home,
                ) {
                    Ok(manifest) => {
                        created += 1;
                        if json {
                            json_results.push(serde_json::json!({
                                "name": name,
                                "vault_id": manifest.vault_id.to_string(),
                                "status": "created",
                            }));
                        } else if is_batch {
                            crate::output::print_success(&format!("Vault '{}' created", name));
                        } else {
                            crate::output::print_success(&format!("Vault '{}' created", name));
                            println!("  ID:           {}", manifest.vault_id);
                            println!("  Owner:        {}", style(fingerprint.to_hex()).cyan());
                            println!("  Environments: {}", manifest.environments.join(", "));

                            println!();
                            println!("{}", style("Next steps:").bold());
                            println!(
                                "  sigyn secret set DATABASE_URL='postgres://...' -v {} -e dev",
                                name
                            );
                            println!("  sigyn project init --vault {}", name);
                            println!("  sigyn run -v {} -e dev -- ./your-app", name);

                            // Offer to create .sigyn.toml
                            let identity_name = loaded.identity.profile.name.clone();
                            let _ = crate::project_config::offer_project_init(
                                name,
                                Some(&identity_name),
                                "dev",
                            );
                        }
                    }
                    Err(e) => {
                        failed += 1;
                        if json {
                            json_results.push(serde_json::json!({
                                "name": name,
                                "status": "failed",
                                "error": e.to_string(),
                            }));
                        } else {
                            crate::output::print_error(&format!(
                                "Failed to create vault '{}': {}",
                                name, e
                            ));
                        }
                    }
                }
            }

            if json {
                if is_batch {
                    crate::output::print_json(&json_results)?;
                } else if let Some(result) = json_results.into_iter().next() {
                    crate::output::print_json(&result)?;
                }
            } else if is_batch {
                println!();
                println!(
                    "{} created, {} failed",
                    style(created).green().bold(),
                    if failed > 0 {
                        style(failed).red().bold()
                    } else {
                        style(failed).dim()
                    }
                );
            }

            if failed > 0 && !is_batch {
                anyhow::bail!("vault creation failed");
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
        VaultCommands::Transfer {
            name,
            to,
            downgrade_to,
        } => {
            let ctx = super::secret::unlock_vault(identity, Some(&name), None)?;

            // Owner-only
            if ctx.fingerprint != ctx.manifest.owner {
                anyhow::bail!(
                    "only the vault owner can initiate a transfer (owner: {})",
                    ctx.manifest.owner.to_hex()
                );
            }

            let new_owner_fp = sigyn_engine::crypto::keys::KeyFingerprint::from_hex(&to)
                .map_err(|e| anyhow::anyhow!("invalid fingerprint: {}", e))?;

            if new_owner_fp == ctx.fingerprint {
                anyhow::bail!("cannot transfer ownership to yourself");
            }

            // Verify new owner is an existing vault member
            if !envelope::has_recipient(&ctx.header, &new_owner_fp) {
                anyhow::bail!(
                    "fingerprint {} is not a member of vault '{}'. Invite them first.",
                    to,
                    name
                );
            }

            // Create signed pending transfer
            let downgrade_role = if downgrade_to == "remove" {
                None
            } else {
                Some(downgrade_to.clone())
            };
            let transfer = sigyn_engine::vault::PendingTransfer::sign(
                ctx.manifest.vault_id,
                &name,
                &ctx.fingerprint,
                &new_owner_fp,
                downgrade_role.clone(),
                ctx.loaded_identity.signing_key(),
            );

            // Validate downgrade role early
            if let Some(ref role_name) = downgrade_role {
                sigyn_engine::policy::roles::Role::from_str_name(role_name)
                    .ok_or_else(|| anyhow::anyhow!("unknown role: {}", role_name))?;
            }

            // Write pending transfer file only — do NOT update manifest or policy yet.
            // The actual ownership change happens atomically in accept-transfer.
            let transfer_path = paths.pending_transfer_path(&name);
            let mut buf = Vec::new();
            ciborium::into_writer(&transfer, &mut buf)
                .map_err(|e| anyhow::anyhow!("failed to serialize transfer: {}", e))?;
            crate::config::secure_write(&transfer_path, &buf)?;

            // Audit — fail if audit cannot be written for this critical operation
            {
                let audit_cipher = sigyn_engine::crypto::sealed::derive_file_cipher_with_salt(
                    ctx.vault_cipher.key_bytes(),
                    b"sigyn-audit-v1",
                    &ctx.manifest.vault_id,
                )
                .map_err(|e| anyhow::anyhow!("failed to derive audit cipher: {}", e))?;
                let mut log = AuditLog::open(&paths.audit_path(&name), audit_cipher)
                    .map_err(|e| anyhow::anyhow!("failed to open audit log: {}", e))?;
                log.append(
                    &ctx.fingerprint,
                    AuditAction::OwnershipTransferred {
                        from: ctx.fingerprint.clone(),
                        to: new_owner_fp.clone(),
                    },
                    None,
                    AuditOutcome::Success,
                    ctx.loaded_identity.signing_key(),
                )
                .map_err(|e| anyhow::anyhow!("failed to write audit entry: {}", e))?;
            }

            if json {
                crate::output::print_json(&serde_json::json!({
                    "action": "transfer_initiated",
                    "vault": name,
                    "from": ctx.fingerprint.to_hex(),
                    "to": to,
                    "downgrade_to": downgrade_to,
                }))?;
            } else {
                crate::output::print_success(&format!(
                    "Ownership transfer initiated for vault '{}'",
                    name
                ));
                println!("  New owner: {}", style(&to).cyan());
                println!("  Old owner downgraded to: {}", downgrade_to);
                println!();
                println!("{}", style("Next steps:").bold());
                println!(
                    "  The new owner must run: sigyn vault accept-transfer {}",
                    name
                );
            }
        }
        VaultCommands::AcceptTransfer { name } => {
            let transfer_path = paths.pending_transfer_path(&name);
            if !transfer_path.exists() {
                anyhow::bail!("no pending transfer found for vault '{}'", name);
            }

            // Read and verify the pending transfer
            let transfer_data = std::fs::read(&transfer_path)?;
            let transfer: sigyn_engine::vault::PendingTransfer =
                ciborium::from_reader(&transfer_data[..])
                    .map_err(|e| anyhow::anyhow!("invalid transfer file: {}", e))?;

            // Unlock vault as the new owner
            let ctx = super::secret::unlock_vault(identity, Some(&name), None)?;

            // Verify we are the intended new owner
            if ctx.fingerprint != transfer.to_owner {
                anyhow::bail!(
                    "this transfer is intended for {}, not for you ({})",
                    transfer.to_owner.to_hex(),
                    ctx.fingerprint.to_hex()
                );
            }

            // Check transfer expiry
            if transfer.is_expired() {
                // Clean up expired transfer file
                let _ = std::fs::remove_file(&transfer_path);
                anyhow::bail!(
                    "transfer expired (created {}). The old owner must initiate a new transfer.",
                    transfer.created_at.format("%Y-%m-%d %H:%M UTC")
                );
            }

            // Verify old owner's signature on the transfer.
            // Look up the old owner's verifying key from the header (no identity store needed).
            let old_owner_vk = {
                let id_store = IdentityStore::new(home.clone());
                let identities = id_store
                    .list()
                    .map_err(|e| anyhow::anyhow!("failed to list identities: {}", e))?;
                identities
                    .iter()
                    .find(|id| id.fingerprint == transfer.from_owner)
                    .map(|id| id.signing_pubkey.clone())
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "old owner identity {} not found locally — cannot verify transfer signature",
                            transfer.from_owner.to_hex()
                        )
                    })?
            };
            transfer
                .verify(&old_owner_vk)
                .map_err(|_| anyhow::anyhow!("transfer signature verification failed"))?;

            // Now apply the ownership change atomically:
            // 1. Update manifest owner
            let mut manifest = ctx.manifest.clone();
            manifest.owner = ctx.fingerprint.clone();
            let sealed = manifest
                .to_sealed_bytes(&ctx.vault_cipher)
                .map_err(|e| anyhow::anyhow!("failed to seal manifest: {}", e))?;
            crate::config::secure_write(&paths.manifest_path(&name), &sealed)?;

            // 2. Update policy: downgrade old owner, remove new owner from members
            let mut policy = ctx.policy.clone();
            if let Some(ref role_name) = transfer.downgrade_role {
                if let Some(role) = sigyn_engine::policy::roles::Role::from_str_name(role_name) {
                    let member = sigyn_engine::policy::member::MemberPolicy::new(
                        transfer.from_owner.clone(),
                        role,
                    );
                    policy.add_member(member);
                }
            }
            policy.remove_member(&ctx.fingerprint);

            // 3. Re-sign header with new owner's signing key
            let signed = envelope::sign_header(
                &ctx.header,
                ctx.loaded_identity.signing_key(),
                manifest.vault_id,
            )
            .map_err(|e| anyhow::anyhow!("failed to sign header: {}", e))?;
            crate::config::secure_write(&paths.members_path(&name), &signed)?;

            // 4. Re-sign policy with new owner's signing key
            policy.save_signed(
                &paths.policy_path(&name),
                &ctx.vault_cipher,
                ctx.loaded_identity.signing_key(),
                &manifest.vault_id,
            )?;

            // Delete pending transfer file
            std::fs::remove_file(&transfer_path)?;

            // Update TOFU pin to new owner's signing pubkey
            let device_key = sigyn_engine::device::load_or_create_device_key(&home)?;
            if let Ok(mut pin_store) =
                sigyn_engine::vault::local_state::load_pinned_store(&home, &device_key)
            {
                let state = pin_store.entry_mut(&name);
                state.pin = Some(sigyn_engine::vault::VaultPin {
                    vault_id: manifest.vault_id,
                    owner_fingerprint: ctx.fingerprint.clone(),
                    owner_signing_pubkey_bytes: ctx
                        .loaded_identity
                        .identity
                        .signing_pubkey
                        .to_bytes()
                        .to_vec(),
                    pinned_at: chrono::Utc::now(),
                });
                let _ = sigyn_engine::vault::local_state::save_pinned_store(
                    &pin_store,
                    &home,
                    &device_key,
                );
            }

            // Audit
            if let Ok(audit_cipher) = sigyn_engine::crypto::sealed::derive_file_cipher_with_salt(
                ctx.vault_cipher.key_bytes(),
                b"sigyn-audit-v1",
                &manifest.vault_id,
            ) {
                if let Ok(mut log) = AuditLog::open(&paths.audit_path(&name), audit_cipher) {
                    let _ = log.append(
                        &ctx.fingerprint,
                        AuditAction::OwnershipTransferAccepted {
                            by: ctx.fingerprint.clone(),
                        },
                        None,
                        AuditOutcome::Success,
                        ctx.loaded_identity.signing_key(),
                    );
                }
            }

            if json {
                crate::output::print_json(&serde_json::json!({
                    "action": "transfer_accepted",
                    "vault": name,
                    "new_owner": ctx.fingerprint.to_hex(),
                    "from_owner": transfer.from_owner.to_hex(),
                }))?;
            } else {
                crate::output::print_success(&format!(
                    "Ownership transfer accepted for vault '{}'",
                    name
                ));
                println!(
                    "  You ({}) are now the owner.",
                    style(&ctx.fingerprint.to_hex()[..12]).cyan()
                );
            }
        }
        VaultCommands::Export {
            name,
            output,
            force,
        } => {
            let ctx = super::secret::unlock_vault(identity, Some(&name), None)?;
            super::secret::check_access(
                &ctx,
                sigyn_engine::policy::engine::AccessAction::ManagePolicy,
                None,
            )?;

            let vault_dir = paths
                .safe_vault_dir(&name)
                .map_err(|e| anyhow::anyhow!("symlink safety check failed: {}", e))?;

            // Refuse to overwrite existing files unless --force
            let output_path = std::path::Path::new(&output);
            if output_path.exists() && !force {
                anyhow::bail!(
                    "output file '{}' already exists. Use --force to overwrite.",
                    output
                );
            }

            // Create tar.gz of vault directory (all files are already encrypted on disk)
            let output_file = std::fs::File::create(&output)
                .map_err(|e| anyhow::anyhow!("failed to create output file: {}", e))?;
            let gz = flate2::write::GzEncoder::new(output_file, flate2::Compression::default());
            let mut tar_builder = tar::Builder::new(gz);
            tar_builder
                .append_dir_all(&name, &vault_dir)
                .map_err(|e| anyhow::anyhow!("failed to build archive: {}", e))?;
            tar_builder
                .finish()
                .map_err(|e| anyhow::anyhow!("failed to finish archive: {}", e))?;

            // Audit
            if let Ok(audit_cipher) = sigyn_engine::crypto::sealed::derive_file_cipher_with_salt(
                ctx.vault_cipher.key_bytes(),
                b"sigyn-audit-v1",
                &ctx.manifest.vault_id,
            ) {
                if let Ok(mut log) = AuditLog::open(&paths.audit_path(&name), audit_cipher) {
                    let _ = log.append(
                        &ctx.fingerprint,
                        AuditAction::VaultExported,
                        None,
                        AuditOutcome::Success,
                        ctx.loaded_identity.signing_key(),
                    );
                }
            }

            if json {
                crate::output::print_json(&serde_json::json!({
                    "action": "vault_exported",
                    "vault": name,
                    "output": output,
                }))?;
            } else {
                crate::output::print_success(&format!("Vault '{}' exported to '{}'", name, output));
                println!("  All data is encrypted — no plaintext secrets in the archive.");
            }
        }
        VaultCommands::Delete { name, force } => {
            let manifest_path = paths.manifest_path(&name);
            if !manifest_path.exists() {
                anyhow::bail!("vault '{}' not found", name);
            }

            // Unlock vault to verify ownership
            let ctx = super::secret::unlock_vault(identity, Some(&name), None)?;
            let manifest = &ctx.manifest;

            // Owner-only check
            if ctx.fingerprint != manifest.owner {
                anyhow::bail!(
                    "only the vault owner can delete a vault (owner: {})",
                    manifest.owner.to_hex()
                );
            }

            // Check for other members
            if !force {
                let member_count = ctx.policy.members.len();
                if member_count > 0 {
                    let member_fps: Vec<String> = ctx
                        .policy
                        .members
                        .values()
                        .take(5)
                        .map(|m| m.fingerprint.to_hex()[..12].to_string())
                        .collect();
                    anyhow::bail!(
                        "vault '{}' has {} other member(s): {}{}. \
                         Revoke their access first, or use --force.",
                        name,
                        member_count,
                        member_fps.join(", "),
                        if member_count > 5 { ", ..." } else { "" }
                    );
                }
            }

            // Confirmation: must type vault name
            if crate::config::is_interactive() {
                let typed: String = dialoguer::Input::new()
                    .with_prompt(format!(
                        "Type '{}' to confirm deletion (this cannot be undone)",
                        name
                    ))
                    .interact_text()?;
                if typed != name {
                    anyhow::bail!("vault name does not match — deletion aborted");
                }
            } else if !force {
                anyhow::bail!("use --force in non-interactive mode");
            }

            // Write audit entry BEFORE destroying data — fail if audit cannot be written
            let vault_id = manifest.vault_id;
            let audit_cipher = sigyn_engine::crypto::sealed::derive_file_cipher_with_salt(
                ctx.vault_cipher.key_bytes(),
                b"sigyn-audit-v1",
                &vault_id,
            )
            .map_err(|e| anyhow::anyhow!("failed to derive audit cipher: {}", e))?;
            let mut log = AuditLog::open(&paths.audit_path(&name), audit_cipher)
                .map_err(|e| anyhow::anyhow!("failed to open audit log: {}", e))?;
            log.append(
                &ctx.fingerprint,
                AuditAction::VaultDeleted { vault_id },
                None,
                AuditOutcome::Success,
                ctx.loaded_identity.signing_key(),
            )
            .map_err(|e| anyhow::anyhow!("failed to write audit entry: {}", e))?;

            // Best-effort sync push to persist audit on remote
            let _ = crate::commands::sync::auto_push(&name);

            // Remove vault directory (symlink-safe)
            let vault_dir = paths
                .safe_vault_dir(&name)
                .map_err(|e| anyhow::anyhow!("symlink safety check failed: {}", e))?;
            if vault_dir.exists() {
                std::fs::remove_dir_all(&vault_dir)?;
            }

            // Remove from pinned vaults
            let device_key = sigyn_engine::device::load_or_create_device_key(&home)?;
            if let Ok(mut pin_store) =
                sigyn_engine::vault::local_state::load_pinned_store(&home, &device_key)
            {
                pin_store.remove(&name);
                let _ = sigyn_engine::vault::local_state::save_pinned_store(
                    &pin_store,
                    &home,
                    &device_key,
                );
            }

            if json {
                crate::output::print_json(&serde_json::json!({
                    "action": "vault_deleted",
                    "name": name,
                    "vault_id": vault_id.to_string(),
                }))?;
            } else {
                crate::output::print_success(&format!("Vault '{}' deleted", name));
            }
        }
    }
    Ok(())
}
