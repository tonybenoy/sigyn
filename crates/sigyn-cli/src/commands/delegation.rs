use anyhow::{Context, Result};
use clap::Subcommand;
use console::style;
use sigyn_engine::audit::entry::AuditOutcome;
use sigyn_engine::audit::{AuditAction, AuditLog};
use sigyn_engine::crypto::envelope::{self, EnvelopeHeader};
use sigyn_engine::crypto::keys::KeyFingerprint;
use sigyn_engine::delegation::invite::InvitationFile;
use sigyn_engine::delegation::tree::DelegationNode;
use sigyn_engine::identity::keygen::IdentityStore;
use sigyn_engine::policy::engine::AccessAction;
use sigyn_engine::policy::member::MemberPolicy;
use sigyn_engine::policy::roles::Role;
use sigyn_engine::policy::storage::VaultPolicy;
use sigyn_engine::policy::storage::VaultPolicyExt;
use sigyn_engine::vault::{env_file, VaultPaths};

use super::secret::{check_access, unlock_vault, UnlockedVaultContext};
use crate::config::sigyn_home;

#[derive(Subcommand)]
pub enum DelegationCommands {
    /// Show the delegation tree
    Tree,
    /// Create an invitation
    Invite {
        /// Invitee's public key fingerprint
        #[arg(long)]
        pubkey: String,
        /// Role to assign
        #[arg(long, default_value = "readonly")]
        role: String,
        /// Allowed environments (comma-separated)
        #[arg(long, default_value = "*")]
        envs: String,
    },
    /// Accept an invitation
    Accept {
        /// Invitation ID (UUID) or path to invitation file
        invitation: String,
    },
    /// Revoke member(s)' access
    Revoke {
        /// Member fingerprint(s) to revoke
        #[arg(required = true, num_args = 1..)]
        fingerprints: Vec<String>,
        /// Also revoke all members they invited
        #[arg(long)]
        cascade: bool,
    },
    /// List pending invitations
    Pending,
    /// Grant member(s) access to an additional environment (v2 only)
    GrantEnv {
        /// Member fingerprint(s)
        #[arg(required = true, num_args = 1..)]
        fingerprints: Vec<String>,
        /// Environment name to grant
        #[arg(long)]
        env: String,
    },
    /// Bulk invite members from a JSON file
    #[command(name = "bulk-invite")]
    BulkInvite {
        /// Path to JSON file with member definitions
        #[arg(long)]
        file: String,
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
    /// Bulk revoke members from a JSON file or list
    #[command(name = "bulk-revoke")]
    BulkRevoke {
        /// Path to JSON file with fingerprint list
        #[arg(long)]
        file: String,
        /// Also revoke all members they invited
        #[arg(long)]
        cascade: bool,
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
    /// Revoke member(s)' access to a specific environment (v2 only)
    RevokeEnv {
        /// Member fingerprint(s)
        #[arg(required = true, num_args = 1..)]
        fingerprints: Vec<String>,
        /// Environment name to revoke
        #[arg(long)]
        env: String,
    },
}

/// Build a delegation tree from the vault policy members.
/// Returns a list of root-level DelegationNode trees.
fn build_delegation_tree(policy: &VaultPolicy, owner_fp: &KeyFingerprint) -> Vec<DelegationNode> {
    // First, collect all members into nodes
    let members: Vec<&MemberPolicy> = policy.members.values().collect();

    // Build nodes for members that have no delegated_by (root-level members delegated by owner)
    // or whose delegated_by matches the owner
    fn build_children(
        parent_fp: &KeyFingerprint,
        members: &[&MemberPolicy],
        depth: u32,
    ) -> Vec<DelegationNode> {
        let mut children = Vec::new();
        for member in members {
            let is_child = match &member.delegated_by {
                Some(delegator) => delegator == parent_fp,
                None => false,
            };
            if is_child {
                let grandchildren = build_children(&member.fingerprint, members, depth + 1);
                children.push(DelegationNode {
                    fingerprint: member.fingerprint.clone(),
                    name: member.fingerprint.to_hex()[..12].to_string(),
                    role: member.role,
                    depth,
                    delegated_by: member.delegated_by.clone(),
                    children: grandchildren,
                });
            }
        }
        children
    }

    // Root-level members: those with no delegated_by or delegated_by == owner
    let mut roots = Vec::new();
    for member in &members {
        let is_root = match &member.delegated_by {
            Some(delegator) => delegator == owner_fp,
            None => true,
        };
        if is_root {
            let children = build_children(&member.fingerprint, &members, 1);
            roots.push(DelegationNode {
                fingerprint: member.fingerprint.clone(),
                name: member.fingerprint.to_hex()[..12].to_string(),
                role: member.role,
                depth: 0,
                delegated_by: member.delegated_by.clone(),
                children,
            });
        }
    }

    roots
}

/// Save the envelope header to disk (signed with the actor's signing key).
fn save_header(
    header: &EnvelopeHeader,
    paths: &VaultPaths,
    vault_name: &str,
    signing_key: &sigyn_engine::crypto::keys::SigningKeyPair,
    vault_id: uuid::Uuid,
) -> Result<()> {
    let signed = envelope::sign_header(header, signing_key, vault_id)
        .map_err(|e| anyhow::anyhow!("failed to sign header: {}", e))?;
    let members_path = paths.members_path(vault_name);
    crate::config::secure_write(&members_path, &signed)
        .map_err(|e| anyhow::anyhow!("failed to write members file: {}", e))?;
    Ok(())
}

/// Append an audit entry, then enforce the vault's audit push policy.
fn audit_log(ctx: &UnlockedVaultContext, action: AuditAction) -> Result<()> {
    let audit_path = ctx.paths.audit_path(&ctx.vault_name);
    let audit_cipher = match sigyn_engine::crypto::sealed::derive_file_cipher_with_salt(
        ctx.vault_cipher.key_bytes(),
        b"sigyn-audit-v1",
        &ctx.manifest.vault_id,
    ) {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };
    if let Ok(mut log) = AuditLog::open(&audit_path, audit_cipher) {
        let _ = log.append(
            &ctx.fingerprint,
            action.clone(),
            Some(ctx.env_name.clone()),
            AuditOutcome::Success,
            ctx.loaded_identity.signing_key(),
        );
    }

    // Enforce audit push policy
    let audit_mode = ctx.policy.audit_mode;
    if audit_mode != sigyn_engine::policy::AuditMode::Offline {
        let vault_dir = ctx.paths.vault_dir(&ctx.vault_name);
        let engine = sigyn_engine::sync::git::GitSyncEngine::new(vault_dir);
        let msg = format!("sigyn: audit ({})", action.short_name());
        let deploy_key = sigyn_engine::sync::deploy_key::load_and_unseal(
            &ctx.paths.deploy_key_path(&ctx.vault_name),
            &ctx.vault_cipher,
        )
        .ok()
        .flatten();
        let dk_bytes = deploy_key.as_ref().map(|(k, _)| k.as_slice());
        if let sigyn_engine::audit::AuditPushOutcome::BestEffortFailed(reason) =
            sigyn_engine::audit::enforce_audit_push(audit_mode, &engine, &msg, dk_bytes)?
        {
            eprintln!(
                "{} audit push failed (best-effort mode): {}",
                style("warning:").yellow().bold(),
                reason
            );
        }
    }

    Ok(())
}

pub fn handle(
    cmd: DelegationCommands,
    vault: Option<&str>,
    identity: Option<&str>,
    json: bool,
) -> Result<()> {
    let vault_name = vault.unwrap_or("default");

    match cmd {
        DelegationCommands::Tree => {
            let ctx = unlock_vault(identity, Some(vault_name), None)?;

            let trees = build_delegation_tree(&ctx.policy, &ctx.manifest.owner);

            if json {
                crate::output::print_json(&serde_json::json!({
                    "vault": ctx.vault_name,
                    "owner": ctx.manifest.owner.to_hex(),
                    "members": trees.len(),
                }))?;
            } else {
                println!(
                    "{} for vault '{}'",
                    style("Delegation Tree").bold(),
                    ctx.vault_name
                );
                println!("{}", style("\u{2500}".repeat(60)).dim());
                println!("  [owner] {} (you)", &ctx.manifest.owner.to_hex()[..12]);

                if trees.is_empty() {
                    println!("  \u{2514}\u{2500}\u{2500} (no delegated members yet)");
                } else {
                    for (i, node) in trees.iter().enumerate() {
                        let prefix = if i == trees.len() - 1 {
                            "\u{2514}\u{2500}\u{2500}"
                        } else {
                            "\u{251c}\u{2500}\u{2500}"
                        };
                        println!("  {} {}", prefix, format_node(node));
                        print_children(node, "  ", i == trees.len() - 1);
                    }
                }
            }
        }
        DelegationCommands::Invite { pubkey, role, envs } => {
            let ctx = unlock_vault(identity, Some(vault_name), None)?;
            check_access(&ctx, AccessAction::ManageMembers, None)?;

            let role_enum = Role::from_str_name(&role).ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown role: '{}'. Use: readonly, auditor, operator, contributor, manager, admin",
                    role
                )
            })?;

            // Validate: delegator cannot invite with a role higher than their own
            if ctx.fingerprint == ctx.manifest.owner {
                // Owner can invite any role except Owner itself
                if role_enum == Role::Owner {
                    anyhow::bail!("cannot invite with 'owner' role — ownership is not delegable");
                }
            } else if let Some(delegator) = ctx.policy.get_member(&ctx.fingerprint) {
                if role_enum.level() >= delegator.role.level() {
                    anyhow::bail!(
                        "cannot invite with role '{}' (level {}) — your role '{}' (level {}) must be higher",
                        role_enum,
                        role_enum.level(),
                        delegator.role,
                        delegator.role.level()
                    );
                }
            } else {
                anyhow::bail!("you are not a member of this vault");
            }

            let invitee_fp = KeyFingerprint::from_hex(&pubkey)
                .map_err(|e| anyhow::anyhow!("invalid fingerprint: {}", e))?;

            let allowed_envs: Vec<String> = envs.split(',').map(|s| s.trim().to_string()).collect();

            // Enforce delegation depth, delegatee limits, and role level (non-owners only)
            if ctx.fingerprint != ctx.manifest.owner {
                sigyn_engine::delegation::validate_delegation(
                    &ctx.policy,
                    &ctx.fingerprint,
                    role_enum,
                    Some(&ctx.manifest.owner),
                )
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            }

            // Build the member policy
            let mut member = MemberPolicy::new(invitee_fp.clone(), role_enum);
            member.allowed_envs = allowed_envs.clone();
            member.delegated_by = Some(ctx.fingerprint.clone());
            // Inherit reduced delegation depth from delegator
            if let Some(delegator) = ctx.policy.get_member(&ctx.fingerprint) {
                member.max_delegation_depth = delegator.max_delegation_depth.saturating_sub(1);
            }

            // Look up the invitee's public key from the identity store
            let home = sigyn_home();
            let store = IdentityStore::new(home.clone());
            let identities = store
                .list()
                .map_err(|e| anyhow::anyhow!("failed to list identities: {}", e))?;
            let invitee_identity = identities
                .iter()
                .find(|id| id.fingerprint == invitee_fp)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "invitee identity not found in local store for fingerprint {}. \
                         The invitee must first create an identity on this machine.",
                        invitee_fp
                    )
                })?;

            // Add the member to policy
            let mut policy = ctx.policy.clone();
            policy.add_member(member);

            // Use the already-verified header from unlock_vault()
            let mut header: EnvelopeHeader = ctx.header.clone();

            // Add vault_key_slot + per-env slots
            envelope::add_vault_key_recipient(
                &mut header,
                ctx.vault_cipher.key_bytes(),
                &invitee_identity.encryption_pubkey,
                ctx.manifest.vault_id,
            )
            .map_err(|e| anyhow::anyhow!("failed to add vault key recipient: {}", e))?;

            // Add env slots for each allowed env
            let envs_to_grant: Vec<String> = if allowed_envs.iter().any(|e| e == "*") {
                ctx.manifest.environments.clone()
            } else {
                allowed_envs.clone()
            };
            for env_name in &envs_to_grant {
                let env_key = ctx.env_ciphers.get(env_name).ok_or_else(|| {
                    anyhow::anyhow!(
                        "cannot grant access to env '{}' — you don't hold its key",
                        env_name
                    )
                })?;
                envelope::add_env_recipient(
                    &mut header,
                    env_name,
                    env_key.key_bytes(),
                    &invitee_identity.encryption_pubkey,
                    ctx.manifest.vault_id,
                )
                .map_err(|e| {
                    anyhow::anyhow!("failed to add env recipient for '{}': {}", env_name, e)
                })?;
            }

            // Save policy and header
            policy
                .save_signed(
                    &ctx.paths.policy_path(&ctx.vault_name),
                    &ctx.vault_cipher,
                    ctx.loaded_identity.signing_key(),
                    &ctx.manifest.vault_id,
                )
                .map_err(|e| anyhow::anyhow!("failed to save policy: {}", e))?;
            save_header(
                &header,
                &ctx.paths,
                &ctx.vault_name,
                ctx.loaded_identity.signing_key(),
                ctx.manifest.vault_id,
            )?;

            // Write invitation file to ~/.sigyn/invitations/<uuid>.json
            let invitation_id = uuid::Uuid::new_v4();
            let secret_patterns = vec!["*".into()];
            let max_delegation_depth = 0u32;
            let signing_payload = InvitationFile::signing_payload(
                invitation_id,
                &ctx.vault_name,
                ctx.manifest.vault_id,
                &ctx.fingerprint,
                role_enum,
                &allowed_envs,
                &secret_patterns,
                max_delegation_depth,
            );
            let invitation_sig = ctx.loaded_identity.signing_key().sign(&signing_payload);

            let now = chrono::Utc::now();
            let invitation_file = InvitationFile {
                id: invitation_id,
                vault_name: ctx.vault_name.clone(),
                vault_id: ctx.manifest.vault_id,
                inviter_fingerprint: ctx.fingerprint.clone(),
                proposed_role: role_enum,
                allowed_envs: allowed_envs.clone(),
                secret_patterns,
                max_delegation_depth,
                signature: invitation_sig,
                created_at: now,
                expires_at: Some(now + chrono::Duration::days(7)),
            };

            let invitations_dir = home.join("invitations");
            std::fs::create_dir_all(&invitations_dir)
                .context("failed to create invitations directory")?;
            let invitation_path = invitations_dir.join(format!("{}.json", invitation_id));
            let invitation_json = serde_json::to_string_pretty(&invitation_file)
                .context("failed to serialize invitation")?;
            crate::config::secure_write(&invitation_path, invitation_json.as_bytes())
                .map_err(|e| anyhow::anyhow!("failed to write invitation file: {}", e))?;

            // Audit
            audit_log(
                &ctx,
                AuditAction::MemberInvited {
                    fingerprint: invitee_fp.clone(),
                },
            )?;

            if json {
                crate::output::print_json(&serde_json::json!({
                    "action": "invitation_created",
                    "invitee": pubkey,
                    "role": role_enum.to_string(),
                    "envs": allowed_envs,
                    "invitation_id": invitation_id.to_string(),
                    "invitation_path": invitation_path.display().to_string(),
                }))?;
            } else {
                crate::output::print_success(&format!(
                    "Invited {} as {} (envs: {})",
                    &pubkey[..12.min(pubkey.len())],
                    role_enum,
                    envs
                ));
                println!("  Invitation file: {}", invitation_path.display());
            }
        }
        DelegationCommands::Accept { invitation } => {
            // Accept UUID, UUID prefix, or file path
            let path = {
                let p = std::path::Path::new(&invitation);
                if p.exists() {
                    p.to_path_buf()
                } else {
                    // Try to find by UUID in the invitations directory
                    let inv_dir = sigyn_home().join("invitations");
                    let mut found = None;
                    if inv_dir.is_dir() {
                        if let Ok(entries) = std::fs::read_dir(&inv_dir) {
                            for entry in entries.flatten() {
                                let name = entry.file_name().to_string_lossy().to_string();
                                if name.ends_with(".json") {
                                    let stem = name.trim_end_matches(".json");
                                    if stem == invitation || stem.starts_with(&invitation) {
                                        if found.is_some() {
                                            anyhow::bail!(
                                                "ambiguous invitation prefix '{}' — multiple matches. Use a longer prefix.",
                                                invitation
                                            );
                                        }
                                        found = Some(entry.path());
                                    }
                                }
                            }
                        }
                    }
                    found.ok_or_else(|| {
                        anyhow::anyhow!(
                            "invitation '{}' not found.\n  \
                         Use a file path, full UUID, or UUID prefix.\n  \
                         List pending invitations with: sigyn delegation pending",
                            invitation
                        )
                    })?
                }
            };

            // Read and parse the invitation file
            let contents =
                std::fs::read_to_string(path).context("failed to read invitation file")?;
            let invite_file: InvitationFile =
                serde_json::from_str(&contents).context("invalid invitation file format")?;

            // Verify the inviter's signature by looking up their identity in the store
            let home = sigyn_home();
            let store = IdentityStore::new(home);
            let identities = store
                .list()
                .map_err(|e| anyhow::anyhow!("failed to list identities: {}", e))?;

            let inviter_identity = identities
                .iter()
                .find(|id| id.fingerprint == invite_file.inviter_fingerprint);

            let inviter = inviter_identity.ok_or_else(|| {
                anyhow::anyhow!(
                    "inviter identity {} not found locally — cannot verify invitation signature.\n  \
                     Import the inviter's identity first, then re-accept the invitation.",
                    invite_file.inviter_fingerprint.to_hex()
                )
            })?;
            invite_file.verify(&inviter.signing_pubkey).map_err(|_| {
                anyhow::anyhow!(
                    "invitation signature verification failed for inviter {}",
                    invite_file.inviter_fingerprint.to_hex()
                )
            })?;

            // Check invitation expiry
            if let Some(expires_at) = invite_file.expires_at {
                if chrono::Utc::now() > expires_at {
                    anyhow::bail!(
                        "invitation {} has expired (expired at {}). Ask the inviter to create a new invitation.",
                        invite_file.id,
                        expires_at.format("%Y-%m-%d %H:%M UTC")
                    );
                }
            }

            if json {
                crate::output::print_json(&serde_json::json!({
                    "action": "invitation_accepted",
                    "invitation_id": invite_file.id.to_string(),
                    "vault_name": invite_file.vault_name,
                    "vault_id": invite_file.vault_id.to_string(),
                    "inviter": invite_file.inviter_fingerprint.to_hex(),
                    "role": invite_file.proposed_role.to_string(),
                    "envs": invite_file.allowed_envs,
                    "signature_verified": true,
                }))?;
            } else {
                crate::output::print_success("Invitation accepted");
                println!("  Invitation ID: {}", invite_file.id);
                println!("  Vault:         {}", invite_file.vault_name);
                println!(
                    "  Invited by:    {}",
                    &invite_file.inviter_fingerprint.to_hex()[..12]
                );
                println!("  Role:          {}", invite_file.proposed_role);
                println!("  Environments:  {}", invite_file.allowed_envs.join(", "));
                println!("  Signature:     verified");

                eprintln!();
                eprintln!(
                    "{} The vault owner must sync for your access to take effect.",
                    style("note:").cyan().bold()
                );
                println!();
                println!("{}", style("Next steps:").bold());
                println!("  sigyn sync pull -v {}", invite_file.vault_name);
                println!(
                    "  sigyn secret list -v {} -e {}",
                    invite_file.vault_name,
                    invite_file
                        .allowed_envs
                        .first()
                        .map(|s| s.as_str())
                        .unwrap_or("dev")
                );

                // Offer to create .sigyn.toml pointing at the accepted vault
                let first_env = invite_file
                    .allowed_envs
                    .first()
                    .map(|s| s.as_str())
                    .unwrap_or("dev");
                let _ = crate::project_config::offer_project_init(
                    &invite_file.vault_name,
                    None,
                    first_env,
                );
            }
        }
        DelegationCommands::Revoke {
            fingerprints,
            cascade,
        } => {
            let ctx = unlock_vault(identity, Some(vault_name), None)?;
            check_access(&ctx, AccessAction::ManageMembers, None)?;

            let is_batch = fingerprints.len() > 1;
            let mut revoked = 0usize;
            let mut failed = 0usize;
            let mut json_results: Vec<serde_json::Value> = Vec::new();

            let home = sigyn_home();
            let store = IdentityStore::new(home);
            let identities = store
                .list()
                .map_err(|e| anyhow::anyhow!("failed to list identities: {}", e))?;

            // Mutable state that accumulates across iterations
            let mut header: EnvelopeHeader = ctx.header.clone();
            let mut policy = ctx.policy.clone();
            let mut effective_vault_cipher_key = *ctx.vault_cipher.key_bytes();

            for fingerprint in &fingerprints {
                let target_fp = match KeyFingerprint::from_hex(fingerprint) {
                    Ok(fp) => fp,
                    Err(e) => {
                        failed += 1;
                        if json {
                            json_results.push(serde_json::json!({
                                "fingerprint": fingerprint,
                                "status": "failed",
                                "error": e.to_string(),
                            }));
                        } else {
                            crate::output::print_error(&format!(
                                "invalid fingerprint '{}': {}",
                                fingerprint, e
                            ));
                        }
                        continue;
                    }
                };

                // Build remaining pubkeys from current policy state
                let mut remaining_pubkeys: Vec<(
                    KeyFingerprint,
                    sigyn_engine::crypto::keys::X25519PublicKey,
                )> = Vec::new();
                remaining_pubkeys.push((
                    ctx.fingerprint.clone(),
                    ctx.loaded_identity.identity.encryption_pubkey.clone(),
                ));
                for member_policy in policy.members.values() {
                    if let Some(id) = identities
                        .iter()
                        .find(|id| id.fingerprint == member_policy.fingerprint)
                    {
                        remaining_pubkeys
                            .push((id.fingerprint.clone(), id.encryption_pubkey.clone()));
                    }
                }

                // Build member_env_access map
                let mut member_env_access = std::collections::BTreeMap::new();
                member_env_access
                    .insert(ctx.fingerprint.clone(), ctx.manifest.environments.clone());
                for mp in policy.members.values() {
                    let envs = if mp.allowed_envs.iter().any(|e| e == "*") {
                        ctx.manifest.environments.clone()
                    } else {
                        mp.allowed_envs.clone()
                    };
                    member_env_access.insert(mp.fingerprint.clone(), envs);
                }

                let result_v2 = match sigyn_engine::delegation::revoke::revoke_member(
                    &target_fp,
                    cascade,
                    &mut policy,
                    &mut header,
                    ctx.manifest.vault_id,
                    &remaining_pubkeys,
                    &member_env_access,
                ) {
                    Ok((r,)) => r,
                    Err(e) => {
                        failed += 1;
                        if json {
                            json_results.push(serde_json::json!({
                                "fingerprint": fingerprint,
                                "status": "failed",
                                "error": e.to_string(),
                            }));
                        } else {
                            crate::output::print_error(&format!(
                                "revocation failed for '{}': {}",
                                &fingerprint[..12.min(fingerprint.len())],
                                e
                            ));
                        }
                        continue;
                    }
                };

                // Re-encrypt affected env files
                for (env_name, new_cipher) in &result_v2.rotated_env_ciphers {
                    let env_path = ctx.paths.env_path(&ctx.vault_name, env_name);
                    if env_path.exists() {
                        let old_cipher = ctx.cipher_for_env(env_name).ok_or_else(|| {
                            anyhow::anyhow!("no access to env '{}' for re-encryption", env_name)
                        })?;
                        let encrypted = env_file::read_encrypted_env(&env_path)?;
                        let plaintext = env_file::decrypt_env(&encrypted, old_cipher)?;
                        let re_encrypted = env_file::encrypt_env(&plaintext, new_cipher, env_name)?;
                        env_file::write_encrypted_env(&env_path, &re_encrypted)?;
                    }
                }

                // Re-encrypt manifest, audit log, and policy with new vault cipher if rotated
                if let Some(ref new_vc) = result_v2.new_vault_cipher {
                    // Re-encrypt manifest with new vault key
                    let manifest_path = ctx.paths.manifest_path(&ctx.vault_name);
                    let manifest_data = std::fs::read(&manifest_path)?;
                    let manifest = sigyn_engine::vault::VaultManifest::from_sealed_bytes(
                        &ctx.vault_cipher,
                        &manifest_data,
                        ctx.manifest.vault_id,
                    )?;
                    let resealed = manifest.to_sealed_bytes(new_vc)?;
                    crate::config::secure_write(&manifest_path, &resealed)?;

                    // Re-encrypt audit log with new vault cipher
                    let audit_path = ctx.paths.audit_path(&ctx.vault_name);
                    if audit_path.exists() {
                        let old_audit_cipher =
                            sigyn_engine::crypto::sealed::derive_file_cipher_with_salt(
                                ctx.vault_cipher.key_bytes(),
                                b"sigyn-audit-v1",
                                &ctx.manifest.vault_id,
                            )?;
                        let new_audit_cipher =
                            sigyn_engine::crypto::sealed::derive_file_cipher_with_salt(
                                new_vc.key_bytes(),
                                b"sigyn-audit-v1",
                                &ctx.manifest.vault_id,
                            )?;
                        AuditLog::rekey(&audit_path, old_audit_cipher, new_audit_cipher)
                            .map_err(|e| anyhow::anyhow!("failed to rekey audit log: {}", e))?;
                    }

                    // Update the effective vault cipher key for saving policy below
                    effective_vault_cipher_key = *new_vc.key_bytes();
                }

                // Audit
                audit_log(
                    &ctx,
                    AuditAction::MemberRevoked {
                        fingerprint: target_fp.clone(),
                    },
                )?;
                for cascade_fp in &result_v2.cascade_revoked {
                    audit_log(
                        &ctx,
                        AuditAction::MemberRevoked {
                            fingerprint: cascade_fp.clone(),
                        },
                    )?;
                }

                crate::notifications::try_notify(
                    &ctx.vault_name,
                    None,
                    None,
                    &ctx.fingerprint.to_hex(),
                    "member.revoked",
                    &format!(
                        "Member {} revoked{}",
                        &fingerprint[..12.min(fingerprint.len())],
                        if cascade { " (cascade)" } else { "" }
                    ),
                );

                revoked += 1;

                if json {
                    let cascade_hex: Vec<String> = result_v2
                        .cascade_revoked
                        .iter()
                        .map(|fp| fp.to_hex())
                        .collect();
                    json_results.push(serde_json::json!({
                        "action": "revoked",
                        "fingerprint": fingerprint,
                        "cascade": cascade,
                        "cascade_revoked": cascade_hex,
                        "affected_envs": result_v2.affected_envs,
                        "env_keys_rotated": result_v2.rotated_env_ciphers.len(),
                    }));
                } else if !is_batch {
                    crate::output::print_success(&format!(
                        "Revoked access for {}{}",
                        &fingerprint[..12.min(fingerprint.len())],
                        if cascade { " (cascade)" } else { "" }
                    ));
                    if !result_v2.cascade_revoked.is_empty() {
                        println!(
                            "  Cascade revoked {} additional member(s)",
                            result_v2.cascade_revoked.len()
                        );
                    }
                    if !result_v2.affected_envs.is_empty() {
                        crate::output::print_info(&format!(
                            "Env keys rotated for: {}",
                            result_v2.affected_envs.join(", ")
                        ));
                    }
                } else {
                    crate::output::print_success(&format!(
                        "Revoked {}{}",
                        &fingerprint[..12.min(fingerprint.len())],
                        if cascade { " (cascade)" } else { "" }
                    ));
                }
            }

            // Save policy and header once after all revocations
            // Use effective vault cipher which may have been rotated during revocation
            let save_cipher =
                sigyn_engine::crypto::vault_cipher::VaultCipher::new(effective_vault_cipher_key);
            policy
                .save_signed(
                    &ctx.paths.policy_path(&ctx.vault_name),
                    &save_cipher,
                    ctx.loaded_identity.signing_key(),
                    &ctx.manifest.vault_id,
                )
                .map_err(|e| anyhow::anyhow!("failed to save policy: {}", e))?;
            save_header(
                &header,
                &ctx.paths,
                &ctx.vault_name,
                ctx.loaded_identity.signing_key(),
                ctx.manifest.vault_id,
            )?;

            if json {
                if is_batch {
                    crate::output::print_json(&json_results)?;
                } else if let Some(result) = json_results.into_iter().next() {
                    crate::output::print_json(&result)?;
                }
            } else if is_batch {
                println!(
                    "\n{} revoked, {} failed",
                    style(revoked).green().bold(),
                    if failed > 0 {
                        style(failed).red().bold()
                    } else {
                        style(failed).dim()
                    }
                );
            }

            if failed > 0 && !is_batch {
                anyhow::bail!("revocation failed");
            }

            // Auto-sync after revoke
            if crate::config::load_config().auto_sync {
                eprintln!("{} auto-syncing...", style("note:").cyan().bold());
                if let Err(e) = crate::commands::sync::auto_push(vault_name) {
                    eprintln!(
                        "{} auto-sync failed: {}",
                        style("warning:").yellow().bold(),
                        e
                    );
                }
            }
        }
        DelegationCommands::Pending => {
            let home = sigyn_home();
            let invitations_dir = home.join("invitations");
            let mut found = Vec::new();

            if invitations_dir.exists() {
                if let Ok(entries) = std::fs::read_dir(&invitations_dir) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.extension().is_some_and(|e| e == "json") {
                            if let Ok(contents) = std::fs::read_to_string(&p) {
                                if let Ok(inv) = serde_json::from_str::<InvitationFile>(&contents) {
                                    found.push(inv);
                                }
                            }
                        }
                    }
                }
            }

            if json {
                let items: Vec<_> = found
                    .iter()
                    .map(|inv| {
                        serde_json::json!({
                            "id": inv.id.to_string(),
                            "vault_name": inv.vault_name,
                            "inviter": inv.inviter_fingerprint.to_hex(),
                            "role": inv.proposed_role.to_string(),
                            "envs": inv.allowed_envs,
                            "created_at": inv.created_at.to_rfc3339(),
                        })
                    })
                    .collect();
                crate::output::print_json(&items)?;
            } else {
                println!("{}", style("Pending Invitations").bold());
                if found.is_empty() {
                    println!("  (no pending invitations)");
                } else {
                    for inv in &found {
                        println!(
                            "  {} vault={} role={} from={} ({})",
                            &inv.id.to_string()[..8],
                            inv.vault_name,
                            inv.proposed_role,
                            &inv.inviter_fingerprint.to_hex()[..12],
                            inv.created_at.format("%Y-%m-%d %H:%M"),
                        );
                    }
                }
            }
        }
        DelegationCommands::BulkInvite { file, force } => {
            let ctx = unlock_vault(identity, Some(vault_name), None)?;
            check_access(&ctx, AccessAction::ManageMembers, None)?;

            // Parse JSON file: [{"fingerprint": "...", "role": "contributor", "envs": "dev,staging"}, ...]
            let file_contents = std::fs::read_to_string(&file)
                .map_err(|e| anyhow::anyhow!("failed to read file '{}': {}", file, e))?;
            let entries: Vec<serde_json::Value> = serde_json::from_str(&file_contents)
                .map_err(|e| anyhow::anyhow!("invalid JSON in '{}': {}", file, e))?;

            // Validate all entries before executing any
            struct BulkEntry {
                fingerprint: KeyFingerprint,
                role: Role,
                envs: Vec<String>,
            }
            let mut validated = Vec::new();
            for (i, entry) in entries.iter().enumerate() {
                let fp_hex = entry["fingerprint"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("entry {}: missing 'fingerprint'", i))?;
                let fp = KeyFingerprint::from_hex(fp_hex)
                    .map_err(|e| anyhow::anyhow!("entry {}: invalid fingerprint: {}", i, e))?;
                let role_str = entry["role"].as_str().unwrap_or("readonly");
                let role = Role::from_str_name(role_str)
                    .ok_or_else(|| anyhow::anyhow!("entry {}: unknown role '{}'", i, role_str))?;
                let envs_str = entry["envs"].as_str().unwrap_or("*");
                let envs: Vec<String> = envs_str.split(',').map(|s| s.trim().to_string()).collect();

                // Validate role level and delegation depth (same checks as single invite)
                if role == Role::Owner {
                    anyhow::bail!("entry {}: cannot invite with 'owner' role", i);
                }
                if ctx.fingerprint != ctx.manifest.owner {
                    if let Some(delegator) = ctx.policy.get_member(&ctx.fingerprint) {
                        if role.level() >= delegator.role.level() {
                            anyhow::bail!(
                                "entry {}: cannot invite with role '{}' (level {}) — your role '{}' (level {}) must be higher",
                                i, role, role.level(), delegator.role, delegator.role.level()
                            );
                        }
                    } else {
                        anyhow::bail!("you are not a member of this vault");
                    }
                    sigyn_engine::delegation::validate_delegation(
                        &ctx.policy,
                        &ctx.fingerprint,
                        role,
                        Some(&ctx.manifest.owner),
                    )
                    .map_err(|e| anyhow::anyhow!("entry {}: {}", i, e))?;
                }

                validated.push(BulkEntry {
                    fingerprint: fp,
                    role,
                    envs,
                });
            }

            if validated.is_empty() {
                anyhow::bail!("no entries in file");
            }

            // Show summary and confirm
            if !force {
                println!("{}", style("Bulk invite summary:").bold());
                for entry in &validated {
                    println!(
                        "  {} {} envs=[{}]",
                        &entry.fingerprint.to_hex()[..12],
                        entry.role,
                        entry.envs.join(",")
                    );
                }
                if crate::config::is_interactive() {
                    let confirm = dialoguer::Confirm::new()
                        .with_prompt(format!("Invite {} member(s)?", validated.len()))
                        .default(false)
                        .interact()?;
                    if !confirm {
                        println!("Aborted.");
                        return Ok(());
                    }
                } else {
                    anyhow::bail!("use --force in non-interactive mode");
                }
            }

            let home = sigyn_home();
            let store = IdentityStore::new(home);
            let identities = store
                .list()
                .map_err(|e| anyhow::anyhow!("failed to list identities: {}", e))?;

            let mut header: EnvelopeHeader = ctx.header.clone();
            let mut policy = ctx.policy.clone();
            let mut invited = 0usize;
            let mut failed = 0usize;

            for entry in &validated {
                let invitee_identity = match identities
                    .iter()
                    .find(|id| id.fingerprint == entry.fingerprint)
                {
                    Some(id) => id,
                    None => {
                        failed += 1;
                        crate::output::print_error(&format!(
                            "identity not found locally for {}",
                            entry.fingerprint.to_hex()
                        ));
                        continue;
                    }
                };

                // Build member policy
                let mut member = MemberPolicy::new(entry.fingerprint.clone(), entry.role);
                member.allowed_envs = entry.envs.clone();
                member.delegated_by = Some(ctx.fingerprint.clone());
                policy.add_member(member);

                // Add vault key slot
                if let Err(e) = envelope::add_vault_key_recipient(
                    &mut header,
                    ctx.vault_cipher.key_bytes(),
                    &invitee_identity.encryption_pubkey,
                    ctx.manifest.vault_id,
                ) {
                    failed += 1;
                    crate::output::print_error(&format!(
                        "failed to add vault key for {}: {}",
                        &entry.fingerprint.to_hex()[..12],
                        e
                    ));
                    continue;
                }

                // Add env slots
                let envs_to_grant: Vec<String> = if entry.envs.iter().any(|e| e == "*") {
                    ctx.manifest.environments.clone()
                } else {
                    entry.envs.clone()
                };
                let mut env_ok = true;
                for env_name in &envs_to_grant {
                    if let Some(env_key) = ctx.env_ciphers.get(env_name) {
                        if let Err(e) = envelope::add_env_recipient(
                            &mut header,
                            env_name,
                            env_key.key_bytes(),
                            &invitee_identity.encryption_pubkey,
                            ctx.manifest.vault_id,
                        ) {
                            crate::output::print_error(&format!(
                                "failed to add env '{}' for {}: {}",
                                env_name,
                                &entry.fingerprint.to_hex()[..12],
                                e
                            ));
                            env_ok = false;
                            break;
                        }
                    }
                }
                if !env_ok {
                    failed += 1;
                    continue;
                }

                audit_log(
                    &ctx,
                    AuditAction::MemberInvited {
                        fingerprint: entry.fingerprint.clone(),
                    },
                )?;
                invited += 1;
            }

            // Save header and policy ONCE at end
            policy
                .save_signed(
                    &ctx.paths.policy_path(&ctx.vault_name),
                    &ctx.vault_cipher,
                    ctx.loaded_identity.signing_key(),
                    &ctx.manifest.vault_id,
                )
                .map_err(|e| anyhow::anyhow!("failed to save policy: {}", e))?;
            save_header(
                &header,
                &ctx.paths,
                &ctx.vault_name,
                ctx.loaded_identity.signing_key(),
                ctx.manifest.vault_id,
            )?;

            if json {
                crate::output::print_json(&serde_json::json!({
                    "action": "bulk_invite",
                    "invited": invited,
                    "failed": failed,
                }))?;
            } else {
                println!(
                    "{} invited, {} failed",
                    style(invited).green().bold(),
                    if failed > 0 {
                        style(failed).red().bold()
                    } else {
                        style(failed).dim()
                    }
                );
            }
        }
        DelegationCommands::BulkRevoke {
            file,
            cascade,
            force,
        } => {
            let ctx = unlock_vault(identity, Some(vault_name), None)?;
            check_access(&ctx, AccessAction::ManageMembers, None)?;

            // Parse JSON file: ["fingerprint1", "fingerprint2", ...]
            let file_contents = std::fs::read_to_string(&file)
                .map_err(|e| anyhow::anyhow!("failed to read file '{}': {}", file, e))?;
            let fp_strings: Vec<String> = serde_json::from_str(&file_contents)
                .map_err(|e| anyhow::anyhow!("invalid JSON in '{}': {}", file, e))?;

            // Validate all fingerprints before executing
            let mut fps = Vec::new();
            for (i, fp_hex) in fp_strings.iter().enumerate() {
                let fp = KeyFingerprint::from_hex(fp_hex)
                    .map_err(|e| anyhow::anyhow!("entry {}: invalid fingerprint: {}", i, e))?;
                fps.push(fp);
            }

            if fps.is_empty() {
                anyhow::bail!("no fingerprints in file");
            }

            // Show summary and confirm
            if !force {
                println!("{}", style("Bulk revoke summary:").bold());
                for fp in &fps {
                    println!("  {}", &fp.to_hex()[..12]);
                }
                if crate::config::is_interactive() {
                    let confirm = dialoguer::Confirm::new()
                        .with_prompt(format!("Revoke {} member(s)?", fps.len()))
                        .default(false)
                        .interact()?;
                    if !confirm {
                        println!("Aborted.");
                        return Ok(());
                    }
                } else {
                    anyhow::bail!("use --force in non-interactive mode");
                }
            }

            // Reuse the existing revoke logic by converting to hex strings and delegating
            let hex_strings: Vec<String> = fps.iter().map(|fp| fp.to_hex()).collect();
            // We can just delegate to the Revoke handler — but to avoid code duplication
            // we'll inline the same pattern
            return super::delegation::handle(
                DelegationCommands::Revoke {
                    fingerprints: hex_strings,
                    cascade,
                },
                vault,
                identity,
                json,
            );
        }
        DelegationCommands::GrantEnv { fingerprints, env } => {
            let ctx = unlock_vault(identity, Some(vault_name), None)?;
            check_access(&ctx, AccessAction::ManageMembers, None)?;

            // Verify env exists
            if !ctx.manifest.environments.contains(&env) {
                anyhow::bail!("environment '{}' does not exist", env);
            }

            let env_key = ctx.env_ciphers.get(&env).ok_or_else(|| {
                anyhow::anyhow!(
                    "cannot grant access to env '{}' — you don't hold its key",
                    env
                )
            })?;

            let home = sigyn_home();
            let store = IdentityStore::new(home);
            let identities = store
                .list()
                .map_err(|e| anyhow::anyhow!("failed to list identities: {}", e))?;

            let mut policy = ctx.policy.clone();
            let mut header = ctx.header.clone();
            let is_batch = fingerprints.len() > 1;
            let mut granted = 0usize;
            let mut failed = 0usize;
            let mut json_results: Vec<serde_json::Value> = Vec::new();

            for fingerprint in &fingerprints {
                let target_fp = match KeyFingerprint::from_hex(fingerprint) {
                    Ok(fp) => fp,
                    Err(e) => {
                        failed += 1;
                        if json {
                            json_results.push(serde_json::json!({
                                "fingerprint": fingerprint, "status": "failed", "error": e.to_string(),
                            }));
                        } else {
                            crate::output::print_error(&format!(
                                "invalid fingerprint '{}': {}",
                                fingerprint, e
                            ));
                        }
                        continue;
                    }
                };

                if policy.get_member(&target_fp).is_none() {
                    failed += 1;
                    if json {
                        json_results.push(serde_json::json!({
                            "fingerprint": fingerprint, "status": "failed", "error": "member not found",
                        }));
                    } else {
                        crate::output::print_error(&format!("member {} not found", fingerprint));
                    }
                    continue;
                }

                let member_id = match identities.iter().find(|id| id.fingerprint == target_fp) {
                    Some(id) => id,
                    None => {
                        failed += 1;
                        if json {
                            json_results.push(serde_json::json!({
                                "fingerprint": fingerprint, "status": "failed",
                                "error": "member identity not found locally",
                            }));
                        } else {
                            crate::output::print_error(&format!(
                                "member identity not found locally for {}",
                                fingerprint
                            ));
                        }
                        continue;
                    }
                };

                if let Err(e) = envelope::add_env_recipient(
                    &mut header,
                    &env,
                    env_key.key_bytes(),
                    &member_id.encryption_pubkey,
                    ctx.manifest.vault_id,
                ) {
                    failed += 1;
                    if json {
                        json_results.push(serde_json::json!({
                            "fingerprint": fingerprint, "status": "failed", "error": e.to_string(),
                        }));
                    } else {
                        crate::output::print_error(&format!(
                            "'{}': failed to add env recipient: {}",
                            &fingerprint[..12.min(fingerprint.len())],
                            e
                        ));
                    }
                    continue;
                }

                if let Some(mp) = policy.get_member_mut(&target_fp) {
                    if !mp.allowed_envs.contains(&env) && !mp.allowed_envs.iter().any(|e| e == "*")
                    {
                        mp.allowed_envs.push(env.clone());
                    }
                }

                granted += 1;
                if json {
                    json_results.push(serde_json::json!({
                        "fingerprint": fingerprint, "env": env, "status": "granted",
                    }));
                } else if !is_batch {
                    crate::output::print_success(&format!(
                        "Granted '{}' access to env '{}'",
                        &fingerprint[..12.min(fingerprint.len())],
                        env
                    ));
                } else {
                    crate::output::print_success(&format!(
                        "Granted '{}'",
                        &fingerprint[..12.min(fingerprint.len())]
                    ));
                }
            }

            policy
                .save_signed(
                    &ctx.paths.policy_path(&ctx.vault_name),
                    &ctx.vault_cipher,
                    ctx.loaded_identity.signing_key(),
                    &ctx.manifest.vault_id,
                )
                .map_err(|e| anyhow::anyhow!("failed to save policy: {}", e))?;
            save_header(
                &header,
                &ctx.paths,
                &ctx.vault_name,
                ctx.loaded_identity.signing_key(),
                ctx.manifest.vault_id,
            )?;

            audit_log(&ctx, AuditAction::PolicyChanged)?;

            if json {
                if is_batch {
                    crate::output::print_json(&json_results)?;
                } else if let Some(result) = json_results.into_iter().next() {
                    crate::output::print_json(&result)?;
                }
            } else if is_batch {
                println!(
                    "\n{} granted env '{}', {} failed",
                    style(granted).green().bold(),
                    &env,
                    if failed > 0 {
                        style(failed).red().bold()
                    } else {
                        style(failed).dim()
                    }
                );
            }
        }
        DelegationCommands::RevokeEnv { fingerprints, env } => {
            let ctx = unlock_vault(identity, Some(vault_name), None)?;
            check_access(&ctx, AccessAction::ManageMembers, None)?;

            let home = sigyn_home();
            let store = IdentityStore::new(home);
            let identities = store
                .list()
                .map_err(|e| anyhow::anyhow!("failed to list identities: {}", e))?;

            let mut policy = ctx.policy.clone();
            let mut header = ctx.header.clone();
            let is_batch = fingerprints.len() > 1;
            let mut revoked_count = 0usize;
            let mut failed = 0usize;
            let mut json_results: Vec<serde_json::Value> = Vec::new();

            for fingerprint in &fingerprints {
                let target_fp = match KeyFingerprint::from_hex(fingerprint) {
                    Ok(fp) => fp,
                    Err(e) => {
                        failed += 1;
                        if json {
                            json_results.push(serde_json::json!({
                                "fingerprint": fingerprint, "status": "failed", "error": e.to_string(),
                            }));
                        } else {
                            crate::output::print_error(&format!(
                                "invalid fingerprint '{}': {}",
                                fingerprint, e
                            ));
                        }
                        continue;
                    }
                };

                if policy.get_member(&target_fp).is_none() {
                    failed += 1;
                    if json {
                        json_results.push(serde_json::json!({
                            "fingerprint": fingerprint, "status": "failed", "error": "member not found",
                        }));
                    } else {
                        crate::output::print_error(&format!("member {} not found", fingerprint));
                    }
                    continue;
                }

                if let Some(mp) = policy.get_member_mut(&target_fp) {
                    // If member has wildcard access, expand to explicit env list
                    // minus the revoked env. Otherwise just remove the specific env.
                    if mp.allowed_envs.iter().any(|e| e == "*") {
                        mp.allowed_envs = ctx
                            .manifest
                            .environments
                            .iter()
                            .filter(|e| *e != &env)
                            .cloned()
                            .collect();
                    } else {
                        mp.allowed_envs.retain(|e| e != &env);
                    }
                }

                envelope::remove_env_recipient(&mut header, &env, &target_fp);
                revoked_count += 1;

                if json {
                    json_results.push(serde_json::json!({
                        "fingerprint": fingerprint, "env": env, "status": "revoked",
                    }));
                } else if !is_batch {
                    crate::output::print_success(&format!(
                        "Revoked '{}' access to env '{}'",
                        &fingerprint[..12.min(fingerprint.len())],
                        env
                    ));
                } else {
                    crate::output::print_success(&format!(
                        "Revoked '{}'",
                        &fingerprint[..12.min(fingerprint.len())]
                    ));
                }
            }

            // Rotate env key for remaining members (once, after all removals)
            if revoked_count > 0 {
                let mut remaining_pubkeys = Vec::new();
                remaining_pubkeys.push(ctx.loaded_identity.identity.encryption_pubkey.clone());
                for mp in policy.members.values() {
                    let has_access = mp.allowed_envs.iter().any(|e| e == "*" || e == &env);
                    if has_access {
                        if let Some(id) = identities
                            .iter()
                            .find(|id| id.fingerprint == mp.fingerprint)
                        {
                            remaining_pubkeys.push(id.encryption_pubkey.clone());
                        }
                    }
                }

                let new_env_key = envelope::rotate_env_key(
                    &mut header,
                    &env,
                    &remaining_pubkeys,
                    ctx.manifest.vault_id,
                )
                .map_err(|e| anyhow::anyhow!("failed to rotate env key: {}", e))?;

                let env_path = ctx.paths.env_path(&ctx.vault_name, &env);
                if env_path.exists() {
                    let old_cipher = ctx.cipher_for_env(&env).ok_or_else(|| {
                        anyhow::anyhow!("no access to env '{}' for re-encryption", env)
                    })?;
                    let encrypted = env_file::read_encrypted_env(&env_path)?;
                    let plaintext = env_file::decrypt_env(&encrypted, old_cipher)?;
                    let new_cipher =
                        sigyn_engine::crypto::vault_cipher::VaultCipher::new(new_env_key);
                    let re_encrypted = env_file::encrypt_env(&plaintext, &new_cipher, &env)?;
                    env_file::write_encrypted_env(&env_path, &re_encrypted)?;
                }
            }

            policy
                .save_signed(
                    &ctx.paths.policy_path(&ctx.vault_name),
                    &ctx.vault_cipher,
                    ctx.loaded_identity.signing_key(),
                    &ctx.manifest.vault_id,
                )
                .map_err(|e| anyhow::anyhow!("failed to save policy: {}", e))?;
            save_header(
                &header,
                &ctx.paths,
                &ctx.vault_name,
                ctx.loaded_identity.signing_key(),
                ctx.manifest.vault_id,
            )?;

            audit_log(&ctx, AuditAction::PolicyChanged)?;

            if json {
                if is_batch {
                    crate::output::print_json(&json_results)?;
                } else if let Some(result) = json_results.into_iter().next() {
                    crate::output::print_json(&result)?;
                }
            } else if is_batch {
                println!(
                    "\n{} revoked from env '{}' (key rotated), {} failed",
                    style(revoked_count).green().bold(),
                    env,
                    if failed > 0 {
                        style(failed).red().bold()
                    } else {
                        style(failed).dim()
                    }
                );
            } else if revoked_count > 0 {
                crate::output::print_info("Env key rotated");
            }
        }
    }
    Ok(())
}

fn format_node(node: &DelegationNode) -> String {
    format!("{} [{}]", node.name, node.role)
}

fn print_children(node: &DelegationNode, prefix: &str, is_last: bool) {
    let connector = if is_last { "    " } else { "\u{2502}   " };
    let child_prefix = format!("{}{}", prefix, connector);
    for (i, child) in node.children.iter().enumerate() {
        let child_connector = if i == node.children.len() - 1 {
            "\u{2514}\u{2500}\u{2500}"
        } else {
            "\u{251c}\u{2500}\u{2500}"
        };
        println!("{}{} {}", child_prefix, child_connector, format_node(child));
        print_children(child, &child_prefix, i == node.children.len() - 1);
    }
}
