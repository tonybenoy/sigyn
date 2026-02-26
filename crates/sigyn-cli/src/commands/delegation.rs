use anyhow::{Context, Result};
use clap::Subcommand;
use console::style;
use sigyn_engine::audit::entry::AuditOutcome;
use sigyn_engine::audit::{AuditAction, AuditLog};
use sigyn_engine::crypto::envelope::{self, EnvelopeHeader};
use sigyn_engine::crypto::keys::KeyFingerprint;
use sigyn_engine::delegation::invite::InvitationFile;
use sigyn_engine::delegation::revoke::revoke_member;
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
        /// Path to invitation file
        invitation: String,
    },
    /// Revoke a member's access
    Revoke {
        /// Member fingerprint to revoke
        fingerprint: String,
        /// Also revoke all members they invited
        #[arg(long)]
        cascade: bool,
    },
    /// List pending invitations
    Pending,
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

/// Save the envelope header to disk.
fn save_header(header: &EnvelopeHeader, paths: &VaultPaths, vault_name: &str) -> Result<()> {
    let mut buf = Vec::new();
    ciborium::into_writer(header, &mut buf)
        .map_err(|e| anyhow::anyhow!("failed to encode header: {}", e))?;
    let members_path = paths.members_path(vault_name);
    std::fs::write(&members_path, &buf).context("failed to write members file")?;
    Ok(())
}

/// Append an audit entry (best-effort).
fn audit_log(ctx: &UnlockedVaultContext, action: AuditAction) {
    let audit_path = ctx.paths.audit_path(&ctx.vault_name);
    if let Ok(mut log) = AuditLog::open(&audit_path) {
        let _ = log.append(
            &ctx.fingerprint,
            action,
            Some(ctx.env_name.clone()),
            AuditOutcome::Success,
            ctx.loaded_identity.signing_key(),
        );
    }
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

            let invitee_fp = KeyFingerprint::from_hex(&pubkey)
                .map_err(|e| anyhow::anyhow!("invalid fingerprint: {}", e))?;

            let allowed_envs: Vec<String> = envs.split(',').map(|s| s.trim().to_string()).collect();

            // Enforce delegation depth and delegatee limits
            if let Some(delegator) = ctx.policy.get_member(&ctx.fingerprint) {
                if delegator.max_delegation_depth == 0 {
                    anyhow::bail!("you have reached the maximum delegation depth (0 remaining)");
                }
                let current_delegatees = ctx
                    .policy
                    .members()
                    .filter(|m| m.delegated_by.as_ref() == Some(&ctx.fingerprint))
                    .count();
                if current_delegatees as u32 >= delegator.max_delegatees {
                    anyhow::bail!(
                        "you have reached the maximum number of delegatees ({})",
                        delegator.max_delegatees
                    );
                }
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

            // Add recipient to envelope header
            let header_bytes = std::fs::read(ctx.paths.members_path(&ctx.vault_name))
                .context("failed to read vault members")?;
            let mut header: EnvelopeHeader = ciborium::from_reader(header_bytes.as_slice())
                .map_err(|e| anyhow::anyhow!("failed to decode header: {}", e))?;

            envelope::add_recipient(
                &mut header,
                ctx.cipher.key_bytes(),
                &invitee_identity.encryption_pubkey,
                ctx.manifest.vault_id,
            )
            .map_err(|e| anyhow::anyhow!("failed to add recipient: {}", e))?;

            // Save policy and header
            policy
                .save_encrypted(&ctx.paths.policy_path(&ctx.vault_name), &ctx.cipher)
                .map_err(|e| anyhow::anyhow!("failed to save policy: {}", e))?;
            save_header(&header, &ctx.paths, &ctx.vault_name)?;

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
                created_at: chrono::Utc::now(),
            };

            let invitations_dir = home.join("invitations");
            std::fs::create_dir_all(&invitations_dir)
                .context("failed to create invitations directory")?;
            let invitation_path = invitations_dir.join(format!("{}.json", invitation_id));
            let invitation_json = serde_json::to_string_pretty(&invitation_file)
                .context("failed to serialize invitation")?;
            std::fs::write(&invitation_path, &invitation_json)
                .context("failed to write invitation file")?;

            // Audit
            audit_log(
                &ctx,
                AuditAction::MemberInvited {
                    fingerprint: invitee_fp.clone(),
                },
            );

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
            let path = std::path::Path::new(&invitation);
            if !path.exists() {
                anyhow::bail!("invitation file not found: {}", invitation);
            }

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

            if let Some(inviter) = inviter_identity {
                invite_file.verify(&inviter.signing_pubkey).map_err(|_| {
                    anyhow::anyhow!(
                        "invitation signature verification failed for inviter {}",
                        invite_file.inviter_fingerprint.to_hex()
                    )
                })?;
            } else {
                // Inviter identity not in local store; warn but proceed
                eprintln!(
                    "{} inviter identity {} not found locally; signature could not be verified",
                    style("WARNING").yellow().bold(),
                    &invite_file.inviter_fingerprint.to_hex()[..12]
                );
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
                    "signature_verified": inviter_identity.is_some(),
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
                if inviter_identity.is_some() {
                    println!("  Signature:     verified");
                } else {
                    println!("  Signature:     not verified (inviter not in local store)");
                }

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
            fingerprint,
            cascade,
        } => {
            let ctx = unlock_vault(identity, Some(vault_name), None)?;
            check_access(&ctx, AccessAction::ManageMembers, None)?;

            let target_fp = KeyFingerprint::from_hex(&fingerprint)
                .map_err(|e| anyhow::anyhow!("invalid fingerprint: {}", e))?;

            // Load current header
            let header_bytes = std::fs::read(ctx.paths.members_path(&ctx.vault_name))
                .context("failed to read vault members")?;
            let mut header: EnvelopeHeader = ciborium::from_reader(header_bytes.as_slice())
                .map_err(|e| anyhow::anyhow!("failed to decode header: {}", e))?;

            let mut policy = ctx.policy.clone();

            // Build the remaining pubkeys list: owner + all current members except the
            // ones about to be revoked. We look up pubkeys from the identity store.
            let home = sigyn_home();
            let store = IdentityStore::new(home);
            let identities = store
                .list()
                .map_err(|e| anyhow::anyhow!("failed to list identities: {}", e))?;

            // Include the owner (current user) plus all policy members
            let mut remaining_pubkeys: Vec<(
                KeyFingerprint,
                sigyn_engine::crypto::keys::X25519PublicKey,
            )> = Vec::new();

            // Add the owner/current identity
            remaining_pubkeys.push((
                ctx.fingerprint.clone(),
                ctx.loaded_identity.identity.encryption_pubkey.clone(),
            ));

            // Add all known members from the identity store
            for member_policy in policy.members.values() {
                if let Some(id) = identities
                    .iter()
                    .find(|id| id.fingerprint == member_policy.fingerprint)
                {
                    remaining_pubkeys.push((id.fingerprint.clone(), id.encryption_pubkey.clone()));
                }
            }

            // Perform the revocation
            let (result, new_cipher_opt) = revoke_member(
                &target_fp,
                cascade,
                &mut policy,
                &mut header,
                ctx.manifest.vault_id,
                &remaining_pubkeys,
            )
            .map_err(|e| anyhow::anyhow!("revocation failed: {}", e))?;

            // If master key was rotated, re-encrypt all environments with the new cipher
            if let Some(ref new_cipher) = new_cipher_opt {
                for env_name in &ctx.manifest.environments {
                    let env_path = ctx.paths.env_path(&ctx.vault_name, env_name);
                    if env_path.exists() {
                        // Decrypt with old cipher, re-encrypt with new cipher
                        let encrypted = env_file::read_encrypted_env(&env_path).map_err(|e| {
                            anyhow::anyhow!("failed to read env '{}': {}", env_name, e)
                        })?;
                        let plaintext =
                            env_file::decrypt_env(&encrypted, &ctx.cipher).map_err(|e| {
                                anyhow::anyhow!("failed to decrypt env '{}': {}", env_name, e)
                            })?;
                        let re_encrypted = env_file::encrypt_env(&plaintext, new_cipher, env_name)
                            .map_err(|e| {
                                anyhow::anyhow!("failed to re-encrypt env '{}': {}", env_name, e)
                            })?;
                        env_file::write_encrypted_env(&env_path, &re_encrypted).map_err(|e| {
                            anyhow::anyhow!("failed to write env '{}': {}", env_name, e)
                        })?;
                    }
                }

                // Save policy with new cipher
                policy
                    .save_encrypted(&ctx.paths.policy_path(&ctx.vault_name), new_cipher)
                    .map_err(|e| anyhow::anyhow!("failed to save policy: {}", e))?;
            } else {
                // Save policy with old cipher (shouldn't happen since we always rotate, but handle it)
                policy
                    .save_encrypted(&ctx.paths.policy_path(&ctx.vault_name), &ctx.cipher)
                    .map_err(|e| anyhow::anyhow!("failed to save policy: {}", e))?;
            }

            // Save the updated header
            save_header(&header, &ctx.paths, &ctx.vault_name)?;

            // Audit log entries
            audit_log(
                &ctx,
                AuditAction::MemberRevoked {
                    fingerprint: target_fp.clone(),
                },
            );
            for cascade_fp in &result.cascade_revoked {
                audit_log(
                    &ctx,
                    AuditAction::MemberRevoked {
                        fingerprint: cascade_fp.clone(),
                    },
                );
            }
            if result.master_key_rotated {
                audit_log(&ctx, AuditAction::MasterKeyRotated);
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

            if json {
                let cascade_hex: Vec<String> = result
                    .cascade_revoked
                    .iter()
                    .map(|fp| fp.to_hex())
                    .collect();
                crate::output::print_json(&serde_json::json!({
                    "action": "revoked",
                    "fingerprint": fingerprint,
                    "cascade": cascade,
                    "cascade_revoked": cascade_hex,
                    "master_key_rotated": result.master_key_rotated,
                }))?;
            } else {
                crate::output::print_success(&format!(
                    "Revoked access for {}{}",
                    &fingerprint[..12.min(fingerprint.len())],
                    if cascade { " (cascade)" } else { "" }
                ));
                if !result.cascade_revoked.is_empty() {
                    println!(
                        "  Cascade revoked {} additional member(s)",
                        result.cascade_revoked.len()
                    );
                }
                if result.master_key_rotated {
                    crate::output::print_info("Master key rotated and environments re-encrypted");
                }
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
