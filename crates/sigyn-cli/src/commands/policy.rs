use anyhow::Result;
use clap::Subcommand;
use console::style;
use sigyn_engine::audit::entry::AuditOutcome;
use sigyn_engine::audit::{AuditAction, AuditLog};
use sigyn_engine::crypto::keys::KeyFingerprint;
use sigyn_engine::policy::constraints::MfaActions;
use sigyn_engine::policy::engine::{AccessAction, AccessRequest, PolicyDecision};
use sigyn_engine::policy::member::MemberPolicy;
use sigyn_engine::policy::roles::Role;
use sigyn_engine::policy::storage::VaultPolicyExt;
use sigyn_engine::policy::PolicyEngine;

use super::secret::{check_access, unlock_vault, UnlockedVaultContext};

#[derive(Subcommand)]
pub enum PolicyCommands {
    /// Show vault policy (all members and their roles)
    Show,
    /// Add a member to the vault policy
    #[command(name = "member-add")]
    MemberAdd {
        /// Member fingerprint (hex)
        fingerprint: String,
        /// Role to assign
        #[arg(long, default_value = "readonly")]
        role: String,
        /// Allowed environments (comma-separated, or * for all)
        #[arg(long, default_value = "*")]
        envs: String,
        /// Secret key patterns (comma-separated globs)
        #[arg(long, default_value = "*")]
        patterns: String,
    },
    /// Remove a member from the vault policy
    #[command(name = "member-remove")]
    MemberRemove {
        /// Member fingerprint (hex)
        fingerprint: String,
    },
    /// Check access for a member
    Check {
        /// Member fingerprint (hex)
        fingerprint: String,
        /// Action to check: read, write, delete, manage-members, manage-policy
        action: String,
        /// Environment to check
        #[arg(long, short, default_value = "dev")]
        env: String,
        /// Optional key to check
        #[arg(long, short)]
        key: Option<String>,
    },
    /// Set per-action MFA requirements on global constraints
    #[command(name = "require-mfa")]
    RequireMfa {
        /// Actions requiring MFA (comma-separated): read,write,delete,manage-members,manage-policy,create-env,promote,all,none
        actions: String,
    },
    /// Show policy-related audit history
    History {
        /// Number of entries to show
        #[arg(short, long, default_value = "50")]
        n: usize,
    },
    /// Set per-action MFA requirements on a specific member
    #[command(name = "member-require-mfa")]
    MemberRequireMfa {
        /// Member fingerprint (hex)
        fingerprint: String,
        /// Actions requiring MFA (comma-separated): read,write,delete,manage-members,manage-policy,create-env,promote,all,none
        actions: String,
    },
}

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

fn parse_fingerprint(hex: &str) -> Result<KeyFingerprint> {
    if hex.len() != 32 {
        anyhow::bail!(
            "invalid fingerprint length: expected 32 hex chars (16 bytes), got {}",
            hex.len()
        );
    }
    KeyFingerprint::from_hex(hex).map_err(|_| anyhow::anyhow!("invalid fingerprint hex: '{}'", hex))
}

fn parse_action(s: &str) -> Result<AccessAction> {
    match s.to_lowercase().as_str() {
        "read" => Ok(AccessAction::Read),
        "write" => Ok(AccessAction::Write),
        "delete" => Ok(AccessAction::Delete),
        "manage-members" => Ok(AccessAction::ManageMembers),
        "manage-policy" => Ok(AccessAction::ManagePolicy),
        "create-env" => Ok(AccessAction::CreateEnv),
        "promote" => Ok(AccessAction::Promote),
        other => anyhow::bail!(
            "unknown action: '{}'. Use: read, write, delete, manage-members, manage-policy, create-env, promote",
            other
        ),
    }
}

pub fn handle(
    cmd: PolicyCommands,
    vault: Option<&str>,
    identity: Option<&str>,
    json: bool,
) -> Result<()> {
    match cmd {
        PolicyCommands::Show => {
            let ctx = unlock_vault(identity, vault, None)?;

            if ctx.policy.members.is_empty() {
                if json {
                    crate::output::print_json(&serde_json::json!({
                        "owner": ctx.manifest.owner.to_hex(),
                        "members": [],
                    }))?;
                } else {
                    println!("{}", style("Vault Policy").bold());
                    println!("  Owner: {}", style(ctx.manifest.owner.to_hex()).cyan());
                    println!("  No additional members.");
                }
                return Ok(());
            }

            if json {
                let global_mfa = ctx
                    .policy
                    .global_constraints
                    .as_ref()
                    .map(|c| c.mfa_actions.to_csv())
                    .unwrap_or_else(|| "none".into());
                let members: Vec<_> = ctx
                    .policy
                    .members
                    .values()
                    .map(|m| {
                        let mfa = m
                            .constraints
                            .as_ref()
                            .map(|c| c.mfa_actions.to_csv())
                            .unwrap_or_else(|| "none".into());
                        serde_json::json!({
                            "fingerprint": m.fingerprint.to_hex(),
                            "role": m.role.to_string(),
                            "envs": m.allowed_envs,
                            "patterns": m.secret_patterns,
                            "mfa": mfa,
                            "delegated_by": m.delegated_by.as_ref().map(|f| f.to_hex()),
                        })
                    })
                    .collect();
                crate::output::print_json(&serde_json::json!({
                    "owner": ctx.manifest.owner.to_hex(),
                    "global_mfa": global_mfa,
                    "members": members,
                }))?;
            } else {
                println!("{}", style("Vault Policy").bold());
                println!("  Owner: {}", style(ctx.manifest.owner.to_hex()).cyan());
                if let Some(global) = &ctx.policy.global_constraints {
                    if global.mfa_actions.any_enabled() {
                        println!(
                            "  Global MFA: {}",
                            style(global.mfa_actions.to_csv()).yellow()
                        );
                    }
                }
                println!("{}", style("-".repeat(60)).dim());
                for m in ctx.policy.members.values() {
                    let fp_short = &m.fingerprint.to_hex()[..16];
                    let delegated = m
                        .delegated_by
                        .as_ref()
                        .map(|f| format!(" (via {})", &f.to_hex()[..16]))
                        .unwrap_or_default();
                    let mfa_info = m
                        .constraints
                        .as_ref()
                        .filter(|c| c.mfa_actions.any_enabled())
                        .map(|c| format!(" mfa=[{}]", c.mfa_actions.to_csv()))
                        .unwrap_or_default();
                    println!(
                        "  {} {} envs=[{}] patterns=[{}]{}{}",
                        style(fp_short).cyan(),
                        style(m.role.to_string()).bold(),
                        m.allowed_envs.join(","),
                        m.secret_patterns.join(","),
                        style(mfa_info).yellow(),
                        style(delegated).dim(),
                    );
                }
            }
        }

        PolicyCommands::MemberAdd {
            fingerprint,
            role,
            envs,
            patterns,
        } => {
            let ctx = unlock_vault(identity, vault, None)?;
            check_access(&ctx, AccessAction::ManageMembers, None)?;

            let fp = parse_fingerprint(&fingerprint)?;
            let role = Role::from_str_name(&role).ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown role: '{}'. Use: readonly, auditor, operator, contributor, manager, admin",
                    role
                )
            })?;

            if ctx.policy.get_member(&fp).is_some() {
                anyhow::bail!("member {} is already in the policy", fingerprint);
            }

            let allowed_envs: Vec<String> = envs.split(',').map(|s| s.trim().to_string()).collect();
            let secret_patterns: Vec<String> =
                patterns.split(',').map(|s| s.trim().to_string()).collect();

            let mut member = MemberPolicy::new(fp.clone(), role);
            member.allowed_envs = allowed_envs;
            member.secret_patterns = secret_patterns;
            member.delegated_by = Some(ctx.fingerprint.clone());

            let mut policy = ctx.policy.clone();
            policy.add_member(member);
            policy.save_signed(
                &ctx.paths.policy_path(&ctx.vault_name),
                &ctx.vault_cipher,
                ctx.loaded_identity.signing_key(),
                &ctx.manifest.vault_id,
            )?;

            audit(&ctx, AuditAction::PolicyChanged, AuditOutcome::Success);

            if json {
                crate::output::print_json(&serde_json::json!({
                    "action": "member_added",
                    "fingerprint": fingerprint,
                    "role": role.to_string(),
                }))?;
            } else {
                crate::output::print_success(&format!(
                    "Added member {} as {}",
                    &fingerprint[..16.min(fingerprint.len())],
                    role
                ));
            }
        }

        PolicyCommands::MemberRemove { fingerprint } => {
            let ctx = unlock_vault(identity, vault, None)?;
            check_access(&ctx, AccessAction::ManageMembers, None)?;

            let fp = parse_fingerprint(&fingerprint)?;
            let mut policy = ctx.policy.clone();

            if policy.remove_member(&fp).is_none() {
                anyhow::bail!("member {} not found in policy", fingerprint);
            }

            policy.save_signed(
                &ctx.paths.policy_path(&ctx.vault_name),
                &ctx.vault_cipher,
                ctx.loaded_identity.signing_key(),
                &ctx.manifest.vault_id,
            )?;

            audit(
                &ctx,
                AuditAction::MemberRevoked { fingerprint: fp },
                AuditOutcome::Success,
            );

            crate::output::print_success(&format!(
                "Removed member {} from policy",
                &fingerprint[..16.min(fingerprint.len())]
            ));
        }

        PolicyCommands::Check {
            fingerprint,
            action,
            env,
            key,
        } => {
            let ctx = unlock_vault(identity, vault, None)?;

            let fp = parse_fingerprint(&fingerprint)?;
            let action = parse_action(&action)?;

            let engine = PolicyEngine::new(&ctx.policy, &ctx.manifest.owner);
            let request = AccessRequest {
                actor: fp,
                action,
                env,
                key,

                mfa_verified: false,
            };

            match engine.evaluate(&request)? {
                PolicyDecision::Allow => {
                    if json {
                        crate::output::print_json(&serde_json::json!({"decision": "allow"}))?;
                    } else {
                        crate::output::print_success("Access: ALLOW");
                    }
                }
                PolicyDecision::AllowWithWarning(msg) => {
                    if json {
                        crate::output::print_json(
                            &serde_json::json!({"decision": "allow", "warning": msg}),
                        )?;
                    } else {
                        crate::output::print_success(&format!("Access: ALLOW (warning: {})", msg));
                    }
                }
                PolicyDecision::Deny(reason) => {
                    if json {
                        crate::output::print_json(
                            &serde_json::json!({"decision": "deny", "reason": reason}),
                        )?;
                    } else {
                        println!("{} Access: DENY ({})", style("X").red().bold(), reason);
                    }
                }
                PolicyDecision::RequiresMfa => {
                    if json {
                        crate::output::print_json(
                            &serde_json::json!({"decision": "requires_mfa"}),
                        )?;
                    } else {
                        println!("{} Access: REQUIRES MFA", style("!").yellow().bold());
                    }
                }
            }
        }

        PolicyCommands::RequireMfa { actions } => {
            let ctx = unlock_vault(identity, vault, None)?;
            check_access(&ctx, AccessAction::ManagePolicy, None)?;

            let mfa_actions =
                MfaActions::from_csv(&actions).map_err(|e| anyhow::anyhow!("{}", e))?;

            let mut policy = ctx.policy.clone();
            let global = policy.global_constraints.get_or_insert_with(|| {
                sigyn_engine::policy::constraints::Constraints {
                    time_windows: vec![],
                    expires_at: None,
                    mfa_actions: MfaActions::none(),
                }
            });
            global.mfa_actions = mfa_actions.clone();
            policy.save_signed(
                &ctx.paths.policy_path(&ctx.vault_name),
                &ctx.vault_cipher,
                ctx.loaded_identity.signing_key(),
                &ctx.manifest.vault_id,
            )?;

            audit(&ctx, AuditAction::PolicyChanged, AuditOutcome::Success);

            if json {
                crate::output::print_json(&serde_json::json!({
                    "action": "global_mfa_updated",
                    "mfa_actions": mfa_actions.to_csv(),
                }))?;
            } else {
                crate::output::print_success(&format!(
                    "Global MFA requirement set: {}",
                    mfa_actions.to_csv()
                ));
            }
        }

        PolicyCommands::History { n } => {
            let ctx = unlock_vault(identity, vault, None)?;
            check_access(&ctx, AccessAction::Audit, None)?;

            let audit_path = ctx.paths.audit_path(&ctx.vault_name);
            if !audit_path.exists() {
                println!("No audit log found for vault '{}'", ctx.vault_name);
                return Ok(());
            }

            let audit_cipher = sigyn_engine::crypto::sealed::derive_file_cipher_with_salt(
                ctx.vault_cipher.key_bytes(),
                b"sigyn-audit-v1",
                &ctx.manifest.vault_id,
            )
            .map_err(|e| anyhow::anyhow!("failed to derive audit cipher: {}", e))?;
            let log = sigyn_engine::audit::AuditLog::open(&audit_path, audit_cipher)?;
            let all_entries = log.tail(1000)?;

            // Filter for policy-related actions
            let policy_entries: Vec<_> = all_entries
                .into_iter()
                .filter(|e| {
                    matches!(
                        e.action,
                        AuditAction::PolicyChanged
                            | AuditAction::MemberInvited { .. }
                            | AuditAction::MemberRevoked { .. }
                            | AuditAction::OwnershipTransferred { .. }
                            | AuditAction::OwnershipTransferAccepted { .. }
                            | AuditAction::EnvironmentCreated { .. }
                            | AuditAction::EnvironmentDeleted { .. }
                    )
                })
                .rev()
                .take(n)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();

            if json {
                crate::output::print_json(&policy_entries)?;
            } else {
                println!(
                    "{} {}",
                    style("Policy History").bold(),
                    style(format!("(showing {})", policy_entries.len())).dim()
                );
                println!("{}", style("─".repeat(80)).dim());
                for entry in &policy_entries {
                    let actor_short = &entry.actor.to_hex()[..12];
                    let action_desc = match &entry.action {
                        AuditAction::PolicyChanged => "policy changed".to_string(),
                        AuditAction::MemberInvited { fingerprint } => {
                            format!("invited {}", &fingerprint.to_hex()[..12])
                        }
                        AuditAction::MemberRevoked { fingerprint } => {
                            format!("revoked {}", &fingerprint.to_hex()[..12])
                        }
                        AuditAction::OwnershipTransferred { from, to } => {
                            format!(
                                "ownership transferred {} -> {}",
                                &from.to_hex()[..12],
                                &to.to_hex()[..12]
                            )
                        }
                        AuditAction::OwnershipTransferAccepted { by } => {
                            format!("transfer accepted by {}", &by.to_hex()[..12])
                        }
                        AuditAction::EnvironmentCreated { name } => {
                            format!("env '{}' created", name)
                        }
                        AuditAction::EnvironmentDeleted { name } => {
                            format!("env '{}' deleted", name)
                        }
                        _ => format!("{:?}", entry.action),
                    };
                    println!(
                        "  {} {} {} {}",
                        style(format!("#{}", entry.sequence)).dim(),
                        style(entry.timestamp.format("%Y-%m-%d %H:%M:%S").to_string()).cyan(),
                        style(actor_short).dim(),
                        action_desc,
                    );
                }
            }
        }
        PolicyCommands::MemberRequireMfa {
            fingerprint,
            actions,
        } => {
            let ctx = unlock_vault(identity, vault, None)?;
            check_access(&ctx, AccessAction::ManagePolicy, None)?;

            let fp = parse_fingerprint(&fingerprint)?;
            let mfa_actions =
                MfaActions::from_csv(&actions).map_err(|e| anyhow::anyhow!("{}", e))?;

            let mut policy = ctx.policy.clone();
            let member = policy
                .get_member_mut(&fp)
                .ok_or_else(|| anyhow::anyhow!("member {} not found in policy", fingerprint))?;

            let constraints = member.constraints.get_or_insert_with(|| {
                sigyn_engine::policy::constraints::Constraints {
                    time_windows: vec![],
                    expires_at: None,
                    mfa_actions: MfaActions::none(),
                }
            });
            constraints.mfa_actions = mfa_actions.clone();
            policy.save_signed(
                &ctx.paths.policy_path(&ctx.vault_name),
                &ctx.vault_cipher,
                ctx.loaded_identity.signing_key(),
                &ctx.manifest.vault_id,
            )?;

            audit(&ctx, AuditAction::PolicyChanged, AuditOutcome::Success);

            if json {
                crate::output::print_json(&serde_json::json!({
                    "action": "member_mfa_updated",
                    "fingerprint": fingerprint,
                    "mfa_actions": mfa_actions.to_csv(),
                }))?;
            } else {
                crate::output::print_success(&format!(
                    "MFA for member {}: {}",
                    &fingerprint[..16.min(fingerprint.len())],
                    mfa_actions.to_csv()
                ));
            }
        }
    }
    Ok(())
}
