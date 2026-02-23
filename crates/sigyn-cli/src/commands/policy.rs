use anyhow::Result;
use clap::Subcommand;
use console::style;
use sigyn_core::audit::{AuditAction, AuditLog};
use sigyn_core::audit::entry::AuditOutcome;
use sigyn_core::crypto::keys::KeyFingerprint;
use sigyn_core::policy::engine::{AccessAction, AccessRequest, PolicyDecision};
use sigyn_core::policy::member::MemberPolicy;
use sigyn_core::policy::roles::Role;
use sigyn_core::policy::PolicyEngine;

use super::secret::{unlock_vault, check_access, UnlockedVaultContext};

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
}

fn audit(ctx: &UnlockedVaultContext, action: AuditAction, outcome: AuditOutcome) {
    let audit_path = ctx.paths.audit_path(&ctx.vault_name);
    if let Ok(mut log) = AuditLog::open(&audit_path) {
        let _ = log.append(
            &ctx.fingerprint,
            action,
            Some(ctx.env_name.clone()),
            outcome,
            ctx.loaded_identity.signing_key(),
        );
    }
}

fn parse_fingerprint(hex: &str) -> Result<KeyFingerprint> {
    KeyFingerprint::from_hex(hex)
        .map_err(|_| anyhow::anyhow!("invalid fingerprint hex: '{}'", hex))
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
                let members: Vec<_> = ctx.policy.members.values().map(|m| {
                    serde_json::json!({
                        "fingerprint": m.fingerprint.to_hex(),
                        "role": m.role.to_string(),
                        "envs": m.allowed_envs,
                        "patterns": m.secret_patterns,
                        "delegated_by": m.delegated_by.as_ref().map(|f| f.to_hex()),
                    })
                }).collect();
                crate::output::print_json(&serde_json::json!({
                    "owner": ctx.manifest.owner.to_hex(),
                    "members": members,
                }))?;
            } else {
                println!("{}", style("Vault Policy").bold());
                println!("  Owner: {}", style(ctx.manifest.owner.to_hex()).cyan());
                println!("{}", style("-".repeat(60)).dim());
                for m in ctx.policy.members.values() {
                    let fp_short = &m.fingerprint.to_hex()[..16];
                    let delegated = m.delegated_by.as_ref()
                        .map(|f| format!(" (via {})", &f.to_hex()[..16]))
                        .unwrap_or_default();
                    println!(
                        "  {} {} envs=[{}] patterns=[{}]{}",
                        style(fp_short).cyan(),
                        style(m.role.to_string()).bold(),
                        m.allowed_envs.join(","),
                        m.secret_patterns.join(","),
                        style(delegated).dim(),
                    );
                }
            }
        }

        PolicyCommands::MemberAdd { fingerprint, role, envs, patterns } => {
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
            let secret_patterns: Vec<String> = patterns.split(',').map(|s| s.trim().to_string()).collect();

            let mut member = MemberPolicy::new(fp.clone(), role);
            member.allowed_envs = allowed_envs;
            member.secret_patterns = secret_patterns;
            member.delegated_by = Some(ctx.fingerprint.clone());

            let mut policy = ctx.policy.clone();
            policy.add_member(member);
            policy.save_encrypted(&ctx.paths.policy_path(&ctx.vault_name), &ctx.cipher)?;

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

            policy.save_encrypted(&ctx.paths.policy_path(&ctx.vault_name), &ctx.cipher)?;

            audit(&ctx, AuditAction::MemberRevoked { fingerprint: fp }, AuditOutcome::Success);

            crate::output::print_success(&format!(
                "Removed member {} from policy",
                &fingerprint[..16.min(fingerprint.len())]
            ));
        }

        PolicyCommands::Check { fingerprint, action, env, key } => {
            let ctx = unlock_vault(identity, vault, None)?;

            let fp = parse_fingerprint(&fingerprint)?;
            let action = parse_action(&action)?;

            let engine = PolicyEngine::new(&ctx.policy, &ctx.manifest.owner);
            let request = AccessRequest {
                actor: fp,
                action,
                env,
                key,
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
                        crate::output::print_json(&serde_json::json!({"decision": "allow", "warning": msg}))?;
                    } else {
                        crate::output::print_success(&format!("Access: ALLOW (warning: {})", msg));
                    }
                }
                PolicyDecision::Deny(reason) => {
                    if json {
                        crate::output::print_json(&serde_json::json!({"decision": "deny", "reason": reason}))?;
                    } else {
                        println!("{} Access: DENY ({})", style("X").red().bold(), reason);
                    }
                }
            }
        }
    }
    Ok(())
}
