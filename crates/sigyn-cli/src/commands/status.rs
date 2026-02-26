use anyhow::Result;
use console::style;

use crate::config::{load_config, sigyn_home};
use crate::project_config::load_project_config;
use sigyn_engine::identity::keygen::IdentityStore;
use sigyn_engine::vault::VaultPaths;

pub fn handle(json: bool) -> Result<()> {
    let home = sigyn_home();
    let config = load_config();
    let project = load_project_config();
    let paths = VaultPaths::new(home.clone());
    let store = IdentityStore::new(home.clone());

    let vaults = paths.list_vaults()?;

    // Resolve current identity
    let identity_info = config
        .default_identity
        .as_deref()
        .and_then(|name| {
            store
                .find_by_name(name)
                .ok()
                .flatten()
                .map(|id| (id.profile.name.clone(), id.fingerprint.to_hex()))
        })
        .or_else(|| {
            // Try from project config
            project
                .as_ref()
                .and_then(|p| p.project.as_ref())
                .and_then(|s| s.identity.as_deref())
                .and_then(|name| {
                    store
                        .find_by_name(name)
                        .ok()
                        .flatten()
                        .map(|id| (id.profile.name.clone(), id.fingerprint.to_hex()))
                })
        });

    // Resolve default vault for extra info
    let default_vault = project
        .as_ref()
        .and_then(|p| p.project.as_ref())
        .and_then(|s| s.vault.clone())
        .or_else(|| config.default_vault.clone());

    // Secret counts per env for default vault
    let mut env_counts: Vec<(String, &str)> = Vec::new();
    let mut sync_status_str = None;
    let mut rotation_due_count = 0u32;

    if let Some(ref dv) = default_vault {
        let manifest_path = paths.manifest_path(dv);
        if manifest_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&manifest_path) {
                if let Ok(manifest) = sigyn_engine::vault::VaultManifest::from_toml(&content) {
                    for env_name in &manifest.environments {
                        let env_path = paths.env_path(dv, env_name);
                        if env_path.exists() {
                            // Count secrets without decrypting — use file existence as indicator
                            env_counts.push((env_name.clone(), "active"));
                        } else {
                            env_counts.push((env_name.clone(), "empty"));
                        }
                    }
                }
            }
        }

        // Sync status
        let vault_dir = home.join("vaults").join(dv);
        if vault_dir.exists() {
            let engine = sigyn_engine::sync::git::GitSyncEngine::new(vault_dir);
            if engine.is_repo() {
                sync_status_str = Some(if engine.has_changes().unwrap_or(false) {
                    "dirty (uncommitted changes)"
                } else {
                    "clean"
                });
            }
        }

        // Rotation due — check rotation_schedules.toml existence
        let sched_path = home.join("vaults").join(dv).join("rotation_schedules.toml");
        if sched_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&sched_path) {
                if let Ok(schedules) = toml::from_str::<
                    std::collections::HashMap<
                        String,
                        sigyn_engine::rotation::schedule::RotationSchedule,
                    >,
                >(&content)
                {
                    rotation_due_count = schedules.len() as u32;
                }
            }
        }
    }

    // Pending invitations
    let invitations_dir = home.join("invitations");
    let pending_invitations = if invitations_dir.exists() {
        std::fs::read_dir(&invitations_dir)
            .map(|d| {
                d.filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
                    .count()
            })
            .unwrap_or(0)
    } else {
        0
    };

    if json {
        let project_json = project.as_ref().and_then(|p| p.project.as_ref()).map(|s| {
            serde_json::json!({
                "vault": s.vault,
                "env": s.env,
                "identity": s.identity,
            })
        });
        crate::output::print_json(&serde_json::json!({
            "home": home.to_string_lossy(),
            "default_vault": config.default_vault,
            "default_env": config.default_env,
            "vault_count": vaults.len(),
            "vaults": vaults,
            "identity": identity_info.as_ref().map(|(n, fp)| serde_json::json!({"name": n, "fingerprint": fp})),
            "project_config": project_json,
            "environments": env_counts.iter().map(|(n, s)| serde_json::json!({"name": n, "status": s})).collect::<Vec<_>>(),
            "sync_status": sync_status_str,
            "rotation_schedules": rotation_due_count,
            "pending_invitations": pending_invitations,
        }))?;
    } else {
        println!("{}", style("Sigyn Status").bold().cyan());
        println!("{}", style("─".repeat(40)).dim());
        println!("  Home:          {}", home.display());

        // Current identity
        if let Some((name, fp)) = &identity_info {
            println!(
                "  Identity:      {} ({})",
                style(name).bold(),
                style(&fp[..16]).dim()
            );
        } else {
            println!("  Identity:      {}", style("-").dim());
        }

        println!(
            "  Default vault: {}",
            config.default_vault.as_deref().unwrap_or("-")
        );
        println!(
            "  Default env:   {}",
            config.default_env.as_deref().unwrap_or("-")
        );
        println!("  Vaults:        {}", vaults.len());
        if !vaults.is_empty() {
            for v in &vaults {
                println!("    - {}", v);
            }
        }

        // Environments for default vault
        if !env_counts.is_empty() {
            let summary: Vec<String> = env_counts
                .iter()
                .map(|(name, status)| format!("{} ({})", name, status))
                .collect();
            println!("  Environments:  {}", summary.join(", "));
        }

        // Sync status
        if let Some(status) = sync_status_str {
            println!("  Sync:          {}", status);
        }

        // Rotation schedules
        if rotation_due_count > 0 {
            println!(
                "  Rotations:     {} schedule(s) configured",
                rotation_due_count
            );
        }

        // Pending invitations
        if pending_invitations > 0 {
            println!(
                "  Invitations:   {} pending — run: sigyn delegation pending",
                style(pending_invitations).yellow()
            );
        }

        if let Some(proj) = &project {
            if let Some(settings) = &proj.project {
                println!();
                println!("{}", style("Project Config (.sigyn.toml)").bold().cyan());
                println!("{}", style("─".repeat(40)).dim());
                println!("  Vault:    {}", settings.vault.as_deref().unwrap_or("-"));
                println!("  Env:      {}", settings.env.as_deref().unwrap_or("-"));
                println!(
                    "  Identity: {}",
                    settings.identity.as_deref().unwrap_or("-")
                );
            }
            if !proj.commands.is_empty() {
                println!(
                    "  Commands: {}",
                    proj.commands.keys().cloned().collect::<Vec<_>>().join(", ")
                );
            }
        }
    }
    Ok(())
}
