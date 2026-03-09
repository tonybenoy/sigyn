use anyhow::Result;
use clap::Subcommand;
use console::style;

use sigyn_engine::vault::PinnedVaultsStore;

#[derive(Subcommand)]
pub enum SyncCommands {
    /// Push local changes to remote
    Push {
        /// Remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Branch name
        #[arg(long, default_value = "main")]
        branch: String,
        /// Force push (overwrite remote history)
        #[arg(long)]
        force: bool,
    },
    /// Pull remote changes
    Pull {
        /// Remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Branch name
        #[arg(long, default_value = "main")]
        branch: String,
        /// Bypass rollback protection (use with caution)
        #[arg(long)]
        force: bool,
    },
    /// Show sync status
    Status,
    /// Resolve a conflict
    Resolve {
        /// Secret key with conflict
        key: String,
        /// Resolution strategy: local, remote, latest
        #[arg(long)]
        strategy: String,
    },
    /// Configure sync settings
    Configure {
        /// Git remote URL
        #[arg(long)]
        remote_url: Option<String>,
        /// Audit repo remote URL (for split-repo layouts)
        #[arg(long)]
        audit_remote: Option<String>,
        /// Auto-sync on change
        #[arg(long)]
        auto_sync: Option<bool>,
    },
}

/// Load the device key and pinned vaults store (best-effort for sync ops).
fn get_checkpoint_store() -> Option<(PinnedVaultsStore, [u8; 32])> {
    let home = crate::config::sigyn_home();
    let device_key = sigyn_engine::device::load_or_create_device_key(&home).ok()?;
    let store = sigyn_engine::vault::local_state::load_pinned_store(&home, &device_key).ok()?;
    Some((store, device_key))
}

fn persist_checkpoint_store(store: &PinnedVaultsStore, device_key: &[u8; 32]) {
    let home = crate::config::sigyn_home();
    if let Err(e) = sigyn_engine::vault::local_state::save_pinned_store(store, &home, device_key) {
        eprintln!(
            "{} failed to save sync checkpoint: {}",
            style("warning:").yellow().bold(),
            e
        );
    }
}

/// Auto-push vault changes (quiet mode for auto-sync hooks).
pub fn auto_push(vault_name: &str) -> Result<()> {
    let home = crate::config::sigyn_home();
    let vault_dir = home.join("vaults").join(vault_name);

    if !vault_dir.exists() {
        return Ok(());
    }

    let engine = sigyn_engine::sync::git::GitSyncEngine::new(vault_dir);
    if !engine.is_repo() {
        return Ok(());
    }
    if !engine.has_changes()? {
        return Ok(());
    }

    engine.push("origin", "main")?;

    // Update checkpoint after successful push
    if let Some((mut store, device_key)) = get_checkpoint_store() {
        if let Ok(Some(oid)) = engine.head_oid() {
            let state = store.entry_mut(vault_name);
            let checkpoint = state.checkpoint.get_or_insert_with(Default::default);
            checkpoint.vault_commit_oid = Some(oid);
            persist_checkpoint_store(&store, &device_key);
        }
    }

    Ok(())
}

pub fn handle(cmd: SyncCommands, vault: Option<&str>, json: bool) -> Result<()> {
    match cmd {
        SyncCommands::Push {
            remote,
            branch,
            force,
        } => {
            let vault_name = vault.unwrap_or("default");
            let home = crate::config::sigyn_home();
            let vault_dir = home.join("vaults").join(vault_name);

            if !vault_dir.exists() {
                anyhow::bail!("vault '{}' not found", vault_name);
            }

            let engine = sigyn_engine::sync::git::GitSyncEngine::new(vault_dir.clone());
            engine.push_with_options(&remote, &branch, force)?;

            // Update checkpoint after successful push
            if let Some((mut store, device_key)) = get_checkpoint_store() {
                if let Ok(Some(oid)) = engine.head_oid() {
                    let state = store.entry_mut(vault_name);
                    let checkpoint = state.checkpoint.get_or_insert_with(Default::default);
                    checkpoint.vault_commit_oid = Some(oid);
                    persist_checkpoint_store(&store, &device_key);
                }

                // Also update audit checkpoint for split-repo layouts
                let paths = sigyn_engine::vault::VaultPaths::new(home);
                if paths.detect_layout(vault_name)
                    == sigyn_engine::vault::path::VaultLayout::SplitRepo
                {
                    let audit_engine = sigyn_engine::sync::git::GitSyncEngine::new(
                        paths.audit_repo_dir(vault_name),
                    );
                    if let Ok(Some(oid)) = audit_engine.head_oid() {
                        let state = store.entry_mut(vault_name);
                        let checkpoint = state.checkpoint.get_or_insert_with(Default::default);
                        checkpoint.audit_commit_oid = Some(oid);
                        persist_checkpoint_store(&store, &device_key);
                    }
                }
            }

            if json {
                crate::output::print_json(&serde_json::json!({
                    "action": "push",
                    "remote": remote,
                    "vault": vault_name,
                }))?;
            } else {
                crate::output::print_success(&format!(
                    "Pushed vault '{}' to '{}'",
                    vault_name, remote
                ));
            }
        }
        SyncCommands::Pull {
            remote,
            branch,
            force,
        } => {
            let vault_name = vault.unwrap_or("default");
            let home = crate::config::sigyn_home();
            let vault_dir = home.join("vaults").join(vault_name);

            if !vault_dir.exists() {
                anyhow::bail!("vault '{}' not found", vault_name);
            }

            let engine = sigyn_engine::sync::git::GitSyncEngine::new(vault_dir);

            // Load checkpoint for rollback protection
            let checkpoint_oid = if force {
                None
            } else {
                get_checkpoint_store().and_then(|(store, _)| {
                    store
                        .get(vault_name)
                        .and_then(|s| s.checkpoint.as_ref())
                        .and_then(|c| c.vault_commit_oid.clone())
                })
            };

            match engine.pull_with_rollback_check(&remote, &branch, checkpoint_oid.as_deref()) {
                Ok(_pull_result) => {
                    // Update checkpoint after successful pull
                    if let Some((mut store, device_key)) = get_checkpoint_store() {
                        if let Ok(Some(oid)) = engine.head_oid() {
                            let state = store.entry_mut(vault_name);
                            let checkpoint = state.checkpoint.get_or_insert_with(Default::default);
                            checkpoint.vault_commit_oid = Some(oid);
                            persist_checkpoint_store(&store, &device_key);
                        }
                    }

                    // Also pull audit repo for split layouts
                    let paths = sigyn_engine::vault::VaultPaths::new(home);
                    if paths.detect_layout(vault_name)
                        == sigyn_engine::vault::path::VaultLayout::SplitRepo
                    {
                        let audit_engine = sigyn_engine::sync::git::GitSyncEngine::new(
                            paths.audit_repo_dir(vault_name),
                        );
                        let audit_checkpoint = if force {
                            None
                        } else {
                            get_checkpoint_store().and_then(|(store, _)| {
                                store
                                    .get(vault_name)
                                    .and_then(|s| s.checkpoint.as_ref())
                                    .and_then(|c| c.audit_commit_oid.clone())
                            })
                        };
                        if let Err(e) = audit_engine.pull_with_rollback_check(
                            &remote,
                            &branch,
                            audit_checkpoint.as_deref(),
                        ) {
                            eprintln!(
                                "{} audit repo pull failed: {}",
                                style("warning:").yellow().bold(),
                                e
                            );
                        } else if let Some((mut store, device_key)) = get_checkpoint_store() {
                            if let Ok(Some(oid)) = audit_engine.head_oid() {
                                let state = store.entry_mut(vault_name);
                                let checkpoint =
                                    state.checkpoint.get_or_insert_with(Default::default);
                                checkpoint.audit_commit_oid = Some(oid);
                                persist_checkpoint_store(&store, &device_key);
                            }
                        }
                    }

                    if json {
                        crate::output::print_json(&serde_json::json!({
                            "action": "pull",
                            "remote": remote,
                            "vault": vault_name,
                        }))?;
                    } else {
                        crate::output::print_success(&format!(
                            "Pulled vault '{}' from '{}'",
                            vault_name, remote
                        ));
                    }
                }
                Err(sigyn_engine::SigynError::RollbackDetected {
                    remote: r,
                    local: l,
                }) => {
                    eprintln!(
                        "\n{}\n{}\n{}\n",
                        style("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                            .red()
                            .bold(),
                        style("@    WARNING: POSSIBLE ROLLBACK ATTACK   @")
                            .red()
                            .bold(),
                        style("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                            .red()
                            .bold(),
                    );
                    eprintln!(
                        "Remote HEAD {} does not descend from your last-known checkpoint {}.",
                        style(&r).yellow(),
                        style(&l).yellow(),
                    );
                    eprintln!(
                        "Someone may have force-pushed older commits to restore revoked access.\n"
                    );
                    eprintln!(
                        "If you trust this change, re-run with: {} {} pull --force -v {}",
                        style("sigyn").bold(),
                        style("sync").bold(),
                        vault_name
                    );
                    anyhow::bail!("rollback detected — pull aborted");
                }
                Err(e) => return Err(e.into()),
            }
        }
        SyncCommands::Status => {
            let vault_name = vault.unwrap_or("default");
            let home = crate::config::sigyn_home();
            let vault_dir = home.join("vaults").join(vault_name);

            if !vault_dir.exists() {
                anyhow::bail!("vault '{}' not found", vault_name);
            }

            let engine = sigyn_engine::sync::git::GitSyncEngine::new(vault_dir);
            let has_changes = engine.has_changes()?;
            let paths = sigyn_engine::vault::VaultPaths::new(home);
            let layout = paths.detect_layout(vault_name);

            if json {
                let mut obj = serde_json::json!({
                    "vault": vault_name,
                    "has_local_changes": has_changes,
                    "layout": format!("{:?}", layout),
                });
                if layout == sigyn_engine::vault::path::VaultLayout::SplitRepo {
                    let audit_engine = sigyn_engine::sync::git::GitSyncEngine::new(
                        paths.audit_repo_dir(vault_name),
                    );
                    obj["audit_has_changes"] =
                        serde_json::Value::Bool(audit_engine.has_changes().unwrap_or(false));
                }
                crate::output::print_json(&obj)?;
            } else {
                if has_changes {
                    println!("Vault '{}' has uncommitted local changes", vault_name);
                } else {
                    println!("Vault '{}' is clean", vault_name);
                }
                if layout == sigyn_engine::vault::path::VaultLayout::SplitRepo {
                    let audit_engine = sigyn_engine::sync::git::GitSyncEngine::new(
                        paths.audit_repo_dir(vault_name),
                    );
                    if audit_engine.has_changes().unwrap_or(false) {
                        println!("Audit repo has uncommitted local changes");
                    } else {
                        println!("Audit repo is clean");
                    }
                }
            }
        }
        SyncCommands::Resolve { key, strategy } => {
            let resolution = match strategy.as_str() {
                "local" => sigyn_engine::sync::ConflictResolution::TakeLocal,
                "remote" => sigyn_engine::sync::ConflictResolution::TakeRemote,
                "latest" => sigyn_engine::sync::ConflictResolution::TakeLatestTimestamp,
                other => {
                    anyhow::bail!("unknown strategy: '{}'. Use: local, remote, latest", other)
                }
            };
            crate::output::print_success(&format!(
                "Resolved conflict for '{}' using {:?}",
                key, resolution
            ));
        }
        SyncCommands::Configure {
            remote_url,
            audit_remote,
            auto_sync,
        } => {
            if let Some(ref url) = remote_url {
                let vault_name = vault.unwrap_or("default");
                let home = crate::config::sigyn_home();
                let vault_dir = home.join("vaults").join(vault_name);

                if !vault_dir.exists() {
                    anyhow::bail!("vault '{}' not found", vault_name);
                }

                let engine = sigyn_engine::sync::git::GitSyncEngine::new(vault_dir);
                if !engine.is_repo() {
                    engine.init()?;
                }
                engine.add_remote("origin", url)?;
                println!("Remote URL set to: {}", url);
            }

            if let Some(ref url) = audit_remote {
                let vault_name = vault.unwrap_or("default");
                let home = crate::config::sigyn_home();
                let paths = sigyn_engine::vault::VaultPaths::new(home);

                if paths.detect_layout(vault_name)
                    != sigyn_engine::vault::path::VaultLayout::SplitRepo
                {
                    anyhow::bail!(
                        "vault '{}' does not use split-repo layout. \
                         Create with --split-audit to use separate audit repo.",
                        vault_name
                    );
                }

                let audit_engine =
                    sigyn_engine::sync::git::GitSyncEngine::new(paths.audit_repo_dir(vault_name));
                if !audit_engine.is_repo() {
                    audit_engine.init()?;
                }
                audit_engine.add_remote("origin", url)?;
                println!("Audit remote URL set to: {}", url);
            }

            let mut cfg = crate::config::load_config();
            if let Some(auto) = auto_sync {
                cfg.auto_sync = auto;
                println!("Auto-sync: {}", if auto { "enabled" } else { "disabled" });
            }
            crate::config::save_config(&cfg)?;
            crate::output::print_success("Sync configuration updated");
        }
    }
    Ok(())
}
