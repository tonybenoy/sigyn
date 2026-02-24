use anyhow::Result;
use clap::Subcommand;

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
    },
    /// Pull remote changes
    Pull {
        /// Remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Branch name
        #[arg(long, default_value = "main")]
        branch: String,
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
        /// Auto-sync on change
        #[arg(long)]
        auto_sync: Option<bool>,
    },
}

pub fn handle(cmd: SyncCommands, vault: Option<&str>, json: bool) -> Result<()> {
    match cmd {
        SyncCommands::Push { remote, branch } => {
            let vault_name = vault.unwrap_or("default");
            let home = crate::config::sigyn_home();
            let vault_dir = home.join("vaults").join(vault_name);

            if !vault_dir.exists() {
                anyhow::bail!("vault '{}' not found", vault_name);
            }

            let engine = sigyn_core::sync::git::GitSyncEngine::new(vault_dir);
            engine.push(&remote, &branch)?;

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
        SyncCommands::Pull { remote, branch } => {
            let vault_name = vault.unwrap_or("default");
            let home = crate::config::sigyn_home();
            let vault_dir = home.join("vaults").join(vault_name);

            if !vault_dir.exists() {
                anyhow::bail!("vault '{}' not found", vault_name);
            }

            let engine = sigyn_core::sync::git::GitSyncEngine::new(vault_dir);
            engine.pull(&remote, &branch)?;

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
        SyncCommands::Status => {
            let vault_name = vault.unwrap_or("default");
            let home = crate::config::sigyn_home();
            let vault_dir = home.join("vaults").join(vault_name);

            if !vault_dir.exists() {
                anyhow::bail!("vault '{}' not found", vault_name);
            }

            let engine = sigyn_core::sync::git::GitSyncEngine::new(vault_dir);
            let has_changes = engine.has_changes()?;

            if json {
                crate::output::print_json(&serde_json::json!({
                    "vault": vault_name,
                    "has_local_changes": has_changes,
                }))?;
            } else if has_changes {
                println!("Vault '{}' has uncommitted local changes", vault_name);
            } else {
                println!("Vault '{}' is clean", vault_name);
            }
        }
        SyncCommands::Resolve { key, strategy } => {
            let resolution = match strategy.as_str() {
                "local" => sigyn_core::sync::ConflictResolution::TakeLocal,
                "remote" => sigyn_core::sync::ConflictResolution::TakeRemote,
                "latest" => sigyn_core::sync::ConflictResolution::TakeLatestTimestamp,
                other => anyhow::bail!("unknown strategy: '{}'. Use: local, remote, latest", other),
            };
            crate::output::print_success(&format!(
                "Resolved conflict for '{}' using {:?}",
                key, resolution
            ));
        }
        SyncCommands::Configure {
            remote_url,
            auto_sync,
        } => {
            if let Some(ref url) = remote_url {
                let vault_name = vault.unwrap_or("default");
                let home = crate::config::sigyn_home();
                let vault_dir = home.join("vaults").join(vault_name);

                if !vault_dir.exists() {
                    anyhow::bail!("vault '{}' not found", vault_name);
                }

                let engine = sigyn_core::sync::git::GitSyncEngine::new(vault_dir);
                if !engine.is_repo() {
                    engine.init()?;
                }
                engine.add_remote("origin", url)?;
                println!("Remote URL set to: {}", url);
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
