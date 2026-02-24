use anyhow::Result;
use clap::Subcommand;
use console::style;
use sigyn_core::audit::entry::AuditOutcome;
use sigyn_core::audit::{AuditAction, AuditLog};
use sigyn_core::crypto::envelope;
use sigyn_core::crypto::vault_cipher::VaultCipher;
use sigyn_core::identity::keygen::IdentityStore;
use sigyn_core::vault::{VaultManifest, VaultPaths};

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
}

pub fn handle(cmd: VaultCommands, identity: Option<&str>, json: bool) -> Result<()> {
    let home = sigyn_home();
    let store = IdentityStore::new(home.clone());
    let paths = VaultPaths::new(home.clone());

    match cmd {
        VaultCommands::Create { name, org } => {
            let loaded = load_identity(&store, identity)?;
            let fingerprint = loaded.identity.fingerprint.clone();

            let vault_dir = paths.vault_dir(&name);
            if vault_dir.exists() {
                anyhow::bail!("vault '{}' already exists", name);
            }

            // If --org is set, validate the org path exists
            if let Some(ref org_path_str) = org {
                let hierarchy_paths =
                    sigyn_core::hierarchy::path::HierarchyPaths::new(home.clone());
                let org_path = sigyn_core::hierarchy::path::OrgPath::parse(org_path_str)
                    .map_err(|_| anyhow::anyhow!("invalid org path: {}", org_path_str))?;
                if !hierarchy_paths.manifest_path(&org_path).exists() {
                    anyhow::bail!("org node '{}' not found", org_path_str);
                }
            }

            let mut manifest = VaultManifest::new(name.clone(), fingerprint.clone());
            manifest.org_path = org.clone();
            let vault_id = manifest.vault_id;

            let master_cipher = VaultCipher::generate();
            let header = envelope::seal_master_key(
                master_cipher.key_bytes(),
                std::slice::from_ref(&loaded.identity.encryption_pubkey),
                vault_id,
            )?;

            std::fs::create_dir_all(paths.env_dir(&name))?;

            let manifest_toml = manifest.to_toml()?;
            std::fs::write(paths.manifest_path(&name), manifest_toml)?;

            let mut header_bytes = Vec::new();
            ciborium::into_writer(&header, &mut header_bytes)
                .map_err(|e| anyhow::anyhow!("failed to encode header: {}", e))?;
            std::fs::write(paths.members_path(&name), header_bytes)?;

            let policy = sigyn_core::policy::storage::VaultPolicy::new();
            policy.save_encrypted(&paths.policy_path(&name), &master_cipher)?;

            for env_name in &manifest.environments {
                let env = sigyn_core::vault::PlaintextEnv::new();
                let encrypted =
                    sigyn_core::vault::env_file::encrypt_env(&env, &master_cipher, env_name)?;
                sigyn_core::vault::env_file::write_encrypted_env(
                    &paths.env_path(&name, env_name),
                    &encrypted,
                )?;
            }

            // Audit: vault created
            if let Ok(mut log) = AuditLog::open(&paths.audit_path(&name)) {
                let _ = log.append(
                    &fingerprint,
                    AuditAction::VaultCreated,
                    None,
                    AuditOutcome::Success,
                    loaded.signing_key(),
                );
            }

            if json {
                crate::output::print_json(&manifest)?;
            } else {
                crate::output::print_success(&format!("Vault '{}' created", name));
                println!("  ID:           {}", vault_id);
                println!("  Owner:        {}", style(fingerprint.to_hex()).cyan());
                println!("  Environments: {}", manifest.environments.join(", "));
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
                    let manifest_path = paths.manifest_path(name);
                    if let Ok(content) = std::fs::read_to_string(&manifest_path) {
                        if let Ok(manifest) = VaultManifest::from_toml(&content) {
                            println!(
                                "  {} ({})",
                                style(name).bold(),
                                manifest.environments.join(", ")
                            );
                            continue;
                        }
                    }
                    println!("  {}", style(name).bold());
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

            let content = std::fs::read_to_string(&manifest_path)?;
            let manifest = VaultManifest::from_toml(&content)?;

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
            let hierarchy_paths = sigyn_core::hierarchy::path::HierarchyPaths::new(home.clone());
            let org_path = sigyn_core::hierarchy::path::OrgPath::parse(&org)
                .map_err(|_| anyhow::anyhow!("invalid org path: {}", org))?;
            if !hierarchy_paths.manifest_path(&org_path).exists() {
                anyhow::bail!("org node '{}' not found", org);
            }

            let content = std::fs::read_to_string(&manifest_path)?;
            let mut manifest = VaultManifest::from_toml(&content)?;

            if manifest.org_path.is_some() {
                anyhow::bail!(
                    "vault '{}' is already linked to '{}'. Detach first.",
                    name,
                    manifest.org_path.as_deref().unwrap()
                );
            }

            manifest.org_path = Some(org.clone());
            std::fs::write(&manifest_path, manifest.to_toml()?)?;

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

            let content = std::fs::read_to_string(&manifest_path)?;
            let mut manifest = VaultManifest::from_toml(&content)?;

            if manifest.org_path.is_none() {
                anyhow::bail!("vault '{}' is not linked to any org", name);
            }

            let old_org = manifest.org_path.take();
            std::fs::write(&manifest_path, manifest.to_toml()?)?;

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
    }
    Ok(())
}
