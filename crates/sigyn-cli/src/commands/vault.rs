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
    },
    /// List all vaults
    List,
    /// Show vault info
    Info {
        /// Vault name
        name: Option<String>,
    },
}

pub fn handle(cmd: VaultCommands, identity: Option<&str>, json: bool) -> Result<()> {
    let home = sigyn_home();
    let store = IdentityStore::new(home.clone());
    let paths = VaultPaths::new(home);

    match cmd {
        VaultCommands::Create { name } => {
            let loaded = load_identity(&store, identity)?;
            let fingerprint = loaded.identity.fingerprint.clone();

            let vault_dir = paths.vault_dir(&name);
            if vault_dir.exists() {
                anyhow::bail!("vault '{}' already exists", name);
            }

            let manifest = VaultManifest::new(name.clone(), fingerprint.clone());
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
            }
        }
    }
    Ok(())
}
