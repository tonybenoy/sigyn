use anyhow::{Context, Result};
use clap::Subcommand;
use console::style;
#[cfg(unix)]
use sigyn_engine::crypto::{SigningKeyPair, X25519PrivateKey};
use sigyn_engine::identity::keygen::IdentityStore;
use sigyn_engine::identity::{Identity, IdentityProfile, LoadedIdentity};
use zeroize::Zeroize;

use crate::config::sigyn_home;

/// Read a passphrase, checking SIGYN_PASSPHRASE env var first (for testing),
/// then falling back to interactive tty prompt.
pub(crate) fn read_passphrase(prompt: &str) -> Result<String> {
    if let Ok(p) = std::env::var("SIGYN_PASSPHRASE") {
        return Ok(p);
    }
    Ok(rpassword::prompt_password(prompt)?)
}

#[derive(Subcommand)]
pub enum IdentityCommands {
    /// Create a new identity
    Create {
        /// Name for this identity
        #[arg(long, short)]
        name: String,
        /// Email address (optional)
        #[arg(long, short = 'E')]
        email: Option<String>,
    },
    /// List all identities
    List,
    /// Show identity details
    Show {
        /// Fingerprint or name
        identity: Option<String>,
    },
    /// Change the passphrase for an identity
    #[command(name = "change-passphrase")]
    ChangePassphrase {
        /// Identity name or fingerprint (uses default if omitted)
        identity: Option<String>,
    },
    /// Delete an identity
    Delete {
        /// Identity name or fingerprint
        identity: String,
        /// Force deletion even if identity is a member of local vaults
        #[arg(long)]
        force: bool,
    },
    /// Rotate keys (creates a new identity with a new fingerprint)
    #[command(name = "rotate-keys")]
    RotateKeys {
        /// Identity name or fingerprint (uses default if omitted)
        identity: Option<String>,
    },
}

pub fn handle(cmd: IdentityCommands, json: bool) -> Result<()> {
    let store = IdentityStore::new(sigyn_home());

    match cmd {
        IdentityCommands::Create { name, email } => {
            if store.find_by_name(&name)?.is_some() {
                anyhow::bail!("identity with name '{}' already exists", name);
            }

            let mut passphrase = read_passphrase("Enter passphrase: ")?;
            let mut confirm = read_passphrase("Confirm passphrase: ")?;
            if passphrase != confirm {
                passphrase.zeroize();
                confirm.zeroize();
                anyhow::bail!("passphrases do not match");
            }
            confirm.zeroize();

            if passphrase.len() < 8 {
                passphrase.zeroize();
                anyhow::bail!("passphrase must be at least 8 characters");
            }

            let profile = IdentityProfile::new(name.clone(), email);
            let identity = store
                .generate(profile, &passphrase)
                .context("failed to generate identity")?;
            passphrase.zeroize();

            if json {
                crate::output::print_json(&identity)?;
            } else {
                crate::output::print_success(&format!("Identity '{}' created", name));
                println!(
                    "  Fingerprint: {}",
                    style(identity.fingerprint.to_hex()).cyan()
                );
                println!(
                    "  Store this fingerprint — others will use it to share secrets with you."
                );
            }
        }
        IdentityCommands::List => {
            let identities = store.list()?;
            if identities.is_empty() {
                println!(
                    "No identities found. Create one with: sigyn identity create --name <name>"
                );
                return Ok(());
            }

            if json {
                crate::output::print_json(&identities)?;
            } else {
                println!("{}", style("Identities").bold());
                println!("{}", style("─".repeat(60)).dim());
                for id in &identities {
                    println!(
                        "  {} {} ({})",
                        style(&id.fingerprint.to_hex()[..16]).cyan(),
                        style(&id.profile.name).bold(),
                        id.profile.email.as_deref().unwrap_or("-")
                    );
                }
            }
        }
        IdentityCommands::Show { identity } => {
            let id = resolve_identity(&store, identity.as_deref())?;

            if json {
                crate::output::print_json(&id)?;
            } else {
                println!("{}", style("Identity").bold());
                println!("  Name:        {}", id.profile.name);
                println!(
                    "  Email:       {}",
                    id.profile.email.as_deref().unwrap_or("-")
                );
                println!("  Fingerprint: {}", style(id.fingerprint.to_hex()).cyan());
                println!(
                    "  Created:     {}",
                    id.profile.created_at.format("%Y-%m-%d %H:%M:%S UTC")
                );
            }
        }
        IdentityCommands::ChangePassphrase { identity } => {
            let id = resolve_identity(&store, identity.as_deref())?;
            let fp_hex = id.fingerprint.to_hex();

            let mut old_passphrase =
                read_passphrase(&format!("Current passphrase for '{}': ", id.profile.name))?;

            // Verify old passphrase by attempting load
            if let Err(e) = store.load(&id.fingerprint, &old_passphrase) {
                old_passphrase.zeroize();
                return Err(e).context("wrong passphrase");
            }

            let mut new_passphrase = read_passphrase("New passphrase: ")?;
            let mut confirm = read_passphrase("Confirm new passphrase: ")?;
            if new_passphrase != confirm {
                new_passphrase.zeroize();
                confirm.zeroize();
                old_passphrase.zeroize();
                anyhow::bail!("passphrases do not match");
            }
            confirm.zeroize();

            if new_passphrase.len() < 8 {
                new_passphrase.zeroize();
                old_passphrase.zeroize();
                anyhow::bail!("passphrase must be at least 8 characters");
            }

            store
                .change_passphrase(&id.fingerprint, &old_passphrase, &new_passphrase)
                .context("failed to change passphrase")?;
            old_passphrase.zeroize();
            new_passphrase.zeroize();

            // Evict agent cache so the old cached material is cleared
            #[cfg(unix)]
            {
                let _ = crate::agent::agent_evict(&fp_hex);
            }

            if json {
                crate::output::print_json(&serde_json::json!({
                    "action": "passphrase_changed",
                    "fingerprint": fp_hex,
                }))?;
            } else {
                crate::output::print_success(&format!(
                    "Passphrase changed for '{}'",
                    id.profile.name
                ));
            }
        }
        IdentityCommands::Delete { identity, force } => {
            let id = resolve_identity(&store, Some(&identity))?;
            let fp_hex = id.fingerprint.to_hex();

            // Verify ownership via passphrase
            let mut passphrase = read_passphrase(&format!(
                "Passphrase for '{}' (to confirm ownership): ",
                id.profile.name
            ))?;
            if let Err(e) = store.load(&id.fingerprint, &passphrase) {
                passphrase.zeroize();
                return Err(e).context("wrong passphrase — cannot verify identity ownership");
            }
            passphrase.zeroize();

            // Check if identity is a member of any local vault
            if !force {
                let home = sigyn_home();
                let paths = sigyn_engine::vault::VaultPaths::new(home);
                let vaults = paths.list_vaults().unwrap_or_default();
                let mut member_of = Vec::new();
                for vault_name in &vaults {
                    let members_path = paths.members_path(vault_name);
                    if let Ok(data) = std::fs::read(&members_path) {
                        if let Ok(header) =
                            sigyn_engine::crypto::envelope::extract_header_unverified(&data)
                        {
                            if sigyn_engine::crypto::envelope::has_recipient(
                                &header,
                                &id.fingerprint,
                            ) {
                                member_of.push(vault_name.clone());
                            }
                        }
                    }
                }
                if !member_of.is_empty() {
                    anyhow::bail!(
                        "identity '{}' is a member of vault(s): {}. \
                         Revoke access first, or use --force.",
                        id.profile.name,
                        member_of.join(", ")
                    );
                }
            }

            if crate::config::is_interactive() {
                let confirm = dialoguer::Confirm::new()
                    .with_prompt(format!(
                        "Delete identity '{}'? This cannot be undone.",
                        id.profile.name
                    ))
                    .default(false)
                    .interact()?;
                if !confirm {
                    println!("Aborted.");
                    return Ok(());
                }
            }

            store
                .delete(&id.fingerprint)
                .context("failed to delete identity")?;

            #[cfg(unix)]
            {
                let _ = crate::agent::agent_evict(&fp_hex);
            }

            if json {
                crate::output::print_json(&serde_json::json!({
                    "action": "identity_deleted",
                    "fingerprint": fp_hex,
                    "name": id.profile.name,
                }))?;
            } else {
                crate::output::print_success(&format!("Identity '{}' deleted", id.profile.name));
            }
        }
        IdentityCommands::RotateKeys { identity } => {
            let id = resolve_identity(&store, identity.as_deref())?;
            let old_fp_hex = id.fingerprint.to_hex();

            eprintln!(
                "{} Key rotation creates a NEW fingerprint. You must be re-invited to all vaults.",
                style("warning:").yellow().bold()
            );

            if crate::config::is_interactive() {
                let confirm = dialoguer::Confirm::new()
                    .with_prompt("Proceed with key rotation?")
                    .default(false)
                    .interact()?;
                if !confirm {
                    println!("Aborted.");
                    return Ok(());
                }
            }

            let mut passphrase =
                read_passphrase(&format!("Passphrase for '{}': ", id.profile.name))?;
            if let Err(e) = store.load(&id.fingerprint, &passphrase) {
                passphrase.zeroize();
                return Err(e).context("wrong passphrase");
            }

            // Generate new identity with same profile
            let new_identity = store
                .generate(id.profile.clone(), &passphrase)
                .context("failed to generate new identity")?;
            passphrase.zeroize();

            // Delete old identity only after new one is successfully created
            store
                .delete(&id.fingerprint)
                .context("failed to delete old identity")?;

            #[cfg(unix)]
            {
                let _ = crate::agent::agent_evict(&old_fp_hex);
            }

            if json {
                crate::output::print_json(&serde_json::json!({
                    "action": "keys_rotated",
                    "old_fingerprint": old_fp_hex,
                    "new_fingerprint": new_identity.fingerprint.to_hex(),
                }))?;
            } else {
                crate::output::print_success("Keys rotated successfully");
                println!(
                    "  Old fingerprint: {}",
                    style(&old_fp_hex).dim().strikethrough()
                );
                println!(
                    "  New fingerprint: {}",
                    style(new_identity.fingerprint.to_hex()).cyan()
                );
                println!();
                println!("{}", style("Next steps:").bold());
                println!("  Share your new fingerprint with vault owners to be re-invited.");
            }
        }
    }
    Ok(())
}

fn resolve_identity(store: &IdentityStore, name_or_fp: Option<&str>) -> Result<Identity> {
    match name_or_fp {
        Some(name_or_fp) => store
            .find_by_name(name_or_fp)?
            .or_else(|| {
                sigyn_engine::crypto::KeyFingerprint::from_hex(name_or_fp)
                    .ok()
                    .and_then(|fp| store.list().ok()?.into_iter().find(|i| i.fingerprint == fp))
            })
            .ok_or_else(|| anyhow::anyhow!("identity not found: {}", name_or_fp)),
        None => {
            let config = crate::config::load_config();
            let name = config
                .default_identity
                .ok_or_else(|| anyhow::anyhow!("no identity specified and no default set"))?;
            store
                .find_by_name(&name)?
                .ok_or_else(|| anyhow::anyhow!("default identity '{}' not found", name))
        }
    }
}

pub fn load_identity(store: &IdentityStore, name_or_fp: Option<&str>) -> Result<LoadedIdentity> {
    let identity = resolve_identity(store, name_or_fp)?;
    let fp_hex = identity.fingerprint.to_hex();

    // Check if the agent has our key cached (Unix only)
    #[cfg(unix)]
    if let Some(key_material) = crate::agent::try_agent_unlock(&fp_hex) {
        if key_material.len() == 64 {
            let signing_bytes: [u8; 32] = key_material[..32].try_into().expect("checked length");
            let encryption_bytes: [u8; 32] =
                key_material[32..64].try_into().expect("checked length");
            let signing_key = SigningKeyPair::from_bytes(&signing_bytes);
            let encryption_key = X25519PrivateKey::from_bytes(encryption_bytes);
            return Ok(LoadedIdentity::new(identity, encryption_key, signing_key));
        }
    }

    let mut passphrase = read_passphrase(&format!(
        "Passphrase for [{}...]: ",
        &fp_hex[..8.min(fp_hex.len())]
    ))?;

    let loaded = store
        .load(&identity.fingerprint, &passphrase)
        .context("failed to unlock identity (wrong passphrase?)");
    passphrase.zeroize();
    let loaded = loaded?;

    // Cache in agent for future use (best-effort, Unix only)
    #[cfg(unix)]
    if crate::agent::get_agent_socket().is_some() {
        let mut signing_bytes = loaded.signing_key().to_bytes();
        let mut encryption_bytes = loaded.encryption_key().to_bytes();
        let mut material = Vec::with_capacity(signing_bytes.len() + encryption_bytes.len());
        material.extend_from_slice(&signing_bytes);
        material.extend_from_slice(&encryption_bytes);
        signing_bytes.zeroize();
        encryption_bytes.zeroize();
        let _ = crate::agent::agent_cache(&fp_hex, &material);
        material.zeroize();
    }

    Ok(loaded)
}
