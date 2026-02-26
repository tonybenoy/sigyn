use anyhow::{Context, Result};
use clap::Subcommand;
use console::style;
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

    // Check if the agent has our key cached
    if let Some(_key_material) = crate::agent::try_agent_unlock(&fp_hex) {
        // Agent has the key — load via passphrase from agent
        // For now, we still need the passphrase to load via the store,
        // so we use the agent's PASSPHRASE protocol.
        // TODO: once agent returns raw key material, reconstruct LoadedIdentity directly
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

    // Cache in agent for future use (best-effort)
    if crate::agent::get_agent_socket().is_some() {
        let signing_bytes = loaded.signing_key().to_bytes();
        let encryption_bytes = loaded.encryption_key().to_bytes();
        let mut material = Vec::with_capacity(signing_bytes.len() + encryption_bytes.len());
        material.extend_from_slice(&signing_bytes);
        material.extend_from_slice(&encryption_bytes);
        let _ = crate::agent::agent_cache(&fp_hex, &material);
    }

    Ok(loaded)
}
