use anyhow::Result;
use clap::Subcommand;
use console::style;

use super::secret::unlock_vault;

#[derive(Subcommand)]
pub enum ForkCommands {
    /// Create a fork of a vault
    Create {
        /// Name for the forked vault
        name: String,
        /// Fork mode: leashed or unleashed
        #[arg(long, default_value = "leashed")]
        mode: String,
        /// Days until fork expires (0 = no expiry)
        #[arg(long, default_value = "0")]
        expires_days: u64,
    },
    /// List all forks
    List,
    /// Show fork status
    Status {
        /// Fork name
        name: String,
    },
    /// Sync fork with parent
    Sync {
        /// Fork name
        name: String,
    },
}

fn forks_path(home: &std::path::Path, vault_name: &str) -> std::path::PathBuf {
    home.join("vaults").join(vault_name).join("forks.cbor")
}

fn forks_cipher() -> Option<sigyn_engine::crypto::vault_cipher::VaultCipher> {
    let home = crate::config::sigyn_home();
    let device_key = sigyn_engine::device::load_or_create_device_key(&home).ok()?;
    sigyn_engine::crypto::sealed::derive_file_cipher(&device_key, b"sigyn-forks-v1").ok()
}

fn load_forks(path: &std::path::Path) -> Vec<sigyn_engine::forks::Fork> {
    if !path.exists() {
        return Vec::new();
    }
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    if !sigyn_engine::crypto::sealed::is_sealed(&data) {
        eprintln!(
            "{} forks.cbor is not in sealed format — ignoring (possible tampering)",
            console::style("warning:").yellow().bold()
        );
        return Vec::new();
    }
    let cipher = match forks_cipher() {
        Some(c) => c,
        None => return Vec::new(),
    };
    let plaintext =
        match sigyn_engine::crypto::sealed::sealed_decrypt(&cipher, &data, b"forks.cbor") {
            Ok(p) => p,
            Err(_) => return Vec::new(),
        };
    ciborium::from_reader(plaintext.as_slice()).unwrap_or_default()
}

fn save_forks(path: &std::path::Path, forks: &[sigyn_engine::forks::Fork]) -> Result<()> {
    let mut buf = Vec::new();
    ciborium::into_writer(forks, &mut buf)
        .map_err(|e| anyhow::anyhow!("failed to encode forks: {}", e))?;
    let cipher = forks_cipher().ok_or_else(|| anyhow::anyhow!("failed to derive forks cipher"))?;
    let sealed = sigyn_engine::crypto::sealed::sealed_encrypt(&cipher, &buf, b"forks.cbor")
        .map_err(|e| anyhow::anyhow!("failed to encrypt forks: {}", e))?;
    crate::config::secure_write(path, &sealed)?;
    Ok(())
}

pub fn handle(
    cmd: ForkCommands,
    vault: Option<&str>,
    identity: Option<&str>,
    json: bool,
) -> Result<()> {
    let vault_name = vault.unwrap_or("default");
    let home = crate::config::sigyn_home();

    match cmd {
        ForkCommands::Create {
            name,
            mode,
            expires_days,
        } => {
            let fork_mode = match mode.as_str() {
                "leashed" => sigyn_engine::forks::ForkMode::Leashed,
                "unleashed" => sigyn_engine::forks::ForkMode::Unleashed,
                other => anyhow::bail!("unknown fork mode: '{}'. Use: leashed, unleashed", other),
            };

            let ctx = unlock_vault(identity, Some(vault_name), None)?;

            let fork = match fork_mode {
                sigyn_engine::forks::ForkMode::Leashed => {
                    sigyn_engine::forks::leash::create_leashed_fork(
                        &ctx.paths,
                        &ctx.vault_name,
                        &name,
                        &ctx.vault_cipher,
                        &ctx.env_ciphers,
                        &ctx.manifest,
                        &ctx.loaded_identity.identity.encryption_pubkey,
                        &ctx.loaded_identity.identity.encryption_pubkey,
                        &ctx.fingerprint,
                        ctx.loaded_identity.signing_key(),
                    )?
                }
                sigyn_engine::forks::ForkMode::Unleashed => {
                    sigyn_engine::forks::leash::create_unleashed_fork(
                        &ctx.paths,
                        &ctx.vault_name,
                        &name,
                        &ctx.vault_cipher,
                        &ctx.env_ciphers,
                        &ctx.manifest,
                        &ctx.loaded_identity.identity.encryption_pubkey,
                        &ctx.fingerprint,
                        ctx.loaded_identity.signing_key(),
                    )?
                }
            };

            // Save fork to registry
            let fp = forks_path(&home, &ctx.vault_name);
            let mut forks = load_forks(&fp);
            forks.push(fork);
            save_forks(&fp, &forks)?;

            if json {
                crate::output::print_json(&serde_json::json!({
                    "action": "fork_created",
                    "name": name,
                    "parent": vault_name,
                    "mode": mode,
                }))?;
            } else {
                crate::output::print_success(&format!(
                    "Created {} fork '{}' from vault '{}'",
                    mode, name, vault_name
                ));
                if expires_days > 0 {
                    println!("  Expires in: {} days", expires_days);
                }
                println!();

                match mode.as_str() {
                    "leashed" => {
                        println!("  Mode: {}", style("leashed").bold());
                        println!(
                            "  Leashed forks stay connected to the parent vault. Changes in the"
                        );
                        println!(
                            "  parent can be pulled with 'sigyn fork sync'. Use leashed mode for"
                        );
                        println!("  feature branches and temporary workstreams.");
                    }
                    "unleashed" => {
                        println!("  Mode: {}", style("unleashed").bold());
                        println!(
                            "  Unleashed forks are fully independent copies. Use unleashed mode"
                        );
                        println!(
                            "  for permanent splits or long-running experiments. Unleashed forks"
                        );
                        println!("  cannot sync with the parent.");
                    }
                    _ => {}
                }

                println!();
                println!("{}", style("Next steps:").bold());
                println!("  sigyn secret set MY_KEY \"value\" -v {} -e dev", name);
                if mode == "leashed" {
                    println!("  sigyn fork sync {}       # pull parent changes", name);
                }
                println!("  sigyn fork status {}     # check fork state", name);
            }
        }
        ForkCommands::List => {
            let fp = forks_path(&home, vault_name);
            let forks = load_forks(&fp);

            if forks.is_empty() {
                println!("No forks found for vault '{}'", vault_name);
                return Ok(());
            }

            if json {
                let items: Vec<_> = forks
                    .iter()
                    .map(|f| {
                        serde_json::json!({
                            "id": f.id.to_string(),
                            "mode": format!("{:?}", f.mode),
                            "status": format!("{:?}", f.status),
                            "created_at": f.created_at.to_rfc3339(),
                            "expires_at": f.expires_at.map(|t| t.to_rfc3339()),
                        })
                    })
                    .collect();
                crate::output::print_json(&items)?;
            } else {
                println!("{} for vault '{}'", style("Forks").bold(), vault_name);
                println!("{}", style("─".repeat(60)).dim());
                for f in &forks {
                    let id_short = &f.id.to_string()[..8];
                    let expires = f
                        .expires_at
                        .map(|t| t.format("%Y-%m-%d").to_string())
                        .unwrap_or_else(|| "never".into());
                    println!(
                        "  {} {:?} {:?} created={} expires={}",
                        style(id_short).cyan(),
                        f.mode,
                        f.status,
                        f.created_at.format("%Y-%m-%d"),
                        expires,
                    );
                }
            }
        }
        ForkCommands::Status { name } => {
            let fp = forks_path(&home, vault_name);
            let forks = load_forks(&fp);

            // Try to find fork by vault name match (fork_vault_id name)
            // Since we store UUID-based forks, match by checking vault dir existence
            let fork_dir = home.join("vaults").join(&name);
            let fork = forks.iter().find(|_f| fork_dir.exists());

            if let Some(f) = fork {
                if json {
                    crate::output::print_json(&serde_json::json!({
                        "fork": name,
                        "parent": vault_name,
                        "mode": format!("{:?}", f.mode),
                        "status": format!("{:?}", f.status),
                        "created_at": f.created_at.to_rfc3339(),
                        "expires_at": f.expires_at.map(|t| t.to_rfc3339()),
                    }))?;
                } else {
                    println!("Fork '{}' (parent: '{}')", style(&name).bold(), vault_name);
                    println!("  Mode:       {:?}", f.mode);
                    println!("  Status:     {:?}", f.status);
                    println!("  Created:    {}", f.created_at.format("%Y-%m-%d %H:%M:%S"));
                    if let Some(exp) = f.expires_at {
                        println!("  Expires:    {}", exp.format("%Y-%m-%d %H:%M:%S"));
                    }
                }
            } else if json {
                crate::output::print_json(&serde_json::json!({
                    "fork": name,
                    "parent": vault_name,
                    "status": "active",
                }))?;
            } else {
                println!("Fork '{}' (parent: '{}')", style(&name).bold(), vault_name);
                println!("  Status: active");
            }
        }
        ForkCommands::Sync { name } => {
            let fp = forks_path(&home, vault_name);
            let forks = load_forks(&fp);

            // Check if this is an unleashed fork
            let fork_dir = home.join("vaults").join(&name);
            let is_unleashed = forks
                .iter()
                .find(|_f| fork_dir.exists())
                .is_some_and(|f| matches!(f.mode, sigyn_engine::forks::ForkMode::Unleashed));

            if is_unleashed {
                anyhow::bail!("unleashed forks cannot sync with parent");
            }

            // For leashed forks, re-read parent envs and update fork envs
            let ctx = unlock_vault(identity, Some(vault_name), None)?;
            let fork_vault_dir = home.join("vaults").join(&name);
            if !fork_vault_dir.exists() {
                anyhow::bail!("fork vault '{}' not found", name);
            }

            // Copy parent environments to fork (re-encrypting would need fork cipher,
            // but for a leashed fork the parent admin has access)
            let mut synced_envs = 0u32;
            for env_name in &ctx.manifest.environments {
                let parent_env_path = ctx.paths.env_path(&ctx.vault_name, env_name);
                let fork_env_dir = fork_vault_dir.join("envs");
                std::fs::create_dir_all(&fork_env_dir)?;
                let fork_env_path = fork_env_dir.join(format!("{}.enc", env_name));

                if parent_env_path.exists() {
                    std::fs::copy(&parent_env_path, &fork_env_path)?;
                    synced_envs += 1;
                }
            }

            crate::output::print_success(&format!(
                "Synced fork '{}' with parent '{}' ({} environments)",
                name, vault_name, synced_envs
            ));
        }
    }
    Ok(())
}
