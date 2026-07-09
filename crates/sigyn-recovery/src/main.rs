use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use console::style;

#[derive(Parser)]
#[command(
    name = "sigyn-recovery",
    version,
    about = "Sigyn disaster recovery tool"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Split an identity's private key into Shamir shards
    Split {
        /// Identity fingerprint or name
        #[arg(long)]
        identity: String,
        /// Threshold (minimum shards needed to reconstruct)
        #[arg(long, default_value = "3")]
        threshold: u8,
        /// Total number of shards to generate
        #[arg(long, default_value = "5")]
        total: u8,
        /// Output directory for shard files
        #[arg(long)]
        output: Option<String>,
    },
    /// Reconstruct an identity from Shamir shards
    Restore {
        /// Paths to shard files (provide at least threshold count)
        #[arg(required = true)]
        shards: Vec<String>,
        /// Write the recovered identity to this path instead of installing it
        /// into the identity store (~/.sigyn/identities/)
        #[arg(long)]
        output: Option<String>,
        /// Overwrite an existing identity file at the destination
        #[arg(long)]
        force: bool,
    },
    /// Print shard details (for labeling paper backups)
    PrintShards {
        /// Paths to shard files
        #[arg(required = true)]
        shards: Vec<String>,
    },
    /// List available vault snapshots from git history
    Snapshots {
        /// Vault name
        #[arg(long)]
        vault: String,
    },
}

fn sigyn_home() -> std::path::PathBuf {
    if let Ok(home) = std::env::var("SIGYN_HOME") {
        return std::path::PathBuf::from(home);
    }
    directories::BaseDirs::new()
        .map(|d| d.home_dir().join(".sigyn"))
        .unwrap_or_else(|| std::path::PathBuf::from(".sigyn"))
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Split {
            identity,
            threshold,
            total,
            output,
        } => cmd_split(&identity, threshold, total, output.as_deref())?,
        Commands::Restore {
            shards,
            output,
            force,
        } => cmd_restore(&shards, output.as_deref(), force)?,
        Commands::PrintShards { shards } => cmd_print_shards(&shards)?,
        Commands::Snapshots { vault } => cmd_snapshots(&vault)?,
    }

    Ok(())
}

fn cmd_split(identity: &str, threshold: u8, total: u8, output_dir: Option<&str>) -> Result<()> {
    let home = sigyn_home();
    let store = sigyn_engine::identity::keygen::IdentityStore::new(home);

    // Find identity by name
    let ident = store
        .find_by_name(identity)?
        .ok_or_else(|| anyhow::anyhow!("identity '{}' not found", identity))?;

    // Prompt for passphrase to unlock
    let passphrase =
        rpassword::prompt_password(format!("Enter passphrase for '{}': ", ident.profile.name))?;

    let loaded = store
        .load(&ident.fingerprint, &passphrase)
        .context("failed to unlock identity")?;

    // Get the encryption private key bytes
    let enc_key_bytes = loaded.encryption_key().to_bytes();

    // Split into shards
    let shard_set = sigyn_engine::identity::split_secret(&enc_key_bytes, threshold, total)
        .context("failed to split secret")?;

    // Write shards to files
    let out_dir = output_dir
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| ".".into()));

    std::fs::create_dir_all(&out_dir)?;

    println!(
        "\n{} Split identity '{}' into {}-of-{} shards\n",
        style("✓").green().bold(),
        ident.profile.name,
        threshold,
        total
    );

    for shard in &shard_set.shards {
        let filename = format!(
            "shard-{}-{}.json",
            ident
                .fingerprint
                .to_hex()
                .chars()
                .take(8)
                .collect::<String>(),
            shard.index
        );
        let path = out_dir.join(&filename);
        let json = serde_json::to_string_pretty(shard)?;
        std::fs::write(&path, &json)?;
        println!(
            "  Shard {}/{}: {}",
            style(shard.index).cyan(),
            total,
            path.display()
        );
    }

    println!();
    println!(
        "{} Store these shards in {} separate secure locations.",
        style("⚠").yellow().bold(),
        total
    );
    println!(
        "  Any {} of {} shards can reconstruct the key.",
        threshold, total
    );
    println!(
        "  Losing more than {} shards makes recovery impossible.",
        total - threshold
    );

    Ok(())
}

fn cmd_restore(shard_paths: &[String], output: Option<&str>, force: bool) -> Result<()> {
    let mut shards = Vec::new();

    for path in shard_paths {
        let content =
            std::fs::read_to_string(path).context(format!("failed to read shard: {}", path))?;
        let shard: sigyn_engine::identity::Shard =
            serde_json::from_str(&content).context(format!("failed to parse shard: {}", path))?;
        shards.push(shard);
    }

    if shards.is_empty() {
        anyhow::bail!("no shards provided");
    }

    let threshold = shards[0].threshold;
    println!(
        "Reconstructing from {} shards (threshold: {})",
        shards.len(),
        threshold
    );

    if shards.iter().all(|s| s.checksum.is_none()) {
        println!(
            "{} These shards predate integrity checksums — the correctness of the",
            style("⚠ WARNING:").yellow().bold()
        );
        println!("  recovered key CANNOT be verified. If reconstruction used wrong or");
        println!("  corrupted shards, the resulting identity will silently not match.");
    }

    let recovered = sigyn_engine::identity::reconstruct_secret(&shards)
        .context("failed to reconstruct secret from shards")?;

    if recovered.len() != 32 {
        anyhow::bail!(
            "recovered key has unexpected length: {} (expected 32)",
            recovered.len()
        );
    }

    // Convert recovered bytes to encryption private key
    let mut enc_key_bytes = [0u8; 32];
    enc_key_bytes.copy_from_slice(&recovered);

    // Derive X25519 public key from the recovered encryption private key
    let enc_private = sigyn_engine::crypto::keys::X25519PrivateKey::from_bytes(enc_key_bytes);
    let enc_pubkey = enc_private.public_key();

    // Generate a new Ed25519 signing keypair (the old signing key was NOT sharded)
    let signing_kp = sigyn_engine::crypto::keys::SigningKeyPair::generate();
    let signing_pubkey = signing_kp.verifying_key();
    let signing_private_bytes = signing_kp.to_bytes();

    // Prompt for new passphrase
    let passphrase = rpassword::prompt_password("Enter new passphrase for recovered identity: ")?;
    let confirm = rpassword::prompt_password("Confirm passphrase: ")?;
    if passphrase != confirm {
        anyhow::bail!("passphrases do not match");
    }

    let profile = sigyn_engine::identity::IdentityProfile {
        name: "recovered".into(),
        email: None,
        created_at: chrono::Utc::now(),
    };

    let wrapped = sigyn_engine::identity::WrappedIdentity::wrap(
        &enc_key_bytes,
        &signing_private_bytes,
        enc_pubkey,
        signing_pubkey,
        profile,
        &passphrase,
    )
    .context("failed to wrap recovered identity")?;

    let fingerprint_hex = wrapped.fingerprint.to_hex();

    match output {
        Some(out) => {
            // Write a portable identity file (CBOR without a device-bound MAC;
            // the identity store adds one on first load).
            let path = std::path::PathBuf::from(out);
            if path.exists() && !force {
                anyhow::bail!(
                    "refusing to overwrite existing file: {} (pass --force to overwrite)",
                    path.display()
                );
            }
            let data = identity_file_bytes(&wrapped, None)?;
            sigyn_engine::io::atomic_write(&path, &data)
                .context("failed to write recovered identity file")?;

            println!(
                "\n{} Identity reconstructed and saved to: {}",
                style("✓").green().bold(),
                path.display()
            );
            println!("  Fingerprint: {}", fingerprint_hex);
            println!("  To install it, copy the file into the identity store:");
            println!(
                "    cp {} ~/.sigyn/identities/{}.identity",
                path.display(),
                fingerprint_hex
            );
        }
        None => {
            // Install directly into the identity store the CLI reads.
            let home = sigyn_home();
            let path = home
                .join("identities")
                .join(format!("{}.identity", fingerprint_hex));
            if path.exists() && !force {
                anyhow::bail!(
                    "identity already exists in the store: {} (pass --force to overwrite)",
                    path.display()
                );
            }
            let device_key = sigyn_engine::device::load_or_create_device_key(&home)
                .context("failed to load device key")?;
            let data = identity_file_bytes(&wrapped, Some(&device_key))?;
            sigyn_engine::io::atomic_write(&path, &data)
                .context("failed to write recovered identity into the identity store")?;

            println!(
                "\n{} Identity reconstructed and installed: {}",
                style("✓").green().bold(),
                path.display()
            );
            println!("  Fingerprint: {}", fingerprint_hex);
            println!("  Verify with: sigyn identity list");
        }
    }

    println!(
        "  {} A new signing keypair was generated (only the encryption key was sharded).",
        style("Note:").cyan().bold()
    );
    println!("  Unlock the identity with the new passphrase you just chose.");

    Ok(())
}

/// Context for the BLAKE3 keyed MAC appended to identity files.
/// Must stay in sync with `IDENTITY_MAC_CONTEXT` in
/// crates/sigyn-engine/src/identity/keygen.rs.
const IDENTITY_MAC_CONTEXT: &str = "sigyn-identity-file-v1";

/// Serialize a wrapped identity in the on-disk `.identity` format read by the
/// CLI's identity store: a CBOR body, optionally followed by a 32-byte BLAKE3
/// keyed MAC derived from the device key. Files without the MAC are accepted
/// by the store as the legacy format and upgraded on first load.
fn identity_file_bytes(
    wrapped: &sigyn_engine::identity::WrappedIdentity,
    device_key: Option<&[u8; 32]>,
) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    ciborium::into_writer(wrapped, &mut data).context("failed to serialize identity")?;
    if let Some(device_key) = device_key {
        let mac_key = blake3::derive_key(IDENTITY_MAC_CONTEXT, device_key);
        let mac = blake3::keyed_hash(&mac_key, &data);
        data.extend_from_slice(mac.as_bytes());
    }
    Ok(data)
}

fn cmd_print_shards(shard_paths: &[String]) -> Result<()> {
    println!("{}", style("Recovery Shard Details").bold());
    println!("{}", style("═".repeat(60)).dim());

    for path in shard_paths {
        let content =
            std::fs::read_to_string(path).context(format!("failed to read shard: {}", path))?;
        let shard: sigyn_engine::identity::Shard =
            serde_json::from_str(&content).context(format!("failed to parse shard: {}", path))?;

        println!();
        println!(
            "  {} Shard {}/{}",
            style("▶").cyan(),
            shard.index,
            shard.total
        );
        println!("  File: {}", path);
        println!("  Threshold: {}-of-{}", shard.threshold, shard.total);
        println!(
            "  Data (hex): {}...",
            shard
                .data
                .iter()
                .take(16)
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );
        println!("  Data length: {} bytes", shard.data.len());
        println!("{}", style("  ─".repeat(20)).dim());
    }

    Ok(())
}

fn cmd_snapshots(vault_name: &str) -> Result<()> {
    let home = sigyn_home();
    let vault_dir = home.join("vaults").join(vault_name);

    if !vault_dir.exists() {
        anyhow::bail!("vault '{}' not found", vault_name);
    }

    println!(
        "{} for vault '{}'",
        style("Git Snapshots").bold(),
        vault_name
    );
    println!("{}", style("─".repeat(60)).dim());

    // Try to open as git repo
    match git2::Repository::open(&vault_dir) {
        Ok(repo) => {
            let mut revwalk = repo.revwalk()?;
            revwalk.push_head()?;
            revwalk.set_sorting(git2::Sort::TIME)?;

            let mut count = 0;
            for oid in revwalk {
                let oid = oid?;
                let commit = repo.find_commit(oid)?;
                let time = commit.time();
                let ts = chrono::DateTime::from_timestamp(time.seconds(), 0).unwrap_or_default();

                println!(
                    "  {} {} {}",
                    style(format!("{:.8}", oid)).cyan(),
                    style(ts.format("%Y-%m-%d %H:%M:%S").to_string()).dim(),
                    commit.message().unwrap_or("(no message)").trim(),
                );

                count += 1;
                if count >= 20 {
                    println!("  ... (showing first 20 snapshots)");
                    break;
                }
            }

            if count == 0 {
                println!("  No snapshots found.");
            }
        }
        Err(_) => {
            println!("  Vault is not tracked by git. No snapshots available.");
            println!("  Initialize with: sigyn sync configure --remote-url <url>");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The recovery tool must write identity files in the exact format the
    /// CLI's identity store reads.
    #[test]
    fn test_identity_file_bytes_loadable_by_identity_store() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();

        let enc_private = sigyn_engine::crypto::keys::X25519PrivateKey::generate();
        let enc_pubkey = enc_private.public_key();
        let signing_kp = sigyn_engine::crypto::keys::SigningKeyPair::generate();

        let profile = sigyn_engine::identity::IdentityProfile {
            name: "recovered".into(),
            email: None,
            created_at: chrono::Utc::now(),
        };

        let wrapped = sigyn_engine::identity::WrappedIdentity::wrap(
            &enc_private.to_bytes(),
            &signing_kp.to_bytes(),
            enc_pubkey,
            signing_kp.verifying_key(),
            profile,
            "test-passphrase",
        )
        .unwrap();
        let fingerprint = wrapped.fingerprint.clone();

        let path = home
            .join("identities")
            .join(format!("{}.identity", fingerprint.to_hex()));

        // Store format: CBOR + device-key MAC.
        let device_key = sigyn_engine::device::load_or_create_device_key(&home).unwrap();
        let data = identity_file_bytes(&wrapped, Some(&device_key)).unwrap();
        sigyn_engine::io::atomic_write(&path, &data).unwrap();

        let store = sigyn_engine::identity::keygen::IdentityStore::new(home.clone());
        let loaded = store.load(&fingerprint, "test-passphrase").unwrap();
        assert_eq!(loaded.identity.fingerprint, fingerprint);
        assert_eq!(loaded.encryption_key().to_bytes(), enc_private.to_bytes());

        // Portable format (--output): plain CBOR, accepted as the legacy
        // MAC-less format and upgraded by the store on first load.
        let data = identity_file_bytes(&wrapped, None).unwrap();
        sigyn_engine::io::atomic_write(&path, &data).unwrap();
        let loaded = store.load(&fingerprint, "test-passphrase").unwrap();
        assert_eq!(loaded.identity.fingerprint, fingerprint);
    }
}
