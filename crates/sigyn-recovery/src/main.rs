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
        /// Output path for the recovered identity file
        #[arg(long)]
        output: Option<String>,
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
        Commands::Restore { shards, output } => cmd_restore(&shards, output.as_deref())?,
        Commands::PrintShards { shards } => cmd_print_shards(&shards)?,
        Commands::Snapshots { vault } => cmd_snapshots(&vault)?,
    }

    Ok(())
}

fn cmd_split(identity: &str, threshold: u8, total: u8, output_dir: Option<&str>) -> Result<()> {
    let home = sigyn_home();
    let store = sigyn_core::identity::keygen::IdentityStore::new(home);

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
    let shard_set = sigyn_core::identity::split_secret(&enc_key_bytes, threshold, total)
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

fn cmd_restore(shard_paths: &[String], output: Option<&str>) -> Result<()> {
    let mut shards = Vec::new();

    for path in shard_paths {
        let content =
            std::fs::read_to_string(path).context(format!("failed to read shard: {}", path))?;
        let shard: sigyn_core::identity::Shard =
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

    let recovered = sigyn_core::identity::reconstruct_secret(&shards)
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
    let enc_private = sigyn_core::crypto::keys::X25519PrivateKey::from_bytes(enc_key_bytes);
    let enc_pubkey = enc_private.public_key();

    // Generate a new Ed25519 signing keypair (the old signing key was NOT sharded)
    let signing_kp = sigyn_core::crypto::keys::SigningKeyPair::generate();
    let signing_pubkey = signing_kp.verifying_key();
    let signing_private_bytes = signing_kp.to_bytes();

    // Prompt for new passphrase
    let passphrase = rpassword::prompt_password("Enter new passphrase for recovered identity: ")?;
    let confirm = rpassword::prompt_password("Confirm passphrase: ")?;
    if passphrase != confirm {
        anyhow::bail!("passphrases do not match");
    }

    let profile = sigyn_core::identity::IdentityProfile {
        name: "recovered".into(),
        email: None,
        created_at: chrono::Utc::now(),
    };

    let wrapped = sigyn_core::identity::WrappedIdentity::wrap(
        &enc_key_bytes,
        &signing_private_bytes,
        enc_pubkey,
        signing_pubkey,
        profile,
        &passphrase,
    )
    .context("failed to wrap recovered identity")?;

    let output_path = output.unwrap_or("recovered.identity.toml");
    let toml_content = toml::to_string_pretty(&wrapped).context("failed to serialize identity")?;
    std::fs::write(output_path, &toml_content)?;

    println!(
        "\n{} Identity reconstructed and saved to: {}",
        style("✓").green().bold(),
        output_path
    );
    println!("  Fingerprint: {}", wrapped.fingerprint.to_hex());
    println!(
        "  {} A new signing keypair was generated (only the encryption key was sharded).",
        style("Note:").cyan().bold()
    );
    println!("  Import with: sigyn identity import {}", output_path);

    Ok(())
}

fn cmd_print_shards(shard_paths: &[String]) -> Result<()> {
    println!("{}", style("Recovery Shard Details").bold());
    println!("{}", style("═".repeat(60)).dim());

    for path in shard_paths {
        let content =
            std::fs::read_to_string(path).context(format!("failed to read shard: {}", path))?;
        let shard: sigyn_core::identity::Shard =
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
