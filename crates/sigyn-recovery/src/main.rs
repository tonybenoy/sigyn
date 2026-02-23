use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use console::style;

#[derive(Parser)]
#[command(name = "sigyn-recovery", version, about = "Sigyn disaster recovery tool")]
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
    /// Manage succession planning
    Succession {
        #[command(subcommand)]
        command: SuccessionCommands,
    },
}

#[derive(Subcommand)]
enum SuccessionCommands {
    /// Show current succession configuration
    Show,
    /// Set a successor identity
    Set {
        /// Successor's fingerprint
        #[arg(long)]
        successor: String,
        /// Days of inactivity before succession triggers
        #[arg(long, default_value = "90")]
        dead_man_days: u64,
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
        Commands::Succession { command } => match command {
            SuccessionCommands::Show => cmd_succession_show()?,
            SuccessionCommands::Set {
                successor,
                dead_man_days,
            } => cmd_succession_set(&successor, dead_man_days)?,
        },
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
    let passphrase = rpassword::prompt_password(format!(
        "Enter passphrase for '{}': ",
        ident.profile.name
    ))?;

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
            ident.fingerprint.to_hex().chars().take(8).collect::<String>(),
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
        let content = std::fs::read_to_string(path)
            .context(format!("failed to read shard: {}", path))?;
        let shard: sigyn_core::identity::Shard = serde_json::from_str(&content)
            .context(format!("failed to parse shard: {}", path))?;
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

    let output_path = output.unwrap_or("recovered_key.bin");
    std::fs::write(output_path, &recovered)?;

    println!(
        "\n{} Key reconstructed and saved to: {}",
        style("✓").green().bold(),
        output_path
    );
    println!(
        "{}",
        style("  This file contains sensitive key material. Handle with care.").yellow()
    );

    Ok(())
}

fn cmd_print_shards(shard_paths: &[String]) -> Result<()> {
    println!("{}", style("Recovery Shard Details").bold());
    println!("{}", style("═".repeat(60)).dim());

    for path in shard_paths {
        let content = std::fs::read_to_string(path)
            .context(format!("failed to read shard: {}", path))?;
        let shard: sigyn_core::identity::Shard = serde_json::from_str(&content)
            .context(format!("failed to parse shard: {}", path))?;

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
                let ts = chrono::DateTime::from_timestamp(time.seconds(), 0)
                    .unwrap_or_default();

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
            println!(
                "  Initialize with: sigyn sync configure --remote-url <url>"
            );
        }
    }

    Ok(())
}

fn cmd_succession_show() -> Result<()> {
    let home = sigyn_home();
    let path = home.join("succession.json");

    if !path.exists() {
        println!("No succession plan configured.");
        println!("Set one with: sigyn-recovery succession set --successor <fingerprint>");
        return Ok(());
    }

    let content = std::fs::read_to_string(&path)?;
    let config: serde_json::Value = serde_json::from_str(&content)?;

    println!("{}", style("Succession Plan").bold());
    println!("{}", style("─".repeat(40)).dim());
    println!(
        "  Successor: {}",
        config["successor"].as_str().unwrap_or("(not set)")
    );
    println!(
        "  Dead-man trigger: {} days of inactivity",
        config["dead_man_days"].as_u64().unwrap_or(0)
    );

    Ok(())
}

fn cmd_succession_set(successor: &str, dead_man_days: u64) -> Result<()> {
    let home = sigyn_home();
    std::fs::create_dir_all(&home)?;
    let path = home.join("succession.json");

    let config = serde_json::json!({
        "successor": successor,
        "dead_man_days": dead_man_days,
        "configured_at": chrono::Utc::now().to_rfc3339(),
    });

    std::fs::write(&path, serde_json::to_string_pretty(&config)?)?;

    println!(
        "{} Succession plan configured",
        style("✓").green().bold()
    );
    println!("  Successor: {}", successor);
    println!(
        "  Dead-man trigger: {} days of inactivity",
        dead_man_days
    );

    Ok(())
}
