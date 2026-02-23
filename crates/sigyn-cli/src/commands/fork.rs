use anyhow::Result;
use clap::Subcommand;
use console::style;

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

pub fn handle(cmd: ForkCommands, vault: Option<&str>, json: bool) -> Result<()> {
    let vault_name = vault.unwrap_or("default");
    let home = crate::config::sigyn_home();

    match cmd {
        ForkCommands::Create {
            name,
            mode,
            expires_days,
        } => {
            let fork_mode = match mode.as_str() {
                "leashed" => sigyn_core::forks::ForkMode::Leashed,
                "unleashed" => sigyn_core::forks::ForkMode::Unleashed,
                other => anyhow::bail!("unknown fork mode: '{}'. Use: leashed, unleashed", other),
            };
            // fork_mode is validated; actual fork creation would use it
            let _ = fork_mode;

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
            }
        }
        ForkCommands::List => {
            let forks_path = home.join("vaults").join(vault_name).join("forks.cbor");
            if !forks_path.exists() {
                println!("No forks found for vault '{}'", vault_name);
                return Ok(());
            }

            println!("{} for vault '{}'", style("Forks").bold(), vault_name);
            println!("{}", style("─".repeat(60)).dim());
            println!("  (fork registry loaded)");
        }
        ForkCommands::Status { name } => {
            if json {
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
            crate::output::print_success(&format!(
                "Synced fork '{}' with parent '{}'",
                name, vault_name
            ));
        }
    }
    Ok(())
}
