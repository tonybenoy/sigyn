use anyhow::Result;
use clap::Subcommand;
use console::style;
use std::path::PathBuf;

use crate::config::sigyn_home;
use crate::project_config::ProjectConfig;

#[derive(Subcommand)]
pub enum ProjectCommands {
    /// Initialize a .sigyn.toml for this project
    Init {
        /// Write to ~/.sigyn/project.toml instead of ./.sigyn.toml
        #[arg(long)]
        global: bool,
        /// Vault name
        #[arg(long, short)]
        vault: Option<String>,
        /// Environment name
        #[arg(long, short)]
        env: Option<String>,
        /// Identity name
        #[arg(long, short)]
        identity: Option<String>,
    },
}

pub fn handle(cmd: ProjectCommands, json: bool) -> Result<()> {
    match cmd {
        ProjectCommands::Init {
            global,
            vault,
            env,
            identity,
        } => init_project(global, vault, env, identity, json),
    }
}

fn init_project(
    global: bool,
    vault_arg: Option<String>,
    env_arg: Option<String>,
    identity_arg: Option<String>,
    json: bool,
) -> Result<()> {
    use sigyn_engine::identity::keygen::IdentityStore;
    use sigyn_engine::vault::VaultPaths;

    let home = sigyn_home();
    let store = IdentityStore::new(home.clone());
    let paths = VaultPaths::new(home.clone());

    let target_path = if global {
        home.join("project.toml")
    } else {
        PathBuf::from(".sigyn.toml")
    };

    if target_path.exists() {
        anyhow::bail!(
            "{} already exists. Edit it directly or delete it first.",
            target_path.display()
        );
    }

    // Detect project type for smart defaults
    let detection = crate::project_detect::detect_project();

    // Resolve vault: use arg, or prompt from available vaults with smart default
    let vault = if let Some(v) = vault_arg {
        Some(v)
    } else {
        let vaults = paths.list_vaults().unwrap_or_default();
        if vaults.is_empty() {
            eprintln!(
                "{}",
                style("No vaults found. Create one first: sigyn vault create <name>").dim()
            );
            eprintln!(
                "  Suggested name based on {}: {}",
                detection.source,
                style(&detection.suggested_vault_name).cyan()
            );
            None
        } else {
            // Pre-select the vault matching the detected project name, if any
            let default_idx = vaults
                .iter()
                .position(|v| v == &detection.suggested_vault_name)
                .unwrap_or(0);

            let selection = dialoguer::Select::new()
                .with_prompt(format!(
                    "Select vault for this project (detected: {})",
                    &detection.suggested_vault_name
                ))
                .items(&vaults)
                .default(default_idx)
                .interact()?;
            Some(vaults[selection].clone())
        }
    };

    // Resolve identity: use arg, or prompt from available identities
    let identity = if let Some(i) = identity_arg {
        Some(i)
    } else {
        let identities = store.list().unwrap_or_default();
        if identities.is_empty() {
            eprintln!(
                "{}",
                style("No identities found. Create one first: sigyn identity create -n <name>")
                    .dim()
            );
            None
        } else if identities.len() == 1 {
            let name = identities[0].profile.name.clone();
            eprintln!("  Using identity: {}", style(&name).cyan());
            Some(name)
        } else {
            let names: Vec<_> = identities.iter().map(|i| i.profile.name.clone()).collect();
            let selection = dialoguer::Select::new()
                .with_prompt("Select identity for this project")
                .items(&names)
                .default(0)
                .interact()?;
            Some(names[selection].clone())
        }
    };

    // Resolve env: use arg, or default to "dev"
    let env = env_arg.or_else(|| Some("dev".into()));

    // Write the project config file using the shared helper
    crate::project_config::write_project_config(
        &target_path,
        vault.as_deref(),
        identity.as_deref(),
        env.as_deref().unwrap_or("dev"),
    )?;

    let content = std::fs::read_to_string(&target_path)?;

    if json {
        let config: ProjectConfig = toml::from_str(&content)?;
        crate::output::print_json(&serde_json::json!({
            "path": target_path.display().to_string(),
            "project": config.project,
        }))?;
    } else {
        crate::output::print_success(&format!("Created {}", target_path.display()));
        println!();
        println!("{}", style(&content).dim());
        println!(
            "Edit {} to add named commands and adjust settings.",
            target_path.display()
        );
    }

    Ok(())
}
