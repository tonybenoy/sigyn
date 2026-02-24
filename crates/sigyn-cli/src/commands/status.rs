use anyhow::Result;
use console::style;

use crate::config::{load_config, sigyn_home};
use crate::project_config::load_project_config;
use sigyn_core::vault::VaultPaths;

pub fn handle(json: bool) -> Result<()> {
    let home = sigyn_home();
    let config = load_config();
    let project = load_project_config();
    let paths = VaultPaths::new(home.clone());

    let vaults = paths.list_vaults()?;

    if json {
        let project_json = project.as_ref().and_then(|p| p.project.as_ref()).map(|s| {
            serde_json::json!({
                "vault": s.vault,
                "env": s.env,
                "identity": s.identity,
            })
        });
        crate::output::print_json(&serde_json::json!({
            "home": home.to_string_lossy(),
            "default_vault": config.default_vault,
            "default_env": config.default_env,
            "vault_count": vaults.len(),
            "vaults": vaults,
            "project_config": project_json,
        }))?;
    } else {
        println!("{}", style("Sigyn Status").bold().cyan());
        println!("{}", style("─".repeat(40)).dim());
        println!("  Home:          {}", home.display());
        println!(
            "  Default vault: {}",
            config.default_vault.as_deref().unwrap_or("-")
        );
        println!(
            "  Default env:   {}",
            config.default_env.as_deref().unwrap_or("-")
        );
        println!("  Vaults:        {}", vaults.len());
        if !vaults.is_empty() {
            for v in &vaults {
                println!("    - {}", v);
            }
        }

        if let Some(proj) = &project {
            if let Some(settings) = &proj.project {
                println!();
                println!("{}", style("Project Config (.sigyn.toml)").bold().cyan());
                println!("{}", style("─".repeat(40)).dim());
                println!("  Vault:    {}", settings.vault.as_deref().unwrap_or("-"));
                println!("  Env:      {}", settings.env.as_deref().unwrap_or("-"));
                println!(
                    "  Identity: {}",
                    settings.identity.as_deref().unwrap_or("-")
                );
            }
            if !proj.commands.is_empty() {
                println!(
                    "  Commands: {}",
                    proj.commands.keys().cloned().collect::<Vec<_>>().join(", ")
                );
            }
        }
    }
    Ok(())
}
