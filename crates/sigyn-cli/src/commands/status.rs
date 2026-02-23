use anyhow::Result;
use console::style;

use crate::config::{load_config, sigyn_home};
use sigyn_core::vault::VaultPaths;

pub fn handle(json: bool) -> Result<()> {
    let home = sigyn_home();
    let config = load_config();
    let paths = VaultPaths::new(home.clone());

    let vaults = paths.list_vaults()?;

    if json {
        crate::output::print_json(&serde_json::json!({
            "home": home.to_string_lossy(),
            "default_vault": config.default_vault,
            "default_env": config.default_env,
            "vault_count": vaults.len(),
            "vaults": vaults,
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
    }
    Ok(())
}
