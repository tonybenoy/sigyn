use anyhow::Result;
use console::style;
use crate::config::sigyn_home;

pub fn run_doctor() -> Result<()> {
    println!("{}", style("Sigyn Doctor").bold().cyan());
    println!("{}", style("─".repeat(40)).dim());

    let home = sigyn_home();
    check("Home directory exists", home.exists());

    let id_dir = home.join("identities");
    let id_count = if id_dir.exists() {
        std::fs::read_dir(&id_dir)?.count()
    } else {
        0
    };
    check("Identity configured", id_count > 0);
    if id_count > 0 {
        println!("  {} identities found", id_count);
    }

    let vaults_dir = home.join("vaults");
    let vault_count = if vaults_dir.exists() {
        std::fs::read_dir(&vaults_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .count()
    } else {
        0
    };
    check("Vaults present", vault_count > 0);
    if vault_count > 0 {
        println!("  {} vaults found", vault_count);
    }

    let config_path = home.join("config.toml");
    check("Config file exists", config_path.exists());

    println!();
    println!("{}", style("Doctor check complete.").green());
    Ok(())
}

fn check(label: &str, ok: bool) {
    if ok {
        println!("  {} {}", style("✓").green(), label);
    } else {
        println!("  {} {}", style("✗").red(), label);
    }
}
