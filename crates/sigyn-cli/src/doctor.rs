use crate::config::sigyn_home;
use anyhow::Result;
use console::style;

pub fn run_doctor() -> Result<()> {
    println!("{}", style("Sigyn Doctor").bold().cyan());
    println!("{}", style("─".repeat(40)).dim());

    let home = sigyn_home();

    // 1. Home directory
    check("Home directory exists", home.exists());

    // 2. Identities
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

    // 3. Vaults
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

    // 4. Config file
    let config_path = home.join("config.toml");
    check("Config file exists", config_path.exists());

    // 5. Project config in current directory tree
    let has_project_config = crate::project_config::load_project_config().is_some();
    check("Project config (.sigyn.toml) found", has_project_config);

    // 6. Default vault resolves
    let config = crate::config::load_config();
    if let Some(ref dv) = config.default_vault {
        let vault_exists = home.join("vaults").join(dv).exists();
        check(&format!("Default vault '{}' exists", dv), vault_exists);
    }

    // 7. git available
    let git_ok = std::process::Command::new("git")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    check("git available (for sync)", git_ok);

    // 8. Pending invitations
    let invitations_dir = home.join("invitations");
    let pending_count = if invitations_dir.exists() {
        std::fs::read_dir(&invitations_dir)
            .map(|d| {
                d.filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
                    .count()
            })
            .unwrap_or(0)
    } else {
        0
    };
    if pending_count > 0 {
        println!(
            "  {} {} pending invitation(s) — run: sigyn delegation pending",
            style("i").blue(),
            pending_count
        );
    }

    // 9. Project type detection
    let detection = crate::project_detect::detect_project();
    println!(
        "  {} Detected project: {} (from {})",
        style("i").blue(),
        style(&detection.suggested_vault_name).bold(),
        detection.source
    );

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
