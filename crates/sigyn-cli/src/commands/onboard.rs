use anyhow::Result;
use console::style;
use sigyn_engine::identity::keygen::IdentityStore;
use sigyn_engine::vault::VaultPaths;

use crate::config::sigyn_home;

pub fn handle(json: bool) -> Result<()> {
    let home = sigyn_home();
    let store = IdentityStore::new(home.clone());
    let paths = VaultPaths::new(home.clone());

    if json {
        // Non-interactive: report what's missing
        let identities = store.list().unwrap_or_default();
        let vaults = paths.list_vaults().unwrap_or_default();
        let has_project = crate::project_config::load_project_config().is_some();

        crate::output::print_json(&serde_json::json!({
            "has_identity": !identities.is_empty(),
            "has_vault": !vaults.is_empty(),
            "has_project_config": has_project,
            "identity_count": identities.len(),
            "vault_count": vaults.len(),
        }))?;
        return Ok(());
    }

    if !crate::config::is_interactive() {
        // Print checklist of what's missing
        let identities = store.list().unwrap_or_default();
        let vaults = paths.list_vaults().unwrap_or_default();
        let has_project = crate::project_config::load_project_config().is_some();

        println!("{}", style("Sigyn Setup Checklist").bold().cyan());
        println!("{}", style("─".repeat(40)).dim());
        check("Identity created", !identities.is_empty());
        check("Vault created", !vaults.is_empty());
        check("Project config (.sigyn.toml)", has_project);

        if identities.is_empty() {
            println!("  → sigyn identity create -n <name>");
        }
        if vaults.is_empty() {
            println!("  → sigyn vault create <name>");
        }
        if !has_project {
            println!("  → sigyn project init");
        }
        return Ok(());
    }

    println!("{}", style("Welcome to Sigyn!").bold().cyan());
    println!("This wizard will help you set up your secret management.\n");

    let mut setup_summary = Vec::new();

    // Step 1: Identity
    let identities = store.list().unwrap_or_default();
    if identities.is_empty() {
        println!("{}", style("Step 1: Create an identity").bold());
        println!("An identity is your cryptographic keypair for encrypting and signing.\n");

        let create = dialoguer::Confirm::new()
            .with_prompt("Create an identity now?")
            .default(true)
            .interact()?;

        if create {
            let detection = crate::project_detect::detect_project();
            let default_name = std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| detection.suggested_vault_name.clone());

            let name: String = dialoguer::Input::new()
                .with_prompt("Identity name")
                .default(default_name)
                .interact_text()?;

            crate::commands::identity::handle(
                crate::commands::identity::IdentityCommands::Create {
                    name: name.clone(),
                    email: None,
                },
                false,
            )?;
            setup_summary.push(format!("Identity '{}' created", name));
        }
        println!();
    } else {
        println!(
            "{} Identity: {} ({})",
            style("✓").green(),
            style(&identities[0].profile.name).bold(),
            &identities[0].fingerprint.to_hex()[..16]
        );
        println!();
    }

    // Step 2: Vault
    let vaults = paths.list_vaults().unwrap_or_default();
    if vaults.is_empty() {
        println!("{}", style("Step 2: Create a vault").bold());
        println!("A vault holds your encrypted secrets.\n");

        let create = dialoguer::Confirm::new()
            .with_prompt("Create a vault now?")
            .default(true)
            .interact()?;

        if create {
            let detection = crate::project_detect::detect_project();
            let name: String = dialoguer::Input::new()
                .with_prompt("Vault name")
                .default(detection.suggested_vault_name.clone())
                .interact_text()?;

            let identities = store.list().unwrap_or_default();
            let identity_name = identities.first().map(|i| i.profile.name.as_str());

            crate::commands::vault::handle(
                crate::commands::vault::VaultCommands::Create {
                    names: vec![name.clone()],
                    org: None,
                    split_audit: false,
                    remote_url: None,
                },
                identity_name,
                false,
            )?;
            setup_summary.push(format!("Vault '{}' created", name));
        }
        println!();
    } else {
        println!("{} Vault: {}", style("✓").green(), vaults.join(", "));
        println!();
    }

    // Step 3: Scan for .env files
    println!("{}", style("Step 3: Import existing secrets").bold());
    let cwd = std::env::current_dir()?;
    let env_files: Vec<_> = [".env", ".env.local", ".env.example"]
        .iter()
        .filter(|f| cwd.join(f).exists())
        .collect();

    if !env_files.is_empty() {
        println!(
            "  Found: {}",
            env_files
                .iter()
                .map(|f| style(f).cyan().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );

        let import = dialoguer::Confirm::new()
            .with_prompt("Import secrets from these files?")
            .default(true)
            .interact()?;

        if import {
            for env_file in &env_files {
                let path = cwd.join(env_file).display().to_string();
                println!("  Importing {}...", env_file);
                let result = crate::commands::import::handle(
                    crate::commands::import::ImportCommands::Dotenv {
                        file: path,
                        env: None,
                    },
                    None,
                    None,
                    false,
                );
                if let Err(e) = result {
                    eprintln!(
                        "  {} import of {} failed: {}",
                        style("warning:").yellow().bold(),
                        env_file,
                        e
                    );
                } else {
                    setup_summary.push(format!("Imported {}", env_file));
                }
            }
        }
    } else {
        println!("  No .env files found in current directory.");
    }
    println!();

    // Step 4: Project config
    let has_project = crate::project_config::load_project_config().is_some();
    if !has_project {
        println!("{}", style("Step 4: Project config").bold());

        let vaults = paths.list_vaults().unwrap_or_default();
        if !vaults.is_empty() {
            let identities = store.list().unwrap_or_default();
            let identity_name = identities.first().map(|i| i.profile.name.as_str());
            let vault_name = vaults.first().map(|v| v.as_str()).unwrap_or("default");

            if crate::project_config::offer_project_init(vault_name, identity_name, "dev")? {
                setup_summary.push("Created .sigyn.toml".into());
            }
        } else {
            println!("  Skipped (no vaults available).");
        }
    } else {
        println!("{} Project config (.sigyn.toml) found", style("✓").green());
    }

    // Summary
    println!();
    println!("{}", style("─".repeat(40)).dim());
    if setup_summary.is_empty() {
        println!(
            "{} Everything is already configured!",
            style("✓").green().bold()
        );
    } else {
        println!("{}", style("Setup complete:").bold().green());
        for item in &setup_summary {
            println!("  {} {}", style("✓").green(), item);
        }
    }

    println!();
    println!("{}", style("Quick start:").bold());
    println!("  sigyn secret set MY_SECRET \"value\" -e dev");
    println!("  sigyn secret list -e dev");
    println!("  sigyn run -e dev -- ./myapp");

    Ok(())
}

fn check(label: &str, ok: bool) {
    if ok {
        println!("  {} {}", style("✓").green(), label);
    } else {
        println!("  {} {}", style("✗").red(), label);
    }
}
