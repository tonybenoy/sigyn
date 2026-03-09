use anyhow::{Context, Result};
use base64::Engine;
use clap::Subcommand;
use console::style;
use sigyn_engine::identity::keygen::IdentityStore;

use crate::config::sigyn_home;

#[derive(Subcommand)]
pub enum CiCommands {
    /// Export a single CI bundle for use in GitHub Actions (or other CI systems)
    Setup {
        /// Identity name or fingerprint (uses default if omitted)
        identity: Option<String>,
    },
}

pub fn handle(cmd: CiCommands, json: bool) -> Result<()> {
    match cmd {
        CiCommands::Setup { identity } => handle_setup(identity.as_deref(), json),
    }
}

fn handle_setup(identity: Option<&str>, json: bool) -> Result<()> {
    let home = sigyn_home();
    let store = IdentityStore::new(home.clone());

    let id = super::identity::resolve_identity_pub(&store, identity)?;
    let fp_hex = id.fingerprint.to_hex();

    // Read identity file
    let identity_path = home.join("identities").join(format!("{}.identity", fp_hex));
    let identity_bytes = std::fs::read(&identity_path)
        .with_context(|| format!("failed to read identity file: {}", identity_path.display()))?;
    let identity_b64 = base64::engine::general_purpose::STANDARD.encode(&identity_bytes);

    // Read device key
    let device_key_path = home.join(".device_key");
    let device_key_bytes = std::fs::read(&device_key_path)
        .with_context(|| format!("failed to read device key: {}", device_key_path.display()))?;
    let device_key_b64 = base64::engine::general_purpose::STANDARD.encode(&device_key_bytes);

    // Build the bundle: JSON with all three values, then base64 the whole thing
    let bundle_json = serde_json::json!({
        "fingerprint": fp_hex,
        "identity": identity_b64,
        "device_key": device_key_b64,
    });
    let bundle_b64 =
        base64::engine::general_purpose::STANDARD.encode(bundle_json.to_string().as_bytes());

    if json {
        crate::output::print_json(&serde_json::json!({
            "identity_name": id.profile.name,
            "fingerprint": fp_hex,
            "bundle": bundle_b64,
        }))?;
    } else {
        println!(
            "{} CI setup for identity '{}' ({}...)",
            style("sigyn ci").cyan().bold(),
            style(&id.profile.name).bold(),
            &fp_hex[..16.min(fp_hex.len())]
        );
        println!();
        println!(
            "{}",
            style("Add these as GitHub Actions secrets (Settings > Secrets):").bold()
        );
        println!();

        println!("{}", style("1. SIGYN_CI_BUNDLE:").yellow().bold());
        println!("{}", bundle_b64);
        println!();

        println!("{}", style("2. SIGYN_PASSPHRASE:").yellow().bold());
        println!("(your identity passphrase — enter manually)");
        println!();

        println!("{}", style("3. VAULT_SSH_KEY:").yellow().bold());
        println!("(SSH deploy key with read access to your vault repo)");
        println!();

        println!("{}", style("Usage in your workflow:").bold());
        println!();
        println!(
            "{}",
            style(
                "\
  - uses: tonybenoy/sigyn/action@main
    with:
      bundle: ${{ secrets.SIGYN_CI_BUNDLE }}
      passphrase: ${{ secrets.SIGYN_PASSPHRASE }}
      vault-ssh-key: ${{ secrets.VAULT_SSH_KEY }}
      vault-repo: git@github.com:org/sigyn-vaults.git
      vault: myapp
      environment: prod"
            )
            .dim()
        );
        println!();

        println!(
            "{} This identity must be a member of the target vault with read access.",
            style("note:").cyan().bold()
        );
        println!("      Create a dedicated CI identity rather than reusing a personal one.");
    }

    Ok(())
}
