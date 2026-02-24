use anyhow::{Context, Result};
use clap::Subcommand;
use console::style;
use sigyn_engine::crypto::keys::KeyFingerprint;
use sigyn_engine::error::SigynError;
use sigyn_engine::identity::keygen::IdentityStore;
use sigyn_engine::identity::mfa::{hash_backup_code, verify_backup_code, MfaState, MfaStore};
use sigyn_engine::identity::session::MfaSessionStore;
use sigyn_engine::identity::LoadedIdentity;
use totp_rs::{Algorithm, Secret, TOTP};

use crate::commands::identity::{load_identity, read_passphrase};
use crate::config::sigyn_home;

#[derive(Subcommand)]
pub enum MfaCommands {
    /// Enroll TOTP-based MFA for an identity
    Setup,
    /// Disable MFA (requires current TOTP code)
    Disable,
    /// Show MFA enrollment status
    Status,
    /// Generate new backup codes (requires current TOTP code)
    Backup,
}

pub fn handle(cmd: MfaCommands, identity: Option<&str>, json: bool) -> Result<()> {
    match cmd {
        MfaCommands::Setup => setup(identity, json),
        MfaCommands::Disable => disable(identity, json),
        MfaCommands::Status => status(identity, json),
        MfaCommands::Backup => backup(identity, json),
    }
}

fn mfa_store() -> MfaStore {
    MfaStore::new(sigyn_home().join("identities"))
}

fn session_store() -> MfaSessionStore {
    MfaSessionStore::new(sigyn_home().join("sessions"))
}

fn encryption_key_bytes(loaded: &LoadedIdentity) -> [u8; 32] {
    loaded.encryption_key().to_bytes()
}

fn setup(identity: Option<&str>, json: bool) -> Result<()> {
    let home = sigyn_home();
    let store = IdentityStore::new(home);
    let loaded = load_identity(&store, identity)?;
    let fp = loaded.fingerprint().clone();
    let enc_key = encryption_key_bytes(&loaded);
    let mfa_store = mfa_store();

    if mfa_store.exists(&fp) {
        return Err(SigynError::MfaAlreadyEnrolled(fp.to_hex()).into());
    }

    // Generate TOTP secret
    let secret = Secret::generate_secret();
    let secret_base32 = secret.to_encoded().to_string();
    let identity_name = &loaded.identity.profile.name;

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret
            .to_bytes()
            .map_err(|e| anyhow::anyhow!("secret error: {}", e))?,
        Some("sigyn".into()),
        identity_name.clone(),
    )
    .map_err(|e| anyhow::anyhow!("TOTP creation failed: {}", e))?;

    let uri = totp.get_url();

    if json {
        crate::output::print_json(&serde_json::json!({
            "step": "verify",
            "otpauth_uri": uri,
            "secret": secret_base32,
        }))?;
    } else {
        println!("{}", style("TOTP Setup").bold());
        println!("{}", style("─".repeat(60)).dim());
        println!();
        println!("Scan this QR code with your authenticator app:");
        println!();
        qr2term::print_qr(&uri).unwrap_or_else(|_| {
            println!("  (QR rendering failed, use the URI below)");
        });
        println!();
        println!("  Secret: {}", style(&secret_base32).yellow().bold());
        println!();
    }

    // Prompt user to verify with a code
    let code = read_passphrase("Enter TOTP code to verify: ")?;
    let code = code.trim();

    if !totp
        .check_current(code)
        .map_err(|e| anyhow::anyhow!("TOTP check failed: {}", e))?
    {
        return Err(SigynError::MfaVerificationFailed.into());
    }

    // Generate 8 backup codes
    let backup_codes = generate_backup_codes(8);
    let hashed_codes: Vec<String> = backup_codes.iter().map(|c| hash_backup_code(c)).collect();

    // Save MFA state
    let state = MfaState {
        totp_secret: secret_base32,
        backup_codes: hashed_codes,
        enabled_at: chrono::Utc::now(),
    };
    mfa_store
        .save(&fp, &state, &enc_key)
        .context("failed to save MFA state")?;

    if json {
        crate::output::print_json(&serde_json::json!({
            "status": "enrolled",
            "backup_codes": backup_codes,
        }))?;
    } else {
        crate::output::print_success("MFA enrolled successfully");
        println!();
        println!(
            "{} Save these backup codes in a safe place:",
            style("IMPORTANT:").red().bold()
        );
        println!();
        for code in &backup_codes {
            println!("  {}", style(code).yellow().bold());
        }
        println!();
        println!("Each backup code can only be used once.");
    }

    Ok(())
}

fn disable(identity: Option<&str>, json: bool) -> Result<()> {
    let home = sigyn_home();
    let store = IdentityStore::new(home);
    let loaded = load_identity(&store, identity)?;
    let fp = loaded.fingerprint().clone();
    let enc_key = encryption_key_bytes(&loaded);
    let mfa_store = mfa_store();

    let state = mfa_store
        .load(&fp, &enc_key)?
        .ok_or_else(|| SigynError::MfaNotEnrolled(fp.to_hex()))?;

    // Verify with current TOTP code
    let code = read_passphrase("Enter TOTP code to confirm disable: ")?;
    let code = code.trim();

    if !verify_totp_or_backup(code, &state) {
        return Err(SigynError::MfaVerificationFailed.into());
    }

    mfa_store.remove(&fp)?;
    session_store().clear(&fp)?;

    if json {
        crate::output::print_json(&serde_json::json!({"status": "disabled"}))?;
    } else {
        crate::output::print_success("MFA disabled");
    }

    Ok(())
}

fn status(identity: Option<&str>, json: bool) -> Result<()> {
    let home = sigyn_home();
    let store = IdentityStore::new(home);
    let loaded = load_identity(&store, identity)?;
    let fp = loaded.fingerprint().clone();
    let enc_key = encryption_key_bytes(&loaded);
    let mfa_store = mfa_store();

    let enrolled = mfa_store.exists(&fp);
    let session_valid = session_store().is_valid(
        &fp,
        sigyn_engine::identity::session::DEFAULT_GRACE_PERIOD_SECS,
    );

    if json {
        let mut info = serde_json::json!({
            "enrolled": enrolled,
            "session_active": session_valid,
        });
        if enrolled {
            if let Ok(Some(state)) = mfa_store.load(&fp, &enc_key) {
                info["enabled_at"] = serde_json::json!(state.enabled_at.to_rfc3339());
                info["backup_codes_remaining"] = serde_json::json!(state.backup_codes.len());
            }
        }
        crate::output::print_json(&info)?;
    } else {
        println!("{}", style("MFA Status").bold());
        println!("{}", style("─".repeat(40)).dim());
        println!(
            "  Enrolled:       {}",
            if enrolled {
                style("yes").green()
            } else {
                style("no").red()
            }
        );
        if enrolled {
            if let Ok(Some(state)) = mfa_store.load(&fp, &enc_key) {
                println!(
                    "  Enabled at:     {}",
                    state.enabled_at.format("%Y-%m-%d %H:%M:%S UTC")
                );
                println!("  Backup codes:   {} remaining", state.backup_codes.len());
            }
        }
        println!(
            "  Session active: {}",
            if session_valid {
                style("yes").green()
            } else {
                style("no").dim()
            }
        );
    }

    Ok(())
}

fn backup(identity: Option<&str>, json: bool) -> Result<()> {
    let home = sigyn_home();
    let store = IdentityStore::new(home);
    let loaded = load_identity(&store, identity)?;
    let fp = loaded.fingerprint().clone();
    let enc_key = encryption_key_bytes(&loaded);
    let mfa_store = mfa_store();

    let mut state = mfa_store
        .load(&fp, &enc_key)?
        .ok_or_else(|| SigynError::MfaNotEnrolled(fp.to_hex()))?;

    // Verify with current TOTP code
    let code = read_passphrase("Enter TOTP code to confirm: ")?;
    let code = code.trim();

    if !verify_totp_or_backup(code, &state) {
        return Err(SigynError::MfaVerificationFailed.into());
    }

    // Generate new backup codes
    let new_codes = generate_backup_codes(8);
    let hashed = new_codes.iter().map(|c| hash_backup_code(c)).collect();
    state.backup_codes = hashed;

    mfa_store
        .save(&fp, &state, &enc_key)
        .context("failed to save updated MFA state")?;

    if json {
        crate::output::print_json(&serde_json::json!({
            "backup_codes": new_codes,
        }))?;
    } else {
        crate::output::print_success("New backup codes generated");
        println!();
        println!(
            "{} Save these backup codes in a safe place (old codes are now invalid):",
            style("IMPORTANT:").red().bold()
        );
        println!();
        for code in &new_codes {
            println!("  {}", style(code).yellow().bold());
        }
        println!();
    }

    Ok(())
}

/// Verify a TOTP code or backup code against the MFA state.
pub fn verify_totp_or_backup(code: &str, state: &MfaState) -> bool {
    // Try TOTP first
    if let Ok(totp) = make_totp(state) {
        if let Ok(true) = totp.check_current(code) {
            return true;
        }
    }

    // Try backup codes
    verify_backup_code(code, &state.backup_codes).is_some()
}

/// Verify a TOTP code or backup code, consuming the backup code if used.
/// Returns true if verified, false otherwise.
pub fn verify_and_consume_backup(code: &str, state: &mut MfaState) -> bool {
    // Try TOTP first
    if let Ok(totp) = make_totp(state) {
        if let Ok(true) = totp.check_current(code) {
            return true;
        }
    }

    // Try backup codes — consume on match
    if let Some(idx) = verify_backup_code(code, &state.backup_codes) {
        state.backup_codes.remove(idx);
        return true;
    }

    false
}

fn make_totp(state: &MfaState) -> Result<TOTP> {
    let secret_bytes = Secret::Encoded(state.totp_secret.clone())
        .to_bytes()
        .map_err(|e| anyhow::anyhow!("invalid TOTP secret: {}", e))?;
    TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes, None, String::new())
        .map_err(|e| anyhow::anyhow!("TOTP creation failed: {}", e))
}

fn generate_backup_codes(count: usize) -> Vec<String> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let charset: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    (0..count)
        .map(|_| {
            (0..8)
                .map(|_| charset[rng.gen_range(0..charset.len())] as char)
                .collect()
        })
        .collect()
}

/// Prompt for MFA verification during access checks.
/// This is called from `check_access()` when RequiresMfa is returned.
pub fn prompt_and_verify_mfa(fingerprint: &KeyFingerprint, loaded: &LoadedIdentity) -> Result<()> {
    let mfa_store = mfa_store();
    let session_store = session_store();

    // Check session grace period first
    if session_store.is_valid(
        fingerprint,
        sigyn_engine::identity::session::DEFAULT_GRACE_PERIOD_SECS,
    ) {
        return Ok(());
    }

    let enc_key = encryption_key_bytes(loaded);
    let mut state = mfa_store
        .load(fingerprint, &enc_key)?
        .ok_or_else(|| SigynError::MfaNotEnrolled(fingerprint.to_hex()))?;

    let code = read_passphrase("MFA code: ")?;
    let code = code.trim();

    if !verify_and_consume_backup(code, &mut state) {
        return Err(SigynError::MfaVerificationFailed.into());
    }

    // If a backup code was consumed, save updated state
    // (We always re-save to handle backup code consumption)
    mfa_store.save(fingerprint, &state, &enc_key)?;

    // Create session
    session_store
        .create(fingerprint)
        .context("failed to create MFA session")?;

    Ok(())
}
