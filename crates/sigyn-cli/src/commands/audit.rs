use anyhow::Result;
use clap::Subcommand;
use console::style;

#[derive(Subcommand)]
pub enum AuditCommands {
    /// Show recent audit entries
    Tail {
        /// Number of entries to show
        #[arg(short, long, default_value = "20")]
        n: usize,
    },
    /// Verify audit chain integrity
    Verify,
    /// Query audit log
    Query {
        /// Filter by actor fingerprint
        #[arg(long)]
        actor: Option<String>,
        /// Filter by environment
        #[arg(long)]
        env: Option<String>,
    },
    /// Export audit log
    Export {
        /// Output file path
        #[arg(long)]
        output: String,
        /// Format: json, csv
        #[arg(long, default_value = "json")]
        format: String,
    },
    /// Sign the latest audit entry as a witness
    Witness,
    /// Anchor audit log to git (cryptographic hash commit)
    Anchor,
}

fn derive_audit_cipher(
    ctx: &super::secret::UnlockedVaultContext,
) -> Result<sigyn_engine::crypto::vault_cipher::VaultCipher> {
    sigyn_engine::crypto::sealed::derive_file_cipher_with_salt(
        ctx.cipher.key_bytes(),
        b"sigyn-audit-v1",
        &ctx.manifest.vault_id,
    )
    .map_err(|e| anyhow::anyhow!("failed to derive audit cipher: {}", e))
}

pub fn handle(
    cmd: AuditCommands,
    vault: Option<&str>,
    identity: Option<&str>,
    json: bool,
) -> Result<()> {
    let vault_name = vault.unwrap_or("default");

    match cmd {
        AuditCommands::Tail { n } => {
            let ctx = super::secret::unlock_vault(identity, Some(vault_name), None)?;
            super::secret::check_access(
                &ctx,
                sigyn_engine::policy::engine::AccessAction::Audit,
                None,
            )?;

            let audit_path = ctx.paths.audit_path(&ctx.vault_name);
            if !audit_path.exists() {
                println!("No audit log found for vault '{}'", ctx.vault_name);
                return Ok(());
            }

            let log = sigyn_engine::audit::AuditLog::open(&audit_path, derive_audit_cipher(&ctx)?)?;
            let entries = log.tail(n)?;

            if json {
                crate::output::print_json(&entries)?;
            } else {
                println!(
                    "{} {}",
                    style("Audit Log").bold(),
                    style(format!("(last {} entries)", entries.len())).dim()
                );
                println!("{}", style("─".repeat(80)).dim());
                for entry in &entries {
                    println!(
                        "  {} {} {} {}",
                        style(format!("#{}", entry.sequence)).dim(),
                        style(entry.timestamp.format("%Y-%m-%d %H:%M:%S").to_string()).cyan(),
                        style(format!("{:?}", entry.action)).yellow(),
                        entry.env.as_deref().unwrap_or("-"),
                    );
                }
            }
        }
        AuditCommands::Verify => {
            let ctx = super::secret::unlock_vault(identity, Some(vault_name), None)?;
            super::secret::check_access(
                &ctx,
                sigyn_engine::policy::engine::AccessAction::Audit,
                None,
            )?;

            let audit_path = ctx.paths.audit_path(&ctx.vault_name);
            if !audit_path.exists() {
                println!("No audit log found for vault '{}'", ctx.vault_name);
                return Ok(());
            }

            let log = sigyn_engine::audit::AuditLog::open(&audit_path, derive_audit_cipher(&ctx)?)?;
            match log.verify_chain() {
                Ok(count) => {
                    if json {
                        crate::output::print_json(&serde_json::json!({
                            "valid": true,
                            "entries_verified": count,
                        }))?;
                    } else {
                        crate::output::print_success(&format!(
                            "Audit chain verified: {} entries, all hashes valid",
                            count
                        ));
                    }
                }
                Err(e) => {
                    let err_msg = e.to_string();
                    if json {
                        crate::output::print_json(&serde_json::json!({
                            "valid": false,
                            "error": err_msg,
                        }))?;
                    } else {
                        eprintln!(
                            "{} Audit chain verification failed: {}",
                            style("ERROR").red().bold(),
                            err_msg
                        );
                    }
                }
            }
        }
        AuditCommands::Query { actor, env } => {
            let ctx = super::secret::unlock_vault(identity, Some(vault_name), None)?;
            super::secret::check_access(
                &ctx,
                sigyn_engine::policy::engine::AccessAction::Audit,
                None,
            )?;

            let audit_path = ctx.paths.audit_path(&ctx.vault_name);
            if !audit_path.exists() {
                println!("No audit log found for vault '{}'", ctx.vault_name);
                return Ok(());
            }

            let log = sigyn_engine::audit::AuditLog::open(&audit_path, derive_audit_cipher(&ctx)?)?;
            let all = log.tail(1000)?;
            let filtered: Vec<_> = all
                .into_iter()
                .filter(|e| {
                    if let Some(ref a) = actor {
                        if e.actor.to_hex() != *a {
                            return false;
                        }
                    }
                    if let Some(ref env_filter) = env {
                        if e.env.as_deref() != Some(env_filter.as_str()) {
                            return false;
                        }
                    }
                    true
                })
                .collect();

            if json {
                crate::output::print_json(&filtered)?;
            } else {
                println!("Found {} matching entries", filtered.len());
                for entry in &filtered {
                    println!(
                        "  #{} {} {:?} {}",
                        entry.sequence,
                        entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
                        entry.action,
                        entry.env.as_deref().unwrap_or("-"),
                    );
                }
            }
        }
        AuditCommands::Witness => {
            // Unlock the vault to obtain the current identity and signing key
            let ctx = super::secret::unlock_vault(identity, Some(vault_name), None)?;

            let audit_path = ctx.paths.audit_path(&ctx.vault_name);
            if !audit_path.exists() {
                anyhow::bail!("no audit log found for vault '{}'", ctx.vault_name);
            }

            let log = sigyn_engine::audit::AuditLog::open(&audit_path, derive_audit_cipher(&ctx)?)?;
            let entries = log.tail(1)?;
            let latest = entries.last().ok_or_else(|| {
                anyhow::anyhow!("audit log is empty for vault '{}'", ctx.vault_name)
            })?;

            // Sign the entry hash with the current identity's signing key
            let signature = ctx.loaded_identity.signing_key().sign(&latest.entry_hash);
            let witness_sig = sigyn_engine::audit::WitnessSignature {
                witness: ctx.fingerprint.clone(),
                signature,
                timestamp: chrono::Utc::now(),
            };

            // Persist to the witnesses file next to the audit log (encrypted)
            let witnesses_path = ctx.paths.witnesses_path(&ctx.vault_name);
            let witness_cipher = sigyn_engine::crypto::sealed::derive_file_cipher_with_salt(
                ctx.cipher.key_bytes(),
                b"sigyn-witness-v1",
                &ctx.manifest.vault_id,
            )
            .map_err(|e| anyhow::anyhow!("failed to derive witness cipher: {}", e))?;
            let mut witness_log =
                sigyn_engine::audit::WitnessLog::open(&witnesses_path, witness_cipher)?;
            witness_log.add_witness(latest.entry_hash, witness_sig)?;

            let witness_count = witness_log.witnesses_for(&latest.entry_hash).len();

            if json {
                crate::output::print_json(&serde_json::json!({
                    "action": "witnessed",
                    "entry_sequence": latest.sequence,
                    "entry_hash": latest.entry_hash.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    "witness": ctx.fingerprint.to_hex(),
                    "total_witnesses": witness_count,
                }))?;
            } else {
                crate::output::print_success(&format!(
                    "Witnessed audit entry #{} (hash: {}...)",
                    latest.sequence,
                    &latest
                        .entry_hash
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()[..16],
                ));
                println!("  Signed by: {}", &ctx.fingerprint.to_hex()[..12]);
                println!("  Total witnesses for this entry: {}", witness_count);
            }
        }
        AuditCommands::Anchor => {
            let ctx = super::secret::unlock_vault(identity, Some(vault_name), None)?;
            super::secret::check_access(
                &ctx,
                sigyn_engine::policy::engine::AccessAction::Audit,
                None,
            )?;

            let audit_path = ctx.paths.audit_path(&ctx.vault_name);
            if !audit_path.exists() {
                anyhow::bail!("no audit log found for vault '{}'", ctx.vault_name);
            }

            let vault_dir = crate::config::sigyn_home()
                .join("vaults")
                .join(&ctx.vault_name);
            let git_engine = sigyn_engine::sync::git::GitSyncEngine::new(vault_dir);
            if !git_engine.is_repo() {
                git_engine.init()?;
            }

            let mut anchor = sigyn_engine::audit::anchor::GitAnchor::new();
            let hash = anchor.anchor(&audit_path, &git_engine)?;
            let hash_hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();

            if json {
                crate::output::print_json(&serde_json::json!({
                    "action": "anchored",
                    "hash": hash_hex,
                    "vault": ctx.vault_name,
                }))?;
            } else {
                crate::output::print_success(&format!(
                    "Audit log anchored to git (hash: {}...)",
                    &hash_hex[..16]
                ));
            }
        }
        AuditCommands::Export { output, format } => {
            let ctx = super::secret::unlock_vault(identity, Some(vault_name), None)?;
            super::secret::check_access(
                &ctx,
                sigyn_engine::policy::engine::AccessAction::ManagePolicy,
                None,
            )?;

            let audit_path = ctx.paths.audit_path(&ctx.vault_name);
            if !audit_path.exists() {
                anyhow::bail!("no audit log found for vault '{}'", ctx.vault_name);
            }

            let log = sigyn_engine::audit::AuditLog::open(&audit_path, derive_audit_cipher(&ctx)?)?;
            let entries = log.tail(usize::MAX)?;

            match format.as_str() {
                "json" => {
                    let content = serde_json::to_string_pretty(&entries)?;
                    std::fs::write(&output, content)?;
                }
                "csv" => {
                    let mut content = String::from("sequence,timestamp,action,env,actor\n");
                    for e in &entries {
                        content.push_str(&format!(
                            "{},{},{:?},{},{}\n",
                            e.sequence,
                            e.timestamp.to_rfc3339(),
                            e.action,
                            e.env.as_deref().unwrap_or(""),
                            e.actor.to_hex(),
                        ));
                    }
                    std::fs::write(&output, content)?;
                }
                other => anyhow::bail!("unknown format: '{}'. Use: json, csv", other),
            }

            crate::output::print_success(&format!(
                "Exported {} entries to '{}'",
                entries.len(),
                output
            ));
        }
    }
    Ok(())
}
