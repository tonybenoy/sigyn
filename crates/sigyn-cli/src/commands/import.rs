use anyhow::{Context, Result};
use clap::Subcommand;
use sigyn_engine::secrets::types::SecretValue;
use sigyn_engine::vault::env_file;

use crate::commands::secret::{check_access, unlock_vault};
use crate::output;
use sigyn_engine::policy::engine::AccessAction;

#[derive(Subcommand)]
pub enum ImportCommands {
    /// Import secrets from a .env file
    Dotenv {
        /// Path to .env file
        file: String,
        /// Environment
        #[arg(long, short)]
        env: Option<String>,
    },
    /// Import secrets from a JSON file (key-value object)
    Json {
        /// Path to JSON file
        file: String,
        /// Environment
        #[arg(long, short)]
        env: Option<String>,
    },
    /// Import secrets from Doppler
    Doppler {
        /// Doppler project name
        #[arg(long)]
        project: String,
        /// Doppler config (e.g. dev, staging, production)
        #[arg(long)]
        config: String,
        /// Environment
        #[arg(long, short)]
        env: Option<String>,
    },
    /// Import a secret from AWS Secrets Manager
    Aws {
        /// AWS secret ID or ARN
        #[arg(long)]
        secret_id: String,
        /// AWS region (e.g. us-east-1)
        #[arg(long)]
        region: Option<String>,
        /// Environment
        #[arg(long, short)]
        env: Option<String>,
    },
    /// Import a secret from GCP Secret Manager
    Gcp {
        /// GCP project ID
        #[arg(long)]
        project: String,
        /// Secret name in GCP Secret Manager
        #[arg(long)]
        secret: String,
        /// Secret version (defaults to "latest")
        #[arg(long)]
        version: Option<String>,
        /// Environment
        #[arg(long, short)]
        env: Option<String>,
    },
    /// Import secrets from 1Password CLI
    #[command(name = "1password", alias = "op")]
    OnePassword {
        /// 1Password vault name
        #[arg(long)]
        vault: String,
        /// 1Password item name or ID
        #[arg(long)]
        item: String,
        /// Environment
        #[arg(long, short)]
        env: Option<String>,
    },
}

/// Store a list of key-value pairs into the vault, returning how many were stored.
fn store_pairs(
    pairs: Vec<(String, String)>,
    vault: Option<&str>,
    identity: Option<&str>,
    env_name: Option<&str>,
) -> Result<usize> {
    if pairs.is_empty() {
        output::print_info("No secrets found to import.");
        return Ok(0);
    }

    let ctx = unlock_vault(identity, vault, env_name)?;
    check_access(&ctx, AccessAction::Write, None)?;

    let env_path = ctx.paths.env_path(&ctx.vault_name, &ctx.env_name);
    let mut plaintext = if env_path.exists() {
        let encrypted = env_file::read_encrypted_env(&env_path)?;
        env_file::decrypt_env(&encrypted, &ctx.cipher)?
    } else {
        sigyn_engine::vault::PlaintextEnv::new()
    };

    let mut count = 0;
    for (key, value) in &pairs {
        // Validate key name; skip invalid keys with a warning
        if let Err(e) = sigyn_engine::secrets::validate_key_name(key) {
            output::print_warning(&format!("Skipping invalid key '{}': {}", key, e));
            continue;
        }
        plaintext.set(
            key.clone(),
            SecretValue::String(value.clone()),
            &ctx.fingerprint,
        );
        count += 1;
    }

    if count > 0 {
        let encrypted = env_file::encrypt_env(&plaintext, &ctx.cipher, &ctx.env_name)?;
        env_file::write_encrypted_env(&env_path, &encrypted)?;
    }

    Ok(count)
}

pub fn handle(
    cmd: ImportCommands,
    vault: Option<&str>,
    identity: Option<&str>,
    json: bool,
) -> Result<()> {
    match cmd {
        ImportCommands::Dotenv { file, env } => {
            let content =
                std::fs::read_to_string(&file).context(format!("failed to read file: {}", file))?;

            let ctx = unlock_vault(identity, vault, env.as_deref())?;
            check_access(&ctx, AccessAction::Write, None)?;

            let env_path = ctx.paths.env_path(&ctx.vault_name, &ctx.env_name);
            let mut plaintext = if env_path.exists() {
                let encrypted = env_file::read_encrypted_env(&env_path)?;
                env_file::decrypt_env(&encrypted, &ctx.cipher)?
            } else {
                sigyn_engine::vault::PlaintextEnv::new()
            };

            let count =
                crate::importexport::import_dotenv(&content, &mut plaintext, &ctx.fingerprint)?;

            if count > 0 {
                let encrypted = env_file::encrypt_env(&plaintext, &ctx.cipher, &ctx.env_name)?;
                env_file::write_encrypted_env(&env_path, &encrypted)?;
            }

            print_summary(count, "dotenv file", &file, json)?;
        }
        ImportCommands::Json { file, env } => {
            let content =
                std::fs::read_to_string(&file).context(format!("failed to read file: {}", file))?;

            let ctx = unlock_vault(identity, vault, env.as_deref())?;
            check_access(&ctx, AccessAction::Write, None)?;

            let env_path = ctx.paths.env_path(&ctx.vault_name, &ctx.env_name);
            let mut plaintext = if env_path.exists() {
                let encrypted = env_file::read_encrypted_env(&env_path)?;
                env_file::decrypt_env(&encrypted, &ctx.cipher)?
            } else {
                sigyn_engine::vault::PlaintextEnv::new()
            };

            let count =
                crate::importexport::import_json(&content, &mut plaintext, &ctx.fingerprint)?;

            if count > 0 {
                let encrypted = env_file::encrypt_env(&plaintext, &ctx.cipher, &ctx.env_name)?;
                env_file::write_encrypted_env(&env_path, &encrypted)?;
            }

            print_summary(count, "JSON file", &file, json)?;
        }
        ImportCommands::Doppler {
            project,
            config,
            env,
        } => {
            let pairs = crate::importexport::cloud::import_doppler(&project, &config)?;
            let source = format!("Doppler ({}/{})", project, config);
            let count = store_pairs(pairs, vault, identity, env.as_deref())?;
            print_summary(count, "Doppler", &source, json)?;
        }
        ImportCommands::Aws {
            secret_id,
            region,
            env,
        } => {
            let pairs =
                crate::importexport::cloud::import_aws_secret(&secret_id, region.as_deref())?;
            let source = format!("AWS Secrets Manager ({})", secret_id);
            let count = store_pairs(pairs, vault, identity, env.as_deref())?;
            print_summary(count, "AWS Secrets Manager", &source, json)?;
        }
        ImportCommands::Gcp {
            project,
            secret,
            version,
            env,
        } => {
            let pairs = crate::importexport::cloud::import_gcp_secret(
                &project,
                &secret,
                version.as_deref(),
            )?;
            let source = format!("GCP Secret Manager ({}/{})", project, secret);
            let count = store_pairs(pairs, vault, identity, env.as_deref())?;
            print_summary(count, "GCP Secret Manager", &source, json)?;
        }
        ImportCommands::OnePassword {
            vault: op_vault,
            item,
            env,
        } => {
            let pairs = crate::importexport::cloud::import_1password(&op_vault, &item)?;
            let source = format!("1Password ({}/{})", op_vault, item);
            let count = store_pairs(pairs, vault, identity, env.as_deref())?;
            print_summary(count, "1Password", &source, json)?;
        }
    }

    Ok(())
}

fn print_summary(count: usize, provider: &str, source: &str, json: bool) -> Result<()> {
    if json {
        crate::output::print_json(&serde_json::json!({
            "imported": count,
            "provider": provider,
            "source": source,
        }))?;
    } else {
        output::print_success(&format!("{} secrets imported from {}", count, source));
    }
    Ok(())
}
