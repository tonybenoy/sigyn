use anyhow::Result;
use clap::Subcommand;
use serde::{Deserialize, Serialize};

use crate::config::sigyn_home;

/// Persistent shell context stored at ~/.sigyn/context.toml
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ShellContext {
    pub vault: Option<String>,
    pub env: Option<String>,
}

#[derive(Subcommand)]
pub enum ContextCommands {
    /// Set the active context (vault and optional environment)
    Set {
        /// Vault name
        vault: String,
        /// Environment name
        env: Option<String>,
    },
    /// Show the current context
    Show,
    /// Clear the current context
    Clear,
}

fn context_path() -> std::path::PathBuf {
    sigyn_home().join("context.toml")
}

/// Load the current context (returns None if no context file exists).
pub fn load_context() -> Option<ShellContext> {
    let path = context_path();
    if !path.exists() {
        return None;
    }
    let data = std::fs::read(&path).ok()?;
    if !sigyn_engine::crypto::sealed::is_sealed(&data) {
        eprintln!(
            "{} context.toml is not in sealed format — ignoring (possible tampering)",
            console::style("warning:").yellow().bold()
        );
        return None;
    }
    let home = crate::config::sigyn_home();
    let device_key = sigyn_engine::device::load_or_create_device_key(&home).ok()?;
    let cipher =
        sigyn_engine::crypto::sealed::derive_file_cipher(&device_key, b"sigyn-context-v1").ok()?;
    let plaintext =
        sigyn_engine::crypto::sealed::sealed_decrypt(&cipher, &data, b"context.toml").ok()?;
    let content = String::from_utf8(plaintext).ok()?;
    let ctx: ShellContext = toml::from_str(&content).ok()?;
    if ctx.vault.is_some() || ctx.env.is_some() {
        Some(ctx)
    } else {
        None
    }
}

/// Save context encrypted with device key.
fn save_context(ctx: &ShellContext) -> anyhow::Result<()> {
    let home = crate::config::sigyn_home();
    let content = toml::to_string_pretty(ctx)?;
    let device_key = sigyn_engine::device::load_or_create_device_key(&home)?;
    let cipher =
        sigyn_engine::crypto::sealed::derive_file_cipher(&device_key, b"sigyn-context-v1")?;
    let sealed =
        sigyn_engine::crypto::sealed::sealed_encrypt(&cipher, content.as_bytes(), b"context.toml")?;
    crate::config::secure_write(&context_path(), &sealed)?;
    Ok(())
}

pub fn handle(cmd: ContextCommands, json: bool) -> Result<()> {
    match cmd {
        ContextCommands::Set { vault, env } => {
            let ctx = ShellContext {
                vault: Some(vault.clone()),
                env: env.clone(),
            };
            crate::config::ensure_sigyn_home()?;
            save_context(&ctx)?;

            if json {
                crate::output::print_json(&serde_json::json!({
                    "vault": vault,
                    "env": env,
                }))?;
            } else {
                let mut msg = format!("Context set: vault='{}'", vault);
                if let Some(ref e) = env {
                    msg.push_str(&format!(", env='{}'", e));
                }
                crate::output::print_success(&msg);
            }
        }
        ContextCommands::Show => {
            let ctx = load_context();
            if json {
                crate::output::print_json(&serde_json::json!({
                    "vault": ctx.as_ref().and_then(|c| c.vault.as_deref()),
                    "env": ctx.as_ref().and_then(|c| c.env.as_deref()),
                }))?;
            } else if let Some(ctx) = ctx {
                println!("{}", console::style("Current context").bold());
                if let Some(ref v) = ctx.vault {
                    println!("  vault: {}", console::style(v).cyan());
                }
                if let Some(ref e) = ctx.env {
                    println!("  env:   {}", console::style(e).cyan());
                }
            } else {
                println!("No context set. Use 'sigyn context set <vault> [env]' to set one.");
            }
        }
        ContextCommands::Clear => {
            let path = context_path();
            if path.exists() {
                std::fs::remove_file(&path)?;
            }
            if json {
                crate::output::print_json(&serde_json::json!({"cleared": true}))?;
            } else {
                crate::output::print_success("Context cleared");
            }
        }
    }
    Ok(())
}
