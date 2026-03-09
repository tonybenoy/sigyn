use std::collections::HashMap;
use std::process::Command;

use anyhow::{Context, Result};
use sigyn_engine::vault::PlaintextEnv;

/// System environment variables that must never be overridden by secrets.
/// Overriding these enables code execution (LD_PRELOAD), PATH hijacking, or DoS.
const DANGEROUS_ENV_VARS: &[&str] = &[
    "PATH",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_BIND_NOW",
    "HOME",
    "SHELL",
    "USER",
    "LOGNAME",
    "IFS",
    "CDPATH",
    "ENV",
    "BASH_ENV",
    "SIGYN_HOME",
    "SIGYN_PASSPHRASE",
];

/// Check if a secret key name would shadow a dangerous system environment variable.
/// Returns the blocked var name if dangerous, None if safe.
pub fn check_dangerous_env_override(key: &str) -> Option<&'static str> {
    DANGEROUS_ENV_VARS
        .iter()
        .find(|&&v| v.eq_ignore_ascii_case(key))
        .copied()
}

pub fn run_with_secrets(env: &PlaintextEnv, command: &[String], inherit_env: bool) -> Result<i32> {
    if command.is_empty() {
        anyhow::bail!("no command specified");
    }

    // Warn about /proc visibility when verbose mode is on
    if std::env::var("SIGYN_VERBOSE").is_ok() {
        eprintln!(
            "warning: secrets will be visible in /proc/{{}}/environ of the child process. \
             This is inherent to environment variable injection. Use `sigyn run serve` \
             for socket-based injection if this is a concern."
        );
    }

    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);

    if !inherit_env {
        cmd.env_clear();
    }
    // Never leak sigyn internals to child processes
    cmd.env_remove("SIGYN_PASSPHRASE");
    cmd.env_remove("SIGYN_HOME");

    // Inject secrets as environment variables, blocking dangerous overrides
    for (key, entry) in &env.entries {
        if let Some(val) = entry.value.as_str() {
            if let Some(blocked) = check_dangerous_env_override(key) {
                eprintln!(
                    "{} secret '{}' shadows system variable '{}' — skipped to prevent hijacking. \
                     Rename this secret or use `sigyn run serve` for socket-based injection.",
                    console::style("warning:").yellow().bold(),
                    key,
                    blocked,
                );
                continue;
            }
            cmd.env(key, val);
        }
    }

    let status = cmd
        .status()
        .context(format!("failed to execute '{}'", command[0]))?;

    Ok(status.code().unwrap_or(1))
}

/// Replace `{{KEY}}` patterns in command arguments with secret values from the environment.
/// Unresolved refs are left as-is.
pub fn substitute_secret_refs(args: &[String], env: &PlaintextEnv) -> Vec<String> {
    let re = regex::Regex::new(r"\{\{(\w+)\}\}").expect("invalid regex");
    args.iter()
        .map(|arg| {
            re.replace_all(arg, |caps: &regex::Captures| {
                let key = &caps[1];
                env.get(key)
                    .and_then(|e| e.value.as_str().map(String::from))
                    .unwrap_or_else(|| caps[0].to_string())
            })
            .into_owned()
        })
        .collect()
}

#[allow(dead_code)]
pub fn collect_env_vars(env: &PlaintextEnv) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    for (key, entry) in &env.entries {
        if let Some(val) = entry.value.as_str() {
            vars.insert(key.clone(), val.to_string());
        }
    }
    vars
}
