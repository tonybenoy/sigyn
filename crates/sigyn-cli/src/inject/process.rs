use std::collections::HashMap;
use std::process::Command;

use anyhow::{Context, Result};
use sigyn_engine::vault::PlaintextEnv;

pub fn run_with_secrets(env: &PlaintextEnv, command: &[String], inherit_env: bool) -> Result<i32> {
    if command.is_empty() {
        anyhow::bail!("no command specified");
    }

    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);

    if !inherit_env {
        cmd.env_clear();
    }

    // Inject secrets as environment variables
    for (key, entry) in &env.entries {
        if let Some(val) = entry.value.as_str() {
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
