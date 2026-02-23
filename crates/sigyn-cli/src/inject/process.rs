use std::collections::HashMap;
use std::process::Command;

use anyhow::{Context, Result};
use sigyn_core::vault::PlaintextEnv;

pub fn run_with_secrets(
    env: &PlaintextEnv,
    command: &[String],
    inherit_env: bool,
) -> Result<i32> {
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
