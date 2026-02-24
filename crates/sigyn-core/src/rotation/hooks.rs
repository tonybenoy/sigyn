use std::process::Command;

use crate::error::{Result, SigynError};

#[derive(Debug)]
pub struct HookResult {
    pub hook: String,
    pub success: bool,
    pub output: String,
}

pub fn execute_rotation_hooks(
    hooks: &[String],
    key: &str,
    env_name: &str,
) -> Result<Vec<HookResult>> {
    let mut results = Vec::new();

    for hook in hooks {
        let output = Command::new("sh")
            .arg("-c")
            .arg(hook)
            .env("SIGYN_ROTATED_KEY", key)
            .env("SIGYN_ENV", env_name)
            .output()
            .map_err(|e| SigynError::RotationFailed(key.into(), e.to_string()))?;

        results.push(HookResult {
            hook: hook.clone(),
            success: output.status.success(),
            output: String::from_utf8_lossy(&output.stdout).to_string(),
        });
    }

    Ok(results)
}

pub fn execute_single_hook(hook: &str, env_vars: &[(&str, &str)]) -> Result<bool> {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(hook);
    for (k, v) in env_vars {
        cmd.env(k, v);
    }
    let status = cmd
        .status()
        .map_err(|e| SigynError::RotationFailed("hook".into(), e.to_string()))?;
    Ok(status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_rotation_hooks() {
        // Use a simple echo command to test
        let hooks = vec!["echo $SIGYN_ROTATED_KEY".to_string()];
        let results = execute_rotation_hooks(&hooks, "TEST_KEY", "dev").unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].success);
        assert_eq!(results[0].output.trim(), "TEST_KEY");
    }

    #[test]
    fn test_execute_single_hook_with_env() {
        let env_vars = [("FOO", "BAR"), ("BAZ", "QUX")];
        let result = execute_single_hook(
            "test \"$FOO\" = \"BAR\" && test \"$BAZ\" = \"QUX\"",
            &env_vars,
        )
        .unwrap();
        assert!(result);

        let result = execute_single_hook("test \"$FOO\" = \"WRONG\"", &env_vars).unwrap();
        assert!(!result);
    }
}
