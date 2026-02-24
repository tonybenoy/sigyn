use regex::Regex;
use std::sync::LazyLock;

use crate::error::{Result, SigynError};

static KEY_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_.\-/]*$").expect("hardcoded regex"));

pub fn validate_key_name(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(SigynError::InvalidKeyName(
            "key name cannot be empty".into(),
        ));
    }
    if key.len() > 256 {
        return Err(SigynError::InvalidKeyName(
            "key name too long (max 256)".into(),
        ));
    }
    if !KEY_PATTERN.is_match(key) {
        return Err(SigynError::InvalidKeyName(format!(
            "'{}' must match [A-Za-z_][A-Za-z0-9_.\\-/]*",
            key
        )));
    }
    Ok(())
}

pub fn validate_env_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(SigynError::ValidationFailed(
            "environment name cannot be empty".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(SigynError::ValidationFailed(format!(
            "environment name '{}' contains invalid characters",
            name
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_key_names() {
        assert!(validate_key_name("DATABASE_URL").is_ok());
        assert!(validate_key_name("api.key").is_ok());
        assert!(validate_key_name("my-secret").is_ok());
        assert!(validate_key_name("nested/key").is_ok());
        assert!(validate_key_name("_private").is_ok());
    }

    #[test]
    fn test_invalid_key_names() {
        assert!(validate_key_name("").is_err());
        assert!(validate_key_name("123starts_with_num").is_err());
        assert!(validate_key_name("has spaces").is_err());
        assert!(validate_key_name("special!char").is_err());
    }

    #[test]
    fn test_valid_env_names() {
        assert!(validate_env_name("dev").is_ok());
        assert!(validate_env_name("staging").is_ok());
        assert!(validate_env_name("prod-us-east").is_ok());
    }

    #[test]
    fn test_invalid_env_names() {
        assert!(validate_env_name("").is_err());
        assert!(validate_env_name("has space").is_err());
    }
}
