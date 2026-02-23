use crate::error::{SigynError, Result};
use super::types::SecretValue;

pub struct SecretReference {
    pub vault: String,
    pub env: String,
    pub key: String,
}

impl SecretReference {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s
            .strip_prefix("@ref:")
            .ok_or_else(|| SigynError::ValidationFailed("reference must start with @ref:".into()))?;

        let (vault_env, key) = s.rsplit_once(':').ok_or_else(|| {
            SigynError::ValidationFailed("reference must contain vault/env:key".into())
        })?;

        let (vault, env) = vault_env.split_once('/').ok_or_else(|| {
            SigynError::ValidationFailed("reference must contain vault/env".into())
        })?;

        Ok(Self {
            vault: vault.to_string(),
            env: env.to_string(),
            key: key.to_string(),
        })
    }

    pub fn to_value(&self) -> SecretValue {
        SecretValue::Reference {
            vault: self.vault.clone(),
            env: self.env.clone(),
            key: self.key.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_reference() {
        let r = SecretReference::parse("@ref:myapp/dev:DATABASE_URL").unwrap();
        assert_eq!(r.vault, "myapp");
        assert_eq!(r.env, "dev");
        assert_eq!(r.key, "DATABASE_URL");
    }

    #[test]
    fn test_invalid_reference() {
        assert!(SecretReference::parse("not-a-ref").is_err());
        assert!(SecretReference::parse("@ref:noenv").is_err());
    }
}
