use crate::error::Result;
use globset::{Glob, GlobSetBuilder};

pub fn matches_secret_pattern(key: &str, patterns: &[String]) -> Result<bool> {
    if patterns.is_empty() || patterns.iter().any(|p| p == "*") {
        return Ok(true);
    }

    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(
            Glob::new(pattern).map_err(|e| crate::SigynError::PolicyViolation(e.to_string()))?,
        );
    }
    let set = builder
        .build()
        .map_err(|e| crate::SigynError::PolicyViolation(e.to_string()))?;

    Ok(set.is_match(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_pattern() {
        assert!(matches_secret_pattern("ANY_KEY", &["*".into()]).unwrap());
        assert!(matches_secret_pattern("ANY_KEY", &[]).unwrap());
    }

    #[test]
    fn test_specific_pattern() {
        assert!(matches_secret_pattern("DB_URL", &["DB_*".into()]).unwrap());
        assert!(!matches_secret_pattern("API_KEY", &["DB_*".into()]).unwrap());
    }
}
