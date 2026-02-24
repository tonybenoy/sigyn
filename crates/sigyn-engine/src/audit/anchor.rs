use sigyn_core::error::Result;

#[allow(dead_code)]
pub struct GitAnchor {
    last_anchored_hash: Option<[u8; 32]>,
    last_anchored_sequence: Option<u64>,
}

impl GitAnchor {
    pub fn new() -> Self {
        Self {
            last_anchored_hash: None,
            last_anchored_sequence: None,
        }
    }

    pub fn anchor(
        &mut self,
        audit_path: &std::path::Path,
        git_engine: &crate::sync::git::GitSyncEngine,
    ) -> Result<[u8; 32]> {
        let content = std::fs::read(audit_path)?;
        let hash = *blake3::hash(&content).as_bytes();

        if git_engine.has_changes()? {
            git_engine.stage_all()?;
            let msg = format!("sigyn: audit anchor {}", hex_short(&hash));
            git_engine.commit(&msg)?;
        }

        self.last_anchored_hash = Some(hash);
        Ok(hash)
    }

    pub fn verify_anchor(&self, audit_path: &std::path::Path) -> Result<bool> {
        match self.last_anchored_hash {
            Some(expected) => {
                let content = std::fs::read(audit_path)?;
                let actual = *blake3::hash(&content).as_bytes();
                Ok(actual == expected)
            }
            None => Ok(true),
        }
    }
}

impl Default for GitAnchor {
    fn default() -> Self {
        Self::new()
    }
}

fn hex_short(hash: &[u8; 32]) -> String {
    hash[..8].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::git::GitSyncEngine;

    #[test]
    fn test_git_anchor_new() {
        let anchor = GitAnchor::new();
        assert!(anchor.last_anchored_hash.is_none());
        assert!(anchor.last_anchored_sequence.is_none());
    }

    #[test]
    fn test_git_anchor_default() {
        let anchor = GitAnchor::default();
        assert!(anchor.last_anchored_hash.is_none());
    }

    #[test]
    fn test_verify_anchor_no_previous_anchor() {
        let anchor = GitAnchor::new();
        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir.path().join("audit.log");
        std::fs::write(&audit_path, "some content").unwrap();
        assert!(anchor.verify_anchor(&audit_path).unwrap());
    }

    #[test]
    fn test_anchor_and_verify() {
        let dir = tempfile::tempdir().unwrap();
        let engine = GitSyncEngine::new(dir.path().to_path_buf());
        engine.init().unwrap();

        let audit_path = dir.path().join("audit.log.json");
        std::fs::write(&audit_path, r#"[{"seq":1,"action":"create"}]"#).unwrap();

        let mut anchor = GitAnchor::new();
        let hash = anchor.anchor(&audit_path, &engine).unwrap();
        assert_ne!(hash, [0u8; 32]);

        // Verify should succeed with unchanged file
        assert!(anchor.verify_anchor(&audit_path).unwrap());
    }

    #[test]
    fn test_anchor_detects_modification() {
        let dir = tempfile::tempdir().unwrap();
        let engine = GitSyncEngine::new(dir.path().to_path_buf());
        engine.init().unwrap();

        let audit_path = dir.path().join("audit.log.json");
        std::fs::write(&audit_path, "original content").unwrap();

        let mut anchor = GitAnchor::new();
        anchor.anchor(&audit_path, &engine).unwrap();

        // Modify the file after anchoring
        std::fs::write(&audit_path, "tampered content").unwrap();

        assert!(!anchor.verify_anchor(&audit_path).unwrap());
    }

    #[test]
    fn test_hex_short() {
        let hash = [0xABu8; 32];
        let short = hex_short(&hash);
        assert_eq!(short.len(), 16);
        assert_eq!(short, "abababababababab");
    }
}
