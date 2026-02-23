use crate::error::Result;

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
