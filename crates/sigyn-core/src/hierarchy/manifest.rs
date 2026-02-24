use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::keys::KeyFingerprint;

/// Reference to a child node within a hierarchy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildRef {
    pub node_id: Uuid,
    pub name: String,
    pub node_type: String,
}

/// Git remote configuration for a hierarchy node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitRemoteConfig {
    pub url: String,
    #[serde(default = "default_branch")]
    pub branch: String,
}

fn default_branch() -> String {
    "main".into()
}

/// Manifest for a hierarchy node (org, division, team, project, etc.).
/// Stored as `node.toml` in the node's directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeManifest {
    pub node_id: Uuid,
    pub name: String,
    pub node_type: String,
    pub parent_id: Option<Uuid>,
    pub owner: KeyFingerprint,
    #[serde(default)]
    pub children: Vec<ChildRef>,
    pub created_at: DateTime<Utc>,
    pub description: Option<String>,
    pub git_remote: Option<GitRemoteConfig>,
}

impl NodeManifest {
    pub fn new(name: String, node_type: String, owner: KeyFingerprint) -> Self {
        Self {
            node_id: Uuid::new_v4(),
            name,
            node_type,
            parent_id: None,
            owner,
            children: Vec::new(),
            created_at: Utc::now(),
            description: None,
            git_remote: None,
        }
    }

    pub fn to_toml(&self) -> crate::Result<String> {
        toml::to_string_pretty(self).map_err(|e| crate::SigynError::Serialization(e.to_string()))
    }

    pub fn from_toml(s: &str) -> crate::Result<Self> {
        toml::from_str(s).map_err(|e| crate::SigynError::Deserialization(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyFingerprint;

    #[test]
    fn test_node_manifest_new() {
        let owner = KeyFingerprint([0xAA; 16]);
        let manifest = NodeManifest::new("acme".into(), "org".into(), owner.clone());
        assert_eq!(manifest.name, "acme");
        assert_eq!(manifest.node_type, "org");
        assert!(manifest.parent_id.is_none());
        assert!(manifest.children.is_empty());
        assert!(manifest.git_remote.is_none());
        assert_eq!(manifest.owner, owner);
    }

    #[test]
    fn test_node_manifest_toml_roundtrip() {
        let owner = KeyFingerprint([0xBB; 16]);
        let mut manifest = NodeManifest::new("platform".into(), "division".into(), owner);
        manifest.description = Some("Platform team".into());
        manifest.parent_id = Some(Uuid::new_v4());
        manifest.children.push(ChildRef {
            node_id: Uuid::new_v4(),
            name: "web".into(),
            node_type: "team".into(),
        });
        manifest.git_remote = Some(GitRemoteConfig {
            url: "git@github.com:acme/platform.git".into(),
            branch: "main".into(),
        });

        let toml_str = manifest.to_toml().unwrap();
        let parsed = NodeManifest::from_toml(&toml_str).unwrap();

        assert_eq!(parsed.name, "platform");
        assert_eq!(parsed.node_type, "division");
        assert_eq!(parsed.parent_id, manifest.parent_id);
        assert_eq!(parsed.children.len(), 1);
        assert_eq!(parsed.children[0].name, "web");
        assert!(parsed.git_remote.is_some());
        assert_eq!(
            parsed.git_remote.unwrap().url,
            "git@github.com:acme/platform.git"
        );
    }

    #[test]
    fn test_git_remote_config_default_branch() {
        let toml_str = r#"url = "https://example.com/repo.git""#;
        let config: GitRemoteConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.branch, "main");
    }
}
