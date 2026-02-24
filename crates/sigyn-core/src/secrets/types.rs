use serde::{Deserialize, Serialize};

use crate::crypto::keys::KeyFingerprint;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecretValue {
    String(String),
    Multiline(String),
    Json(serde_json::Value),
    Certificate(String),
    SshPrivateKey(String),
    File {
        name: String,
        content: Vec<u8>,
    },
    Generated(String),
    Reference {
        vault: String,
        env: String,
        key: String,
    },
}

impl SecretValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            SecretValue::String(s) | SecretValue::Multiline(s) | SecretValue::Generated(s) => {
                Some(s)
            }
            _ => None,
        }
    }

    pub fn display_value(&self, reveal: bool) -> String {
        if !reveal {
            return "••••••••".to_string();
        }
        match self {
            SecretValue::String(s) => s.clone(),
            SecretValue::Multiline(s) => s.clone(),
            SecretValue::Json(v) => serde_json::to_string_pretty(v).unwrap_or_default(),
            SecretValue::Certificate(s) => s.clone(),
            SecretValue::SshPrivateKey(_) => "[SSH PRIVATE KEY]".to_string(),
            SecretValue::File { name, content } => {
                format!("[FILE: {} ({} bytes)]", name, content.len())
            }
            SecretValue::Generated(s) => s.clone(),
            SecretValue::Reference { vault, env, key } => {
                format!("@ref:{}/{}:{}", vault, env, key)
            }
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            SecretValue::String(_) => "string",
            SecretValue::Multiline(_) => "multiline",
            SecretValue::Json(_) => "json",
            SecretValue::Certificate(_) => "certificate",
            SecretValue::SshPrivateKey(_) => "ssh-key",
            SecretValue::File { .. } => "file",
            SecretValue::Generated(_) => "generated",
            SecretValue::Reference { .. } => "reference",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub version: u64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub created_by: KeyFingerprint,
    pub updated_by: KeyFingerprint,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub rotation_policy: Option<String>,
}

impl SecretMetadata {
    pub fn new(creator: KeyFingerprint) -> Self {
        let now = chrono::Utc::now();
        Self {
            version: 1,
            created_at: now,
            updated_at: now,
            created_by: creator.clone(),
            updated_by: creator,
            description: None,
            tags: Vec::new(),
            rotation_policy: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    pub key: String,
    pub value: SecretValue,
    pub metadata: SecretMetadata,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_as_str_string_variants() {
        assert_eq!(SecretValue::String("hello".into()).as_str(), Some("hello"));
        assert_eq!(
            SecretValue::Multiline("line1\nline2".into()).as_str(),
            Some("line1\nline2")
        );
        assert_eq!(
            SecretValue::Generated("gen-123".into()).as_str(),
            Some("gen-123")
        );
    }

    #[test]
    fn test_as_str_non_string_variants() {
        assert!(SecretValue::Json(serde_json::json!({"a": 1}))
            .as_str()
            .is_none());
        assert!(SecretValue::Certificate("cert".into()).as_str().is_none());
        assert!(SecretValue::SshPrivateKey("key".into()).as_str().is_none());
        assert!(SecretValue::File {
            name: "f".into(),
            content: vec![]
        }
        .as_str()
        .is_none());
        assert!(SecretValue::Reference {
            vault: "v".into(),
            env: "e".into(),
            key: "k".into()
        }
        .as_str()
        .is_none());
    }

    #[test]
    fn test_display_value_hidden() {
        let vals = [
            SecretValue::String("secret".into()),
            SecretValue::Json(serde_json::json!({})),
            SecretValue::Certificate("cert".into()),
        ];
        for v in &vals {
            assert_eq!(v.display_value(false), "••••••••");
        }
    }

    #[test]
    fn test_display_value_reveal_string() {
        assert_eq!(
            SecretValue::String("hello".into()).display_value(true),
            "hello"
        );
    }

    #[test]
    fn test_display_value_reveal_multiline() {
        assert_eq!(
            SecretValue::Multiline("a\nb".into()).display_value(true),
            "a\nb"
        );
    }

    #[test]
    fn test_display_value_reveal_json() {
        let v = SecretValue::Json(serde_json::json!({"key": "val"}));
        let displayed = v.display_value(true);
        assert!(displayed.contains("key"));
        assert!(displayed.contains("val"));
    }

    #[test]
    fn test_display_value_reveal_certificate() {
        assert_eq!(
            SecretValue::Certificate("BEGIN CERT".into()).display_value(true),
            "BEGIN CERT"
        );
    }

    #[test]
    fn test_display_value_reveal_ssh_key() {
        assert_eq!(
            SecretValue::SshPrivateKey("key-data".into()).display_value(true),
            "[SSH PRIVATE KEY]"
        );
    }

    #[test]
    fn test_display_value_reveal_file() {
        let v = SecretValue::File {
            name: "data.bin".into(),
            content: vec![0; 100],
        };
        assert_eq!(v.display_value(true), "[FILE: data.bin (100 bytes)]");
    }

    #[test]
    fn test_display_value_reveal_generated() {
        assert_eq!(
            SecretValue::Generated("gen-abc".into()).display_value(true),
            "gen-abc"
        );
    }

    #[test]
    fn test_display_value_reveal_reference() {
        let v = SecretValue::Reference {
            vault: "myv".into(),
            env: "prod".into(),
            key: "DB".into(),
        };
        assert_eq!(v.display_value(true), "@ref:myv/prod:DB");
    }

    #[test]
    fn test_type_name_all_variants() {
        assert_eq!(SecretValue::String("".into()).type_name(), "string");
        assert_eq!(SecretValue::Multiline("".into()).type_name(), "multiline");
        assert_eq!(
            SecretValue::Json(serde_json::json!(null)).type_name(),
            "json"
        );
        assert_eq!(
            SecretValue::Certificate("".into()).type_name(),
            "certificate"
        );
        assert_eq!(SecretValue::SshPrivateKey("".into()).type_name(), "ssh-key");
        assert_eq!(
            SecretValue::File {
                name: "".into(),
                content: vec![]
            }
            .type_name(),
            "file"
        );
        assert_eq!(SecretValue::Generated("".into()).type_name(), "generated");
        assert_eq!(
            SecretValue::Reference {
                vault: "".into(),
                env: "".into(),
                key: "".into()
            }
            .type_name(),
            "reference"
        );
    }

    #[test]
    fn test_secret_metadata_new() {
        let fp = KeyFingerprint([0xAA; 16]);
        let meta = SecretMetadata::new(fp.clone());
        assert_eq!(meta.version, 1);
        assert_eq!(meta.created_by, fp);
        assert_eq!(meta.updated_by, fp);
        assert!(meta.description.is_none());
        assert!(meta.tags.is_empty());
        assert!(meta.rotation_policy.is_none());
    }
}
