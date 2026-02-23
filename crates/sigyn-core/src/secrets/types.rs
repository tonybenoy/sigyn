use serde::{Deserialize, Serialize};

use crate::crypto::keys::KeyFingerprint;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecretValue {
    String(String),
    Multiline(String),
    Json(serde_json::Value),
    Certificate(String),
    SshPrivateKey(String),
    File { name: String, content: Vec<u8> },
    Generated(String),
    Reference { vault: String, env: String, key: String },
}

impl SecretValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            SecretValue::String(s)
            | SecretValue::Multiline(s)
            | SecretValue::Generated(s) => Some(s),
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
