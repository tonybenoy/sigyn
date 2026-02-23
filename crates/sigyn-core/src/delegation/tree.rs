use serde::{Deserialize, Serialize};
use crate::crypto::keys::KeyFingerprint;
use crate::policy::roles::Role;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationNode {
    pub fingerprint: KeyFingerprint,
    pub name: String,
    pub role: Role,
    pub depth: u32,
    pub delegated_by: Option<KeyFingerprint>,
    pub children: Vec<DelegationNode>,
}

impl DelegationNode {
    pub fn display_tree(&self, indent: usize) -> String {
        let mut out = format!(
            "{}{} ({}) [{}]\n",
            "  ".repeat(indent),
            self.name,
            self.fingerprint,
            self.role
        );
        for child in &self.children {
            out.push_str(&child.display_tree(indent + 1));
        }
        out
    }
}
