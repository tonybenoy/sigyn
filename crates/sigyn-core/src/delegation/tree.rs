use crate::crypto::keys::KeyFingerprint;
use crate::policy::roles::Role;
use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(name: &str, role: Role, children: Vec<DelegationNode>) -> DelegationNode {
        DelegationNode {
            fingerprint: KeyFingerprint([0u8; 16]),
            name: name.to_string(),
            role,
            depth: 0,
            delegated_by: None,
            children,
        }
    }

    #[test]
    fn test_display_tree_leaf() {
        let node = make_node("alice", Role::Owner, vec![]);
        let output = node.display_tree(0);
        assert!(output.contains("alice"));
        assert!(output.contains("[owner]"));
        assert!(output.ends_with('\n'));
    }

    #[test]
    fn test_display_tree_nested() {
        let child = make_node("bob", Role::Contributor, vec![]);
        let root = make_node("alice", Role::Owner, vec![child]);
        let output = root.display_tree(0);
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("alice"));
        assert!(lines[1].starts_with("  bob"));
    }

    #[test]
    fn test_display_tree_indentation() {
        let grandchild = make_node("charlie", Role::ReadOnly, vec![]);
        let child = make_node("bob", Role::Manager, vec![grandchild]);
        let root = make_node("alice", Role::Owner, vec![child]);
        let output = root.display_tree(0);
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(!lines[0].starts_with(' '));
        assert!(lines[1].starts_with("  "));
        assert!(lines[2].starts_with("    "));
    }
}
