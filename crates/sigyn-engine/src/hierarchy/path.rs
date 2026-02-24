use std::path::PathBuf;

use sigyn_core::error::Result;
pub use sigyn_core::hierarchy::path::OrgPath;

/// Resolves `OrgPath` values to filesystem paths under `~/.sigyn/orgs/`.
///
/// Layout:
/// ```text
/// ~/.sigyn/orgs/acme/                          (root org)
///   ├── node.toml
///   ├── members.cbor
///   ├── policy.cbor
///   └── children/
///       └── platform/                          (child)
///           ├── node.toml
///           ├── members.cbor
///           ├── policy.cbor
///           └── children/
///               └── web/                       (grandchild)
/// ```
pub struct HierarchyPaths {
    base: PathBuf,
}

impl HierarchyPaths {
    pub fn new(base: PathBuf) -> Self {
        Self { base }
    }

    /// Root directory for all orgs: `~/.sigyn/orgs/`
    pub fn orgs_dir(&self) -> PathBuf {
        self.base.join("orgs")
    }

    /// Directory for a specific node given its OrgPath.
    pub fn node_dir(&self, path: &OrgPath) -> PathBuf {
        let mut dir = self.orgs_dir().join(path.root());
        for seg in &path.segments()[1..] {
            dir = dir.join("children").join(seg);
        }
        dir
    }

    /// Path to the node manifest (`node.toml`).
    pub fn manifest_path(&self, path: &OrgPath) -> PathBuf {
        self.node_dir(path).join("node.toml")
    }

    /// Path to the node's envelope header (`members.cbor`).
    pub fn members_path(&self, path: &OrgPath) -> PathBuf {
        self.node_dir(path).join("members.cbor")
    }

    /// Path to the node's encrypted policy (`policy.cbor`).
    pub fn policy_path(&self, path: &OrgPath) -> PathBuf {
        self.node_dir(path).join("policy.cbor")
    }

    /// Directory containing child nodes.
    pub fn children_dir(&self, path: &OrgPath) -> PathBuf {
        self.node_dir(path).join("children")
    }

    /// List root org names.
    pub fn list_orgs(&self) -> Result<Vec<String>> {
        let orgs_dir = self.orgs_dir();
        if !orgs_dir.exists() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&orgs_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    let manifest = entry.path().join("node.toml");
                    if manifest.exists() {
                        names.push(name.to_string());
                    }
                }
            }
        }
        names.sort();
        Ok(names)
    }

    /// List child node names under a given path.
    pub fn list_children(&self, path: &OrgPath) -> Result<Vec<String>> {
        let children_dir = self.children_dir(path);
        if !children_dir.exists() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&children_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    let manifest = entry.path().join("node.toml");
                    if manifest.exists() {
                        names.push(name.to_string());
                    }
                }
            }
        }
        names.sort();
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hierarchy_paths_node_dir() {
        let paths = HierarchyPaths::new(PathBuf::from("/home/user/.sigyn"));

        let root = OrgPath::parse("acme").unwrap();
        assert_eq!(
            paths.node_dir(&root),
            PathBuf::from("/home/user/.sigyn/orgs/acme")
        );

        let child = OrgPath::parse("acme/platform").unwrap();
        assert_eq!(
            paths.node_dir(&child),
            PathBuf::from("/home/user/.sigyn/orgs/acme/children/platform")
        );

        let grandchild = OrgPath::parse("acme/platform/web").unwrap();
        assert_eq!(
            paths.node_dir(&grandchild),
            PathBuf::from("/home/user/.sigyn/orgs/acme/children/platform/children/web")
        );
    }

    #[test]
    fn test_hierarchy_paths_manifest() {
        let paths = HierarchyPaths::new(PathBuf::from("/base"));
        let org = OrgPath::parse("acme").unwrap();
        assert_eq!(
            paths.manifest_path(&org),
            PathBuf::from("/base/orgs/acme/node.toml")
        );
    }

    #[test]
    fn test_hierarchy_paths_members() {
        let paths = HierarchyPaths::new(PathBuf::from("/base"));
        let org = OrgPath::parse("acme/platform").unwrap();
        assert_eq!(
            paths.members_path(&org),
            PathBuf::from("/base/orgs/acme/children/platform/members.cbor")
        );
    }

    #[test]
    fn test_hierarchy_paths_policy() {
        let paths = HierarchyPaths::new(PathBuf::from("/base"));
        let org = OrgPath::parse("acme").unwrap();
        assert_eq!(
            paths.policy_path(&org),
            PathBuf::from("/base/orgs/acme/policy.cbor")
        );
    }

    #[test]
    fn test_list_orgs_empty() {
        let dir = tempfile::tempdir().unwrap();
        let paths = HierarchyPaths::new(dir.path().to_path_buf());
        assert_eq!(paths.list_orgs().unwrap(), Vec::<String>::new());
    }

    #[test]
    fn test_list_orgs_with_manifests() {
        let dir = tempfile::tempdir().unwrap();
        let orgs = dir.path().join("orgs");

        std::fs::create_dir_all(orgs.join("beta")).unwrap();
        std::fs::write(orgs.join("beta/node.toml"), "name = \"beta\"").unwrap();
        std::fs::create_dir_all(orgs.join("alpha")).unwrap();
        std::fs::write(orgs.join("alpha/node.toml"), "name = \"alpha\"").unwrap();

        // Dir without node.toml should be ignored
        std::fs::create_dir_all(orgs.join("orphan")).unwrap();

        let paths = HierarchyPaths::new(dir.path().to_path_buf());
        let result = paths.list_orgs().unwrap();
        assert_eq!(result, vec!["alpha", "beta"]);
    }

    #[test]
    fn test_list_children() {
        let dir = tempfile::tempdir().unwrap();
        let org_dir = dir.path().join("orgs").join("acme");
        let children_dir = org_dir.join("children");

        std::fs::create_dir_all(&org_dir).unwrap();
        std::fs::write(org_dir.join("node.toml"), "name = \"acme\"").unwrap();

        std::fs::create_dir_all(children_dir.join("web")).unwrap();
        std::fs::write(children_dir.join("web/node.toml"), "name = \"web\"").unwrap();
        std::fs::create_dir_all(children_dir.join("api")).unwrap();
        std::fs::write(children_dir.join("api/node.toml"), "name = \"api\"").unwrap();

        let paths = HierarchyPaths::new(dir.path().to_path_buf());
        let org = OrgPath::parse("acme").unwrap();
        let children = paths.list_children(&org).unwrap();
        assert_eq!(children, vec!["api", "web"]);
    }
}
