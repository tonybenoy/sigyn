use std::path::PathBuf;

use crate::error::{Result, SigynError};

/// A slash-separated path within the org hierarchy, e.g. `"acme/platform/web"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OrgPath {
    segments: Vec<String>,
}

impl OrgPath {
    /// Parse an org path from a slash-separated string.
    /// Each segment must be non-empty and contain only alphanumeric chars, hyphens, or underscores.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim_matches('/');
        if s.is_empty() {
            return Err(SigynError::InvalidOrgPath("empty path".into()));
        }
        let segments: Vec<String> = s.split('/').map(|seg| seg.to_string()).collect();
        for seg in &segments {
            if seg.is_empty() {
                return Err(SigynError::InvalidOrgPath(
                    "path contains empty segment".into(),
                ));
            }
            if !seg
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
            {
                return Err(SigynError::InvalidOrgPath(format!(
                    "invalid segment '{}': only alphanumeric, hyphens, and underscores allowed",
                    seg
                )));
            }
        }
        Ok(Self { segments })
    }

    /// The root (first) segment, i.e. the org name.
    pub fn root(&self) -> &str {
        &self.segments[0]
    }

    /// The number of segments in the path.
    pub fn depth(&self) -> usize {
        self.segments.len()
    }

    /// The individual segments.
    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    /// Return the parent path, or `None` if this is a root path.
    pub fn parent(&self) -> Option<Self> {
        if self.segments.len() <= 1 {
            None
        } else {
            Some(Self {
                segments: self.segments[..self.segments.len() - 1].to_vec(),
            })
        }
    }

    /// Return a child path by appending a segment.
    pub fn child(&self, name: &str) -> Result<Self> {
        let mut segments = self.segments.clone();
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(SigynError::InvalidOrgPath(format!(
                "invalid child name '{}'",
                name
            )));
        }
        segments.push(name.to_string());
        Ok(Self { segments })
    }

    /// Return all ancestor paths from root down to (but not including) self.
    pub fn ancestors(&self) -> Vec<Self> {
        let mut result = Vec::new();
        for i in 1..self.segments.len() {
            result.push(Self {
                segments: self.segments[..i].to_vec(),
            });
        }
        result
    }

    /// Convert to the canonical slash-separated string representation.
    pub fn as_str(&self) -> String {
        self.segments.join("/")
    }
}

impl std::fmt::Display for OrgPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

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
    fn test_org_path_parse_simple() {
        let path = OrgPath::parse("acme").unwrap();
        assert_eq!(path.segments(), &["acme"]);
        assert_eq!(path.root(), "acme");
        assert_eq!(path.depth(), 1);
    }

    #[test]
    fn test_org_path_parse_nested() {
        let path = OrgPath::parse("acme/platform/web").unwrap();
        assert_eq!(path.segments(), &["acme", "platform", "web"]);
        assert_eq!(path.root(), "acme");
        assert_eq!(path.depth(), 3);
    }

    #[test]
    fn test_org_path_parse_trims_slashes() {
        let path = OrgPath::parse("/acme/platform/").unwrap();
        assert_eq!(path.segments(), &["acme", "platform"]);
    }

    #[test]
    fn test_org_path_parse_empty_fails() {
        assert!(OrgPath::parse("").is_err());
        assert!(OrgPath::parse("/").is_err());
    }

    #[test]
    fn test_org_path_parse_double_slash_fails() {
        assert!(OrgPath::parse("acme//web").is_err());
    }

    #[test]
    fn test_org_path_parse_invalid_chars_fails() {
        assert!(OrgPath::parse("acme/web app").is_err());
        assert!(OrgPath::parse("acme/web.team").is_err());
    }

    #[test]
    fn test_org_path_parent() {
        let path = OrgPath::parse("acme/platform/web").unwrap();
        let parent = path.parent().unwrap();
        assert_eq!(parent.as_str(), "acme/platform");
        let grandparent = parent.parent().unwrap();
        assert_eq!(grandparent.as_str(), "acme");
        assert!(grandparent.parent().is_none());
    }

    #[test]
    fn test_org_path_child() {
        let path = OrgPath::parse("acme").unwrap();
        let child = path.child("platform").unwrap();
        assert_eq!(child.as_str(), "acme/platform");
    }

    #[test]
    fn test_org_path_child_invalid_fails() {
        let path = OrgPath::parse("acme").unwrap();
        assert!(path.child("").is_err());
        assert!(path.child("bad name").is_err());
    }

    #[test]
    fn test_org_path_ancestors() {
        let path = OrgPath::parse("acme/platform/web").unwrap();
        let ancestors = path.ancestors();
        assert_eq!(ancestors.len(), 2);
        assert_eq!(ancestors[0].as_str(), "acme");
        assert_eq!(ancestors[1].as_str(), "acme/platform");
    }

    #[test]
    fn test_org_path_ancestors_root_empty() {
        let path = OrgPath::parse("acme").unwrap();
        assert!(path.ancestors().is_empty());
    }

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

    #[test]
    fn test_org_path_display() {
        let path = OrgPath::parse("acme/platform/web").unwrap();
        assert_eq!(format!("{}", path), "acme/platform/web");
    }

    #[test]
    fn test_org_path_hyphens_and_underscores() {
        let path = OrgPath::parse("my-org/my_team").unwrap();
        assert_eq!(path.segments(), &["my-org", "my_team"]);
    }
}
