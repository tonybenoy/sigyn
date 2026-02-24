use super::manifest::{GitRemoteConfig, NodeManifest};
use super::path::{HierarchyPaths, OrgPath};
use crate::error::Result;

/// Walk from the given node up to the root org, returning the first non-`None`
/// `git_remote` found in any ancestor's NodeManifest.
///
/// The lookup order is: current node → parent → grandparent → ... → root org.
pub fn resolve_git_remote(
    hierarchy_paths: &HierarchyPaths,
    org_path: &OrgPath,
) -> Result<Option<GitRemoteConfig>> {
    // Build the chain: self + ancestors (reversed so we check self first)
    let mut chain = vec![org_path.clone()];
    let mut ancestors = org_path.ancestors();
    ancestors.reverse();
    chain.extend(ancestors);
    // chain is now: [self, parent, grandparent, ..., root]
    // But ancestors() returns [root, ..., parent], reversed gives [parent, ..., root]
    // So chain = [self, parent, ..., root] — correct order for "nearest first"

    for path in &chain {
        let manifest_path = hierarchy_paths.manifest_path(path);
        if manifest_path.exists() {
            let content = std::fs::read_to_string(&manifest_path)?;
            let manifest = NodeManifest::from_toml(&content)?;
            if manifest.git_remote.is_some() {
                return Ok(manifest.git_remote);
            }
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyFingerprint;
    use crate::hierarchy::manifest::NodeManifest;

    fn make_node(name: &str, git_remote: Option<GitRemoteConfig>) -> NodeManifest {
        let mut m = NodeManifest::new(name.into(), "org".into(), KeyFingerprint([0xAA; 16]));
        m.git_remote = git_remote;
        m
    }

    fn setup_node(base: &std::path::Path, org_path: &OrgPath, manifest: &NodeManifest) {
        let paths = HierarchyPaths::new(base.to_path_buf());
        let dir = paths.node_dir(org_path);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(paths.manifest_path(org_path), manifest.to_toml().unwrap()).unwrap();
    }

    #[test]
    fn test_resolve_from_current_node() {
        let dir = tempfile::tempdir().unwrap();
        let paths = HierarchyPaths::new(dir.path().to_path_buf());

        let remote = GitRemoteConfig {
            url: "git@github.com:acme/web.git".into(),
            branch: "main".into(),
        };
        let org = OrgPath::parse("acme").unwrap();
        setup_node(dir.path(), &org, &make_node("acme", Some(remote.clone())));

        let result = resolve_git_remote(&paths, &org).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().url, "git@github.com:acme/web.git");
    }

    #[test]
    fn test_resolve_inherits_from_parent() {
        let dir = tempfile::tempdir().unwrap();
        let paths = HierarchyPaths::new(dir.path().to_path_buf());

        let remote = GitRemoteConfig {
            url: "git@github.com:acme/mono.git".into(),
            branch: "main".into(),
        };
        let root = OrgPath::parse("acme").unwrap();
        setup_node(dir.path(), &root, &make_node("acme", Some(remote)));

        let child = OrgPath::parse("acme/web").unwrap();
        setup_node(dir.path(), &child, &make_node("web", None));

        // Child should inherit parent's remote
        let result = resolve_git_remote(&paths, &child).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().url, "git@github.com:acme/mono.git");
    }

    #[test]
    fn test_resolve_child_overrides_parent() {
        let dir = tempfile::tempdir().unwrap();
        let paths = HierarchyPaths::new(dir.path().to_path_buf());

        let parent_remote = GitRemoteConfig {
            url: "git@github.com:acme/mono.git".into(),
            branch: "main".into(),
        };
        let child_remote = GitRemoteConfig {
            url: "git@github.com:acme/web.git".into(),
            branch: "develop".into(),
        };

        let root = OrgPath::parse("acme").unwrap();
        setup_node(dir.path(), &root, &make_node("acme", Some(parent_remote)));

        let child = OrgPath::parse("acme/web").unwrap();
        setup_node(dir.path(), &child, &make_node("web", Some(child_remote)));

        let result = resolve_git_remote(&paths, &child).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().url, "git@github.com:acme/web.git");
    }

    #[test]
    fn test_resolve_no_remote_anywhere() {
        let dir = tempfile::tempdir().unwrap();
        let paths = HierarchyPaths::new(dir.path().to_path_buf());

        let root = OrgPath::parse("acme").unwrap();
        setup_node(dir.path(), &root, &make_node("acme", None));

        let child = OrgPath::parse("acme/web").unwrap();
        setup_node(dir.path(), &child, &make_node("web", None));

        let result = resolve_git_remote(&paths, &child).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_deep_hierarchy() {
        let dir = tempfile::tempdir().unwrap();
        let paths = HierarchyPaths::new(dir.path().to_path_buf());

        let remote = GitRemoteConfig {
            url: "git@github.com:acme/all.git".into(),
            branch: "main".into(),
        };
        let root = OrgPath::parse("acme").unwrap();
        setup_node(dir.path(), &root, &make_node("acme", Some(remote)));

        let mid = OrgPath::parse("acme/platform").unwrap();
        setup_node(dir.path(), &mid, &make_node("platform", None));

        let leaf = OrgPath::parse("acme/platform/web").unwrap();
        setup_node(dir.path(), &leaf, &make_node("web", None));

        // Grandchild should inherit from root
        let result = resolve_git_remote(&paths, &leaf).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().url, "git@github.com:acme/all.git");
    }
}
