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
